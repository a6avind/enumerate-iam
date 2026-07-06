"""Regression checks for enumerate_iam internals. Run: python test_enumerate.py

No framework, no network: the AWS-touching helpers are exercised with fake
clients so the classification/mapping logic is covered offline.
"""
import types
import datetime

import botocore.session
import botocore.exceptions as exc

from enumerate_iam import main


def client_error(code):
    return exc.ClientError({'Error': {'Code': code}}, 'Op')


def fake_probe_client(error=None):
    str_shape = types.SimpleNamespace(type_name='string', metadata={})
    input_shape = types.SimpleNamespace(required_members=['Bucket'],
                                        members={'Bucket': str_shape})
    op_model = types.SimpleNamespace(input_shape=input_shape)
    model = types.SimpleNamespace(
        operation_names=['GetBucketPolicy'],
        operation_model=lambda name: op_model,
    )

    class Client:
        meta = types.SimpleNamespace(service_model=model)

        def get_bucket_policy(self, **kwargs):
            if error is not None:
                raise error
            return {'Policy': '{}'}

    return Client()


def fake_read_client(error=None, response=None):
    class Client:
        def can_paginate(self, _op):
            return False  # exercise the non-paginated branch of check_one_permission

        def list_buckets(self):
            if error is not None:
                raise error
            return response or {'Buckets': []}

    return Client()


def fake_paginated_client(all_items):
    """Client whose list_buckets paginates; build_full_result merges every page."""
    class Paginator:
        def paginate(self, **kwargs):
            return self

        def build_full_result(self):
            return {'Buckets': list(all_items)}

    class Client:
        def can_paginate(self, _op):
            return True

        def get_paginator(self, _op):
            return Paginator()

        def list_buckets(self):  # present so the op passes the getattr existence check
            return {'Buckets': []}

    return Client()


def test_check_one_permission_paginates():
    orig = main.get_client
    try:
        pages = [{'Name': 'b%d' % i} for i in range(120)]  # more than one API page
        arg = _run_check(fake_paginated_client(pages), 'list_buckets')
        key, data = main.check_one_permission(arg)
        assert key == 's3.list_buckets'
        assert len(data['Buckets']) == 120  # all pages captured, not just the first
    finally:
        main.get_client = orig


def test_json_encoder():
    assert main.json_encoder(datetime.datetime(2020, 1, 2, 3, 4, 5)) == '2020-01-02T03:04:05'
    assert main.json_encoder(b'hi') == 'hi'
    try:
        main.json_encoder(object())
        assert False, 'expected TypeError'
    except TypeError:
        pass


def test_remove_metadata():
    assert main.remove_metadata({'ResponseMetadata': {}, 'x': 1}) == {'x': 1}
    assert main.remove_metadata('not-a-dict') == 'not-a-dict'


def test_account_id():
    assert main.account_id({'iam': {'arn_id': '123456789012'}}) == '123456789012'
    nested = {'iam': {'iam.get_user': {'User': {'Arn': 'arn:aws:iam::999988887777:user/bob'}}}}
    assert main.account_id(nested) == '999988887777'
    assert main.account_id({'iam': {}}) is None


def test_action_from_key():
    session = botocore.session.get_session()
    assert main.action_from_key(session, 's3.list_buckets') == 's3:ListBuckets'
    assert main.action_from_key(session, 'rds.describe_db_instances') == 'rds:DescribeDBInstances'
    assert main.action_from_key(session, 'nope-not-a-service.foo') is None


def test_confirmed_actions():
    out = {'bruteforce': {'s3.list_buckets': {}},
           'probe': {'s3.get_bucket_policy': {}},
           'iam': {'iam.get_user': {}, 'arn': 'x'}}
    assert main.confirmed_actions(out) == ['iam:GetUser', 's3:GetBucketPolicy', 's3:ListBuckets']


def test_dummy_for_shape():
    s = types.SimpleNamespace
    assert main.dummy_for_shape(s(type_name='string', metadata={})) == 'enumerate-iam'
    assert main.dummy_for_shape(s(type_name='string', metadata={'enum': ['A', 'B']})) == 'A'
    assert main.dummy_for_shape(s(type_name='integer', metadata={})) == 1
    assert main.dummy_for_shape(s(type_name='boolean', metadata={})) is False


def _run_check(monkeypatch_client, op):
    main.CLIENT_POOL.clear()
    main.get_client = lambda *a, **k: monkeypatch_client
    arg = ('ak', 'sk', None, 'us-east-1', None, 's3', op)
    return arg


def test_check_one_permission():
    orig = main.get_client
    try:
        arg = _run_check(fake_read_client(response={'Buckets': [1]}), 'list_buckets')
        key, data = main.check_one_permission(arg)
        assert key == 's3.list_buckets' and data == {'Buckets': [1]}

        arg = _run_check(fake_read_client(error=client_error('AccessDenied')), 'list_buckets')
        assert main.check_one_permission(arg) is None
    finally:
        main.get_client = orig


def test_check_one_probe():
    orig = main.get_client
    try:
        # denial -> not confirmed
        arg = _run_check(fake_probe_client(client_error('AccessDenied')), 'get_bucket_policy')
        assert main.check_one_probe(arg) is None

        # throttling -> inconclusive
        arg = _run_check(fake_probe_client(client_error('Throttling')), 'get_bucket_policy')
        assert main.check_one_probe(arg) is None

        # validation error -> passed authz -> confirmed
        arg = _run_check(fake_probe_client(client_error('ValidationException')), 'get_bucket_policy')
        assert main.check_one_probe(arg) == 's3.get_bucket_policy'

        # outright success -> confirmed
        arg = _run_check(fake_probe_client(None), 'get_bucket_policy')
        assert main.check_one_probe(arg) == 's3.get_bucket_policy'
    finally:
        main.get_client = orig


def test_scan_secrets():
    # Mirrors the real find: a hardcoded env var in a lambda.list_functions response.
    out = {'bruteforce': {'lambda.list_functions': {'Functions': [
        {'FunctionName': 'billing-prod',
         'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:billing-prod',
         'Environment': {'Variables': {
             'DB_PASSWORD': 'Sup3rSecretP@ssw0rd!!',   # secret-named key
             'GITHUB_TOKEN': 'ghp_' + 'a' * 36,        # token pattern
             'CONN': 'postgres://u:realpass@db:5432/x', # creds in URL
             'LOG_LEVEL': 'INFO',                       # benign
             'PLACEHOLDER_PW': 'changeme',              # placeholder
         }}},
    ]}}}
    findings = main.scan_secrets(out)
    by_key = {f['key']: f for f in findings}
    assert {'DB_PASSWORD', 'GITHUB_TOKEN', 'CONN'} <= set(by_key)
    assert {'LOG_LEVEL', 'PLACEHOLDER_PW'}.isdisjoint(by_key)

    # Full plaintext value (not masked) and the real resource ARN, not Functions[0].
    assert by_key['DB_PASSWORD']['value'] == 'Sup3rSecretP@ssw0rd!!'
    assert by_key['DB_PASSWORD']['resource'].endswith(':function:billing-prod')
    assert by_key['DB_PASSWORD']['service'] == 'lambda'
    assert by_key['DB_PASSWORD']['operation'] == 'list_functions'


def test_scan_secrets_entropy_and_base64():
    import base64 as _b64
    main.SCAN_ENTROPY = True  # opt-in heuristic; base64 path is independent of it
    aws_secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'  # 40-char, high entropy
    b64_token = _b64.b64encode(b'AKIAIOSFODNN7EXAMPLE').decode()
    out = {'bruteforce': {'svc.get_x': {
        'unknown_field': aws_secret,          # no key hint -> caught by entropy
        'blob': b64_token,                    # base64-wrapped AWS key id
        'region': 'us-east-1',                # benign, low entropy
        'arn': 'arn:aws:iam::123456789012:role/app',  # structured, not flagged
        'md5': 'd41d8cd98f00b204e9800998ecf8427e',     # hex hash, not flagged
        'RoleId': 'AROAJ4EXAMPLE7ABCDEFG',    # AWS unique id: uppercase, not a secret
        'UserId': 'AIDAI23EXAMPLE9HIJKLM',    # ditto
        'DisplayName': 'Jane Q Random Xy7',   # id/name key: entropy suppressed
    }}}
    try:
        findings = {f['location'].split('.')[-1]: f for f in main.scan_secrets(out)}
    finally:
        main.SCAN_ENTROPY = False
    assert 'unknown_field' in findings
    assert any('entropy' in r for r in findings['unknown_field']['reasons'])
    assert 'blob' in findings
    assert any(r.startswith('base64:') for r in findings['blob']['reasons'])
    assert {'region', 'arn', 'md5', 'RoleId', 'UserId', 'DisplayName'}.isdisjoint(findings)

    # Off by default: the same high-entropy field is NOT flagged.
    assert not any(f['key'] == 'unknown_field' for f in main.scan_secrets(out))


def test_throttle_defaults_and_sleep():
    assert main.DEFAULT_DELAY > 0 and main.DEFAULT_JITTER > 0  # on by default
    slept = []
    orig_sleep, orig_delay, orig_jitter = main.time.sleep, main.REQUEST_DELAY, main.REQUEST_JITTER
    try:
        main.time.sleep = lambda s: slept.append(s)
        main.REQUEST_DELAY, main.REQUEST_JITTER = 0.2, 0.0
        main._throttle()
        assert slept == [0.2]
        # disabled -> no sleep call at all
        slept.clear()
        main.REQUEST_DELAY, main.REQUEST_JITTER = 0.0, 0.0
        main._throttle()
        assert slept == []
    finally:
        main.time.sleep, main.REQUEST_DELAY, main.REQUEST_JITTER = orig_sleep, orig_delay, orig_jitter


def test_multi_region_tagging():
    # single region: keys unchanged (back-compat)
    assert main._tag_region({'lambda.list_functions': {}}, 'us-east-1', False) \
        == {'lambda.list_functions': {}}
    # multi region: key gets @region suffix
    assert main._tag_region({'lambda.list_functions': {}}, 'eu-west-1', True) \
        == {'lambda.list_functions@eu-west-1': {}}

    # confirmed_actions strips @region and collapses the same action across regions
    out = {'bruteforce': {'s3.list_buckets@us-east-1': {}, 's3.list_buckets@eu-west-1': {}},
           'iam': {}}
    assert main.confirmed_actions(out) == ['s3:ListBuckets']

    # scan_secrets tags the finding with its region and derives service/operation
    out = {'bruteforce': {'lambda.list_functions@eu-west-1': {'Functions': [
        {'FunctionName': 'f', 'Environment': {'Variables': {'DB_PASSWORD': 'hunter2secret'}}}]}}}
    f = main.scan_secrets(out)[0]
    assert f['region'] == 'eu-west-1' and f['service'] == 'lambda' and f['key'] == 'DB_PASSWORD'


if __name__ == '__main__':
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
            print('ok', name)
    print('all passed')
