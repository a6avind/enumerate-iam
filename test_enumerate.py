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
        def list_buckets(self):
            if error is not None:
                raise error
            return response or {'Buckets': []}

    return Client()


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
        {'Environment': {'Variables': {
            'DB_PASSWORD': 'Sup3rSecretP@ssw0rd!!',   # secret-named key
            'GITHUB_TOKEN': 'ghp_' + 'a' * 36,        # token pattern
            'CONN': 'postgres://u:realpass@db:5432/x', # creds in URL
            'LOG_LEVEL': 'INFO',                       # benign
            'PLACEHOLDER_PW': 'changeme',              # placeholder
        }}},
    ]}}}
    keys = {f['key'] for f in main.scan_secrets(out)}
    assert {'DB_PASSWORD', 'GITHUB_TOKEN', 'CONN'} <= keys
    assert {'LOG_LEVEL', 'PLACEHOLDER_PW'}.isdisjoint(keys)

    # Redaction never echoes the raw value.
    for f in main.scan_secrets(out):
        assert '*' in f['value_preview']


def test_scan_secrets_entropy_and_base64():
    import base64 as _b64
    aws_secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'  # 40-char, high entropy
    b64_token = _b64.b64encode(b'AKIAIOSFODNN7EXAMPLE').decode()
    out = {'bruteforce': {'svc.get_x': {
        'unknown_field': aws_secret,          # no key hint -> caught by entropy
        'blob': b64_token,                    # base64-wrapped AWS key id
        'region': 'us-east-1',                # benign, low entropy
        'arn': 'arn:aws:iam::123456789012:role/app',  # structured, not flagged
        'md5': 'd41d8cd98f00b204e9800998ecf8427e',     # hex hash, not flagged
    }}}
    findings = {f['location'].split('.')[-1]: f for f in main.scan_secrets(out)}
    assert 'unknown_field' in findings
    assert any('entropy' in r for r in findings['unknown_field']['reasons'])
    assert 'blob' in findings
    assert any(r.startswith('base64:') for r in findings['blob']['reasons'])
    assert {'region', 'arn', 'md5'}.isdisjoint(findings)


if __name__ == '__main__':
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
            print('ok', name)
    print('all passed')
