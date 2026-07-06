"""
IAM Account Enumerator

This code provides a mechanism to attempt to validate the permissions assigned
to a given set of AWS tokens.

Initial code from:

    https://gist.github.com/darkarnium/1df59865f503355ef30672168063da4e

Improvements:
    * Complete refactoring
    * Results returned in a programmatic way
    * Threads
    * Improved logging
    * Increased API call coverage
    * Export as a library
"""
import os
import re
import sys
import math
import time
import base64
import random
import logging
import datetime
import collections
import boto3
import botocore
import botocore.session

from botocore import xform_name
from botocore.client import Config
from botocore.endpoint import MAX_POOL_CONNECTIONS
from multiprocessing.dummy import Pool as ThreadPool

from enumerate_iam.bruteforce_tests import BRUTEFORCE_TESTS

MAX_THREADS = 25
CLIENT_POOL = {}

# Upper bound on items pulled per paginated read, so one huge list (millions of
# S3 objects, log events, ...) can't exhaust memory/time. Truncation is logged.
MAX_PAGINATED_ITEMS = 5000

# Per-call throttle (seconds): sleep DELAY + random[0, JITTER) before each API
# call. Default 2-7s keeps the sweep low-and-slow under rate limits / detection.
DEFAULT_DELAY = 2.0
DEFAULT_JITTER = 5.0

# How often (seconds) a running pass emits a progress heartbeat.
HEARTBEAT_SECONDS = 30
REQUEST_DELAY = DEFAULT_DELAY
REQUEST_JITTER = DEFAULT_JITTER

# High-entropy heuristic is noisy (flags random-looking names/ids that aren't
# secrets), so it's opt-in; pattern + secret-named-key + base64 detection stay on.
SCAN_ENTROPY = False


def _throttle():
    delay = REQUEST_DELAY + (random.uniform(0, REQUEST_JITTER) if REQUEST_JITTER else 0.0)
    if delay:
        time.sleep(delay)


# max_attempts was 30, which made unreachable endpoints hang for minutes.
# adaptive mode adds client-side rate limiting so bursts don't trip throttling.
BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=5,
    retries={'max_attempts': 3, 'mode': 'adaptive'},
    max_pool_connections=MAX_POOL_CONNECTIONS * 2,
)

# Error codes that mean the caller lacks the permission (as opposed to a bad
# request, which still proves the permission because the call passed authz).
DENY_CODES = frozenset({
    'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
    'AuthorizationError', 'Forbidden', 'MissingAuthenticationToken',
})

# Skip any single failed call rather than abort the run; ClientError is not a
# BotoCoreError subclass, so both are listed.
SKIPPABLE_ERRORS = (
    botocore.exceptions.ClientError,
    botocore.exceptions.BotoCoreError,
)


def remove_metadata(boto_response):
    if isinstance(boto_response, dict):
        boto_response.pop('ResponseMetadata', None)

    return boto_response


def json_encoder(obj):
    """default= hook for json.dumps: serialise the non-JSON types AWS returns."""
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()

    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')

    raise TypeError('Object of type %s is not JSON serializable' % type(obj).__name__)


def account_id(output):
    """Best-effort AWS account id from an enumerate_iam() result, or None."""
    # sts:GetCallerIdentity is authoritative and needs no perms; prefer it.
    account = output.get('identity', {}).get('Account')
    if account:
        return account

    iam = output.get('iam', {})
    if iam.get('arn_id'):
        return iam['arn_id']

    arn = iam.get('iam.get_user', {}).get('User', {}).get('Arn')
    if arn and len(arn.split(':')) > 4:
        return arn.split(':')[4]

    return None


def report_arn(candidate):
    """Extract and slice an ARN from an IAM error string, for output['arn'].

    Identity is printed once by get_identity() (authoritative sts call); this is
    a silent extractor so the ARN/id aren't logged a second time.
    """
    arn_search = re.search(r'.*(arn:aws:.*?) .*', candidate)

    if arn_search:
        arn = arn_search.group(1)

        arn_id = arn.split(':')[4]
        arn_path = arn.split(':')[5]

        return arn, arn_id, arn_path

    return None, None, None


def action_from_key(session, key):
    """Map a stored 'service.snake_op' result key to its IAM action.

    endpointPrefix is the IAM service prefix for the vast majority of services;
    the operation's wire name gives the correct casing (DescribeDBInstances,
    not a lossy snake->camel guess). Returns None if the service is unknown.
    """
    service, _, operation = key.partition('.')
    try:
        model = session.get_service_model(service)
    except botocore.exceptions.UnknownServiceError:
        return None

    prefix = model.metadata.get('endpointPrefix', service)
    for name in model.operation_names:
        if xform_name(name) == operation:
            return '%s:%s' % (prefix, name)
    return '%s:%s' % (prefix, operation)


def confirmed_actions(output):
    """Synthesise the sorted list of IAM actions confirmed by the enumeration."""
    session = botocore.session.get_session()
    keys = list(output.get('bruteforce', {})) + list(output.get('probe', {}))
    # Strip an optional '@region' suffix; the same action confirmed in several
    # regions collapses to one entry.
    keys = [k.partition('@')[0] for k in keys]
    keys += [k for k in output.get('iam', {}) if k.startswith('iam.')]

    actions = {action_from_key(session, k) for k in keys}
    actions.discard(None)
    return sorted(actions)


def get_identity(access_key, secret_key, session_token, region, endpoint_url):
    """Authoritative caller identity via sts:GetCallerIdentity (needs no perms)."""
    logger = logging.getLogger()
    client = get_client(access_key, secret_key, session_token, 'sts', region, endpoint_url)
    if client is None:
        return None

    try:
        identity = remove_metadata(client.get_caller_identity())
    except SKIPPABLE_ERRORS:
        return None

    logger.info('-- Account ARN : %s', identity.get('Arn'))
    logger.info('-- Account Id  : %s', identity.get('Account'))
    logger.info('-- User Id     : %s', identity.get('UserId'))
    return identity


def _run_read_pass(args, timeout=None, threads=MAX_THREADS, label=''):
    """Call each (…, service, operation) tuple, capturing responses that work."""
    output = dict()
    logger = logging.getLogger()
    total = len(args)
    start = time.monotonic()
    deadline = start + timeout if timeout else None
    last_beat = start
    where = '%s ' % label if label else ''

    pool = ThreadPool(threads)
    try:
        try:
            for done, thread_result in enumerate(
                    pool.imap_unordered(check_one_permission, args), start=1):
                now = time.monotonic()
                if deadline and now > deadline:
                    logger.warning('Timeout reached after %d/%d calls; stopping.', done, total)
                    break
                # Periodic heartbeat so a long, throttled run visibly progresses.
                if now - last_beat >= HEARTBEAT_SECONDS or done == total:
                    last_beat = now
                    logger.info('Progress: %s%d/%d calls (%d%%), %d found',
                                where, done, total, 100 * done // total, len(output))
                if thread_result is None:
                    continue
                key, action_result = thread_result
                output[key] = action_result
        except KeyboardInterrupt:
            print('')
            logger.info('Ctrl+C received, stopping all threads.')
            logger.info('Hit Ctrl+C again to force exit.')
    finally:
        # terminate() frees the pool's semaphores; close()/join() alone leaks them.
        pool.terminate()
        pool.join()

    return output


def enumerate_using_bruteforce(access_key, secret_key, session_token, region,
                               endpoint_url=None, services=None, timeout=None,
                               threads=MAX_THREADS):
    """
    Attempt to brute-force common describe calls.
    """
    logger = logging.getLogger()
    logger.info('Attempting common-service describe / list brute force.')

    args = list(generate_args(access_key, secret_key, session_token, region, endpoint_url, services))
    return _run_read_pass(args, timeout, threads, label=region)


def generate_all_read_args(session, access_key, secret_key, session_token, region,
                           endpoint_url, services=None):
    """Every zero-arg list_/describe_/get_ operation across all botocore services.

    Superset of the curated BRUTEFORCE_TESTS set; param-requiring reads are left
    to --probe (which confirms authz but can't capture a response to scan)."""
    service_names = [s for s in session.get_available_services()
                     if services is None or s in services]
    random.shuffle(service_names)

    for service_name in service_names:
        model = session.get_service_model(service_name)
        for wire_name in model.operation_names:
            operation = xform_name(wire_name)
            if not operation.startswith(('list_', 'describe_', 'get_')):
                continue
            input_shape = model.operation_model(wire_name).input_shape
            if input_shape is not None and input_shape.required_members:
                continue
            yield access_key, secret_key, session_token, region, endpoint_url, service_name, operation


def enumerate_all_services(access_key, secret_key, session_token, region,
                           endpoint_url=None, services=None, timeout=None,
                           threads=MAX_THREADS):
    """Sweep every zero-arg read op across all services, capturing responses so
    scan_secrets sees the widest possible surface (slow, many calls)."""
    logger = logging.getLogger()
    logger.info('Sweeping every zero-arg read operation across all services (slow).')

    session = botocore.session.get_session()
    args = list(generate_all_read_args(session, access_key, secret_key, session_token,
                                       region, endpoint_url, services))
    return _run_read_pass(args, timeout, threads, label=region)


def generate_args(access_key, secret_key, session_token, region, endpoint_url, services=None):
    service_names = [s for s in BRUTEFORCE_TESTS if services is None or s in services]
    random.shuffle(service_names)

    for service_name in service_names:
        actions = list(BRUTEFORCE_TESTS[service_name])
        random.shuffle(actions)

        for action in actions:
            yield access_key, secret_key, session_token, region, endpoint_url, service_name, action


def get_client(access_key, secret_key, session_token, service_name, region, endpoint_url=None):
    key = '%s-%s-%s-%s-%s-%s' % (access_key, secret_key, session_token, service_name, region, endpoint_url)

    client = CLIENT_POOL.get(key, None)
    if client is not None:
        return client

    logger = logging.getLogger()
    logger.debug('Getting client for %s in region %s' % (service_name, region))

    try:
        client = boto3.client(
            service_name,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
            endpoint_url=endpoint_url,
            verify=False,
            config=BOTO_CONFIG,
        )
    except:
        # The service might not be available in this region
        return

    CLIENT_POOL[key] = client

    return client


def check_one_permission(arg_tuple):
    access_key, secret_key, session_token, region, endpoint_url, service_name, operation_name = arg_tuple
    logger = logging.getLogger()

    service_client = get_client(access_key, secret_key, session_token, service_name, region, endpoint_url)
    if service_client is None:
        return

    try:
        action_function = getattr(service_client, operation_name)
    except AttributeError:
        # The service might not have this action (this is most likely
        # an error with generate_bruteforce_tests.py)
        logger.error('Remove %s.%s action' % (service_name, operation_name))
        return

    logger.debug('Testing %s.%s() in region %s' % (service_name, operation_name, region))

    _throttle()
    try:
        if service_client.can_paginate(operation_name):
            # Capture every page (all functions/resources, not just the first ~50),
            # so the secret scan sees the full result. Capped to bound huge lists.
            result = service_client.get_paginator(operation_name).paginate(
                PaginationConfig={'MaxItems': MAX_PAGINATED_ITEMS}).build_full_result()
            if result.get('NextToken') or result.get('NextMarker'):
                logger.warning('%s.%s truncated at %d items (more pages exist)',
                               service_name, operation_name, MAX_PAGINATED_ITEMS)
            action_response = result
        else:
            action_response = action_function()
    except botocore.exceptions.ParamValidationError:
        # Listed before SKIPPABLE_ERRORS (its superclass) to keep this signal.
        logger.error('Remove %s.%s action' % (service_name, operation_name))
        return
    except SKIPPABLE_ERRORS:
        return

    logger.info('-- %s.%s() worked!', service_name, operation_name)

    key = '%s.%s' % (service_name, operation_name)

    return key, remove_metadata(action_response)


# Error codes that are inconclusive: the call failed before authz could be
# decided (throttling) or on the credentials themselves.
AMBIGUOUS_CODES = frozenset({
    'Throttling', 'ThrottlingException', 'RequestLimitExceeded',
    'TooManyRequestsException', 'RequestThrottled', 'InvalidClientTokenId',
    'SignatureDoesNotMatch', 'ExpiredToken', 'ExpiredTokenException',
    'InvalidAccessKeyId', 'AuthFailure',
})


def dummy_for_shape(shape, depth=0):
    """Minimal placeholder value satisfying a required input shape."""
    kind = shape.type_name
    if kind == 'string':
        enum = shape.metadata.get('enum')
        return enum[0] if enum else 'enumerate-iam'
    if kind in ('integer', 'long'):
        return 1
    if kind in ('float', 'double'):
        return 1.0
    if kind == 'boolean':
        return False
    if kind == 'timestamp':
        return 0
    if kind == 'blob':
        return b'enumerate-iam'
    if kind == 'list':
        return [] if depth > 3 else [dummy_for_shape(shape.member, depth + 1)]
    if kind == 'map':
        return {}
    if kind == 'structure':
        if depth > 3:
            return {}
        return {name: dummy_for_shape(shape.members[name], depth + 1)
                for name in shape.required_members}
    return 'enumerate-iam'


def check_one_probe(arg_tuple):
    """Probe a parameter-requiring read op with dummy input.

    Any answer other than an authz denial (or a throttling/credential error)
    means the call passed authorization, so the permission is present even
    though the request itself was rejected as invalid.
    """
    access_key, secret_key, session_token, region, endpoint_url, service_name, operation_name = arg_tuple

    client = get_client(access_key, secret_key, session_token, service_name, region, endpoint_url)
    if client is None:
        return

    model = client.meta.service_model
    wire_name = next((n for n in model.operation_names
                      if xform_name(n) == operation_name), None)
    if wire_name is None:
        return

    input_shape = model.operation_model(wire_name).input_shape
    kwargs = {name: dummy_for_shape(input_shape.members[name])
              for name in input_shape.required_members}

    _throttle()
    try:
        getattr(client, operation_name)(**kwargs)
    except botocore.exceptions.ParamValidationError:
        return
    except botocore.exceptions.ClientError as err:
        code = err.response.get('Error', {}).get('Code', '')
        if code in DENY_CODES or code in AMBIGUOUS_CODES:
            return
    except botocore.exceptions.BotoCoreError:
        return

    logger = logging.getLogger()
    logger.info('-- %s.%s() permission confirmed (probe)', service_name, operation_name)
    return '%s.%s' % (service_name, operation_name)


def generate_probe_args(session, access_key, secret_key, session_token, region,
                        endpoint_url, services=None):
    service_names = [s for s in session.get_available_services()
                     if services is None or s in services]
    random.shuffle(service_names)

    for service_name in service_names:
        model = session.get_service_model(service_name)
        for wire_name in model.operation_names:
            operation = xform_name(wire_name)
            if not operation.startswith(('list_', 'describe_', 'get_')):
                continue
            input_shape = model.operation_model(wire_name).input_shape
            if input_shape is None or not input_shape.required_members:
                continue  # zero-arg ops are covered by the brute-force pass
            yield access_key, secret_key, session_token, region, endpoint_url, service_name, operation


def enumerate_using_probe(access_key, secret_key, session_token, region,
                          endpoint_url=None, services=None, timeout=None,
                          threads=MAX_THREADS):
    """Confirm parameter-requiring read permissions via error-code analysis."""
    output = dict()
    logger = logging.getLogger()
    logger.info('Probing parameter-requiring read operations (may take a while).')

    session = botocore.session.get_session()
    args = list(generate_probe_args(session, access_key, secret_key, session_token,
                                    region, endpoint_url, services))
    total = len(args)
    start = time.monotonic()
    deadline = start + timeout if timeout else None
    last_beat = start

    pool = ThreadPool(threads)
    try:
        try:
            for done, key in enumerate(pool.imap_unordered(check_one_probe, args), start=1):
                now = time.monotonic()
                if deadline and now > deadline:
                    logger.warning('Timeout reached; stopping probe.')
                    break
                if now - last_beat >= HEARTBEAT_SECONDS or done == total:
                    last_beat = now
                    logger.info('Progress: probe %s %d/%d calls (%d%%), %d found',
                                region, done, total, 100 * done // total, len(output))
                if key is not None:
                    output[key] = {'confirmed_via': 'probe'}
        except KeyboardInterrupt:
            print('')
            logger.info('Ctrl+C received, stopping all threads.')
    finally:
        pool.terminate()
        pool.join()

    return output


# Keys whose value is a secret by virtue of the name (env-var style k/v maps:
# Lambda Environment.Variables, ECS task-def env, CloudFormation params, ...).
SECRET_KEY_HINTS = (
    'SECRET', 'PASSWORD', 'PASSWD', 'TOKEN', 'APIKEY', 'ACCESSKEY',
    'PRIVATEKEY', 'CREDENTIAL', 'CONNECTIONSTRING', 'CONNSTR', 'AUTH',
    'CLIENTSECRET', 'ENCRYPTIONKEY', 'SIGNINGKEY',
)

# High-confidence value patterns worth flagging regardless of the key name.
SECRET_VALUE_PATTERNS = {
    'aws_access_key_id': re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
    'private_key_block': re.compile(r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----'),
    'github_token': re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{22,}\b'),
    'slack_token': re.compile(r'\bxox[baprs]-[0-9A-Za-z-]{10,}\b'),
    'google_api_key': re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'),
    'jwt': re.compile(r'\beyJ[0-9A-Za-z_\-]{8,}\.eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]+\b'),
    'db_conn_with_password': re.compile(
        r'\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@'),
}

# Values that trip a key-name hint but carry no real secret.
_PLACEHOLDER_VALUES = frozenset({
    '', 'none', 'null', 'true', 'false', 'changeme', 'change-me', 'example',
    'password', 'secret', 'placeholder', 'todo', 'xxx', 'test',
})


def _looks_placeholder(value):
    low = value.strip().lower()
    if low in _PLACEHOLDER_VALUES or len(low) < 6:
        return True
    # ${VAR}, {{ref}}, <fill-me> style templating, not a literal secret.
    if re.fullmatch(r'[\$\{<][^\s]*[\}>]', value.strip()):
        return True
    return len(set(low)) <= 2  # 'xxxxxx', '000000'


def _shannon_entropy(value):
    if not value:
        return 0.0
    n = len(value)
    return -sum((c / n) * math.log2(c / n)
                for c in collections.Counter(value).values())


# A single opaque token (no spaces), long enough to be a key, in a base64/hex/
# url-safe charset. Excludes ARNs/URLs/paths that are structured, not random.
_TOKEN_SHAPE = re.compile(r'[A-Za-z0-9+/=_\-]{20,200}')


def _is_high_entropy_secret(value):
    """Random-looking token unlikely to be a benign id/hash. Deliberately
    conservative: base64-alphabet only, entropy >= 4.0 bits/char. Pure hex and
    all-uppercase ids are skipped (md5/sha fingerprints; AWS unique ids like
    AROA…/AIDA… are uppercase, real base64 secrets are mixed-case)."""
    v = value.strip()
    if not _TOKEN_SHAPE.fullmatch(v):
        return False
    if v.startswith(('arn:', 'http://', 'https://')):
        return False
    if re.fullmatch(r'[0-9a-fA-F]+', v):  # pure hex -> too many benign hashes/ids
        return False
    if v.isupper():  # AWS RoleId/UserId/AccessKeyId and other uppercase ids
        return False
    return _shannon_entropy(v) >= 4.0


def _maybe_b64_decode(value):
    """Decode base64 to printable UTF-8 text, else None. Catches secrets stashed
    as base64 (encoded JSON creds, user-data, wrapped tokens)."""
    v = value.strip()
    if len(v) < 16 or len(v) % 4 != 0 or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', v):
        return None
    try:
        raw = base64.b64decode(v, validate=True)  # binascii.Error subclasses ValueError
    except ValueError:
        return None
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if text == v or sum(c.isprintable() or c.isspace() for c in text) < 0.9 * len(text):
        return None
    return text


# Key names whose value is a public identifier / metadata, never a secret. The
# fuzzy entropy heuristic is suppressed for these (RoleId, DisplayName, Arn, ...);
# explicit value patterns still fire regardless of key.
_BENIGN_KEY = re.compile(
    r'(id|ids|arn|arns|name|names|region|version|zone|etag|account|owner|'
    r'path|url|uri|endpoint|host|hostname|date|time|timestamp|hash|digest|'
    r'checksum|fingerprint|md5|sha1|sha256)$')


def _detect(key, value):
    """Reasons this (key, value) pair looks like a hardcoded secret; [] if not."""
    reasons = [name for name, pat in SECRET_VALUE_PATTERNS.items() if pat.search(value)]

    norm_key = re.sub(r'[^a-z0-9]', '', key.lower())
    if any(hint in norm_key.upper() for hint in SECRET_KEY_HINTS) and not _looks_placeholder(value):
        reasons.append('secret-named key %r' % key)

    if (SCAN_ENTROPY and not reasons and not _BENIGN_KEY.search(norm_key)
            and _is_high_entropy_secret(value)):
        reasons.append('high-entropy string (%.1f bits/char)' % _shannon_entropy(value))

    return reasons


def _resource_id(node):
    """Best identifier for a record dict: its ARN, else a *Name, else an *Id."""
    if not isinstance(node, dict):
        return None
    for suffix in ('Arn', 'Name', 'Id'):
        # Exact match first ('Arn'), then any key ending in it ('FunctionArn').
        for k, v in node.items():
            if isinstance(v, str) and v and (k == suffix or k.endswith(suffix)):
                return v
    return None


def _walk_strings(node, path='', resource=None):
    """Yield (path, key, value, resource) for every string leaf. `resource` is
    the ARN/name of the nearest enclosing record, so a finding points at the
    real resource, not just the API call and an array index."""
    if isinstance(node, dict):
        here = _resource_id(node) or resource
        for k, v in node.items():
            child = '%s.%s' % (path, k) if path else str(k)
            if isinstance(v, str):
                yield child, str(k), v, here
            else:
                yield from _walk_strings(v, child, here)
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            child = '%s[%d]' % (path, i)
            if isinstance(v, str):
                yield child, '', v, resource
            else:
                yield from _walk_strings(v, child, resource)


# Response sections keyed by 'service.operation'; the rest of output is scanned
# generically (iam, identity, ...).
_CALL_SECTIONS = ('bruteforce', 'probe')


def scan_secrets(output):
    """Flag hardcoded secrets in already-collected API responses.

    No extra AWS calls: list/describe responses (Lambda Environment.Variables,
    EC2 user-data, ECS task-defs, ...) already sit in `output`; this reads them
    back and reports env-var-style secrets and embedded keys/tokens, tagged with
    the resource they belong to. The full value is included (the plaintext is
    already in the results JSON under the raw response — masking it there is
    pointless), so the findings list is directly actionable.
    """
    logger = logging.getLogger()
    findings = []
    seen = set()

    def collect(node, base_path, service=None, operation=None, region=None):
        for path, key, value, resource in _walk_strings(node, base_path):
            reasons = _detect(key, value)
            if not reasons:
                decoded = _maybe_b64_decode(value)
                if decoded is not None:
                    reasons = ['base64: ' + r for r in _detect(key, decoded)]
            if not reasons:
                continue

            dedup = (region, resource, key, value)
            if dedup in seen:
                continue
            seen.add(dedup)

            findings.append({
                'service': service,
                'operation': operation,
                'region': region,
                'resource': resource,
                'key': key,
                'value': value,
                'reasons': reasons,
                'location': path,
            })
            logger.info('-- Possible secret: %s %s [%s] (%s)',
                        '%s.%s' % (service, operation) if service else path,
                        resource or '', key, ', '.join(reasons))

    for section in _CALL_SECTIONS:
        for call_key, response in output.get(section, {}).items():
            base, _, region = call_key.partition('@')
            service, _, operation = base.partition('.')
            collect(response, '%s.%s' % (section, call_key), service, operation, region or None)

    for key, value in output.items():
        if key in _CALL_SECTIONS or key in ('findings', 'confirmed_actions'):
            continue
        collect(value, key)

    findings.sort(key=lambda f: (f.get('region') or '', f.get('service') or '',
                                 f.get('resource') or '', f['location']))
    return findings


class ColorFormatter(logging.Formatter):
    GREEN = '\033[32m'
    CYAN = '\033[36m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    RESET = '\033[0m'

    # Honour NO_COLOR (https://no-color.org) and skip colours when not a TTY.
    enabled = sys.stderr.isatty() and 'NO_COLOR' not in os.environ

    # Found permissions and the run summary (coloured green when shown).
    HITS = ('worked!', 'permission confirmed', 'Run for the hills',
            'root credentials', 'Enumeration complete', 'Possible secret')
    # Caller identity — shown even in the default (filtered) view.
    ACCOUNT = ('Account ARN', 'Account Id', 'User Id')
    # The only INFO lines the default (quiet) view keeps: identity, found secrets,
    # the final summary, and root/critical hits. Per-op "worked!" confirmations and
    # progress chatter are dropped here (still in the JSON and under --verbose).
    QUIET = ACCOUNT + ('Possible secret', 'Enumeration complete', 'Progress',
                       'Run for the hills', 'root credentials')

    def format(self, record):
        line = super().format(record)
        if not self.enabled:
            return line

        message = record.getMessage()
        if record.levelno >= logging.ERROR:
            colour = self.RED
        elif record.levelno == logging.WARNING:
            colour = self.YELLOW
        elif any(hit in message for hit in self.HITS):
            colour = self.GREEN
        elif any(hit in message for hit in self.ACCOUNT):
            colour = self.CYAN
        else:
            return line

        return '%s%s%s' % (colour, line, self.RESET)


def _findings_only(record):
    # Keep only high-value lines + warnings/errors; drop per-op confirmations
    # and progress chatter (all still captured in the JSON / shown with --verbose).
    return (record.levelno >= logging.WARNING
            or any(hit in record.getMessage() for hit in ColorFormatter.QUIET))


def configure_logging(verbose=False):
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter(
        '%(asctime)s - %(process)d - [%(levelname)s] %(message)s'
    ))
    if not verbose:
        handler.addFilter(_findings_only)
    logging.basicConfig(level=logging.INFO, handlers=[handler])

    # Suppress boto INFO.
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('nose').setLevel(logging.WARNING)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    urllib3.disable_warnings(botocore.vendored.requests.packages.urllib3.exceptions.InsecureRequestWarning)


def _tag_region(results, region, multi):
    """Suffix each 'service.operation' key with '@region' when sweeping several
    regions, so per-region responses don't collide. Single region keeps the
    original key (back-compatible output shape)."""
    if not multi:
        return results
    return {'%s@%s' % (k, region): v for k, v in results.items()}


def enumerate_iam(access_key, secret_key, session_token, region, endpoint_url=None,
                  dry_run=False, verbose=False, services=None, probe=False,
                  full=True, timeout=None, threads=MAX_THREADS, regions=None,
                  delay=DEFAULT_DELAY, jitter=DEFAULT_JITTER, entropy=False):
    """IAM Account Enumerator.

    This code provides a mechanism to attempt to validate the permissions assigned
    to a given set of AWS tokens. Pass `regions` (a list) to sweep the regional
    read operations across several regions; `region` is the single-region default
    and the endpoint for the global IAM/STS calls. `delay`/`jitter` throttle each
    API call by `delay + random[0, jitter)` seconds.
    """
    global REQUEST_DELAY, REQUEST_JITTER, SCAN_ENTROPY
    REQUEST_DELAY, REQUEST_JITTER, SCAN_ENTROPY = delay, jitter, entropy

    output = dict()
    # dry-run always logs in full; otherwise verbose controls the chatter.
    configure_logging(verbose=verbose or dry_run)
    logger = logging.getLogger()

    if dry_run:
        total = sum(len(ops) for ops in BRUTEFORCE_TESTS.values())
        logger.info('Dry run: would test %d operations across %d services '
                    '(no AWS API calls made).', total, len(BRUTEFORCE_TESTS))
        for service_name in sorted(BRUTEFORCE_TESTS):
            for operation_name in BRUTEFORCE_TESTS[service_name]:
                logger.info('-- %s.%s', service_name, operation_name)
        return output

    if access_key is None and secret_key is None:
        # No keys passed: let boto3 resolve them, but fail early and clearly if
        # nothing is found instead of crashing mid-enumeration.
        try:
            found = botocore.session.Session().get_credentials()
        except botocore.exceptions.BotoCoreError:
            found = None
        if found is None:
            logger.error(
                'No credentials provided and none found in the environment, '
                'shared config, or instance metadata. Pass --access-key/'
                '--secret-key or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.'
            )
            return output

    region_list = regions or [region]
    multi = len(region_list) > 1
    if multi:
        logger.info('Sweeping %d regions: %s', len(region_list), ', '.join(region_list))

    identity = get_identity(access_key, secret_key, session_token, region, endpoint_url)
    if identity is not None:
        output['identity'] = identity

    # IAM and STS are global; enumerate once against the primary region endpoint.
    output['iam'] = enumerate_using_iam(access_key, secret_key, session_token, region, endpoint_url)

    # Default read pass sweeps every service; --curated (full=False) uses the
    # smaller hand-picked set. Both land in output['bruteforce'].
    read_pass = enumerate_all_services if full else enumerate_using_bruteforce
    output['bruteforce'] = {}
    output['probe'] = {} if probe else None
    for reg in region_list:
        if multi:
            logger.info('--- Region %s ---', reg)
        output['bruteforce'].update(_tag_region(read_pass(
            access_key, secret_key, session_token, reg, endpoint_url, services, timeout, threads),
            reg, multi))
        if probe:
            output['probe'].update(_tag_region(enumerate_using_probe(
                access_key, secret_key, session_token, reg, endpoint_url, services, timeout, threads),
                reg, multi))

    if output['probe'] is None:
        del output['probe']

    output['confirmed_actions'] = confirmed_actions(output)
    output['findings'] = scan_secrets(output)

    iam_hits = sum(1 for key in output['iam'] if key.startswith('iam.'))
    logger.info('Enumeration complete: %d actions confirmed (%d IAM, %d read, %d probe) '
                'across %d region(s). %d possible secret(s) flagged.',
                len(output['confirmed_actions']), iam_hits, len(output['bruteforce']),
                len(output.get('probe', {})), len(region_list), len(output['findings']))

    return output


def enumerate_using_iam(access_key, secret_key, session_token, region, endpoint_url=None):
    output = dict()
    logger = logging.getLogger()

    logger.info('Starting permission enumeration for access-key-id "%s"', access_key)
    iam_client = boto3.client(
        'iam',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region,
        endpoint_url=endpoint_url,
        verify=False,
        config=BOTO_CONFIG,
    )

    try:
        everything = iam_client.get_account_authorization_details()
    except SKIPPABLE_ERRORS:
        pass
    else:
        logger.info('Run for the hills, get_account_authorization_details worked!')

        output['iam.get_account_authorization_details'] = remove_metadata(everything)

    enumerate_user(iam_client, output)
    enumerate_role(iam_client, output)

    return output


def enumerate_role(iam_client, output):
    logger = logging.getLogger()

    user_or_role_arn = output.get('arn', None)

    if user_or_role_arn is None:
        # The checks which follow all required the user name to run, if we were
        # unable to get that piece of information just return
        return

    try:
        role = iam_client.get_role(RoleName=user_or_role_arn)
    except botocore.exceptions.ClientError as err:
        arn, arn_id, arn_path = report_arn(str(err))

        if arn is not None:
            output['arn'] = arn
            output['arn_id'] = arn_id
            output['arn_path'] = arn_path

        if 'role' not in user_or_role_arn:
            # We did out best, but we got nothing from iam
            return
        else:
            role_name = user_or_role_arn

    else:
        output['iam.get_role'] = remove_metadata(role)
        role_name = role['Role']['RoleName']

    try:
        role_policies = iam_client.list_attached_role_policies(RoleName=role_name)
    except botocore.exceptions.ClientError:
        pass
    else:
        output['iam.list_attached_role_policies'] = remove_metadata(role_policies)

        logger.info(
            'Role "%s" has %0d attached policies',
            role_name,
            len(role_policies['AttachedPolicies'])
        )

        for policy in role_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

    try:
        role_policies = iam_client.list_role_policies(RoleName=role_name)
    except botocore.exceptions.ClientError:
        pass
    else:
        output['iam.list_role_policies'] = remove_metadata(role_policies)

        logger.info(
            'Role "%s" has %0d inline policies',
            role_name,
            len(role_policies['PolicyNames'])
        )

        for policy in role_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

    return output


def enumerate_user(iam_client, output):
    logger = logging.getLogger()
    output['root_account'] = False

    try:
        user = iam_client.get_user()
    except SKIPPABLE_ERRORS as err:
        arn, arn_id, arn_path = report_arn(str(err))

        output['arn'] = arn
        output['arn_id'] = arn_id
        output['arn_path'] = arn_path

        # The checks which follow all required the user name to run, if we were
        # unable to get that piece of information just return
        return
    else:
        output['iam.get_user'] = remove_metadata(user)

    if 'UserName' not in user['User']:
        if user['User']['Arn'].endswith(':root'):
            logger.warning('Found root credentials!')
            output['root_account'] = True
            return
        else:
            logger.error('Unexpected iam.get_user() response: %s' % user)
            return
    else:
        user_name = user['User']['UserName']

    try:
        user_policies = iam_client.list_attached_user_policies(UserName=user_name)
    except botocore.exceptions.ClientError:
        pass
    else:
        output['iam.list_attached_user_policies'] = remove_metadata(user_policies)

        logger.info(
            'User "%s" has %0d attached policies',
            user_name,
            len(user_policies['AttachedPolicies'])
        )

        for policy in user_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

    try:
        user_policies = iam_client.list_user_policies(UserName=user_name)
    except botocore.exceptions.ClientError:
        pass
    else:
        output['iam.list_user_policies'] = remove_metadata(user_policies)

        logger.info(
            'User "%s" has %0d inline policies',
            user_name,
            len(user_policies['PolicyNames'])
        )

        for policy in user_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

    user_groups = dict()
    user_groups['Groups'] = []

    try:
        user_groups = iam_client.list_groups_for_user(UserName=user_name)
    except botocore.exceptions.ClientError:
        pass
    else:
        output['iam.list_groups_for_user'] = remove_metadata(user_groups)

        logger.info(
            'User "%s" has %0d groups associated',
            user_name,
            len(user_groups['Groups'])
        )

    output['iam.list_group_policies'] = dict()

    for group in user_groups['Groups']:
        try:
            group_policy = iam_client.list_group_policies(GroupName=group['GroupName'])

            output['iam.list_group_policies'][group['GroupName']] = remove_metadata(group_policy)

            logger.info(
                '-- Group "%s" has %0d inline policies',
                group['GroupName'],
                len(group_policy['PolicyNames'])
            )

            for policy in group_policy['PolicyNames']:
                logger.info('---- Policy "%s"', policy)
        except botocore.exceptions.ClientError:
            pass

    return output

