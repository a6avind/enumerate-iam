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
import random
import logging
import datetime
import boto3
import botocore
import botocore.session

from botocore.client import Config
from botocore.endpoint import MAX_POOL_CONNECTIONS
from multiprocessing.dummy import Pool as ThreadPool

from enumerate_iam.bruteforce_tests import BRUTEFORCE_TESTS

MAX_THREADS = 25
CLIENT_POOL = {}

# max_attempts was 30, which made unreachable endpoints hang for minutes.
BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=5,
    retries={'max_attempts': 3},
    max_pool_connections=MAX_POOL_CONNECTIONS * 2,
)

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
    iam = output.get('iam', {})
    if iam.get('arn_id'):
        return iam['arn_id']

    arn = iam.get('iam.get_user', {}).get('User', {}).get('Arn')
    if arn and len(arn.split(':')) > 4:
        return arn.split(':')[4]

    return None


def report_arn(candidate):
    """
    Attempt to extract and slice up an ARN from the input string
    """
    logger = logging.getLogger()

    arn_search = re.search(r'.*(arn:aws:.*?) .*', candidate)

    if arn_search:
        arn = arn_search.group(1)

        arn_id = arn.split(':')[4]
        arn_path = arn.split(':')[5]

        logger.info('-- Account ARN : %s', arn)
        logger.info('-- Account Id  : %s', arn_id)
        logger.info('-- Account Path: %s', arn_path)

        return arn, arn_id, arn_path

    return None, None, None


def enumerate_using_bruteforce(access_key, secret_key, session_token, region, endpoint_url=None):
    """
    Attempt to brute-force common describe calls.
    """
    output = dict()

    logger = logging.getLogger()
    logger.info('Attempting common-service describe / list brute force.')

    pool = ThreadPool(MAX_THREADS)
    args_generator = generate_args(access_key, secret_key, session_token, region, endpoint_url)

    try:
        try:
            results = pool.map(check_one_permission, args_generator)
        except KeyboardInterrupt:
            print('')
            logger.info('Ctrl+C received, stopping all threads.')
            logger.info('Hit Ctrl+C again to force exit.')
            return output

        for thread_result in results:
            if thread_result is None:
                continue

            key, action_result = thread_result
            output[key] = action_result
    finally:
        # terminate() frees the pool's semaphores; close()/join() alone leaks them.
        pool.terminate()
        pool.join()

    return output


def generate_args(access_key, secret_key, session_token, region, endpoint_url):

    service_names = list(BRUTEFORCE_TESTS.keys())

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

    try:
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


class ColorFormatter(logging.Formatter):
    GREEN = '\033[32m'
    CYAN = '\033[36m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    RESET = '\033[0m'

    # Honour NO_COLOR (https://no-color.org) and skip colours when not a TTY.
    enabled = sys.stderr.isatty() and 'NO_COLOR' not in os.environ

    # Found permissions and the run summary.
    HITS = ('worked!', 'Run for the hills', 'root credentials', 'Enumeration complete')
    # Caller identity — shown even in the default (filtered) view.
    ACCOUNT = ('Account ARN', 'Account Id', 'Account Path')

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
    # Keep results and warnings/errors; drop the routine progress chatter.
    return (record.levelno >= logging.WARNING
            or any(hit in record.getMessage()
                   for hit in ColorFormatter.HITS + ColorFormatter.ACCOUNT))


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


def enumerate_iam(access_key, secret_key, session_token, region, endpoint_url=None,
                  dry_run=False, verbose=False):
    """IAM Account Enumerator.

    This code provides a mechanism to attempt to validate the permissions assigned
    to a given set of AWS tokens.
    """
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

    output['iam'] = enumerate_using_iam(access_key, secret_key, session_token, region, endpoint_url)
    output['bruteforce'] = enumerate_using_bruteforce(access_key, secret_key, session_token, region, endpoint_url)

    iam_hits = sum(1 for key in output['iam'] if key.startswith('iam.'))
    logger.info('Enumeration complete: %d API calls succeeded (%d IAM, %d brute force).',
                iam_hits + len(output['bruteforce']), iam_hits, len(output['bruteforce']))

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
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_attached_role_policies'] = remove_metadata(role_policies)

        logger.info(
            'Role "%s" has %0d attached policies',
            role['Role']['RoleName'],
            len(role_policies['AttachedPolicies'])
        )

        for policy in role_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

    try:
        role_policies = iam_client.list_role_policies(RoleName=role_name)
    except botocore.exceptions.ClientError as err:
        pass
    else:
        output['iam.list_role_policies'] = remove_metadata(role_policies)

        logger.info(
            'User "%s" has %0d inline policies',
            role['Role']['RoleName'],
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
    except botocore.exceptions.ClientError as err:
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
    except botocore.exceptions.ClientError as err:
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
    except botocore.exceptions.ClientError as err:
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
        except botocore.exceptions.ClientError as err:
            pass

    return output

