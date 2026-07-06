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
import logging
import boto3
import botocore
import botocore.session
import random

from botocore.client import Config
from botocore.endpoint import MAX_POOL_CONNECTIONS
from multiprocessing.dummy import Pool as ThreadPool

from enumerate_iam.utils.remove_metadata import remove_metadata
from enumerate_iam.bruteforce_tests import BRUTEFORCE_TESTS

MAX_THREADS = 25
CLIENT_POOL = {}

# Shared client config. max_attempts was 30, which turned unreachable regional
# endpoints into multi-minute hangs (issue #14); 3 is plenty for throttling.
BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=5,
    retries={'max_attempts': 3},
    max_pool_connections=MAX_POOL_CONNECTIONS * 2,
)

# Errors that mean "this endpoint didn't answer usefully" — skip and move on.
RETRYABLE_ERRORS = (
    botocore.exceptions.ClientError,
    botocore.exceptions.EndpointConnectionError,
    botocore.exceptions.ConnectTimeoutError,
    botocore.exceptions.ReadTimeoutError,
)


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
        # terminate() (not just close/join) releases the pool's internal
        # semaphores, avoiding the leaked-semaphore warning at shutdown (#24).
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
    except RETRYABLE_ERRORS:
        return
    except botocore.exceptions.ParamValidationError:
        logger.error('Remove %s.%s action' % (service_name, operation_name))
        return

    msg = '-- %s.%s() worked!'
    args = (service_name, operation_name)
    logger.info(msg % args)

    key = '%s.%s' % (service_name, operation_name)

    return key, remove_metadata(action_response)


class ColorFormatter(logging.Formatter):
    GREEN = '\033[32m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    RESET = '\033[0m'

    # Honour NO_COLOR (https://no-color.org) and skip colours when not a TTY.
    enabled = sys.stderr.isatty() and 'NO_COLOR' not in os.environ

    HITS = ('worked!', 'Run for the hills', 'root credentials')

    def format(self, record):
        line = super().format(record)
        if not self.enabled:
            return line

        if record.levelno >= logging.ERROR:
            colour = self.RED
        elif record.levelno == logging.WARNING:
            colour = self.YELLOW
        elif any(hit in record.getMessage() for hit in self.HITS):
            colour = self.GREEN
        else:
            return line

        return '%s%s%s' % (colour, line, self.RESET)


def configure_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter(
        '%(asctime)s - %(process)d - [%(levelname)s] %(message)s'
    ))
    logging.basicConfig(level=logging.INFO, handlers=[handler])

    # Suppress boto INFO.
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('nose').setLevel(logging.WARNING)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # import botocore.vendored.requests.packages.urllib3 as urllib3
    urllib3.disable_warnings(botocore.vendored.requests.packages.urllib3.exceptions.InsecureRequestWarning)


def enumerate_iam(access_key, secret_key, session_token, region, endpoint_url=None, dry_run=False):
    """IAM Account Enumerator.

    This code provides a mechanism to attempt to validate the permissions assigned
    to a given set of AWS tokens.
    """
    output = dict()
    configure_logging()
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
        # Fall back to boto3's default credential chain (env vars, shared
        # config/profile, instance role). Fail early with a clear message if it
        # resolves to nothing, rather than crashing mid-enumeration.
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

    return output


def enumerate_using_iam(access_key, secret_key, session_token, region, endpoint_url=None):
    output = dict()
    logger = logging.getLogger()

    # Connect to the IAM API and start testing.
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

    # Try for the kitchen sink.
    try:
        everything = iam_client.get_account_authorization_details()
    except RETRYABLE_ERRORS:
        pass
    else:
        logger.info('Run for the hills, get_account_authorization_details worked!')

        output['iam.get_account_authorization_details'] = remove_metadata(everything)

    enumerate_user(iam_client, output)
    enumerate_role(iam_client, output)

    return output


def enumerate_role(iam_client, output):
    logger = logging.getLogger()

    # This is the closest thing we have to a role ARN
    user_or_role_arn = output.get('arn', None)

    if user_or_role_arn is None:
        # The checks which follow all required the user name to run, if we were
        # unable to get that piece of information just return
        return

    # Attempt to get role to start.
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

    # Attempt to get policies attached to this user.
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

        # List all policies, if present.
        for policy in role_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

    # Attempt to get inline policies for this user.
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

        # List all policies, if present.
        for policy in role_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

    return output


def enumerate_user(iam_client, output):
    logger = logging.getLogger()
    output['root_account'] = False

    # Attempt to get user to start.
    try:
        user = iam_client.get_user()
    except RETRYABLE_ERRORS as err:
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
            # OMG
            logger.warning('Found root credentials!')
            output['root_account'] = True
            return
        else:
            logger.error('Unexpected iam.get_user() response: %s' % user)
            return
    else:
        user_name = user['User']['UserName']

    # Attempt to get policies attached to this user.
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

        # List all policies, if present.
        for policy in user_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])

    # Attempt to get inline policies for this user.
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

        # List all policies, if present.
        for policy in user_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

    # Attempt to get the groups attached to this user.
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

    # Attempt to get the group policies
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

            # List all group policy names.
            for policy in group_policy['PolicyNames']:
                logger.info('---- Policy "%s"', policy)
        except botocore.exceptions.ClientError as err:
            pass

    return output

