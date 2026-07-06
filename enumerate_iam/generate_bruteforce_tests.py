"""
Regenerate BRUTEFORCE_TESTS from the installed botocore models.

Service and operation names are taken straight from botocore, so every entry
is guaranteed to match a real boto3 client method that accepts zero arguments.
Run after upgrading boto3/botocore to refresh coverage:

    python -m enumerate_iam.generate_bruteforce_tests
"""
import os
import json

import botocore.session
from botocore import xform_name

OUTPUT_FMT = 'BRUTEFORCE_TESTS = %s\n'
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), 'bruteforce_tests.py')

# Only probe read-only operations that leak information.
OPERATION_PREFIXES = ('list_', 'describe_', 'get_')

# Operations that are read-only by name but noisy, dangerous, or known to
# behave badly when called blind. See original tool history for provenance.
BLACKLIST_OPERATIONS = {
    'get_apis',
    'get_bucket_notification',
    'get_bucket_notification_configuration',
    'list_web_ac_ls',
    'get_hls_streaming_session_url',
    'get_dash_streaming_session_url',
    'describe_scaling_plans',
    'list_certificate_authorities',
    'list_event_sources',
    'get_geo_location',
    'get_checker_ip_ranges',
    'list_geo_locations',
    'list_public_keys',

    # https://twitter.com/AndresRiancho/status/1106680434442809350
    'describe_stacks',
    'describe_service_errors',
    'describe_application_versions',
    'describe_applications',
    'describe_environments',
    'describe_events',
    'list_available_solution_stacks',
    'list_platform_versions',
}


def zero_arg_readonly_operations(service_model):
    operations = []

    for operation_name in service_model.operation_names:
        method_name = xform_name(operation_name)

        if not method_name.startswith(OPERATION_PREFIXES):
            continue

        if method_name in BLACKLIST_OPERATIONS:
            continue

        input_shape = service_model.operation_model(operation_name).input_shape
        if input_shape is not None and input_shape.required_members:
            # Cannot be called without arguments.
            continue

        operations.append(method_name)

    operations = sorted(set(operations))
    return operations


def main():
    session = botocore.session.get_session()
    bruteforce_tests = {}

    for service_name in session.get_available_services():
        service_model = session.get_service_model(service_name)
        operations = zero_arg_readonly_operations(service_model)

        if operations:
            bruteforce_tests[service_name] = operations

    output = OUTPUT_FMT % json.dumps(bruteforce_tests, indent=4, sort_keys=True)

    with open(OUTPUT_FILE, 'w') as handle:
        handle.write(output)

    total = sum(len(v) for v in bruteforce_tests.values())
    print('Wrote %d operations across %d services to %s'
          % (total, len(bruteforce_tests), OUTPUT_FILE))


if __name__ == '__main__':
    main()
