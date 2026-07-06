#!/usr/bin/env python
import json
import argparse

from enumerate_iam.main import enumerate_iam
from enumerate_iam.utils.json_utils import json_encoder


def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM permissions')

    # Optional: when omitted, boto3's default credential chain is used
    # (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY env vars, AWS_PROFILE, shared
    # config files, or an instance/container role). Passing keys on the command
    # line leaks them into `ps` output and shell history, so the env/profile
    # path is preferred.
    parser.add_argument('--access-key', help='AWS access key (else env/profile)')
    parser.add_argument('--secret-key', help='AWS secret key (else env/profile)')
    parser.add_argument('--session-token', help='STS session token')
    parser.add_argument('--region', help='AWS region to send API requests to', default='us-east-1')
    parser.add_argument('--endpoint-url', help='Override the AWS endpoint URL (e.g. a localstack or proxy URL)')
    parser.add_argument('--dry-run', action='store_true',
                        help='List the operations that would be tested and exit, without calling AWS')
    parser.add_argument('--output', metavar='FILE',
                        help='Write JSON results to FILE instead of stdout')

    args = parser.parse_args()

    output = enumerate_iam(args.access_key,
                           args.secret_key,
                           args.session_token,
                           args.region,
                           endpoint_url=args.endpoint_url,
                           dry_run=args.dry_run)

    if not args.dry_run:
        results = json.dumps(output, indent=4, default=json_encoder, sort_keys=True)
        if args.output:
            with open(args.output, 'w') as handle:
                handle.write(results + '\n')
            print('Results written to %s' % args.output)
        else:
            print(results)


if __name__ == '__main__':
    main()
