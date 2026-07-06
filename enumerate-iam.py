#!/usr/bin/env python
import json
import argparse

from enumerate_iam.main import enumerate_iam, json_encoder


def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM permissions')

    # Omit to use boto3's default chain (env/profile/role); prefer that over
    # passing keys on the CLI, which leak into `ps` and shell history.
    parser.add_argument('--access-key', help='AWS access key (else env/profile)')
    parser.add_argument('--secret-key', help='AWS secret key (else env/profile)')
    parser.add_argument('--session-token', help='STS session token')
    parser.add_argument('--region', help='AWS region to send API requests to', default='us-east-1')
    parser.add_argument('--endpoint-url', help='Override the AWS endpoint URL (e.g. a localstack or proxy URL)')
    parser.add_argument('--dry-run', action='store_true',
                        help='List the operations that would be tested and exit, without calling AWS')
    parser.add_argument('--output', metavar='FILE',
                        help='Write JSON results to FILE instead of stdout')
    parser.add_argument('--verbose', action='store_true',
                        help='Show all progress chatter (default shows only findings, identity and summary)')

    args = parser.parse_args()

    output = enumerate_iam(args.access_key,
                           args.secret_key,
                           args.session_token,
                           args.region,
                           endpoint_url=args.endpoint_url,
                           dry_run=args.dry_run,
                           verbose=args.verbose)

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
