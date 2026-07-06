import sys
import json
import argparse

import boto3

from enumerate_iam.main import enumerate_iam, json_encoder, account_id, MAX_THREADS

AUTO_OUTPUT = '\x00auto'
STDOUT = '-'


def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM permissions')

    # Omit to use boto3's default chain (env/profile/role); prefer that over
    # passing keys on the CLI, which leak into `ps` and shell history.
    parser.add_argument('--access-key', help='AWS access key (else env/profile)')
    parser.add_argument('--secret-key', help='AWS secret key (else env/profile)')
    parser.add_argument('--session-token', help='STS session token')
    parser.add_argument('--profile', help='Named profile from the shared AWS credentials file')
    parser.add_argument('--region', help='AWS region to send API requests to', default='us-east-1')
    parser.add_argument('--endpoint-url', help='Override the AWS endpoint URL (e.g. a localstack or proxy URL)')
    parser.add_argument('--output', metavar='FILE', default=AUTO_OUTPUT,
                        help='Where to write the full JSON results: a path, or - for stdout. '
                             'Default: an auto-named file enumerate-iam-<account-id>.json')
    parser.add_argument('--services', metavar='LIST',
                        help='Comma-separated services to limit the scan to (e.g. s3,ec2,iam)')
    parser.add_argument('--probe', action='store_true',
                        help='Also confirm parameter-requiring read permissions via error-code '
                             'analysis (much broader coverage, slower)')
    parser.add_argument('--all-services', action='store_true',
                        help='Sweep every zero-arg list/describe/get op across all AWS services '
                             '(not just the curated set) and scan every response for secrets '
                             '(widest coverage, many calls, slow)')
    parser.add_argument('--threads', metavar='N', type=int, default=MAX_THREADS,
                        help='Concurrent API calls (default %(default)s; raise for the '
                             '--all-services sweep, lower to avoid throttling)')
    parser.add_argument('--timeout', metavar='MINUTES', type=float,
                        help='Wall-clock cap on the brute-force/probe phases')
    parser.add_argument('--dry-run', action='store_true',
                        help='List the operations that would be tested and exit, without calling AWS')
    parser.add_argument('--verbose', action='store_true',
                        help='Show all progress chatter (default shows only findings, identity and summary)')

    args = parser.parse_args()

    access_key, secret_key, session_token = args.access_key, args.secret_key, args.session_token
    if args.profile:
        if access_key or secret_key or session_token:
            parser.error('--profile is mutually exclusive with --access-key/--secret-key')
        creds = boto3.Session(profile_name=args.profile).get_credentials()
        if creds is None:
            parser.error('profile %r has no credentials' % args.profile)
        frozen = creds.get_frozen_credentials()
        access_key, secret_key, session_token = frozen.access_key, frozen.secret_key, frozen.token

    services = None
    if args.services:
        services = {s.strip() for s in args.services.split(',') if s.strip()}

    output = enumerate_iam(access_key,
                           secret_key,
                           session_token,
                           args.region,
                           endpoint_url=args.endpoint_url,
                           dry_run=args.dry_run,
                           verbose=args.verbose,
                           services=services,
                           probe=args.probe,
                           all_services=args.all_services,
                           threads=args.threads,
                           timeout=args.timeout * 60 if args.timeout else None)

    if not args.dry_run:
        results = json.dumps(output, indent=4, default=json_encoder, sort_keys=True)
        if args.output == STDOUT:
            print(results)
        else:
            dest = args.output
            if dest == AUTO_OUTPUT:
                dest = 'enumerate-iam-%s.json' % (account_id(output) or 'unknown')
            with open(dest, 'w') as handle:
                handle.write(results + '\n')
            print('Full results written to %s' % dest)


if __name__ == '__main__':
    main()
