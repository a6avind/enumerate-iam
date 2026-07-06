## Enumerate IAM permissions

Found a set of AWS credentials and have no idea which permissions it might have?

```console
$ ./enumerate-iam.py --access-key AKIA... --secret-key StF0q...
[INFO] -- Account ARN : arn:aws:iam::123456789012:user/bob
[INFO] -- Account Id  : 123456789012
[INFO] Run for the hills, get_account_authorization_details worked!
[INFO] -- gamelift.list_builds() worked!
[INFO] -- cloudformation.list_stack_sets() worked!
[INFO] -- sqs.list_queues() worked!
[INFO] -- lambda.list_functions() worked!
[INFO] -- Possible secret at bruteforce.lambda.list_functions.Functions[0].Environment.Variables.DB_PASSWORD (secret-named key 'DB_PASSWORD')
[INFO] Enumeration complete: 5 actions confirmed (1 IAM, 4 brute force, 0 all-services, 0 probe). 1 possible secret(s) flagged.
```

The terminal shows only the results — the caller's identity (cyan), the found
permissions (green), and a summary — with the routine progress chatter hidden
(pass `--verbose` for the full log). The complete JSON is written to an
auto-named file (`enumerate-iam-<account-id>.json`) rather than dumped to the
screen; use `--output -` to send it to stdout for piping to `jq`. Now you do!

`enumerate-iam.py` tries to brute force all API calls allowed by the IAM policy.
The calls performed by this tool are all non-destructive (only get* and list*
calls are performed).

## Usage

```
--access-key      AWS access key (optional, see credentials below)
--secret-key      AWS secret key (optional, see credentials below)
--session-token   STS session token
--profile         Named profile from the shared AWS credentials file
--region          AWS region to send API requests to (default: us-east-1)
--endpoint-url    Override the AWS endpoint URL (e.g. a localstack or proxy URL)
--output FILE     Where to write full JSON results: a path, or - for stdout
                  (default: auto-named enumerate-iam-<account-id>.json)
--services LIST   Limit the scan to these services (comma-separated, e.g. s3,ec2)
--probe           Also confirm parameter-requiring read permissions via
                  error-code analysis (much broader coverage, slower)
--all-services    Sweep every zero-arg list/describe/get op across all services
                  (not just the curated set) and scan every response for secrets
                  (widest coverage, many calls, slow)
--threads N       Concurrent API calls (default 25; raise for --all-services,
                  lower to avoid throttling)
--timeout MINUTES Wall-clock cap on the brute-force/probe phases
--dry-run         List the operations that would be tested and exit
--verbose         Show all progress chatter (default shows only the results)
```

The caller's identity comes from `sts:GetCallerIdentity` (needs no permissions),
and every confirmed call is mapped to its IAM action — the result JSON includes a
`confirmed_actions` list (e.g. `s3:ListBuckets`) you can drop straight into a
policy.

### Coverage and `--probe`

The default pass only tests read operations callable with **no arguments**
(roughly a third of all `get*`/`list*`/`describe*` calls). `--probe` additionally
fires the parameter-requiring ones with dummy input and reads the error: an
authorization denial means "no permission", while a validation or not-found error
means the call passed authorization, so the permission *is* present. Best-effort
(a few results can be false positives), but it widens coverage from ~2400 to most
of AWS's ~7700 read operations.

`--all-services` takes the other axis: instead of confirming *permissions*, it
sweeps every zero-arg read op across all ~300 services (the full ~2400, not just
the hand-curated subset the default pass uses) and keeps the **response bodies**
so the secret scanner sees the widest possible surface. It's many calls and slow
— pair it with `--threads`, `--timeout`, and/or `--services`.

### Secret scanning

Every captured response is scanned for hardcoded secrets, and the hits land in a
`findings` list in the result JSON (and print in green). No extra API calls — the
data is already there. A `lambda.list_functions` response, for example, includes
each function's `Environment.Variables`, so a password hardcoded as an env var is
surfaced automatically. Detection covers:

 * **Secret-named keys** — env-var-style keys like `DB_PASSWORD`, `*_TOKEN`,
   `*SECRET*`, `CLIENT_SECRET` with a non-placeholder value.
 * **Known value patterns** — AWS access keys (`AKIA…`/`ASIA…`), PEM private
   keys, GitHub/Slack/Google tokens, JWTs, and DB connection strings that embed a
   password (`postgres://user:pass@…`).
 * **High-entropy strings** — random-looking tokens (base64 alphabet, ≥4.0
   bits/char) even under an unremarkable key name. Pure hex is skipped to avoid
   flagging hashes/resource ids.
 * **Base64-wrapped secrets** — values that decode to printable text are decoded
   and re-scanned, catching secrets stashed as base64.

Reported values are redacted (`Sup***************d!!`); the raw secret is never
written to the results.

The widest surface comes from combining this with `--all-services`, which pulls
*every* zero-arg read response (Lambda env vars, ECS task-defs, CloudFormation
parameters, SSM, …) through the scanner.

### Credentials

`--access-key` / `--secret-key` are optional. When omitted, the tool uses
boto3's default credential chain: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
environment variables, a shared profile (`AWS_PROFILE` + `~/.aws/credentials`),
or an instance/container role. Prefer these over passing keys on the command
line, which leaks them into `ps` output and shell history.

## Installation

```
git clone git@github.com:a6avind/enumerate-iam.git
cd enumerate-iam/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Or install it as a package to get an `enumerate-iam` command on your `PATH`:

```
pip install .
enumerate-iam --help
```

Requires Python 3. Tested on Python 3.14 with boto3/botocore 1.43.

## Library

This software was written to be easy to integrate with other tools, just import
the main function and provide the required arguments:

```python
from enumerate_iam.main import enumerate_iam

results = enumerate_iam(access_key,
                        secret_key,
                        session_token,
                        region,
                        endpoint_url=None,
                        dry_run=False,
                        verbose=False,
                        services=None,
                        probe=False,
                        all_services=False,
                        threads=25)
```

The returned value is a python dictionary containing all the enumerated
permission information, plus a `findings` list of any secrets spotted in the
captured responses.

## Other tools

Before writing `enumerate-iam.py` I tried a few that performed the same task.
Decided to write my own because the others:

 * Did not check for all API calls
 * Where painfully slow when adding more API calls to the list
 * Did not return the permissions in a programmatic way

## Updating the API calls

The API calls to be performed during permission enumeration are stored in
`enumerate_iam/bruteforce_tests.py`, a Python dict() which is generated by
`enumerate_iam/generate_bruteforce_tests.py` directly from the installed
botocore models. Every entry is guaranteed to match a real boto3 client method
that accepts zero arguments.

AWS releases new services every quarter, to make sure that this tool is finding
all the existing permissions upgrade boto3/botocore and regenerate:

```console
pip install --upgrade boto3 botocore
python -m enumerate_iam.generate_bruteforce_tests
```

## Related tools

This tool was released as part of the [Internet-Scale Analysis of AWS Cognito Security](https://www.blackhat.com/us-19/briefings/schedule/?hootPostID=4abc475398765919352042ac015752e6#internet-scale-analysis-of-aws-cognito-security-15829)
research. During this research the [cc-lambda](https://github.com/andresriancho/cc-lambda) tool
was also used to extract information from the Common Crawl data.

## Initial code

The initial code was released in [this gist](https://gist.github.com/darkarnium/1df59865f503355ef30672168063da4e)
and improved in multiple ways:

 * Complete refactoring
 * Results returned in a programmatic way
 * Threads
 * Improved logging
 * Increased API call coverage
 * Export as a library
