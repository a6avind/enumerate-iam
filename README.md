## Enumerate IAM permissions

Found a set of AWS credentials and have no idea which permissions it might have?

```console
$ ./enumerate-iam.py --access-key AKIA... --secret-key StF0q...
[INFO] -- Account ARN : arn:aws:iam::123456789012:user/bob
[INFO] -- Account Id  : 123456789012
[INFO] Run for the hills, get_account_authorization_details worked!
[INFO] -- Possible secret: lambda.list_functions [arn:aws:lambda:us-east-1:123456789012:function:billing-prod] (DB_PASSWORD) (secret-named key 'DB_PASSWORD')
[INFO] Enumeration complete: 143 actions confirmed (1 IAM, 142 read, 0 probe) across 34 region(s). 1 possible secret(s) flagged.
```

The terminal stays quiet on purpose: it shows only the caller's identity, any
secrets found, root/critical hits, and the final summary. The per-operation
`worked!` confirmations and progress chatter are hidden (`--verbose` for the full
log). The complete JSON — every confirmed call and its full response — is written
to an auto-named file (`enumerate-iam-<account-id>.json`); use `--output -` to
send it to stdout for piping to `jq`.

Only non-destructive reads are performed (`get*`/`list*`/`describe*`). By default
the tool sweeps **every service** in **every region**, throttled low-and-slow, and
scans every captured response for hardcoded secrets.

## Usage

```
--access-key      AWS access key (optional, see credentials below)
--secret-key      AWS secret key (optional, see credentials below)
--session-token   STS session token
--profile         Named profile from the shared AWS credentials file
--region REGION   Limit to a single region (default: sweep every region).
                  Also the endpoint for the global IAM/STS calls.
--regions LIST    Sweep this comma-separated region list instead of all
--endpoint-url    Override the AWS endpoint URL (e.g. a localstack or proxy URL)
--output FILE     Where to write full JSON results: a path, or - for stdout
                  (default: auto-named enumerate-iam-<account-id>.json)
--services LIST   Limit the scan to these services (comma-separated, e.g. s3,ec2)
--curated         Only test the hand-picked set instead of sweeping every service
                  (faster, fewer calls)
--probe           Also confirm parameter-requiring read permissions via
                  error-code analysis (broader permission coverage, slower)
--entropy         Also flag high-entropy strings as possible secrets (noisier)
--threads N       Concurrent API calls (default 25; lower to avoid throttling)
--delay SECONDS   Base sleep before each API call (default 2.0; 0 disables)
--jitter SECONDS  Extra random 0..N seconds added to --delay per call (default 5.0)
--timeout MINUTES Wall-clock cap per region and per pass (not a global deadline)
--dry-run         List the operations that would be tested and exit
--verbose         Show all progress chatter (default shows only the useful lines)
```

The caller's identity comes from `sts:GetCallerIdentity` (needs no permissions),
and every confirmed call is mapped to its IAM action — the result JSON includes a
`confirmed_actions` list (e.g. `s3:ListBuckets`) you can drop straight into a
policy.

### Coverage

By default the tool sweeps **every zero-argument** `list*`/`describe*`/`get*`
operation across all ~300 services (~2400 calls), keeps every response, and
paginates each one (all pages, capped at 5000 items) so nothing is missed to a
first-page cutoff. `--curated` restricts this to a smaller hand-picked set
(`enumerate_iam/bruteforce_tests.py`) for a quick look.

`--probe` adds the parameter-requiring reads: it fires them with dummy input and
reads the error — an authorization denial means "no permission", while a
validation or not-found error means the call passed authorization, so the
permission *is* present. Best-effort (a few false positives), widening permission
coverage toward most of AWS's ~7700 read operations. Probe confirms authz only; it
does not capture a response body to scan.

### Multi-region

Lambda, EC2, and most services are regional, and regional secrets differ per
region, so by default the read pass runs in **every region** AWS advertises
(IAM/STS are global and run once). Narrow with `--region us-east-1` (single) or
`--regions us-east-1,eu-west-1` (a list). A custom `--endpoint-url` defaults to a
single region. In the JSON, multi-region response keys are tagged
`service.operation@region`, and each finding carries its `region`.

### Throttling

Each API call sleeps `--delay + random(0, --jitter)` seconds first — **2 to 7
seconds by default** — to stay low-and-slow under rate limits and detection.
Combined with all-services × all-regions this makes a default run deliberately
long; `--delay 0` disables throttling, and `--threads` / `--timeout` /
`--services` / `--region` bound the scope. Note `--timeout` caps each region and
each pass (read/probe) separately, not the whole run — an all-region sweep can run
many times the per-pass value.

### Secret scanning

Every captured response is scanned for hardcoded secrets, and the hits land in a
`findings` list in the result JSON (and print to the terminal). No extra API
calls — the data is already there. A `lambda.list_functions` response, for
example, includes each function's `Environment.Variables`, so a password
hardcoded as an env var is surfaced automatically. Detection covers:

 * **Secret-named keys** — env-var-style keys like `DB_PASSWORD`, `*_TOKEN`,
   `*SECRET*`, `CLIENT_SECRET` with a non-placeholder value.
 * **Known value patterns** — AWS access keys (`AKIA…`/`ASIA…`), PEM private
   keys, GitHub/Slack/Google tokens, JWTs, and DB connection strings that embed a
   password (`postgres://user:pass@…`).
 * **Base64-wrapped secrets** — values that decode to printable text are decoded
   and re-scanned, catching secrets stashed as base64.
 * **High-entropy strings** (`--entropy`, off by default) — random-looking tokens
   even under an unremarkable key name. Off by default because it's noisy; the
   other three are high-precision.

Each finding names the `service`, `operation`, `region`, the `resource` it
belongs to (its ARN/name, not an array index), the offending `key`, and the full
`value` — the plaintext is already in the raw response in the same file, so it is
reported in full to be directly actionable.

```json
{
  "service": "lambda",
  "operation": "list_functions",
  "region": "us-east-1",
  "resource": "arn:aws:lambda:us-east-1:123456789012:function:billing-prod",
  "key": "DB_PASSWORD",
  "value": "Sup3rSecretP@ssw0rd!!",
  "reasons": ["secret-named key 'DB_PASSWORD'"],
  "location": "bruteforce.lambda.list_functions@us-east-1.Functions[0].Environment.Variables.DB_PASSWORD"
}
```

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
                        full=True,          # sweep all services (False = curated set)
                        timeout=None,       # seconds, capped per region per pass (None = uncapped)
                        regions=None,       # list of regions (None = the single `region`)
                        threads=25,
                        delay=2.0,
                        jitter=5.0,
                        entropy=False)
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

The curated `--curated` set is stored in `enumerate_iam/bruteforce_tests.py`, a
Python dict() generated by `enumerate_iam/generate_bruteforce_tests.py` directly
from the installed botocore models. Every entry is guaranteed to match a real
boto3 client method that accepts zero arguments. (The default all-services sweep
enumerates the botocore models directly and needs no regeneration.)

AWS releases new services every quarter; to refresh the curated set upgrade
boto3/botocore and regenerate:

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
