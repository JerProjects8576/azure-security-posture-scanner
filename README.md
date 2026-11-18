# Azure security posture scanner

[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

A small Python command-line tool that checks Azure resources for common security
misconfigurations: public storage, open management ports, exposed Key Vaults, weak TLS
and more. Every finding comes with a severity, a fix and the MITRE ATT&CK technique it
helps prevent.

It works in two ways:

- **Offline**, on a JSON export of your resources. No Azure account needed, which is how
  the tests and the pipeline run.
- **Live**, against a real subscription through Azure Resource Graph, with read-only access.

Reports come out as a table for the terminal, Markdown for pull requests, JSON for other
tools, or SARIF for security dashboards. The exit code makes it easy to fail a pipeline on
serious findings.

## Quick start

```bash
pip install -e ".[dev]"
azposture --input examples/sample-resources.json
```

```text
SEVERITY  RULE        RESOURCE      DETAIL
CRITICAL  AZ-NSG-002  nsg-demo-vm   rule 'allow-everything' allows all ports from the internet
HIGH      AZ-KV-002   kv-demo-open  publicNetworkAccess is Enabled and networkAcls.defaultAction is Allow
HIGH      AZ-NSG-001  nsg-demo-vm   rule 'allow-rdp' allows RDP (port 3389) from the internet
...
11 finding(s) in 8 resource(s) (1 critical, 4 high, 6 medium, 0 low); 1 resource(s) of unsupported types skipped
```

The example file contains insecure resources on purpose, next to secure ones that should
not be flagged.

## Usage

```bash
# Other formats, written to a file
azposture -i resources.json -f markdown -o report.md
azposture -i resources.json -f sarif -o report.sarif

# Only show high and critical, fail the pipeline only on critical
azposture -i resources.json --min-severity high --fail-on critical

# List all rules
azposture --list-rules
```

| Exit code | Meaning |
| --- | --- |
| 0 | No findings at or above `--fail-on` (default: `high`) |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Invalid input or arguments |

### Scanning a real subscription

```bash
pip install -e ".[live]"
az login
azposture --subscription <subscription-id>
```

The tool signs in with `DefaultAzureCredential` (your `az login`, a managed identity, or
the `AZURE_*` environment variables) and only reads. The **Reader** role is enough.

You can also export the resources yourself and scan the file later:

```bash
az graph query -q "Resources | project id, name, type, location, properties" --first 1000 > resources.json
azposture -i resources.json
```

Both a plain JSON list and the `{"data": [...]}` output of `az graph query` are accepted.

## Rules

| ID | Severity | Check | MITRE ATT&CK |
| --- | --- | --- | --- |
| AZ-STG-001 | high | Storage account allows anonymous blob access | T1530 Data from Cloud Storage |
| AZ-STG-002 | medium | Storage account accepts unencrypted HTTP | T1557 Adversary-in-the-Middle |
| AZ-STG-003 | medium | Storage account allows TLS older than 1.2 | T1557 Adversary-in-the-Middle |
| AZ-KV-001 | medium | Key Vault purge protection is disabled | T1485 Data Destruction |
| AZ-KV-002 | high | Key Vault is reachable from the whole internet | T1555.006 Cloud Secrets Management Stores |
| AZ-NSG-001 | high | SSH or RDP is open to the internet | T1021 Remote Services, T1110 Brute Force |
| AZ-NSG-002 | critical | All inbound ports are open to the internet | T1190 Exploit Public-Facing Application |
| AZ-APP-001 | medium | Web app accepts unencrypted HTTP | T1557 Adversary-in-the-Middle |
| AZ-APP-002 | medium | Web app allows TLS older than 1.2 | T1557 Adversary-in-the-Middle |
| AZ-SQL-001 | medium | SQL server allows public network access | T1190 Exploit Public-Facing Application |
| AZ-SQL-002 | high | SQL firewall allows every IP address | T1190 Exploit Public-Facing Application |

Each rule is a short Python function in [`src/azposture/rules.py`](src/azposture/rules.py),
registered with a decorator. Adding a rule means writing one function and one test.

## How it is built

```text
src/azposture/
  models.py     Resource, Rule, Finding and Severity
  rules.py      the security checks
  scanner.py    loads resources and runs the rules
  reporters.py  table, Markdown, JSON and SARIF output
  live.py       fetches resources from Azure Resource Graph, with pagination
  cli.py        command-line interface and exit codes
tests/          47 tests, 99% coverage, no Azure account needed
```

Design choices:

- **No dependencies for the core.** The Azure SDK is only needed for live mode, so the
  tool installs and tests in seconds.
- **Testable live mode.** The Resource Graph client is passed in, so the pagination logic
  is tested with a fake client.
- **Tolerant input.** Property names are matched case-insensitively and `"true"`/`true`
  are both understood, because Azure exports are not always consistent.
- **Secure examples in the test data.** Every rule is tested for false positives too,
  for example SSH that is only open to an office IP is not reported.

## Pipeline

On every push and pull request GitHub Actions:

1. runs `ruff` for linting and formatting,
2. runs the tests with coverage on Python 3.10 and 3.12 (minimum 90%),
3. scans the example environment, shows the Markdown report in the job summary and
   uploads the Markdown and SARIF reports as an artifact.

## Limitations and next steps

- SQL firewall rules are child resources and are not returned by the default Resource
  Graph query; they are checked when they are in the input file.
- More rules: diagnostic settings, Defender for Cloud plans, managed identities instead
  of keys, and private endpoints for more services.
- Suppressions with a reason, so accepted risks do not keep failing the pipeline.

## License

MIT
