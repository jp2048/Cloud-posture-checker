# Cloud Security Posture Checker

A read-only, CIS Benchmark-aligned posture scanner for Azure and AWS — a
mini-CSPM you can run from a laptop or in CI. It evaluates cloud resources
against common misconfigurations, reports pass/fail per resource, and emits
actionable remediation guidance.

Live scans use the official SDKs (`azure-mgmt-*`, `boto3`) with the standard
credential chains — no credentials are ever hardcoded. A `--demo` mode runs
the exact same check logic against realistic synthetic data in `demo_data/`,
so the whole workflow is demonstrable with zero cloud access.

## Checks

11 checks across both providers. CIS references are best-effort mappings
against the CIS Microsoft Azure Foundations Benchmark v2.0 and the CIS AWS
Foundations Benchmark v1.5 — validate them against the official benchmarks
before audit use.

| Check ID | Title | CIS ref | Severity |
| --- | --- | --- | --- |
| AZR-001 | Storage account allows public blob access | CIS Azure 3.2 | High |
| AZR-002 | NSG allows internet ingress on sensitive ports (22/3389/1433/…) | CIS Azure 6.1/6.2 | High |
| AZR-003 | Key Vault without purge protection | CIS Azure 8.5 | Medium |
| AZR-004 | SQL server without Microsoft Defender for SQL | CIS Azure 2.1 | Medium |
| AZR-005 | No enforced Conditional Access policy requiring MFA for all users | CIS Azure 1.4 | High |
| AWS-001 | IAM user with console access but no MFA | CIS AWS 1.2 | High |
| AWS-002 | S3 bucket with public read access | CIS AWS 2.1.4 | High |
| AWS-003 | Security group allows internet ingress on sensitive ports | CIS AWS 4.1/4.2 | High |
| AWS-004 | CloudTrail logging or log-validation issue | CIS AWS 3.1/3.2 | High |
| AWS-005 | Root account has active access keys | CIS AWS 1.12 | Critical |
| AWS-006 | EBS volume not encrypted | CIS AWS 2.2.1 | Medium |

Each check returns one finding per evaluated resource: check ID, title, CIS
reference, severity, resource, pass/fail status, evidence, and remediation
text. Checks that cannot be evaluated (e.g. missing Graph consent for AZR-005)
are reported with status `error`, never silently dropped.

## Setup

Requires Python 3.9+.

```bash
git clone <this-repo>
cd cloud-posture-checker
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Authentication

**Azure** — any `DefaultAzureCredential` source works:

```bash
az login
export AZURE_SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"
```

(A managed identity or service-principal environment variables work too. The
AZR-005 Conditional Access check additionally needs Microsoft Graph
`Policy.Read.All` consent and the optional `msgraph-sdk` package.)

**AWS** — the standard boto3 chain:

```bash
export AWS_REGION=us-east-1
# then one of:
aws sso login --profile my-profile   # or
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
```

The scan needs read-only IAM permissions, e.g. the AWS managed
`SecurityAudit` policy. For Azure, the built-in `Reader` role is sufficient,
plus `Policy.Read.All` on Microsoft Graph for AZR-005.

## Usage

```bash
# Demo mode — no credentials, runs against demo_data/
python3 checker.py --demo --provider all

# Live scans
python3 checker.py --provider azure
python3 checker.py --provider aws --region us-west-2

# Write reports (format inferred from extension)
python3 checker.py --demo --output report.md
python3 checker.py --demo --output report.json

# Explicit format, stdout
python3 checker.py --demo --format json | jq '.summary'
```

Exit codes: `0` = all checks passed, `1` = one or more failures/errors,
`2` = configuration problem (missing SDKs, credentials, or subscription).

## Demo walkthrough

The demo dataset (`demo_data/azure.json`, `demo_data/aws.json`) models a
small, imperfect environment: a storage account with public blob access, an
NSG exposing RDP to the internet, a Key Vault without purge protection, a SQL
server without Defender, a Conditional Access MFA policy stuck in report-only
mode, an IAM user without MFA, a public S3 bucket, an open security group, a
CloudTrail trail without log validation, active root access keys, and an
unencrypted EBS volume — alongside correctly configured counterparts so
passes are exercised too.

```bash
python3 checker.py --demo --provider all
```

Sample output (abridged — see [sample_report.md](sample_report.md) for the full report):

```
## Summary

- Resources evaluated: **21**
- Passed: **10**
- Failed: **11**
- Errors: **0**

### Failed findings by severity

| Severity | Count |
| --- | ---: |
| Critical | 1 |
| High | 7 |
| Medium | 3 |
| Low | 0 |

### [Critical] AWS-005 — Root account has active access keys

- **Resource:** `iam/root`
- **CIS reference:** CIS AWS 1.12
- **Evidence:** 1 active access key(s) found on the root account.
- **Remediation:** Delete the root access keys immediately (IAM > Users > root >
  Security credentials). Create least-privilege IAM users/roles for daily work
  and protect root with MFA stored offline.
```

JSON output (`--format json`) is designed for automation: a `scan` metadata
block, a `summary` block, and a `findings` array. Pipe it into `jq`, a SIEM,
or a ticketing workflow.

## Limitations

- **Read-only by design.** The tool reports findings; it does not remediate.
  Auto-remediation is a different risk profile and is intentionally out of scope.
- **Single region for AWS** (configurable via `AWS_REGION`); multi-region and
  multi-subscription aggregation is on the roadmap.
- **Demo data is synthetic.** It exercises the check logic but is not a
  substitute for a real environment.
- **AZR-005 needs Microsoft Graph** (`msgraph-sdk` + `Policy.Read.All`
  consent). Without it, the check reports `error` instead of guessing.
- **CIS mappings are approximate.** Treat them as a starting point, not an
  audit attestation.

## Roadmap

- GCP provider (Compute firewall rules, IAM, Cloud Storage, Cloud Audit Logs)
- Terraform plan output (`--format tfplan`-style findings for shift-left use)
- Multi-region / multi-subscription aggregation
- JUnit and SARIF output for CI pipelines
- Additional checks: Azure Defender coverage, S3 encryption, RDS backup retention
