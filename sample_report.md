# Cloud Security Posture Report

> **Example report** — generated with `python3 checker.py --demo --provider all`.
> All resources below are synthetic data from `demo_data/`; no real cloud
> resources were scanned.

Generated: `2026-10-04T22:11:44.393710+00:00`
Providers: azure, aws
Mode: `demo`
Checks run: 11

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

## Findings

| Check | Severity | Resource | Status | CIS |
| --- | --- | --- | --- | --- |
| AWS-005 | Critical | `iam/root` | FAIL | CIS AWS 1.12 |
| AWS-001 | High | `iam-user/alice.dev` | PASS | CIS AWS 1.2 |
| AWS-001 | High | `iam-user/bob.ops` | FAIL | CIS AWS 1.2 |
| AWS-001 | High | `iam-user/carol.sec` | PASS | CIS AWS 1.2 |
| AWS-002 | High | `s3/acme-private-data` | PASS | CIS AWS 2.1.4 |
| AWS-002 | High | `s3/acme-public-assets` | FAIL | CIS AWS 2.1.4 |
| AWS-003 | High | `sg/sg-0a1b2c3d4e5f60718 (web-sg, vpc: vpc-0123456789abcdef0)` | FAIL | CIS AWS 4.1/4.2 |
| AWS-003 | High | `sg/sg-9a8b7c6d5e4f30291 (db-sg, vpc: vpc-0123456789abcdef0)` | PASS | CIS AWS 4.1/4.2 |
| AWS-004 | High | `cloudtrail/org-trail` | FAIL | CIS AWS 3.1/3.2 |
| AZR-001 | High | `storage/stappprod001 (rg: rg-prod)` | FAIL | CIS Azure 3.2 |
| AZR-001 | High | `storage/stbackups002 (rg: rg-prod)` | PASS | CIS Azure 3.2 |
| AZR-002 | High | `nsg/nsg-db-prod (rg: rg-prod)` | PASS | CIS Azure 6.1/6.2 |
| AZR-002 | High | `nsg/nsg-web-prod (rg: rg-prod)` | FAIL | CIS Azure 6.1/6.2 |
| AZR-005 | High | `tenant/conditional-access` | FAIL | CIS Azure 1.4 |
| AWS-006 | Medium | `ebs/vol-0aaa111bbb222ccc33 (100 GiB, us-east-1a)` | PASS | CIS AWS 2.2.1 |
| AWS-006 | Medium | `ebs/vol-0ddd444eee555fff66 (50 GiB, us-east-1b)` | FAIL | CIS AWS 2.2.1 |
| AWS-006 | Medium | `ebs/vol-0ggg777hhh888iii99 (200 GiB, us-east-1c)` | PASS | CIS AWS 2.2.1 |
| AZR-003 | Medium | `keyvault/kv-prod-keys (rg: rg-prod)` | PASS | CIS Azure 8.5 |
| AZR-003 | Medium | `keyvault/kv-prod-secrets (rg: rg-prod)` | FAIL | CIS Azure 8.5 |
| AZR-004 | Medium | `sql/sql-prod-001 (rg: rg-prod)` | FAIL | CIS Azure 2.1 |
| AZR-004 | Medium | `sql/sql-prod-002 (rg: rg-prod)` | PASS | CIS Azure 2.1 |

## Remediation guidance (failed findings)

### [Critical] AWS-005 — Root account has active access keys

- **Resource:** `iam/root`
- **CIS reference:** CIS AWS 1.12
- **Evidence:** 1 active access key(s) found on the root account.
- **Remediation:** Delete the root access keys immediately (IAM > Users > root > Security credentials). Create least-privilege IAM users/roles for daily work and protect root with MFA stored offline.

### [High] AWS-001 — IAM user with console access but no MFA

- **Resource:** `iam-user/bob.ops`
- **CIS reference:** CIS AWS 1.2
- **Evidence:** Console access is enabled but no MFA device is assigned.
- **Remediation:** Enable MFA for the user: IAM > Users > bob.ops > Security credentials > Assign MFA device. Enforce with the aws:MultiFactorAuthPresent condition in IAM policies.

### [High] AWS-002 — S3 bucket with public read access

- **Resource:** `s3/acme-public-assets`
- **CIS reference:** CIS AWS 2.1.4
- **Evidence:** Bucket is publicly readable (bucket policy allows s3:GetObject for *).
- **Remediation:** Enable all four S3 Block Public Access settings at the account and bucket level, remove public ACL grants and public bucket-policy statements, and re-verify with the policy status check.

### [High] AWS-003 — Security group allows internet ingress on sensitive ports

- **Resource:** `sg/sg-0a1b2c3d4e5f60718 (web-sg, vpc: vpc-0123456789abcdef0)`
- **CIS reference:** CIS AWS 4.1/4.2
- **Evidence:** Ingress from 0.0.0.0/0 on: 22 (SSH).
- **Remediation:** Replace 0.0.0.0/0 with specific CIDRs, security-group references, or remove the rule and use SSM Session Manager / a bastion host.

### [High] AWS-004 — CloudTrail logging or log validation issue

- **Resource:** `cloudtrail/org-trail`
- **CIS reference:** CIS AWS 3.1/3.2
- **Evidence:** Log file validation is disabled.
- **Remediation:** Enable log file validation and multi-region coverage on the trail (CloudTrail > Trails > Edit). Validation lets you detect tampering with delivered log files.

### [High] AZR-001 — Storage account allows public blob access

- **Resource:** `storage/stappprod001 (rg: rg-prod)`
- **CIS reference:** CIS Azure 3.2
- **Evidence:** allow_blob_public_access is enabled on this storage account.
- **Remediation:** Set 'Allow Blob public access' to Disabled on the storage account (Storage account > Configuration). Audit existing containers for Public access level = Blob/Container and revert to Private.

### [High] AZR-002 — NSG allows internet ingress on sensitive ports

- **Resource:** `nsg/nsg-web-prod (rg: rg-prod)`
- **CIS reference:** CIS Azure 6.1/6.2
- **Evidence:** Inbound from internet on: port 3389 (RDP) via rule 'allow-rdp-any'.
- **Remediation:** Restrict the listed rules to known source IPs, a bastion host, or remove them and use just-in-time VM access / Azure Bastion instead.

### [High] AZR-005 — No enforced Conditional Access policy requiring MFA for all users

- **Resource:** `tenant/conditional-access`
- **CIS reference:** CIS Azure 1.4
- **Evidence:** No enabled Conditional Access policy requires MFA for all users. Found in report-only mode (not enforced): CA-Require-MFA-All-Users.
- **Remediation:** Create and enforce a Conditional Access policy that requires MFA for all users (Entra ID > Security > Conditional Access). Exclude only documented emergency-access (break-glass) accounts, and monitor them.

### [Medium] AWS-006 — EBS volume not encrypted

- **Resource:** `ebs/vol-0ddd444eee555fff66 (50 GiB, us-east-1b)`
- **CIS reference:** CIS AWS 2.2.1
- **Evidence:** Volume is not encrypted at rest.
- **Remediation:** Enable EBS encryption by default for the region/account, and migrate this volume: snapshot it, copy the snapshot with encryption enabled, and create a new encrypted volume.

### [Medium] AZR-003 — Key Vault without purge protection

- **Resource:** `keyvault/kv-prod-secrets (rg: rg-prod)`
- **CIS reference:** CIS Azure 8.5
- **Evidence:** enable_purge_protection is false or unset.
- **Remediation:** Enable purge protection on the vault (Key vault > Properties). Note: purge protection cannot be disabled once enabled, and the vault must already have soft delete turned on.

### [Medium] AZR-004 — SQL server without Microsoft Defender for SQL

- **Resource:** `sql/sql-prod-001 (rg: rg-prod)`
- **CIS reference:** CIS Azure 2.1
- **Evidence:** Defender for SQL (server security alert policy) is not enabled.
- **Remediation:** Enable Microsoft Defender for SQL on the server (Defender for Cloud > Environment settings > SQL servers on machines, or the server's Microsoft Defender for Cloud blade).
