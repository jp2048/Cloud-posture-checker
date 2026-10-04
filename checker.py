#!/usr/bin/env python3
"""
Cloud Security Posture Checker
==============================
A read-only, CIS Benchmark-aligned posture scanner for Azure and AWS.

It runs a set of security checks against live cloud resources (via the
official SDKs) or, with ``--demo``, against realistic mock data so the full
workflow is demonstrable without cloud credentials.

Every check returns one Finding per evaluated resource:

    check_id     e.g. "AZR-001"
    provider     "azure" | "aws"
    title        human-readable check name
    cis_ref      approximate CIS Benchmark control reference
    severity     Critical | High | Medium | Low
    resource     the evaluated resource identifier
    status       "pass" | "fail" | "error"
    remediation  concise, actionable guidance
    detail       evidence for this specific resource

CIS mappings are best-effort against the CIS Microsoft Azure Foundations
Benchmark v2.0 and the CIS Amazon Web Services Foundations Benchmark v1.5.
Validate them against the official benchmarks before audit use.

The tool never modifies anything: all SDK calls are read-only (list/get/
describe). Findings with status "error" mean a check could not be evaluated
(e.g. missing permissions); they are reported, not silently dropped.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Guarded SDK imports. The tool works in --demo mode with zero dependencies;
# live scans need the SDKs plus configured credentials (env vars, Azure CLI,
# ~/.aws/credentials, or an attached managed identity / IAM role).
# ---------------------------------------------------------------------------

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.storage import StorageManagementClient

    AZURE_SDK = True
except ImportError:  # pragma: no cover - exercised only with SDKs installed
    AZURE_SDK = False

try:
    from msgraph import GraphServiceClient

    MSGRAPH_SDK = True
except ImportError:
    MSGRAPH_SDK = False

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    AWS_SDK = True
except ImportError:
    AWS_SDK = False


class ConfigurationError(Exception):
    """Raised when credentials, SDKs, or permissions are missing for a scan."""


# Ports whose exposure to the internet is treated as a finding.
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class Finding:
    check_id: str
    provider: str
    title: str
    cis_ref: str
    severity: str
    resource: str
    status: str  # "pass" | "fail" | "error"
    remediation: str
    detail: str = ""


# ---------------------------------------------------------------------------
# Check registry. Each check function takes a provider context and returns
# a list of Findings (one per evaluated resource).
# ---------------------------------------------------------------------------

CHECKS: list[dict] = []


def register(check_id: str, title: str, cis_ref: str, severity: str):
    """Decorator registering a check function in the global CHECKS list."""

    def decorator(fn):
        CHECKS.append(
            {
                "check_id": check_id,
                "provider": check_id.split("-")[0].lower().replace("azr", "azure"),
                "title": title,
                "cis_ref": cis_ref,
                "severity": severity,
                "fn": fn,
            }
        )
        return fn

    return decorator


def _fail(check_id, provider, title, cis_ref, severity, resource, remediation, detail=""):
    return Finding(check_id, provider, title, cis_ref, severity, resource, "fail", remediation, detail)


def _pass(check_id, provider, title, cis_ref, severity, resource, detail=""):
    return Finding(check_id, provider, title, cis_ref, severity, resource, "pass", "", detail)


def _error(check_id, provider, title, cis_ref, severity, resource, detail):
    return Finding(
        check_id,
        provider,
        title,
        cis_ref,
        severity,
        resource,
        "error",
        "Re-run with sufficient permissions and verify the resource still exists.",
        detail,
    )


def _port_matches(port_spec: str | None, target: int) -> bool:
    """True if an Azure NSG port spec ('3389', '22-25', '*') covers target."""
    if not port_spec:
        return False
    spec = port_spec.strip()
    if spec in ("*", "0-65535"):
        return True
    if "-" in spec:
        try:
            lo, hi = (int(p) for p in spec.split("-", 1))
        except ValueError:
            return False
        return lo <= target <= hi
    try:
        return int(spec) == target
    except ValueError:
        return False


def _is_internet_source(source: str | None) -> bool:
    return (source or "").strip().lower() in ("*", "0.0.0.0/0", "internet", "<none>")


def _resource_group_from_id(resource_id: str) -> str:
    parts = (resource_id or "").split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""

# ---------------------------------------------------------------------------
# Provider contexts. Each context exposes the same normalized resource shapes
# (plain dicts) so check functions work identically against live SDKs and
# demo data.
# ---------------------------------------------------------------------------


class AzureContext:
    """Live Azure context using the azure-mgmt-* SDKs and DefaultAzureCredential."""

    def __init__(self, subscription_id: str):
        if not AZURE_SDK:
            raise ConfigurationError(
                "Azure SDKs are not installed. Install requirements.txt, "
                "or run with --demo."
            )
        if not subscription_id:
            raise ConfigurationError(
                "AZURE_SUBSCRIPTION_ID is not set. Export it or pass "
                "--subscription-id. Authenticate first (e.g. `az login`)."
            )
        try:
            credential = DefaultAzureCredential()
            # Force an early token request so auth problems fail fast with a
            # clear message instead of surfacing mid-scan.
            credential.get_token("https://management.azure.com/.default")
        except Exception as exc:  # noqa: BLE001 - surface any auth failure plainly
            raise ConfigurationError(
                "Azure credentials not configured or invalid. Authenticate with "
                f"`az login`, a managed identity, or service-principal env vars. ({exc})"
            ) from exc
        self.subscription_id = subscription_id
        self.credential = credential
        self.storage = StorageManagementClient(credential, subscription_id)
        self.network = NetworkManagementClient(credential, subscription_id)
        self.keyvault = KeyVaultManagementClient(credential, subscription_id)
        self.sql = SqlManagementClient(credential, subscription_id)

    def storage_accounts(self) -> list[dict]:
        accounts = []
        for acct in self.storage.storage_accounts.list():
            props = acct.as_dict()
            accounts.append(
                {
                    "name": acct.name,
                    "resource_group": _resource_group_from_id(acct.id),
                    "allow_blob_public_access": bool(props.get("allow_blob_public_access")),
                    "id": acct.id,
                }
            )
        return accounts

    def nsgs(self) -> list[dict]:
        nsgs = []
        for nsg in self.network.network_security_groups.list_all():
            rules = []
            for rule in nsg.security_rules or []:
                ports: list[int] = []
                if rule.destination_port_range:
                    ports.append(rule.destination_port_range)
                ports.extend(rule.destination_port_ranges or [])
                rules.append(
                    {
                        "name": rule.name,
                        "direction": rule.direction,
                        "access": rule.access,
                        "source": rule.source_address_prefix
                        or ",".join(rule.source_address_prefixes or []),
                        "ports": ports,
                        "protocol": rule.protocol,
                    }
                )
            nsgs.append(
                {
                    "name": nsg.name,
                    "resource_group": _resource_group_from_id(nsg.id),
                    "rules": rules,
                }
            )
        return nsgs

    def key_vaults(self) -> list[dict]:
        vaults = []
        for vault in self.keyvault.vaults.list():
            props = vault.properties.as_dict() if vault.properties else {}
            vaults.append(
                {
                    "name": vault.name,
                    "resource_group": _resource_group_from_id(vault.id),
                    "purge_protection_enabled": bool(props.get("enable_purge_protection")),
                }
            )
        return vaults

    def sql_servers(self) -> list[dict]:
        servers = []
        for server in self.sql.servers.list():
            rg = _resource_group_from_id(server.id)
            defender_enabled = False
            try:
                policy = self.sql.server_security_alert_policies.get(rg, server.name, "Default")
                defender_enabled = (policy.state or "").lower() == "enabled"
            except Exception:  # noqa: BLE001 - treat lookup failure as not enabled
                defender_enabled = False
            servers.append(
                {"name": server.name, "resource_group": rg, "defender_enabled": defender_enabled}
            )
        return servers

    def conditional_access(self) -> dict:
        """Best-effort MFA/Conditional Access signal via Microsoft Graph."""
        if not MSGRAPH_SDK:
            raise ConfigurationError(
                "msgraph-sdk is not installed, so the Conditional Access check cannot run. "
                "Install it (see requirements.txt) or skip check AZR-005."
            )

        async def _fetch() -> list[dict]:
            client = GraphServiceClient(
                credentials=self.credential, scopes=["https://graph.microsoft.com/.default"]
            )
            page = await client.identity.conditional_access.policies.get()
            policies = []
            for policy in page.value or []:
                conditions = policy.conditions
                users = conditions.users if conditions else None
                include_all = bool(users and "All" in (users.include_users or []))
                excluded = list(users.exclude_users or []) if users else []
                grant = policy.grant_controls.built_in_controls if policy.grant_controls else []
                requires_mfa = "mfa" in [str(c).lower() for c in (grant or [])]
                policies.append(
                    {
                        "name": policy.display_name,
                        "state": str(policy.state),
                        "applies_to_all_users": include_all,
                        "requires_mfa": requires_mfa,
                        "excluded_users": excluded,
                    }
                )
            return policies

        try:
            policies = asyncio.run(_fetch())
        except Exception as exc:  # noqa: BLE001
            raise ConfigurationError(
                "Could not read Conditional Access policies via Microsoft Graph. "
                "This needs the Policy.Read.All application permission consented. "
                f"({exc})"
            ) from exc
        return {"policies": policies}


class AWSContext:
    """Live AWS context using boto3 and the default credential chain."""

    def __init__(self, region: str):
        if not AWS_SDK:
            raise ConfigurationError(
                "boto3 is not installed. Install requirements.txt, or run with --demo."
            )
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        try:
            sts = boto3.client("sts", region_name=self.region)
            self.account_id = sts.get_caller_identity()["Account"]
        except NoCredentialsError as exc:
            raise ConfigurationError(
                "AWS credentials not configured. Set AWS_ACCESS_KEY_ID / "
                "AWS_SECRET_ACCESS_KEY, configure a profile, or attach an IAM role."
            ) from exc
        except ClientError as exc:
            raise ConfigurationError(f"AWS authentication failed: {exc}") from exc
        self.iam = boto3.client("iam", region_name=self.region)
        self.s3 = boto3.client("s3", region_name=self.region)
        self.ec2 = boto3.client("ec2", region_name=self.region)
        self.cloudtrail = boto3.client("cloudtrail", region_name=self.region)

    def iam_users(self) -> list[dict]:
        users = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                name = user["UserName"]
                try:
                    mfa = self.iam.list_mfa_devices(UserName=name)["MFADevices"]
                except ClientError:
                    mfa = []
                try:
                    profile = self.iam.get_login_profile(UserName=name)
                    console_access = True
                except self.iam.exceptions.NoSuchEntityException:
                    console_access = False
                except ClientError:
                    console_access = False
                users.append(
                    {
                        "name": name,
                        "mfa_enabled": len(mfa) > 0,
                        "console_access": console_access,
                    }
                )
        return users

    def s3_buckets(self) -> list[dict]:
        buckets = []
        for bucket in self.s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            public_read = False
            via = ""
            # PublicAccessBlock: all four must be true to consider it locked down.
            try:
                pab = self.s3.get_public_access_block(Bucket=name)[
                    "PublicAccessBlockConfiguration"
                ]
                if not all(
                    pab.get(k, False)
                    for k in (
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    )
                ):
                    via = "PublicAccessBlock not fully enabled"
            except ClientError:
                via = "no PublicAccessBlock configuration"
            # Bucket ACL grants to the AllUsers / AuthenticatedUsers groups.
            try:
                for grant in self.s3.get_bucket_acl(Bucket=name).get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        via = via or f"ACL grant to {uri.split('/')[-1]}"
            except ClientError:
                pass
            # Bucket policy status (authoritative public/private verdict).
            try:
                if self.s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]:
                    via = via or "bucket policy allows public access"
            except ClientError:
                pass
            public_read = bool(via)
            buckets.append({"name": name, "public_read": public_read, "via": via})
        return buckets

    def security_groups(self) -> list[dict]:
        groups = []
        paginator = self.ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                rules = []
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    ports = (
                        list(range(from_port, to_port + 1))
                        if isinstance(from_port, int) and isinstance(to_port, int)
                        else ["all"]
                    )
                    for ip_range in perm.get("IpRanges", []):
                        rules.append({"cidr": ip_range.get("CidrIp"), "ports": ports})
                    for ip_range in perm.get("Ipv6Ranges", []):
                        rules.append({"cidr": ip_range.get("CidrIpv6"), "ports": ports})
                groups.append(
                    {
                        "id": sg["GroupId"],
                        "name": sg.get("GroupName", ""),
                        "vpc": sg.get("VpcId", ""),
                        "rules": rules,
                    }
                )
        return groups

    def cloudtrails(self) -> list[dict]:
        trails = []
        for trail in self.cloudtrail.describe_trails().get("trailList", []):
            arn = trail["TrailARN"]
            try:
                status = self.cloudtrail.get_trail_status(Name=arn)
                is_logging = status.get("IsLogging", False)
            except ClientError:
                is_logging = False
            trails.append(
                {
                    "name": trail.get("Name", arn),
                    "is_logging": is_logging,
                    "log_validation_enabled": bool(trail.get("LogFileValidationEnabled")),
                    "is_multi_region": bool(trail.get("IsMultiRegionTrail")),
                }
            )
        return trails

    def root_access_keys(self) -> dict:
        summary = self.iam.get_account_summary()["SummaryMap"]
        return {"access_keys_present": int(summary.get("AccountAccessKeysPresent", 0))}

    def ebs_volumes(self) -> list[dict]:
        volumes = []
        paginator = self.ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                volumes.append(
                    {
                        "id": vol["VolumeId"],
                        "encrypted": bool(vol.get("Encrypted")),
                        "size_gb": vol.get("Size"),
                        "az": vol.get("AvailabilityZone"),
                    }
                )
        return volumes


class DemoAzureContext:
    """Azure context backed by demo_data/azure.json (no credentials needed)."""

    def __init__(self, path: str):
        with open(path, encoding="utf-8") as fh:
            self._data = json.load(fh)

    def storage_accounts(self) -> list[dict]:
        return self._data.get("storage_accounts", [])

    def nsgs(self) -> list[dict]:
        return self._data.get("nsgs", [])

    def key_vaults(self) -> list[dict]:
        return self._data.get("key_vaults", [])

    def sql_servers(self) -> list[dict]:
        return self._data.get("sql_servers", [])

    def conditional_access(self) -> dict:
        return self._data.get("conditional_access", {"policies": []})


class DemoAWSContext:
    """AWS context backed by demo_data/aws.json (no credentials needed)."""

    def __init__(self, path: str):
        with open(path, encoding="utf-8") as fh:
            self._data = json.load(fh)

    def iam_users(self) -> list[dict]:
        return self._data.get("iam_users", [])

    def s3_buckets(self) -> list[dict]:
        return self._data.get("s3_buckets", [])

    def security_groups(self) -> list[dict]:
        return self._data.get("security_groups", [])

    def cloudtrails(self) -> list[dict]:
        return self._data.get("cloudtrails", [])

    def root_access_keys(self) -> dict:
        return self._data.get("root", {"access_keys_present": 0})

    def ebs_volumes(self) -> list[dict]:
        return self._data.get("ebs_volumes", [])

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@register("AZR-001", "Storage account allows public blob access", "CIS Azure 3.2", "High")
def check_azure_storage_public_blob(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AZR-001")
    findings = []
    for acct in ctx.storage_accounts():
        if acct.get("allow_blob_public_access"):
            findings.append(
                _fail(
                    remediation=(
                        "Set 'Allow Blob public access' to Disabled on the storage account "
                        "(Storage account > Configuration). Audit existing containers for "
                        "Public access level = Blob/Container and revert to Private."
                    ),
                    detail="allow_blob_public_access is enabled on this storage account.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="azure",
                    resource=f"storage/{acct['name']} (rg: {acct.get('resource_group', '?')})",
                )
            )
        else:
            findings.append(
                _pass(
                    detail="allow_blob_public_access is disabled.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="azure",
                    resource=f"storage/{acct['name']} (rg: {acct.get('resource_group', '?')})",
                )
            )
    return findings


@register(
    "AZR-002",
    "NSG allows internet ingress on sensitive ports",
    "CIS Azure 6.1/6.2",
    "High",
)
def check_azure_nsg_open_ports(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AZR-002")
    findings = []
    for nsg in ctx.nsgs():
        exposed: dict[int, str] = {}
        for rule in nsg.get("rules", []):
            if (rule.get("direction"), rule.get("access")) != ("Inbound", "Allow"):
                continue
            if not _is_internet_source(rule.get("source")):
                continue
            for port in SENSITIVE_PORTS:
                port_specs = rule.get("ports") or []
                if any(_port_matches(str(spec), port) for spec in port_specs):
                    exposed[port] = rule.get("name", "?")
        resource = f"nsg/{nsg['name']} (rg: {nsg.get('resource_group', '?')})"
        if exposed:
            detail = "; ".join(
                f"port {p} ({SENSITIVE_PORTS[p]}) via rule '{r}'" for p, r in sorted(exposed.items())
            )
            findings.append(
                _fail(
                    remediation=(
                        "Restrict the listed rules to known source IPs, a bastion host, or "
                        "remove them and use just-in-time VM access / Azure Bastion instead."
                    ),
                    detail=f"Inbound from internet on: {detail}.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="azure",
                    resource=resource,
                )
            )
        else:
            findings.append(
                _pass(
                    detail="No internet ingress on sensitive ports.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="azure",
                    resource=resource,
                )
            )
    return findings


@register("AZR-003", "Key Vault without purge protection", "CIS Azure 8.5", "Medium")
def check_azure_keyvault_purge_protection(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AZR-003")
    findings = []
    for vault in ctx.key_vaults():
        resource = f"keyvault/{vault['name']} (rg: {vault.get('resource_group', '?')})"
        if not vault.get("purge_protection_enabled"):
            findings.append(
                _fail(
                    remediation=(
                        "Enable purge protection on the vault (Key vault > Properties). "
                        "Note: purge protection cannot be disabled once enabled, and the "
                        "vault must already have soft delete turned on."
                    ),
                    detail="enable_purge_protection is false or unset.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="azure",
                    resource=resource,
                )
            )
        else:
            findings.append(
                _pass(
                    detail="Purge protection is enabled.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="azure",
                    resource=resource,
                )
            )
    return findings


@register("AZR-004", "SQL server without Microsoft Defender for SQL", "CIS Azure 2.1", "Medium")
def check_azure_sql_defender(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AZR-004")
    findings = []
    for server in ctx.sql_servers():
        resource = f"sql/{server['name']} (rg: {server.get('resource_group', '?')})"
        if not server.get("defender_enabled"):
            findings.append(
                _fail(
                    remediation=(
                        "Enable Microsoft Defender for SQL on the server "
                        "(Defender for Cloud > Environment settings > SQL servers on machines, "
                        "or the server's Microsoft Defender for Cloud blade)."
                    ),
                    detail="Defender for SQL (server security alert policy) is not enabled.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="azure",
                    resource=resource,
                )
            )
        else:
            findings.append(
                _pass(
                    detail="Defender for SQL is enabled.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="azure",
                    resource=resource,
                )
            )
    return findings


@register(
    "AZR-005",
    "No enforced Conditional Access policy requiring MFA for all users",
    "CIS Azure 1.4",
    "High",
)
def check_azure_conditional_access_mfa(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AZR-005")
    kwargs = {k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")}
    try:
        ca = ctx.conditional_access()
    except ConfigurationError as exc:
        return [_error(provider="azure", resource="tenant/conditional-access", detail=str(exc), **kwargs)]
    enforced = [
        p
        for p in ca.get("policies", [])
        if str(p.get("state", "")).lower() == "enabled"
        and p.get("applies_to_all_users")
        and p.get("requires_mfa")
    ]
    if enforced:
        names = ", ".join(f"'{p['name']}'" for p in enforced)
        excluded = sorted({u for p in enforced for u in p.get("excluded_users", [])})
        detail = f"Enforced by: {names}."
        if excluded:
            detail += f" Excluded accounts (verify these are break-glass only): {', '.join(excluded)}."
        return [_pass(provider="azure", resource="tenant/conditional-access", detail=detail, **kwargs)]
    report_only = [
        p["name"] for p in ca.get("policies", []) if "report" in str(p.get("state", "")).lower()
    ]
    detail = "No enabled Conditional Access policy requires MFA for all users."
    if report_only:
        detail += f" Found in report-only mode (not enforced): {', '.join(report_only)}."
    return [
        _fail(
            provider="azure",
            resource="tenant/conditional-access",
            remediation=(
                "Create and enforce a Conditional Access policy that requires MFA for "
                "all users (Entra ID > Security > Conditional Access). Exclude only "
                "documented emergency-access (break-glass) accounts, and monitor them."
            ),
            detail=detail,
            **kwargs,
        )
    ]


@register("AWS-001", "IAM user with console access but no MFA", "CIS AWS 1.2", "High")
def check_aws_iam_mfa(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AWS-001")
    findings = []
    for user in ctx.iam_users():
        if not user.get("console_access", True):
            continue  # programmatic-only users have no console to protect with MFA
        resource = f"iam-user/{user['name']}"
        if not user.get("mfa_enabled"):
            findings.append(
                _fail(
                    remediation=(
                        f"Enable MFA for the user: IAM > Users > {user['name']} > Security "
                        "credentials > Assign MFA device. Enforce with the "
                        "aws:MultiFactorAuthPresent condition in IAM policies."
                    ),
                    detail="Console access is enabled but no MFA device is assigned.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="aws",
                    resource=resource,
                )
            )
        else:
            findings.append(
                _pass(
                    detail="MFA device is assigned.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="aws",
                    resource=resource,
                )
            )
    return findings


@register("AWS-002", "S3 bucket with public read access", "CIS AWS 2.1.4", "High")
def check_aws_s3_public(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AWS-002")
    findings = []
    for bucket in ctx.s3_buckets():
        resource = f"s3/{bucket['name']}"
        if bucket.get("public_read"):
            findings.append(
                _fail(
                    remediation=(
                        "Enable all four S3 Block Public Access settings at the account and "
                        "bucket level, remove public ACL grants and public bucket-policy "
                        "statements, and re-verify with the policy status check."
                    ),
                    detail=f"Bucket is publicly readable ({bucket.get('via', 'public access detected')}).",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="aws",
                    resource=resource,
                )
            )
        else:
            findings.append(
                _pass(
                    detail="Bucket is not publicly readable.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="aws",
                    resource=resource,
                )
            )
    return findings


@register(
    "AWS-003",
    "Security group allows internet ingress on sensitive ports",
    "CIS AWS 4.1/4.2",
    "High",
)
def check_aws_sg_open_ports(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AWS-003")
    findings = []
    for sg in ctx.security_groups():
        exposed: list[int] = []
        for rule in sg.get("rules", []):
            cidr = (rule.get("cidr") or "").strip()
            if cidr not in ("0.0.0.0/0", "::/0"):
                continue
            for port in SENSITIVE_PORTS:
                if "all" in rule.get("ports", []) or port in rule.get("ports", []):
                    exposed.append(port)
        resource = f"sg/{sg['id']} ({sg.get('name', '?')}, vpc: {sg.get('vpc', '?')})"
        if exposed:
            detail = ", ".join(f"{p} ({SENSITIVE_PORTS[p]})" for p in sorted(set(exposed)))
            findings.append(
                _fail(
                    remediation=(
                        "Replace 0.0.0.0/0 with specific CIDRs, security-group references, "
                        "or remove the rule and use SSM Session Manager / a bastion host."
                    ),
                    detail=f"Ingress from 0.0.0.0/0 on: {detail}.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="aws",
                    resource=resource,
                )
            )
        else:
            findings.append(
                _pass(
                    detail="No internet ingress on sensitive ports.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="aws",
                    resource=resource,
                )
            )
    return findings


@register("AWS-004", "CloudTrail logging or log validation issue", "CIS AWS 3.1/3.2", "High")
def check_aws_cloudtrail(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AWS-004")
    kwargs = {k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")}
    trails = ctx.cloudtrails()
    active = [t for t in trails if t.get("is_logging")]
    if not active:
        return [
            _fail(
                provider="aws",
                resource="cloudtrail/(none active)",
                remediation=(
                    "Create a multi-region CloudTrail trail logging to a dedicated, "
                    "access-controlled S3 bucket with log file validation enabled."
                ),
                detail="No CloudTrail trail is currently logging.",
                **kwargs,
            )
        ]
    findings = []
    for trail in active:
        resource = f"cloudtrail/{trail['name']}"
        problems = []
        if not trail.get("log_validation_enabled"):
            problems.append("log file validation is disabled")
        if not trail.get("is_multi_region"):
            problems.append("trail is not multi-region")
        if problems:
            findings.append(
                _fail(
                    provider="aws",
                    resource=resource,
                    remediation=(
                        "Enable log file validation and multi-region coverage on the trail "
                        "(CloudTrail > Trails > Edit). Validation lets you detect tampering "
                        "with delivered log files."
                    ),
                    detail="; ".join(problems).capitalize() + ".",
                    **kwargs,
                )
            )
        else:
            findings.append(
                _pass(
                    provider="aws",
                    resource=resource,
                    detail="Logging, log validation, and multi-region coverage are enabled.",
                    **kwargs,
                )
            )
    return findings


@register("AWS-005", "Root account has active access keys", "CIS AWS 1.12", "Critical")
def check_aws_root_access_keys(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AWS-005")
    kwargs = {k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")}
    count = ctx.root_access_keys().get("access_keys_present", 0)
    if count > 0:
        return [
            _fail(
                provider="aws",
                resource="iam/root",
                remediation=(
                    "Delete the root access keys immediately (IAM > Users > root > Security "
                    "credentials). Create least-privilege IAM users/roles for daily work and "
                    "protect root with MFA stored offline."
                ),
                detail=f"{count} active access key(s) found on the root account.",
                **kwargs,
            )
        ]
    return [
        _pass(
            provider="aws",
            resource="iam/root",
            detail="No active access keys on the root account.",
            **kwargs,
        )
    ]


@register("AWS-006", "EBS volume not encrypted", "CIS AWS 2.2.1", "Medium")
def check_aws_ebs_encryption(ctx) -> list[Finding]:
    meta = next(c for c in CHECKS if c["check_id"] == "AWS-006")
    findings = []
    for vol in ctx.ebs_volumes():
        resource = f"ebs/{vol['id']} ({vol.get('size_gb', '?')} GiB, {vol.get('az', '?')})"
        if not vol.get("encrypted"):
            findings.append(
                _fail(
                    remediation=(
                        "Enable EBS encryption by default for the region/account, and "
                        "migrate this volume: snapshot it, copy the snapshot with "
                        "encryption enabled, and create a new encrypted volume."
                    ),
                    detail="Volume is not encrypted at rest.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="aws",
                    resource=resource,
                )
            )
        else:
            findings.append(
                _pass(
                    detail="Volume is encrypted at rest.",
                    **{k: meta[k] for k in ("check_id", "title", "cis_ref", "severity")},
                    provider="aws",
                    resource=resource,
                )
            )
    return findings

# ---------------------------------------------------------------------------
# Scan runner and reporting
# ---------------------------------------------------------------------------


def run_scan(providers: list[str], demo: bool, demo_dir: str) -> tuple[list[Finding], dict]:
    """Run all registered checks for the requested providers."""
    findings: list[Finding] = []
    scanned: list[str] = []
    for check in CHECKS:
        provider = check["provider"]
        if provider not in providers:
            continue
        if provider == "azure":
            ctx = (
                DemoAzureContext(os.path.join(demo_dir, "azure.json"))
                if demo
                else AzureContext(os.environ.get("AZURE_SUBSCRIPTION_ID", ""))
            )
        else:
            ctx = (
                DemoAWSContext(os.path.join(demo_dir, "aws.json"))
                if demo
                else AWSContext(os.environ.get("AWS_REGION", "us-east-1"))
            )
        try:
            findings.extend(check["fn"](ctx))
        except ConfigurationError as exc:
            # A whole check could not run (e.g. missing Graph consent):
            # record it as an error finding instead of aborting the scan.
            findings.append(
                _error(
                    check_id=check["check_id"],
                    provider=provider,
                    title=check["title"],
                    cis_ref=check["cis_ref"],
                    severity=check["severity"],
                    resource="(check-level)",
                    detail=str(exc),
                )
            )
        scanned.append(check["check_id"])
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "providers": providers,
        "mode": "demo" if demo else "live",
        "checks_run": sorted(set(scanned)),
    }
    return findings, meta


def summarize(findings: list[Finding]) -> dict:
    by_status = {"pass": 0, "fail": 0, "error": 0}
    by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
        if f.status == "fail":
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "total_findings": len(findings),
        "passed": by_status["pass"],
        "failed": by_status["fail"],
        "errors": by_status["error"],
        "failed_by_severity": by_severity,
    }


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.check_id, f.resource)
    )


def render_markdown(findings: list[Finding], meta: dict) -> str:
    summary = summarize(findings)
    lines = [
        "# Cloud Security Posture Report",
        "",
        f"Generated: `{meta['generated_at']}`",
        f"Providers: {', '.join(meta['providers'])}",
        f"Mode: `{meta['mode']}`",
        f"Checks run: {len(meta['checks_run'])}",
        "",
        "## Summary",
        "",
        f"- Resources evaluated: **{summary['total_findings']}**",
        f"- Passed: **{summary['passed']}**",
        f"- Failed: **{summary['failed']}**",
        f"- Errors: **{summary['errors']}**",
        "",
        "### Failed findings by severity",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for sev in ("Critical", "High", "Medium", "Low"):
        lines.append(f"| {sev} | {summary['failed_by_severity'][sev]} |")
    lines += ["", "## Findings", ""]
    lines.append("| Check | Severity | Resource | Status | CIS |")
    lines.append("| --- | --- | --- | --- | --- |")
    for f in _sorted_findings(findings):
        lines.append(
            f"| {f.check_id} | {f.severity} | `{f.resource}` | {f.status.upper()} | {f.cis_ref} |"
        )
    lines += ["", "## Remediation guidance (failed findings)", ""]
    failed = [f for f in _sorted_findings(findings) if f.status == "fail"]
    if not failed:
        lines.append("No failed findings. 🎉")
    for f in failed:
        lines += [
            f"### [{f.severity}] {f.check_id} — {f.title}",
            "",
            f"- **Resource:** `{f.resource}`",
            f"- **CIS reference:** {f.cis_ref}",
            f"- **Evidence:** {f.detail}",
            f"- **Remediation:** {f.remediation}",
            "",
        ]
    errored = [f for f in _sorted_findings(findings) if f.status == "error"]
    if errored:
        lines += ["## Errors (checks that could not be evaluated)", ""]
        for f in errored:
            lines += [
                f"### {f.check_id} — {f.title}",
                "",
                f"- **Resource:** `{f.resource}`",
                f"- **Detail:** {f.detail}",
                "",
            ]
    return "\n".join(lines).rstrip() + "\n"


def render_json(findings: list[Finding], meta: dict) -> str:
    payload = {
        "scan": meta,
        "summary": summarize(findings),
        "findings": [asdict(f) for f in _sorted_findings(findings)],
    }
    return json.dumps(payload, indent=2) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only CIS-aligned cloud posture checks for Azure and AWS.",
        epilog="Exit code: 0 = all checks passed, 1 = one or more failures, 2 = configuration error.",
    )
    parser.add_argument(
        "--provider",
        choices=["azure", "aws", "all"],
        default="all",
        help="Which cloud provider(s) to scan (default: all).",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run against realistic mock data in demo_data/ (no credentials needed).",
    )
    parser.add_argument(
        "--demo-dir",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_data"),
        help="Directory containing azure.json / aws.json demo data.",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="Write the report to PATH instead of stdout. Format is inferred from "
        "the extension (.json or .md); use --format to override.",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        help="Report format (default: inferred from --output extension, else markdown).",
    )
    parser.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
        help="Azure subscription ID (or set AZURE_SUBSCRIPTION_ID).",
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_REGION", "us-east-1"),
        help="AWS region (or set AWS_REGION).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    providers = ["azure", "aws"] if args.provider == "all" else [args.provider]

    if args.format:
        fmt = args.format
    elif args.output and args.output.lower().endswith(".json"):
        fmt = "json"
    else:
        fmt = "markdown"

    if not args.demo:
        # Fail fast with a clear message when live-scan prerequisites are missing.
        if "azure" in providers and not AZURE_SDK:
            print(
                "error: Azure SDKs not installed. Run `pip install -r requirements.txt` "
                "or use --demo.",
                file=sys.stderr,
            )
            return 2
        if "aws" in providers and not AWS_SDK:
            print(
                "error: boto3 not installed. Run `pip install -r requirements.txt` "
                "or use --demo.",
                file=sys.stderr,
            )
            return 2
        if "azure" in providers and not args.subscription_id:
            print(
                "error: AZURE_SUBSCRIPTION_ID is not set. Export it or pass "
                "--subscription-id (or use --demo).",
                file=sys.stderr,
            )
            return 2

    # Make CLI-provided values visible to the contexts via the environment.
    if args.subscription_id:
        os.environ["AZURE_SUBSCRIPTION_ID"] = args.subscription_id
    if args.region:
        os.environ["AWS_REGION"] = args.region

    try:
        findings, meta = run_scan(providers, args.demo, args.demo_dir)
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = render_json(findings, meta) if fmt == "json" else render_markdown(findings, meta)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Report written to {args.output}")
    else:
        print(report, end="")

    summary = summarize(findings)
    return 1 if (summary["failed"] > 0 or summary["errors"] > 0) else 0


if __name__ == "__main__":
    sys.exit(main())
