"""
Access control security checks.
Covers: Block Public Access, IAM/bucket policy least privilege, ACL analysis.
"""
from __future__ import annotations
from providers.base import AccessConfig
from checks.base import CheckResult, CheckStatus, Severity, CISReference

# Check whether Block Public Access (or equivalent) is fully enabled
def check_public_access_block(config: AccessConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="public_access_block",
        check_name="Block Public Access",
        weight=weight,
        max_score=weight,
        severity=Severity.CRITICAL,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    if config.public_access_blocked:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = "Block Public Access is fully enabled"
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        missing = []
        if not config.block_public_acls:
            missing.append("BlockPublicAcls")
        if not config.block_public_policy:
            missing.append("BlockPublicPolicy")
        if not config.ignore_public_acls:
            missing.append("IgnorePublicAcls")
        if not config.restrict_public_buckets:
            missing.append("RestrictPublicBuckets")

        if missing:
            result.details = f"Block Public Access is NOT fully enabled. Missing: {', '.join(missing)}."
        else:
            result.details = "Block Public Access is not enabled"

        result.remediation = (
            "Enable all four Block Public Access settings (AWS), "
            "disable public access at the storage account level (Azure), "
            "or enforce public access prevention on the bucket (GCP)."
        )

    return result

# Check if IAM/bucket policy follows least-privilege principle
def check_iam_policy_least_privilege(config: AccessConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="iam_policy_least_privilege",
        check_name="IAM Policy Least Privilege",
        weight=weight,
        max_score=weight,
        severity=Severity.HIGH,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    issues = []
    if config.policy_allows_wildcard_principal:
        issues.append("Policy allows wildcard principal (*)")
    if config.policy_allows_wildcard_action:
        issues.append("Policy allows wildcard actions (s3:* / *)")

    if not config.has_bucket_policy:
        # No policy is acceptable so relying on IAM
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = "No bucket/container policy configured. Access controlled via IAM."
    elif config.policy_is_least_privilege and not issues:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = "Bucket/container policy follows least-privilege principle."
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = f"Policy violates least privilege: {'; '.join(issues)}."
        result.remediation = (
            "Review and restrict bucket/container policy. Remove wildcard principals "
            "and actions. Grant only the minimum permissions required."
        )

    return result

# Check if ACLs grant public or AllUsers/AllAuthenticatedUsers access
def check_acl_not_public(config: AccessConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="acl_not_public",
        check_name="ACL Not Public",
        weight=weight,
        max_score=weight,
        severity=Severity.HIGH,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    issues = []
    if config.acl_public_read:
        issues.append("ACL grants public read access (AllUsers)")
    if config.acl_public_write:
        issues.append("ACL grants public write access (AllUsers)")
    if config.acl_authenticated_read:
        issues.append("ACL grants access to all authenticated users")

    if not issues:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = "ACLs do not grant public access."
        if config.uniform_access_enabled:
            result.details += " Uniform bucket-level access is enabled (ACLs disabled)."
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = f"Public ACL detected: {'; '.join(issues)}."
        result.remediation = (
            "Remove public ACL grants. On AWS, enable Block Public Access. "
            "On Azure, set container access to Private. "
            "On GCP, enable Uniform Bucket-Level Access to disable object ACLs."
        )

    return result


def run_access_control_checks(config: AccessConfig, provider: str, bucket_name: str, weights: dict, cis_mappings: dict) -> list[CheckResult]:
    provider_key = provider.lower()
    results = []

    checks = [
        ("public_access_block", check_public_access_block),
        ("iam_policy_least_privilege", check_iam_policy_least_privilege),
        ("acl_not_public", check_acl_not_public),
    ]

    for check_id, check_fn in checks:
        weight = weights.get(check_id, {}).get("weight", 0)
        cis = cis_mappings.get(check_id, {}).get(provider_key, {})
        results.append(check_fn(config, provider_key, bucket_name, weight, cis))

    return results
