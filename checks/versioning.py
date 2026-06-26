"""
Data protection and versioning security checks.
Covers: versioning, soft delete/MFA delete/Object Lock, lifecycle policies.
"""
from __future__ import annotations
from providers.base import VersioningConfig
from checks.base import CheckResult, CheckStatus, Severity, CISReference

# Checking if object versioning is enabled
def check_versioning_enabled(config: VersioningConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:

    result = CheckResult(
        check_id="versioning_enabled",
        check_name="Object Versioning",
        weight=weight,
        max_score=weight,
        severity=Severity.HIGH,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    if config.versioning_enabled:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = f"Object versioning is enabled (status: {config.versioning_status})."
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        status_info = f" (status: {config.versioning_status})" if config.versioning_status else ""
        result.details = f"Object versioning is NOT enabled{status_info}."
        result.remediation = (
            "Enable versioning on the bucket/container to protect against "
            "accidental or malicious deletion and enable data recovery."
        )

    return result


def check_soft_delete_or_mfa_delete(config: VersioningConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="soft_delete_or_mfa_delete",
        check_name="Deletion Protection (Soft Delete/MFA Delete/Object Lock)",
        weight=weight,
        max_score=weight,
        severity=Severity.MEDIUM,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    protections = []
    if config.mfa_delete_enabled:
        protections.append("MFA Delete")
    if config.soft_delete_enabled:
        detail = "Soft Delete"
        if config.soft_delete_retention_days:
            detail += f" ({config.soft_delete_retention_days} days retention)"
        protections.append(detail)
    if config.object_lock_enabled:
        protections.append("Object Lock")
    if config.retention_policy_set:
        detail = "Retention Policy"
        if config.retention_days:
            detail += f" ({config.retention_days} days)"
        protections.append(detail)

    if protections:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = f"Deletion protection active: {', '.join(protections)}."
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = "No deletion protection configured (no soft delete, MFA delete, or object lock)."
        result.remediation = (
            "On AWS, enable MFA Delete or Object Lock on the bucket. "
            "On Azure, enable soft delete for blobs and containers. "
            "On GCP, configure retention policies or enable soft delete."
        )

    return result

# Checking if lifecycle management rules are configured or not
def check_lifecycle_policy(config: VersioningConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="lifecycle_policy",
        check_name="Lifecycle Policy",
        weight=weight,
        max_score=weight,
        severity=Severity.LOW,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    if config.lifecycle_rules_configured:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = (
            f"Lifecycle management is configured with {config.lifecycle_rule_count} rule(s)."
        )
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = "No lifecycle management rules configured."
        result.remediation = (
            "Configure lifecycle rules to automatically transition or expire objects. "
            "This reduces attack surface by removing obsolete data and helps manage storage costs."
        )

    return result


def run_versioning_checks(config: VersioningConfig, provider: str, bucket_name: str, weights: dict, cis_mappings: dict) -> list[CheckResult]:
    provider_key = provider.lower()
    results = []

    checks = [
        ("versioning_enabled", check_versioning_enabled),
        ("soft_delete_or_mfa_delete", check_soft_delete_or_mfa_delete),
        ("lifecycle_policy", check_lifecycle_policy),
    ]

    for check_id, check_fn in checks:
        weight = weights.get(check_id, {}).get("weight", 0)
        cis = cis_mappings.get(check_id, {}).get(provider_key, {})
        results.append(check_fn(config, provider_key, bucket_name, weight, cis))

    return results
