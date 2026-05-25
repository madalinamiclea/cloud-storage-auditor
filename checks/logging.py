"""
Logging and monitoring security checks.
Checking ccess logging configuration and audit trail (CloudTrail/Azure Monitor/Cloud Audit Logs)
"""
from __future__ import annotations
from providers.base import LoggingConfig
from checks.base import CheckResult, CheckStatus, Severity, CISReference


def check_access_logging(config: LoggingConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="access_logging",
        check_name="Access Logging",
        weight=weight,
        max_score=weight,
        severity=Severity.HIGH,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    if config.access_logging_enabled:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = f"Access logging is enabled. Log destination: {config.log_destination}."
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = "Access logging is NOT enabled."
        result.remediation = (
            "On AWS, enable S3 server access logging and specify a target bucket. "
            "On Azure, enable Storage Analytics logging for the Blob service. "
            "On GCP, configure a log bucket in the bucket's logging settings."
        )

    return result

# Check whether cloud audit trail covers storage operations
def check_audit_trail(config: LoggingConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="audit_trail",
        check_name="Audit Trail",
        weight=weight,
        max_score=weight,
        severity=Severity.MEDIUM,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    if config.audit_trail_enabled:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = (
            f"Audit trail is active via {config.audit_trail_service}."
        )
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = "No cloud audit trail detected for storage operations."
        result.remediation = (
            "On AWS, ensure CloudTrail is enabled in all regions with S3 data events. "
            "On Azure, configure Diagnostic Settings for the storage account. "
            "On GCP, verify Cloud Audit Logs are enabled (Admin Activity is on by default; "
            "Data Access logs may need explicit configuration)."
        )

    return result


def run_logging_checks(config: LoggingConfig, provider: str, bucket_name: str, weights: dict, cis_mappings: dict) -> list[CheckResult]:
    provider_key = provider.lower()
    results = []

    checks = [
        ("access_logging", check_access_logging),
        ("audit_trail", check_audit_trail),
    ]

    for check_id, check_fn in checks:
        weight = weights.get(check_id, {}).get("weight", 0)
        cis = cis_mappings.get(check_id, {}).get(provider_key, {})
        results.append(check_fn(config, provider_key, bucket_name, weight, cis))

    return results
