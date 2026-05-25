"""
Encryption security checks.
Encryption at rest (SSE) and encryption in transit (HTTPS-only enforcement).
"""
from __future__ import annotations
from providers.base import EncryptionConfig
from checks.base import CheckResult, CheckStatus, Severity, CISReference

# Checking if server-side encryption at rest is enabled/disabled
def check_encryption_at_rest(config: EncryptionConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="encryption_at_rest",
        check_name="Encryption at Rest",
        weight=weight,
        max_score=weight,
        severity=Severity.HIGH,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    if config.encryption_at_rest_enabled:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        details = f"Server-side encryption is enabled (algorithm: {config.encryption_algorithm})."
        if config.uses_customer_managed_key:
            details += f" Customer-managed key in use (Key: {config.key_id})."
        else:
            details += " Using provider-managed keys."
        result.details = details
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = "Server-side encryption at rest is NOT enabled."
        result.remediation = (
            "Enable server-side encryption. On AWS, configure SSE-S3 or SSE-KMS. "
            "On Azure, encryption is enabled by default (verify CMK for enhanced control). "
            "On GCP, enable CMEK for customer-managed key encryption."
        )

    return result

# Checking if HTTPS-only access is enforced or not
def check_encryption_in_transit(config: EncryptionConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="encryption_in_transit",
        check_name="Encryption in Transit (HTTPS-Only)",
        weight=weight,
        max_score=weight,
        severity=Severity.HIGH,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    if config.https_only_enforced:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        details = "HTTPS-only access is enforced."
        if config.tls_version_minimum:
            details += f" Minimum TLS version: {config.tls_version_minimum}."
        result.details = details
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = "HTTPS-only access is NOT enforced. HTTP access may be possible."
        result.remediation = (
            "On AWS, add a bucket policy with Condition aws:SecureTransport=false to deny HTTP. "
            "On Azure, enable 'Secure transfer required' on the storage account. "
            "On GCP, HTTPS is enforced by default for API access."
        )

    return result

def run_encryption_checks(config: EncryptionConfig, provider: str, bucket_name: str, weights: dict, cis_mappings: dict) -> list[CheckResult]:
    provider_key = provider.lower()
    results = []

    checks = [
        ("encryption_at_rest", check_encryption_at_rest),
        ("encryption_in_transit", check_encryption_in_transit),
    ]

    for check_id, check_fn in checks:
        weight = weights.get(check_id, {}).get("weight", 0)
        cis = cis_mappings.get(check_id, {}).get(provider_key, {})
        results.append(check_fn(config, provider_key, bucket_name, weight, cis))

    return results
