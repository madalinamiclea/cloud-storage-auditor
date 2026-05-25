"""
CORS policy security check.
Evaluates whether CORS configuration allows overly permissive cross-origin access.
"""
from __future__ import annotations
from providers.base import CorsConfig
from checks.base import CheckResult, CheckStatus, Severity, CISReference

# Checking if CORS policy is absent or restrictively configured
def check_cors_restrictive(config: CorsConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="cors_restrictive",
        check_name="CORS Policy",
        weight=weight,
        max_score=weight,
        severity=Severity.MEDIUM,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    if not config.cors_enabled:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = "No CORS policy configured (cross-origin access is blocked by default)"
        return result

    issues = []
    if config.allows_wildcard_origin:
        issues.append("allows wildcard origin (*)")
    if config.allows_all_methods:
        issues.append("allows all HTTP methods (GET, PUT, POST, DELETE)")
    if config.allows_all_headers:
        issues.append("allows all headers (*)")

    if not issues:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = (
            f"CORS is configured with {len(config.rules)} rule(s) "
            f"but does not contain overly permissive settings."
        )
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = (
            f"CORS policy is overly permissive: {'; '.join(issues)}. "
            f"This may enable cross-site data exfiltration."
        )
        result.remediation = (
            "Restrict CORS policy to specific trusted origins instead of using wildcards. "
            "Limit allowed methods to only those required (e.g., GET only). "
            "Specify explicit allowed headers rather than using wildcard (*)."
        )

    return result


def run_cors_checks(config: CorsConfig, provider: str, bucket_name: str, weights: dict, cis_mappings: dict) -> list[CheckResult]:
    provider_key = provider.lower()
    weight = weights.get("cors_restrictive", {}).get("weight", 0)
    cis = cis_mappings.get("cors_restrictive", {}).get(provider_key, {})
    return [check_cors_restrictive(config, provider_key, bucket_name, weight, cis)]
