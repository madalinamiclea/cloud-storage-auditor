"""
Public object exposure security check.
Evaluating if individual objects within a bucket are publicly accessible.
"""
from __future__ import annotations
from providers.base import PublicExposureConfig
from checks.base import CheckResult, CheckStatus, Severity, CISReference


def check_no_public_objects(config: PublicExposureConfig, provider: str, bucket_name: str, weight: float, cis: dict) -> CheckResult:
    result = CheckResult(
        check_id="no_public_objects",
        check_name="No Public Objects",
        weight=weight,
        max_score=weight,
        severity=Severity.CRITICAL,
        provider=provider,
        bucket_name=bucket_name,
        cis_reference=CISReference(**cis) if cis else CISReference(),
    )

    if config.objects_sampled == 0:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = "No objects found in bucket (empty bucket)."
        return result

    if config.public_objects_found == 0:
        result.status = CheckStatus.PASS
        result.score_contribution = weight
        result.details = (
            f"Sampled {config.objects_sampled} object(s), none are publicly accessible."
        )
    else:
        result.status = CheckStatus.FAIL
        result.score_contribution = 0.0
        result.details = (
            f"Found {config.public_objects_found} publicly accessible object(s) "
            f"out of {config.objects_sampled} sampled "
            f"(exposure ratio: {config.exposure_ratio:.1%}). "
            f"Public objects: {', '.join(config.public_object_names[:5])}"
        )
        if len(config.public_object_names) > 5:
            result.details += f" ... and {len(config.public_object_names) - 5} more."
        result.remediation = (
            "Review and remove public ACLs or permissions on individual objects. "
            "On AWS, enable Block Public Access to override object-level ACLs. "
            "On Azure, set container access level to Private. "
            "On GCP, enable Uniform Bucket-Level Access to prevent object-level ACLs."
        )

    return result


def run_public_exposure_checks(config: PublicExposureConfig, provider: str, bucket_name: str, weights: dict, cis_mappings: dict) -> list[CheckResult]:
    provider_key = provider.lower()
    weight = weights.get("no_public_objects", {}).get("weight", 0)
    cis = cis_mappings.get("no_public_objects", {}).get(provider_key, {})
    return [check_no_public_objects(config, provider_key, bucket_name, weight, cis)]
