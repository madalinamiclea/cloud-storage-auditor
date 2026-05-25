"""
comparison/vs_existing_tools.py — Comparison with existing auditing tools.

Provides utilities for comparing the results of this framework with
Prowler and ScoutSuite output, addressing RQ4 from the thesis.

The module can:
  1. Parse Prowler JSON/CSV output and extract storage-related findings
  2. Parse ScoutSuite JSON output and extract storage-related findings
  3. Compare detection coverage against our framework's results
  4. Generate a comparative analysis report
"""

import json
import csv
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

from checks.base import AuditResult, CheckStatus

logger = logging.getLogger(__name__)


@dataclass
class ExternalToolResult:
    """Parsed results from an external auditing tool."""
    tool_name: str = ""
    provider: str = ""
    total_findings: int = 0
    storage_findings: int = 0
    findings: list = field(default_factory=list)  # list of dicts with check details
    severity_breakdown: dict = field(default_factory=dict)


@dataclass
class ToolComparison:
    """Comparison between our framework and an external tool."""
    our_tool: str = "cloud-storage-auditor"
    external_tool: str = ""
    provider: str = ""
    bucket_name: str = ""

    # Coverage comparison
    our_checks_count: int = 0
    external_checks_count: int = 0

    # Detection overlap
    both_detected: list = field(default_factory=list)    # Issues found by both tools
    only_ours: list = field(default_factory=list)         # Issues found only by our tool
    only_external: list = field(default_factory=list)     # Issues found only by external tool

    our_score: float = 0.0
    external_severity_summary: dict = field(default_factory=dict)


# =============================================================================
# Prowler Output Parsing
# =============================================================================

# Provider-specific mapping from Prowler check IDs to our check IDs.
# Keys are (provider, prowler_check_id) tuples; values are lists of our
# check IDs that the external check semantically covers.
PROWLER_TO_OURS = {
    # --- AWS (S3) ---
    ("aws", "s3_bucket_public_access"): ["public_access_block"],
    ("aws", "s3_bucket_policy_public_write_access"): ["iam_policy_least_privilege"],
    ("aws", "s3_bucket_acl_prohibited"): ["acl_not_public"],
    ("aws", "s3_bucket_default_encryption"): ["encryption_at_rest"],
    ("aws", "s3_bucket_secure_transport_policy"): ["encryption_in_transit"],
    ("aws", "s3_bucket_server_access_logging_enabled"): ["access_logging"],
    ("aws", "cloudtrail_multi_region_enabled"): ["audit_trail"],
    ("aws", "s3_bucket_versioning"): ["versioning_enabled"],
    ("aws", "s3_bucket_object_lock"): ["soft_delete_or_mfa_delete"],
    ("aws", "s3_bucket_lifecycle_policy"): ["lifecycle_policy"],
    ("aws", "s3_bucket_cors_wildcard"): ["cors_restrictive"],
    # --- Azure ---
    ("azure", "storage_blob_public_access_level_is_disabled"): ["public_access_block", "acl_not_public"],
    ("azure", "storage_default_network_access_rule_is_denied"): ["public_access_block"],
    ("azure", "storage_ensure_encryption_with_customer_managed_keys"): ["encryption_at_rest"],
    ("azure", "storage_secure_transfer_required_is_enabled"): ["encryption_in_transit"],
    ("azure", "storage_ensure_minimum_tls_version_12"): ["encryption_in_transit"],
    ("azure", "storage_blob_versioning_is_enabled"): ["versioning_enabled"],
    ("azure", "storage_ensure_soft_delete_is_enabled"): ["soft_delete_or_mfa_delete"],
    ("azure", "storage_ensure_file_shares_soft_delete_is_enabled"): ["soft_delete_or_mfa_delete"],
    # --- GCP ---
    ("gcp", "cloudstorage_bucket_public_access"): ["public_access_block", "iam_policy_least_privilege", "no_public_objects"],
    ("gcp", "cloudstorage_bucket_uniform_bucket_level_access"): ["acl_not_public"],
    ("gcp", "cloudstorage_bucket_logging_enabled"): ["access_logging"],
    ("gcp", "cloudstorage_audit_logs_enabled"): ["audit_trail"],
    ("gcp", "cloudstorage_bucket_versioning_enabled"): ["versioning_enabled"],
    ("gcp", "cloudstorage_bucket_soft_delete_enabled"): ["soft_delete_or_mfa_delete"],
    ("gcp", "cloudstorage_bucket_sufficient_retention_period"): ["soft_delete_or_mfa_delete"],
    ("gcp", "cloudstorage_bucket_lifecycle_management_enabled"): ["lifecycle_policy"],
}  # type: Dict[Tuple[str, str], list]

# Provider-specific mapping from ScoutSuite finding IDs to our check IDs.
SCOUTSUITE_TO_OURS = {
    # --- Azure ---
    ("azure", "storageaccount-public-blob-container"): ["public_access_block", "acl_not_public", "no_public_objects"],
    ("azure", "storageaccount-public-traffic-allowed"): ["public_access_block"],
    ("azure", "storageaccount-encrypted-not-customer-managed"): ["encryption_at_rest"],
    ("azure", "storageaccount-account-allowing-clear-text"): ["encryption_in_transit"],
    ("azure", "storageaccount-soft-delete-enabled"): ["soft_delete_or_mfa_delete"],
    # --- GCP ---
    ("gcp", "cloudstorage-bucket-no-public-access-prevention"): ["public_access_block"],
    ("gcp", "cloudstorage-bucket-allUsers"): ["public_access_block", "iam_policy_least_privilege", "no_public_objects"],
    ("gcp", "cloudstorage-bucket-allAuthenticatedUsers"): ["public_access_block", "iam_policy_least_privilege", "no_public_objects"],
    ("gcp", "cloudstorage-uniform-bucket-level-access-disabled"): ["acl_not_public"],
    ("gcp", "cloudstorage-bucket-no-logging"): ["access_logging"],
    ("gcp", "cloudstorage-bucket-no-versioning"): ["versioning_enabled"],
}  # type: Dict[Tuple[str, str], list]


def parse_prowler_json(filepath: str) -> ExternalToolResult:
    """Parse Prowler JSON output and extract storage-related findings."""
    result = ExternalToolResult(tool_name="Prowler")

    path = Path(filepath)
    if not path.exists():
        logger.error("Prowler output file not found: %s", filepath)
        return result

    with open(path, "r") as f:
        # Prowler outputs JSON lines (one JSON object per line)
        findings = []
        content = f.read().strip()
        if content.startswith("["):
            findings = json.loads(content)
        else:
            for line in content.split("\n"):
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    result.total_findings = len(findings)

    # Filter storage-related findings
    storage_keywords = ["s3", "storage", "blob", "bucket", "container", "object"]
    for finding in findings:
        service = str(finding.get("ServiceName", finding.get("service_name", ""))).lower()
        check_id = str(finding.get("CheckID", finding.get("check_id", ""))).lower()
        resource = str(finding.get("ResourceId", finding.get("resource_id", ""))).lower()

        is_storage = any(kw in service or kw in check_id or kw in resource
                        for kw in storage_keywords)
        if is_storage:
            result.storage_findings += 1
            status = finding.get("Status", finding.get("status", "")).upper()
            severity = finding.get("Severity", finding.get("severity", "")).capitalize()
            result.findings.append({
                "check_id": finding.get("CheckID", finding.get("check_id", "")),
                "check_title": finding.get("CheckTitle", finding.get("check_title", "")),
                "status": status,
                "severity": severity,
                "resource": finding.get("ResourceId", finding.get("resource_id", "")),
                "details": finding.get("StatusExtended", finding.get("status_extended", "")),
            })

            if severity:
                result.severity_breakdown[severity] = result.severity_breakdown.get(severity, 0) + 1

    result.provider = findings[0].get("Provider", "unknown").lower() if findings else "unknown"
    return result


def parse_prowler_csv(filepath: str) -> ExternalToolResult:
    """Parse Prowler CSV output and extract storage-related findings."""
    result = ExternalToolResult(tool_name="Prowler")

    path = Path(filepath)
    if not path.exists():
        logger.error("Prowler CSV file not found: %s", filepath)
        return result

    with open(path, "r") as f:
        reader = csv.DictReader(f, delimiter=";")
        storage_keywords = ["s3", "storage", "blob", "bucket"]

        for row in reader:
            result.total_findings += 1
            service = str(row.get("SERVICE_NAME", row.get("service_name", ""))).lower()
            check_id = str(row.get("CHECK_ID", row.get("check_id", ""))).lower()

            if any(kw in service or kw in check_id for kw in storage_keywords):
                result.storage_findings += 1
                status = row.get("STATUS", row.get("status", "")).upper()
                severity = row.get("SEVERITY", row.get("severity", "")).capitalize()
                result.findings.append({
                    "check_id": row.get("CHECK_ID", row.get("check_id", "")),
                    "check_title": row.get("CHECK_TITLE", row.get("check_title", "")),
                    "status": status,
                    "severity": severity,
                    "resource": row.get("RESOURCE_ID", row.get("resource_id", "")),
                    "details": row.get("STATUS_EXTENDED", row.get("status_extended", "")),
                })

                if severity:
                    result.severity_breakdown[severity] = result.severity_breakdown.get(severity, 0) + 1

    return result


# =============================================================================
# ScoutSuite Output Parsing
# =============================================================================

def parse_scoutsuite_json(filepath: str) -> ExternalToolResult:
    """Parse ScoutSuite JSON results and extract storage-related findings."""
    result = ExternalToolResult(tool_name="ScoutSuite")

    path = Path(filepath)
    if not path.exists():
        logger.error("ScoutSuite output file not found: %s", filepath)
        return result

    with open(path, "r") as f:
        data = json.load(f)

    # ScoutSuite stores results by service
    services = data.get("services", {})

    # Look for S3 / Storage / Cloud Storage services
    storage_services = {}
    for svc_name, svc_data in services.items():
        if any(kw in svc_name.lower() for kw in ["s3", "storage", "cloudstorage"]):
            storage_services[svc_name] = svc_data

    for svc_name, svc_data in storage_services.items():
        findings = svc_data.get("findings", {})
        for finding_id, finding_data in findings.items():
            result.total_findings += 1
            result.storage_findings += 1

            items = finding_data.get("items", [])
            flagged = finding_data.get("flagged_items", 0)
            level = finding_data.get("level", "warning")
            severity_map = {"danger": "Critical", "warning": "High", "info": "Medium"}
            severity = severity_map.get(level, "Medium")

            result.findings.append({
                "check_id": finding_id,
                "check_title": finding_data.get("description", ""),
                "status": "FAIL" if flagged > 0 else "PASS",
                "severity": severity,
                "flagged_items": flagged,
                "total_items": len(items),
            })

            if severity:
                result.severity_breakdown[severity] = result.severity_breakdown.get(severity, 0) + 1

    result.provider = data.get("provider_code", "unknown").lower()
    return result


# =============================================================================
# Comparison Logic
# =============================================================================

def _get_mapping(tool_name):
    # type: (...) -> dict
    """Return the provider-aware mapping dict for the given external tool."""
    if tool_name.lower() == "scoutsuite":
        return SCOUTSUITE_TO_OURS
    return PROWLER_TO_OURS


def compare_with_external(our_audit: AuditResult,
                          external: ExternalToolResult) -> ToolComparison:
    """
    Compare our audit results with an external tool's findings.

    Matches findings based on the provider-specific check ID mapping and
    classifies them as detected by both, only by our tool, or only by the
    external tool.  Each external finding may map to multiple of our checks.
    """
    provider = our_audit.provider.lower()
    mapping = _get_mapping(external.tool_name)

    comp = ToolComparison(
        external_tool=external.tool_name,
        provider=provider,
        bucket_name=our_audit.bucket_name,
        our_checks_count=len(our_audit.check_results),
        external_checks_count=external.storage_findings,
        our_score=our_audit.normalised_score,
        external_severity_summary=external.severity_breakdown,
    )

    # Map our failed/passed checks
    our_failures = {r.check_id: r for r in our_audit.check_results
                    if r.status == CheckStatus.FAIL}
    our_passes = {r.check_id: r for r in our_audit.check_results
                  if r.status == CheckStatus.PASS}

    # Map external failures using provider-aware mapping (1:many)
    external_failures = {}  # type: Dict[str, dict]
    external_passes = {}  # type: Dict[str, dict]
    for f in external.findings:
        ext_check_id = f["check_id"]
        our_equivalents = mapping.get((provider, ext_check_id), [])
        for our_eq in our_equivalents:
            if f["status"] == "FAIL":
                if our_eq not in external_failures:
                    external_failures[our_eq] = f
            else:
                if our_eq not in external_passes:
                    external_passes[our_eq] = f

    # Classify
    all_check_ids = set(list(our_failures.keys()) + list(our_passes.keys()) +
                        list(external_failures.keys()) + list(external_passes.keys()))

    for check_id in all_check_ids:
        our_failed = check_id in our_failures
        ext_failed = check_id in external_failures

        if our_failed and ext_failed:
            comp.both_detected.append({
                "check_id": check_id,
                "our_details": our_failures[check_id].details,
                "external_details": external_failures[check_id].get("details", ""),
            })
        elif our_failed and not ext_failed:
            comp.only_ours.append({
                "check_id": check_id,
                "details": our_failures[check_id].details,
                "note": "Not detected or not checked by " + external.tool_name,
            })
        elif ext_failed and not our_failed:
            comp.only_external.append({
                "check_id": check_id,
                "details": external_failures.get(check_id, {}).get("details", ""),
                "note": "Detected by " + external.tool_name + " but passed our checks",
            })

    return comp


def print_tool_comparison(comp: ToolComparison) -> None:
    """Print comparison report between our tool and an external tool."""
    print(f"\n{'=' * 70}")
    print(f"  TOOL COMPARISON: {comp.our_tool} vs {comp.external_tool}")
    print(f"{'=' * 70}")
    print(f"  Provider: {comp.provider.upper()}  |  Bucket: {comp.bucket_name}")
    print(f"\n  Our framework:    {comp.our_checks_count} checks  |  Score: {comp.our_score:.1f}/100")
    print(f"  {comp.external_tool}:   {comp.external_checks_count} storage-related findings")

    if comp.external_severity_summary:
        print(f"  Severity breakdown: {comp.external_severity_summary}")

    print(f"\n  Detection Overlap:")
    print(f"    Both detected:     {len(comp.both_detected)} issue(s)")
    print(f"    Only our tool:     {len(comp.only_ours)} issue(s)")
    print(f"    Only {comp.external_tool}:  {len(comp.only_external)} issue(s)")

    if comp.both_detected:
        print(f"\n  Issues detected by BOTH tools:")
        for item in comp.both_detected:
            print(f"    - {item['check_id']}")

    if comp.only_ours:
        print(f"\n  Issues detected ONLY by our framework:")
        for item in comp.only_ours:
            print(f"    - {item['check_id']}: {item['details']}")

    if comp.only_external:
        print(f"\n  Issues detected ONLY by {comp.external_tool}:")
        for item in comp.only_external:
            print(f"    - {item['check_id']}: {item.get('details', '')}")

    print(f"{'=' * 70}\n")
