#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json

from pathlib import Path
from checks.base import AuditResult, CheckResult, CheckStatus, Severity, CISReference
from comparison.vs_existing_tools import (
    compare_with_external,
    parse_prowler_csv,
    parse_prowler_json,
    parse_scoutsuite_json,
)


def _to_status(value: str) -> CheckStatus:
    mapping = {
        "PASS": CheckStatus.PASS,
        "FAIL": CheckStatus.FAIL,
        "WARNING": CheckStatus.WARNING,
        "ERROR": CheckStatus.ERROR,
        "N/A": CheckStatus.NOT_APPLICABLE,
        "NOT_APPLICABLE": CheckStatus.NOT_APPLICABLE,
    }
    return mapping.get(str(value).upper(), CheckStatus.ERROR)


def _to_severity(value: str) -> Severity:
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFORMATIONAL": Severity.INFO,
        "INFO": Severity.INFO,
    }
    return mapping.get(str(value).upper(), Severity.MEDIUM)


def load_our_report(path: Path) -> AuditResult:
    data = json.loads(path.read_text())
    summary = data.get("summary", {})

    audit = AuditResult(
        provider=str(summary.get("provider", "")),
        bucket_name=str(summary.get("bucket", "")),
        normalised_score=float(summary.get("overall_score", 0.0)),
        max_possible_score=float(summary.get("max_score", 100.0)),
        category_scores=data.get("category_scores", {}),
    )

    checks = []
    for item in data.get("checks", []):
        cis = item.get("cis_reference") or {}
        checks.append(
            CheckResult(
                check_id=item.get("check_id", ""),
                check_name=item.get("check_name", ""),
                status=_to_status(item.get("status", "ERROR")),
                severity=_to_severity(item.get("severity", "Medium")),
                weight=float(item.get("weight", 0.0)),
                score_contribution=float(item.get("score", 0.0)),
                max_score=float(item.get("max_score", 0.0)),
                details=item.get("details", ""),
                remediation=item.get("remediation", ""),
                cis_reference=CISReference(
                    cis_id=cis.get("cis_id", "") if isinstance(cis, dict) else "",
                    control=cis.get("control", "") if isinstance(cis, dict) else "",
                    benchmark=cis.get("benchmark", "") if isinstance(cis, dict) else "",
                ),
                provider=audit.provider,
                bucket_name=audit.bucket_name,
            )
        )

    audit.check_results = checks
    return audit


def find_our_reports(ours_root: Path) -> list[tuple[str, str, Path]]:
    providers = ["aws", "azure", "gcp"]
    scenarios = ["default", "misconfigured", "hardened"]
    found = []
    for provider in providers:
        for scenario in scenarios:
            path = ours_root / provider / f"{scenario}.json"
            if path.exists():
                found.append((provider, scenario, path))
    return found


def find_prowler_file(root: Path, provider: str, scenario: str) -> Path | None:
    json_path = root / provider / f"{scenario}.json"
    csv_path = root / provider / f"{scenario}.csv"
    if json_path.exists():
        return json_path
    if csv_path.exists():
        return csv_path
    return None


def find_scoutsuite_file(root: Path, provider: str, scenario: str) -> Path | None:
    path = root / provider / f"{scenario}.json"
    return path if path.exists() else None


def write_markdown(rows: list[dict], path: Path) -> None:
    lines = [
        "| Provider | Scenario | Tool | Both detected | Only ours | Only external | Our score | External findings |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['provider']} | {r['scenario']} | {r['tool']} | {r['both_detected']} | {r['only_ours']} | {r['only_external']} | {r['our_score']:.1f} | {r['external_storage_findings']} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate RQ4 comparison table against Prowler/ScoutSuite outputs."
    )
    parser.add_argument("--ours-root", default="results", help="Root folder of our JSON reports")
    parser.add_argument("--prowler-root", default="external/prowler", help="Root folder for Prowler outputs")
    parser.add_argument("--scoutsuite-root", default="external/scoutsuite", help="Root folder for ScoutSuite outputs")
    parser.add_argument("--tools", nargs="+", choices=["prowler", "scoutsuite"], default=["prowler", "scoutsuite"])
    parser.add_argument("--output-csv", default="results/tables/rq4_comparison.csv")
    parser.add_argument("--output-md", default="results/tables/rq4_comparison.md")
    args = parser.parse_args()

    ours_root = Path(args.ours_root)
    prowler_root = Path(args.prowler_root)
    scout_root = Path(args.scoutsuite_root)

    reports = find_our_reports(ours_root)
    if not reports:
        raise SystemExit(f"No reports found under {ours_root}. Expected results/<provider>/<scenario>.json")

    rows: list[dict] = []

    for provider, scenario, report_path in reports:
        our_audit = load_our_report(report_path)

        if "prowler" in args.tools:
            ext_path = find_prowler_file(prowler_root, provider, scenario)
            if ext_path:
                external = parse_prowler_json(str(ext_path)) if ext_path.suffix.lower() == ".json" else parse_prowler_csv(str(ext_path))
                comp = compare_with_external(our_audit, external)
                rows.append({
                    "provider": provider,
                    "scenario": scenario,
                    "tool": "prowler",
                    "both_detected": len(comp.both_detected),
                    "only_ours": len(comp.only_ours),
                    "only_external": len(comp.only_external),
                    "our_score": comp.our_score,
                    "external_storage_findings": external.storage_findings,
                })

        if "scoutsuite" in args.tools:
            ext_path = find_scoutsuite_file(scout_root, provider, scenario)
            if ext_path:
                external = parse_scoutsuite_json(str(ext_path))
                comp = compare_with_external(our_audit, external)
                rows.append({
                    "provider": provider,
                    "scenario": scenario,
                    "tool": "scoutsuite",
                    "both_detected": len(comp.both_detected),
                    "only_ours": len(comp.only_ours),
                    "only_external": len(comp.only_external),
                    "our_score": comp.our_score,
                    "external_storage_findings": external.storage_findings,
                })

    if not rows:
        raise SystemExit(
            "No comparable external files found. Expected paths like external/prowler/<provider>/<scenario>.json (or .csv) and external/scoutsuite/<provider>/<scenario>.json"
        )

    output_csv = Path(args.output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "provider",
                "scenario",
                "tool",
                "both_detected",
                "only_ours",
                "only_external",
                "our_score",
                "external_storage_findings",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    write_markdown(rows, Path(args.output_md))

    print(f"Saved CSV: {output_csv}")
    print(f"Saved Markdown: {args.output_md}")
    print(f"Rows: {len(rows)}")


if __name__ == "__main__":
    main()
