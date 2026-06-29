
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from checks.base import AuditResult, CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

_COLORS = {
    "PASS": "\033[92m",   # green
    "FAIL": "\033[91m",   # red
    "WARNING": "\033[93m",  # yellow
    "ERROR": "\033[95m",  # magenta
    "N/A": "\033[90m",    # grey
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "HEADER": "\033[94m",  # blue
}


def _severity_color(severity: Severity) -> str:
    mapping = {
        Severity.CRITICAL: "\033[91m",
        Severity.HIGH: "\033[93m",
        Severity.MEDIUM: "\033[33m",
        Severity.LOW: "\033[36m",
        Severity.INFO: "\033[90m",
    }
    return mapping.get(severity, "")

def print_cli_report(audit: AuditResult, use_color: bool = True) -> None:
    c = _COLORS if use_color else {k: "" for k in _COLORS}

    print()
    print(f"{c['BOLD']}{'=' * 80}{c['RESET']}")
    print(f"{c['BOLD']}  CLOUD STORAGE SECURITY AUDIT REPORT{c['RESET']}")
    print(f"{c['BOLD']}{'=' * 80}{c['RESET']}")
    print(f"  Provider:  {audit.provider.upper()}")
    print(f"  Bucket:    {audit.bucket_name}")
    print(f"  Date:      {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{c['BOLD']}{'─' * 80}{c['RESET']}")

    # Overall score
    score_color = c["PASS"] if audit.normalised_score >= 70 else (
        c["WARNING"] if audit.normalised_score >= 40 else c["FAIL"]
    )
    print(f"\n  {c['BOLD']}Overall Security Score: "
          f"{score_color}{audit.normalised_score:.1f} / 100{c['RESET']}\n")

    # Category breakdown
    print(f"  {c['HEADER']}Category Scores:{c['RESET']}")
    for cat, score in sorted(audit.category_scores.items()):
        bar_len = int(score / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        cat_color = c["PASS"] if score >= 70 else (c["WARNING"] if score >= 40 else c["FAIL"])
        print(f"    {cat:<25s} {cat_color}{bar} {score:5.1f}%{c['RESET']}")

    print(f"\n{c['BOLD']}{'─' * 80}{c['RESET']}")
    print(f"  {c['HEADER']}Detailed Check Results:{c['RESET']}\n")

    # Header
    print(f"  {'Status':<8s} {'Score':>6s} {'Check':<35s} {'Severity':<10s} {'CIS Ref':<10s}")
    print(f"  {'─' * 8} {'─' * 6} {'─' * 35} {'─' * 10} {'─' * 10}")

    for r in audit.check_results:
        status_str = r.status.value
        status_c = c.get(status_str, "")
        sev_c = _severity_color(r.severity) if use_color else ""
        cis_id = r.cis_reference.cis_id if r.cis_reference.cis_id else "N/A"
        score_str = f"{r.score_contribution:.0f}/{r.max_score:.0f}"

        print(
            f"  {status_c}{status_str:<8s}{c['RESET']} "
            f"{score_str:>6s} "
            f"{r.check_name:<35s} "
            f"{sev_c}{r.severity.value:<10s}{c['RESET']} "
            f"{cis_id:<10s}"
        )

    failed = [r for r in audit.check_results if r.status == CheckStatus.FAIL]
    if failed:
        print(f"\n{c['BOLD']}{'─' * 80}{c['RESET']}")
        print(f"  {c['FAIL']}Findings & Remediation ({len(failed)} issue(s)):{c['RESET']}\n")

        for i, r in enumerate(failed, 1):
            sev_c = _severity_color(r.severity) if use_color else ""
            print(f"  {c['BOLD']}{i}. [{sev_c}{r.severity.value}{c['RESET']}{c['BOLD']}] "
                  f"{r.check_name}{c['RESET']}")
            print(f"     Finding:     {r.details}")
            print(f"     Remediation: {r.remediation}")
            if r.cis_reference.cis_id:
                print(f"     CIS Ref:     {r.cis_reference.cis_id} — {r.cis_reference.control}")
            print()

    print(f"{c['BOLD']}{'=' * 80}{c['RESET']}\n")

def generate_json_report(audit: AuditResult) -> dict:
    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "cloud-storage-auditor",
            "version": "1.0.0",
        },
        "summary": {
            "provider": audit.provider,
            "bucket": audit.bucket_name,
            "overall_score": audit.normalised_score,
            "max_score": 100,
            "total_checks": len(audit.check_results),
            "passed": sum(1 for r in audit.check_results if r.status == CheckStatus.PASS),
            "failed": sum(1 for r in audit.check_results if r.status == CheckStatus.FAIL),
            "warnings": sum(1 for r in audit.check_results if r.status == CheckStatus.WARNING),
            "errors": sum(1 for r in audit.check_results if r.status == CheckStatus.ERROR),
        },
        "category_scores": audit.category_scores,
        "checks": [
            {
                "check_id": r.check_id,
                "check_name": r.check_name,
                "status": r.status.value,
                "severity": r.severity.value,
                "weight": r.weight,
                "score": r.score_contribution,
                "max_score": r.max_score,
                "details": r.details,
                "remediation": r.remediation,
                "cis_reference": {
                    "cis_id": r.cis_reference.cis_id,
                    "control": r.cis_reference.control,
                    "benchmark": r.cis_reference.benchmark,
                } if r.cis_reference.cis_id else None,
            }
            for r in audit.check_results
        ],
    }


def save_json_report(audit: AuditResult, output_path: str) -> None:
    report = generate_json_report(audit)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("JSON report saved to %s", path)

def generate_html_report(audit: AuditResult) -> str:
    score_class = (
        "score-good" if audit.normalised_score >= 70
        else "score-warn" if audit.normalised_score >= 40
        else "score-bad"
    )

    checks_html = ""
    for r in audit.check_results:
        status_class = r.status.value.lower().replace("/", "")
        cis_id = r.cis_reference.cis_id if r.cis_reference.cis_id else "N/A"
        checks_html += f"""
        <tr class="{status_class}">
            <td><span class="status-badge status-{status_class}">{r.status.value}</span></td>
            <td>{r.score_contribution:.0f}/{r.max_score:.0f}</td>
            <td>{r.check_name}</td>
            <td>{r.severity.value}</td>
            <td>{cis_id}</td>
            <td>{r.details}</td>
            <td>{r.remediation if r.status == CheckStatus.FAIL else ''}</td>
        </tr>"""

    categories_html = ""
    for cat, score in sorted(audit.category_scores.items()):
        cat_class = "score-good" if score >= 70 else ("score-warn" if score >= 40 else "score-bad")
        categories_html += f"""
        <div class="category">
            <span class="cat-name">{cat}</span>
            <div class="progress-bar">
                <div class="progress-fill {cat_class}" style="width: {score}%"></div>
            </div>
            <span class="cat-score {cat_class}">{score:.1f}%</span>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cloud Storage Audit — {audit.provider.upper()} / {audit.bucket_name}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1100px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #2c3e50; margin-top: 30px; }}
        .meta {{ color: #666; margin-bottom: 20px; }}
        .score-box {{ text-align: center; padding: 20px; margin: 20px 0; border-radius: 8px; }}
        .score-good {{ color: #27ae60; }} .score-warn {{ color: #f39c12; }} .score-bad {{ color: #e74c3c; }}
        .score-box .score {{ font-size: 48px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        th {{ background: #2c3e50; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f9f9f9; }}
        .status-badge {{ padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .status-pass {{ background: #d4edda; color: #155724; }}
        .status-fail {{ background: #f8d7da; color: #721c24; }}
        .status-warning {{ background: #fff3cd; color: #856404; }}
        .category {{ display: flex; align-items: center; margin: 8px 0; }}
        .cat-name {{ width: 200px; font-weight: 500; }}
        .progress-bar {{ flex: 1; height: 20px; background: #ecf0f1; border-radius: 10px; overflow: hidden; margin: 0 10px; }}
        .progress-fill {{ height: 100%; border-radius: 10px; transition: width 0.3s; }}
        .progress-fill.score-good {{ background: #27ae60; }}
        .progress-fill.score-warn {{ background: #f39c12; }}
        .progress-fill.score-bad {{ background: #e74c3c; }}
        .cat-score {{ width: 60px; text-align: right; font-weight: bold; }}
    </style>
</head>
<body>
<div class="container">
    <h1>Cloud Storage Security Audit Report</h1>
    <div class="meta">
        <strong>Provider:</strong> {audit.provider.upper()} &nbsp;|&nbsp;
        <strong>Bucket:</strong> {audit.bucket_name} &nbsp;|&nbsp;
        <strong>Date:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
    </div>

    <div class="score-box">
        <div class="score {score_class}">{audit.normalised_score:.1f} / 100</div>
        <div>Overall Security Score</div>
    </div>

    <h2>Category Scores</h2>
    {categories_html}

    <h2>Detailed Results</h2>
    <table>
        <thead>
            <tr><th>Status</th><th>Score</th><th>Check</th><th>Severity</th><th>CIS</th><th>Details</th><th>Remediation</th></tr>
        </thead>
        <tbody>
            {checks_html}
        </tbody>
    </table>
</div>
</body>
</html>"""
    return html


def save_html_report(audit: AuditResult, output_path: str) -> None:
    html = generate_html_report(audit)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(html)
    logger.info("HTML report saved to %s", path)
