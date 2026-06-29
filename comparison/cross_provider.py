
from __future__ import annotations
import json
import logging

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from checks.base import AuditResult, CheckStatus

logger = logging.getLogger(__name__)


@dataclass
class ProviderComparison:
    providers: list = field(default_factory=list)
    results: dict = field(default_factory=dict)

    overall_scores: dict = field(default_factory=dict)
    category_comparison: dict = field(default_factory=dict)
    check_comparison: dict = field(default_factory=dict)
    risk_ranking: list = field(default_factory=list)
    common_failures: list = field(default_factory=list)
    provider_specific_issues: dict = field(default_factory=dict)


def compare_providers(results: dict[str, AuditResult]) -> ProviderComparison:
    comparison = ProviderComparison(
        providers=list(results.keys()),
        results=results,
    )

    comparison.overall_scores = {
        provider: r.normalised_score for provider, r in results.items()
    }

    comparison.risk_ranking = sorted(
        results.keys(), key=lambda p: results[p].normalised_score
    )

    all_categories = set()
    for r in results.values():
        all_categories.update(r.category_scores.keys())

    comparison.category_comparison = {
        cat: {provider: r.category_scores.get(cat, 0) for provider, r in results.items()}
        for cat in sorted(all_categories)
    }

    all_check_ids = set()
    for r in results.values():
        for cr in r.check_results:
            all_check_ids.add(cr.check_id)

    comparison.check_comparison = {}
    for check_id in sorted(all_check_ids):
        comparison.check_comparison[check_id] = {}
        for provider, r in results.items():
            for cr in r.check_results:
                if cr.check_id == check_id:
                    comparison.check_comparison[check_id][provider] = {
                        "status": cr.status.value,
                        "score": cr.score_contribution,
                        "max_score": cr.max_score,
                        "details": cr.details,
                    }
                    break

    comparison.common_failures = []
    for check_id, provider_data in comparison.check_comparison.items():
        if all(
            d.get("status") == CheckStatus.FAIL.value
            for d in provider_data.values()
        ):
            comparison.common_failures.append(check_id)

    comparison.provider_specific_issues = {p: [] for p in results.keys()}
    for check_id, provider_data in comparison.check_comparison.items():
        for provider in results.keys():
            if provider_data.get(provider, {}).get("status") == CheckStatus.FAIL.value:
                others_pass = all(
                    provider_data.get(other, {}).get("status") != CheckStatus.FAIL.value
                    for other in results.keys() if other != provider
                )
                if others_pass:
                    comparison.provider_specific_issues[provider].append(check_id)

    return comparison


def print_comparison_report(comp: ProviderComparison, use_color: bool = True) -> None:
    c_green = "\033[92m" if use_color else ""
    c_red = "\033[91m" if use_color else ""
    c_yellow = "\033[93m" if use_color else ""
    c_bold = "\033[1m" if use_color else ""
    c_blue = "\033[94m" if use_color else ""
    c_reset = "\033[0m" if use_color else ""

    print(f"\n{c_bold}{'=' * 80}{c_reset}")
    print(f"{c_bold}  CROSS-PROVIDER SECURITY COMPARISON{c_reset}")
    print(f"{c_bold}{'=' * 80}{c_reset}")

    print(f"\n{c_blue}  Overall Security Scores:{c_reset}")
    for provider in comp.risk_ranking:
        score = comp.overall_scores[provider]
        sc = c_green if score >= 70 else (c_yellow if score >= 40 else c_red)
        bar_len = int(score / 2.5)
        bar = "█" * bar_len + "░" * (40 - bar_len)
        print(f"    {provider.upper():<8s} {sc}{bar} {score:5.1f}/100{c_reset}")

    print(f"\n{c_blue}  Category Comparison:{c_reset}")
    print(f"    {'Category':<25s}", end="")
    for p in comp.providers:
        print(f" {p.upper():>10s}", end="")
    print(f" {'Best':>10s}")
    print(f"    {'─' * 25}", end="")
    for _ in comp.providers:
        print(f" {'─' * 10}", end="")
    print(f" {'─' * 10}")

    for cat, scores in comp.category_comparison.items():
        print(f"    {cat:<25s}", end="")
        best_provider = max(scores, key=scores.get)
        for p in comp.providers:
            score = scores.get(p, 0)
            sc = c_green if score >= 70 else (c_yellow if score >= 40 else c_red)
            marker = " *" if p == best_provider else "  "
            print(f" {sc}{score:7.1f}%{marker}{c_reset}", end="")
        print(f" {best_provider.upper():>10s}")

    print(f"\n{c_blue}  Check-Level Comparison:{c_reset}")
    print(f"    {'Check':<35s}", end="")
    for p in comp.providers:
        print(f" {p.upper():>8s}", end="")
    print()
    print(f"    {'─' * 35}", end="")
    for _ in comp.providers:
        print(f" {'─' * 8}", end="")
    print()

    for check_id, provider_data in comp.check_comparison.items():
        check_name = check_id.replace("_", " ").title()
        print(f"    {check_name:<35s}", end="")
        for p in comp.providers:
            status = provider_data.get(p, {}).get("status", "N/A")
            if status == "PASS":
                print(f" {c_green}{'PASS':>8s}{c_reset}", end="")
            elif status == "FAIL":
                print(f" {c_red}{'FAIL':>8s}{c_reset}", end="")
            else:
                print(f" {status:>8s}", end="")
        print()

    if comp.common_failures:
        print(f"\n{c_red}  Common Failures (fail on ALL providers):{c_reset}")
        for check_id in comp.common_failures:
            print(f"    - {check_id.replace('_', ' ').title()}")

    for provider, issues in comp.provider_specific_issues.items():
        if issues:
            print(f"\n{c_yellow}  {provider.upper()}-Specific Issues (fail only on {provider.upper()}):{c_reset}")
            for check_id in issues:
                details = comp.check_comparison[check_id].get(provider, {}).get("details", "")
                print(f"    - {check_id.replace('_', ' ').title()}: {details}")

    print(f"\n{c_bold}  Summary:{c_reset}")
    best = comp.risk_ranking[-1]
    worst = comp.risk_ranking[0]
    print(f"    Best security posture:  {c_green}{best.upper()} "
          f"({comp.overall_scores[best]:.1f}/100){c_reset}")
    print(f"    Worst security posture: {c_red}{worst.upper()} "
          f"({comp.overall_scores[worst]:.1f}/100){c_reset}")
    score_diff = comp.overall_scores[best] - comp.overall_scores[worst]
    print(f"    Score difference:       {score_diff:.1f} points")

    print(f"\n{c_bold}{'=' * 80}{c_reset}\n")


def save_comparison_json(comp: ProviderComparison, output_path: str) -> None:
    report = {
        "providers": comp.providers,
        "overall_scores": comp.overall_scores,
        "risk_ranking": comp.risk_ranking,
        "category_comparison": comp.category_comparison,
        "check_comparison": comp.check_comparison,
        "common_failures": comp.common_failures,
        "provider_specific_issues": comp.provider_specific_issues,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", path)
