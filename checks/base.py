"""
Base class for security checks and result data model.
---------------
Each check evaluates one security property from the normalised config dataclasses
and returns a CheckResult with pass/fail status, score contribution, CIS mapping
and remediation advice.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class CheckStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"
    NOT_APPLICABLE = "N/A"


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class CISReference:
    cis_id: str = ""
    control: str = ""
    benchmark: str = ""
    note: Optional[str] = None


@dataclass
class CheckResult:
    check_id: str
    check_name: str
    status: CheckStatus = CheckStatus.ERROR
    severity: Severity = Severity.MEDIUM
    weight: float = 0.0
    score_contribution: float = 0.0
    max_score: float = 0.0
    details: str = ""
    remediation: str = ""
    cis_reference: CISReference = field(default_factory=CISReference)
    provider: str = ""
    bucket_name: str = ""


@dataclass
class AuditResult:
    bucket_name: str = ""
    provider: str = ""
    total_score: float = 0.0
    max_possible_score: float = 100.0
    normalised_score: float = 0.0
    check_results: list = field(default_factory=list)
    category_scores: dict = field(default_factory=dict)

    def calculate_scores(self) -> None:
        self.total_score = sum(r.score_contribution for r in self.check_results)
        self.max_possible_score = sum(r.max_score for r in self.check_results)
        if self.max_possible_score > 0:
            self.normalised_score = round(
                (self.total_score / self.max_possible_score) * 100, 2
            )
        else:
            self.normalised_score = 0.0

        # Category breakdown
        categories = {}
        for r in self.check_results:
            cat = self._check_category(r.check_id)
            if cat not in categories:
                categories[cat] = {"earned": 0.0, "max": 0.0}
            categories[cat]["earned"] += r.score_contribution
            categories[cat]["max"] += r.max_score

        self.category_scores = {
            cat: round((v["earned"] / v["max"]) * 100, 2) if v["max"] > 0 else 0
            for cat, v in categories.items()
        }

    @staticmethod
    def _check_category(check_id: str) -> str:
        # Mapping check ID to security category
        mapping = {
            "public_access_block": "Access Control",
            "iam_policy_least_privilege": "Access Control",
            "acl_not_public": "Access Control",
            "encryption_at_rest": "Encryption",
            "encryption_in_transit": "Encryption",
            "access_logging": "Logging & Monitoring",
            "audit_trail": "Logging & Monitoring",
            "versioning_enabled": "Data Protection",
            "soft_delete_or_mfa_delete": "Data Protection",
            "lifecycle_policy": "Data Protection",
            "no_public_objects": "Public Exposure",
            "cors_restrictive": "CORS",
        }
        return mapping.get(check_id, "Other")
