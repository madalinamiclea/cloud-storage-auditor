"""
Scoring engine
"""

import yaml
import os
import logging
from __future__ import annotations
from pathlib import Path
from typing import Optional
from providers.base import BucketConfig
from checks.base import AuditResult
from checks.access_control import run_access_control_checks
from checks.encryption import run_encryption_checks
from checks.logging import run_logging_checks
from checks.versioning import run_versioning_checks
from checks.public_exposure import run_public_exposure_checks
from checks.cors import run_cors_checks

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def load_yaml(filepath: Path) -> dict:
    with open(filepath, "r") as f:
        return yaml.safe_load(f) or {}


class ScoringEngine:
    def __init__(
        self,
        weights_path: Optional[Path] = None,
        cis_mappings_path: Optional[Path] = None,
    ):
        self.weights_path = weights_path or CONFIG_DIR / "scoring_weights.yaml"
        self.cis_mappings_path = cis_mappings_path or CONFIG_DIR / "cis_mappings.yaml"

        self.weights: dict = {}
        self.cis_mappings: dict = {}
        self._load_config()

    def _load_config(self) -> None:
        raw_weights = load_yaml(self.weights_path)
        self.weights = raw_weights.get("checks", {})

        raw_cis = load_yaml(self.cis_mappings_path)
        self.cis_mappings = raw_cis.get("checks", {})

        total_weight = sum(c.get("weight", 0) for c in self.weights.values())
        logger.info(
            "Loaded %d checks (total weight: %d) and %d CIS mappings",
            len(self.weights), total_weight, len(self.cis_mappings),
        )

        if total_weight != 100:
            logger.warning(
                "Total weight is %d (expected 100). Scores will be normalised.",
                total_weight,
            )

    def audit_bucket(self, bucket_config: BucketConfig) -> AuditResult:
        provider = bucket_config.bucket_info.provider.value
        bucket_name = bucket_config.bucket_info.name

        all_results = []

        # Access control checks
        all_results.extend(run_access_control_checks(
            bucket_config.access, provider, bucket_name,
            self.weights, self.cis_mappings,
        ))

        # Encryption checks
        all_results.extend(run_encryption_checks(
            bucket_config.encryption, provider, bucket_name,
            self.weights, self.cis_mappings,
        ))

        # Logging checks
        all_results.extend(run_logging_checks(
            bucket_config.logging, provider, bucket_name,
            self.weights, self.cis_mappings,
        ))

        # versioning/data protection checks
        all_results.extend(run_versioning_checks(
            bucket_config.versioning, provider, bucket_name,
            self.weights, self.cis_mappings,
        ))

        # Public exposure checks
        all_results.extend(run_public_exposure_checks(
            bucket_config.public_exposure, provider, bucket_name,
            self.weights, self.cis_mappings,
        ))

        # CORS checks
        all_results.extend(run_cors_checks(
            bucket_config.cors, provider, bucket_name,
            self.weights, self.cis_mappings,
        ))

        audit = AuditResult(
            bucket_name=bucket_name,
            provider=provider,
            check_results=all_results,
        )
        audit.calculate_scores()

        logger.info(
            "Audit complete: %s/%s — Score: %.1f/100",
            provider, bucket_name, audit.normalised_score,
        )

        return audit
