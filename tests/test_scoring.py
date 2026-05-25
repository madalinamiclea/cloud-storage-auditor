"""
Unit tests for the scoring engine and report generation.
Testing the ScoringEngine with synthetic BucketConfig instances to verify
correct score aggregation, normalisation and category breakdowns
"""

import unittest
import json
import sys
from pathlib import Path
from providers.base import ( ProviderType, BucketInfo, BucketConfig, AccessConfig, EncryptionConfig, LoggingConfig, VersioningConfig, CorsConfig, PublicExposureConfig )
from scoring.model import ScoringEngine
from scoring.report import generate_json_report

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

class TestScoringEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ScoringEngine()

    def _make_config(self, **overrides) -> BucketConfig:
        config = BucketConfig(
            bucket_info=BucketInfo(name="test-bucket", provider=ProviderType.AWS),
            access=overrides.get("access", AccessConfig()),
            encryption=overrides.get("encryption", EncryptionConfig()),
            logging=overrides.get("logging", LoggingConfig()),
            versioning=overrides.get("versioning", VersioningConfig()),
            cors=overrides.get("cors", CorsConfig()),
            public_exposure=overrides.get("public_exposure", PublicExposureConfig()),
        )
        return config

    def test_fully_insecure_scores_low(self):
        config = self._make_config()
        result = self.engine.audit_bucket(config)

        # with all defaults, most checks should fail
        self.assertLess(result.normalised_score, 40,
                        f"Expected low score for insecure config, got {result.normalised_score}")

    def test_fully_secure_scores_high(self):
        config = self._make_config(
            access=AccessConfig(
                public_access_blocked=True,
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
                has_bucket_policy=True,
                policy_is_least_privilege=True,
            ),
            encryption=EncryptionConfig(
                encryption_at_rest_enabled=True,
                encryption_algorithm="AES256",
                https_only_enforced=True,
            ),
            logging=LoggingConfig(
                access_logging_enabled=True,
                log_destination="log-bucket",
                audit_trail_enabled=True,
                audit_trail_service="CloudTrail",
            ),
            versioning=VersioningConfig(
                versioning_enabled=True,
                versioning_status="Enabled",
                mfa_delete_enabled=True,
                lifecycle_rules_configured=True,
                lifecycle_rule_count=2,
            ),
            cors=CorsConfig(cors_enabled=False),
            public_exposure=PublicExposureConfig(objects_sampled=5, public_objects_found=0),
        )
        result = self.engine.audit_bucket(config)
        self.assertEqual(result.normalised_score, 100.0,
                         f"Expected 100 for fully secure config, got {result.normalised_score}")

    def test_score_between_extremes(self):
        config = self._make_config(
            access=AccessConfig(public_access_blocked=True, block_public_acls=True,
                                block_public_policy=True, ignore_public_acls=True,
                                restrict_public_buckets=True),
            encryption=EncryptionConfig(
                encryption_at_rest_enabled=True,
                encryption_algorithm="AES256",
            ),
            # no logging, no versioning, no CORS issues, no public objects
            cors=CorsConfig(cors_enabled=False),
            public_exposure=PublicExposureConfig(objects_sampled=0),
        )
        result = self.engine.audit_bucket(config)
        self.assertGreater(result.normalised_score, 20)
        self.assertLess(result.normalised_score, 80)

    def test_total_weight_is_100(self):
        total = sum(c.get("weight", 0) for c in self.engine.weights.values())
        self.assertEqual(total, 100, f"Total weight should be 100, got {total}")

    def test_check_count(self):
        config = self._make_config()
        result = self.engine.audit_bucket(config)
        self.assertEqual(len(result.check_results), 12,
                         f"Expected 12 checks, got {len(result.check_results)}")

    def test_category_scores_present(self):
        config = self._make_config()
        result = self.engine.audit_bucket(config)
        expected_categories = {
            "Access Control", "Encryption", "Logging & Monitoring",
            "Data Protection", "Public Exposure", "CORS",
        }
        self.assertEqual(set(result.category_scores.keys()), expected_categories)

    def test_normalised_score_range(self):
        config = self._make_config()
        result = self.engine.audit_bucket(config)
        self.assertGreaterEqual(result.normalised_score, 0)
        self.assertLessEqual(result.normalised_score, 100)


class TestJSONReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        engine = ScoringEngine()
        config = BucketConfig(
            bucket_info=BucketInfo(name="test-bucket", provider=ProviderType.AWS),
        )
        cls.audit = engine.audit_bucket(config)

    def test_json_structure(self):
        report = generate_json_report(self.audit)
        self.assertIn("report_metadata", report)
        self.assertIn("summary", report)
        self.assertIn("category_scores", report)
        self.assertIn("checks", report)

    def test_json_summary_fields(self):
        report = generate_json_report(self.audit)
        summary = report["summary"]
        self.assertIn("provider", summary)
        self.assertIn("bucket", summary)
        self.assertIn("overall_score", summary)
        self.assertIn("total_checks", summary)
        self.assertIn("passed", summary)
        self.assertIn("failed", summary)

    def test_json_serialisable(self):
        report = generate_json_report(self.audit)
        # Should not raise
        serialised = json.dumps(report, indent=2)
        self.assertIsInstance(serialised, str)

    def test_check_count_matches(self):
        report = generate_json_report(self.audit)
        self.assertEqual(len(report["checks"]), 12)


if __name__ == "__main__":
    unittest.main()
