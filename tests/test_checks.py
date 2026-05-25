import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from providers.base import (
    AccessConfig, EncryptionConfig, LoggingConfig,
    VersioningConfig, CorsConfig, PublicExposureConfig,
)
from checks.base import CheckStatus
from checks.access_control import (
    check_public_access_block,
    check_iam_policy_least_privilege,
    check_acl_not_public,
)
from checks.encryption import check_encryption_at_rest, check_encryption_in_transit
from checks.logging import check_access_logging, check_audit_trail
from checks.versioning import (
    check_versioning_enabled,
    check_soft_delete_or_mfa_delete,
    check_lifecycle_policy,
)
from checks.public_exposure import check_no_public_objects
from checks.cors import check_cors_restrictive


class TestPublicAccessBlock(unittest.TestCase):
    def test_pass_when_fully_blocked(self):
        config = AccessConfig(
            public_access_blocked=True,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
        )
        result = check_public_access_block(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.PASS)
        self.assertEqual(result.score_contribution, 10)

    def test_fail_when_not_blocked(self):
        config = AccessConfig(public_access_blocked=False)
        result = check_public_access_block(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertEqual(result.score_contribution, 0)

    def test_fail_shows_missing_settings(self):
        config = AccessConfig(
            public_access_blocked=False,
            block_public_acls=True,
            block_public_policy=False,
            ignore_public_acls=True,
            restrict_public_buckets=False,
        )
        result = check_public_access_block(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("BlockPublicPolicy", result.details)
        self.assertIn("RestrictPublicBuckets", result.details)


class TestIAMPolicyLeastPrivilege(unittest.TestCase):
    def test_pass_no_policy(self):
        config = AccessConfig(has_bucket_policy=False)
        result = check_iam_policy_least_privilege(config, "aws", "test-bucket", 8, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_pass_least_privilege(self):
        config = AccessConfig(
            has_bucket_policy=True,
            policy_is_least_privilege=True,
        )
        result = check_iam_policy_least_privilege(config, "aws", "test-bucket", 8, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_wildcard_principal(self):
        config = AccessConfig(
            has_bucket_policy=True,
            policy_allows_wildcard_principal=True,
            policy_is_least_privilege=False,
        )
        result = check_iam_policy_least_privilege(config, "aws", "test-bucket", 8, {})
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("wildcard principal", result.details)

    def test_fail_wildcard_action(self):
        config = AccessConfig(
            has_bucket_policy=True,
            policy_allows_wildcard_action=True,
            policy_is_least_privilege=False,
        )
        result = check_iam_policy_least_privilege(config, "aws", "test-bucket", 8, {})
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("wildcard actions", result.details)


class TestACLNotPublic(unittest.TestCase):
    def test_pass_private(self):
        config = AccessConfig()
        result = check_acl_not_public(config, "aws", "test-bucket", 7, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_public_read(self):
        config = AccessConfig(acl_public_read=True)
        result = check_acl_not_public(config, "aws", "test-bucket", 7, {})
        self.assertEqual(result.status, CheckStatus.FAIL)

    def test_fail_public_write(self):
        config = AccessConfig(acl_public_write=True)
        result = check_acl_not_public(config, "aws", "test-bucket", 7, {})
        self.assertEqual(result.status, CheckStatus.FAIL)

    def test_pass_with_uniform_access(self):
        config = AccessConfig(uniform_access_enabled=True)
        result = check_acl_not_public(config, "gcp", "test-bucket", 7, {})
        self.assertEqual(result.status, CheckStatus.PASS)
        self.assertIn("Uniform", result.details)


class TestEncryptionAtRest(unittest.TestCase):
    def test_pass_with_sse(self):
        config = EncryptionConfig(
            encryption_at_rest_enabled=True,
            encryption_algorithm="AES256",
        )
        result = check_encryption_at_rest(config, "aws", "test-bucket", 12, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_pass_with_cmk(self):
        config = EncryptionConfig(
            encryption_at_rest_enabled=True,
            encryption_algorithm="aws:kms",
            uses_customer_managed_key=True,
            key_id="arn:aws:kms:us-east-1:123:key/abc",
        )
        result = check_encryption_at_rest(config, "aws", "test-bucket", 12, {})
        self.assertEqual(result.status, CheckStatus.PASS)
        self.assertIn("Customer-managed key", result.details)

    def test_fail_no_encryption(self):
        config = EncryptionConfig(encryption_at_rest_enabled=False)
        result = check_encryption_at_rest(config, "aws", "test-bucket", 12, {})
        self.assertEqual(result.status, CheckStatus.FAIL)


class TestEncryptionInTransit(unittest.TestCase):
    def test_pass_https_enforced(self):
        config = EncryptionConfig(https_only_enforced=True)
        result = check_encryption_in_transit(config, "aws", "test-bucket", 8, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_http_allowed(self):
        config = EncryptionConfig(https_only_enforced=False)
        result = check_encryption_in_transit(config, "aws", "test-bucket", 8, {})
        self.assertEqual(result.status, CheckStatus.FAIL)


class TestAccessLogging(unittest.TestCase):
    def test_pass_logging_enabled(self):
        config = LoggingConfig(access_logging_enabled=True, log_destination="log-bucket")
        result = check_access_logging(config, "aws", "test-bucket", 8, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_logging_disabled(self):
        config = LoggingConfig(access_logging_enabled=False)
        result = check_access_logging(config, "aws", "test-bucket", 8, {})
        self.assertEqual(result.status, CheckStatus.FAIL)


class TestAuditTrail(unittest.TestCase):
    def test_pass_trail_active(self):
        config = LoggingConfig(audit_trail_enabled=True, audit_trail_service="CloudTrail")
        result = check_audit_trail(config, "aws", "test-bucket", 7, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_no_trail(self):
        config = LoggingConfig(audit_trail_enabled=False)
        result = check_audit_trail(config, "aws", "test-bucket", 7, {})
        self.assertEqual(result.status, CheckStatus.FAIL)


class TestVersioning(unittest.TestCase):
    def test_pass_versioning_enabled(self):
        config = VersioningConfig(versioning_enabled=True, versioning_status="Enabled")
        result = check_versioning_enabled(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_versioning_disabled(self):
        config = VersioningConfig(versioning_enabled=False)
        result = check_versioning_enabled(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.FAIL)

    def test_fail_versioning_suspended(self):
        config = VersioningConfig(versioning_enabled=False, versioning_status="Suspended")
        result = check_versioning_enabled(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("Suspended", result.details)


class TestSoftDeleteMFADelete(unittest.TestCase):
    def test_pass_mfa_delete(self):
        config = VersioningConfig(mfa_delete_enabled=True)
        result = check_soft_delete_or_mfa_delete(config, "aws", "test-bucket", 6, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_pass_soft_delete(self):
        config = VersioningConfig(soft_delete_enabled=True, soft_delete_retention_days=30)
        result = check_soft_delete_or_mfa_delete(config, "azure", "test-container", 6, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_pass_object_lock(self):
        config = VersioningConfig(object_lock_enabled=True)
        result = check_soft_delete_or_mfa_delete(config, "aws", "test-bucket", 6, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_no_protection(self):
        config = VersioningConfig()
        result = check_soft_delete_or_mfa_delete(config, "aws", "test-bucket", 6, {})
        self.assertEqual(result.status, CheckStatus.FAIL)


class TestLifecyclePolicy(unittest.TestCase):
    def test_pass_lifecycle_configured(self):
        config = VersioningConfig(lifecycle_rules_configured=True, lifecycle_rule_count=2)
        result = check_lifecycle_policy(config, "aws", "test-bucket", 4, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_no_lifecycle(self):
        config = VersioningConfig()
        result = check_lifecycle_policy(config, "aws", "test-bucket", 4, {})
        self.assertEqual(result.status, CheckStatus.FAIL)


class TestPublicObjects(unittest.TestCase):
    def test_pass_empty_bucket(self):
        config = PublicExposureConfig(objects_sampled=0)
        result = check_no_public_objects(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_pass_no_public_objects(self):
        config = PublicExposureConfig(objects_sampled=5, public_objects_found=0)
        result = check_no_public_objects(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_public_objects_found(self):
        config = PublicExposureConfig(
            objects_sampled=5,
            public_objects_found=2,
            public_object_names=["file1.txt", "file2.txt"],
            exposure_ratio=0.4,
        )
        result = check_no_public_objects(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("40.0%", result.details)


class TestCORS(unittest.TestCase):
    def test_pass_no_cors(self):
        config = CorsConfig(cors_enabled=False)
        result = check_cors_restrictive(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_pass_restrictive_cors(self):
        config = CorsConfig(cors_enabled=True, rules=[{}])
        result = check_cors_restrictive(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.PASS)

    def test_fail_wildcard_origin(self):
        config = CorsConfig(cors_enabled=True, allows_wildcard_origin=True, rules=[{}])
        result = check_cors_restrictive(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("wildcard origin", result.details)

    def test_fail_all_methods(self):
        config = CorsConfig(cors_enabled=True, allows_all_methods=True, rules=[{}])
        result = check_cors_restrictive(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.status, CheckStatus.FAIL)


class TestScoreContribution(unittest.TestCase):
    """Verify that score contributions match expected values."""

    def test_pass_gives_full_weight(self):
        config = AccessConfig(public_access_blocked=True)
        result = check_public_access_block(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.score_contribution, result.weight)

    def test_fail_gives_zero(self):
        config = AccessConfig(public_access_blocked=False)
        result = check_public_access_block(config, "aws", "test-bucket", 10, {})
        self.assertEqual(result.score_contribution, 0)

    def test_max_score_equals_weight(self):
        config = EncryptionConfig(encryption_at_rest_enabled=True, encryption_algorithm="AES256")
        result = check_encryption_at_rest(config, "aws", "test-bucket", 12, {})
        self.assertEqual(result.max_score, 12)


if __name__ == "__main__":
    unittest.main()
