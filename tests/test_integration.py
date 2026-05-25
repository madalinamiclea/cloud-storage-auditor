"""
Integration tests against LocalStack.

These tests require a running LocalStack instance at http://localhost:4566.
They create real S3 buckets with different configurations and verify that
the auditor produces correct scores.

To run:
    1. Start LocalStack: docker run -d -p 4566:4566 localstack/localstack
    2. Run: python -m pytest tests/test_integration.py -v

Tests are skipped if LocalStack is not available.
"""

import unittest
import json
import sys
from pathlib import Path
import boto3
from botocore.exceptions import EndpointConnectionError, ClientError
from providers.aws import AWSProvider
from scoring.model import ScoringEngine
from checks.base import CheckStatus

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
ACCESS_KEY = "test"
SECRET_KEY = "test"


def localstack_available() -> bool:
    try:
        s3 = boto3.client(
            "s3",
            endpoint_url=ENDPOINT,
            region_name=REGION,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
        )
        s3.list_buckets()
        return True
    except (EndpointConnectionError, Exception):
        return False


LOCALSTACK_OK = localstack_available()
skip_msg = "LocalStack not available at " + ENDPOINT


@unittest.skipUnless(LOCALSTACK_OK, skip_msg)
class TestLocalStackIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s3 = boto3.client(
            "s3",
            endpoint_url=ENDPOINT,
            region_name=REGION,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
        )
        cls.engine = ScoringEngine()
        cls.provider = AWSProvider(
            region=REGION,
            endpoint_url=ENDPOINT,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
        )
        cls.provider.connect()
        cls.created_buckets = []

    @classmethod
    def tearDownClass(cls):
        for bucket in cls.created_buckets:
            try:
                # Delete versions
                try:
                    versions = cls.s3.list_object_versions(Bucket=bucket)
                    for v in versions.get("Versions", []):
                        cls.s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
                    for dm in versions.get("DeleteMarkers", []):
                        cls.s3.delete_object(Bucket=bucket, Key=dm["Key"], VersionId=dm["VersionId"])
                except Exception:
                    pass
                # Delete objects
                resp = cls.s3.list_objects_v2(Bucket=bucket)
                for obj in resp.get("Contents", []):
                    cls.s3.delete_object(Bucket=bucket, Key=obj["Key"])
                cls.s3.delete_bucket(Bucket=bucket)
            except Exception:
                pass

    def _create_bucket(self, name: str) -> str:
        try:
            self.s3.create_bucket(Bucket=name)
        except self.s3.exceptions.BucketAlreadyOwnedByYou:
            pass
        self.created_buckets.append(name)
        return name

    def test_default_bucket_score(self):
        bucket = self._create_bucket("integ-default-test")
        self.s3.put_object(Bucket=bucket, Key="test.txt", Body=b"test")

        config = self.provider.get_full_config(bucket)
        result = self.engine.audit_bucket(config)

        self.assertLess(result.normalised_score, 40,
                        f"Default bucket scored {result.normalised_score}, expected <40")
        self.assertEqual(len(result.check_results), 12)

    def test_misconfigured_bucket_score(self):
        bucket = self._create_bucket("integ-misconfig-test")

        # Disable Block Public Access
        try:
            self.s3.delete_public_access_block(Bucket=bucket)
        except Exception:
            pass

        # Public ACL
        try:
            self.s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
        except Exception:
            pass

        # Wildcard policy
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        })
        self.s3.put_bucket_policy(Bucket=bucket, Policy=policy)

        # Wildcard CORS
        self.s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={
            "CORSRules": [{
                "AllowedOrigins": ["*"],
                "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
                "AllowedHeaders": ["*"],
            }]
        })

        # Suspend versioning
        self.s3.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Suspended"},
        )

        self.s3.put_object(Bucket=bucket, Key="test.txt", Body=b"test")

        config = self.provider.get_full_config(bucket)
        result = self.engine.audit_bucket(config)

        self.assertLess(result.normalised_score, 15,
                        f"Misconfigured bucket scored {result.normalised_score}, expected <15")

        check_map = {r.check_id: r for r in result.check_results}
        self.assertEqual(check_map["iam_policy_least_privilege"].status, CheckStatus.FAIL)
        self.assertEqual(check_map["cors_restrictive"].status, CheckStatus.FAIL)
        self.assertEqual(check_map["versioning_enabled"].status, CheckStatus.FAIL)

    def test_hardened_bucket_score(self):
        bucket = self._create_bucket("integ-hardened-test")
        log_bucket = self._create_bucket("integ-hardened-logs")

        # Block Public Access
        self.s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        # Encryption
        self.s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )

        # HTTPS-only policy
        self.s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            },
        )
        https_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }],
        })
        self.s3.put_bucket_policy(Bucket=bucket, Policy=https_policy)
        self.s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        # Logging
        try:
            self.s3.put_bucket_logging(
                Bucket=bucket,
                BucketLoggingStatus={
                    "LoggingEnabled": {"TargetBucket": log_bucket, "TargetPrefix": "logs/"}
                },
            )
        except Exception:
            pass

        # Versioning
        self.s3.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )

        # Lifecycle
        self.s3.put_bucket_lifecycle_configuration(
            Bucket=bucket,
            LifecycleConfiguration={
                "Rules": [{
                    "ID": "test",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "Transitions": [{"Days": 90, "StorageClass": "STANDARD_IA"}],
                }]
            },
        )

        self.s3.put_object(Bucket=bucket, Key="test.txt", Body=b"test")

        config = self.provider.get_full_config(bucket)
        result = self.engine.audit_bucket(config)

        self.assertGreater(result.normalised_score, 60,
                           f"Hardened bucket scored {result.normalised_score}, expected >60")

        check_map = {r.check_id: r for r in result.check_results}
        self.assertEqual(check_map["public_access_block"].status, CheckStatus.PASS)
        self.assertEqual(check_map["encryption_at_rest"].status, CheckStatus.PASS)
        self.assertEqual(check_map["versioning_enabled"].status, CheckStatus.PASS)
        self.assertEqual(check_map["cors_restrictive"].status, CheckStatus.PASS)

    def test_score_deterministic(self):
        bucket = self._create_bucket("integ-deterministic-test")
        self.s3.put_object(Bucket=bucket, Key="test.txt", Body=b"test")

        config1 = self.provider.get_full_config(bucket)
        result1 = self.engine.audit_bucket(config1)

        config2 = self.provider.get_full_config(bucket)
        result2 = self.engine.audit_bucket(config2)

        self.assertEqual(result1.normalised_score, result2.normalised_score)


if __name__ == "__main__":
    unittest.main()
