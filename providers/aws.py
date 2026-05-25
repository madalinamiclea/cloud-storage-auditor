"""
AWS S3 provider implementation.
Connects via boto3, supports both real AWS and LocalStack endpoints.
"""
from __future__ import annotations

import json
import logging
import boto3
from botocore.exceptions import ClientError
from typing import Optional
from providers.base import (AbstractProvider, ProviderType, BucketInfo, AccessConfig, EncryptionConfig, LoggingConfig, VersioningConfig, CorsConfig, PublicExposureConfig)

logger = logging.getLogger(__name__)


class AWSProvider(AbstractProvider):
    provider_type = ProviderType.AWS

    def __init__(
        self,
        region: str = "us-east-1",
        endpoint_url: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
    ):
        self.region = region
        self.endpoint_url = endpoint_url
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.s3_client = None
        self.sts_client = None

    def connect(self) -> None:
        session_kwargs = {"region_name": self.region}
        if self.aws_access_key_id:
            session_kwargs["aws_access_key_id"] = self.aws_access_key_id
        if self.aws_secret_access_key:
            session_kwargs["aws_secret_access_key"] = self.aws_secret_access_key

        session = boto3.Session(**session_kwargs)
        client_kwargs = {}
        if self.endpoint_url:
            client_kwargs["endpoint_url"] = self.endpoint_url

        self.s3_client = session.client("s3", **client_kwargs)
        self.sts_client = session.client("sts", **client_kwargs) if not self.endpoint_url else None
        logger.info("Connected to AWS S3 (endpoint=%s, region=%s)", self.endpoint_url or "default", self.region)

    def list_buckets(self) -> list[BucketInfo]:
        resp = self.s3_client.list_buckets()
        buckets = []
        for b in resp.get("Buckets", []):
            try:
                loc = self.s3_client.get_bucket_location(Bucket=b["Name"])
                region = loc.get("LocationConstraint") or "us-east-1"
            except ClientError:
                region = self.region

            buckets.append(BucketInfo(
                name=b["Name"],
                provider=ProviderType.AWS,
                region=region,
                creation_date=str(b.get("CreationDate", "")),
            ))
        return buckets

    def get_access_config(self, bucket_name: str) -> AccessConfig:
        config = AccessConfig()

        # Block Public Access
        try:
            pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
            conf = pab.get("PublicAccessBlockConfiguration", {})
            config.block_public_acls = conf.get("BlockPublicAcls", False)
            config.block_public_policy = conf.get("BlockPublicPolicy", False)
            config.ignore_public_acls = conf.get("IgnorePublicAcls", False)
            config.restrict_public_buckets = conf.get("RestrictPublicBuckets", False)
            config.public_access_blocked = all([
                config.block_public_acls,
                config.block_public_policy,
                config.ignore_public_acls,
                config.restrict_public_buckets,
            ])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                config.public_access_blocked = False
            else:
                logger.warning("Error fetching Block Public Access for %s: %s", bucket_name, e)

        # ACLs
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = acl.get("Grants", [])
            config.acl_grants = grants
            for grant in grants:
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri:
                    perm = grant.get("Permission", "")
                    if perm in ("READ", "FULL_CONTROL"):
                        config.acl_public_read = True
                    if perm in ("WRITE", "FULL_CONTROL"):
                        config.acl_public_write = True
                elif "AuthenticatedUsers" in uri:
                    config.acl_authenticated_read = True
        except ClientError as e:
            logger.warning("Error fetching ACL for %s: %s", bucket_name, e)

        # Bucket Policy
        try:
            pol = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_str = pol.get("Policy", "{}")
            config.has_bucket_policy = True
            config.policy_raw = policy_str
            policy = json.loads(policy_str)

            for statement in policy.get("Statement", []):
                if statement.get("Effect") == "Allow":
                    principal = statement.get("Principal", "")
                    if principal == "*" or (isinstance(principal, dict) and "*" in principal.get("AWS", [])):
                        config.policy_allows_wildcard_principal = True
                        config.policy_is_least_privilege = False

                    action = statement.get("Action", "")
                    if action == "*" or action == "s3:*":
                        config.policy_allows_wildcard_action = True
                        config.policy_is_least_privilege = False
                    elif isinstance(action, list) and ("*" in action or "s3:*" in action):
                        config.policy_allows_wildcard_action = True
                        config.policy_is_least_privilege = False
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                config.has_bucket_policy = False
            else:
                logger.warning("Error fetching bucket policy for %s: %s", bucket_name, e)

        return config

    def get_encryption_config(self, bucket_name: str) -> EncryptionConfig:
        config = EncryptionConfig()

        try:
            enc = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                config.encryption_at_rest_enabled = True
                default_enc = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                config.encryption_algorithm = default_enc.get("SSEAlgorithm", "")
                if default_enc.get("KMSMasterKeyID"):
                    config.uses_customer_managed_key = True
                    config.key_id = default_enc["KMSMasterKeyID"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                config.encryption_at_rest_enabled = False
            else:
                logger.warning("Error fetching encryption for %s: %s", bucket_name, e)

        try:
            pol = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(pol.get("Policy", "{}"))
            for statement in policy.get("Statement", []):
                if statement.get("Effect") == "Deny":
                    condition = statement.get("Condition", {})
                    bool_cond = condition.get("Bool", {})
                    if bool_cond.get("aws:SecureTransport") == "false":
                        config.https_only_enforced = True
                        break
        except ClientError:
            pass

        return config

    def get_logging_config(self, bucket_name: str) -> LoggingConfig:
        config = LoggingConfig()
        try:
            log = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            logging_enabled = log.get("LoggingEnabled")
            if logging_enabled:
                config.access_logging_enabled = True
                config.log_destination = logging_enabled.get("TargetBucket", "")
        except ClientError as e:
            logger.warning("Error fetching logging for %s: %s", bucket_name, e)

        try:
            if not self.endpoint_url:
                ct = boto3.client("cloudtrail", region_name=self.region)
                trails = ct.describe_trails().get("trailList", [])
                for trail in trails:
                    if trail.get("IsMultiRegionTrail") or trail.get("HomeRegion") == self.region:
                        config.audit_trail_enabled = True
                        config.audit_trail_service = "CloudTrail"
                        break
            else:
                try:
                    session = boto3.Session(
                        region_name=self.region,
                        aws_access_key_id=self.aws_access_key_id,
                        aws_secret_access_key=self.aws_secret_access_key,
                    )
                    ct = session.client("cloudtrail", endpoint_url=self.endpoint_url)
                    trails = ct.describe_trails().get("trailList", [])
                    if trails:
                        config.audit_trail_enabled = True
                        config.audit_trail_service = "CloudTrail"
                except Exception:
                    logger.debug("CloudTrail not available on LocalStack")
        except Exception as e:
            logger.debug("CloudTrail check failed: %s", e)

        return config

    def get_versioning_config(self, bucket_name: str) -> VersioningConfig:
        config = VersioningConfig()

        # Versioning and MFA Delete
        try:
            ver = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = ver.get("Status", "")
            config.versioning_status = status if status else None
            config.versioning_enabled = status == "Enabled"
            config.mfa_delete_enabled = ver.get("MFADelete", "") == "Enabled"
        except ClientError as e:
            logger.warning("Error fetching versioning for %s: %s", bucket_name, e)

        # Object Lock
        try:
            lock = self.s3_client.get_object_lock_configuration(Bucket=bucket_name)
            lock_conf = lock.get("ObjectLockConfiguration", {})
            config.object_lock_enabled = lock_conf.get("ObjectLockEnabled") == "Enabled"
            rule = lock_conf.get("Rule", {})
            if rule.get("DefaultRetention"):
                config.retention_policy_set = True
                ret = rule["DefaultRetention"]
                config.retention_days = ret.get("Days", 0)
        except ClientError:
            pass

        # Lifecycle
        try:
            lc = self.s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            rules = lc.get("Rules", [])
            config.lifecycle_rules_configured = len(rules) > 0
            config.lifecycle_rule_count = len(rules)
        except ClientError:
            pass

        return config

    def get_cors_config(self, bucket_name: str) -> CorsConfig:
        config = CorsConfig()

        try:
            cors = self.s3_client.get_bucket_cors(Bucket=bucket_name)
            rules = cors.get("CORSRules", [])
            if rules:
                config.cors_enabled = True
                config.rules = rules
                for rule in rules:
                    origins = rule.get("AllowedOrigins", [])
                    methods = rule.get("AllowedMethods", [])
                    headers = rule.get("AllowedHeaders", [])
                    if "*" in origins:
                        config.allows_wildcard_origin = True
                    if set(methods) >= {"GET", "PUT", "POST", "DELETE"}:
                        config.allows_all_methods = True
                    if "*" in headers:
                        config.allows_all_headers = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchCORSConfiguration":
                config.cors_enabled = False
            else:
                logger.warning("Error fetching CORS for %s: %s", bucket_name, e)

        return config

    def get_public_exposure(self, bucket_name: str, sample_size: int = 10) -> PublicExposureConfig:
        config = PublicExposureConfig()

        try:
            resp = self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=sample_size)
            objects = resp.get("Contents", [])
            config.objects_sampled = len(objects)

            for obj in objects:
                key = obj["Key"]
                try:
                    acl = self.s3_client.get_object_acl(Bucket=bucket_name, Key=key)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        uri = grantee.get("URI", "")
                        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                            config.public_objects_found += 1
                            config.public_object_names.append(key)
                            break
                except ClientError:
                    pass

            if config.objects_sampled > 0:
                config.exposure_ratio = config.public_objects_found / config.objects_sampled
        except ClientError as e:
            logger.warning("Error scanning objects in %s: %s", bucket_name, e)

        return config
