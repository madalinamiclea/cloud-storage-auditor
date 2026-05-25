"""
Google Cloud Storage provider implementation
Connects via google-cloud-storage SDK
"""

import logging
from __future__ import annotations
from typing import Optional
from google.cloud import storage as gcs
from google.cloud.storage import Bucket
from google.api_core.exceptions import NotFound, Forbidden
from providers.base import ( AbstractProvider, ProviderType, BucketInfo, AccessConfig, EncryptionConfig, LoggingConfig, VersioningConfig, CorsConfig, PublicExposureConfig )

logger = logging.getLogger(__name__)


class GCPProvider(AbstractProvider):
    provider_type = ProviderType.GCP

    def __init__(
        self,
        project_id: Optional[str] = None,
        credentials_path: Optional[str] = None,
    ):
        self.project_id = project_id
        self.credentials_path = credentials_path
        self.client: Optional[gcs.Client] = None

    def connect(self) -> None:
        kwargs = {}
        if self.project_id:
            kwargs["project"] = self.project_id

        if self.credentials_path:
            self.client = gcs.Client.from_service_account_json(
                self.credentials_path, **kwargs
            )
        else:
            self.client = gcs.Client(**kwargs)

        logger.info("Connected to Google Cloud Storage (project=%s)", self.project_id)

    def list_buckets(self) -> list[BucketInfo]:
        buckets = []
        for b in self.client.list_buckets():
            buckets.append(BucketInfo(
                name=b.name,
                provider=ProviderType.GCP,
                region=b.location,
                creation_date=str(b.time_created) if b.time_created else None,
            ))
        return buckets

    def get_access_config(self, bucket_name: str) -> AccessConfig:
        config = AccessConfig()
        bucket = self.client.get_bucket(bucket_name)

        # Uniform bucket-level access
        iam_config = bucket.iam_configuration
        config.uniform_access_enabled = iam_config.uniform_bucket_level_access_enabled
        if config.uniform_access_enabled:
            config.block_public_acls = True
            config.ignore_public_acls = True

        # IAM policy check
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            config.has_bucket_policy = True

            for binding in policy.bindings:
                members = binding.get("members", [])
                role = binding.get("role", "")

                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    config.policy_allows_wildcard_principal = True
                    config.policy_is_least_privilege = False
                    if "allUsers" in members:
                        config.acl_public_read = True
                        if "Writer" in role or "Admin" in role or "Owner" in role:
                            config.acl_public_write = True
                    if "allAuthenticatedUsers" in members:
                        config.acl_authenticated_read = True

                if role in ("roles/storage.admin", "roles/storage.objectAdmin"):
                    for member in members:
                        if member in ("allUsers", "allAuthenticatedUsers"):
                            config.policy_allows_wildcard_action = True
                            config.policy_is_least_privilege = False
        except (Forbidden, Exception) as e:
            logger.warning("Error fetching IAM policy for %s: %s", bucket_name, e)

        # Public access prevention
        if hasattr(iam_config, "public_access_prevention"):
            pap = iam_config.public_access_prevention
            if pap == "enforced":
                config.public_access_blocked = True
                config.block_public_policy = True
                config.restrict_public_buckets = True
        else:
            config.public_access_blocked = not config.acl_public_read

        return config

    def get_encryption_config(self, bucket_name: str) -> EncryptionConfig:
        config = EncryptionConfig()
        bucket = self.client.get_bucket(bucket_name)

        config.encryption_at_rest_enabled = True
        config.encryption_algorithm = "AES256"

        # check for CMEK
        if bucket.default_kms_key_name:
            config.uses_customer_managed_key = True
            config.key_id = bucket.default_kms_key_name

        config.https_only_enforced = True

        return config

    def get_logging_config(self, bucket_name: str) -> LoggingConfig:
        config = LoggingConfig()
        bucket = self.client.get_bucket(bucket_name)

        # Access logging
        logging_cfg = None
        try:
            logging_cfg = getattr(bucket, "logging", None)
        except Exception:
            logging_cfg = None

        if not logging_cfg:
            logging_cfg = bucket._properties.get("logging", {}) if hasattr(bucket, "_properties") else {}

        if logging_cfg:
            log_bucket = logging_cfg.get("logBucket")
            if log_bucket:
                config.access_logging_enabled = True
                config.log_destination = log_bucket

        # Cloud Audit Logs
        config.audit_trail_enabled = True
        config.audit_trail_service = "Cloud Audit Logs"

        return config

    def get_versioning_config(self, bucket_name: str) -> VersioningConfig:
        config = VersioningConfig()
        bucket = self.client.get_bucket(bucket_name)

        # object versioning
        config.versioning_enabled = bool(bucket.versioning_enabled)
        config.versioning_status = "Enabled" if config.versioning_enabled else "Disabled"

        # retention policy
        if bucket.retention_policy_effective_time:
            config.retention_policy_set = True
        if bucket.retention_period:
            config.retention_policy_set = True
            retention_seconds = bucket.retention_period
            try:
                retention_seconds = int(retention_seconds)
            except (TypeError, ValueError):
                retention_seconds = 0
            config.retention_days = retention_seconds // 86400
            config.object_lock_enabled = True

        # soft delete
        if hasattr(bucket, "soft_delete_policy"):
            sdp = bucket.soft_delete_policy
            if sdp and sdp.get("retentionDurationSeconds"):
                retention_seconds = sdp.get("retentionDurationSeconds")
                try:
                    retention_seconds = int(retention_seconds)
                except (TypeError, ValueError):
                    retention_seconds = 0
                config.soft_delete_enabled = True
                config.soft_delete_retention_days = retention_seconds // 86400

        # lifecycle
        rules = bucket.lifecycle_rules
        if rules:
            rule_list = list(rules)
            config.lifecycle_rules_configured = len(rule_list) > 0
            config.lifecycle_rule_count = len(rule_list)

        return config

    def get_cors_config(self, bucket_name: str) -> CorsConfig:
        config = CorsConfig()
        bucket = self.client.get_bucket(bucket_name)

        cors_rules = bucket.cors
        if cors_rules:
            config.cors_enabled = True
            config.rules = cors_rules
            for rule in cors_rules:
                origins = rule.get("origin", [])
                methods = rule.get("method", [])
                headers = rule.get("responseHeader", [])
                if "*" in origins:
                    config.allows_wildcard_origin = True
                if set(methods) >= {"GET", "PUT", "POST", "DELETE"}:
                    config.allows_all_methods = True
                if "*" in headers:
                    config.allows_all_headers = True

        return config

    def get_public_exposure(self, bucket_name: str, sample_size: int = 10) -> PublicExposureConfig:
        config = PublicExposureConfig()

        try:
            bucket = self.client.get_bucket(bucket_name)
            blobs = list(bucket.list_blobs(max_results=sample_size))
            config.objects_sampled = len(blobs)

            for blob in blobs:
                try:
                    blob.reload()
                    acl = blob.acl
                    acl.reload()
                    for entry in acl:
                        entity = entry.get("entity", "")
                        if entity in ("allUsers", "allAuthenticatedUsers"):
                            config.public_objects_found += 1
                            config.public_object_names.append(blob.name)
                            break
                except Exception:
                    import requests
                    url = f"https://storage.googleapis.com/{bucket_name}/{blob.name}"
                    try:
                        resp = requests.head(url, timeout=5)
                        if resp.status_code == 200:
                            config.public_objects_found += 1
                            config.public_object_names.append(blob.name)
                    except Exception:
                        pass

            if config.objects_sampled > 0:
                config.exposure_ratio = config.public_objects_found / config.objects_sampled
        except Exception as e:
            logger.warning("Error checking public exposure for %s: %s", bucket_name, e)

        return config
