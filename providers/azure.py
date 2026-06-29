"""
Azure Blob Storage provider implementation.
Connects via azure-storage-blob and azure-mgmt-storage SDKs.
"""
from __future__ import annotations

import logging
from typing import Optional
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient, PublicAccess

from providers.base import ( AbstractProvider, ProviderType, BucketInfo, AccessConfig, EncryptionConfig, LoggingConfig, VersioningConfig, CorsConfig, PublicExposureConfig )

logger = logging.getLogger(__name__)

class AzureProvider(AbstractProvider):

    provider_type = ProviderType.AZURE

    def __init__(
        self,
        subscription_id: str = "",
        resource_group: str = "",
        account_name: str = "",
        connection_string: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.account_name = account_name
        self.connection_string = connection_string
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.blob_service_client: Optional[BlobServiceClient] = None
        self.mgmt_client: Optional[StorageManagementClient] = None
        self.credential = None

    def connect(self) -> None:
        if self.connection_string:
            self.blob_service_client = BlobServiceClient.from_connection_string(
                self.connection_string
            )
        else:
            if self.tenant_id and self.client_id and self.client_secret:
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                )
            else:
                self.credential = DefaultAzureCredential()

            account_url = f"https://{self.account_name}.blob.core.windows.net"
            self.blob_service_client = BlobServiceClient(
                account_url=account_url, credential=self.credential
            )
        if self.subscription_id:
            cred = self.credential or DefaultAzureCredential()
            self.mgmt_client = StorageManagementClient(cred, self.subscription_id)

        logger.info("Connected to Azure Blob Storage (account=%s)", self.account_name)

    def list_buckets(self) -> list[BucketInfo]:
        containers = []
        for container in self.blob_service_client.list_containers(include_metadata=True):
            containers.append(BucketInfo(
                name=container["name"],
                provider=ProviderType.AZURE,
                region=None,  # Determined at account level
                creation_date=str(container.get("last_modified", "")),
                raw_metadata=dict(container.get("metadata", {})),
            ))
        return containers

    def get_access_config(self, bucket_name: str) -> AccessConfig:
        config = AccessConfig()

        # Container-level public access
        try:
            container_client = self.blob_service_client.get_container_client(bucket_name)
            props = container_client.get_container_properties()
            public_access = props.get("public_access")

            if public_access is None or public_access == "None":
                config.public_access_blocked = True
            elif public_access == PublicAccess.BLOB or public_access == "blob":
                config.acl_public_read = True
            elif public_access == PublicAccess.CONTAINER or public_access == "container":
                config.acl_public_read = True
                config.acl_public_write = False
        except Exception as e:
            logger.warning("Error fetching container access for %s: %s", bucket_name, e)

        # Account-level public access
        if self.mgmt_client and self.resource_group and self.account_name:
            try:
                account = self.mgmt_client.storage_accounts.get_properties(
                    self.resource_group, self.account_name
                )
                if hasattr(account, "allow_blob_public_access"):
                    if not account.allow_blob_public_access:
                        config.public_access_blocked = True
                        config.block_public_acls = True
                        config.block_public_policy = True
                        config.ignore_public_acls = True
                        config.restrict_public_buckets = True
                if hasattr(account, "allow_shared_key_access"):
                    config.shared_key_access_enabled = account.allow_shared_key_access

                config.policy_is_least_privilege = not config.acl_public_read
            except Exception as e:
                logger.warning("Error fetching account properties: %s", e)

        return config

    def get_encryption_config(self, bucket_name: str) -> EncryptionConfig:
        config = EncryptionConfig()
        config.encryption_at_rest_enabled = True
        config.encryption_algorithm = "AES256"

        if self.mgmt_client and self.resource_group and self.account_name:
            try:
                account = self.mgmt_client.storage_accounts.get_properties(
                    self.resource_group, self.account_name
                )
                # Check for CMK
                enc = account.encryption
                if enc and enc.key_source == "Microsoft.Keyvault":
                    config.uses_customer_managed_key = True
                    if enc.key_vault_properties:
                        config.key_id = enc.key_vault_properties.key_vault_uri

                # HTTPS only
                if hasattr(account, "enable_https_traffic_only"):
                    config.https_only_enforced = account.enable_https_traffic_only
                if hasattr(account, "minimum_tls_version"):
                    config.tls_version_minimum = str(account.minimum_tls_version)
            except Exception as e:
                logger.warning("Error fetching encryption config: %s", e)

        return config

    def get_logging_config(self, bucket_name: str) -> LoggingConfig:
        config = LoggingConfig()

        # Blob service analytics logging
        try:
            props = self.blob_service_client.get_service_properties()
            analytics = props.get("analytics_logging")
            if analytics:
                if analytics.read or analytics.write or analytics.delete:
                    config.access_logging_enabled = True
                    config.log_destination = "$logs container"
        except Exception as e:
            logger.warning("Error fetching blob analytics logging: %s", e)

        if self.mgmt_client and self.resource_group and self.account_name:
            try:
                from azure.mgmt.monitor import MonitorManagementClient
                monitor = MonitorManagementClient(
                    self.credential or DefaultAzureCredential(),
                    self.subscription_id,
                )
                resource_id = (
                    f"/subscriptions/{self.subscription_id}"
                    f"/resourceGroups/{self.resource_group}"
                    f"/providers/Microsoft.Storage"
                    f"/storageAccounts/{self.account_name}"
                )
                settings = list(monitor.diagnostic_settings.list(resource_id))
                if settings:
                    config.audit_trail_enabled = True
                    config.audit_trail_service = "Azure Monitor"
            except Exception as e:
                logger.debug("Azure Monitor check skipped: %s", e)

        return config

    def get_versioning_config(self, bucket_name: str) -> VersioningConfig:
        config = VersioningConfig()

        if self.mgmt_client and self.resource_group and self.account_name:
            try:
                blob_services = self.mgmt_client.blob_services.get_service_properties(
                    self.resource_group, self.account_name
                )
                # Versioning
                if hasattr(blob_services, "is_versioning_enabled"):
                    config.versioning_enabled = bool(blob_services.is_versioning_enabled)
                    config.versioning_status = "Enabled" if config.versioning_enabled else "Disabled"

                # Soft delete
                delete_policy = blob_services.delete_retention_policy
                if delete_policy and delete_policy.enabled:
                    config.soft_delete_enabled = True
                    config.soft_delete_retention_days = delete_policy.days

                # Container soft delete
                container_delete = blob_services.container_delete_retention_policy
                if container_delete and container_delete.enabled:
                    config.soft_delete_enabled = True
            except Exception as e:
                logger.warning("Error fetching versioning config: %s", e)

        # Lifecycle management
        if self.mgmt_client:
            try:
                policies = self.mgmt_client.management_policies.get(
                    self.resource_group, self.account_name
                )
                if policies and policies.policy and policies.policy.rules:
                    config.lifecycle_rules_configured = True
                    config.lifecycle_rule_count = len(policies.policy.rules)
            except Exception:
                pass

        return config

    def get_cors_config(self, bucket_name: str) -> CorsConfig:
        config = CorsConfig()

        try:
            props = self.blob_service_client.get_service_properties()
            cors_rules = props.get("cors", [])
            if cors_rules:
                config.cors_enabled = True
                config.rules = [
                    {
                        "AllowedOrigins": r.allowed_origins,
                        "AllowedMethods": r.allowed_methods,
                        "AllowedHeaders": r.allowed_headers,
                    }
                    for r in cors_rules
                ]
                for rule in cors_rules:
                    if "*" in (rule.allowed_origins or []):
                        config.allows_wildcard_origin = True
                    if set(rule.allowed_methods or []) >= {"GET", "PUT", "POST", "DELETE"}:
                        config.allows_all_methods = True
                    if "*" in (rule.allowed_headers or []):
                        config.allows_all_headers = True
        except Exception as e:
            logger.warning("Error fetching CORS config: %s", e)

        return config

    def get_public_exposure(self, bucket_name: str, sample_size: int = 10) -> PublicExposureConfig:
        config = PublicExposureConfig()

        try:
            container_client = self.blob_service_client.get_container_client(bucket_name)
            props = container_client.get_container_properties()
            public_access = props.get("public_access")

            blobs = list(container_client.list_blobs())[:sample_size]
            config.objects_sampled = len(blobs)

            if public_access and public_access != "None":
                # if container has public access all blobs are considered public
                import requests
                account_url = self.blob_service_client.url.rstrip("/")
                for blob in blobs:
                    blob_url = f"{account_url}/{bucket_name}/{blob.name}"
                    try:
                        resp = requests.head(blob_url, timeout=5)
                        if resp.status_code == 200:
                            config.public_objects_found += 1
                            config.public_object_names.append(blob.name)
                    except Exception:
                        pass

            if config.objects_sampled > 0:
                config.exposure_ratio = config.public_objects_found / config.objects_sampled
        except Exception as e:
            logger.warning("Error scanning public exposure for %s: %s", bucket_name, e)

        return config
