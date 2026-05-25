"""
All provider implementations (AWS, Azure, GCP) must inherit from AbstractProvider
and return these common dataclasses, ensuring provider-agnostic check evaluation.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

class ProviderType(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class AccessLevel(Enum):
    # Bucket/container access level classification
    PRIVATE = "private"
    PUBLIC_READ = "public-read"
    PUBLIC_READ_WRITE = "public-read-write"
    AUTHENTICATED_READ = "authenticated-read"
    UNKNOWN = "unknown"

@dataclass
class BucketInfo:
    name: str
    provider: ProviderType
    region: Optional[str] = None
    creation_date: Optional[str] = None
    raw_metadata: dict = field(default_factory=dict)


@dataclass
class AccessConfig:
    # Block Public Access (AWS)/Public access disabled (Azure)/Uniform access (GCP)
    public_access_blocked: bool = False
    block_public_acls: bool = False
    block_public_policy: bool = False
    ignore_public_acls: bool = False
    restrict_public_buckets: bool = False

    # ACL analysis
    acl_public_read: bool = False
    acl_public_write: bool = False
    acl_authenticated_read: bool = False
    acl_grants: list = field(default_factory=list)

    # IAM/Bucket policy analysis
    has_bucket_policy: bool = False
    policy_allows_wildcard_principal: bool = False
    policy_allows_wildcard_action: bool = False
    policy_is_least_privilege: bool = True
    policy_raw: Optional[str] = None

    # Provider-specific extras
    # Azure SAS tokens, shared key access
    shared_key_access_enabled: bool = True
    sas_policies: list = field(default_factory=list)
    # GCP uniform bucket-level access
    uniform_access_enabled: bool = False

    raw_data: dict = field(default_factory=dict)


@dataclass
class EncryptionConfig:
    encryption_at_rest_enabled: bool = False
    encryption_algorithm: Optional[str] = None
    uses_customer_managed_key: bool = False
    key_id: Optional[str] = None

    https_only_enforced: bool = False
    tls_version_minimum: Optional[str] = None

    raw_data: dict = field(default_factory=dict)


@dataclass
class LoggingConfig:
    access_logging_enabled: bool = False
    log_destination: Optional[str] = None

    audit_trail_enabled: bool = False
    audit_trail_service: Optional[str] = None

    raw_data: dict = field(default_factory=dict)


@dataclass
class VersioningConfig:
    versioning_enabled: bool = False
    versioning_status: Optional[str] = None

    mfa_delete_enabled: bool = False
    soft_delete_enabled: bool = False
    soft_delete_retention_days: Optional[int] = None

    object_lock_enabled: bool = False
    retention_policy_set: bool = False
    retention_days: Optional[int] = None

    lifecycle_rules_configured: bool = False
    lifecycle_rule_count: int = 0

    raw_data: dict = field(default_factory=dict)


@dataclass
class CorsConfig:
    cors_enabled: bool = False
    rules: list = field(default_factory=list)
    allows_wildcard_origin: bool = False
    allows_all_methods: bool = False
    allows_all_headers: bool = False

    raw_data: dict = field(default_factory=dict)


@dataclass
class PublicExposureConfig:
    objects_sampled: int = 0
    public_objects_found: int = 0
    public_object_names: list = field(default_factory=list)
    exposure_ratio: float = 0.0

    raw_data: dict = field(default_factory=dict)


@dataclass
class BucketConfig:
    bucket_info: BucketInfo = None
    access: AccessConfig = field(default_factory=AccessConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    versioning: VersioningConfig = field(default_factory=VersioningConfig)
    cors: CorsConfig = field(default_factory=CorsConfig)
    public_exposure: PublicExposureConfig = field(default_factory=PublicExposureConfig)

class AbstractProvider(ABC):
    provider_type: ProviderType

    @abstractmethod
    def connect(self) -> None:
        ...

    @abstractmethod
    def list_buckets(self) -> list[BucketInfo]:
        ...

    @abstractmethod
    def get_access_config(self, bucket_name: str) -> AccessConfig:
        ...

    @abstractmethod
    def get_encryption_config(self, bucket_name: str) -> EncryptionConfig:
        ...

    @abstractmethod
    def get_logging_config(self, bucket_name: str) -> LoggingConfig:
        ...

    @abstractmethod
    def get_versioning_config(self, bucket_name: str) -> VersioningConfig:
        ...

    @abstractmethod
    def get_cors_config(self, bucket_name: str) -> CorsConfig:
        ...

    @abstractmethod
    def get_public_exposure(self, bucket_name: str, sample_size: int = 10) -> PublicExposureConfig:
        ...

    def get_full_config(self, bucket_name: str) -> BucketConfig:
        bucket_info = None
        for b in self.list_buckets():
            if b.name == bucket_name:
                bucket_info = b
                break

        if bucket_info is None:
            bucket_info = BucketInfo(name=bucket_name, provider=self.provider_type)

        return BucketConfig(
            bucket_info=bucket_info,
            access=self.get_access_config(bucket_name),
            encryption=self.get_encryption_config(bucket_name),
            logging=self.get_logging_config(bucket_name),
            versioning=self.get_versioning_config(bucket_name),
            cors=self.get_cors_config(bucket_name),
            public_exposure=self.get_public_exposure(bucket_name),
        )
