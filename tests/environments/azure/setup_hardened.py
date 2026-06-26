"""
Prepare an Azure Blob Storage container with hardened settings.
Used to validate that secure Azure configurations score as expected.

Applied hardening:
    1. Container access level: Private (no public access)
    2. Soft delete enabled for blobs and containers
    3. Versioning enabled
    4. No CORS (default: blocked)
    5. Lifecycle management rules configured

Note: Account-level hardening (HTTPS-only, disable shared key access, CMK encryption)
must be configured via Azure portal or azure-mgmt-storage separately.
"""

import os
import sys
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import (
    BlobServiceProperties,
    DeleteRetentionPolicy,
    ManagementPolicy,
    ManagementPolicyRule,
    ManagementPolicyDefinition,
    ManagementPolicyFilter,
    ManagementPolicyAction,
    ManagementPolicyBaseBlob,
    DateAfterModification,
)


ACCOUNT_NAME = os.environ.get("AZURE_STORAGE_ACCOUNT", "")
SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
RESOURCE_GROUP = os.environ.get("AZURE_RESOURCE_GROUP", "")
CONTAINER_NAME = "test-hardened-container"


def setup():
    if not all([ACCOUNT_NAME, SUBSCRIPTION_ID, RESOURCE_GROUP]):
        print("[!] Set AZURE_STORAGE_ACCOUNT, AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP.")
        sys.exit(1)

    credential = DefaultAzureCredential()

    # --- Account-level hardening via management API ---
    mgmt = StorageManagementClient(credential, SUBSCRIPTION_ID)

    # Enable versioning and soft delete
    try:
        blob_props = BlobServiceProperties(
            is_versioning_enabled=True,
            delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=30),
            container_delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=30),
        )
        mgmt.blob_services.set_service_properties(
            RESOURCE_GROUP, ACCOUNT_NAME, blob_props
        )
        print("[+] Enabled versioning, blob soft delete (30d), container soft delete (30d)")
    except Exception as e:
        print(f"[!] Could not set blob service properties: {e}")

    # Configure lifecycle management
    try:
        lifecycle_policy = ManagementPolicy(
            policy={
                "rules": [
                    {
                        "name": "TransitionToCool",
                        "enabled": True,
                        "type": "Lifecycle",
                        "definition": {
                            "filters": {"blobTypes": ["blockBlob"]},
                            "actions": {
                                "baseBlob": {
                                    "tierToCool": {"daysAfterModificationGreaterThan": 30},
                                    "tierToArchive": {"daysAfterModificationGreaterThan": 180},
                                    "delete": {"daysAfterModificationGreaterThan": 365},
                                }
                            },
                        },
                    }
                ]
            }
        )
        mgmt.management_policies.create_or_update(
            RESOURCE_GROUP, ACCOUNT_NAME, "default", lifecycle_policy
        )
        print("[+] Lifecycle management rules configured")
    except Exception as e:
        print(f"[!] Could not set lifecycle policy: {e}")

    # --- Container-level setup ---
    blob_service = BlobServiceClient(
        account_url=f"https://{ACCOUNT_NAME}.blob.core.windows.net",
        credential=credential,
    )

    # Create container with PRIVATE access
    try:
        blob_service.create_container(CONTAINER_NAME)
        print(f"[+] Created private container: {CONTAINER_NAME}")
    except Exception as e:
        if "ContainerAlreadyExists" in str(e):
            print(f"[*] Container already exists: {CONTAINER_NAME}")
        else:
            raise

    # Clear any CORS rules
    blob_service.set_service_properties(cors=[])
    print("[+] Cleared CORS rules")

    # Enable analytics logging
    try:
        from azure.storage.blob import BlobAnalyticsLogging
        analytics = BlobAnalyticsLogging(read=True, write=True, delete=True, retention_policy=DeleteRetentionPolicy(enabled=True, days=30))
        blob_service.set_service_properties(analytics_logging=analytics)
        print("[+] Enabled analytics logging (read/write/delete)")
    except Exception as e:
        print(f"[!] Could not enable analytics logging: {e}")

    # Upload sample blob
    container_client = blob_service.get_container_client(CONTAINER_NAME)
    container_client.upload_blob(
        "secure-document.txt",
        b"This document is stored securely.",
        overwrite=True,
    )
    print(f"[+] Uploaded sample blob to {CONTAINER_NAME}")

    print(f"\n[*] Hardened container '{CONTAINER_NAME}' ready for auditing.")
    print(f"[*] Expected audit score: HIGH (most checks should PASS)")


def teardown():
    if not ACCOUNT_NAME:
        print("[!] Set AZURE_STORAGE_ACCOUNT environment variable.")
        sys.exit(1)

    credential = DefaultAzureCredential()
    blob_service = BlobServiceClient(
        account_url=f"https://{ACCOUNT_NAME}.blob.core.windows.net",
        credential=credential,
    )
    try:
        blob_service.delete_container(CONTAINER_NAME)
        print(f"[-] Deleted container: {CONTAINER_NAME}")
    except Exception as e:
        print(f"[!] Error during teardown: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "teardown":
        teardown()
    else:
        setup()
