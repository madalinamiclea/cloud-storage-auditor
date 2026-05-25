"""
tests/environments/azure/setup_misconfigured.py

Creates an Azure Blob Storage container with DELIBERATE MISCONFIGURATIONS.
Experiment 2: Can the tool detect known Azure-specific vulnerabilities?

Misconfigurations introduced:
  1. Container public access set to 'blob' (individual blob public access)
  2. No versioning
  3. No soft delete
  4. CORS with wildcard origins
  5. No lifecycle management

Note: Some misconfigurations (like disabling HTTPS-only) require account-level
changes via azure-mgmt-storage. This script focuses on container-level settings.
"""

import os
import sys
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, PublicAccess, CorsRule


ACCOUNT_NAME = os.environ.get("AZURE_STORAGE_ACCOUNT", "")
CONTAINER_NAME = "test-misconfigured-container"


def setup():
    if not ACCOUNT_NAME:
        print("[!] Set AZURE_STORAGE_ACCOUNT environment variable.")
        sys.exit(1)

    credential = DefaultAzureCredential()
    blob_service = BlobServiceClient(
        account_url=f"https://{ACCOUNT_NAME}.blob.core.windows.net",
        credential=credential,
    )

    # 1. Create container with PUBLIC BLOB access
    try:
        blob_service.create_container(
            CONTAINER_NAME,
            public_access=PublicAccess.BLOB,
        )
        print(f"[+] Created container with public blob access: {CONTAINER_NAME}")
    except Exception as e:
        if "ContainerAlreadyExists" in str(e):
            print(f"[*] Container already exists: {CONTAINER_NAME}")
            # Update access level
            container_client = blob_service.get_container_client(CONTAINER_NAME)
            container_client.set_container_access_policy({}, public_access=PublicAccess.BLOB)
            print("[+] Set container access to public blob")
        else:
            raise

    # 2. Set overly permissive CORS
    cors_rule = CorsRule(
        allowed_origins=["*"],
        allowed_methods=["GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS", "MERGE", "PATCH"],
        allowed_headers=["*"],
        exposed_headers=["*"],
        max_age_in_seconds=86400,
    )
    blob_service.set_service_properties(cors=[cors_rule])
    print("[+] Set CORS with wildcard origin (*) and all methods")

    # 3. Upload sample blobs
    container_client = blob_service.get_container_client(CONTAINER_NAME)
    container_client.upload_blob(
        "public-data.txt",
        b"This file is publicly accessible via Azure Blob.",
        overwrite=True,
    )
    container_client.upload_blob(
        "sensitive-report.pdf",
        b"Confidential financial report content.",
        overwrite=True,
    )
    print("[+] Uploaded sample blobs")

    print(f"\n[*] Misconfigured container '{CONTAINER_NAME}' ready for auditing.")
    print(f"[*] Expected audit score: LOW (several checks should FAIL)")


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
