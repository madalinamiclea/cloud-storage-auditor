"""
tests/environments/azure/setup_default.py

Creates an Azure Blob Storage container with DEFAULT settings.
Experiment 1: What is the out-of-the-box security posture on Azure?

Prerequisites:
  - Azure CLI logged in (az login) or service principal credentials set
  - Environment variables: AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, AZURE_STORAGE_ACCOUNT
    or pass them as arguments.
"""

import os
import sys
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient


ACCOUNT_NAME = os.environ.get("AZURE_STORAGE_ACCOUNT", "")
CONTAINER_NAME = "test-default-container"


def setup():
    if not ACCOUNT_NAME:
        print("[!] Set AZURE_STORAGE_ACCOUNT environment variable.")
        sys.exit(1)

    credential = DefaultAzureCredential()
    blob_service = BlobServiceClient(
        account_url=f"https://{ACCOUNT_NAME}.blob.core.windows.net",
        credential=credential,
    )

    # Create container with default settings
    try:
        blob_service.create_container(CONTAINER_NAME)
        print(f"[+] Created default container: {CONTAINER_NAME}")
    except Exception as e:
        if "ContainerAlreadyExists" in str(e):
            print(f"[*] Container already exists: {CONTAINER_NAME}")
        else:
            raise

    # Upload a sample blob
    container_client = blob_service.get_container_client(CONTAINER_NAME)
    container_client.upload_blob(
        "sample-document.txt",
        b"This is a sample document for security testing.",
        overwrite=True,
    )
    print(f"[+] Uploaded sample blob to {CONTAINER_NAME}")

    print(f"\n[*] Default container '{CONTAINER_NAME}' ready for auditing.")
    print(f"[*] Run: python main.py --provider azure --bucket {CONTAINER_NAME} "
          f"--azure-account {ACCOUNT_NAME} --azure-subscription $AZURE_SUBSCRIPTION_ID "
          f"--azure-resource-group $AZURE_RESOURCE_GROUP")


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
