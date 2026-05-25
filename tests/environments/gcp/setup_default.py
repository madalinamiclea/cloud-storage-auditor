"""
tests/environments/gcp/setup_default.py

Creates a GCP Cloud Storage bucket with DEFAULT settings.
Experiment 1: What is the out-of-the-box security posture on GCP?

Prerequisites:
  - gcloud CLI authenticated (gcloud auth application-default login)
  - Environment variable: GCP_PROJECT_ID
"""

import os
import sys
from google.cloud import storage


PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
BUCKET_NAME = os.environ.get("GCP_TEST_BUCKET", f"{PROJECT_ID}-test-default")
LOCATION = "US"


def setup():
    if not PROJECT_ID:
        print("[!] Set GCP_PROJECT_ID environment variable.")
        sys.exit(1)

    client = storage.Client(project=PROJECT_ID)

    # Create bucket with default settings
    try:
        bucket = client.create_bucket(BUCKET_NAME, location=LOCATION)
        print(f"[+] Created default bucket: {BUCKET_NAME}")
    except Exception as e:
        if "409" in str(e):
            print(f"[*] Bucket already exists: {BUCKET_NAME}")
            bucket = client.get_bucket(BUCKET_NAME)
        else:
            raise

    # Upload a sample object
    blob = bucket.blob("sample-document.txt")
    blob.upload_from_string("This is a sample document for security testing.")
    print(f"[+] Uploaded sample object to {BUCKET_NAME}")

    print(f"\n[*] Default bucket '{BUCKET_NAME}' ready for auditing.")
    print(f"[*] Run: python main.py --provider gcp --bucket {BUCKET_NAME} --gcp-project {PROJECT_ID}")


def teardown():
    if not PROJECT_ID:
        print("[!] Set GCP_PROJECT_ID environment variable.")
        sys.exit(1)

    client = storage.Client(project=PROJECT_ID)
    try:
        bucket = client.get_bucket(BUCKET_NAME)
        bucket.delete(force=True)
        print(f"[-] Deleted bucket: {BUCKET_NAME}")
    except Exception as e:
        print(f"[!] Error during teardown: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "teardown":
        teardown()
    else:
        setup()
