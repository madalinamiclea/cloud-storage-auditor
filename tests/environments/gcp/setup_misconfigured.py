"""
tests/environments/gcp/setup_misconfigured.py

Creates a GCP Cloud Storage bucket with DELIBERATE MISCONFIGURATIONS.
Experiment 2: Can the tool detect known GCP-specific vulnerabilities?

Misconfigurations introduced:
  1. allUsers granted Storage Object Viewer role (public read)
  2. Uniform bucket-level access DISABLED (legacy ACLs)
  3. No access logging
  4. No versioning
  5. CORS with wildcard origins
"""

import os
import sys
from google.cloud import storage
from google.cloud.storage import Bucket


PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
BUCKET_NAME = os.environ.get("GCP_TEST_BUCKET_MISCONFIG", f"{PROJECT_ID}-test-misconfigured")
LOCATION = "US"


def setup():
    if not PROJECT_ID:
        print("[!] Set GCP_PROJECT_ID environment variable.")
        sys.exit(1)

    client = storage.Client(project=PROJECT_ID)

    # Create bucket
    try:
        bucket = client.create_bucket(BUCKET_NAME, location=LOCATION)
        print(f"[+] Created bucket: {BUCKET_NAME}")
    except Exception as e:
        if "409" in str(e):
            print(f"[*] Bucket already exists: {BUCKET_NAME}")
            bucket = client.get_bucket(BUCKET_NAME)
        else:
            raise

    # 1. Disable uniform bucket-level access (enable legacy ACLs)
    bucket.iam_configuration.uniform_bucket_level_access_enabled = False
    bucket.patch()
    print("[+] Uniform bucket-level access DISABLED (legacy ACLs enabled)")

    # 2. Make bucket publicly readable via IAM
    policy = bucket.get_iam_policy(requested_policy_version=3)
    policy.bindings.append({
        "role": "roles/storage.objectViewer",
        "members": ["allUsers"],
    })
    bucket.set_iam_policy(policy)
    print("[+] Granted allUsers objectViewer role (public read)")

    # 3. Disable versioning
    bucket.versioning_enabled = False
    bucket.patch()
    print("[+] Versioning DISABLED")

    # 4. Set overly permissive CORS
    bucket.cors = [
        {
            "origin": ["*"],
            "method": ["GET", "PUT", "POST", "DELETE", "HEAD"],
            "responseHeader": ["*"],
            "maxAgeSeconds": 86400,
        }
    ]
    bucket.patch()
    print("[+] Set CORS with wildcard origin (*) and all methods")

    # 5. No logging configured (default)
    # Remove any existing logging
    bucket.logging = None
    bucket.patch()
    print("[+] Access logging DISABLED")

    # Upload sample objects
    blob_public = bucket.blob("public-data.txt")
    blob_public.upload_from_string("This file is publicly accessible.")
    blob_sensitive = bucket.blob("sensitive-report.pdf")
    blob_sensitive.upload_from_string("Confidential financial report content.")
    print("[+] Uploaded sample objects")

    print(f"\n[*] Misconfigured bucket '{BUCKET_NAME}' ready for auditing.")
    print(f"[*] Expected audit score: LOW (several checks should FAIL)")


def teardown():
    if not PROJECT_ID:
        print("[!] Set GCP_PROJECT_ID environment variable.")
        sys.exit(1)

    client = storage.Client(project=PROJECT_ID)
    try:
        bucket = client.get_bucket(BUCKET_NAME)
        # Remove public access first
        policy = bucket.get_iam_policy(requested_policy_version=3)
        policy.bindings = [b for b in policy.bindings if "allUsers" not in b.get("members", [])]
        bucket.set_iam_policy(policy)
        bucket.delete(force=True)
        print(f"[-] Deleted bucket: {BUCKET_NAME}")
    except Exception as e:
        print(f"[!] Error during teardown: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "teardown":
        teardown()
    else:
        setup()
