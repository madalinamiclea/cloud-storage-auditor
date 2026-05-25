"""
tests/environments/gcp/setup_hardened.py

Creates a GCP Cloud Storage bucket with BEST-PRACTICE (CIS-compliant) settings.
Experiment 3: Does the tool correctly score a fully secured GCP bucket?

Hardening applied:
  1. Uniform bucket-level access ENABLED
  2. Public access prevention ENFORCED
  3. Versioning enabled
  4. Access logging to a dedicated log bucket
  5. Retention policy configured
  6. Lifecycle rules configured
  7. No CORS (default: blocked)
"""

import os
import sys
from google.cloud import storage


PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
BUCKET_NAME = os.environ.get("GCP_TEST_BUCKET_HARDENED", f"{PROJECT_ID}-test-hardened")
LOG_BUCKET_NAME = f"{PROJECT_ID}-test-hardened-logs"
LOCATION = "US"


def setup():
    if not PROJECT_ID:
        print("[!] Set GCP_PROJECT_ID environment variable.")
        sys.exit(1)

    client = storage.Client(project=PROJECT_ID)

    # Create log bucket first
    try:
        log_bucket = client.create_bucket(LOG_BUCKET_NAME, location=LOCATION)
        print(f"[+] Created log bucket: {LOG_BUCKET_NAME}")
    except Exception as e:
        if "409" in str(e):
            log_bucket = client.get_bucket(LOG_BUCKET_NAME)
        else:
            raise

    # Create main bucket
    try:
        bucket = client.create_bucket(BUCKET_NAME, location=LOCATION)
        print(f"[+] Created bucket: {BUCKET_NAME}")
    except Exception as e:
        if "409" in str(e):
            print(f"[*] Bucket already exists: {BUCKET_NAME}")
            bucket = client.get_bucket(BUCKET_NAME)
        else:
            raise

    # 1. Enable uniform bucket-level access
    bucket.iam_configuration.uniform_bucket_level_access_enabled = True
    bucket.patch()
    print("[+] Uniform bucket-level access ENABLED")

    # 2. Enforce public access prevention
    bucket.iam_configuration.public_access_prevention = "enforced"
    bucket.patch()
    print("[+] Public access prevention ENFORCED")

    # 3. Enable versioning
    bucket.versioning_enabled = True
    bucket.patch()
    print("[+] Versioning ENABLED")

    # 4. Configure access logging
    bucket.logging = {"logBucket": LOG_BUCKET_NAME, "logObjectPrefix": f"{BUCKET_NAME}/"}
    bucket.patch()
    print(f"[+] Access logging enabled (target: {LOG_BUCKET_NAME})")

    # 5. Set retention policy (7 days)
    bucket.retention_period = 7 * 86400  # 7 days in seconds
    bucket.patch()
    print("[+] Retention policy set (7 days)")

    # 6. Configure lifecycle rules
    bucket.lifecycle_rules = [
        {
            "action": {"type": "SetStorageClass", "storageClass": "NEARLINE"},
            "condition": {"age": 30},
        },
        {
            "action": {"type": "SetStorageClass", "storageClass": "COLDLINE"},
            "condition": {"age": 90},
        },
        {
            "action": {"type": "Delete"},
            "condition": {"age": 365},
        },
    ]
    bucket.patch()
    print("[+] Lifecycle rules configured (Nearline→Coldline→Delete)")

    # 7. No CORS (default)
    bucket.cors = []
    bucket.patch()
    print("[+] No CORS rules (cross-origin access blocked)")

    # Upload sample object
    blob = bucket.blob("secure-document.txt")
    blob.upload_from_string("This document is stored securely.")
    print(f"[+] Uploaded sample object to {BUCKET_NAME}")

    print(f"\n[*] Hardened bucket '{BUCKET_NAME}' ready for auditing.")
    print(f"[*] Expected audit score: HIGH (most checks should PASS)")
    print(f"[*] Run: python main.py --provider gcp --bucket {BUCKET_NAME} --gcp-project {PROJECT_ID}")


def teardown():
    if not PROJECT_ID:
        print("[!] Set GCP_PROJECT_ID environment variable.")
        sys.exit(1)

    client = storage.Client(project=PROJECT_ID)
    for name in [BUCKET_NAME, LOG_BUCKET_NAME]:
        try:
            bucket = client.get_bucket(name)
            # Remove retention policy first (otherwise delete fails)
            try:
                bucket.retention_period = None
                bucket.patch()
            except Exception:
                pass
            bucket.delete(force=True)
            print(f"[-] Deleted bucket: {name}")
        except Exception as e:
            print(f"[!] Error deleting {name}: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "teardown":
        teardown()
    else:
        setup()
