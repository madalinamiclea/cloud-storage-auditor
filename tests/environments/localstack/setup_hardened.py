"""
Prepare an AWS S3 bucket on LocalStack with hardened settings aligned to CIS guidance.
Used to validate that secure configurations score as expected.

Applied hardening:
    1. Block Public Access enabled (all four settings)
    2. Private ACL
    3. Encryption enabled (SSE-S3, AES256)
    4. HTTPS-only bucket policy (deny aws:SecureTransport=false)
    5. Server access logging enabled
    6. Versioning enabled
    7. Lifecycle rules configured
    8. No CORS (default = blocked)
"""

import json
import boto3
import sys

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
BUCKET_NAME = "test-hardened-bucket"
LOG_BUCKET_NAME = "test-hardened-logs"


def setup():
    """Create a bucket with CIS-compliant security settings."""
    s3 = boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )

    # Create log bucket first
    try:
        s3.create_bucket(Bucket=LOG_BUCKET_NAME)
        print(f"[+] Created log bucket: {LOG_BUCKET_NAME}")
    except s3.exceptions.BucketAlreadyOwnedByYou:
        pass

    # 1. Create main bucket
    try:
        s3.create_bucket(Bucket=BUCKET_NAME)
        print(f"[+] Created bucket: {BUCKET_NAME}")
    except s3.exceptions.BucketAlreadyOwnedByYou:
        print(f"[*] Bucket already exists: {BUCKET_NAME}")

    # 2. Enable Block Public Access (all four settings)
    s3.put_public_access_block(
        Bucket=BUCKET_NAME,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print("[+] Block Public Access ENABLED (all four settings)")

    # 3. Set private ACL
    s3.put_bucket_acl(Bucket=BUCKET_NAME, ACL="private")
    print("[+] ACL set to private")

    # 4. Enable SSE-S3 encryption
    s3.put_bucket_encryption(
        Bucket=BUCKET_NAME,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    },
                    "BucketKeyEnabled": True,
                }
            ]
        },
    )
    print("[+] Server-side encryption enabled (AES256 / SSE-S3)")

    # 5. HTTPS-only bucket policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyHTTP",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{BUCKET_NAME}",
                    f"arn:aws:s3:::{BUCKET_NAME}/*",
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false",
                    }
                },
            }
        ],
    }
    # Note: need to temporarily adjust Block Public Policy for LocalStack
    try:
        s3.put_bucket_policy(Bucket=BUCKET_NAME, Policy=json.dumps(policy))
        print("[+] HTTPS-only bucket policy applied")
    except Exception as e:
        print(f"[!] Could not set bucket policy (may be blocked by BPA): {e}")
        # Re-enable BPA after policy attempt
        try:
            s3.put_public_access_block(
                Bucket=BUCKET_NAME,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,  # Temporarily disable
                    "RestrictPublicBuckets": True,
                },
            )
            s3.put_bucket_policy(Bucket=BUCKET_NAME, Policy=json.dumps(policy))
            # Re-enable BlockPublicPolicy
            s3.put_public_access_block(
                Bucket=BUCKET_NAME,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            print("[+] HTTPS-only bucket policy applied (with BPA workaround)")
        except Exception as e2:
            print(f"[!] Still could not set bucket policy: {e2}")

    # 6. Enable server access logging
    try:
        s3.put_bucket_logging(
            Bucket=BUCKET_NAME,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": LOG_BUCKET_NAME,
                    "TargetPrefix": f"{BUCKET_NAME}/",
                }
            },
        )
        print(f"[+] Server access logging enabled (target: {LOG_BUCKET_NAME})")
    except Exception as e:
        print(f"[!] Could not enable logging: {e}")

    # 7. Enable versioning
    s3.put_bucket_versioning(
        Bucket=BUCKET_NAME,
        VersioningConfiguration={"Status": "Enabled"},
    )
    print("[+] Versioning ENABLED")

    # 8. Configure lifecycle rules
    s3.put_bucket_lifecycle_configuration(
        Bucket=BUCKET_NAME,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "TransitionToIA",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "Transitions": [
                        {"Days": 90, "StorageClass": "STANDARD_IA"},
                    ],
                },
                {
                    "ID": "ExpireOldVersions",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "NoncurrentVersionExpiration": {"NoncurrentDays": 365},
                },
            ]
        },
    )
    print("[+] Lifecycle rules configured (IA transition + version expiration)")

    # 9. Upload sample object
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key="secure-document.txt",
        Body=b"This document is stored securely.",
    )
    print(f"[+] Uploaded sample object to {BUCKET_NAME}")

    print(f"\n[*] Hardened bucket '{BUCKET_NAME}' ready for auditing.")
    print(f"[*] Expected audit score: HIGH (most checks should PASS)")
    print(f"[*] Run: python main.py --provider aws --bucket {BUCKET_NAME} "
          f"--endpoint {ENDPOINT} --aws-access-key test --aws-secret-key test")


def teardown():
    """Remove the test buckets and their contents."""
    s3 = boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    for bucket in [BUCKET_NAME, LOG_BUCKET_NAME]:
        try:
            # Delete all object versions
            try:
                versions = s3.list_object_versions(Bucket=bucket)
                for v in versions.get("Versions", []):
                    s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
                for dm in versions.get("DeleteMarkers", []):
                    s3.delete_object(Bucket=bucket, Key=dm["Key"], VersionId=dm["VersionId"])
            except Exception:
                pass

            resp = s3.list_objects_v2(Bucket=bucket)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
            print(f"[-] Deleted bucket: {bucket}")
        except Exception as e:
            print(f"[!] Error deleting {bucket}: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "teardown":
        teardown()
    else:
        setup()
