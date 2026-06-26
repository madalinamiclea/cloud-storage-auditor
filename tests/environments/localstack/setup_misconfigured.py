"""
Prepare an AWS S3 bucket on LocalStack with intentionally weak settings.
Used to validate detection of common storage misconfigurations.

Applied changes:
    1. Block Public Access disabled
    2. Public-read ACL
    3. Wildcard bucket policy (allows any principal s3:GetObject)
    4. No encryption enforcement
    5. No server access logging
    6. Versioning disabled
    7. No lifecycle policy
    8. Overly permissive CORS (wildcard origin)
"""

import json
import boto3
import sys

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
BUCKET_NAME = "test-misconfigured-bucket"


def setup():
    """Create a bucket with known security misconfigurations."""
    s3 = boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )

    # 1. Create bucket
    try:
        s3.create_bucket(Bucket=BUCKET_NAME)
        print(f"[+] Created bucket: {BUCKET_NAME}")
    except s3.exceptions.BucketAlreadyOwnedByYou:
        print(f"[*] Bucket already exists: {BUCKET_NAME}")

    # 2. Disable Block Public Access (ensure all four settings are OFF)
    try:
        s3.delete_public_access_block(Bucket=BUCKET_NAME)
        print("[+] Block Public Access DISABLED")
    except Exception:
        print("[*] Block Public Access was already disabled or not supported")

    # 3. Set public-read ACL
    try:
        s3.put_bucket_acl(Bucket=BUCKET_NAME, ACL="public-read")
        print("[+] Set ACL to public-read")
    except Exception as e:
        print(f"[!] Could not set public-read ACL: {e}")

    # 4. Add wildcard bucket policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
            },
            {
                "Sid": "WildcardActions",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{BUCKET_NAME}",
                    f"arn:aws:s3:::{BUCKET_NAME}/*",
                ],
            },
        ],
    }
    s3.put_bucket_policy(Bucket=BUCKET_NAME, Policy=json.dumps(policy))
    print("[+] Added wildcard bucket policy (Principal: *, Action: s3:*)")

    # 5. No encryption (don't set any encryption configuration)
    try:
        s3.delete_bucket_encryption(Bucket=BUCKET_NAME)
        print("[+] Encryption removed (no SSE)")
    except Exception:
        print("[*] No encryption to remove")

    # 6. Versioning explicitly suspended
    s3.put_bucket_versioning(
        Bucket=BUCKET_NAME,
        VersioningConfiguration={"Status": "Suspended"},
    )
    print("[+] Versioning SUSPENDED")

    # 7. Add overly permissive CORS
    cors = {
        "CORSRules": [
            {
                "AllowedOrigins": ["*"],
                "AllowedMethods": ["GET", "PUT", "POST", "DELETE", "HEAD"],
                "AllowedHeaders": ["*"],
                "MaxAgeSeconds": 3600,
            }
        ]
    }
    s3.put_bucket_cors(Bucket=BUCKET_NAME, CORSConfiguration=cors)
    print("[+] Set CORS with wildcard origin (*) and all methods")

    # 8. Upload sample objects (some with public ACL)
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key="public-data.txt",
        Body=b"This file is publicly accessible.",
    )
    try:
        s3.put_object_acl(
            Bucket=BUCKET_NAME,
            Key="public-data.txt",
            ACL="public-read",
        )
    except Exception:
        pass

    s3.put_object(
        Bucket=BUCKET_NAME,
        Key="sensitive-report.pdf",
        Body=b"Confidential financial report content.",
    )

    print(f"\n[*] Misconfigured bucket '{BUCKET_NAME}' ready for auditing.")
    print(f"[*] Expected audit score: VERY LOW (most checks should FAIL)")
    print(f"[*] Run: python main.py --provider aws --bucket {BUCKET_NAME} "
          f"--endpoint {ENDPOINT} --aws-access-key test --aws-secret-key test")


def teardown():
    """Remove the test bucket and its contents."""
    s3 = boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    try:
        resp = s3.list_objects_v2(Bucket=BUCKET_NAME)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=BUCKET_NAME, Key=obj["Key"])
        s3.delete_bucket(Bucket=BUCKET_NAME)
        print(f"[-] Deleted bucket: {BUCKET_NAME}")
    except Exception as e:
        print(f"[!] Error during teardown: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "teardown":
        teardown()
    else:
        setup()
