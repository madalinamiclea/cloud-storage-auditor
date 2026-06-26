"""
Prepare an AWS S3 bucket on LocalStack with default settings.
Used as the baseline scenario for security posture evaluation.
"""

import boto3
import sys

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
BUCKET_NAME = "test-default-bucket"


def setup():
    """Create a bucket with completely default settings."""
    s3 = boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )

    # Create bucket with no extra configuration
    try:
        s3.create_bucket(Bucket=BUCKET_NAME)
        print(f"[+] Created default bucket: {BUCKET_NAME}")
    except s3.exceptions.BucketAlreadyOwnedByYou:
        print(f"[*] Bucket already exists: {BUCKET_NAME}")

    # Upload a sample object
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key="sample-document.txt",
        Body=b"This is a sample document for security testing.",
    )
    print(f"[+] Uploaded sample object to {BUCKET_NAME}")

    print(f"\n[*] Default bucket '{BUCKET_NAME}' ready for auditing.")
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

    # Delete all objects
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
