#!/usr/bin/env python3

import argparse
import json
import logging
import sys
from pathlib import Path
from providers.base import ProviderType
from scoring.model import ScoringEngine
from scoring.report import print_cli_report, save_json_report, save_html_report

sys.path.insert(0, str(Path(__file__).resolve().parent))

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-storage-auditor",
        description=(
            "Automated security auditing of cloud object storage configurations. "
            "Evaluates AWS S3, Azure Blob Storage and Google Cloud Storage against "
            "a weighted scoring model mapped to CIS Foundation Benchmarks."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments
    parser.add_argument(
        "--provider", "-p",
        choices=["aws", "azure", "gcp"],
        required=True,
        help="Cloud storage provider to audit",
    )

    # Bucket selection
    bucket_group = parser.add_mutually_exclusive_group(required=True)
    bucket_group.add_argument(
        "--bucket", "-b",
        help="Name of the bucket/container to audit",
    )
    bucket_group.add_argument(
        "--all-buckets",
        action="store_true",
        help="Audit all accessible buckets/containers",
    )

    # AWS-specific options
    aws_group = parser.add_argument_group("AWS options")
    aws_group.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    aws_group.add_argument("--endpoint", help="Custom endpoint URL (e.g., http://localhost:4566 for LocalStack)")
    aws_group.add_argument("--aws-access-key", help="AWS access key ID")
    aws_group.add_argument("--aws-secret-key", help="AWS secret access key")

    # Azure-specific options
    azure_group = parser.add_argument_group("Azure options")
    azure_group.add_argument("--azure-connection-string", help="Azure Storage connection string")
    azure_group.add_argument("--azure-account", help="Azure Storage account name")
    azure_group.add_argument("--azure-subscription", help="Azure subscription ID")
    azure_group.add_argument("--azure-resource-group", help="Azure resource group name")
    azure_group.add_argument("--azure-tenant-id", help="Azure tenant ID")
    azure_group.add_argument("--azure-client-id", help="Azure client ID")
    azure_group.add_argument("--azure-client-secret", help="Azure client secret")

    # GCP-specific options
    gcp_group = parser.add_argument_group("GCP options")
    gcp_group.add_argument("--gcp-project", help="GCP project ID")
    gcp_group.add_argument("--gcp-credentials", help="Path to GCP service account JSON key file")

    # Output options
    output_group = parser.add_argument_group("Output options")
    output_group.add_argument("--output-json", help="Save report as JSON to the specified file path")
    output_group.add_argument("--output-html", help="Save report as HTML to the specified file path")
    output_group.add_argument("--no-color", action="store_true", help="Disable coloured terminal output")
    output_group.add_argument("--quiet", "-q", action="store_true", help="Suppress terminal report (use with --output-json/--output-html)")

    # Misc
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--sample-size", type=int, default=10, help="Number of objects to sample for public exposure check (default: 10)")

    return parser


def create_provider(args):
    if args.provider == "aws":
        from providers.aws import AWSProvider
        provider = AWSProvider(
            region=args.region,
            endpoint_url=args.endpoint,
            aws_access_key_id=args.aws_access_key,
            aws_secret_access_key=args.aws_secret_key,
        )
    elif args.provider == "azure":
        from providers.azure import AzureProvider
        provider = AzureProvider(
            subscription_id=args.azure_subscription or "",
            resource_group=args.azure_resource_group or "",
            account_name=args.azure_account or "",
            connection_string=args.azure_connection_string,
            tenant_id=args.azure_tenant_id,
            client_id=args.azure_client_id,
            client_secret=args.azure_client_secret,
        )
    elif args.provider == "gcp":
        from providers.gcp import GCPProvider
        provider = GCPProvider(
            project_id=args.gcp_project,
            credentials_path=args.gcp_credentials,
        )
    else:
        raise ValueError(f"Unsupported provider: {args.provider}")

    provider.connect()
    return provider


def main():
    parser = create_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        provider = create_provider(args)
        engine = ScoringEngine()

        # Checking target buckets to audit
        if args.all_buckets:
            buckets = provider.list_buckets()
            bucket_names = [b.name for b in buckets]
            logging.info("Found %d bucket(s) to audit", len(bucket_names))
        else:
            bucket_names = [args.bucket]

        if not bucket_names:
            logging.warning("No buckets found to audit.")
            sys.exit(0)

        all_results = []
        for bucket_name in bucket_names:
            logging.info("Auditing %s/%s ...", args.provider.upper(), bucket_name)

            try:
                bucket_config = provider.get_full_config(bucket_name)
                audit_result = engine.audit_bucket(bucket_config)
                all_results.append(audit_result)

                if not args.quiet:
                    print_cli_report(audit_result, use_color=not args.no_color)

                # Here we save the reports
                if args.output_json:
                    if len(bucket_names) > 1:
                        base = Path(args.output_json)
                        out_path = str(base.parent / f"{base.stem}_{bucket_name}{base.suffix}")
                    else:
                        out_path = args.output_json
                    save_json_report(audit_result, out_path)

                if args.output_html:
                    if len(bucket_names) > 1:
                        base = Path(args.output_html)
                        out_path = str(base.parent / f"{base.stem}_{bucket_name}{base.suffix}")
                    else:
                        out_path = args.output_html
                    save_html_report(audit_result, out_path)

            except Exception as e:
                logging.error("Error auditing %s: %s", bucket_name, e)
                if args.verbose:
                    import traceback
                    traceback.print_exc()

        if len(all_results) > 1 and not args.quiet:
            print(f"\n{'=' * 60}")
            print(f"  SUMMARY — {len(all_results)} bucket(s) audited")
            print(f"{'=' * 60}")
            for r in sorted(all_results, key=lambda x: x.normalised_score):
                score_indicator = (
                    "🟢" if r.normalised_score >= 70
                    else "🟡" if r.normalised_score >= 40
                    else "🔴"
                )
                print(f"  {score_indicator} {r.provider.upper():>5s}/{r.bucket_name:<30s} "
                      f"Score: {r.normalised_score:.1f}/100")
            avg = sum(r.normalised_score for r in all_results) / len(all_results)
            print(f"\n  Average score: {avg:.1f}/100")
            print(f"{'=' * 60}\n")

    except KeyboardInterrupt:
        print("\nAudit cancelled.")
        sys.exit(1)
    except Exception as e:
        logging.error("Fatal error: %s", e)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
