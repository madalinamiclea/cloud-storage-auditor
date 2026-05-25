# Cloud Storage Auditor

Multi-cloud security auditing framework for object storage services:
- **AWS S3**
- **Azure Blob Storage**
- **Google Cloud Storage (GCS)**

The tool evaluates bucket/container configuration with a weighted scoring model (0-100), maps checks to CIS benchmark controls, and generates CLI/JSON/HTML reports.

## Features

- Audits one bucket/container or all accessible buckets for a provider
- Runs **12 security checks** across access control, encryption, logging, versioning, public exposure, and CORS
- Uses configurable weights from `config/scoring_weights.yaml`
- Uses CIS mappings from `config/cis_mappings.yaml`
- Outputs:
    - terminal report
    - JSON report (`--output-json`)
    - HTML report (`--output-html`)
 

## Project Structure

```
cloud-storage-auditor/
├── main.py                     # CLI entry point
├── providers/                  # AWS / Azure / GCP collectors
├── checks/                     # Security checks by category
├── scoring/                    # Score model + report rendering
├── config/                     # Weights and CIS mappings
├── comparison/                 # RQ4 comparison utilities
├── tests/                      # Unit + integration tests
├── external/                   # Optional external tool outputs
└── results/                    # Generated experiment artifacts
```

## Architecture

```
CLI (main.py)
  → Provider.connect()        # Authenticate with cloud provider
  → Provider.get_*_config()   # Retrieve normalised configuration
  → Checks[].evaluate()       # Run provider-agnostic checks
  → ScoringEngine.compute()   # Weighted score aggregation
  → Report.generate()         # Output (CLI / JSON / HTML)
```

## Security Checks

Implemented checks:

1. `public_access_block`
2. `iam_policy_least_privilege`
3. `acl_not_public`
4. `encryption_at_rest`
5. `encryption_in_transit`
6. `access_logging`
7. `audit_trail`
8. `versioning_enabled`
9. `soft_delete_or_mfa_delete`
10. `lifecycle_policy`
11. `no_public_objects`
12. `cors_restrictive`

Weights sum to 100 and final score is normalized to a 0-100 scale.

| # | Check | Weight | Category | Severity |
|---|-------|--------|----------|----------|
| 1 | Block Public Access | 10 | Access Control | Critical |
| 2 | IAM Policy Least Privilege | 8 | Access Control | High |
| 3 | ACL Not Public | 7 | Access Control | High |
| 4 | Encryption at Rest | 12 | Encryption | High |
| 5 | Encryption in Transit (HTTPS) | 8 | Encryption | High |
| 6 | Access Logging | 8 | Logging & Monitoring | High |
| 7 | Audit Trail | 7 | Logging & Monitoring | Medium |
| 8 | Object Versioning | 10 | Data Protection | High |
| 9 | Deletion Protection | 6 | Data Protection | Medium |
| 10 | Lifecycle Policy | 4 | Data Protection | Low |
| 11 | No Public Objects | 10 | Public Exposure | Critical |
| 12 | CORS Policy | 10 | CORS | Medium |
| | **Total** | **100** | | |

## Requirements

- Python 3.10+
- Access credentials for at least one cloud provider

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

General pattern:

```bash
python main.py --provider <aws|azure|gcp> --bucket <name>
```

### AWS S3

```bash
python main.py --provider aws --bucket my-bucket --region us-east-1
```

With LocalStack:

```bash
python main.py --provider aws --bucket test-bucket --endpoint http://localhost:4566
```

### Azure Blob Storage

```bash
python main.py --provider azure --bucket my-container \
    --azure-account myaccount \
    --azure-subscription <SUBSCRIPTION_ID> \
    --azure-resource-group <RESOURCE_GROUP>
```

### Google Cloud Storage

```bash
python main.py --provider gcp --bucket my-bucket --gcp-project my-project
```

### Audit all buckets

```bash
python main.py --provider aws --all-buckets
```

### Save reports

```bash
python main.py --provider aws --bucket my-bucket \
    --output-json report.json \
    --output-html report.html
```

Useful flags:

- `--verbose` for debug logs
- `--quiet` to suppress terminal output
- `--no-color` for plain terminal output
- `--sample-size N` for public object sampling (default: 10)

## Authentication

The auditor uses cloud SDK default credential chains unless explicit CLI credentials are provided.

- **AWS**: environment variables, profile, IAM role, or `--aws-access-key` / `--aws-secret-key`
- **Azure**: `DefaultAzureCredential`, service principal args, or `--azure-connection-string`
- **GCP**: ADC / service account via `--gcp-credentials`

## Testing

Run unit tests:

```bash
python -m pytest tests/test_checks.py tests/test_scoring.py -v
```

Run all tests:

```bash
python -m pytest tests -v
```

Integration tests (LocalStack for AWS):

```bash
docker run -d -p 4566:4566 localstack/localstack
python -m pytest tests/test_integration.py -v
```

## Notes

- `results/` and `external/` are intended for generated/experimental artifacts.
- Scoring and CIS mappings are configurable and can be tuned for your evaluation scenario.

