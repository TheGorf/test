# Lambda@Edge Signature Validation

Cryptographic signature validation for HTTP requests at the AWS CloudFront edge using Lambda@Edge and DynamoDB.

## Overview

This Lambda@Edge function validates cryptographic signatures in HTTP headers before requests reach your origin servers. It supports both HMAC-SHA256 and RSA-SHA256 algorithms, retrieves keys from DynamoDB, and prevents replay attacks through timestamp validation.

## Features

- **Edge Validation**: Validates signatures at CloudFront edge locations
- **Multiple Algorithms**: Supports HMAC-SHA256 and RSA-SHA256
- **Dynamic Key Management**: Keys stored in DynamoDB with key ID-based lookups
- **Replay Protection**: Timestamp validation with configurable time windows
- **Caching**: In-memory key caching for optimal performance
- **Verification Headers**: Adds validation confirmation headers to authenticated requests

## Architecture

```
Client → CloudFront → Lambda@Edge → DynamoDB
                ↓
            Origin (validated requests only)
```

## Prerequisites

- AWS Account with permissions for Lambda, CloudFront, and DynamoDB
- Python 3.11
- AWS CLI configured
- pip for Python package management

## Setup Instructions

### 1. Create DynamoDB Table

```bash
cd deploy
./create-table.sh us-east-1
```

### 2. Generate Sample Keys

```bash
cd deploy
python3 generate_sample_keys.py signature-keys us-east-1
```

This creates sample HMAC and RSA keys and stores them in DynamoDB. Keys are also saved to `sample-keys.json` for reference.

### 3. Create IAM Role

Create an IAM role for Lambda@Edge with the policy in `deploy/iam-policy.json`:

```bash
aws iam create-role \
  --role-name lambda-edge-signature-validation-role \
  --assume-role-policy-document file://trust-policy.json

aws iam put-role-policy \
  --role-name lambda-edge-signature-validation-role \
  --policy-name signature-validation-policy \
  --policy-document file://deploy/iam-policy.json
```

Trust policy (`trust-policy.json`):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "lambda.amazonaws.com",
          "edgelambda.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### 4. Build Deployment Package

```bash
./deploy/build_package.sh
```

This creates `build/lambda-edge-signature-validation.zip`.

**Note**: If the package exceeds 1MB, consider using a Lambda Layer for the `cryptography` library.

### 5. Deploy Lambda Function

Deploy to **us-east-1** (required for Lambda@Edge):

```bash
aws lambda create-function \
  --function-name signature-validation-edge \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT_ID:role/lambda-edge-signature-validation-role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://build/lambda-edge-signature-validation.zip \
  --timeout 5 \
  --memory-size 128 \
  --environment Variables="{DYNAMODB_TABLE_NAME=signature-keys,DYNAMODB_REGION=us-east-1,MAX_TIMESTAMP_AGE=300,LOG_LEVEL=INFO}" \
  --region us-east-1
```

### 6. Publish Lambda Version

```bash
aws lambda publish-version \
  --function-name signature-validation-edge \
  --region us-east-1
```

Note the version ARN for CloudFront configuration.

### 7. Configure CloudFront Distribution

Add the Lambda@Edge function to your CloudFront distribution:

```bash
aws cloudfront update-distribution \
  --id YOUR_DISTRIBUTION_ID \
  --distribution-config file://cloudfront-config.json
```

Lambda@Edge association configuration:
```json
{
  "LambdaFunctionAssociations": {
    "Quantity": 1,
    "Items": [
      {
        "LambdaFunctionARN": "arn:aws:lambda:us-east-1:ACCOUNT_ID:function:signature-validation-edge:VERSION",
        "EventType": "viewer-request",
        "IncludeBody": true
      }
    ]
  }
}
```

## Configuration

Environment variables (set in Lambda configuration):

| Variable | Default | Description |
|----------|---------|-------------|
| `DYNAMODB_TABLE_NAME` | `signature-keys` | DynamoDB table name |
| `DYNAMODB_REGION` | `us-east-1` | DynamoDB region |
| `MAX_TIMESTAMP_AGE` | `300` | Max timestamp age in seconds (5 min) |
| `CLOCK_SKEW_TOLERANCE` | `30` | Clock skew tolerance in seconds |
| `LOG_LEVEL` | `INFO` | Logging level |
| `KEY_CACHE_TTL` | `300` | Key cache TTL in seconds |

## Request Format

Clients must include these headers:

- `X-Signature`: Base64-encoded signature
- `X-Timestamp`: Unix timestamp (seconds)
- `X-Algorithm`: `HMAC-SHA256` or `RSA-SHA256` (optional, defaults to HMAC-SHA256)

The key ID must be in the URL:
- Path format: `/api/{key_id}/resource`
- Query parameter: `?key_id=abc123`

## Response Codes

| Code | Description |
|------|-------------|
| 200 | Request validated and forwarded to origin |
| 400 | Bad request (missing key ID, timestamp, or unsupported algorithm) |
| 401 | Unauthorized (missing signature, invalid key, expired timestamp) |
| 403 | Forbidden (invalid signature) |
| 500 | Internal server error |

## Verification Header

Successfully validated requests include:
```
X-Signature-Verified: validated; timestamp=1234567890; key_id=abc123; algorithm=HMAC-SHA256
```

## DynamoDB Schema

Table: `signature-keys`

| Attribute | Type | Description |
|-----------|------|-------------|
| `key_id` | String (PK) | Unique key identifier |
| `key_value` | String | Base64-encoded key material |
| `algorithm` | String | `HMAC-SHA256` or `RSA-SHA256` |
| `status` | String | `active` or `revoked` |
| `created_at` | Number | Unix timestamp |
| `updated_at` | Number | Unix timestamp |

## Performance

- Cold start: 200-500ms
- Warm execution (cache hit): 5-20ms
- Warm execution (DynamoDB query): 50-150ms

## Security Considerations

- Keys are never logged or exposed in error messages
- Constant-time comparison prevents timing attacks
- Timestamp validation prevents replay attacks
- Key status field supports revocation
- Verification header format prevents client spoofing

## Troubleshooting

### Package Size Too Large

If the deployment package exceeds 1MB:
1. Create a Lambda Layer with the `cryptography` library
2. Remove `cryptography` from the deployment package
3. Attach the layer to your Lambda function

### DynamoDB Access Errors

Ensure the Lambda execution role has permissions to read from the DynamoDB table in the configured region.

### CloudFront Integration Issues

- Lambda function must be in us-east-1
- Use versioned ARN (not $LATEST)
- Event type must be viewer-request
- IncludeBody must be true for POST/PUT requests

## License

MIT
