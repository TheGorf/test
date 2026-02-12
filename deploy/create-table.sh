#!/bin/bash
# Create DynamoDB table for signature keys

set -e

REGION=${1:-us-east-1}

echo "Creating DynamoDB table in region: $REGION"

aws dynamodb create-table \
  --cli-input-json file://dynamodb-table.json \
  --region $REGION

echo "Waiting for table to become active..."
aws dynamodb wait table-exists \
  --table-name signature-keys \
  --region $REGION

echo "DynamoDB table 'signature-keys' created successfully"
