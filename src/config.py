"""Configuration module for Lambda@Edge signature validation."""
import os

# DynamoDB Configuration
DYNAMODB_TABLE_NAME = os.environ.get('DYNAMODB_TABLE_NAME', 'signature-keys')
DYNAMODB_REGION = os.environ.get('DYNAMODB_REGION', 'us-east-1')

# Timestamp Validation Configuration
MAX_TIMESTAMP_AGE = int(os.environ.get('MAX_TIMESTAMP_AGE', '300'))  # 5 minutes
CLOCK_SKEW_TOLERANCE = int(os.environ.get('CLOCK_SKEW_TOLERANCE', '30'))  # 30 seconds

# Logging Configuration
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

# Supported Algorithms
SUPPORTED_ALGORITHMS = ['HMAC-SHA256', 'RSA-SHA256']
DEFAULT_ALGORITHM = 'HMAC-SHA256'

# Cache Configuration
KEY_CACHE_TTL = int(os.environ.get('KEY_CACHE_TTL', '300'))  # 5 minutes

# Header Names
SIGNATURE_HEADER = 'x-signature'
TIMESTAMP_HEADER = 'x-timestamp'
ALGORITHM_HEADER = 'x-algorithm'
VERIFICATION_HEADER = 'x-signature-verified'
