#!/usr/bin/env python3
"""Generate sample keys and populate DynamoDB table."""
import base64
import secrets
import time
import json
import boto3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_hmac_key():
    """Generate a random HMAC secret key."""
    # Generate 32 bytes (256 bits) of random data
    secret = secrets.token_bytes(32)
    return base64.b64encode(secret).decode('utf-8')


def generate_rsa_keypair():
    """Generate RSA key pair and return public key in PEM format."""
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize public key to PEM format
    public_pem = public_key.public_key_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Serialize private key to PEM format (for client use)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    return public_pem, private_pem


def create_sample_keys(table_name='signature-keys', region='us-east-1'):
    """Create sample keys in DynamoDB."""
    dynamodb = boto3.resource('dynamodb', region_name=region)
    table = dynamodb.Table(table_name)
    
    timestamp = int(time.time())
    
    # Generate HMAC key
    hmac_secret = generate_hmac_key()
    hmac_key_id = 'test-hmac-key-001'
    
    print(f"\n=== HMAC Key Generated ===")
    print(f"Key ID: {hmac_key_id}")
    print(f"Secret (base64): {hmac_secret}")
    
    # Store HMAC key in DynamoDB
    table.put_item(Item={
        'key_id': hmac_key_id,
        'key_value': hmac_secret,
        'algorithm': 'HMAC-SHA256',
        'status': 'active',
        'created_at': timestamp,
        'updated_at': timestamp
    })
    print(f"✓ HMAC key stored in DynamoDB")
    
    # Generate RSA key pair
    public_pem, private_pem = generate_rsa_keypair()
    rsa_key_id = 'test-rsa-key-001'
    
    print(f"\n=== RSA Key Pair Generated ===")
    print(f"Key ID: {rsa_key_id}")
    print(f"\nPublic Key (PEM):")
    print(public_pem)
    print(f"\nPrivate Key (PEM) - Save this for client signing:")
    print(private_pem)
    
    # Store RSA public key in DynamoDB
    table.put_item(Item={
        'key_id': rsa_key_id,
        'key_value': public_pem,
        'algorithm': 'RSA-SHA256',
        'status': 'active',
        'created_at': timestamp,
        'updated_at': timestamp
    })
    print(f"✓ RSA public key stored in DynamoDB")
    
    # Save keys to file for reference
    keys_data = {
        'hmac': {
            'key_id': hmac_key_id,
            'secret': hmac_secret,
            'algorithm': 'HMAC-SHA256'
        },
        'rsa': {
            'key_id': rsa_key_id,
            'public_key': public_pem,
            'private_key': private_pem,
            'algorithm': 'RSA-SHA256'
        }
    }
    
    with open('sample-keys.json', 'w') as f:
        json.dump(keys_data, f, indent=2)
    
    print(f"\n✓ Keys saved to sample-keys.json")
    print(f"\nSample keys created successfully!")


if __name__ == '__main__':
    import sys
    
    table_name = sys.argv[1] if len(sys.argv) > 1 else 'signature-keys'
    region = sys.argv[2] if len(sys.argv) > 2 else 'us-east-1'
    
    print(f"Generating sample keys for table: {table_name} in region: {region}")
    create_sample_keys(table_name, region)
