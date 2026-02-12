# Client Integration Guide

This guide explains how to generate signatures and make authenticated requests to the Lambda@Edge signature validation system.

## Overview

Clients must:
1. Include a key ID in the request URL
2. Generate a signature of the request
3. Add required headers (signature, timestamp, algorithm)
4. Send the request to CloudFront

## Signing Payload Format

The signing payload is constructed as:

```
{HTTP_METHOD}\n
{URI_PATH}\n
{CANONICAL_QUERY_STRING}\n
{TIMESTAMP}\n
{BODY_HASH}
```

### Components

- **HTTP_METHOD**: GET, POST, PUT, DELETE, etc.
- **URI_PATH**: The path portion of the URL (e.g., `/api/test-hmac-key-001/resource`)
- **CANONICAL_QUERY_STRING**: Sorted query parameters (e.g., `key1=value1&key2=value2`)
- **TIMESTAMP**: Unix timestamp in seconds
- **BODY_HASH**: SHA256 hex digest of request body (or empty string hash if no body)

## HMAC-SHA256 Example (Python)

```python
import hmac
import hashlib
import base64
import time
import requests
from urllib.parse import urlencode

def sign_request_hmac(method, uri_path, query_params, body, secret_key, timestamp=None):
    """
    Generate HMAC-SHA256 signature for request.
    
    Args:
        method: HTTP method (e.g., 'GET', 'POST')
        uri_path: URI path (e.g., '/api/test-hmac-key-001/resource')
        query_params: Dict of query parameters
        body: Request body bytes (or None)
        secret_key: Base64-encoded secret key
        timestamp: Unix timestamp (or None for current time)
    
    Returns:
        Tuple of (signature, timestamp)
    """
    # Generate timestamp if not provided
    if timestamp is None:
        timestamp = int(time.time())
    
    # Build canonical query string
    if query_params:
        sorted_params = sorted(query_params.items())
        canonical_qs = urlencode(sorted_params)
    else:
        canonical_qs = ''
    
    # Compute body hash
    if body:
        body_hash = hashlib.sha256(body).hexdigest()
    else:
        body_hash = hashlib.sha256(b'').hexdigest()
    
    # Build signing payload
    payload_parts = [
        method,
        uri_path,
        canonical_qs,
        str(timestamp),
        body_hash
    ]
    payload = '\n'.join(payload_parts).encode('utf-8')
    
    # Decode secret key
    secret_bytes = base64.b64decode(secret_key)
    
    # Compute HMAC
    signature = hmac.new(secret_bytes, payload, hashlib.sha256).digest()
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    return signature_b64, timestamp


# Example usage
def make_authenticated_request():
    # Configuration
    cloudfront_url = 'https://your-distribution.cloudfront.net'
    key_id = 'test-hmac-key-001'
    secret_key = 'YOUR_BASE64_SECRET_KEY'  # From sample-keys.json
    
    # Request details
    method = 'GET'
    uri_path = f'/api/{key_id}/resource'
    query_params = {'param1': 'value1'}
    body = None
    
    # Generate signature
    signature, timestamp = sign_request_hmac(
        method, uri_path, query_params, body, secret_key
    )
    
    # Build request
    url = f"{cloudfront_url}{uri_path}"
    headers = {
        'X-Signature': signature,
        'X-Timestamp': str(timestamp),
        'X-Algorithm': 'HMAC-SHA256'
    }
    
    # Send request
    response = requests.get(url, params=query_params, headers=headers)
    
    print(f"Status: {response.status_code}")
    print(f"Verification Header: {response.headers.get('X-Signature-Verified')}")
    
    return response


if __name__ == '__main__':
    make_authenticated_request()
```

## RSA-SHA256 Example (Python)

```python
import hashlib
import base64
import time
import requests
from urllib.parse import urlencode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def sign_request_rsa(method, uri_path, query_params, body, private_key_pem, timestamp=None):
    """
    Generate RSA-SHA256 signature for request.
    
    Args:
        method: HTTP method
        uri_path: URI path
        query_params: Dict of query parameters
        body: Request body bytes (or None)
        private_key_pem: PEM-formatted RSA private key
        timestamp: Unix timestamp (or None for current time)
    
    Returns:
        Tuple of (signature, timestamp)
    """
    # Generate timestamp if not provided
    if timestamp is None:
        timestamp = int(time.time())
    
    # Build canonical query string
    if query_params:
        sorted_params = sorted(query_params.items())
        canonical_qs = urlencode(sorted_params)
    else:
        canonical_qs = ''
    
    # Compute body hash
    if body:
        body_hash = hashlib.sha256(body).hexdigest()
    else:
        body_hash = hashlib.sha256(b'').hexdigest()
    
    # Build signing payload
    payload_parts = [
        method,
        uri_path,
        canonical_qs,
        str(timestamp),
        body_hash
    ]
    payload = '\n'.join(payload_parts).encode('utf-8')
    
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    
    # Sign payload
    signature = private_key.sign(
        payload,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    return signature_b64, timestamp


# Example usage
def make_authenticated_request_rsa():
    # Configuration
    cloudfront_url = 'https://your-distribution.cloudfront.net'
    key_id = 'test-rsa-key-001'
    
    # Load private key from file
    with open('sample-keys.json', 'r') as f:
        import json
        keys = json.load(f)
        private_key_pem = keys['rsa']['private_key']
    
    # Request details
    method = 'POST'
    uri_path = f'/api/{key_id}/resource'
    query_params = {}
    body = b'{"data": "example"}'
    
    # Generate signature
    signature, timestamp = sign_request_rsa(
        method, uri_path, query_params, body, private_key_pem
    )
    
    # Build request
    url = f"{cloudfront_url}{uri_path}"
    headers = {
        'X-Signature': signature,
        'X-Timestamp': str(timestamp),
        'X-Algorithm': 'RSA-SHA256',
        'Content-Type': 'application/json'
    }
    
    # Send request
    response = requests.post(url, data=body, headers=headers)
    
    print(f"Status: {response.status_code}")
    print(f"Verification Header: {response.headers.get('X-Signature-Verified')}")
    
    return response


if __name__ == '__main__':
    make_authenticated_request_rsa()
```

## JavaScript/Node.js Example (HMAC)

```javascript
const crypto = require('crypto');
const axios = require('axios');

function signRequestHMAC(method, uriPath, queryParams, body, secretKey, timestamp = null) {
  // Generate timestamp if not provided
  if (!timestamp) {
    timestamp = Math.floor(Date.now() / 1000);
  }
  
  // Build canonical query string
  let canonicalQs = '';
  if (queryParams && Object.keys(queryParams).length > 0) {
    const sortedParams = Object.entries(queryParams).sort();
    canonicalQs = sortedParams.map(([k, v]) => `${k}=${v}`).join('&');
  }
  
  // Compute body hash
  const bodyHash = body 
    ? crypto.createHash('sha256').update(body).digest('hex')
    : crypto.createHash('sha256').update('').digest('hex');
  
  // Build signing payload
  const payloadParts = [
    method,
    uriPath,
    canonicalQs,
    timestamp.toString(),
    bodyHash
  ];
  const payload = payloadParts.join('\n');
  
  // Decode secret key from base64
  const secretBytes = Buffer.from(secretKey, 'base64');
  
  // Compute HMAC
  const hmac = crypto.createHmac('sha256', secretBytes);
  hmac.update(payload);
  const signature = hmac.digest('base64');
  
  return { signature, timestamp };
}

async function makeAuthenticatedRequest() {
  // Configuration
  const cloudfrontUrl = 'https://your-distribution.cloudfront.net';
  const keyId = 'test-hmac-key-001';
  const secretKey = 'YOUR_BASE64_SECRET_KEY';  // From sample-keys.json
  
  // Request details
  const method = 'GET';
  const uriPath = `/api/${keyId}/resource`;
  const queryParams = { param1: 'value1' };
  const body = null;
  
  // Generate signature
  const { signature, timestamp } = signRequestHMAC(
    method, uriPath, queryParams, body, secretKey
  );
  
  // Build request
  const url = `${cloudfrontUrl}${uriPath}`;
  const headers = {
    'X-Signature': signature,
    'X-Timestamp': timestamp.toString(),
    'X-Algorithm': 'HMAC-SHA256'
  };
  
  // Send request
  try {
    const response = await axios.get(url, { params: queryParams, headers });
    console.log('Status:', response.status);
    console.log('Verification Header:', response.headers['x-signature-verified']);
    return response;
  } catch (error) {
    console.error('Error:', error.response?.status, error.response?.data);
    throw error;
  }
}

makeAuthenticatedRequest();
```

## cURL Example

```bash
#!/bin/bash

# Configuration
CLOUDFRONT_URL="https://your-distribution.cloudfront.net"
KEY_ID="test-hmac-key-001"
SECRET_KEY="YOUR_BASE64_SECRET_KEY"

# Request details
METHOD="GET"
URI_PATH="/api/${KEY_ID}/resource"
QUERY_STRING="param1=value1"
TIMESTAMP=$(date +%s)

# Compute body hash (empty for GET)
BODY_HASH=$(echo -n "" | sha256sum | cut -d' ' -f1)

# Build signing payload
PAYLOAD="${METHOD}
${URI_PATH}
${QUERY_STRING}
${TIMESTAMP}
${BODY_HASH}"

# Decode secret and compute HMAC
SECRET_BYTES=$(echo -n "$SECRET_KEY" | base64 -d)
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET_BYTES" -binary | base64)

# Make request
curl -X GET "${CLOUDFRONT_URL}${URI_PATH}?${QUERY_STRING}" \
  -H "X-Signature: ${SIGNATURE}" \
  -H "X-Timestamp: ${TIMESTAMP}" \
  -H "X-Algorithm: HMAC-SHA256" \
  -v
```

## Testing

Use the sample keys generated by `deploy/generate_sample_keys.py`:

1. HMAC key: `test-hmac-key-001`
2. RSA key: `test-rsa-key-001`

Keys are saved in `sample-keys.json` after generation.

## Common Issues

### Signature Validation Failed

- Ensure payload construction matches exactly (including newlines)
- Verify timestamp is current (within 5 minutes)
- Check that query parameters are sorted alphabetically
- Confirm body hash is computed correctly

### Missing Key ID

- Key ID must be in URL path: `/api/{key_id}/resource`
- Or in query parameter: `?key_id=abc123`

### Timestamp Expired

- Timestamp must be within 5 minutes of current time
- Check system clock synchronization

## Best Practices

1. **Key Management**: Rotate keys regularly and use the `status` field to revoke old keys
2. **Timestamp Sync**: Ensure client clocks are synchronized (use NTP)
3. **HTTPS Only**: Always use HTTPS to prevent signature interception
4. **Error Handling**: Implement retry logic for transient failures
5. **Key Storage**: Store private keys securely (never in code or version control)
