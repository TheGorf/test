"""Request parser for extracting and validating request components."""
import re
import hashlib
import base64
from typing import Optional, Dict, Any
from urllib.parse import parse_qs, urlencode
from config import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    ALGORITHM_HEADER,
    DEFAULT_ALGORITHM
)


class RequestParser:
    """Parses CloudFront request and extracts validation components."""
    
    # Regex pattern to extract key_id from URL path (e.g., /api/{key_id}/resource)
    KEY_ID_PATH_PATTERN = re.compile(r'/api/([^/]+)')
    
    def extract_key_id(self, request: Dict[str, Any]) -> Optional[str]:
        """
        Extract key ID from URL path or query parameter.
        
        Args:
            request: CloudFront request object
            
        Returns:
            Key ID string or None if not found
        """
        # Try to extract from URL path first
        uri = request.get('uri', '')
        match = self.KEY_ID_PATH_PATTERN.search(uri)
        if match:
            return match.group(1)
        
        # Fallback to query parameter
        querystring = request.get('querystring', '')
        if querystring:
            params = parse_qs(querystring)
            key_ids = params.get('key_id', [])
            if key_ids:
                return key_ids[0]
        
        return None
    
    def extract_signature(self, headers: Dict[str, list]) -> Optional[str]:
        """
        Extract signature from X-Signature header.
        
        Args:
            headers: CloudFront headers dict
            
        Returns:
            Signature string or None if not found
        """
        header_values = headers.get(SIGNATURE_HEADER, [])
        if header_values:
            return header_values[0].get('value')
        return None
    
    def extract_timestamp(self, headers: Dict[str, list]) -> Optional[str]:
        """
        Extract timestamp from X-Timestamp header.
        
        Args:
            headers: CloudFront headers dict
            
        Returns:
            Timestamp string or None if not found
        """
        header_values = headers.get(TIMESTAMP_HEADER, [])
        if header_values:
            return header_values[0].get('value')
        return None
    
    def extract_algorithm(self, headers: Dict[str, list]) -> str:
        """
        Extract algorithm from X-Algorithm header with default.
        
        Args:
            headers: CloudFront headers dict
            
        Returns:
            Algorithm string (defaults to HMAC-SHA256)
        """
        header_values = headers.get(ALGORITHM_HEADER, [])
        if header_values:
            return header_values[0].get('value', DEFAULT_ALGORITHM)
        return DEFAULT_ALGORITHM
    
    def build_signing_payload(self, request: Dict[str, Any], timestamp: str) -> bytes:
        """
        Construct canonical signing payload from request components.
        
        Payload format:
        {HTTP_METHOD}\n
        {URI_PATH}\n
        {CANONICAL_QUERY_STRING}\n
        {TIMESTAMP}\n
        {BODY_HASH}
        
        Args:
            request: CloudFront request object
            timestamp: Request timestamp string
            
        Returns:
            Signing payload as bytes
        """
        method = request.get('method', 'GET')
        uri = request.get('uri', '/')
        querystring = request.get('querystring', '')
        
        # Build canonical query string (sorted key=value pairs)
        canonical_qs = self._build_canonical_querystring(querystring)
        
        # Compute body hash
        body_hash = self._compute_body_hash(request)
        
        # Construct payload
        payload_parts = [
            method,
            uri,
            canonical_qs,
            timestamp,
            body_hash
        ]
        
        payload = '\n'.join(payload_parts)
        return payload.encode('utf-8')
    
    def _build_canonical_querystring(self, querystring: str) -> str:
        """
        Build canonical query string by sorting parameters.
        
        Args:
            querystring: Raw query string
            
        Returns:
            Canonical query string
        """
        if not querystring:
            return ''
        
        # Parse and sort parameters
        params = parse_qs(querystring, keep_blank_values=True)
        sorted_params = sorted(params.items())
        
        # Rebuild query string
        canonical_pairs = []
        for key, values in sorted_params:
            for value in sorted(values):
                canonical_pairs.append(f"{key}={value}")
        
        return '&'.join(canonical_pairs)
    
    def _compute_body_hash(self, request: Dict[str, Any]) -> str:
        """
        Compute SHA256 hash of request body.
        
        Args:
            request: CloudFront request object
            
        Returns:
            Hex-encoded SHA256 hash of body (or empty string hash if no body)
        """
        body = request.get('body', {})
        
        if not body or not body.get('data'):
            # No body - return hash of empty string
            return hashlib.sha256(b'').hexdigest()
        
        # Decode base64 body data
        body_data = body.get('data', '')
        try:
            body_bytes = base64.b64decode(body_data)
        except Exception:
            # If decode fails, hash the raw string
            body_bytes = body_data.encode('utf-8')
        
        return hashlib.sha256(body_bytes).hexdigest()
