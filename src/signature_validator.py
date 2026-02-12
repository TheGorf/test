"""Cryptographic signature validator."""
import hmac
import hashlib
import base64
from typing import Dict, Any, Tuple, Optional
from config import SUPPORTED_ALGORITHMS
from logger import log_warning


class SignatureValidator:
    """Validates cryptographic signatures using HMAC or RSA."""
    
    def validate(self, signature: str, payload: bytes, key: Dict[str, Any], 
                 algorithm: str) -> Tuple[bool, Optional[str]]:
        """
        Main validation entry point.
        
        Args:
            signature: Base64-encoded signature
            payload: Signing payload bytes
            key: Key data from DynamoDB
            algorithm: Algorithm to use
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check key status
        if key.get('status') != 'active':
            log_warning("Key is not active", 
                       key_id=key.get('key_id'), 
                       status=key.get('status'))
            return False, "Key has been revoked"
        
        # Check algorithm is supported
        if algorithm not in SUPPORTED_ALGORITHMS:
            return False, "Unsupported algorithm"
        
        # Verify algorithm matches key configuration
        key_algorithm = key.get('algorithm', 'HMAC-SHA256')
        if algorithm != key_algorithm:
            log_warning("Algorithm mismatch", 
                       requested=algorithm, 
                       key_algorithm=key_algorithm)
            return False, "Algorithm mismatch"
        
        # Route to appropriate validator
        if algorithm == 'HMAC-SHA256':
            return self.validate_hmac(signature, payload, key.get('key_value'))
        elif algorithm == 'RSA-SHA256':
            return self.validate_rsa(signature, payload, key.get('key_value'))
        
        return False, "Unsupported algorithm"
    
    def validate_hmac(self, signature: str, payload: bytes, secret: str) -> Tuple[bool, Optional[str]]:
        """
        Validate HMAC-SHA256 signature.
        
        Args:
            signature: Base64-encoded signature
            payload: Signing payload bytes
            secret: Base64-encoded secret key
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Decode signature from base64
            provided_signature = base64.b64decode(signature)
        except Exception as e:
            return False, "Invalid signature encoding"
        
        try:
            # Decode secret key from base64
            secret_bytes = base64.b64decode(secret)
        except Exception as e:
            return False, "Invalid key encoding"
        
        # Compute expected HMAC
        expected_hmac = hmac.new(secret_bytes, payload, hashlib.sha256).digest()
        
        # Constant-time comparison to prevent timing attacks
        if hmac.compare_digest(provided_signature, expected_hmac):
            return True, None
        
        return False, "Signature validation failed"
    
    def validate_rsa(self, signature: str, payload: bytes, public_key_pem: str) -> Tuple[bool, Optional[str]]:
        """
        Validate RSA-SHA256 signature.
        
        Args:
            signature: Base64-encoded signature
            payload: Signing payload bytes
            public_key_pem: PEM-formatted RSA public key
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.exceptions import InvalidSignature
        except ImportError:
            return False, "RSA validation not available"
        
        try:
            # Decode signature from base64
            provided_signature = base64.b64decode(signature)
        except Exception as e:
            return False, "Invalid signature encoding"
        
        try:
            # Load RSA public key from PEM
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8')
            )
        except Exception as e:
            return False, "Invalid public key format"
        
        try:
            # Verify RSA signature
            public_key.verify(
                provided_signature,
                payload,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True, None
        except InvalidSignature:
            return False, "Signature validation failed"
        except Exception as e:
            return False, "Signature verification error"
