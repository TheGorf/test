"""Response builder for CloudFront responses."""
import time
from typing import Dict, Any
from config import VERIFICATION_HEADER


class ResponseBuilder:
    """Builds CloudFront responses and modifies requests."""
    
    def add_verification_header(self, request: Dict[str, Any], key_id: str, 
                               algorithm: str) -> Dict[str, Any]:
        """
        Add X-Signature-Verified header to request.
        
        Args:
            request: CloudFront request object
            key_id: Key ID used for validation
            algorithm: Algorithm used for validation
            
        Returns:
            Modified request with verification header
        """
        timestamp = int(time.time())
        
        # Format: validated; timestamp=1234567890; key_id=abc123; algorithm=HMAC-SHA256
        header_value = f"validated; timestamp={timestamp}; key_id={key_id}; algorithm={algorithm}"
        
        # Add header to request
        if 'headers' not in request:
            request['headers'] = {}
        
        request['headers'][VERIFICATION_HEADER] = [{
            'key': VERIFICATION_HEADER.title(),
            'value': header_value
        }]
        
        return request
    
    def build_error_response(self, status_code: int, message: str) -> Dict[str, Any]:
        """
        Build CloudFront-compatible error response.
        
        Args:
            status_code: HTTP status code
            message: Error message
            
        Returns:
            CloudFront error response object
        """
        status_descriptions = {
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            500: 'Internal Server Error'
        }
        
        status_description = status_descriptions.get(status_code, 'Error')
        
        return {
            'status': str(status_code),
            'statusDescription': status_description,
            'headers': {
                'content-type': [{
                    'key': 'Content-Type',
                    'value': 'application/json'
                }]
            },
            'body': f'{{"error": "{message}"}}'
        }
