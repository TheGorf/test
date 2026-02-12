"""Lambda@Edge handler for signature validation."""
from typing import Dict, Any
from request_parser import RequestParser
from timestamp_validator import TimestampValidator
from key_retriever import KeyRetriever
from signature_validator import SignatureValidator
from response_builder import ResponseBuilder
from logger import log_info, log_warning, log_error


# Initialize components (reused across invocations)
request_parser = RequestParser()
timestamp_validator = TimestampValidator()
key_retriever = KeyRetriever()
signature_validator = SignatureValidator()
response_builder = ResponseBuilder()


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    CloudFront viewer-request event handler.
    
    Args:
        event: CloudFront viewer request event
        context: Lambda context object
        
    Returns:
        Modified request or error response
    """
    try:
        # Extract CloudFront request
        cf_request = event['Records'][0]['cf']['request']
        request_id = context.request_id if hasattr(context, 'request_id') else 'unknown'
        
        # Extract key ID from URL
        key_id = request_parser.extract_key_id(cf_request)
        if not key_id:
            log_warning("Missing key ID in request", request_id=request_id)
            return response_builder.build_error_response(400, "Missing key ID in request")
        
        # Extract headers
        headers = cf_request.get('headers', {})
        
        signature = request_parser.extract_signature(headers)
        if not signature:
            log_warning("Missing signature header", request_id=request_id, key_id=key_id)
            return response_builder.build_error_response(401, "Missing signature header")
        
        timestamp_str = request_parser.extract_timestamp(headers)
        if not timestamp_str:
            log_warning("Missing timestamp header", request_id=request_id, key_id=key_id)
            return response_builder.build_error_response(400, "Missing timestamp header")
        
        algorithm = request_parser.extract_algorithm(headers)
        
        # Validate timestamp
        timestamp_valid, timestamp_error = timestamp_validator.validate(timestamp_str)
        if not timestamp_valid:
            log_warning("Timestamp validation failed", 
                       request_id=request_id, 
                       key_id=key_id,
                       reason=timestamp_error)
            return response_builder.build_error_response(401, timestamp_error)
        
        # Build signing payload
        payload = request_parser.build_signing_payload(cf_request, timestamp_str)
        
        # Retrieve key from DynamoDB
        key = key_retriever.get_key(key_id)
        if not key:
            log_warning("Key not found", request_id=request_id, key_id=key_id)
            return response_builder.build_error_response(401, "Invalid key ID")
        
        # Validate signature
        signature_valid, signature_error = signature_validator.validate(
            signature, payload, key, algorithm
        )
        
        if not signature_valid:
            log_warning("Signature validation failed",
                       request_id=request_id,
                       key_id=key_id,
                       algorithm=algorithm,
                       reason=signature_error)
            
            # Map error to appropriate status code
            if signature_error in ["Unsupported algorithm", "Algorithm mismatch"]:
                status_code = 400
            elif signature_error == "Key has been revoked":
                status_code = 401
            else:
                status_code = 403
            
            return response_builder.build_error_response(status_code, signature_error)
        
        # Add verification header
        modified_request = response_builder.add_verification_header(
            cf_request, key_id, algorithm
        )
        
        log_info("Signature validated successfully",
                request_id=request_id,
                key_id=key_id,
                algorithm=algorithm)
        
        return modified_request
        
    except Exception as e:
        log_error("Unexpected error during validation",
                 error=str(e),
                 error_type=type(e).__name__)
        return response_builder.build_error_response(500, "Internal server error")
