"""Timestamp validator for preventing replay attacks."""
import time
from typing import Optional, Tuple
from config import MAX_TIMESTAMP_AGE, CLOCK_SKEW_TOLERANCE


class TimestampValidator:
    """Validates request timestamps to prevent replay attacks."""
    
    def __init__(self, max_age_seconds: int = MAX_TIMESTAMP_AGE, 
                 clock_skew_seconds: int = CLOCK_SKEW_TOLERANCE):
        """
        Initialize timestamp validator.
        
        Args:
            max_age_seconds: Maximum age for timestamps (default 300 seconds)
            clock_skew_seconds: Clock skew tolerance (default 30 seconds)
        """
        self.max_age_seconds = max_age_seconds
        self.clock_skew_seconds = clock_skew_seconds
    
    def validate(self, timestamp_str: str) -> Tuple[bool, Optional[str]]:
        """
        Validate timestamp is within acceptable window.
        
        Args:
            timestamp_str: Unix timestamp as string
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Parse timestamp
        try:
            timestamp = int(timestamp_str)
        except (ValueError, TypeError):
            return False, "Invalid timestamp format"
        
        current_time = int(time.time())
        
        # Check if timestamp is in the future (with clock skew tolerance)
        if timestamp > current_time + self.clock_skew_seconds:
            return False, "Timestamp is in the future"
        
        # Check if timestamp is too old
        age = current_time - timestamp
        if age > self.max_age_seconds:
            return False, "Request timestamp expired"
        
        return True, None
