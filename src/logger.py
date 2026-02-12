"""Structured logging utility for Lambda@Edge."""
import json
import logging
from typing import Any, Dict, Optional
from config import LOG_LEVEL

# Configure logger
logger = logging.getLogger()
logger.setLevel(getattr(logging, LOG_LEVEL))


def log_info(message: str, **kwargs: Any) -> None:
    """Log info level message with structured data."""
    log_data = _build_log_entry('INFO', message, **kwargs)
    logger.info(json.dumps(log_data))


def log_warning(message: str, **kwargs: Any) -> None:
    """Log warning level message with structured data."""
    log_data = _build_log_entry('WARN', message, **kwargs)
    logger.warning(json.dumps(log_data))


def log_error(message: str, **kwargs: Any) -> None:
    """Log error level message with structured data."""
    log_data = _build_log_entry('ERROR', message, **kwargs)
    logger.error(json.dumps(log_data))


def _build_log_entry(level: str, message: str, **kwargs: Any) -> Dict[str, Any]:
    """Build structured log entry."""
    log_entry = {
        'level': level,
        'message': message
    }
    
    # Add additional fields, filtering out None values and sensitive data
    for key, value in kwargs.items():
        if value is not None and key not in ['key_value', 'secret', 'private_key']:
            log_entry[key] = value
    
    return log_entry
