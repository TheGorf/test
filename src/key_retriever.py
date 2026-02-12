"""DynamoDB key retriever with caching."""
import time
from typing import Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError
from config import DYNAMODB_TABLE_NAME, DYNAMODB_REGION, KEY_CACHE_TTL
from logger import log_info, log_error


# Module-level cache for keys (persists across Lambda invocations)
_key_cache: Dict[str, Dict[str, Any]] = {}


class KeyRetriever:
    """Retrieves cryptographic keys from DynamoDB with caching."""
    
    def __init__(self, table_name: str = DYNAMODB_TABLE_NAME, 
                 region: str = DYNAMODB_REGION):
        """
        Initialize key retriever with DynamoDB configuration.
        
        Args:
            table_name: DynamoDB table name
            region: AWS region
        """
        self.table_name = table_name
        self.region = region
        self._dynamodb = None
    
    @property
    def dynamodb(self):
        """Lazy initialization of DynamoDB client for cold start optimization."""
        if self._dynamodb is None:
            self._dynamodb = boto3.resource('dynamodb', region_name=self.region)
        return self._dynamodb
    
    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve key from cache or DynamoDB.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Key data dict or None if not found
            {
                'key_id': str,
                'key_value': str,
                'algorithm': str,
                'status': str
            }
        """
        # Check cache first
        cached_key = self._get_from_cache(key_id)
        if cached_key:
            log_info("Key retrieved from cache", key_id=key_id)
            return cached_key
        
        # Query DynamoDB
        try:
            table = self.dynamodb.Table(self.table_name)
            response = table.get_item(Key={'key_id': key_id})
            
            if 'Item' not in response:
                log_info("Key not found in DynamoDB", key_id=key_id)
                return None
            
            key_data = response['Item']
            
            # Cache the key
            self._add_to_cache(key_id, key_data)
            
            log_info("Key retrieved from DynamoDB", key_id=key_id)
            return key_data
            
        except ClientError as e:
            log_error("DynamoDB query failed", 
                     key_id=key_id, 
                     error=str(e))
            raise
    
    def _get_from_cache(self, key_id: str) -> Optional[Dict[str, Any]]:
        """
        Get key from cache if not expired.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Cached key data or None
        """
        if key_id not in _key_cache:
            return None
        
        cached_entry = _key_cache[key_id]
        cache_time = cached_entry.get('_cache_time', 0)
        
        # Check if cache entry is expired
        if time.time() - cache_time > KEY_CACHE_TTL:
            del _key_cache[key_id]
            return None
        
        # Return cached data without internal fields
        key_data = {k: v for k, v in cached_entry.items() if not k.startswith('_')}
        return key_data
    
    def _add_to_cache(self, key_id: str, key_data: Dict[str, Any]) -> None:
        """
        Add key to cache with timestamp.
        
        Args:
            key_id: Key identifier
            key_data: Key data to cache
        """
        cached_entry = dict(key_data)
        cached_entry['_cache_time'] = time.time()
        _key_cache[key_id] = cached_entry
