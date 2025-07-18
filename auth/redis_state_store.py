"""
Redis-based state storage for OAuth authentication.

This module provides persistent storage for OAuth state information
to support multi-tenant authentication across server restarts and
multiple instances.
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from datetime import timedelta

import redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class RedisStateStore:
    """Manages OAuth state storage in Redis."""
    
    def __init__(self, redis_url: Optional[str] = None):
        """
        Initialize Redis state store.
        
        Args:
            redis_url: Redis URL (defaults to REDIS_URL env var or localhost)
        """
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client: Optional[redis.Redis] = None
        self.ttl = timedelta(minutes=10)  # OAuth state TTL
        self.enabled = True
        
    @property
    def client(self) -> Optional[redis.Redis]:
        """Get Redis client with lazy initialization."""
        if self._client is None and self.enabled:
            try:
                self._client = redis.from_url(
                    self.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                # Test connection
                self._client.ping()
                logger.info(f"Connected to Redis at {self.redis_url}")
            except (RedisError, OSError) as e:
                logger.warning(f"Failed to connect to Redis: {e}. Falling back to in-memory storage.")
                self.enabled = False
                return None
        return self._client
    
    def store_oauth_state(self, state: str, session_id: Optional[str], 
                         client_id: Optional[str], client_secret: Optional[str]) -> bool:
        """
        Store OAuth state information in Redis.
        
        Args:
            state: OAuth state parameter
            session_id: MCP session ID
            client_id: OAuth client ID
            client_secret: OAuth client secret
            
        Returns:
            True if stored successfully, False otherwise
        """
        if not self.client:
            return False
            
        try:
            data = {
                "session_id": session_id,
                "client_id": client_id,
                "client_secret": client_secret
            }
            
            key = f"oauth_state:{state}"
            self.client.setex(
                key,
                self.ttl,
                json.dumps(data)
            )
            logger.debug(f"Stored OAuth state in Redis: {state}")
            return True
            
        except RedisError as e:
            logger.error(f"Failed to store OAuth state in Redis: {e}")
            return False
    
    def get_oauth_state(self, state: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve and remove OAuth state information from Redis.
        
        Args:
            state: OAuth state parameter
            
        Returns:
            Dict with session_id, client_id, client_secret or None
        """
        if not self.client:
            return None
            
        try:
            key = f"oauth_state:{state}"
            
            # Get and delete atomically
            pipeline = self.client.pipeline()
            pipeline.get(key)
            pipeline.delete(key)
            results = pipeline.execute()
            
            data_str = results[0]
            if data_str:
                logger.debug(f"Retrieved OAuth state from Redis: {state}")
                return json.loads(data_str)
            else:
                logger.debug(f"OAuth state not found in Redis: {state}")
                return None
                
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Failed to retrieve OAuth state from Redis: {e}")
            return None
    
    def store_session_credentials(self, session_id: str, credentials_json: str, 
                                 ttl: Optional[timedelta] = None) -> bool:
        """
        Store session credentials in Redis.
        
        Args:
            session_id: MCP session ID
            credentials_json: JSON string of credentials
            ttl: Time to live (defaults to 30 minutes)
            
        Returns:
            True if stored successfully, False otherwise
        """
        if not self.client:
            return False
            
        try:
            key = f"session_creds:{session_id}"
            ttl = ttl or timedelta(minutes=30)
            
            self.client.setex(
                key,
                ttl,
                credentials_json
            )
            logger.debug(f"Stored session credentials in Redis: {session_id}")
            return True
            
        except RedisError as e:
            logger.error(f"Failed to store session credentials in Redis: {e}")
            return False
    
    def get_session_credentials(self, session_id: str) -> Optional[str]:
        """
        Retrieve session credentials from Redis.
        
        Args:
            session_id: MCP session ID
            
        Returns:
            JSON string of credentials or None
        """
        if not self.client:
            return None
            
        try:
            key = f"session_creds:{session_id}"
            creds = self.client.get(key)
            
            if creds:
                # Refresh TTL on access
                self.client.expire(key, timedelta(minutes=30))
                logger.debug(f"Retrieved session credentials from Redis: {session_id}")
                
            return creds
            
        except RedisError as e:
            logger.error(f"Failed to retrieve session credentials from Redis: {e}")
            return None
    
    def delete_session_credentials(self, session_id: str) -> bool:
        """
        Delete session credentials from Redis.
        
        Args:
            session_id: MCP session ID
            
        Returns:
            True if deleted successfully, False otherwise
        """
        if not self.client:
            return False
            
        try:
            key = f"session_creds:{session_id}"
            deleted = self.client.delete(key)
            if deleted:
                logger.debug(f"Deleted session credentials from Redis: {session_id}")
            return bool(deleted)
            
        except RedisError as e:
            logger.error(f"Failed to delete session credentials from Redis: {e}")
            return False
    
    def store_user_credentials(self, user_email: str, client_id: str, 
                              credentials_json: str, ttl: Optional[timedelta] = None) -> bool:
        """
        Store user credentials in Redis with tenant isolation.
        
        Args:
            user_email: User's Google email
            client_id: OAuth client ID (for tenant isolation)
            credentials_json: JSON string of credentials
            ttl: Time to live (defaults to 7 days)
            
        Returns:
            True if stored successfully, False otherwise
        """
        if not self.client:
            return False
            
        try:
            # Key includes client_id for tenant isolation
            key = f"user_creds:{client_id}:{user_email}"
            ttl = ttl or timedelta(days=7)  # Longer TTL for user credentials
            
            self.client.setex(
                key,
                ttl,
                credentials_json
            )
            logger.debug(f"Stored user credentials in Redis: {user_email} (tenant: {client_id[:10]}...)")
            return True
            
        except RedisError as e:
            logger.error(f"Failed to store user credentials in Redis: {e}")
            return False
    
    def get_user_credentials(self, user_email: str, client_id: str) -> Optional[str]:
        """
        Retrieve user credentials from Redis with tenant isolation.
        
        Args:
            user_email: User's Google email
            client_id: OAuth client ID (for tenant isolation)
            
        Returns:
            JSON string of credentials or None
        """
        if not self.client:
            return None
            
        try:
            key = f"user_creds:{client_id}:{user_email}"
            creds = self.client.get(key)
            
            if creds:
                # Refresh TTL on access
                self.client.expire(key, timedelta(days=7))
                logger.debug(f"Retrieved user credentials from Redis: {user_email} (tenant: {client_id[:10]}...)")
                
            return creds
            
        except RedisError as e:
            logger.error(f"Failed to retrieve user credentials from Redis: {e}")
            return None
    
    def delete_user_credentials(self, user_email: str, client_id: str) -> bool:
        """
        Delete user credentials from Redis.
        
        Args:
            user_email: User's Google email
            client_id: OAuth client ID (for tenant isolation)
            
        Returns:
            True if deleted successfully, False otherwise
        """
        if not self.client:
            return False
            
        try:
            key = f"user_creds:{client_id}:{user_email}"
            deleted = self.client.delete(key)
            if deleted:
                logger.debug(f"Deleted user credentials from Redis: {user_email} (tenant: {client_id[:10]}...)")
            return bool(deleted)
            
        except RedisError as e:
            logger.error(f"Failed to delete user credentials from Redis: {e}")
            return False
    
    def close(self):
        """Close Redis connection."""
        if self._client:
            try:
                self._client.close()
                logger.info("Closed Redis connection")
            except Exception as e:
                logger.error(f"Error closing Redis connection: {e}")
            finally:
                self._client = None


# Global instance
_redis_store: Optional[RedisStateStore] = None


def get_redis_store() -> RedisStateStore:
    """Get or create the global Redis state store instance."""
    global _redis_store
    if _redis_store is None:
        _redis_store = RedisStateStore()
    return _redis_store


def close_redis_store():
    """Close the global Redis state store."""
    global _redis_store
    if _redis_store:
        _redis_store.close()
        _redis_store = None