"""
WAF Rate Limiter
Handles request rate limiting using Redis
"""

import time
import redis
import os
from dataclasses import dataclass
from typing import Dict, Optional, Any
from flask import Request

from ..utils.logger import get_logger

@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    is_blocked: bool
    reason: str
    remaining_requests: int
    reset_time: int

class RateLimiter:
    """Rate limiting component using Redis"""
    
    def __init__(self, redis_url: Optional[str] = None):
        """Initialize rate limiter"""
        self.logger = get_logger(__name__)
        
        # Redis configuration
        self.redis_url = redis_url or os.getenv('WAF_REDIS_URL', 'redis://localhost:6379')
        self.redis_client = None
        
        # Rate limit configuration
        self.default_limit = int(os.getenv('WAF_RATE_LIMIT', 100))
        self.default_window = int(os.getenv('WAF_RATE_WINDOW', 3600))  # 1 hour
        self.burst_limit = int(os.getenv('WAF_BURST_LIMIT', 10))
        self.burst_window = int(os.getenv('WAF_BURST_WINDOW', 60))  # 1 minute
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'rate_limited': 0,
            'burst_limited': 0
        }
        
        # Initialize Redis connection
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.from_url(self.redis_url)
            # Test connection
            self.redis_client.ping()
            self.logger.info("Redis connection established")
        except Exception as e:
            self.logger.warning(f"Redis connection failed: {str(e)}")
            self.logger.warning("Rate limiting will be disabled")
            self.redis_client = None
    
    def check_rate_limit(self, request: Request) -> RateLimitResult:
        """Check if request exceeds rate limits"""
        self.stats['total_checks'] += 1
        
        if not self.redis_client:
            # If Redis is not available, allow all requests
            return RateLimitResult(
                is_blocked=False,
                reason="",
                remaining_requests=self.default_limit,
                reset_time=int(time.time() + self.default_window)
            )
        
        try:
            # Get client identifier (IP address)
            client_id = self._get_client_id(request)
            
            # Check burst limit (short window)
            burst_result = self._check_limit(
                client_id, 
                self.burst_limit, 
                self.burst_window, 
                'burst'
            )
            
            if burst_result.is_blocked:
                self.stats['burst_limited'] += 1
                return burst_result
            
            # Check regular rate limit (long window)
            rate_result = self._check_limit(
                client_id, 
                self.default_limit, 
                self.default_window, 
                'rate'
            )
            
            if rate_result.is_blocked:
                self.stats['rate_limited'] += 1
                return rate_result
            
            return rate_result
            
        except Exception as e:
            self.logger.error(f"Rate limit check error: {str(e)}")
            # On error, allow the request
            return RateLimitResult(
                is_blocked=False,
                reason="",
                remaining_requests=self.default_limit,
                reset_time=int(time.time() + self.default_window)
            )
    
    def _get_client_id(self, request: Request) -> str:
        """Get unique client identifier"""
        # Try to get real IP from headers
        real_ip = request.headers.get('X-Real-IP') or \
                  request.headers.get('X-Forwarded-For', '').split(',')[0] or \
                  request.remote_addr
        
        return f"rate_limit:{real_ip}"
    
    def _check_limit(self, client_id: str, limit: int, window: int, limit_type: str) -> RateLimitResult:
        """Check specific rate limit"""
        current_time = int(time.time())
        window_start = current_time - window
        
        # Use Redis pipeline for atomic operations
        pipe = self.redis_client.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(client_id, 0, window_start)
        
        # Count current requests
        pipe.zcard(client_id)
        
        # Add current request
        pipe.zadd(client_id, {str(current_time): current_time})
        
        # Set expiry
        pipe.expire(client_id, window)
        
        # Execute pipeline
        results = pipe.execute()
        current_count = results[1]
        
        # Check if limit exceeded
        if current_count > limit:
            # Get oldest request time for reset calculation
            oldest = self.redis_client.zrange(client_id, 0, 0, withscores=True)
            reset_time = oldest[0][1] + window if oldest else current_time + window
            
            return RateLimitResult(
                is_blocked=True,
                reason=f"{limit_type} limit exceeded ({current_count}/{limit})",
                remaining_requests=0,
                reset_time=reset_time
            )
        
        # Calculate remaining requests and reset time
        remaining = max(0, limit - current_count)
        reset_time = current_time + window
        
        return RateLimitResult(
            is_blocked=False,
            reason="",
            remaining_requests=remaining,
            reset_time=reset_time
        )
    
    def get_client_stats(self, client_id: str) -> Dict[str, Any]:
        """Get rate limit statistics for a specific client"""
        if not self.redis_client:
            return {}
        
        try:
            current_time = int(time.time())
            
            # Get burst stats
            burst_key = f"rate_limit:{client_id}"
            burst_count = self.redis_client.zcount(burst_key, current_time - self.burst_window, current_time)
            
            # Get rate stats
            rate_count = self.redis_client.zcount(burst_key, current_time - self.default_window, current_time)
            
            return {
                'burst_requests': burst_count,
                'burst_limit': self.burst_limit,
                'rate_requests': rate_count,
                'rate_limit': self.default_limit,
                'burst_remaining': max(0, self.burst_limit - burst_count),
                'rate_remaining': max(0, self.default_limit - rate_count)
            }
        except Exception as e:
            self.logger.error(f"Error getting client stats: {str(e)}")
            return {}
    
    def reset_client_limit(self, client_id: str):
        """Reset rate limit for a specific client"""
        if not self.redis_client:
            return
        
        try:
            key = f"rate_limit:{client_id}"
            self.redis_client.delete(key)
            self.logger.info(f"Reset rate limit for client: {client_id}")
        except Exception as e:
            self.logger.error(f"Error resetting client limit: {str(e)}")
    
    def update_limits(self, rate_limit: Optional[int] = None, rate_window: Optional[int] = None,
                     burst_limit: Optional[int] = None, burst_window: Optional[int] = None):
        """Update rate limit configuration"""
        if rate_limit is not None:
            self.default_limit = rate_limit
        if rate_window is not None:
            self.default_window = rate_window
        if burst_limit is not None:
            self.burst_limit = burst_limit
        if burst_window is not None:
            self.burst_window = burst_window
        
        self.logger.info("Rate limit configuration updated")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        return {
            **self.stats,
            'redis_connected': self.redis_client is not None,
            'default_limit': self.default_limit,
            'default_window': self.default_window,
            'burst_limit': self.burst_limit,
            'burst_window': self.burst_window
        }
    
    def test_redis_connection(self) -> bool:
        """Test Redis connection"""
        if not self.redis_client:
            return False
        
        try:
            self.redis_client.ping()
            return True
        except Exception:
            return False
    
    def reconnect_redis(self):
        """Reconnect to Redis"""
        self._init_redis() 