"""FastAPI dependencies for database, Redis, and other services."""

import time
from collections.abc import AsyncGenerator

import redis.asyncio as redis
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from phisherman.config import settings
from phisherman.datastore.database import AsyncSessionLocal

# Global Redis connection pool
_redis_pool: dict[str, redis.Redis] = {}


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session dependency."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_redis_client():
    """Get Redis client dependency."""
    if "default" not in _redis_pool:
        _redis_pool["default"] = redis.from_url(
            settings.redis_url,
            max_connections=settings.redis_max_connections,
            retry_on_timeout=True,
        )
    return _redis_pool["default"]


class RateLimiter:
    """Simple token bucket rate limiter using Redis."""

    def __init__(
        self,
        requests_per_minute: int = None,
        burst_size: int = None,
    ):
        self.requests_per_minute = (
            requests_per_minute or settings.rate_limit_requests_per_minute
        )
        self.burst_size = burst_size or settings.rate_limit_burst_size
        self.window_size = 60  # seconds

    async def is_allowed(self, client_id: str, redis_client: redis.Redis) -> bool:
        """Check if request is allowed for client."""
        now = int(time.time())
        window_start = now - self.window_size

        # Use Redis pipeline for atomic operations
        pipe = redis_client.pipeline()

        # Remove old entries
        pipe.zremrangebyscore(f"rate_limit:{client_id}", 0, window_start)

        # Count current requests
        pipe.zcard(f"rate_limit:{client_id}")

        # Add current request
        pipe.zadd(f"rate_limit:{client_id}", {str(now): now})

        # Set expiry
        pipe.expire(f"rate_limit:{client_id}", self.window_size)

        results = await pipe.execute()
        current_requests = results[1]

        return current_requests < self.requests_per_minute


# Global rate limiter instance
rate_limiter = RateLimiter()


async def rate_limit_dependency(
    request: Request,
    redis_client=Depends(get_redis_client),
) -> None:
    """Rate limiting dependency."""
    # Use client IP as identifier (in production, consider API keys)
    client_ip = request.client.host if request.client else "unknown"
    client_id = f"ip:{client_ip}"

    try:
        if not await rate_limiter.is_allowed(client_id, redis_client):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": {
                        "code": 429,
                        "message": f"Rate limit exceeded: {settings.rate_limit_requests_per_minute} requests per minute",
                        "type": "rate_limit_error",
                    }
                },
            )
    except HTTPException:
        raise
    except Exception:
        # If rate limiting fails, allow the request (fail open)
        pass
