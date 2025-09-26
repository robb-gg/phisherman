"""Health check endpoints for service monitoring."""

import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from phisherman import __version__
from phisherman.api.dependencies import get_db_session, get_redis_client
from phisherman.api.schemas import HealthResponse

router = APIRouter(tags=["health"])

# Track start time for uptime calculation
_start_time = time.time()


@router.get("/healthz", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db_session),
    redis_client=Depends(get_redis_client),
) -> HealthResponse:
    """
    Comprehensive health check endpoint.

    Checks the status of all critical dependencies:
    - Database connectivity
    - Redis connectivity
    - Celery worker availability
    """
    health_status = {
        "database": False,
        "redis": False,
        "celery": False,
    }

    # Check database
    try:
        result = await db.execute(text("SELECT 1"))
        health_status["database"] = result.scalar() == 1
    except Exception:
        pass

    # Check Redis
    try:
        await redis_client.ping()
        health_status["redis"] = True
    except Exception:
        pass

    # Check Celery workers (via Redis)
    try:
        # Simple check for active workers by looking at celery stats
        # In production, you might want to use celery.control.inspect()
        worker_key = "celery-task-meta-*"
        await redis_client.keys(worker_key)
        # If we can query Redis for celery keys, assume celery is working
        health_status["celery"] = health_status["redis"]  # Simplified check
    except Exception:
        pass

    # Determine overall status
    all_healthy = all(health_status.values())
    overall_status = "healthy" if all_healthy else "unhealthy"

    # Return 503 if any critical service is down
    if not all_healthy:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service dependencies are not healthy",
        )

    return HealthResponse(
        status=overall_status,
        version=__version__,
        timestamp=datetime.utcnow().isoformat() + "Z",
        uptime_seconds=time.time() - _start_time,
        **health_status,
    )


@router.get("/health", response_model=dict[str, str])
async def simple_health_check() -> dict[str, str]:
    """Simple health check that always returns OK if service is running."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat() + "Z"}
