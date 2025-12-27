"""Main FastAPI application with middleware, exception handlers, and routing."""

import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import generate_latest
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from phisherman.api.metrics import REQUEST_COUNT, REQUEST_DURATION
from phisherman.api.routers import analyze, health
from phisherman.config import settings
from phisherman.datastore.database import engine, init_db
from phisherman.services.feeds_client import FeedsClient

logger = logging.getLogger(__name__)


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Middleware to collect Prometheus metrics."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()

        response = await call_next(request)

        duration = time.time() - start_time
        endpoint = request.url.path
        method = request.method
        status_code = str(response.status_code)

        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status_code).inc()
        REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(duration)

        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager."""
    # Startup
    logger.info("Starting Phisherman API")
    await init_db()

    yield

    # Shutdown
    logger.info("Shutting down Phisherman API")
    await FeedsClient.close()
    await engine.dispose()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Phisherman API",
        description="Production-ready phishing and malware URL analyzer service",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_hosts if not settings.debug else ["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Prometheus metrics
    app.add_middleware(PrometheusMiddleware)

    # Exception handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, exc: HTTPException
    ) -> JSONResponse:
        """Handle HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                    "type": "http_error",
                }
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle validation errors."""
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": 422,
                    "message": "Validation error",
                    "type": "validation_error",
                    "details": exc.errors(),
                }
            },
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle general exceptions without exposing internals."""
        logger.exception("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": 500,
                    "message": "Internal server error",
                    "type": "internal_error",
                }
            },
        )

    # Metrics endpoint
    @app.get(settings.metrics_endpoint)
    async def metrics() -> Response:
        """Prometheus metrics endpoint."""
        return Response(
            content=generate_latest(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    # Include routers
    app.include_router(health.router, prefix=settings.api_prefix)
    app.include_router(analyze.router, prefix=settings.api_prefix)

    # Feeds administration API (internal)
    try:
        from phisherman.api.routers import feeds_admin

        app.include_router(feeds_admin.router, prefix=f"{settings.api_prefix}/admin")
        logger.info("Feeds admin API enabled")
    except ImportError:
        logger.warning("Feeds admin API not available")

    # Victim cataloging API (for B2B/B2C features)
    try:
        from phisherman.api.routers import victims

        app.include_router(victims.router, prefix=settings.api_prefix)
    except ImportError:
        logger.warning(
            "Victims API router not available - victim cataloging features disabled"
        )

    return app


# Create app instance
app = create_app()
