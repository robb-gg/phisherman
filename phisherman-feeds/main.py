"""Microservicio interno de feeds - FastAPI app."""

import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .config import feeds_settings
from .routers import feeds, lookup
from .security import verify_internal_access

logger = logging.getLogger(__name__)


class InternalOnlyMiddleware(BaseHTTPMiddleware):
    """Middleware para garantizar que solo servicios internos accedan."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Permitir endpoints de health sin autenticación
        if request.url.path in ["/health", "/feeds/v1/health"]:
            return await call_next(request)

        try:
            await verify_internal_access(request)
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": {"message": e.detail, "type": "access_denied"}},
            )

        return await call_next(request)


class TimingMiddleware(BaseHTTPMiddleware):
    """Middleware para medir tiempos de respuesta."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time

        response.headers["X-Process-Time"] = str(duration)
        logger.info(f"Request {request.method} {request.url.path} - {duration:.3f}s")

        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager."""
    logger.info("Starting Phisherman Feeds Microservice")
    yield
    logger.info("Shutting down Phisherman Feeds Microservice")


def create_feeds_app() -> FastAPI:
    """Crear y configurar la aplicación de feeds."""
    app = FastAPI(
        title="Phisherman Feeds Service",
        description="Microservicio interno para gestión de feeds de threat intelligence",
        version="1.0.0",
        docs_url="/docs" if feeds_settings.debug else None,
        redoc_url=None,  # Deshabilitar redoc para servicio interno
        lifespan=lifespan,
    )

    # Middleware para acceso interno únicamente
    app.add_middleware(InternalOnlyMiddleware)
    app.add_middleware(TimingMiddleware)

    # Exception handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, exc: HTTPException
    ) -> JSONResponse:
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

    @app.exception_handler(Exception)
    async def general_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": 500,
                    "message": "Internal service error",
                    "type": "internal_error",
                }
            },
        )

    # Health endpoint básico
    @app.get("/health")
    async def health_check():
        """Health check público."""
        return {"status": "healthy", "service": "feeds"}

    # Include routers
    app.include_router(feeds.router, prefix=feeds_settings.api_prefix)
    app.include_router(lookup.router, prefix=feeds_settings.api_prefix)

    return app


# Create app instance
app = create_feeds_app()
