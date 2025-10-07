"""Endpoints administrativos para gestión de feeds."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer

from phisherman.services.feeds_client import feeds_client

logger = logging.getLogger(__name__)

router = APIRouter(tags=["feeds-admin"])
security = HTTPBearer()


@router.get("/feeds/status")
async def get_feeds_status(token: str = Depends(security)) -> dict[str, Any]:
    """
    Obtener estado de todos los feeds (endpoint administrativo).

    Requiere autenticación bearer token.
    """
    try:
        return await feeds_client.get_feeds_status()
    except Exception as e:
        logger.error(f"Error getting feeds status: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get feeds status: {str(e)}"
        ) from e


@router.post("/feeds/refresh/{feed_name}")
async def trigger_feed_refresh(
    feed_name: str, token: str = Depends(security)
) -> dict[str, Any]:
    """
    Trigger manual refresh de un feed específico.

    Feeds disponibles: phishtank, openphish, urlhaus, safebrowsing
    """
    valid_feeds = ["phishtank", "openphish", "urlhaus", "safebrowsing"]

    if feed_name not in valid_feeds:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feed name. Available feeds: {', '.join(valid_feeds)}",
        )

    try:
        return await feeds_client.refresh_feed(feed_name)
    except Exception as e:
        logger.error(f"Error refreshing feed {feed_name}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to refresh feed: {str(e)}"
        ) from e


@router.get("/feeds/stats")
async def get_feeds_statistics(token: str = Depends(security)) -> dict[str, Any]:
    """
    Obtener estadísticas detalladas de feeds.
    """
    try:
        return await feeds_client.get_feeds_stats()
    except Exception as e:
        logger.error(f"Error getting feeds stats: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get feeds stats: {str(e)}"
        ) from e


@router.get("/feeds/health")
async def check_feeds_service_health() -> dict[str, Any]:
    """
    Verificar estado de salud del microservicio de feeds.

    Este endpoint no requiere autenticación para facilitar monitoreo.
    """
    try:
        is_healthy = await feeds_client.health_check()
        return {
            "feeds_service_healthy": is_healthy,
            "feeds_service_url": feeds_client.base_url,
        }
    except Exception as e:
        logger.error(f"Error checking feeds health: {e}")
        return {
            "feeds_service_healthy": False,
            "error": str(e),
            "feeds_service_url": feeds_client.base_url,
        }
