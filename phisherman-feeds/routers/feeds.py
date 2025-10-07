"""Endpoints para gestión y consulta de feeds."""

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel

from ..services.feed_manager import FeedManager
from ..services.google_safebrowsing import GoogleSafeBrowsingService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["feeds"])


class FeedRefreshResponse(BaseModel):
    """Response para refresh de feed."""

    feed_name: str
    status: str  # "success" | "error" | "running"
    message: str
    entries_processed: int | None = None
    error_details: str | None = None
    started_at: datetime
    completed_at: datetime | None = None


class FeedStatus(BaseModel):
    """Estado de un feed."""

    name: str
    enabled: bool
    last_refresh: datetime | None
    next_refresh: datetime | None
    total_entries: int
    refresh_interval_minutes: int
    status: str  # "active" | "error" | "disabled"
    last_error: str | None = None


class AllFeedsStatus(BaseModel):
    """Estado de todos los feeds."""

    feeds: list[FeedStatus]
    total_active_feeds: int
    total_entries: int
    last_global_refresh: datetime | None


# Instancia del feed manager
feed_manager = FeedManager()
safebrowsing_service = GoogleSafeBrowsingService()


@router.post("/refresh/{feed_name}", response_model=FeedRefreshResponse)
async def refresh_feed(
    feed_name: str, background_tasks: BackgroundTasks
) -> FeedRefreshResponse:
    """
    Refresh manual de un feed específico.

    Feeds disponibles: phishtank, openphish, urlhaus, safebrowsing
    """
    valid_feeds = ["phishtank", "openphish", "urlhaus", "safebrowsing"]

    if feed_name not in valid_feeds:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feed name. Available feeds: {', '.join(valid_feeds)}",
        )

    started_at = datetime.now(UTC)

    try:
        # Ejecutar refresh en background
        if feed_name == "safebrowsing":
            background_tasks.add_task(safebrowsing_service.refresh_threats)
        else:
            background_tasks.add_task(feed_manager.refresh_single_feed, feed_name)

        return FeedRefreshResponse(
            feed_name=feed_name,
            status="running",
            message=f"Feed {feed_name} refresh started in background",
            started_at=started_at,
        )

    except Exception as e:
        logger.error(f"Error starting refresh for feed {feed_name}: {e}")
        return FeedRefreshResponse(
            feed_name=feed_name,
            status="error",
            message=f"Failed to start refresh: {str(e)}",
            error_details=str(e),
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )


@router.post("/refresh-all")
async def refresh_all_feeds(background_tasks: BackgroundTasks) -> dict[str, Any]:
    """
    Refresh de todos los feeds disponibles.
    """
    started_at = datetime.now(UTC)

    try:
        # Iniciar refresh de todos los feeds en background
        background_tasks.add_task(feed_manager.refresh_all_feeds)
        background_tasks.add_task(safebrowsing_service.refresh_threats)

        return {
            "status": "running",
            "message": "All feeds refresh started in background",
            "feeds": ["phishtank", "openphish", "urlhaus", "safebrowsing"],
            "started_at": started_at.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error starting refresh for all feeds: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to start feeds refresh: {str(e)}"
        ) from e


@router.get("/status")
async def get_feeds_status() -> dict[str, Any]:
    """
    Obtener estado de todos los feeds.
    """
    try:
        feeds_status = await feed_manager.get_all_feeds_status()
        safebrowsing_status = await safebrowsing_service.get_status()

        # Combinar estados
        all_feeds = feeds_status["feeds"] + [safebrowsing_status]

        return {
            "feeds": all_feeds,
            "total_active_feeds": sum(1 for f in all_feeds if f["status"] == "active"),
            "total_entries": sum(f["total_entries"] for f in all_feeds),
            "last_global_refresh": max(
                [f["last_refresh"] for f in all_feeds if f["last_refresh"]],
                default=None,
            ),
        }

    except Exception as e:
        logger.error(f"Error getting feeds status: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get feeds status: {str(e)}"
        ) from e


@router.get("/status/{feed_name}", response_model=FeedStatus)
async def get_feed_status(feed_name: str) -> FeedStatus:
    """
    Obtener estado de un feed específico.
    """
    valid_feeds = ["phishtank", "openphish", "urlhaus", "safebrowsing"]

    if feed_name not in valid_feeds:
        raise HTTPException(
            status_code=404,
            detail=f"Feed not found. Available feeds: {', '.join(valid_feeds)}",
        )

    try:
        if feed_name == "safebrowsing":
            return await safebrowsing_service.get_status()
        else:
            return await feed_manager.get_feed_status(feed_name)

    except Exception as e:
        logger.error(f"Error getting status for feed {feed_name}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get feed status: {str(e)}"
        ) from e


@router.delete("/clean-old-entries")
async def clean_old_entries(
    background_tasks: BackgroundTasks,
    days_old: int = Query(
        30, ge=1, le=365, description="Días de antigüedad para limpiar"
    ),
) -> dict[str, Any]:
    """
    Limpiar entradas antiguas de feeds para liberar espacio.
    """
    started_at = datetime.now(UTC)

    try:
        background_tasks.add_task(feed_manager.clean_old_entries, days_old)

        return {
            "status": "running",
            "message": f"Cleanup of entries older than {days_old} days started",
            "started_at": started_at.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error starting cleanup: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to start cleanup: {str(e)}"
        ) from e


@router.get("/sources")
async def get_available_sources() -> dict[str, Any]:
    """
    Obtener lista de fuentes de feeds disponibles y su información.
    """
    return {
        "sources": [
            {
                "name": "phishtank",
                "description": "PhishTank community phishing URLs",
                "url": "http://data.phishtank.com/data/online-valid.json",
                "type": "phishing",
                "confidence": 0.9,
            },
            {
                "name": "openphish",
                "description": "OpenPhish automated phishing detection",
                "url": "https://openphish.com/feed.txt",
                "type": "phishing",
                "confidence": 0.85,
            },
            {
                "name": "urlhaus",
                "description": "URLhaus malware URLs",
                "url": "https://urlhaus.abuse.ch/downloads/json/",
                "type": "malware",
                "confidence": 0.9,
            },
            {
                "name": "safebrowsing",
                "description": "Google Safe Browsing API",
                "url": "https://safebrowsing.googleapis.com/",
                "type": "phishing,malware",
                "confidence": 0.95,
            },
        ],
        "total_sources": 4,
        "supported_threat_types": ["phishing", "malware", "suspicious"],
    }
