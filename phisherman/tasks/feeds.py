"""Celery tasks for refreshing threat intelligence feeds."""

import logging
from typing import Any

from asgiref.sync import async_to_sync
from celery import shared_task

from phisherman.datastore.database import AsyncSessionLocal
from phisherman.feeds import FeedProcessor

logger = logging.getLogger(__name__)


# Shared processor instance
_processor: FeedProcessor | None = None


def get_processor() -> FeedProcessor:
    """Get or create the feed processor instance."""
    global _processor
    if _processor is None:
        _processor = FeedProcessor()
    return _processor


@shared_task(bind=True, max_retries=3)
def refresh_phishtank(self) -> dict[str, Any]:
    """Refresh PhishTank phishing URL feed."""
    return async_to_sync(_refresh_feed)("phishtank")


@shared_task(bind=True, max_retries=3)
def refresh_openphish(self) -> dict[str, Any]:
    """Refresh OpenPhish phishing URL feed."""
    return async_to_sync(_refresh_feed)("openphish")


@shared_task(bind=True, max_retries=3)
def refresh_urlhaus(self) -> dict[str, Any]:
    """Refresh URLhaus malware URL feed."""
    return async_to_sync(_refresh_feed)("urlhaus")


@shared_task(bind=True, max_retries=3)
def refresh_all_feeds(self) -> dict[str, Any]:
    """Refresh all threat intelligence feeds."""
    return async_to_sync(_refresh_all)()


async def _refresh_feed(feed_name: str) -> dict[str, Any]:
    """Internal async function to refresh a single feed."""
    processor = get_processor()

    async with AsyncSessionLocal() as session:
        result = await processor.refresh_feed(feed_name, session)
        return result.to_dict()


async def _refresh_all() -> dict[str, Any]:
    """Internal async function to refresh all feeds."""
    processor = get_processor()

    async with AsyncSessionLocal() as session:
        results = await processor.refresh_all_feeds(session)

        success_count = sum(1 for r in results.values() if r.status == "success")

        return {
            "status": "completed",
            "feeds": {name: result.to_dict() for name, result in results.items()},
            "successful_feeds": success_count,
            "total_feeds": len(results),
        }


# Legacy function exports for backwards compatibility
async def _refresh_phishtank() -> dict[str, Any]:
    """Legacy function - use refresh_phishtank task instead."""
    return await _refresh_feed("phishtank")


async def _refresh_openphish() -> dict[str, Any]:
    """Legacy function - use refresh_openphish task instead."""
    return await _refresh_feed("openphish")


async def _refresh_urlhaus() -> dict[str, Any]:
    """Legacy function - use refresh_urlhaus task instead."""
    return await _refresh_feed("urlhaus")
