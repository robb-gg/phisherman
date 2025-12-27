"""Manager para coordinar todos los feeds disponibles."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select

from phisherman.datastore.database import AsyncSessionLocal
from phisherman.datastore.models import FeedEntry, Indicator
from phisherman.feeds import FeedProcessor, FeedResult

from ..config import feeds_settings

logger = logging.getLogger(__name__)


class FeedManager:
    """Manager central para todos los feeds."""

    def __init__(self):
        """Initialize the feed manager with the shared processor."""
        self.processor = FeedProcessor()
        self.feed_intervals = {
            "phishtank": feeds_settings.phishtank_refresh_interval,
            "openphish": feeds_settings.openphish_refresh_interval,
            "urlhaus": feeds_settings.urlhaus_refresh_interval,
        }

    async def refresh_single_feed(self, feed_name: str) -> dict[str, Any]:
        """Refresh un feed específico."""
        if feed_name not in self.processor.get_available_feeds():
            raise ValueError(f"Unknown feed: {feed_name}")

        logger.info(f"Starting refresh for feed: {feed_name}")

        async with AsyncSessionLocal() as session:
            result = await self.processor.refresh_feed(feed_name, session)
            logger.info(f"Feed {feed_name} refresh completed: {result.to_dict()}")
            return result.to_dict()

    async def refresh_all_feeds(self) -> dict[str, Any]:
        """Refresh todos los feeds en paralelo."""
        logger.info("Starting refresh for all feeds")

        async with AsyncSessionLocal() as session:
            results = await self.processor.refresh_all_feeds(session)

        feed_results = {name: result.to_dict() for name, result in results.items()}
        success_count = sum(1 for r in results.values() if r.status == "success")

        logger.info(
            f"All feeds refresh completed: {success_count}/{len(results)} successful"
        )

        return {
            "status": "completed",
            "feeds": feed_results,
            "successful_feeds": success_count,
            "total_feeds": len(results),
            "completed_at": datetime.now(UTC).isoformat(),
        }

    async def get_feed_status(self, feed_name: str) -> dict[str, Any]:
        """Obtener estado de un feed específico."""
        if feed_name not in self.processor.get_available_feeds():
            raise ValueError(f"Unknown feed: {feed_name}")

        async with AsyncSessionLocal() as db:
            # Última entrada del feed
            stmt = (
                select(FeedEntry)
                .where(FeedEntry.feed_name == feed_name)
                .order_by(FeedEntry.feed_timestamp.desc())
                .limit(1)
            )

            result = await db.execute(stmt)
            last_entry = result.scalar_one_or_none()

            # Total de indicadores de esta fuente
            stmt = select(Indicator).where(Indicator.source == feed_name)
            result = await db.execute(stmt)
            total_indicators = len(result.scalars().all())

            interval = self.feed_intervals.get(feed_name, 15)

            # Calcular próximo refresh
            next_refresh = None
            if last_entry and last_entry.feed_timestamp:
                next_refresh = last_entry.feed_timestamp + timedelta(minutes=interval)

            return {
                "name": feed_name,
                "enabled": True,
                "last_refresh": last_entry.feed_timestamp if last_entry else None,
                "next_refresh": next_refresh,
                "total_entries": total_indicators,
                "refresh_interval_minutes": interval,
                "status": "active" if last_entry else "never_refreshed",
                "last_error": None,
            }

    async def get_all_feeds_status(self) -> dict[str, Any]:
        """Obtener estado de todos los feeds."""
        feeds_status = []
        total_entries = 0

        for feed_name in self.processor.get_available_feeds():
            try:
                status = await self.get_feed_status(feed_name)
                feeds_status.append(status)
                total_entries += status["total_entries"]
            except Exception as e:
                logger.error(f"Error getting status for feed {feed_name}: {e}")
                feeds_status.append(
                    {
                        "name": feed_name,
                        "enabled": False,
                        "status": "error",
                        "last_error": str(e),
                        "total_entries": 0,
                        "refresh_interval_minutes": self.feed_intervals.get(
                            feed_name, 15
                        ),
                        "last_refresh": None,
                        "next_refresh": None,
                    }
                )

        return {
            "feeds": feeds_status,
            "total_active_feeds": sum(
                1 for f in feeds_status if f["status"] == "active"
            ),
            "total_entries": total_entries,
        }

    async def clean_old_entries(self, days_old: int = 30) -> dict[str, Any]:
        """Limpiar entradas antiguas de feeds."""
        cutoff_date = datetime.now(UTC) - timedelta(days=days_old)

        logger.info(
            f"Starting cleanup of entries older than {days_old} days "
            f"(before {cutoff_date})"
        )

        async with AsyncSessionLocal() as db:
            try:
                # Primero eliminar indicadores antiguos
                stmt_indicators = delete(Indicator).where(
                    Indicator.first_seen < cutoff_date
                )
                result_indicators = await db.execute(stmt_indicators)
                indicators_deleted = result_indicators.rowcount

                # Luego eliminar entradas de feed
                stmt_feeds = delete(FeedEntry).where(
                    FeedEntry.feed_timestamp < cutoff_date
                )
                result_feeds = await db.execute(stmt_feeds)
                feeds_deleted = result_feeds.rowcount

                await db.commit()

                logger.info(
                    f"Cleanup completed: {indicators_deleted} indicators, "
                    f"{feeds_deleted} feed entries deleted"
                )

                return {
                    "status": "success",
                    "indicators_deleted": indicators_deleted,
                    "feed_entries_deleted": feeds_deleted,
                    "cutoff_date": cutoff_date.isoformat(),
                }

            except Exception as e:
                await db.rollback()
                logger.error(f"Cleanup failed: {e}")
                raise e
