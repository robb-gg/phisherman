"""Cache cleanup tasks for Phisherman."""

import asyncio
import logging
from datetime import UTC, datetime

from phisherman.datastore.database import AsyncSessionLocal
from phisherman.utils.cache import AnalysisCache

logger = logging.getLogger(__name__)


async def cleanup_expired_cache():
    """Clean up expired cache entries."""
    try:
        cache = AnalysisCache()

        async with AsyncSessionLocal() as db:
            cleared_count = await cache.clear_expired(db)

        logger.info(
            f"Cache cleanup completed. Cleared {cleared_count} expired entries."
        )
        return cleared_count

    except Exception as e:
        logger.error(f"Cache cleanup failed: {e}")
        return 0


async def get_cache_stats():
    """Get cache statistics."""
    try:
        async with AsyncSessionLocal() as db:
            from sqlalchemy import func, select

            from phisherman.datastore.models import Verdict

            # Total cache entries
            total_result = await db.execute(select(func.count(Verdict.id)))
            total_count = total_result.scalar()

            # Active (non-expired) entries
            now = datetime.now(UTC)
            active_result = await db.execute(
                select(func.count(Verdict.id)).where(Verdict.expires_at > now)
            )
            active_count = active_result.scalar()

            # Expired entries
            expired_count = total_count - active_count

            # Cache hit statistics
            hit_stats = await db.execute(
                select(
                    func.sum(Verdict.hit_count).label("total_hits"),
                    func.avg(Verdict.hit_count).label("avg_hits"),
                ).where(Verdict.expires_at > now)
            )
            hit_data = hit_stats.first()

            stats = {
                "total_entries": total_count,
                "active_entries": active_count,
                "expired_entries": expired_count,
                "total_hits": int(hit_data.total_hits or 0),
                "average_hits_per_entry": float(hit_data.avg_hits or 0.0),
            }

            logger.info(f"Cache stats: {stats}")
            return stats

    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        return {}


if __name__ == "__main__":
    # Can be run as a standalone script
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "stats":
        # Show stats
        asyncio.run(get_cache_stats())
    else:
        # Run cleanup
        asyncio.run(cleanup_expired_cache())
