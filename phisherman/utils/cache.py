"""URL analysis cache utilities."""

import hashlib
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from phisherman.datastore.models import Verdict

logger = logging.getLogger(__name__)


class AnalysisCache:
    """Manages caching of URL analysis results."""

    def __init__(self, ttl_hours: int = 24):
        """
        Initialize cache with TTL (Time To Live).

        Args:
            ttl_hours: Cache TTL in hours (default 24h)
        """
        self.ttl_hours = ttl_hours

    @staticmethod
    def generate_url_hash(url: str) -> str:
        """Generate a consistent hash for a URL."""
        return hashlib.sha256(url.encode("utf-8")).hexdigest()

    async def get_cached_result(
        self, db: AsyncSession, normalized_url: str
    ) -> Verdict | None:
        """
        Get cached analysis result if available and not expired.

        Args:
            db: Database session
            normalized_url: Normalized URL to check

        Returns:
            Cached verdict if found and valid, None otherwise
        """
        try:
            url_hash = self.generate_url_hash(normalized_url)
            now = datetime.now(UTC)

            # Query for valid (non-expired) cached result
            stmt = (
                select(Verdict)
                .where(Verdict.url_hash == url_hash, Verdict.expires_at > now)
                .order_by(Verdict.created_at.desc())
            )

            result = await db.execute(stmt)
            verdict = result.scalar_one_or_none()

            if verdict:
                # Update access tracking
                verdict.hit_count += 1
                verdict.last_accessed = now
                await db.commit()

                logger.debug(f"Cache HIT for URL: {normalized_url}")
                return verdict

            logger.debug(f"Cache MISS for URL: {normalized_url}")
            return None

        except Exception as e:
            logger.error(f"Cache lookup error for {normalized_url}: {e}")
            return None

    async def store_result(
        self,
        db: AsyncSession,
        normalized_url: str,
        is_malicious: bool,
        risk_score: float,
        confidence: float,
        labels: list[str],
        analyzer_version: str = "1.0.0",
        model_version: str = "1.0.0",
    ) -> Verdict | None:
        """
        Store analysis result in cache.

        Args:
            db: Database session
            normalized_url: Normalized URL
            is_malicious: Whether URL is malicious
            risk_score: Risk score
            confidence: Confidence level
            labels: Risk labels
            analyzer_version: Version of analyzer
            model_version: Version of scoring model

        Returns:
            Created verdict or None if failed
        """
        try:
            url_hash = self.generate_url_hash(normalized_url)
            now = datetime.now(UTC)
            expires_at = now + timedelta(hours=self.ttl_hours)

            # Delete existing cache entry for this URL
            await db.execute(select(Verdict).where(Verdict.url_hash == url_hash))
            existing = (
                await db.execute(select(Verdict).where(Verdict.url_hash == url_hash))
            ).scalar_one_or_none()

            if existing:
                await db.delete(existing)

            # Create new cache entry
            verdict = Verdict(
                url_hash=url_hash,
                normalized_url=normalized_url,
                is_malicious=is_malicious,
                risk_score=risk_score,
                confidence=confidence,
                labels=labels,
                analyzer_version=analyzer_version,
                model_version=model_version,
                expires_at=expires_at,
                hit_count=0,
            )

            db.add(verdict)
            await db.commit()
            await db.refresh(verdict)

            logger.debug(f"Cached result for URL: {normalized_url}")
            return verdict

        except Exception as e:
            logger.error(f"Cache store error for {normalized_url}: {e}")
            await db.rollback()
            return None

    async def clear_expired(self, db: AsyncSession) -> int:
        """
        Clear expired cache entries.

        Args:
            db: Database session

        Returns:
            Number of entries cleared
        """
        try:
            now = datetime.now(UTC)

            # Get expired entries
            stmt = select(Verdict).where(Verdict.expires_at <= now)
            result = await db.execute(stmt)
            expired_verdicts = result.scalars().all()

            count = len(expired_verdicts)

            # Delete expired entries
            for verdict in expired_verdicts:
                await db.delete(verdict)

            await db.commit()

            logger.info(f"Cleared {count} expired cache entries")
            return count

        except Exception as e:
            logger.error(f"Cache cleanup error: {e}")
            await db.rollback()
            return 0
