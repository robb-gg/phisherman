"""Unified feed processor for all threat intelligence feeds."""

import asyncio
import hashlib
import logging
import os
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from phisherman.datastore.models import FeedEntry, Indicator
from phisherman.feeds.models import FeedResult, ParsedEntry
from phisherman.feeds.parsers.base import BaseFeedParser
from phisherman.feeds.parsers.openphish import OpenPhishParser
from phisherman.feeds.parsers.phishtank import PhishTankParser
from phisherman.feeds.parsers.urlhaus import URLhausParser

logger = logging.getLogger(__name__)


class FeedProcessor:
    """
    Unified processor for all threat intelligence feeds.

    This class coordinates fetching, parsing, and storing indicators
    from multiple threat intelligence sources.
    """

    def __init__(
        self,
        phishtank_api_key: str | None = None,
        http_timeout: int = 120,
    ):
        """
        Initialize the feed processor.

        Args:
            phishtank_api_key: Optional PhishTank API key for authenticated access.
            http_timeout: HTTP timeout in seconds.
        """
        # Get API key from environment if not provided
        self.phishtank_api_key = phishtank_api_key or os.getenv("PHISHTANK_API_KEY", "")
        self.http_timeout = http_timeout

        # Initialize parsers
        self.parsers: dict[str, BaseFeedParser] = {
            "phishtank": PhishTankParser(api_key=self.phishtank_api_key),
            "openphish": OpenPhishParser(),
            "urlhaus": URLhausParser(),
        }

    async def refresh_feed(
        self,
        feed_name: str,
        session: AsyncSession,
    ) -> FeedResult:
        """
        Refresh a single feed.

        Args:
            feed_name: Name of the feed to refresh.
            session: Database session for storing results.

        Returns:
            FeedResult with processing statistics.
        """
        if feed_name not in self.parsers:
            return FeedResult(
                feed_name=feed_name,
                status="error",
                error=f"Unknown feed: {feed_name}",
                completed_at=datetime.now(UTC),
            )

        parser = self.parsers[feed_name]
        logger.info(f"Starting refresh for feed: {feed_name}")

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.http_timeout),
                follow_redirects=True,
            ) as client:
                entries = await parser.fetch_and_parse(client)

            # Store entries in database
            result = await self._store_entries(
                session=session,
                feed_name=feed_name,
                feed_url=parser.feed_url,
                entries=entries,
            )

            result.completed_at = datetime.now(UTC)
            logger.info(
                f"Feed {feed_name} refresh completed: "
                f"{result.entries_processed} new, {result.duplicates} duplicates"
            )
            return result

        except Exception as e:
            logger.error(f"Feed {feed_name} refresh failed: {e}")
            return FeedResult(
                feed_name=feed_name,
                status="error",
                error=str(e),
                completed_at=datetime.now(UTC),
            )

    async def refresh_all_feeds(
        self,
        session: AsyncSession,
    ) -> dict[str, FeedResult]:
        """
        Refresh all configured feeds in parallel.

        Args:
            session: Database session for storing results.

        Returns:
            Dictionary of feed names to their results.
        """
        logger.info("Starting refresh for all feeds")

        tasks = []
        for feed_name in self.parsers:
            task = asyncio.create_task(
                self.refresh_feed(feed_name, session),
                name=f"refresh_{feed_name}",
            )
            tasks.append((feed_name, task))

        results = {}
        for feed_name, task in tasks:
            try:
                result = await task
                results[feed_name] = result
            except Exception as e:
                results[feed_name] = FeedResult(
                    feed_name=feed_name,
                    status="error",
                    error=str(e),
                    completed_at=datetime.now(UTC),
                )

        success_count = sum(1 for r in results.values() if r.status == "success")
        logger.info(
            f"All feeds refresh completed: {success_count}/{len(self.parsers)} successful"
        )

        return results

    async def _store_entries(
        self,
        session: AsyncSession,
        feed_name: str,
        feed_url: str,
        entries: list[ParsedEntry],
    ) -> FeedResult:
        """
        Store parsed entries in the database.

        Args:
            session: Database session.
            feed_name: Name of the feed.
            feed_url: URL of the feed.
            entries: Parsed entries to store.

        Returns:
            FeedResult with processing statistics.
        """
        entries_processed = 0
        duplicates = 0
        skipped = 0

        for entry in entries:
            # Generate checksum for deduplication
            extra = entry.external_id or ""
            checksum = self._generate_checksum(feed_name, entry.url, extra)

            # Check if entry already exists
            stmt = select(FeedEntry).where(FeedEntry.checksum == checksum)
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                duplicates += 1
                continue

            try:
                # Create feed entry
                feed_entry = FeedEntry(
                    feed_name=feed_name,
                    feed_url=feed_url,
                    raw_data=entry.to_dict(),
                    checksum=checksum,
                    external_id=entry.external_id,
                    feed_timestamp=entry.feed_timestamp or datetime.now(UTC),
                )
                session.add(feed_entry)

                # Create indicator
                indicator = Indicator(
                    indicator_type="url",
                    indicator_value=entry.url.lower(),
                    threat_type=entry.threat_type,
                    severity=entry.severity,
                    confidence=entry.confidence,
                    source=feed_name,
                    source_url=feed_url,
                    tags=entry.tags,
                    extra_data=entry.metadata,
                    first_seen=datetime.now(UTC),
                    last_seen=datetime.now(UTC),
                )
                session.add(indicator)

                entries_processed += 1

            except Exception as e:
                logger.warning(f"Failed to store entry {entry.url}: {e}")
                skipped += 1

        # Commit all changes
        await session.commit()

        return FeedResult(
            feed_name=feed_name,
            status="success",
            entries_processed=entries_processed,
            entries_skipped=skipped,
            duplicates=duplicates,
        )

    @staticmethod
    def _generate_checksum(feed_name: str, url: str, extra: str = "") -> str:
        """Generate a unique checksum for deduplication."""
        entry_str = f"{feed_name}:{url}:{extra}"
        return hashlib.sha256(entry_str.encode()).hexdigest()

    def get_available_feeds(self) -> list[str]:
        """Get list of available feed names."""
        return list(self.parsers.keys())
