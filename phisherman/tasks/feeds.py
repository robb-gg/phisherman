"""Celery tasks for refreshing threat intelligence feeds."""

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from celery import shared_task
from sqlalchemy import select

from phisherman.config import settings
from phisherman.datastore.database import AsyncSessionLocal
from phisherman.datastore.models import FeedEntry, Indicator

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def refresh_phishtank(self):
    """Refresh PhishTank phishing URL feed."""
    import asyncio

    return asyncio.run(_refresh_phishtank())


@shared_task(bind=True, max_retries=3)
def refresh_openphish(self):
    """Refresh OpenPhish phishing URL feed."""
    import asyncio

    return asyncio.run(_refresh_openphish())


@shared_task(bind=True, max_retries=3)
def refresh_urlhaus(self):
    """Refresh URLhaus malware URL feed."""
    import asyncio

    return asyncio.run(_refresh_urlhaus())


async def _refresh_phishtank() -> dict[str, Any]:
    """Refresh PhishTank feed implementation."""
    feed_name = "phishtank"
    feed_url = "http://data.phishtank.com/data/online-valid.json"

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(
                feed_url, headers={"User-Agent": settings.user_agent}
            )
            response.raise_for_status()

            data = response.json()
            entries_processed = 0

            async with AsyncSessionLocal() as session:
                for entry in data:
                    url = entry.get("url", "").strip()
                    if not url:
                        continue

                    # Create checksum for deduplication
                    entry_str = f"{feed_name}:{url}"
                    checksum = hashlib.sha256(entry_str.encode()).hexdigest()

                    # Check if entry already exists
                    stmt = select(FeedEntry).where(FeedEntry.checksum == checksum)
                    result = await session.execute(stmt)
                    existing = result.scalar_one_or_none()

                    if existing:
                        continue  # Skip existing entries

                    # Create feed entry
                    feed_entry = FeedEntry(
                        feed_name=feed_name,
                        feed_url=feed_url,
                        raw_data=entry,
                        checksum=checksum,
                        external_id=str(entry.get("phish_id", "")),
                        feed_timestamp=datetime.now(UTC),
                    )
                    session.add(feed_entry)

                    # Create indicator
                    indicator = Indicator(
                        indicator_type="url",
                        indicator_value=url.lower(),
                        threat_type="phishing",
                        severity="high",
                        confidence=0.9,
                        source=feed_name,
                        source_url=feed_url,
                        tags=["phishing", "phishtank"],
                        metadata={
                            "phish_id": entry.get("phish_id"),
                            "submission_time": entry.get("submission_time"),
                            "target": entry.get("target", ""),
                        },
                        first_seen=datetime.now(UTC),
                        last_seen=datetime.now(UTC),
                    )
                    session.add(indicator)
                    entries_processed += 1

                await session.commit()

            logger.info(
                f"PhishTank feed refresh completed: {entries_processed} new entries"
            )
            return {"status": "success", "entries_processed": entries_processed}

    except Exception as e:
        logger.error(f"PhishTank feed refresh failed: {e}")
        return {"status": "error", "error": str(e)}


async def _refresh_openphish() -> dict[str, Any]:
    """Refresh OpenPhish feed implementation."""
    feed_name = "openphish"
    feed_url = "https://openphish.com/feed.txt"

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(
                feed_url, headers={"User-Agent": settings.user_agent}
            )
            response.raise_for_status()

            urls = response.text.strip().split("\n")
            entries_processed = 0

            async with AsyncSessionLocal() as session:
                for url in urls:
                    url = url.strip()
                    if not url or url.startswith("#"):
                        continue

                    # Create checksum for deduplication
                    entry_str = f"{feed_name}:{url}"
                    checksum = hashlib.sha256(entry_str.encode()).hexdigest()

                    # Check if entry already exists
                    stmt = select(FeedEntry).where(FeedEntry.checksum == checksum)
                    result = await session.execute(stmt)
                    existing = result.scalar_one_or_none()

                    if existing:
                        continue

                    # Create feed entry
                    feed_entry = FeedEntry(
                        feed_name=feed_name,
                        feed_url=feed_url,
                        raw_data={"url": url},
                        checksum=checksum,
                        feed_timestamp=datetime.now(UTC),
                    )
                    session.add(feed_entry)

                    # Create indicator
                    indicator = Indicator(
                        indicator_type="url",
                        indicator_value=url.lower(),
                        threat_type="phishing",
                        severity="high",
                        confidence=0.85,
                        source=feed_name,
                        source_url=feed_url,
                        tags=["phishing", "openphish"],
                        metadata={"url": url},
                        first_seen=datetime.now(UTC),
                        last_seen=datetime.now(UTC),
                    )
                    session.add(indicator)
                    entries_processed += 1

                await session.commit()

            logger.info(
                f"OpenPhish feed refresh completed: {entries_processed} new entries"
            )
            return {"status": "success", "entries_processed": entries_processed}

    except Exception as e:
        logger.error(f"OpenPhish feed refresh failed: {e}")
        return {"status": "error", "error": str(e)}


async def _refresh_urlhaus() -> dict[str, Any]:
    """Refresh URLhaus malware feed implementation."""
    feed_name = "urlhaus"
    feed_url = "https://urlhaus.abuse.ch/downloads/json/"

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.get(
                feed_url, headers={"User-Agent": settings.user_agent}
            )
            response.raise_for_status()

            # URLhaus returns JSONL format (one JSON object per line)
            lines = response.text.strip().split("\n")
            entries_processed = 0

            async with AsyncSessionLocal() as session:
                for line in lines:
                    if not line.strip():
                        continue

                    try:
                        import json

                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    url = entry.get("url", "").strip()
                    if not url:
                        continue

                    # Create checksum
                    entry_str = f"{feed_name}:{entry.get('id', url)}"
                    checksum = hashlib.sha256(entry_str.encode()).hexdigest()

                    # Check if exists
                    stmt = select(FeedEntry).where(FeedEntry.checksum == checksum)
                    result = await session.execute(stmt)
                    existing = result.scalar_one_or_none()

                    if existing:
                        continue

                    # Create feed entry
                    feed_entry = FeedEntry(
                        feed_name=feed_name,
                        feed_url=feed_url,
                        raw_data=entry,
                        checksum=checksum,
                        external_id=str(entry.get("id", "")),
                        feed_timestamp=datetime.now(UTC),
                    )
                    session.add(feed_entry)

                    # Determine threat type and severity
                    threat_tags = entry.get("tags", [])
                    if isinstance(threat_tags, str):
                        threat_tags = [threat_tags]

                    threat_type = "malware"
                    severity = "high"

                    # Create indicator
                    indicator = Indicator(
                        indicator_type="url",
                        indicator_value=url.lower(),
                        threat_type=threat_type,
                        severity=severity,
                        confidence=0.9,
                        source=feed_name,
                        source_url=feed_url,
                        tags=["malware", "urlhaus"] + threat_tags,
                        metadata={
                            "urlhaus_id": entry.get("id"),
                            "dateadded": entry.get("dateadded"),
                            "url_status": entry.get("url_status"),
                            "threat": entry.get("threat"),
                            "tags": threat_tags,
                        },
                        first_seen=datetime.now(UTC),
                        last_seen=datetime.now(UTC),
                    )
                    session.add(indicator)
                    entries_processed += 1

                await session.commit()

            logger.info(
                f"URLhaus feed refresh completed: {entries_processed} new entries"
            )
            return {"status": "success", "entries_processed": entries_processed}

    except Exception as e:
        logger.error(f"URLhaus feed refresh failed: {e}")
        return {"status": "error", "error": str(e)}
