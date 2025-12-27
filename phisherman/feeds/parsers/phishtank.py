"""PhishTank feed parser."""

import bz2
import csv
import io
import logging
from datetime import datetime
from typing import Any

import httpx

from phisherman.feeds.models import ParsedEntry
from phisherman.feeds.parsers.base import BaseFeedParser

logger = logging.getLogger(__name__)


class PhishTankParser(BaseFeedParser):
    """
    Parser for PhishTank phishing URL feed.

    PhishTank provides a list of verified phishing URLs in CSV format.
    With an API key, compressed (bz2) downloads are available.
    """

    BASE_URL = "https://data.phishtank.com/data"
    PUBLIC_CSV_URL = f"{BASE_URL}/online-valid.csv"

    def __init__(self, api_key: str | None = None):
        super().__init__(api_key)

    @property
    def feed_name(self) -> str:
        return "phishtank"

    @property
    def feed_url(self) -> str:
        """Return appropriate URL based on API key availability."""
        if self.api_key:
            return f"{self.BASE_URL}/{self.api_key}/online-valid.csv.bz2"
        return self.PUBLIC_CSV_URL

    @property
    def user_agent(self) -> str:
        """PhishTank requires a specific user-agent format."""
        return "phishtank/RND1"

    @property
    def timeout(self) -> int:
        """PhishTank can be slow, use longer timeout."""
        return 120

    async def parse_response(self, response: httpx.Response) -> list[ParsedEntry]:
        """Parse PhishTank CSV response."""
        entries: list[ParsedEntry] = []

        # Handle compressed response
        if self.feed_url.endswith(".bz2"):
            csv_content = bz2.decompress(response.content).decode("utf-8").strip()
        else:
            csv_content = response.text.strip()

        csv_reader = csv.DictReader(io.StringIO(csv_content))

        for row in csv_reader:
            entry = self._parse_row(row)
            if entry:
                entries.append(entry)

        return entries

    def _parse_row(self, row: dict[str, Any]) -> ParsedEntry | None:
        """Parse a single CSV row."""
        url = row.get("url", "").strip()
        phish_id = row.get("phish_id", "").strip()

        if not url or not phish_id:
            return None

        # Only process verified and online entries
        if (
            row.get("verified", "").lower() != "yes"
            or row.get("online", "").lower() != "yes"
        ):
            return None

        # Clean target field
        target_raw = row.get("target", "")
        target_clean = target_raw.replace('"', "").strip()

        # Parse timestamps
        feed_timestamp = None
        submission_time = row.get("submission_time", "")
        if submission_time:
            try:
                feed_timestamp = datetime.fromisoformat(
                    submission_time.replace("Z", "+00:00")
                )
            except ValueError:
                pass

        # Build tags
        tags = ["phishing", "phishtank", "verified", "online"]
        if target_clean:
            tags.append(f"target_{target_clean.lower().replace(' ', '_')}")

        return ParsedEntry(
            url=url,
            external_id=phish_id,
            threat_type="phishing",
            confidence=0.95,  # High confidence - verified by community
            severity="high",
            tags=tags,
            metadata={
                "phish_id": int(phish_id) if phish_id.isdigit() else phish_id,
                "submission_time": row.get("submission_time", ""),
                "verification_time": row.get("verification_time", ""),
                "target_company": target_clean,
                "phish_detail_url": row.get("phish_detail_url", ""),
                "community_verified": True,
                "currently_online": True,
            },
            feed_timestamp=feed_timestamp,
        )

