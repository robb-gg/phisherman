"""OpenPhish feed parser."""

import logging

import httpx

from phisherman.feeds.models import ParsedEntry
from phisherman.feeds.parsers.base import BaseFeedParser

logger = logging.getLogger(__name__)


class OpenPhishParser(BaseFeedParser):
    """
    Parser for OpenPhish phishing URL feed.

    OpenPhish provides a simple text file with one URL per line.
    """

    FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

    @property
    def feed_name(self) -> str:
        return "openphish"

    @property
    def feed_url(self) -> str:
        return self.FEED_URL

    @property
    def timeout(self) -> int:
        return 60

    async def parse_response(self, response: httpx.Response) -> list[ParsedEntry]:
        """Parse OpenPhish text response."""
        entries: list[ParsedEntry] = []

        lines = response.text.strip().split("\n")

        for line in lines:
            url = line.strip()

            # Skip empty lines and comments
            if not url or url.startswith("#"):
                continue

            entries.append(
                ParsedEntry(
                    url=url,
                    external_id=None,
                    threat_type="phishing",
                    confidence=0.85,  # Good confidence
                    severity="high",
                    tags=["phishing", "openphish"],
                    metadata={"url": url},
                )
            )

        return entries
