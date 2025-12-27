"""Base class for feed parsers."""

import hashlib
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from phisherman.feeds.models import ParsedEntry

logger = logging.getLogger(__name__)


class BaseFeedParser(ABC):
    """
    Abstract base class for threat intelligence feed parsers.

    All feed parsers should inherit from this class and implement
    the required abstract methods.
    """

    def __init__(self, api_key: str | None = None):
        """
        Initialize the parser.

        Args:
            api_key: Optional API key for authenticated access.
        """
        self.api_key = api_key

    @property
    @abstractmethod
    def feed_name(self) -> str:
        """Unique identifier for this feed."""
        ...

    @property
    @abstractmethod
    def feed_url(self) -> str:
        """URL to fetch the feed data from."""
        ...

    @property
    def user_agent(self) -> str:
        """User-Agent string for HTTP requests."""
        return "Phisherman/1.0 (+https://github.com/phisherman)"

    @property
    def timeout(self) -> int:
        """Request timeout in seconds."""
        return 60

    @abstractmethod
    async def parse_response(self, response: httpx.Response) -> list[ParsedEntry]:
        """
        Parse the feed response and extract entries.

        Args:
            response: HTTP response from the feed.

        Returns:
            List of parsed entries.
        """
        ...

    async def fetch_and_parse(self, client: httpx.AsyncClient) -> list[ParsedEntry]:
        """
        Fetch the feed and parse its contents.

        Args:
            client: Async HTTP client to use for the request.

        Returns:
            List of parsed entries.

        Raises:
            httpx.HTTPError: If the request fails.
        """
        logger.info(f"Fetching feed: {self.feed_name} from {self.feed_url}")

        headers = {"User-Agent": self.user_agent}
        response = await client.get(
            self.feed_url,
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()

        entries = await self.parse_response(response)
        logger.info(f"Parsed {len(entries)} entries from {self.feed_name}")

        return entries

    @staticmethod
    def generate_checksum(feed_name: str, url: str, extra: str = "") -> str:
        """
        Generate a unique checksum for deduplication.

        Args:
            feed_name: Name of the feed.
            url: URL of the threat indicator.
            extra: Optional extra data to include.

        Returns:
            SHA256 hash string.
        """
        entry_str = f"{feed_name}:{url}:{extra}"
        return hashlib.sha256(entry_str.encode()).hexdigest()

    def get_headers(self) -> dict[str, str]:
        """Get HTTP headers for the request."""
        return {"User-Agent": self.user_agent}

