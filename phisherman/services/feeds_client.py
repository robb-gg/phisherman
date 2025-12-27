"""Client for communication with the feeds microservice."""

import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from phisherman.config import settings

logger = logging.getLogger(__name__)


class FeedsClient:
    """
    Client for the feeds microservice with connection pooling.

    Uses a shared HTTP client instance for better performance
    and connection reuse.
    """

    _client: httpx.AsyncClient | None = None

    def __init__(self):
        self.base_url = settings.feeds_service_url.rstrip("/")
        self.timeout = 30
        self.headers = {
            "User-Agent": "Phisherman-API/1.0",
            "X-Internal-Service-Token": settings.secret_key,
        }

    @classmethod
    async def get_client(cls) -> httpx.AsyncClient:
        """
        Get or create the shared HTTP client.

        Returns:
            Shared async HTTP client with connection pooling.
        """
        if cls._client is None or cls._client.is_closed:
            cls._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                ),
                headers={"User-Agent": "Phisherman-API/1.0"},
            )
        return cls._client

    @classmethod
    async def close(cls) -> None:
        """Close the shared HTTP client."""
        if cls._client is not None:
            await cls._client.aclose()
            cls._client = None
            logger.info("FeedsClient HTTP client closed")

    async def lookup_url(self, url: str, normalize: bool = True) -> dict[str, Any]:
        """
        Look up if a URL is cataloged as a threat.

        Args:
            url: URL to check.
            normalize: Whether to normalize the URL.

        Returns:
            Dict with lookup information or empty response if not a threat.
        """
        try:
            client = await self.get_client()
            response = await client.post(
                f"{self.base_url}/feeds/v1/lookup",
                json={"url": url, "normalize": normalize},
                headers=self.headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.debug(f"URL not found in feeds: {url}")
                return self._empty_response(url)
            else:
                logger.error(
                    f"Feeds service HTTP error {e.response.status_code}: "
                    f"{e.response.text}"
                )
                raise

        except httpx.TimeoutException:
            logger.error(f"Feeds service timeout for URL: {url}")
            raise Exception("Feeds service timeout") from None

        except Exception as e:
            logger.error(f"Feeds service error: {e}")
            raise

    async def bulk_lookup_urls(
        self,
        urls: list[str],
        normalize: bool = True,
    ) -> dict[str, Any]:
        """
        Bulk lookup for multiple URLs.

        Args:
            urls: List of URLs to check.
            normalize: Whether to normalize URLs.

        Returns:
            Dict with bulk lookup results.
        """
        try:
            client = await self.get_client()
            response = await client.post(
                f"{self.base_url}/feeds/v1/bulk-lookup",
                json={"urls": urls, "normalize": normalize},
                headers=self.headers,
                timeout=60,  # Longer timeout for bulk
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error(f"Bulk lookup error: {e}")
            raise

    async def get_feeds_stats(self) -> dict[str, Any]:
        """Get feeds statistics."""
        try:
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/feeds/v1/stats",
                headers=self.headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error(f"Error getting feeds stats: {e}")
            raise

    async def refresh_feed(self, feed_name: str) -> dict[str, Any]:
        """
        Trigger manual refresh of a specific feed.

        Args:
            feed_name: Name of the feed to refresh.

        Returns:
            Dict with refresh result.
        """
        try:
            client = await self.get_client()
            response = await client.post(
                f"{self.base_url}/feeds/v1/refresh/{feed_name}",
                headers=self.headers,
                timeout=120,  # Refresh can take time
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error(f"Error refreshing feed {feed_name}: {e}")
            raise

    async def get_feeds_status(self) -> dict[str, Any]:
        """Get status of all feeds."""
        try:
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/feeds/v1/status",
                headers=self.headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error(f"Error getting feeds status: {e}")
            raise

    async def health_check(self) -> bool:
        """
        Check if the feeds microservice is available.

        Returns:
            True if service is healthy, False otherwise.
        """
        try:
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/feeds/v1/health",
                headers=self.headers,
                timeout=5,
            )
            return response.status_code == 200

        except Exception as e:
            logger.warning(f"Feeds service health check failed: {e}")
            return False

    def _empty_response(self, url: str) -> dict[str, Any]:
        """Create empty response when no matches found."""
        return {
            "url": url,
            "normalized_url": None,
            "is_threat": False,
            "matches": [],
            "total_matches": 0,
            "last_checked": datetime.now(UTC).isoformat(),
        }


# Global client instance
feeds_client = FeedsClient()
