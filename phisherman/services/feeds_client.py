"""Cliente para comunicación con el microservicio de feeds."""

import logging
from datetime import UTC
from typing import Any

import httpx

from phisherman.config import settings

logger = logging.getLogger(__name__)


class FeedsClient:
    """Cliente para el microservicio de feeds."""

    def __init__(self):
        self.base_url = settings.feeds_service_url.rstrip("/")
        self.timeout = 30
        self.headers = {
            "User-Agent": "Phisherman-API/1.0",
            "X-Internal-Service-Token": settings.secret_key,
        }

    async def lookup_url(self, url: str, normalize: bool = True) -> dict[str, Any]:
        """
        Consultar si una URL está catalogada como threat.

        Returns:
            Dict con información del lookup o None si no es threat
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/feeds/v1/lookup",
                    json={"url": url, "normalize": normalize},
                    headers=self.headers,
                )
                response.raise_for_status()
                return response.json()

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.debug(f"URL not found in feeds: {url}")
                return self._empty_response(url)
            else:
                logger.error(
                    f"Feeds service HTTP error {e.response.status_code}: {e.response.text}"
                )
                raise e
        except httpx.TimeoutException:
            logger.error(f"Feeds service timeout for URL: {url}")
            raise Exception("Feeds service timeout")
        except Exception as e:
            logger.error(f"Feeds service error: {e}")
            raise e

    async def bulk_lookup_urls(
        self, urls: list[str], normalize: bool = True
    ) -> dict[str, Any]:
        """
        Consulta masiva de URLs.
        """
        try:
            async with httpx.AsyncClient(timeout=60) as client:  # Más tiempo para bulk
                response = await client.post(
                    f"{self.base_url}/feeds/v1/bulk-lookup",
                    json={"urls": urls, "normalize": normalize},
                    headers=self.headers,
                )
                response.raise_for_status()
                return response.json()

        except Exception as e:
            logger.error(f"Bulk lookup error: {e}")
            raise e

    async def get_feeds_stats(self) -> dict[str, Any]:
        """
        Obtener estadísticas de los feeds.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/feeds/v1/stats", headers=self.headers
                )
                response.raise_for_status()
                return response.json()

        except Exception as e:
            logger.error(f"Error getting feeds stats: {e}")
            raise e

    async def refresh_feed(self, feed_name: str) -> dict[str, Any]:
        """
        Trigger manual refresh de un feed específico.
        """
        try:
            async with httpx.AsyncClient(
                timeout=120
            ) as client:  # Refresh puede tomar tiempo
                response = await client.post(
                    f"{self.base_url}/feeds/v1/refresh/{feed_name}",
                    headers=self.headers,
                )
                response.raise_for_status()
                return response.json()

        except Exception as e:
            logger.error(f"Error refreshing feed {feed_name}: {e}")
            raise e

    async def get_feeds_status(self) -> dict[str, Any]:
        """
        Obtener estado de todos los feeds.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/feeds/v1/status", headers=self.headers
                )
                response.raise_for_status()
                return response.json()

        except Exception as e:
            logger.error(f"Error getting feeds status: {e}")
            raise e

    async def health_check(self) -> bool:
        """
        Verificar si el microservicio de feeds está disponible.
        """
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(
                    f"{self.base_url}/feeds/v1/health", headers=self.headers
                )
                return response.status_code == 200

        except Exception as e:
            logger.warning(f"Feeds service health check failed: {e}")
            return False

    def _empty_response(self, url: str) -> dict[str, Any]:
        """
        Response vacía cuando no hay matches.
        """
        from datetime import datetime

        return {
            "url": url,
            "normalized_url": None,
            "is_threat": False,
            "matches": [],
            "total_matches": 0,
            "last_checked": datetime.now(UTC).isoformat(),
        }


# Instancia global del cliente
feeds_client = FeedsClient()
