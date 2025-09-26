"""Integración con Google Safe Browsing API."""

import hashlib
import logging
import os

# Importar desde el proyecto principal
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select

sys.path.append(os.path.join(os.path.dirname(__file__), "../../"))

from phisherman.datastore.database import AsyncSessionLocal
from phisherman.datastore.models import FeedEntry, Indicator

from ..config import feeds_settings

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingService:
    """Servicio para integración con Google Safe Browsing API."""

    def __init__(self):
        self.api_key = feeds_settings.google_safebrowsing_api_key
        self.base_url = "https://safebrowsing.googleapis.com"
        self.client_id = "phisherman"
        self.client_version = "1.0.0"

    async def lookup_urls(self, urls: list[str]) -> dict[str, Any]:
        """
        Consultar URLs usando Google Safe Browsing Lookup API.

        https://developers.google.com/safe-browsing/v4/lookup-api
        """
        if not self.api_key:
            raise ValueError("Google Safe Browsing API key not configured")

        if not urls:
            return {"matches": []}

        # Preparar request para la API
        threat_types = [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
        ]

        platform_types = ["ANY_PLATFORM"]
        threat_entry_types = ["URL"]

        threat_entries = [
            {"url": url} for url in urls[:500]
        ]  # Máximo 500 URLs por request

        payload = {
            "client": {
                "clientId": self.client_id,
                "clientVersion": self.client_version,
            },
            "threatInfo": {
                "threatTypes": threat_types,
                "platformTypes": platform_types,
                "threatEntryTypes": threat_entry_types,
                "threatEntries": threat_entries,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{self.base_url}/v4/threatMatches:find",
                    params={"key": self.api_key},
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": feeds_settings.user_agent,
                    },
                )
                response.raise_for_status()

                return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(
                f"Safe Browsing API HTTP error: {e.response.status_code} - {e.response.text}"
            )
            raise e
        except Exception as e:
            logger.error(f"Safe Browsing API error: {e}")
            raise e

    async def update_threat_lists(self) -> dict[str, Any]:
        """
        Actualizar listas de amenazas usando Update API.

        https://developers.google.com/safe-browsing/v4/update-api
        """
        if not self.api_key:
            logger.warning(
                "Google Safe Browsing API key not configured, skipping update"
            )
            return {"status": "skipped", "reason": "no_api_key"}

        # Por simplicidad, por ahora solo implementamos lookup
        # El Update API es más complejo y requiere manejo de estado
        logger.info("Safe Browsing Update API not implemented, using lookup only")
        return {"status": "not_implemented"}

    async def refresh_threats(self) -> dict[str, Any]:
        """
        Refresh usando URLs conocidas del feed para verificar si aún son amenazas.

        Esta función toma una muestra de URLs de la base de datos y las verifica
        con Safe Browsing para mantener actualizado el estado.
        """
        try:
            async with AsyncSessionLocal() as db:
                # Obtener muestra de URLs recientes (últimos 7 días)
                cutoff_date = datetime.now(UTC) - timedelta(days=7)
                stmt = (
                    select(Indicator.indicator_value)
                    .where(Indicator.indicator_type == "url")
                    .where(Indicator.last_seen > cutoff_date)
                    .limit(100)
                )  # Máximo 100 URLs por verificación

                result = await db.execute(stmt)
                existing_urls = [row[0] for row in result.all()]

                if not existing_urls:
                    logger.info("No URLs found for Safe Browsing verification")
                    return {"status": "success", "entries_processed": 0}

                # Consultar con Safe Browsing
                sb_result = await self.lookup_urls(existing_urls)
                matches = sb_result.get("matches", [])

                entries_processed = 0

                # Procesar matches
                for match in matches:
                    threat_url = match["threat"]["url"]
                    threat_type = match["threatType"]
                    platform_type = match["platformType"]

                    # Mapear tipos de amenaza de Safe Browsing a nuestro sistema
                    our_threat_type = self._map_threat_type(threat_type)
                    severity = self._get_severity(threat_type)

                    # Crear checksum para deduplicación
                    entry_str = f"safebrowsing:{threat_url}"
                    checksum = hashlib.sha256(entry_str.encode()).hexdigest()

                    # Verificar si ya existe
                    stmt = select(FeedEntry).where(FeedEntry.checksum == checksum)
                    result = await db.execute(stmt)
                    existing = result.scalar_one_or_none()

                    if existing:
                        # Actualizar timestamp
                        existing.feed_timestamp = datetime.now(UTC)
                    else:
                        # Crear nueva entrada
                        feed_entry = FeedEntry(
                            feed_name="safebrowsing",
                            feed_url=f"{self.base_url}/v4/threatMatches:find",
                            raw_data=match,
                            checksum=checksum,
                            feed_timestamp=datetime.now(UTC),
                        )
                        db.add(feed_entry)

                    # Actualizar o crear indicador
                    stmt = (
                        select(Indicator)
                        .where(Indicator.indicator_value == threat_url.lower())
                        .where(Indicator.source == "safebrowsing")
                    )
                    result = await db.execute(stmt)
                    existing_indicator = result.scalar_one_or_none()

                    if existing_indicator:
                        # Actualizar existente
                        existing_indicator.last_seen = datetime.now(UTC)
                        existing_indicator.extra_data = match
                    else:
                        # Crear nuevo indicador
                        indicator = Indicator(
                            indicator_type="url",
                            indicator_value=threat_url.lower(),
                            threat_type=our_threat_type,
                            severity=severity,
                            confidence=0.95,  # Safe Browsing tiene alta confianza
                            source="safebrowsing",
                            source_url=f"{self.base_url}/v4/threatMatches:find",
                            tags=["safebrowsing", threat_type.lower()],
                            extra_data={
                                "threat_type": threat_type,
                                "platform_type": platform_type,
                                "cache_duration": match.get("cacheDuration"),
                            },
                            first_seen=datetime.now(UTC),
                            last_seen=datetime.now(UTC),
                        )
                        db.add(indicator)

                    entries_processed += 1

                await db.commit()

                logger.info(
                    f"Safe Browsing refresh completed: {entries_processed} entries processed"
                )
                return {
                    "status": "success",
                    "entries_processed": entries_processed,
                    "urls_checked": len(existing_urls),
                    "matches_found": len(matches),
                }

        except Exception as e:
            logger.error(f"Safe Browsing refresh failed: {e}")
            return {"status": "error", "error": str(e)}

    def _map_threat_type(self, sb_threat_type: str) -> str:
        """Mapear tipos de amenaza de Safe Browsing a nuestro sistema."""
        mapping = {
            "MALWARE": "malware",
            "SOCIAL_ENGINEERING": "phishing",
            "UNWANTED_SOFTWARE": "malware",
            "POTENTIALLY_HARMFUL_APPLICATION": "suspicious",
        }
        return mapping.get(sb_threat_type, "suspicious")

    def _get_severity(self, sb_threat_type: str) -> str:
        """Obtener severidad basada en el tipo de amenaza."""
        high_severity = ["MALWARE", "SOCIAL_ENGINEERING"]
        if sb_threat_type in high_severity:
            return "high"
        else:
            return "medium"

    async def get_status(self) -> dict[str, Any]:
        """Obtener estado del servicio de Safe Browsing."""
        async with AsyncSessionLocal() as db:
            # Última actualización
            stmt = (
                select(FeedEntry)
                .where(FeedEntry.feed_name == "safebrowsing")
                .order_by(FeedEntry.feed_timestamp.desc())
                .limit(1)
            )

            result = await db.execute(stmt)
            last_entry = result.scalar_one_or_none()

            # Total de indicadores
            stmt = select(Indicator).where(Indicator.source == "safebrowsing")
            result = await db.execute(stmt)
            total_indicators = len(result.scalars().all())

            # Próximo refresh
            next_refresh = None
            if last_entry:
                next_refresh = last_entry.feed_timestamp + timedelta(
                    minutes=feeds_settings.safebrowsing_refresh_interval
                )

            status = "active" if self.api_key else "disabled"
            if not self.api_key:
                last_error = "API key not configured"
            else:
                last_error = None

            return {
                "name": "safebrowsing",
                "enabled": bool(self.api_key),
                "last_refresh": last_entry.feed_timestamp if last_entry else None,
                "next_refresh": next_refresh,
                "total_entries": total_indicators,
                "refresh_interval_minutes": feeds_settings.safebrowsing_refresh_interval,
                "status": status,
                "last_error": last_error,
            }
