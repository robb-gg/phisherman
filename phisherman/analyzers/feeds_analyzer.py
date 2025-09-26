"""Analyzer que integra el microservicio de feeds."""

import asyncio
import logging
from typing import Any

from phisherman.services.feeds_client import feeds_client

from .protocol import AnalyzerProtocol

logger = logging.getLogger(__name__)


class FeedsAnalyzer(AnalyzerProtocol):
    """
    Analyzer que consulta el microservicio de feeds para threat intelligence.

    Este analyzer actúa como puente entre el sistema de análisis principal
    y el microservicio de feeds, proporcionando acceso rápido a todas las
    fuentes de threat intelligence disponibles.
    """

    def __init__(self):
        self.name = "feeds"
        self.timeout = 10

    async def analyze(self, url: str, domain: str, **kwargs) -> dict[str, Any]:
        """
        Analizar URL consultando el microservicio de feeds.
        """
        try:
            # Verificar health del servicio de feeds
            service_healthy = await feeds_client.health_check()
            if not service_healthy:
                logger.warning("Feeds service is not healthy, skipping feeds analysis")
                return self._create_error_result("Feeds service unavailable")

            # Consultar feeds
            feeds_result = await asyncio.wait_for(
                feeds_client.lookup_url(url, normalize=True), timeout=self.timeout
            )

            # Procesar resultado
            is_threat = feeds_result.get("is_threat", False)
            matches = feeds_result.get("matches", [])

            if not is_threat:
                return self._create_clean_result(feeds_result)

            # Analizar matches para determinar score y clasificación
            max_confidence = 0
            threat_types = set()
            severities = set()
            sources = set()

            for match in matches:
                confidence = match.get("confidence", 0)
                if confidence > max_confidence:
                    max_confidence = confidence

                threat_types.add(match.get("threat_type", "unknown"))
                severities.add(match.get("severity", "medium"))
                sources.add(match.get("source", "unknown"))

            # Calcular score final basado en confianza y número de fuentes
            base_score = max_confidence * 0.7  # Base del score más alto
            source_bonus = min(len(sources) * 0.1, 0.2)  # Bonus por múltiples fuentes
            final_score = min(base_score + source_bonus, 1.0)

            # Determinar clasificación principal
            primary_threat = self._determine_primary_threat(threat_types)
            primary_severity = self._determine_primary_severity(severities)

            return {
                "analyzer": self.name,
                "url": url,
                "domain": domain,
                "is_malicious": True,
                "confidence": final_score,
                "threat_type": primary_threat,
                "severity": primary_severity,
                "sources": list(sources),
                "total_matches": len(matches),
                "feeds_data": {
                    "original_result": feeds_result,
                    "threat_types": list(threat_types),
                    "severities": list(severities),
                    "max_source_confidence": max_confidence,
                },
                "details": {
                    "matched_in_feeds": True,
                    "feed_sources": list(sources),
                    "threat_classification": primary_threat,
                    "severity_level": primary_severity,
                    "detection_count": len(matches),
                },
            }

        except TimeoutError:
            logger.error(f"Feeds analyzer timeout for URL: {url}")
            return self._create_error_result("Analysis timeout")

        except Exception as e:
            logger.error(f"Feeds analyzer error for URL {url}: {e}")
            return self._create_error_result(f"Analysis error: {str(e)}")

    def _create_clean_result(self, feeds_result: dict[str, Any]) -> dict[str, Any]:
        """Crear resultado para URL limpia."""
        return {
            "analyzer": self.name,
            "url": feeds_result.get("url", ""),
            "domain": "",  # Se llena externamente
            "is_malicious": False,
            "confidence": 0.0,
            "threat_type": "clean",
            "severity": "none",
            "sources": [],
            "total_matches": 0,
            "feeds_data": {
                "original_result": feeds_result,
                "checked_at": feeds_result.get("last_checked"),
            },
            "details": {
                "matched_in_feeds": False,
                "status": "clean",
                "normalized_url": feeds_result.get("normalized_url"),
            },
        }

    def _create_error_result(self, error_msg: str) -> dict[str, Any]:
        """Crear resultado de error."""
        return {
            "analyzer": self.name,
            "is_malicious": False,
            "confidence": 0.0,
            "threat_type": "error",
            "severity": "none",
            "error": error_msg,
            "details": {"status": "error", "error_message": error_msg},
        }

    def _determine_primary_threat(self, threat_types: set) -> str:
        """
        Determinar el tipo de amenaza principal basado en prioridad.
        """
        # Orden de prioridad
        priority_order = ["malware", "phishing", "suspicious", "unknown"]

        for threat_type in priority_order:
            if threat_type in threat_types:
                return threat_type

        return "unknown"

    def _determine_primary_severity(self, severities: set) -> str:
        """
        Determinar la severidad principal basada en el nivel más alto.
        """
        # Orden de prioridad (más alto a más bajo)
        severity_priority = ["critical", "high", "medium", "low", "info"]

        for severity in severity_priority:
            if severity in severities:
                return severity

        return "medium"

    async def get_analyzer_info(self) -> dict[str, Any]:
        """Información sobre el analyzer."""
        try:
            feeds_status = await feeds_client.get_feeds_status()
            return {
                "name": self.name,
                "description": "Threat intelligence feeds analyzer",
                "version": "1.0.0",
                "feeds_service_status": "healthy",
                "available_feeds": [
                    feed["name"]
                    for feed in feeds_status.get("feeds", [])
                    if feed.get("status") == "active"
                ],
                "total_indicators": feeds_status.get("total_entries", 0),
            }
        except Exception as e:
            return {
                "name": self.name,
                "description": "Threat intelligence feeds analyzer",
                "version": "1.0.0",
                "feeds_service_status": "error",
                "error": str(e),
            }
