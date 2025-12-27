"""Analyzer that integrates with the feeds microservice."""

import asyncio
import logging

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer
from phisherman.services.feeds_client import feeds_client

logger = logging.getLogger(__name__)


class FeedsAnalyzer(BaseAnalyzer):
    """
    Analyzer that queries the feeds microservice for threat intelligence.

    This analyzer acts as a bridge between the main analysis system
    and the feeds microservice, providing quick access to all available
    threat intelligence sources.
    """

    def __init__(self):
        super().__init__(timeout=10, max_retries=2)

    @property
    def name(self) -> str:
        return "feeds"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def weight(self) -> float:
        return 1.5  # High weight for feed matches

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """
        Analyze URL by querying the feeds microservice.

        Args:
            url: URL to analyze.

        Returns:
            AnalyzerResult with feed lookup results.
        """
        try:
            # Check feeds service health
            service_healthy = await feeds_client.health_check()
            if not service_healthy:
                logger.warning("Feeds service is not healthy, skipping feeds analysis")
                return self._create_error_result("Feeds service unavailable")

            # Query feeds
            feeds_result = await asyncio.wait_for(
                feeds_client.lookup_url(url, normalize=True),
                timeout=self.timeout,
            )

            # Process result
            is_threat = feeds_result.get("is_threat", False)
            matches = feeds_result.get("matches", [])

            if not is_threat:
                return self._create_clean_result(url, feeds_result)

            # Analyze matches to determine score and classification
            return self._create_threat_result(url, matches, feeds_result)

        except TimeoutError:
            logger.error(f"Feeds analyzer timeout for URL: {url}")
            return self._create_error_result("Analysis timeout")

        except Exception as e:
            logger.error(f"Feeds analyzer error for URL {url}: {e}")
            return self._create_error_result(f"Analysis error: {str(e)}")

    def _create_clean_result(self, url: str, feeds_result: dict) -> AnalyzerResult:
        """Create result for clean URL (not in any feed)."""
        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=0.0,
            confidence=0.8,  # Confident it's not in feeds
            labels=["clean", "not_in_feeds"],
            evidence={
                "url": url,
                "matched_in_feeds": False,
                "feeds_checked": True,
                "normalized_url": feeds_result.get("normalized_url"),
                "last_checked": feeds_result.get("last_checked"),
            },
            execution_time_ms=0.0,
        )

    def _create_threat_result(
        self,
        url: str,
        matches: list[dict],
        feeds_result: dict,
    ) -> AnalyzerResult:
        """Create result for URL found in threat feeds."""
        max_confidence = 0.0
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

        # Calculate risk score based on confidence and number of sources
        # Base score from highest confidence match (scaled to 0-100)
        base_score = max_confidence * 70
        # Bonus for multiple sources (up to 20 points)
        source_bonus = min(len(sources) * 10, 20)
        # Additional 10 points for being in any feed
        feed_bonus = 10

        risk_score = min(base_score + source_bonus + feed_bonus, 100.0)

        # Determine primary threat type and severity
        primary_threat = self._determine_primary_threat(threat_types)
        primary_severity = self._determine_primary_severity(severities)

        # Build labels
        labels = [
            "in_threat_feeds",
            f"threat_{primary_threat}",
            f"severity_{primary_severity}",
        ]
        for source in sources:
            labels.append(f"source_{source}")

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            confidence=max_confidence,
            labels=labels,
            evidence={
                "url": url,
                "matched_in_feeds": True,
                "total_matches": len(matches),
                "sources": list(sources),
                "threat_types": list(threat_types),
                "severities": list(severities),
                "max_source_confidence": max_confidence,
                "primary_threat": primary_threat,
                "primary_severity": primary_severity,
                "feeds_data": feeds_result,
            },
            execution_time_ms=0.0,
        )

    def _create_error_result(self, error_msg: str) -> AnalyzerResult:
        """Create result for analysis error."""
        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=0.0,
            confidence=0.0,
            labels=["feeds_error"],
            evidence={"error": error_msg},
            execution_time_ms=0.0,
            error=error_msg,
        )

    @staticmethod
    def _determine_primary_threat(threat_types: set) -> str:
        """Determine primary threat type based on priority."""
        priority_order = ["malware", "phishing", "suspicious", "unknown"]

        for threat_type in priority_order:
            if threat_type in threat_types:
                return threat_type

        return "unknown"

    @staticmethod
    def _determine_primary_severity(severities: set) -> str:
        """Determine primary severity based on highest level."""
        severity_priority = ["critical", "high", "medium", "low", "info"]

        for severity in severity_priority:
            if severity in severities:
                return severity

        return "medium"
