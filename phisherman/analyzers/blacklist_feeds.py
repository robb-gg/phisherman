"""Blacklist feeds analyzer for known malicious URLs and domains."""

import logging
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from phisherman.analyzers.protocol import AnalyzerResult, BaseAnalyzer
from phisherman.datastore.database import AsyncSessionLocal
from phisherman.datastore.models import Indicator

logger = logging.getLogger(__name__)


class BlacklistFeedsAnalyzer(BaseAnalyzer):
    """
    Checks URLs and domains against blacklist feeds from threat intelligence sources.

    Supported feeds:
    - PhishTank (phishing URLs)
    - OpenPhish (phishing URLs)
    - URLHaus (malware URLs)
    - Custom blacklists

    This analyzer queries the local database where feed data is stored
    by background Celery tasks.
    """

    @property
    def name(self) -> str:
        return "blacklist_feeds"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def weight(self) -> float:
        return 0.9  # High weight for known bad indicators

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Check URL against blacklist feeds."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        normalized_url = url.lower()

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        risk_score = 0.0
        labels: list[str] = []
        evidence: dict[str, Any] = {
            "url": url,
            "domain": domain,
            "matches": [],
        }

        async with AsyncSessionLocal() as session:
            # Check for exact URL matches
            url_matches = await self._check_url_indicators(session, normalized_url)
            if url_matches:
                evidence["matches"].extend(url_matches)
                risk_score += self._calculate_url_match_score(url_matches, labels)

            # Check for domain matches
            domain_matches = await self._check_domain_indicators(session, domain)
            if domain_matches:
                evidence["matches"].extend(domain_matches)
                risk_score += self._calculate_domain_match_score(domain_matches, labels)

            # Check for subdomain patterns (wildcards)
            if "." in domain:
                parent_domains = self._get_parent_domains(domain)
                for parent_domain in parent_domains:
                    parent_matches = await self._check_domain_indicators(
                        session, parent_domain
                    )
                    if parent_matches:
                        evidence["matches"].extend(parent_matches)
                        # Subdomain matches get slightly lower score
                        risk_score += (
                            self._calculate_domain_match_score(parent_matches, labels)
                            * 0.7
                        )

        # Cap the risk score
        risk_score = min(risk_score, 100.0)

        # High confidence if we found matches
        confidence = 0.95 if evidence["matches"] else 0.5

        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=risk_score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            execution_time_ms=0.0,
        )

    async def _check_url_indicators(
        self, session: AsyncSession, url: str
    ) -> list[dict[str, Any]]:
        """Check for exact URL matches in indicators."""
        try:
            stmt = select(Indicator).where(
                Indicator.indicator_type == "url",
                Indicator.indicator_value == url,
                Indicator.is_active == True,  # noqa: E712
            )
            result = await session.execute(stmt)
            indicators = result.scalars().all()

            matches = []
            for indicator in indicators:
                matches.append(
                    {
                        "type": "url",
                        "value": indicator.indicator_value,
                        "threat_type": indicator.threat_type,
                        "severity": indicator.severity,
                        "confidence": indicator.confidence,
                        "source": indicator.source,
                        "tags": indicator.tags,
                        "first_seen": indicator.first_seen.isoformat(),
                        "last_seen": indicator.last_seen.isoformat(),
                    }
                )

            return matches

        except Exception as e:
            logger.error(f"Error checking URL indicators: {e}")
            return []

    async def _check_domain_indicators(
        self, session: AsyncSession, domain: str
    ) -> list[dict[str, Any]]:
        """Check for domain matches in indicators."""
        try:
            stmt = select(Indicator).where(
                Indicator.indicator_type == "domain",
                Indicator.indicator_value == domain,
                Indicator.is_active == True,  # noqa: E712
            )
            result = await session.execute(stmt)
            indicators = result.scalars().all()

            matches = []
            for indicator in indicators:
                matches.append(
                    {
                        "type": "domain",
                        "value": indicator.indicator_value,
                        "threat_type": indicator.threat_type,
                        "severity": indicator.severity,
                        "confidence": indicator.confidence,
                        "source": indicator.source,
                        "tags": indicator.tags,
                        "first_seen": indicator.first_seen.isoformat(),
                        "last_seen": indicator.last_seen.isoformat(),
                    }
                )

            return matches

        except Exception as e:
            logger.error(f"Error checking domain indicators: {e}")
            return []

    def _get_parent_domains(self, domain: str) -> list[str]:
        """Get parent domains for subdomain checking."""
        parts = domain.split(".")
        parent_domains = []

        # Generate parent domains: sub.example.com -> example.com, com
        for i in range(1, len(parts)):
            parent_domain = ".".join(parts[i:])
            parent_domains.append(parent_domain)

        return parent_domains

    def _calculate_url_match_score(
        self, matches: list[dict[str, Any]], labels: list[str]
    ) -> float:
        """Calculate risk score based on URL matches."""
        if not matches:
            return 0.0

        max_score = 0.0
        threat_types = set()
        sources = set()

        for match in matches:
            # Base score by severity
            severity_scores = {
                "critical": 90,
                "high": 75,
                "medium": 50,
                "low": 25,
            }

            base_score = severity_scores.get(match["severity"].lower(), 40)

            # Adjust by confidence
            confidence = match["confidence"]
            adjusted_score = base_score * confidence

            max_score = max(max_score, adjusted_score)

            threat_types.add(match["threat_type"])
            sources.add(match["source"])

        # Add labels
        labels.append("url_blacklisted")
        for threat_type in threat_types:
            labels.append(f"threat_{threat_type.lower()}")
        for source in sources:
            labels.append(f"source_{source.lower()}")

        return max_score

    def _calculate_domain_match_score(
        self, matches: list[dict[str, Any]], labels: list[str]
    ) -> float:
        """Calculate risk score based on domain matches."""
        if not matches:
            return 0.0

        max_score = 0.0
        threat_types = set()
        sources = set()

        for match in matches:
            # Domain matches get slightly lower base scores than URL matches
            severity_scores = {
                "critical": 70,
                "high": 55,
                "medium": 35,
                "low": 15,
            }

            base_score = severity_scores.get(match["severity"].lower(), 30)

            # Adjust by confidence
            confidence = match["confidence"]
            adjusted_score = base_score * confidence

            max_score = max(max_score, adjusted_score)

            threat_types.add(match["threat_type"])
            sources.add(match["source"])

        # Add labels
        labels.append("domain_blacklisted")
        for threat_type in threat_types:
            labels.append(f"threat_{threat_type.lower()}")
        for source in sources:
            labels.append(f"source_{source.lower()}")

        return max_score
