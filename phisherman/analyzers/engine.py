"""Analysis engine that orchestrates multiple analyzers."""

import asyncio
import logging

from phisherman.analyzers.blacklist_feeds import BlacklistFeedsAnalyzer
from phisherman.analyzers.dns_resolver import DnsResolverAnalyzer
from phisherman.analyzers.feeds_analyzer import FeedsAnalyzer
from phisherman.analyzers.protocol import AnalyzerProtocol, AnalyzerResult
from phisherman.analyzers.rdap_whois import RdapWhoisAnalyzer
from phisherman.analyzers.tls_probe import TlsProbeAnalyzer
from phisherman.analyzers.url_heuristics import UrlHeuristicsAnalyzer
from phisherman.analyzers.victim_analyzer import VictimAnalyzer

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """
    Orchestrates multiple analyzers to perform comprehensive URL analysis.

    The engine runs all enabled analyzers in parallel and aggregates
    their results for the scorer to process.
    """

    def __init__(self, enabled_analyzers: list[str] = None):
        """
        Initialize the analysis engine.

        Args:
            enabled_analyzers: List of analyzer names to enable.
                              If None, all analyzers are enabled.
        """
        self.enabled_analyzers = enabled_analyzers or [
            "feeds",  # Nueva integración con microservicio de feeds
            "dns_resolver",
            "rdap_whois",
            "blacklist_feeds",
            "url_heuristics",
            "victim_analyzer",  # New analyzer for victim classification
            "tls_probe",
        ]

        # Registry of available analyzers
        self._analyzer_registry: dict[str, type[AnalyzerProtocol]] = {
            "feeds": FeedsAnalyzer,  # Nueva integración con microservicio
            "dns_resolver": DnsResolverAnalyzer,
            "rdap_whois": RdapWhoisAnalyzer,
            "blacklist_feeds": BlacklistFeedsAnalyzer,
            "url_heuristics": UrlHeuristicsAnalyzer,
            "victim_analyzer": VictimAnalyzer,  # New analyzer
            "tls_probe": TlsProbeAnalyzer,
        }

        # Instantiate enabled analyzers
        self.analyzers: list[AnalyzerProtocol] = []
        for name in self.enabled_analyzers:
            if name in self._analyzer_registry:
                try:
                    analyzer_class = self._analyzer_registry[name]
                    analyzer = analyzer_class()
                    self.analyzers.append(analyzer)
                    logger.info(f"Enabled analyzer: {name}")
                except Exception as e:
                    logger.error(f"Failed to initialize analyzer {name}: {e}")
            else:
                logger.warning(f"Unknown analyzer: {name}")

    async def analyze(self, url: str) -> list[AnalyzerResult]:
        """
        Run all enabled analyzers against a URL.

        Args:
            url: The URL to analyze

        Returns:
            List of analyzer results
        """
        logger.info(f"Starting analysis of URL: {url}")

        # Run all analyzers in parallel
        tasks = [analyzer.analyze(url) for analyzer in self.analyzers]

        # Wait for all analyzers to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results and handle exceptions
        analyzer_results: list[AnalyzerResult] = []
        for i, result in enumerate(results):
            analyzer = self.analyzers[i]

            if isinstance(result, Exception):
                # Create error result for failed analyzer
                logger.error(f"Analyzer {analyzer.name} failed: {result}")
                error_result = AnalyzerResult(
                    analyzer_name=analyzer.name,
                    risk_score=0.0,
                    confidence=0.0,
                    labels=["analyzer_error"],
                    evidence={"error": str(result)},
                    execution_time_ms=0.0,
                    error=str(result),
                )
                analyzer_results.append(error_result)
            else:
                analyzer_results.append(result)

        # Log summary
        successful = len([r for r in analyzer_results if r.error is None])
        failed = len(analyzer_results) - successful

        logger.info(
            f"Analysis complete for {url}: {successful} successful, {failed} failed"
        )

        return analyzer_results

    def get_analyzer_info(self) -> dict[str, dict]:
        """Get information about all enabled analyzers."""
        return {
            analyzer.name: {
                "version": analyzer.version,
                "weight": analyzer.weight,
                "enabled": True,
            }
            for analyzer in self.analyzers
        }
