"""Tests for URL analyzers."""

from unittest.mock import patch

import pytest

from phisherman.analyzers.blacklist_feeds import BlacklistFeedsAnalyzer
from phisherman.analyzers.dns_resolver import DnsResolverAnalyzer
from phisherman.analyzers.url_heuristics import UrlHeuristicsAnalyzer


class TestDnsResolverAnalyzer:
    """Tests for DNS resolver analyzer."""

    @pytest.fixture
    def analyzer(self):
        return DnsResolverAnalyzer()

    @pytest.mark.asyncio
    async def test_analyze_legitimate_domain(self, analyzer):
        """Test analysis of legitimate domain."""
        result = await analyzer.analyze("https://google.com")

        assert result.analyzer_name == "dns_resolver"
        assert 0 <= result.risk_score <= 100
        assert 0 <= result.confidence <= 1
        assert isinstance(result.labels, list)
        assert isinstance(result.evidence, dict)
        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_analyze_nonexistent_domain(self, analyzer):
        """Test analysis of non-existent domain."""
        result = await analyzer.analyze(
            "https://this-domain-should-not-exist-12345.com"
        )

        # Should handle DNS resolution failures gracefully
        assert result.analyzer_name == "dns_resolver"
        assert isinstance(result.risk_score, int | float)
        assert isinstance(result.evidence, dict)


class TestUrlHeuristicsAnalyzer:
    """Tests for URL heuristics analyzer."""

    @pytest.fixture
    def analyzer(self):
        return UrlHeuristicsAnalyzer()

    @pytest.mark.asyncio
    async def test_analyze_normal_url(self, analyzer):
        """Test analysis of normal URL."""
        result = await analyzer.analyze("https://example.com/page")

        assert result.analyzer_name == "url_heuristics"
        assert result.risk_score >= 0
        assert 0 <= result.confidence <= 1
        assert "features" in result.evidence

    @pytest.mark.asyncio
    async def test_analyze_suspicious_url(self, analyzer):
        """Test analysis of suspicious URL patterns."""
        # Long domain with many subdomains
        suspicious_url = "https://www.paypal.security.update.verify.account.suspicious-domain-12345.tk/login"
        result = await analyzer.analyze(suspicious_url)

        assert result.risk_score > 0
        assert any("suspicious" in label for label in result.labels)

    @pytest.mark.asyncio
    async def test_analyze_punycode_domain(self, analyzer):
        """Test analysis of punycode domain."""
        # This is a real punycode domain (xn--nxasmq6b = 중국)
        result = await analyzer.analyze("https://xn--nxasmq6b.com")

        assert result.analyzer_name == "url_heuristics"
        if "punycode_domain" in result.labels:
            assert result.risk_score > 10  # Should increase risk score


class TestBlacklistFeedsAnalyzer:
    """Tests for blacklist feeds analyzer."""

    @pytest.fixture
    def analyzer(self):
        return BlacklistFeedsAnalyzer()

    @pytest.mark.asyncio
    async def test_analyze_with_no_matches(self, analyzer):
        """Test analysis when no blacklist matches found."""
        with patch(
            "phisherman.analyzers.blacklist_feeds.AsyncSessionLocal"
        ) as mock_session:
            # Mock database session that returns no matches
            mock_session.return_value.__aenter__.return_value.execute.return_value.scalars.return_value.all.return_value = (
                []
            )

            result = await analyzer.analyze("https://legitimate-site.com")

            assert result.analyzer_name == "blacklist_feeds"
            assert result.risk_score == 0.0
            assert result.evidence["matches"] == []
