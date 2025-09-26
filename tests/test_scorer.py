"""Tests for scoring system."""

import pytest

from phisherman.analyzers.protocol import AnalyzerResult
from phisherman.scorer.linear_scorer import LinearScorer


class TestLinearScorer:
    """Tests for linear weighted scorer."""

    @pytest.fixture
    def scorer(self):
        return LinearScorer()

    @pytest.fixture
    def sample_results(self):
        """Sample analyzer results for testing."""
        return [
            AnalyzerResult(
                analyzer_name="dns_resolver",
                risk_score=30.0,
                confidence=0.8,
                labels=["suspicious_nameserver"],
                evidence={"ns_records": ["ns1.suspicious.com"]},
                execution_time_ms=150.0,
            ),
            AnalyzerResult(
                analyzer_name="url_heuristics",
                risk_score=60.0,
                confidence=0.6,
                labels=["long_domain", "suspicious_keyword"],
                evidence={"domain_length": 75, "suspicious_keyword": "paypal"},
                execution_time_ms=50.0,
            ),
            AnalyzerResult(
                analyzer_name="blacklist_feeds",
                risk_score=90.0,
                confidence=0.95,
                labels=["url_blacklisted", "threat_phishing"],
                evidence={
                    "matches": [{"source": "phishtank", "threat_type": "phishing"}]
                },
                execution_time_ms=25.0,
            ),
        ]

    def test_calculate_score_with_results(self, scorer, sample_results):
        """Test score calculation with multiple analyzer results."""
        result = scorer.calculate_score(sample_results)

        assert result.method_used == "linear_scorer"
        assert 0 <= result.final_score <= 100
        assert 0 <= result.confidence <= 1
        assert len(result.analyzer_weights) == 3

        # Should be weighted towards blacklist feeds (highest weight and score)
        assert result.final_score > 60  # Should be fairly high due to blacklist match

    def test_calculate_score_empty_results(self, scorer):
        """Test score calculation with no results."""
        result = scorer.calculate_score([])

        assert result.final_score == 0.0
        assert result.confidence == 0.0
        assert "error" in result.details

    def test_calculate_score_all_failed(self, scorer):
        """Test score calculation when all analyzers failed."""
        failed_results = [
            AnalyzerResult(
                analyzer_name="dns_resolver",
                risk_score=0.0,
                confidence=0.0,
                labels=["analysis_error"],
                evidence={"error": "DNS timeout"},
                execution_time_ms=1000.0,
                error="DNS timeout",
            )
        ]

        result = scorer.calculate_score(failed_results)

        assert result.final_score == 0.0
        assert result.confidence == 0.0
        assert "All analyzers failed" in result.details["error"]

    def test_consensus_adjustments(self, scorer):
        """Test consensus-based score adjustments."""
        # High consensus on high risk
        high_risk_results = [
            AnalyzerResult("analyzer1", 80.0, 0.8, [], {}, 0),
            AnalyzerResult("analyzer2", 85.0, 0.7, [], {}, 0),
            AnalyzerResult("analyzer3", 90.0, 0.9, [], {}, 0),
        ]

        result = scorer.calculate_score(high_risk_results)

        # Should apply consensus bonus
        assert "consensus_adjustments" in result.details
        adjustments = result.details["consensus_adjustments"]
        assert adjustments.get("consensus_bonus", 0) > 0
