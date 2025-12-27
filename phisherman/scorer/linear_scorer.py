"""Linear weighted scorer for combining analyzer results."""

import logging
import os

import yaml

from phisherman.analyzers.protocol import AnalyzerResult
from phisherman.scorer.protocol import BaseScorer, ScoringResult

logger = logging.getLogger(__name__)


class LinearScorer(BaseScorer):
    """
    Linear weighted scorer that combines analyzer results using configurable weights.

    The final score is calculated as a weighted SUM of analyzer scores (capped at 100),
    with additional adjustments based on confidence levels and consensus.

    Score = min(100, Σ(analyzer_score * weight * confidence))
    """

    def __init__(self, config_path: str = None):
        # Default weights for analyzers (multipliers for their scores)
        self.default_weights = {
            "blacklist_feeds": 1.5,  # Highest weight - known bad indicators are critical
            "rdap_whois": 1.2,  # High weight - registration data is very reliable
            "dns_resolver": 0.8,  # Good weight for DNS signals
            "url_heuristics": 0.9,  # Good weight for URL pattern detection
            "tls_probe": 0.7,  # Moderate weight for TLS signals
            "victim_analyzer": 0.8,  # Good weight for victim classification
            "saas_detector_enhanced": 0.6,  # Moderate weight
            "web_content_analyzer": 0.9,  # Good weight for content analysis
        }

        # Risk thresholds
        self.thresholds = {
            "low": 25.0,
            "medium": 50.0,
            "high": 75.0,
        }

        super().__init__(config_path)

    @property
    def name(self) -> str:
        return "linear_scorer"

    @property
    def version(self) -> str:
        return "1.0.0"

    def _load_config(self) -> None:
        """Load scorer configuration from YAML file."""
        if not self.config_path:
            # Look for config in default locations
            config_paths = [
                "configs/weights.yaml",
                "/app/configs/weights.yaml",
                os.path.join(os.path.dirname(__file__), "../configs/weights.yaml"),
            ]

            for path in config_paths:
                if os.path.exists(path):
                    self.config_path = path
                    break

        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path) as f:
                    config = yaml.safe_load(f)

                # Update weights from config
                scorer_config = config.get("scorers", {}).get("linear", {})
                if "weights" in scorer_config:
                    self.default_weights.update(scorer_config["weights"])

                if "thresholds" in scorer_config:
                    self.thresholds.update(scorer_config["thresholds"])

                logger.info(f"Loaded scorer config from {self.config_path}")

            except Exception as e:
                logger.warning(f"Failed to load scorer config: {e}, using defaults")
        else:
            logger.info("Using default scorer configuration")

    def calculate_score(self, analyzer_results: list[AnalyzerResult]) -> ScoringResult:
        """Calculate weighted linear score from analyzer results."""
        if not analyzer_results:
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                method_used=self.name,
                analyzer_weights={},
                details={"error": "No analyzer results provided"},
            )

        # Filter successful results
        successful_results = self._filter_successful_results(analyzer_results)

        if not successful_results:
            # All analyzers failed
            return ScoringResult(
                final_score=0.0,
                confidence=0.0,
                method_used=self.name,
                analyzer_weights={},
                details={
                    "error": "All analyzers failed",
                    "failed_analyzers": [r.analyzer_name for r in analyzer_results],
                },
            )

        # Calculate weighted score using SUMMATION (not average)
        # This ensures multiple risk signals compound rather than dilute
        total_weighted_score = 0.0
        analyzer_weights = {}
        analyzer_contributions = {}

        for result in successful_results:
            analyzer_name = result.analyzer_name
            weight = self.default_weights.get(analyzer_name, 0.5)  # Default weight 0.5

            # Only positive scores contribute (negative scores reduce risk)
            # Adjust contribution by confidence
            contribution = result.risk_score * weight * result.confidence

            total_weighted_score += contribution

            analyzer_weights[analyzer_name] = weight
            analyzer_contributions[analyzer_name] = {
                "raw_score": result.risk_score,
                "confidence": result.confidence,
                "weight": weight,
                "contribution": contribution,
            }

        # Final score is the sum (capped at 100)
        final_score = total_weighted_score

        # Apply consensus adjustments
        final_score, consensus_details = self._apply_consensus_adjustments(
            final_score, successful_results
        )

        # Calculate overall confidence
        overall_confidence = self._calculate_overall_confidence(successful_results)

        # Normalize final score
        final_score = self._normalize_score(final_score)

        # Determine risk level
        risk_level = self._get_risk_level(final_score)

        details = {
            "successful_analyzers": len(successful_results),
            "failed_analyzers": len(analyzer_results) - len(successful_results),
            "analyzer_contributions": analyzer_contributions,
            "consensus_adjustments": consensus_details,
            "risk_level": risk_level,
            "total_weighted_score": total_weighted_score,
            "scoring_method": "weighted_sum",
        }

        return ScoringResult(
            final_score=final_score,
            confidence=overall_confidence,
            method_used=self.name,
            analyzer_weights=analyzer_weights,
            details=details,
        )

    def _apply_consensus_adjustments(
        self, base_score: float, results: list[AnalyzerResult]
    ) -> tuple[float, dict]:
        """Apply consensus-based adjustments and high-risk signal bonuses."""
        adjustments = {
            "consensus_bonus": 0.0,
            "signal_bonus": 0.0,
            "applied": True,
            "triggered_signals": [],
        }

        # Collect all labels from all analyzers
        all_labels = []
        for result in results:
            all_labels.extend(result.labels)

        # HIGH-RISK SIGNAL COMBINATIONS - these indicate phishing with high confidence
        high_risk_signals = {
            # Domain age signals
            "very_new_domain": 25.0,  # Domain created recently - major red flag
            "new_domain": 15.0,  # Domain created within months
            "high_risk_tld": 20.0,  # Suspicious TLD (.cc, .tk, etc.)
            # Certificate signals
            "newly_issued_cert": 10.0,  # Certificate just issued
            "issuer_free_ca": 5.0,  # Free CA (Let's Encrypt) - common in phishing
            "self_signed_certificate": 30.0,  # Self-signed cert
            "expired_certificate": 25.0,  # Expired cert
            "hostname_mismatch": 35.0,  # Cert doesn't match domain
            # Content signals
            "has_password_input": 15.0,  # Has login form
            "suspicious_keyword": 10.0,  # URL has suspicious words
            "suspicious_keywords": 15.0,  # Content has phishing keywords
            "credential_theft_indicators": 25.0,  # Password + phishing keywords
            # URL structure signals
            "excessive_subdomains": 15.0,  # Too many subdomains
            "suspicious_path": 10.0,  # Path looks suspicious
            # Classification signals
            "unclassified_potential_phishing": 10.0,  # Potential phishing detected
            # REDIRECT SIGNALS - very important for evasion detection
            "javascript_redirect": 20.0,  # JS redirect detected
            "meta_refresh_redirect": 15.0,  # Meta refresh redirect
            "redirector_page": 30.0,  # Page is primarily a redirector
            "multiple_redirects": 15.0,  # Long redirect chain
            "shortener_in_redirect": 20.0,  # URL shortener in chain
            # CLOAKING SIGNALS
            "potential_cloaking": 25.0,  # Cloaking techniques detected in code
            "ua_cloaking_detected": 35.0,  # Active cloaking detected via multi-UA
            "cloaking_redirect_cloaking": 40.0,  # Different redirects per UA
            "cloaking_content_cloaking": 30.0,  # Different content per UA
            "cloaking_credential_cloaking": 45.0,  # Password form only for mobile
            "cloaking_status_code_cloaking": 25.0,  # Different status codes per UA
        }

        # TRUST SIGNALS - reduce score for legitimate sites
        trust_signals = {
            "established_domain": -30.0,  # Domain registered long ago
            "issuer_enterprise": -15.0,  # Enterprise CA (DigiCert, etc.)
            "known_provider": -10.0,  # Known legitimate provider
        }

        signal_bonus = 0.0
        triggered = []

        for label, bonus in high_risk_signals.items():
            if label in all_labels:
                signal_bonus += bonus
                triggered.append(f"+{label}")

        for label, penalty in trust_signals.items():
            if label in all_labels:
                signal_bonus += penalty  # penalty is negative
                triggered.append(f"-{label}")

        # Compound bonus: multiple signals together are more suspicious
        if len(triggered) >= 3:
            compound_bonus = len(triggered) * 5.0
            signal_bonus += compound_bonus
            adjustments["compound_bonus"] = compound_bonus

        base_score += signal_bonus
        adjustments["signal_bonus"] = signal_bonus
        adjustments["triggered_signals"] = triggered

        # Original consensus logic
        if len(results) >= 2:
            scores = [r.risk_score for r in results]
            high_scores = [s for s in scores if s >= 50]

            if len(high_scores) >= len(results) * 0.5:
                consensus_bonus = min(15.0, len(high_scores) * 3.0)
                base_score += consensus_bonus
                adjustments["consensus_bonus"] = consensus_bonus

        return base_score, adjustments

    def _calculate_overall_confidence(self, results: list[AnalyzerResult]) -> float:
        """Calculate overall confidence based on individual analyzer confidences."""
        if not results:
            return 0.0

        # Weighted average of confidences
        total_weighted_confidence = 0.0
        total_weights = 0.0

        for result in results:
            weight = self.default_weights.get(result.analyzer_name, 0.5)
            total_weighted_confidence += result.confidence * weight
            total_weights += weight

        base_confidence = (
            total_weighted_confidence / total_weights if total_weights > 0 else 0.0
        )

        # Adjust confidence based on number of successful analyzers
        analyzer_count_factor = min(
            1.0, len(results) / 4.0
        )  # Max confidence with 4+ analyzers

        return base_confidence * analyzer_count_factor

    def _calculate_standard_deviation(self, scores: list[float]) -> float:
        """Calculate standard deviation of scores."""
        if len(scores) < 2:
            return 0.0

        mean = sum(scores) / len(scores)
        variance = sum((x - mean) ** 2 for x in scores) / len(scores)
        return variance**0.5

    def _get_risk_level(self, score: float) -> str:
        """Get risk level based on score and thresholds."""
        if score >= self.thresholds["high"]:
            return "high"
        elif score >= self.thresholds["medium"]:
            return "medium"
        elif score >= self.thresholds["low"]:
            return "low"
        else:
            return "very_low"
