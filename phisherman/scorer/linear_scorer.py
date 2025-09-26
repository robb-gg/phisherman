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

    The final score is calculated as a weighted average of analyzer scores,
    with additional adjustments based on confidence levels and consensus.

    Score = Σ(analyzer_score * weight * confidence) / Σ(weight * confidence)
    """

    def __init__(self, config_path: str = None):
        # Default weights for analyzers
        self.default_weights = {
            "blacklist_feeds": 0.9,  # Highest weight for known bad indicators
            "dns_resolver": 0.8,  # High weight for DNS reputation
            "rdap_whois": 0.7,  # Good weight for registration data
            "url_heuristics": 0.6,  # Moderate weight for heuristics
            "tls_probe": 0.4,  # Lower weight (especially for placeholder)
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

        # Calculate weighted score
        total_weighted_score = 0.0
        total_weights = 0.0
        analyzer_weights = {}
        analyzer_contributions = {}

        for result in successful_results:
            analyzer_name = result.analyzer_name
            weight = self.default_weights.get(analyzer_name, 0.5)  # Default weight 0.5

            # Adjust weight by confidence
            effective_weight = weight * result.confidence

            # Calculate contribution
            contribution = result.risk_score * effective_weight

            total_weighted_score += contribution
            total_weights += effective_weight

            analyzer_weights[analyzer_name] = weight
            analyzer_contributions[analyzer_name] = {
                "raw_score": result.risk_score,
                "confidence": result.confidence,
                "weight": weight,
                "effective_weight": effective_weight,
                "contribution": contribution,
            }

        # Calculate final score
        if total_weights > 0:
            final_score = total_weighted_score / total_weights
        else:
            final_score = 0.0

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
            "total_weights": total_weights,
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
        """Apply consensus-based adjustments to the base score."""
        if len(results) < 2:
            return base_score, {"applied": False, "reason": "insufficient_analyzers"}

        scores = [r.risk_score for r in results]
        high_scores = [s for s in scores if s >= 70]  # High risk threshold
        low_scores = [s for s in scores if s <= 30]  # Low risk threshold

        adjustments = {
            "consensus_bonus": 0.0,
            "consensus_penalty": 0.0,
            "applied": True,
        }

        # High consensus bonus
        if len(high_scores) >= len(results) * 0.7:  # 70% agreement on high risk
            consensus_bonus = min(15.0, len(high_scores) * 3.0)
            base_score += consensus_bonus
            adjustments["consensus_bonus"] = consensus_bonus
            adjustments["reason"] = "high_risk_consensus"

        # Low consensus penalty (reduce false positives)
        elif len(low_scores) >= len(results) * 0.7:  # 70% agreement on low risk
            consensus_penalty = min(10.0, len(low_scores) * 2.0)
            base_score -= consensus_penalty
            adjustments["consensus_penalty"] = consensus_penalty
            adjustments["reason"] = "low_risk_consensus"

        # Disagreement penalty (reduce confidence when analyzers disagree)
        else:
            score_std = self._calculate_standard_deviation(scores)
            if score_std > 30:  # High disagreement
                disagreement_penalty = min(5.0, score_std * 0.1)
                base_score -= disagreement_penalty
                adjustments["consensus_penalty"] = disagreement_penalty
                adjustments["reason"] = "high_disagreement"

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
