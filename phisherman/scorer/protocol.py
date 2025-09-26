"""Protocol definition for scoring systems."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from phisherman.analyzers.protocol import AnalyzerResult


@dataclass
class ScoringResult:
    """Final scoring result combining all analyzer results."""

    final_score: float  # 0-100 scale
    confidence: float  # 0-1 scale
    method_used: str  # Scoring method name
    analyzer_weights: dict[str, float]  # Weights applied to each analyzer
    details: dict[str, Any]  # Additional scoring details


@runtime_checkable
class ScorerProtocol(Protocol):
    """Protocol that all scorers must implement."""

    @property
    def name(self) -> str:
        """Scorer name for identification."""
        ...

    @property
    def version(self) -> str:
        """Scorer version."""
        ...

    def calculate_score(self, analyzer_results: list[AnalyzerResult]) -> ScoringResult:
        """Calculate final score from analyzer results."""
        ...


class BaseScorer(ABC):
    """Abstract base class for scorers with common functionality."""

    def __init__(self, config_path: str = None):
        """
        Initialize scorer with optional configuration.

        Args:
            config_path: Path to scoring configuration file
        """
        self.config_path = config_path
        self._load_config()

    @property
    @abstractmethod
    def name(self) -> str:
        """Scorer name for identification."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Scorer version."""
        pass

    @abstractmethod
    def _load_config(self) -> None:
        """Load scorer configuration from file or defaults."""
        pass

    @abstractmethod
    def calculate_score(self, analyzer_results: list[AnalyzerResult]) -> ScoringResult:
        """Calculate final score from analyzer results."""
        pass

    def _filter_successful_results(
        self, results: list[AnalyzerResult]
    ) -> list[AnalyzerResult]:
        """Filter out analyzer results that had errors."""
        return [result for result in results if result.error is None]

    def _normalize_score(self, score: float) -> float:
        """Normalize score to 0-100 range."""
        return max(0.0, min(100.0, score))
