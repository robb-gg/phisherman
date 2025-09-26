"""Protocol definition for URL analyzers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass
class AnalyzerResult:
    """Result from an individual analyzer."""

    analyzer_name: str
    risk_score: float  # 0-100 scale
    confidence: float  # 0-1 scale
    labels: list[str]  # Risk categories/tags
    evidence: dict[str, Any]  # Supporting evidence
    execution_time_ms: float
    error: str | None = None


@runtime_checkable
class AnalyzerProtocol(Protocol):
    """Protocol that all analyzers must implement."""

    @property
    def name(self) -> str:
        """Analyzer name for identification."""
        ...

    @property
    def version(self) -> str:
        """Analyzer version."""
        ...

    @property
    def weight(self) -> float:
        """Default weight for score calculation (0-1)."""
        ...

    async def analyze(self, url: str) -> AnalyzerResult:
        """Analyze a URL and return risk assessment."""
        ...


class BaseAnalyzer(ABC):
    """Abstract base class for analyzers with common functionality."""

    def __init__(self, timeout: int = 10, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries

    @property
    @abstractmethod
    def name(self) -> str:
        """Analyzer name for identification."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Analyzer version."""
        pass

    @property
    def weight(self) -> float:
        """Default weight for score calculation (0-1)."""
        return 1.0

    @abstractmethod
    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        """Implement the actual analysis logic."""
        pass

    async def analyze(self, url: str) -> AnalyzerResult:
        """
        Analyze a URL with error handling and timing.

        Wraps the implementation with common error handling,
        timing measurement, and retry logic.
        """
        import asyncio
        import time

        from tenacity import (
            AsyncRetrying,
            RetryError,
            stop_after_attempt,
            wait_exponential,
        )

        start_time = time.time()

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_exponential(multiplier=1, min=4, max=10),
                reraise=True,
            ):
                with attempt:
                    # Apply timeout to the analysis
                    result = await asyncio.wait_for(
                        self._analyze_impl(url), timeout=self.timeout
                    )

                    # Ensure result is properly formatted
                    if result.analyzer_name != self.name:
                        result.analyzer_name = self.name

                    result.execution_time_ms = (time.time() - start_time) * 1000
                    return result

        except (TimeoutError, RetryError, Exception) as e:
            # Return error result instead of raising
            execution_time = (time.time() - start_time) * 1000
            error_message = f"Analysis failed: {type(e).__name__}: {e}"

            return AnalyzerResult(
                analyzer_name=self.name,
                risk_score=0.0,  # Neutral score on error
                confidence=0.0,  # No confidence on error
                labels=["analysis_error"],
                evidence={"error": error_message},
                execution_time_ms=execution_time,
                error=error_message,
            )
