"""Pydantic schemas for API request/response models."""

from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class UrlAnalysisRequest(BaseModel):
    """Request schema for URL analysis."""

    url: str = Field(
        ...,
        description="URL to analyze for phishing/malware",
        examples=["https://example.com", "http://suspicious-site.evil.com"],
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate URL format and scheme."""
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")

        # Add scheme if missing
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"

        try:
            parsed = urlparse(v)
            if not parsed.netloc:
                raise ValueError("Invalid URL: missing domain")

            # Basic validation
            if len(v) > 2083:  # IE limit
                raise ValueError("URL too long (>2083 characters)")

        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}") from e

        return v


class AnalyzerResult(BaseModel):
    """Individual analyzer result."""

    name: str = Field(..., description="Analyzer name")
    score: float = Field(
        ..., le=100, description="Risk score (can be negative for risk reduction)"
    )
    confidence: float = Field(..., ge=0, le=1, description="Confidence level (0-1)")
    labels: list[str] = Field(default_factory=list, description="Risk labels/tags")
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Supporting evidence"
    )
    execution_time_ms: float = Field(..., description="Analyzer execution time in ms")
    error: str | None = Field(None, description="Error message if analyzer failed")


class UrlAnalysisResponse(BaseModel):
    """Response schema for URL analysis."""

    url: str = Field(..., description="Original URL analyzed")
    malicious: bool = Field(..., description="Whether URL is deemed malicious")
    score: float = Field(
        ...,
        le=100,
        description="Overall risk score (can be negative for very safe URLs)",
    )
    confidence: float = Field(..., ge=0, le=1, description="Overall confidence (0-1)")
    labels: list[str] = Field(
        default_factory=list, description="Risk labels/categories"
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Aggregated evidence"
    )

    # Detailed results
    analyzers: list[AnalyzerResult] = Field(
        default_factory=list, description="Individual analyzer results"
    )

    # Metadata
    analysis_id: str | None = Field(None, description="Unique analysis identifier")
    timestamp: str = Field(..., description="Analysis timestamp (ISO format)")
    processing_time_ms: float = Field(..., description="Total processing time in ms")
    cached: bool = Field(default=False, description="Whether result was cached")

    # Version info
    version: str = Field(default="0.1.0", description="API version")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Service status")
    version: str = Field(..., description="Application version")
    timestamp: str = Field(..., description="Current timestamp")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")

    # Component health
    database: bool = Field(..., description="Database connectivity")
    redis: bool = Field(..., description="Redis connectivity")
    celery: bool = Field(..., description="Celery worker availability")


class ErrorResponse(BaseModel):
    """Error response schema."""

    error: dict[str, Any] = Field(
        ...,
        description="Error details",
        examples=[
            {"code": 400, "message": "Invalid URL format", "type": "validation_error"}
        ],
    )
