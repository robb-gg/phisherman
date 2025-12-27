"""Data models for feed processing."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ParsedEntry:
    """A parsed entry from a threat intelligence feed."""

    url: str
    external_id: str | None
    threat_type: str  # phishing, malware, etc.
    confidence: float  # 0.0 - 1.0
    severity: str  # low, medium, high, critical
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    feed_timestamp: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "url": self.url,
            "external_id": self.external_id,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "severity": self.severity,
            "tags": self.tags,
            "metadata": self.metadata,
            "feed_timestamp": self.feed_timestamp.isoformat() if self.feed_timestamp else None,
        }


@dataclass
class FeedResult:
    """Result from processing a feed."""

    feed_name: str
    status: str  # success, error
    entries_processed: int = 0
    entries_skipped: int = 0
    duplicates: int = 0
    error: str | None = None
    completed_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "feed_name": self.feed_name,
            "status": self.status,
            "entries_processed": self.entries_processed,
            "entries_skipped": self.entries_skipped,
            "duplicates": self.duplicates,
            "error": self.error,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

