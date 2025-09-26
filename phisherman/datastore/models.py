"""SQLAlchemy models for the Phisherman database schema."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column

from phisherman.datastore.database import Base


class UrlScan(Base):
    """Model for storing URL scan results."""

    __tablename__ = "url_scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # URL details
    url: Mapped[str] = mapped_column(String(2083), nullable=False, index=True)
    normalized_url: Mapped[str] = mapped_column(
        String(2083), nullable=False, index=True
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)

    # Analysis results
    is_malicious: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    labels: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Analyzer results
    analyzer_results: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    # Metadata
    scan_duration_ms: Mapped[float] = mapped_column(Float, nullable=False)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Indicator(Base):
    """Model for storing threat indicators from various sources."""

    __tablename__ = "indicators"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Indicator details
    indicator_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # url, domain, ip, hash
    indicator_value: Mapped[str] = mapped_column(
        String(2083), nullable=False, index=True
    )

    # Threat classification
    threat_type: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # phishing, malware, spam, etc.
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # low, medium, high, critical
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    # Source information
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source_url: Mapped[str | None] = mapped_column(String(2083), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    extra_data: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON, nullable=False, default=dict
    )

    # Validity
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, index=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class FeedEntry(Base):
    """Model for storing raw entries from threat intelligence feeds."""

    __tablename__ = "feed_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Feed information
    feed_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    feed_url: Mapped[str] = mapped_column(String(2083), nullable=False)

    # Entry data
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    parsed_data: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    # Processing status
    processed: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )
    processing_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # External ID for deduplication
    external_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    checksum: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Timestamps
    feed_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Verdict(Base):
    """Model for storing cached verdicts to avoid re-analysis."""

    __tablename__ = "verdicts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Target identifier
    url_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    normalized_url: Mapped[str] = mapped_column(
        String(2083), nullable=False, index=True
    )

    # Verdict
    is_malicious: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    labels: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # Cache metadata
    analyzer_version: Mapped[str] = mapped_column(String(20), nullable=False)
    model_version: Mapped[str] = mapped_column(String(20), nullable=False)

    # Validity
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # Usage tracking
    hit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_accessed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
