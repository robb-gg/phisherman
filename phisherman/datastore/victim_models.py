"""Database models for victim company cataloging and phishing campaign tracking."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phisherman.datastore.database import Base


class IndustryEnum(str, Enum):
    """Industry classification for victim companies."""

    BANKING = "banking"
    ECOMMERCE = "ecommerce"
    SOCIAL_MEDIA = "social_media"
    CLOUD_SERVICES = "cloud_services"
    GAMING = "gaming"
    CRYPTOCURRENCY = "cryptocurrency"
    GOVERNMENT = "government"
    HEALTHCARE = "healthcare"
    EDUCATION = "education"
    TECHNOLOGY = "technology"
    TELECOMMUNICATIONS = "telecommunications"
    LOGISTICS = "logistics"
    INSURANCE = "insurance"
    MEDIA = "media"
    OTHER = "other"


class CampaignStatusEnum(str, Enum):
    """Status of phishing campaigns."""

    ACTIVE = "active"
    MONITORING = "monitoring"
    DECLINING = "declining"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class VictimCompany(Base):
    """Model for companies being targeted by phishing attacks."""

    __tablename__ = "victim_companies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Company identification
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    normalized_name: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    brand_names: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )

    # Company details
    industry: Mapped[IndustryEnum] = mapped_column(nullable=False, index=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True, index=True)
    market_cap: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )  # large, medium, small

    # Legitimate domains and patterns
    official_domains: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    official_tlds: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )

    # Brand information
    logo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    brand_colors: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )

    # Phishing statistics
    total_phishing_urls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    active_campaigns: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )  # How targeted they are

    # Detection patterns for automatic classification
    brand_keywords: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    common_misspellings: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )

    # Business intelligence
    is_premium: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )  # For B2B monetization
    data_sharing_allowed: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    # Metadata
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(100), default="manual", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    phishing_campaigns: Mapped[list["PhishingCampaign"]] = relationship(
        "PhishingCampaign", back_populates="victim_company"
    )
    victim_urls: Mapped[list["VictimUrl"]] = relationship(
        "VictimUrl", back_populates="victim_company"
    )


class PhishingCampaign(Base):
    """Model for tracking organized phishing campaigns against specific companies."""

    __tablename__ = "phishing_campaigns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Campaign identification
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    campaign_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    # Target information
    victim_company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("victim_companies.id"), nullable=False, index=True
    )

    # Campaign details
    status: Mapped[CampaignStatusEnum] = mapped_column(
        nullable=False, index=True, default=CampaignStatusEnum.ACTIVE
    )
    attack_vector: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # email, social, sms, etc.
    complexity_level: Mapped[str] = mapped_column(
        String(20), default="medium", nullable=False
    )  # low, medium, high

    # Campaign characteristics
    common_themes: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    target_regions: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    languages: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )

    # Statistics
    total_urls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    active_urls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    domains_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    avg_lifespan_hours: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Threat intelligence
    infrastructure_fingerprint: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    ttps: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )  # Tactics, Techniques, Procedures

    # Timeline
    first_observed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_observed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    predicted_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Analysis metadata
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)

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

    # Relationships
    victim_company: Mapped[VictimCompany] = relationship(
        "VictimCompany", back_populates="phishing_campaigns"
    )
    victim_urls: Mapped[list["VictimUrl"]] = relationship(
        "VictimUrl", back_populates="campaign"
    )


class VictimUrl(Base):
    """Junction table connecting URLs to victim companies and campaigns."""

    __tablename__ = "victim_urls"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # URL reference (from existing UrlScan model)
    url_scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("url_scans.id"), nullable=False, index=True
    )

    # Victim company reference
    victim_company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("victim_companies.id"), nullable=False, index=True
    )

    # Optional campaign reference
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("phishing_campaigns.id"), nullable=True, index=True
    )

    # Classification details
    impersonation_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # domain_typo, subdomain_abuse, etc.
    similarity_score: Mapped[float] = mapped_column(
        Float, nullable=False
    )  # 0-1 how similar to legitimate
    deception_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )

    # Automated classification
    auto_classified: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    classification_confidence: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )
    classification_method: Mapped[str] = mapped_column(String(100), nullable=False)

    # Manual review
    human_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_by: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Business intelligence flags
    high_value_target: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )  # For B2B sales
    educational_value: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )  # For B2C education

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    victim_company: Mapped[VictimCompany] = relationship(
        "VictimCompany", back_populates="victim_urls"
    )
    campaign: Mapped[PhishingCampaign | None] = relationship(
        "PhishingCampaign", back_populates="victim_urls"
    )
    url_scan: Mapped["UrlScan"] = relationship(  # type: ignore[name-defined]
        "UrlScan", lazy="joined"
    )


class BrandPattern(Base):
    """Patterns for automatic brand/victim detection in URLs and content."""

    __tablename__ = "brand_patterns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Associated victim company
    victim_company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("victim_companies.id"), nullable=False, index=True
    )

    # Pattern details
    pattern_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # domain, keyword, visual
    pattern_value: Mapped[str] = mapped_column(String(500), nullable=False)
    pattern_regex: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    # Pattern metadata
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.8)
    false_positive_rate: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.1
    )
    language: Mapped[str | None] = mapped_column(String(5), nullable=True)

    # Usage statistics
    matches_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    true_positives: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    false_positives: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[str] = mapped_column(
        String(100), default="system", nullable=False
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
