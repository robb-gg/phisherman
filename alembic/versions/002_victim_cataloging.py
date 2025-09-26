"""Add victim cataloging tables for company tracking and phishing campaigns

Revision ID: 002
Revises: 001
Create Date: 2024-01-02 12:00:00.000000

"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum types using simple approach to avoid conflicts
    industry_enum = postgresql.ENUM(
        "banking",
        "ecommerce",
        "social_media",
        "cloud_services",
        "gaming",
        "cryptocurrency",
        "government",
        "healthcare",
        "education",
        "technology",
        "telecommunications",
        "logistics",
        "insurance",
        "media",
        "other",
        name="industryenum",
    )

    campaign_status_enum = postgresql.ENUM(
        "active",
        "monitoring",
        "declining",
        "inactive",
        "unknown",
        name="campaignstatusenum",
    )

    # Create victim_companies table
    op.create_table(
        "victim_companies",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("normalized_name", sa.String(length=255), nullable=False),
        sa.Column("brand_names", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("industry", industry_enum, nullable=False),
        sa.Column("country", sa.String(length=2), nullable=True),
        sa.Column("market_cap", sa.String(length=20), nullable=True),
        sa.Column("official_domains", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("official_tlds", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("logo_url", sa.String(length=500), nullable=True),
        sa.Column("brand_colors", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("total_phishing_urls", sa.Integer(), nullable=False),
        sa.Column("active_campaigns", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("brand_keywords", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("common_misspellings", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("is_premium", sa.Boolean(), nullable=False),
        sa.Column("data_sharing_allowed", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_updated",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_victim_companies_name"), "victim_companies", ["name"], unique=False
    )
    op.create_index(
        op.f("ix_victim_companies_normalized_name"),
        "victim_companies",
        ["normalized_name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_victim_companies_industry"),
        "victim_companies",
        ["industry"],
        unique=False,
    )
    op.create_index(
        op.f("ix_victim_companies_country"),
        "victim_companies",
        ["country"],
        unique=False,
    )

    # Create phishing_campaigns table
    op.create_table(
        "phishing_campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("campaign_hash", sa.String(length=64), nullable=False),
        sa.Column("victim_company_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", campaign_status_enum, nullable=False),
        sa.Column("attack_vector", sa.String(length=100), nullable=False),
        sa.Column("complexity_level", sa.String(length=20), nullable=False),
        sa.Column("common_themes", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("target_regions", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("languages", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("total_urls", sa.Integer(), nullable=False),
        sa.Column("active_urls", sa.Integer(), nullable=False),
        sa.Column("domains_count", sa.Integer(), nullable=False),
        sa.Column("avg_lifespan_hours", sa.Float(), nullable=True),
        sa.Column(
            "infrastructure_fingerprint",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("ttps", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("first_observed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("predicted_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["victim_company_id"],
            ["victim_companies.id"],
        ),
        sa.UniqueConstraint("campaign_hash"),
    )
    op.create_index(
        op.f("ix_phishing_campaigns_victim_company_id"),
        "phishing_campaigns",
        ["victim_company_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_phishing_campaigns_status"),
        "phishing_campaigns",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_phishing_campaigns_first_observed"),
        "phishing_campaigns",
        ["first_observed"],
        unique=False,
    )
    op.create_index(
        op.f("ix_phishing_campaigns_campaign_hash"),
        "phishing_campaigns",
        ["campaign_hash"],
        unique=True,
    )

    # Create victim_urls table
    op.create_table(
        "victim_urls",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url_scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("victim_company_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("impersonation_type", sa.String(length=100), nullable=False),
        sa.Column("similarity_score", sa.Float(), nullable=False),
        sa.Column(
            "deception_techniques", postgresql.ARRAY(sa.String()), nullable=False
        ),
        sa.Column("auto_classified", sa.Boolean(), nullable=False),
        sa.Column("classification_confidence", sa.Float(), nullable=False),
        sa.Column("classification_method", sa.String(length=100), nullable=False),
        sa.Column("human_verified", sa.Boolean(), nullable=False),
        sa.Column("verification_notes", sa.Text(), nullable=True),
        sa.Column("verified_by", sa.String(length=100), nullable=True),
        sa.Column("high_value_target", sa.Boolean(), nullable=False),
        sa.Column("educational_value", sa.Boolean(), nullable=False),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["url_scan_id"],
            ["url_scans.id"],
        ),
        sa.ForeignKeyConstraint(
            ["victim_company_id"],
            ["victim_companies.id"],
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["phishing_campaigns.id"],
        ),
    )
    op.create_index(
        op.f("ix_victim_urls_url_scan_id"), "victim_urls", ["url_scan_id"], unique=False
    )
    op.create_index(
        op.f("ix_victim_urls_victim_company_id"),
        "victim_urls",
        ["victim_company_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_victim_urls_campaign_id"), "victim_urls", ["campaign_id"], unique=False
    )

    # Create brand_patterns table
    op.create_table(
        "brand_patterns",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("victim_company_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pattern_type", sa.String(length=50), nullable=False),
        sa.Column("pattern_value", sa.String(length=500), nullable=False),
        sa.Column("pattern_regex", sa.String(length=1000), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("false_positive_rate", sa.Float(), nullable=False),
        sa.Column("language", sa.String(length=5), nullable=True),
        sa.Column("matches_count", sa.Integer(), nullable=False),
        sa.Column("true_positives", sa.Integer(), nullable=False),
        sa.Column("false_positives", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["victim_company_id"],
            ["victim_companies.id"],
        ),
    )
    op.create_index(
        op.f("ix_brand_patterns_victim_company_id"),
        "brand_patterns",
        ["victim_company_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_brand_patterns_pattern_type"),
        "brand_patterns",
        ["pattern_type"],
        unique=False,
    )


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table("brand_patterns")
    op.drop_table("victim_urls")
    op.drop_table("phishing_campaigns")
    op.drop_table("victim_companies")

    # Drop enums
    campaign_status_enum = postgresql.ENUM(name="campaignstatusenum")
    campaign_status_enum.drop(op.get_bind())

    industry_enum = postgresql.ENUM(name="industryenum")
    industry_enum.drop(op.get_bind())
