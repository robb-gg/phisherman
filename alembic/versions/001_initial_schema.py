"""Initial database schema

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create url_scans table
    op.create_table(
        "url_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.String(length=2083), nullable=False),
        sa.Column("normalized_url", sa.String(length=2083), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("is_malicious", sa.Boolean(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("labels", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "analyzer_results", postgresql.JSON(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("scan_duration_ms", sa.Float(), nullable=False),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
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
    )
    op.create_index(
        op.f("ix_url_scans_client_ip"), "url_scans", ["client_ip"], unique=False
    )
    op.create_index(
        op.f("ix_url_scans_created_at"), "url_scans", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_url_scans_domain"), "url_scans", ["domain"], unique=False)
    op.create_index(
        op.f("ix_url_scans_is_malicious"), "url_scans", ["is_malicious"], unique=False
    )
    op.create_index(
        op.f("ix_url_scans_normalized_url"),
        "url_scans",
        ["normalized_url"],
        unique=False,
    )
    op.create_index(op.f("ix_url_scans_url"), "url_scans", ["url"], unique=False)

    # Create indicators table
    op.create_table(
        "indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("indicator_type", sa.String(length=50), nullable=False),
        sa.Column("indicator_value", sa.String(length=2083), nullable=False),
        sa.Column("threat_type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("source_url", sa.String(length=2083), nullable=True),
        sa.Column("tags", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("metadata", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
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
    )
    op.create_index(
        op.f("ix_indicators_expires_at"), "indicators", ["expires_at"], unique=False
    )
    op.create_index(
        op.f("ix_indicators_first_seen"), "indicators", ["first_seen"], unique=False
    )
    op.create_index(
        op.f("ix_indicators_indicator_type"),
        "indicators",
        ["indicator_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_indicators_indicator_value"),
        "indicators",
        ["indicator_value"],
        unique=False,
    )
    op.create_index(
        op.f("ix_indicators_is_active"), "indicators", ["is_active"], unique=False
    )
    op.create_index(
        op.f("ix_indicators_last_seen"), "indicators", ["last_seen"], unique=False
    )
    op.create_index(
        op.f("ix_indicators_severity"), "indicators", ["severity"], unique=False
    )
    op.create_index(
        op.f("ix_indicators_source"), "indicators", ["source"], unique=False
    )
    op.create_index(
        op.f("ix_indicators_threat_type"), "indicators", ["threat_type"], unique=False
    )

    # Create feed_entries table
    op.create_table(
        "feed_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("feed_name", sa.String(length=100), nullable=False),
        sa.Column("feed_url", sa.String(length=2083), nullable=False),
        sa.Column("raw_data", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "parsed_data", postgresql.JSON(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("processed", sa.Boolean(), nullable=False),
        sa.Column("processing_error", sa.Text(), nullable=True),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.Column("feed_timestamp", sa.DateTime(timezone=True), nullable=True),
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
    )
    op.create_index(
        op.f("ix_feed_entries_checksum"), "feed_entries", ["checksum"], unique=False
    )
    op.create_index(
        op.f("ix_feed_entries_created_at"), "feed_entries", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_feed_entries_external_id"),
        "feed_entries",
        ["external_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_feed_entries_feed_name"), "feed_entries", ["feed_name"], unique=False
    )
    op.create_index(
        op.f("ix_feed_entries_processed"), "feed_entries", ["processed"], unique=False
    )

    # Create verdicts table
    op.create_table(
        "verdicts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url_hash", sa.String(length=64), nullable=False),
        sa.Column("normalized_url", sa.String(length=2083), nullable=False),
        sa.Column("is_malicious", sa.Boolean(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("labels", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("analyzer_version", sa.String(length=20), nullable=False),
        sa.Column("model_version", sa.String(length=20), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hit_count", sa.Integer(), nullable=False),
        sa.Column(
            "last_accessed",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
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
        sa.UniqueConstraint("url_hash"),
    )
    op.create_index(
        op.f("ix_verdicts_expires_at"), "verdicts", ["expires_at"], unique=False
    )
    op.create_index(
        op.f("ix_verdicts_is_malicious"), "verdicts", ["is_malicious"], unique=False
    )
    op.create_index(
        op.f("ix_verdicts_normalized_url"), "verdicts", ["normalized_url"], unique=False
    )
    op.create_index(op.f("ix_verdicts_url_hash"), "verdicts", ["url_hash"], unique=True)


def downgrade() -> None:
    op.drop_table("verdicts")
    op.drop_table("feed_entries")
    op.drop_table("indicators")
    op.drop_table("url_scans")
