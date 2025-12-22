"""increase indicator_value length to support very long URLs

Revision ID: 003
Revises: 002
Create Date: 2025-10-12 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003'
down_revision: Union[str, None] = '002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Increase indicator_value and source_url from VARCHAR(2083) to TEXT.
    
    This is needed because some phishing URLs include very long tokens/hashes
    in their fragments that exceed the 2083 character limit.
    """
    # Change indicator_value to TEXT to support very long URLs with tokens
    op.alter_column(
        'indicators',
        'indicator_value',
        type_=sa.Text(),
        existing_type=sa.String(2083),
        nullable=False
    )
    
    # Also change source_url to TEXT for consistency
    op.alter_column(
        'indicators',
        'source_url',
        type_=sa.Text(),
        existing_type=sa.String(2083),
        nullable=True
    )


def downgrade() -> None:
    """Revert indicator_value and source_url back to VARCHAR(2083)."""
    op.alter_column(
        'indicators',
        'indicator_value',
        type_=sa.String(2083),
        existing_type=sa.Text(),
        nullable=False
    )
    
    op.alter_column(
        'indicators',
        'source_url',
        type_=sa.String(2083),
        existing_type=sa.Text(),
        nullable=True
    )

