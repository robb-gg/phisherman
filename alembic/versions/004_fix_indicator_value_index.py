"""fix indicator_value index for very long URLs

Revision ID: 004
Revises: 003
Create Date: 2025-10-12 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '004'
down_revision: Union[str, None] = '003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Remove B-tree index on indicator_value and create a hash-based index.
    
    PostgreSQL B-tree indexes have a size limit of ~8KB per row.
    For very long URLs (>25K chars), we need to use a hash index for exact matches,
    or create an index on a hash of the value.
    """
    # Drop the existing B-tree index on indicator_value
    op.drop_index('ix_indicators_indicator_value', table_name='indicators')
    
    # Create a hash index instead for exact equality lookups
    # Hash indexes in PostgreSQL are crash-safe since version 10+
    op.execute("""
        CREATE INDEX ix_indicators_indicator_value_hash 
        ON indicators USING hash (indicator_value)
    """)
    
    # Optionally, create an index on MD5 hash for prefix searches
    # This allows for fast lookups while staying within the 8KB limit
    op.execute("""
        CREATE INDEX ix_indicators_indicator_value_md5
        ON indicators (md5(indicator_value))
    """)


def downgrade() -> None:
    """Restore the original B-tree index."""
    # Drop hash indexes
    op.drop_index('ix_indicators_indicator_value_hash', table_name='indicators')
    op.drop_index('ix_indicators_indicator_value_md5', table_name='indicators')
    
    # Recreate the B-tree index (this may fail if there are long URLs)
    op.create_index('ix_indicators_indicator_value', 'indicators', ['indicator_value'], unique=False)

