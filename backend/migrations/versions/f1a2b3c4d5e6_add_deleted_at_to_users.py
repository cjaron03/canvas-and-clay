"""add_deleted_at_to_users

Revision ID: f1a2b3c4d5e6
Revises: e5f6a7b8c9d0
Create Date: 2025-11-17 07:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'f1a2b3c4d5e6'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade():
    """Add deleted_at column to users table for soft deletion."""
    op.add_column('users', sa.Column('deleted_at', sa.DateTime(), nullable=True))


def downgrade():
    """Remove deleted_at column from users table."""
    op.drop_column('users', 'deleted_at')

