"""Add upload quota tracking to users

Revision ID: 1ae401cd5eab
Revises: 40373c6cb1fb
Create Date: 2025-12-09 22:19:45.765105

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1ae401cd5eab'
down_revision = '40373c6cb1fb'
branch_labels = None
depends_on = None

# Default quota: 500MB
DEFAULT_QUOTA = 500 * 1024 * 1024


def upgrade():
    # Add upload quota columns to users table
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'upload_quota_bytes',
            sa.BigInteger(),
            nullable=False,
            server_default=str(DEFAULT_QUOTA)
        ))
        batch_op.add_column(sa.Column(
            'bytes_uploaded',
            sa.BigInteger(),
            nullable=False,
            server_default='0'
        ))


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('bytes_uploaded')
        batch_op.drop_column('upload_quota_bytes')
