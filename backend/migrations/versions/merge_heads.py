"""merge migration branches

Revision ID: a9b8c7d6e5f4
Revises: 6756a6a19a92, f1a2b3c4d5e6
Create Date: 2025-11-20 01:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a9b8c7d6e5f4'
down_revision = ('6756a6a19a92', 'f1a2b3c4d5e6')  # tuple for merge
branch_labels = None
depends_on = None


def upgrade():
    # merge migration - no changes needed, just merging branches
    pass


def downgrade():
    # merge migration - no changes needed, just merging branches
    pass

