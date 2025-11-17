"""normalize_visitor_to_guest_role

Revision ID: e5f6a7b8c9d0
Revises: dd25ebc37dcf
Create Date: 2025-11-16 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e5f6a7b8c9d0'
down_revision = 'dd25ebc37dcf'
branch_labels = None
depends_on = None


def upgrade():
    """Normalize 'visitor' role to 'guest' for consistency."""
    # Update all users with 'visitor' role to 'guest'
    op.execute("UPDATE users SET role = 'guest' WHERE role = 'visitor'")


def downgrade():
    """Revert 'guest' role back to 'visitor' for backwards compatibility."""
    # Note: This will convert ALL guest users to visitor, including those
    # created after the migration. Consider this carefully before downgrading.
    op.execute("UPDATE users SET role = 'visitor' WHERE role = 'guest'")
