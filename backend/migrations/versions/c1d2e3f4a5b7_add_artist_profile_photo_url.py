"""add_artist_profile_photo_url

Revision ID: c1d2e3f4a5b7
Revises: a7c8d9e0f1b2
Create Date: 2024-05-17 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c1d2e3f4a5b7'
down_revision = 'a7c8d9e0f1b2'
branch_labels = None
depends_on = None


def upgrade():
    """Add profile_photo_url to artist profiles."""
    with op.batch_alter_table('artist', schema=None) as batch_op:
        batch_op.add_column(sa.Column('profile_photo_url', sa.String(length=512), nullable=True))


def downgrade():
    """Remove profile_photo_url from artist profiles."""
    with op.batch_alter_table('artist', schema=None) as batch_op:
        batch_op.drop_column('profile_photo_url')
