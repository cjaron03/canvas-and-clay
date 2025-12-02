"""add artist profile photo metadata columns

Revision ID: fedcba987654
Revises: 2d129a93849f
Create Date: 2025-01-15 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fedcba987654'
down_revision = '2d129a93849f'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('artist', schema=None) as batch_op:
        batch_op.add_column(sa.Column('profile_photo_thumb_url', sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column('profile_photo_object_key', sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column('profile_photo_thumb_object_key', sa.String(length=512), nullable=True))


def downgrade():
    with op.batch_alter_table('artist', schema=None) as batch_op:
        batch_op.drop_column('profile_photo_thumb_object_key')
        batch_op.drop_column('profile_photo_object_key')
        batch_op.drop_column('profile_photo_thumb_url')
