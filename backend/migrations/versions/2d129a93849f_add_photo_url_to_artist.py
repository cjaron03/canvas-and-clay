"""add photo url to artist

Revision ID: 2d129a93849f
Revises: a7c8d9e0f1b2
Create Date: 2025-11-30 00:25:53.051704

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2d129a93849f'
down_revision = 'a7c8d9e0f1b2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('artist', schema=None) as batch_op:
        batch_op.add_column(sa.Column('profile_photo_url', sa.String(length=512), nullable=True))


def downgrade():
    with op.batch_alter_table('artist', schema=None) as batch_op:
        batch_op.drop_column('profile_photo_url')
