"""add artwork_photos table for photo uploads

Revision ID: c8d9e5f6a7b8
Revises: 3fdd405089a3
Create Date: 2025-11-03 16:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c8d9e5f6a7b8'
down_revision = '3fdd405089a3'
branch_labels = None
depends_on = None


def upgrade():
    # create artwork_photos table
    op.create_table('artwork_photos',
    sa.Column('photo_id', sa.CHAR(length=8), nullable=False),
    sa.Column('artwork_num', sa.CHAR(length=8), nullable=True),
    sa.Column('filename', sa.String(length=255), nullable=False),
    sa.Column('file_path', sa.String(length=512), nullable=False),
    sa.Column('thumbnail_path', sa.String(length=512), nullable=False),
    sa.Column('file_size', sa.Integer(), nullable=False),
    sa.Column('mime_type', sa.String(length=50), nullable=False),
    sa.Column('width', sa.Integer(), nullable=False),
    sa.Column('height', sa.Integer(), nullable=False),
    sa.Column('uploaded_at', sa.DateTime(), nullable=False),
    sa.Column('uploaded_by', sa.Integer(), nullable=True),
    sa.Column('is_primary', sa.Boolean(), nullable=False, server_default='0'),
    sa.ForeignKeyConstraint(['artwork_num'], ['artwork.artwork_num'],
                          name='fk_artwork_photos_artwork_num',
                          onupdate='CASCADE',
                          ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'],
                          name='fk_artwork_photos_uploaded_by',
                          onupdate='CASCADE',
                          ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('photo_id')
    )

    # create indexes for better query performance
    with op.batch_alter_table('artwork_photos', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_artwork_photos_artwork_num'), ['artwork_num'], unique=False)
        batch_op.create_index(batch_op.f('ix_artwork_photos_uploaded_by'), ['uploaded_by'], unique=False)
        batch_op.create_index(batch_op.f('ix_artwork_photos_uploaded_at'), ['uploaded_at'], unique=False)


def downgrade():
    # drop indexes first
    with op.batch_alter_table('artwork_photos', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_artwork_photos_uploaded_at'))
        batch_op.drop_index(batch_op.f('ix_artwork_photos_uploaded_by'))
        batch_op.drop_index(batch_op.f('ix_artwork_photos_artwork_num'))

    # drop the table
    op.drop_table('artwork_photos')
