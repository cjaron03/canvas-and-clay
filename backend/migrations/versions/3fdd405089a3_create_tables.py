"""create tables

Revision ID: 3fdd405089a3
Revises: d6c8e4bd5a0a
Create Date: 2025-10-27 01:00:41.308614
last modified: 10/30/25 (MK)

Note: Example data seeding removed - use seed_demo.py for demo data instead.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3fdd405089a3'
down_revision = 'b7f8a9c1d2e3'
branch_labels = None
depends_on = None


def upgrade():
    # create table: artist
    op.create_table('artist',
        sa.Column('artist_id', sa.CHAR(8), primary_key=True),
        sa.Column('artist_fname', sa.String(20), nullable=False),
        sa.Column('artist_lname', sa.String(20), nullable=False),
        sa.Column('artist_email', sa.String(100), nullable=True),
        sa.Column('artist_site', sa.String(100), nullable=True),
        sa.Column('artist_bio', sa.String(800), nullable=True),
        sa.Column('artist_phone', sa.CHAR(14), nullable=True),
    )

    # create table: storage
    op.create_table('storage',
        sa.Column('storage_id', sa.CHAR(7), primary_key=True),
        sa.Column('storage_loc', sa.String(30), nullable=True),
        sa.Column('storage_type', sa.String(30), nullable=True))

    # create table: artwork
    op.create_table('artwork',
        sa.Column('artwork_num', sa.CHAR(8), primary_key=True),
        sa.Column('artwork_ttl', sa.String(50), nullable=True),
        sa.Column('artwork_medium', sa.String(50), nullable=True),
        sa.Column('date_created', sa.Date, nullable=True),
        sa.Column('artwork_size', sa.String(50), nullable=True),
        sa.Column('artist_id', sa.CHAR(8), sa.ForeignKey('artist.artist_id',
                                                           onupdate='NO ACTION',
                                                           ondelete='NO ACTION'),
                                            nullable=False),
        sa.Column('storage_id', sa.CHAR(8), sa.ForeignKey('storage.storage_id',
                                                           onupdate='NO ACTION',
                                                           ondelete='NO ACTION'),
                                            nullable=False)
        )

    # create table: flat_file
    op.create_table('flat_file',
        sa.Column('file_id', sa.CHAR(7), sa.ForeignKey('storage.storage_id',
                                                        onupdate='NO ACTION',
                                                        ondelete='NO ACTION'),
                                            primary_key=True),
        sa.Column('letter_code', sa.String(10), nullable=True))

    # create table: wall_space
    op.create_table('wall_space',
        sa.Column('wall_id', sa.CHAR(7), sa.ForeignKey('storage.storage_id',
                                                        onupdate='NO ACTION',
                                                        ondelete='NO ACTION'),
                                            primary_key=True),
        sa.Column('wall_wing', sa.String(10), nullable=True))

    # create table: rack
    op.create_table('rack',
        sa.Column('rack_id', sa.CHAR(7), sa.ForeignKey('storage.storage_id',
                                                        onupdate='NO ACTION',
                                                        ondelete='NO ACTION'),
                                            primary_key=True),
        sa.Column('rack_num', sa.String(10), nullable=True))

def downgrade():
    # drop tables
    op.drop_table('flat_file')
    op.drop_table('wall_space')
    op.drop_table('rack')
    op.drop_table('artwork')
    op.drop_table('storage')
    op.drop_table('artist')
   
    
    
