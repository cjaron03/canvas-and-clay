"""create tables

Revision ID: 3fdd405089a3
Revises: d6c8e4bd5a0a
Create Date: 2025-10-27 01:00:41.308614
last modified: 10/30/25 (MK)

"""
from alembic import op
import sqlalchemy as sa
from example_data import artist_data, storage_data, artwork_data, flatfile_data, wallspace_data, rack_data


# revision identifiers, used by Alembic.
revision = '3fdd405089a3'
down_revision = 'd6c8e4bd5a0a'
branch_labels = None
depends_on = None

# to populate the database run the following within migrations
# docker exec -it canvas_backend flask db upgrade head 
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

    #  populating table with example data
    artist_table = sa.table(
        "artist",
        sa.column("artist_id", sa.CHAR(8)),
        sa.column("artist_fname", sa.String(20)),
        sa.column("artist_lname", sa.String(20)),
        sa.column("artist_email", sa.String(100)),
        sa.column("artist_site", sa.String(100)),
        sa.column("artist_bio", sa.String(800)),
        sa.column("artist_phone", sa.CHAR(14)),
    )
    # creating dict mapping tuple data to art_col
    art_cols = ['artist_id', 'artist_fname','artist_lname', 'artist_email',
                'artist_site', 'artist_bio', 'artist_phone']
    mapped_artists = [dict(zip(art_cols, rows)) for rows in artist_data]
    # inserting rows into artist table
    op.bulk_insert(artist_table, mapped_artists)


    # create table: storage
    op.create_table('storage',
        sa.Column('storage_id', sa.CHAR(7), primary_key=True),
        sa.Column('storage_loc', sa.String(30), nullable=True),
        sa.Column('storage_type', sa.String(30), nullable=True))
    
    # populating storage with example data
    storage_table = sa.table(
        'storage',
        sa.column('storage_id', sa.CHAR(7)),
        sa.column('storage_loc', sa.String(30)),
        sa.column('storage_type', sa.String(30)),
    )
    #creating dict of mapping tuples to columns
    storage_cols = ['storage_id', 'storage_loc', 'storage_type']
    mapped_storage = [dict(zip(storage_cols, rows)) for rows in storage_data]
    # bulk insert into storage table
    op.bulk_insert(storage_table, mapped_storage)


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
    
    # populating artwork with example data
    artwork_table = sa.table(
        'artwork',
        sa.column('artwork_num', sa.CHAR(8)),
        sa.column('artwork_ttl', sa.String(50)),
        sa.column('artwork_medium', sa.String(50)),
        sa.column('date_created', sa.Date),
        sa.column('artwork_size', sa.String(50)),
        sa.column('artist_id', sa.CHAR(8)),
        sa.column('storage_id', sa.CHAR(8)),
    )
    # creating dict for mapping tuples to columns
    artwork_cols = ['artwork_num', 'artwork_ttl', 'artwork_medium', 'date_created',
                    'artwork_size', 'artist_id', 'storage_id']
    mapped_artwork = [dict(zip(artwork_cols, rows)) for rows in artwork_data]
    # insert data into artwork table
    op.bulk_insert(artwork_table, mapped_artwork)
        
   
    
    # create table: flat_file
    op.create_table('flat_file',
        sa.Column('file_id', sa.CHAR(7), sa.ForeignKey('storage.storage_id',
                                                        onupdate='NO ACTION',
                                                        ondelete='NO ACTION'),
                                            primary_key=True),
        sa.Column('letter_code', sa.String(10), nullable=True))
    
    # populating flat_file with example data
    flatfile_table = sa.table(
        'flat_file',
        sa.column('file_id', sa.CHAR(7)),
        sa.column('letter_code', sa.String(10)),
    )
    # creating dict for mapping tuples to columns
    flatfile_cols = ['file_id', 'letter_code']
    mapped_flatfile = [dict(zip(flatfile_cols, rows)) for rows in flatfile_data]
    # inserting data into flat_file table
    op.bulk_insert(flatfile_table, mapped_flatfile)


    # create table: wall_space
    op.create_table('wall_space',
        sa.Column('wall_id', sa.CHAR(7), sa.ForeignKey('storage.storage_id',
                                                        onupdate='NO ACTION',
                                                        ondelete='NO ACTION'),
                                            primary_key=True),
        sa.Column('wall_wing', sa.String(10), nullable=True))
    
    # populating wall_space with example data
    wall_table = sa.table(
        'wall_space',
        sa.column('wall_id', sa.CHAR(7)),
        sa.column('wall_wing', sa.String(10)),
    )
    # creating dict for mapping tuples to columns
    wall_cols = ['wall_id', 'wall_wing']
    mapped_wall = [dict(zip(wall_cols, rows)) for rows in wallspace_data]
    # inserting data into wall_space table
    op.bulk_insert(wall_table, mapped_wall)


    # create table: rack
    op.create_table('rack',
        sa.Column('rack_id', sa.CHAR(7), sa.ForeignKey('storage.storage_id',
                                                        onupdate='NO ACTION',
                                                        ondelete='NO ACTION'),
                                            primary_key=True),
        sa.Column('rack_num', sa.String(10), nullable=True))
    
    # populating rack with example data
    rack_table = sa.table(
        'rack',
        sa.column('rack_id', sa.CHAR(7)),
        sa.column('rack_num', sa.String(10)),
    )
    # creating dict for mapping tuples to columns
    rack_cols = ['rack_id', 'rack_num']
    mapped_rack = [dict(zip(rack_cols, rows)) for rows in rack_data]
    # inserting data into rack table
    op.bulk_insert(rack_table, mapped_rack)

def downgrade():
    # drop tables
    op.drop_table('flat_file')
    op.drop_table('wall_space')
    op.drop_table('rack')
    op.drop_table('artwork')
    op.drop_table('storage')
    op.drop_table('artist')
   
    
    
