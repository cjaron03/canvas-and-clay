""" Populating Canvas and Clay Tables with SQLAlchemyORM
    last modified: 10/27/25 (MK)
    will initialize in app.py
    need to also define tables here in order to interact with Flask
"""

def init_tables(db):
    class Artist(db.Model):
        """ Artist model holding artist information
            
        Attributes:
            artist_id - primary key
            artist_fname - artist first name
            artist_lname - artist last name
            artist_email - artist email nullable=True
            artist_site  - artist website or social media
            artist_bio - artist biography/description
            artist_phone - artist phone number
        """
        __tablename__ = 'artist'
        artist_id = db.Column(db.CHAR(8), primary_key=True)
        artist_fname =  db.Column(db.String(20), nullable=False)
        artist_lname =  db.Column(db.String(20), nullable=False)
        artist_email =  db.Column(db.String(100), nullable=True)
        artist_site = db.Column(db.String(100), nullable=True)
        artist_bio = db.Column(db.String(800), nullable=True)
        artist_phone = db.Column(db.CHAR(14), nullable=True)


    class Artwork(db.Model):
        """ Artwork Model for artwork information

        Attributes: 
            artwork_num - primary key
            artwork_ttl - artwork title/name
            artwork_medium - type of media (watercolor, oil, etc)
            date_created - date made
            artwork size - dimensions of artwork (24x36in, 3x3x3ft)
            artist_id - id of the creator
            storage_id - id of storage location
        """
        __tablename__ = 'artwork'
        artwork_num = db.Column(db.CHAR(8), primary_key=True)
        artwork_ttl = db.Column(db.String(50), nullable=True)
        artwork_medium = db.Column(db.String(50), nullable=True)
        date_created = db.Column(db.Date, nullable=True)
        artwork_size = db.Column(db.String(50), nullable=True)
        artist_id = db.Column(db.CHAR(8), db.ForeignKey('artist.artist_id', 
                                                        onupdate='NO ACTION',
                                                        ondelete='NO ACTION'),
                                                        nullable=False)
        storage_id = db.Column(db.CHAR(7), db.ForeignKey('storage.storage_id', 
                                                        onupdate='NO ACTION',
                                                        ondelete='NO ACTION'),
                                                        nullable=False)



    class Storage(db.Model):
        """ Storage Model - Superclass for artwork locations
        
        Attributes:
            storage_id - primary key
            storage_loc - name of location
            storage type - type of storage (flat file, wall space, rack)
        """
        __tablename__ = 'storage'
        storage_id = db.Column(db.CHAR(7), primary_key=True)
        storage_loc = db.Column(db.String(30), nullable=True)
        storage_type = db.Column(db.String(30), nullable=True)


    class FlatFile(db.Model):
        """ FlatFile Model - subclass for storage
        
        Attributes:
            file_id - primary key
            letter_code - letter code of flat_file
        """
        __tablename__ = 'flat_file'
        file_id = db.Column(db.CHAR(7), db.ForeignKey('storage.storage_id',
                                                    onupdate='NO ACTION',
                                                    ondelete='NO ACTION'),
                                                    primary_key=True)
        letter_code = db.Column(db.String(10), nullable=True)


    class WallSpace(db.Model):
        """ WallSpace Model - sublclass for Storage
        
        Attributes:
            wall_id - primary key
            wall_wing - cardinal direction of wall space
            """
        __tablename__ = 'wall_space'
        wall_id = db.Column(db.CHAR(7), db.ForeignKey('storage.storage_id',
                                                    onupdate='NO ACTION',
                                                    ondelete='NO ACTION'),
                                                    primary_key=True)
        wall_wing = db.Column(db.String(10), nullable=True)


    class Rack(db.Model):
        """ Rack Model - subclass for Storage
        
        Attributes:
            rack_id - primary key
            rack_num - number of rack
        """
        __tablename__ = 'rack'
        rack_id = db.Column(db.CHAR(7), db.ForeignKey('storage.storage_id',
                                                    onupdate='NO ACTION',
                                                    ondelete='NO ACTION'),
                                                    primary_key=True)
        rack_num = db.Column(db.String(10), nullable=True)

    return Artist, Artwork, Storage, FlatFile, WallSpace, Rack


