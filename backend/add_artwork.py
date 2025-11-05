from app import Artist, Artwork, Storage, db

import secrets
import string
# for generating an id that is of type char(length)
def generate_id(length):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def add_artwork(aw_title, aw_medium, 
                date, aw_size,
                artist_num, storage_num):
    """ function add_artwork

        will have parameters for every column except artwork_num
        and will insert a row into the table artwork with the 
        given parameters

        will not insert into artwork if the data to be inserted is
        incorrect (ex: a string too long)

        tests:
        add_artwork("The successful tester", "digital", "2018-12-25", "10x12in", "A0000001",
                    "S000001")
    """
    session = db.session
    # check if artist is in artist table
    artist = session.query(Artist).filter_by(artist_id=artist_num).first()
    storage = session.query(Storage).filter_by(storage_id=storage_num).first()
    if not artist:
        raise ValueError(f"Given Artist ID not in Artist Table: {artist_num}")
    if not storage:
        raise ValueError(f"Given Storage ID not in Storage Table: {storage_num}")

    # creating new artwork_id and ensuring it's unique
    while True:
        # artwork_id is CHAR(8) so put 8 as length 
        new_num = generate_id(8)
        if not session.query(Artwork).filter_by(artwork_num=new_num).first():
            break

    new_artwork = Artwork(
        artwork_num=new_num,
        artwork_ttl=aw_title,
        artwork_medium=aw_medium,
        date_created=date,
        artwork_size=aw_size,
        artist_id=artist_num,
        storage_id=storage_num
    )

    session.add(new_artwork)
    session.commit()
    session.refresh(new_artwork)

    print(f"Successfully inserted new artwork with id of {new_artwork.artwork_num}")
    return new_artwork