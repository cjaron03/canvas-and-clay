"""Seed helper to restore core artworks, artists, and storage without touching users."""
from datetime import date
from app import app, db, Artist, Artwork, Storage


def upsert_storage(storage_id, loc, storage_type):
    storage = db.session.get(Storage, storage_id)
    if not storage:
        storage = Storage(storage_id=storage_id)
        db.session.add(storage)
    storage.storage_loc = loc
    storage.storage_type = storage_type
    return storage


def upsert_artist(artist_id, first_name, last_name, email=None, site=None, bio=None):
    artist = db.session.get(Artist, artist_id)
    if not artist:
        artist = Artist(artist_id=artist_id)
        db.session.add(artist)
    artist.artist_fname = first_name
    artist.artist_lname = last_name
    artist.artist_email = email
    artist.artist_site = site
    artist.artist_bio = bio
    # Do not set user_id here to avoid touching accounts
    return artist


def upsert_artwork(artwork_num, title, medium, artwork_size, artist_id, storage_id, created=None):
    artwork = db.session.get(Artwork, artwork_num)
    if not artwork:
        artwork = Artwork(artwork_num=artwork_num)
        db.session.add(artwork)
    artwork.artwork_ttl = title
    artwork.artwork_medium = medium
    artwork.artwork_size = artwork_size
    artwork.artist_id = artist_id
    artwork.storage_id = storage_id
    artwork.date_created = created
    return artwork


def seed():
    storages = [
        ("STOR001", "Main Gallery Wall", "wall"),
        ("STOR002", "Flat File A1", "flat_file"),
        ("STOR003", "Rack 3", "rack"),
    ]

    artists = [
        ("ARTS0001", "Alicia", "Nguyen", "alicia@example.com", None, "Mixed media painter focused on texture."),
        ("ARTS0002", "David", "Morales", "david@example.com", None, "Photographer exploring urban light."),
        ("ARTS0003", "Priya", "Kumar", "priya@example.com", None, "Watercolor studies of coastal life."),
    ]

    artworks = [
        ("AW000001", "Sunset Layers", "Mixed Media", "24x36 in", "ARTS0001", "STOR001", date(2023, 5, 2)),
        ("AW000002", "City Reflections", "Photography", "18x24 in", "ARTS0002", "STOR003", date(2024, 3, 18)),
        ("AW000003", "Harbor Morning", "Watercolor", "16x20 in", "ARTS0003", "STOR002", date(2022, 9, 12)),
        ("AW000004", "Night Market", "Photography", "20x30 in", "ARTS0002", "STOR003", date(2024, 7, 9)),
        ("AW000005", "Driftwood Study", "Watercolor", "12x16 in", "ARTS0003", "STOR002", date(2023, 1, 21)),
    ]

    for storage_id, loc, stype in storages:
        upsert_storage(storage_id, loc, stype)

    for artist_id, first, last, email, site, bio in artists:
        upsert_artist(artist_id, first, last, email, site, bio)

    for aw in artworks:
        upsert_artwork(*aw)

    db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        seed()
        print("Seeded sample storages, artists, and artworks (users untouched).")
