"""Tests for admin bulk upload (zip + manifest.json)."""
import io
import json
import zipfile
import shutil
import pytest
from PIL import Image
import sys
import os
from datetime import datetime, timezone

# Force tests to use sqlite, not the docker Postgres config
os.environ.setdefault('TEST_DATABASE_URL', 'sqlite:///:memory:')
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app, db, User, Artist, Artwork, ArtworkPhoto, Storage
from upload_utils import ARTWORKS_DIR, THUMBNAILS_DIR


@pytest.fixture
def client():
    """Create a test client with in-memory database and disabled CSRF/rate limits."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['RATELIMIT_ENABLED'] = False

    from app import limiter
    limiter.enabled = False

    with app.test_client(use_cookies=True) as test_client:
        with app.app_context():
            db.create_all()
            yield test_client
            db.session.remove()
            db.drop_all()


@pytest.fixture
def cleanup_uploads():
    """Remove upload artifacts after each test."""
    yield
    shutil.rmtree(ARTWORKS_DIR, ignore_errors=True)
    shutil.rmtree(THUMBNAILS_DIR, ignore_errors=True)


@pytest.fixture
def storage(client):
    storage = Storage(storage_id='STOR001', storage_loc='Test Storage', storage_type='rack')
    db.session.add(storage)
    db.session.commit()
    return storage


@pytest.fixture
def admin_user(client):
    """Create and log in an admin user."""
    client.post('/auth/register', json={
        'email': 'admin@test.com',
        'password': 'AdminPassword123!'
    })
    user = User.query.filter_by(email='admin@test.com').first()
    user.role = 'admin'
    db.session.commit()
    client.post('/auth/login', json={'email': 'admin@test.com', 'password': 'AdminPassword123!'})
    return user


@pytest.fixture
def regular_user(client):
    client.post('/auth/register', json={
        'email': 'user@test.com',
        'password': 'UserPassword123!'
    })
    client.post('/auth/login', json={'email': 'user@test.com', 'password': 'UserPassword123!'})
    return User.query.filter_by(email='user@test.com').first()


def _make_image_bytes(color=(255, 0, 0)):
    """Create a small in-memory JPEG."""
    img = Image.new("RGB", (10, 10), color=color)
    buffer = io.BytesIO()
    img.save(buffer, format="JPEG")
    buffer.seek(0)
    return buffer.getvalue()


def _build_zip(manifest: dict, files: dict) -> bytes:
    """Build an in-memory zip with manifest and image files."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr('manifest.json', json.dumps(manifest))
        for name, data in files.items():
            zf.writestr(name, data)
    buffer.seek(0)
    return buffer.read()


def test_bulk_upload_happy_path(client, admin_user, storage, cleanup_uploads):
    manifest = {
        "default_storage_id": storage.storage_id,
        "artists": [{
            "key": "artist-one",
            "first_name": "Ada",
            "last_name": "Lovelace",
            "email": "ada@example.com"
        }],
        "artworks": [{
            "key": "art-1",
            "title": "Sunset",
            "artist_key": "artist-one",
            "medium": "Oil",
            "artwork_size": "10x10",
        }],
        "photos": [{
            "filename": "sunset.jpg",
            "artwork_key": "art-1",
            "is_primary": True
        }]
    }
    zip_bytes = _build_zip(manifest, {"sunset.jpg": _make_image_bytes()})

    resp = client.post(
        '/api/admin/bulk-upload',
        data={'file': (io.BytesIO(zip_bytes), 'bulk.zip')},
        content_type='multipart/form-data'
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data['summary']['artists_created'] == 1
    assert data['summary']['artworks_created'] == 1
    assert data['summary']['photos_created'] == 1
    assert data['summary']['errors'] == 0

    assert Artist.query.count() == 1
    assert Artwork.query.count() == 1
    assert ArtworkPhoto.query.count() == 1


def test_bulk_upload_existing_artist_without_manifest_artists(client, admin_user, storage, cleanup_uploads):
    existing_artist = Artist(
        artist_id='ARTS0001',
        artist_fname='Existing',
        artist_lname='Artist',
        artist_email='existing@example.com',
        artist_site=None,
        artist_bio=None,
        artist_phone=None,
        is_deleted=False,
        date_deleted=None,
        user_id=None
    )
    db.session.add(existing_artist)
    db.session.commit()

    manifest = {
        "default_storage_id": storage.storage_id,
        "artists": [],  # CLI skips artists when reusing an existing artist
        "artworks": [{
            "key": "art-1",
            "title": "Existing Artist Piece",
            "artist_id": existing_artist.artist_id,
            "artist_email": existing_artist.artist_email,
        }],
        "photos": [{
            "filename": "piece.jpg",
            "artwork_key": "art-1",
            "is_primary": True
        }]
    }

    zip_bytes = _build_zip(manifest, {"piece.jpg": _make_image_bytes(color=(0, 255, 0))})

    resp = client.post(
        '/api/admin/bulk-upload',
        data={'file': (io.BytesIO(zip_bytes), 'bulk.zip')},
        content_type='multipart/form-data'
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data['summary']['artists_created'] == 0
    assert data['summary']['artworks_created'] == 1
    assert data['summary']['photos_created'] == 1
    assert data['summary']['errors'] == 0

    assert Artist.query.count() == 1
    assert Artwork.query.count() == 1
    assert ArtworkPhoto.query.count() == 1
    assert Artwork.query.first().artist_id == existing_artist.artist_id


def test_bulk_upload_duplicate_suffix(client, admin_user, storage, cleanup_uploads):
    artist = Artist(
        artist_id='ARTS0002',
        artist_fname='Dup',
        artist_lname='Artist',
        artist_email='dup@example.com',
        artist_site=None,
        artist_bio=None,
        artist_phone=None,
        is_deleted=False,
        date_deleted=None,
        user_id=None
    )
    db.session.add(artist)
    db.session.commit()

    # Existing artwork with the same title
    existing_artwork = Artwork(
        artwork_num='AW000001',
        artwork_ttl='Sunset',
        artwork_medium=None,
        date_created=None,
        artwork_size=None,
        is_viewable=True,
        is_deleted=False,
        date_deleted=None,
        artist_id=artist.artist_id,
        storage_id=storage.storage_id
    )
    db.session.add(existing_artwork)
    db.session.commit()

    manifest = {
        "default_storage_id": storage.storage_id,
        "duplicate_policy": "suffix",
        "artists": [],
        "artworks": [{
            "key": "art-1",
            "title": "Sunset",
            "artist_id": artist.artist_id,
            "artist_email": artist.artist_email,
        }],
        "photos": [{
            "filename": "sunset.jpg",
            "artwork_key": "art-1",
            "is_primary": True
        }]
    }

    zip_bytes = _build_zip(manifest, {"sunset.jpg": _make_image_bytes(color=(0, 0, 255))})

    resp = client.post(
        '/api/admin/bulk-upload',
        data={'file': (io.BytesIO(zip_bytes), 'bulk.zip')},
        content_type='multipart/form-data'
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data['summary']['artworks_created'] == 1
    assert data['summary']['photos_created'] == 1
    assert data['summary']['errors'] == 0
    # New artwork should have suffixed title
    titles = {a.artwork_ttl for a in Artwork.query.all()}
    assert "Sunset" in titles
    assert any(t.startswith("Sunset (") for t in titles)


def test_bulk_upload_duplicate_override(client, admin_user, storage, cleanup_uploads, monkeypatch):
    artist = Artist(
        artist_id='ARTS0003',
        artist_fname='Dup',
        artist_lname='Override',
        artist_email='dup-override@example.com',
        artist_site=None,
        artist_bio=None,
        artist_phone=None,
        is_deleted=False,
        date_deleted=None,
        user_id=None
    )
    db.session.add(artist)
    db.session.commit()

    existing_artwork = Artwork(
        artwork_num='AW000002',
        artwork_ttl='Moonrise',
        artwork_medium=None,
        date_created=None,
        artwork_size=None,
        is_viewable=True,
        is_deleted=False,
        date_deleted=None,
        artist_id=artist.artist_id,
        storage_id=storage.storage_id
    )
    db.session.add(existing_artwork)
    db.session.commit()

    existing_photo = ArtworkPhoto(
        photo_id='PHOTO001',
        artwork_num=existing_artwork.artwork_num,
        filename='old_moon.jpg',
        file_path='uploads/artworks/old_moon.jpg',
        thumbnail_path='uploads/thumbnails/old_moon.jpg',
        file_size=123,
        mime_type='image/jpeg',
        width=10,
        height=10,
        uploaded_at=datetime.now(timezone.utc),
        uploaded_by=None,
        is_primary=True
    )
    db.session.add(existing_photo)
    db.session.commit()

    # Avoid filesystem deletes during test
    monkeypatch.setattr('app.delete_photo_files', lambda *args, **kwargs: (True, True))

    manifest = {
        "default_storage_id": storage.storage_id,
        "duplicate_policy": "override",
        "artists": [],
        "artworks": [{
            "key": "art-1",
            "title": "Moonrise",
            "artist_id": artist.artist_id,
            "artist_email": artist.artist_email,
        }],
        "photos": [{
            "filename": "moonrise.jpg",
            "artwork_key": "art-1",
            "is_primary": True
        }]
    }

    zip_bytes = _build_zip(manifest, {"moonrise.jpg": _make_image_bytes(color=(255, 0, 255))})

    resp = client.post(
        '/api/admin/bulk-upload',
        data={'file': (io.BytesIO(zip_bytes), 'bulk.zip')},
        content_type='multipart/form-data'
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data['summary']['artworks_created'] == 1
    assert data['summary']['photos_created'] == 1
    assert data['summary']['errors'] == 0
    # Override should leave only one artwork with title Moonrise
    artworks = Artwork.query.filter_by(artist_id=artist.artist_id).all()
    assert len(artworks) == 1
    assert artworks[0].artwork_ttl == 'Moonrise'
    assert ArtworkPhoto.query.filter_by(artwork_num=artworks[0].artwork_num).count() == 1


def test_bulk_upload_requires_admin(client, regular_user, storage, cleanup_uploads):
    manifest = {
        "default_storage_id": storage.storage_id,
        "artists": [],
        "artworks": [],
        "photos": []
    }
    zip_bytes = _build_zip(manifest, {})

    resp = client.post(
        '/api/admin/bulk-upload',
        data={'file': (io.BytesIO(zip_bytes), 'bulk.zip')},
        content_type='multipart/form-data'
    )

    assert resp.status_code == 403
