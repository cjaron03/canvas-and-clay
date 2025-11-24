"""Tests for admin bulk upload (zip + manifest.json)."""
import io
import json
import zipfile
import shutil
import pytest
from PIL import Image
import sys
import os

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
