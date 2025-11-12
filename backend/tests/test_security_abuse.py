"""Red-team style abuse tests for critical security controls."""
import io
import os
from datetime import datetime, timezone
from urllib.parse import quote

import pytest
from PIL import Image

from app import app, db, User, Artist, Artwork, Storage, ArtworkPhoto, limiter
from upload_utils import ARTWORKS_DIR, THUMBNAILS_DIR


def _make_image(filename='test.jpg'):
    """Create an in-memory JPEG suitable for upload tests."""
    img = Image.new('RGB', (80, 80), color='blue')
    buffer = io.BytesIO()
    img.save(buffer, format='JPEG')
    buffer.seek(0)
    return buffer, filename


def _seed_artwork(user_id=None, artwork_id='SECART01'):
    """Create storage, artist, and artwork rows for tests."""
    suffix = artwork_id[-5:] if len(artwork_id) >= 5 else artwork_id
    storage_id = f"ST{suffix}".upper()
    artist_id = f"AR{suffix}".upper()

    storage = Storage(storage_id=storage_id[:7], storage_loc='Secure Rack', storage_type='rack')
    artist = Artist(
        artist_id=artist_id[:8],
        artist_fname='Secure',
        artist_lname='Artist',
        artist_email=f'secure.{suffix.lower()}@example.com',
        user_id=user_id
    )
    db.session.add(storage)
    db.session.add(artist)
    db.session.flush()  # ensure FK targets exist before artwork insert
    artwork = Artwork(
        artwork_num=artwork_id,
        artwork_ttl='Security Test Artwork',
        artwork_medium='Oil',
        storage_id=storage.storage_id,
        artist_id=artist.artist_id
    )
    db.session.add(artwork)
    db.session.commit()
    return artwork


def _register_and_login(client, email, password):
    """Helper to create and authenticate a user."""
    client.post('/auth/register', json={'email': email, 'password': password})
    client.post('/auth/login', json={'email': email, 'password': password})
    return User.query.filter_by(email=email).first()


def _get_csrf_token(client):
    response = client.get('/auth/csrf-token')
    return response.get_json()['csrf_token']


@pytest.fixture
def client():
    """Baseline client with CSRF disabled but limiter enabled."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['RATELIMIT_ENABLED'] = True

    limiter.enabled = False

    with app.test_client(use_cookies=True) as test_client:
        with app.app_context():
            db.create_all()
            yield test_client
            db.session.remove()
            db.drop_all()


@pytest.fixture
def csrf_client():
    """Client with CSRF protection enforced."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['RATELIMIT_ENABLED'] = False

    limiter.enabled = False

    with app.test_client(use_cookies=True) as test_client:
        with app.app_context():
            db.create_all()
            yield test_client
            db.session.remove()
            db.drop_all()


@pytest.fixture
def cleanup_uploads():
    """Remove files created during upload tests."""
    yield
    for directory in (ARTWORKS_DIR, THUMBNAILS_DIR):
        if os.path.isdir(directory):
            for name in os.listdir(directory):
                path = os.path.join(directory, name)
                try:
                    if os.path.isfile(path):
                        os.remove(path)
                except OSError:
                    pass


class TestIDORProtections:
    """Ensure IDOR attempts on artwork/photo resources fail."""

    def test_non_owner_cannot_delete_photo(self, client, monkeypatch):
        """Attacker deleting someone else's photo should be blocked."""
        owner = _register_and_login(client, 'owner@example.com', 'OwnerPass123!')
        artwork = _seed_artwork(user_id=owner.id)

        # Insert a fake photo owned by the first user
        photo = ArtworkPhoto(
            photo_id='PHOTOID1',
            artwork_num=artwork.artwork_num,
            filename='owner_photo.jpg',
            file_path='uploads/artworks/owner_photo.jpg',
            thumbnail_path='uploads/thumbnails/owner_photo_thumb.jpg',
            file_size=1024,
            mime_type='image/jpeg',
            width=80,
            height=80,
            uploaded_at=datetime.now(timezone.utc),
            uploaded_by=owner.id,
            is_primary=False
        )
        db.session.add(photo)
        db.session.commit()

        # Prevent filesystem touches during the delete call
        monkeypatch.setattr('app.delete_photo_files', lambda *args, **kwargs: None)

        _register_and_login(client, 'attacker@example.com', 'AttackPass123!')
        response = client.delete(f'/api/photos/{photo.photo_id}')

        assert response.status_code == 403
        assert 'Permission denied' in response.json['error']

    def test_photo_upload_requires_authentication(self, client, cleanup_uploads):
        """Unauthenticated upload must be rejected."""
        artwork = _seed_artwork()
        image, filename = _make_image('test.jpg')
        response = client.post(
            f'/api/artworks/{artwork.artwork_num}/photos',
            data={'photo': (image, filename)},
            content_type='multipart/form-data'
        )

        assert response.status_code == 401
        assert response.json['error'] == 'Authentication required'


class TestCSRFMitigation:
    """Validate CSRF tokens are enforced on privileged routes."""

    def _bootstrap_admin(self, client):
        token = _get_csrf_token(client)
        client.post('/auth/register', json={
            'email': 'admin@example.com',
            'password': 'AdminPass123!'
        }, headers={'X-CSRFToken': token})

        admin = User.query.filter_by(email='admin@example.com').first()
        admin.role = 'admin'
        db.session.commit()

        token = _get_csrf_token(client)
        client.post('/auth/login', json={
            'email': 'admin@example.com',
            'password': 'AdminPass123!'
        }, headers={'X-CSRFToken': token})

    def _prepare_references(self):
        storage = Storage(storage_id='CSRFS01', storage_loc='CSRF Rack', storage_type='rack')
        artist = Artist(
            artist_id='CSRFA01',
            artist_fname='CSRF',
            artist_lname='Tester',
            artist_email='csrf@test.com'
        )
        db.session.add_all([storage, artist])
        db.session.commit()

    def test_artwork_creation_missing_csrf(self, csrf_client):
        """Admin requests without CSRF token should fail hard."""
        self._bootstrap_admin(csrf_client)
        self._prepare_references()

        payload = {
            'title': 'CSRF Test',
            'artist_id': 'CSRFA01',
            'storage_id': 'CSRFS01'
        }

        response = csrf_client.post('/api/artworks', json=payload)
        assert response.status_code == 400

    def test_artwork_creation_invalid_csrf(self, csrf_client):
        """Invalid CSRF token should be rejected."""
        self._bootstrap_admin(csrf_client)
        self._prepare_references()

        payload = {
            'title': 'CSRF Invalid Token',
            'artist_id': 'CSRFA01',
            'storage_id': 'CSRFS01'
        }

        response = csrf_client.post(
            '/api/artworks',
            json=payload,
            headers={'X-CSRFToken': 'invalid-token'}
        )
        assert response.status_code == 400


class TestRateLimiting:
    """Ensure brute-force protection trips correctly."""

    def test_login_rate_limit_enforced(self, client):
        """21st login attempt from same IP should receive 429 (rate limit is 20 per 15 minutes)."""
        limiter.enabled = True
        try:
            _register_and_login(client, 'rate@test.com', 'RatePass123!')

            # Make 20 successful login attempts (within rate limit)
            for _ in range(20):
                resp = client.post(
                    '/auth/login',
                    json={'email': 'rate@test.com', 'password': 'RatePass123!'},
                    environ_base={'REMOTE_ADDR': '203.0.113.10'}
                )
                assert resp.status_code == 200

            # 21st attempt should be rate limited
            twenty_first = client.post(
                '/auth/login',
                json={'email': 'rate@test.com', 'password': 'RatePass123!'},
                environ_base={'REMOTE_ADDR': '203.0.113.10'}
            )
            assert twenty_first.status_code == 429
        finally:
            limiter.enabled = False

    def test_registration_rate_limit_enforced(self, client):
        """Fourth registration attempt from same IP should be blocked."""
        limiter.enabled = True
        try:
            base_payload = {'password': 'SecurePass123!'}

            for attempt in range(3):
                resp = client.post(
                    '/auth/register',
                    json={'email': f'user{attempt}@example.com', **base_payload},
                    environ_base={'REMOTE_ADDR': '203.0.113.20'}
                )
                assert resp.status_code == 201

            blocked = client.post(
                '/auth/register',
                json={'email': 'user-blocked@example.com', **base_payload},
                environ_base={'REMOTE_ADDR': '203.0.113.20'}
            )
            assert blocked.status_code == 429
        finally:
            limiter.enabled = False


class TestInputHardening:
    """Validate abuse-resistant query params and uploads."""

    def test_artwork_search_handles_sqli_strings(self, client):
        """SQLi-ish search strings should not explode or over-return."""
        _register_and_login(client, 'seed@example.com', 'SeedPass123!')
        _seed_artwork(artwork_id='HARDA001')
        _seed_artwork(artwork_id='HARDA002')

        payload = quote("' OR 1=1--")
        response = client.get(f'/api/artworks?search={payload}')

        assert response.status_code == 200
        data = response.get_json()
        assert 'artworks' in data
        assert data['pagination']['total'] <= 2

    def test_artwork_pagination_caps_page_size(self, client):
        """per_page should clamp to 100 even if attacker asks for thousands."""
        _register_and_login(client, 'paginate@example.com', 'Paginate123!')
        _seed_artwork(artwork_id='PAGE0001')
        _seed_artwork(artwork_id='PAGE0002')

        response = client.get('/api/artworks?per_page=5000')
        assert response.status_code == 200
        assert response.get_json()['pagination']['per_page'] == 100

    def test_filename_sanitization_blocks_traversal(self, client, cleanup_uploads):
        """Uploaded filenames should be sanitized to prevent traversal."""
        admin = _register_and_login(client, 'upload-admin@example.com', 'UploadPass123!')
        admin.role = 'admin'
        db.session.commit()

        artwork = _seed_artwork()
        image, _ = _make_image('../../evil.jpg')
        image.seek(0)

        response = client.post(
            f'/api/artworks/{artwork.artwork_num}/photos',
            data={'photo': (image, '../../evil.jpg')},
            content_type='multipart/form-data'
        )

        assert response.status_code == 201
        filename = response.json['photo']['filename']
        assert '..' not in filename
        assert '/' not in filename and '\\' not in filename
