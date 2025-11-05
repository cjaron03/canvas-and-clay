"""Tests for artwork ownership and photo upload authorization."""
import pytest
import io
from PIL import Image
import json
from app import app, db


@pytest.fixture
def client():
    """Create a test client with a fresh database."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False  # disable csrf for tests
    app.config['SESSION_COOKIE_SECURE'] = False  # allow testing without https
    app.config['RATELIMIT_ENABLED'] = False  # disable rate limiting for tests

    # disable limiter if it exists
    from app import limiter
    limiter.enabled = False

    with app.test_client(use_cookies=True) as test_client:
        with app.app_context():
            db.create_all()
            yield test_client
            db.session.remove()
            db.drop_all()


@pytest.fixture
def test_image():
    """Create a test image in memory."""
    img = Image.new('RGB', (100, 100), color='red')
    buf = io.BytesIO()
    img.save(buf, format='JPEG')
    buf.seek(0)
    return buf


@pytest.fixture
def admin_user(client):
    """Create and log in as admin user."""
    # Register admin
    response = client.post('/auth/register', json={
        'email': 'admin@test.com',
        'password': 'AdminPassword123!',
        'role': 'admin'
    })

    # Login
    response = client.post('/auth/login', json={
        'email': 'admin@test.com',
        'password': 'AdminPassword123!'
    })

    return response.json


@pytest.fixture
def regular_user(client):
    """Create and log in as regular (non-admin) user."""
    # Register user
    response = client.post('/auth/register', json={
        'email': 'user@test.com',
        'password': 'UserPassword123!',
        'role': 'visitor'
    })

    # Login
    response = client.post('/auth/login', json={
        'email': 'user@test.com',
        'password': 'UserPassword123!'
    })

    return response.json


@pytest.fixture
def artist_and_artwork(client):
    """Create test artist and artwork."""
    from create_tbls import init_tables

    Artist, Artwork, Storage, _, _, _, _ = init_tables(db)

    # Create storage location first
    storage = Storage(
        storage_id='TST0001',
        storage_loc='Test Storage',
        storage_type='rack'
    )
    db.session.add(storage)

    # Create artist (no user_id initially)
    artist = Artist(
        artist_id='TSTART01',
        artist_fname='Test',
        artist_lname='Artist',
        artist_email='test@artist.com',
        user_id=None
    )
    db.session.add(artist)

    # Create artwork
    artwork = Artwork(
        artwork_num='TSTAW001',
        artwork_ttl='Test Artwork',
        artwork_medium='Oil on Canvas',
        artist_id='TSTART01',
        storage_id='TST0001'
    )
    db.session.add(artwork)
    db.session.commit()

    return {'artist_id': 'TSTART01', 'artwork_id': 'TSTAW001'}


class TestArtworkOwnership:
    """Test artwork ownership enforcement for photo uploads."""

    def test_admin_can_upload_to_unlinked_artwork(self, client, admin_user, artist_and_artwork, test_image):
        """Test that admin can upload photos to artworks with no user_id."""
        artwork_id = artist_and_artwork['artwork_id']

        response = client.post(
            f'/api/artworks/{artwork_id}/photos',
            data={
                'photo': (test_image, 'test_admin.jpg'),
            },
            content_type='multipart/form-data'
        )

        assert response.status_code == 201
        assert 'Photo uploaded successfully' in response.json['message']

    def test_regular_user_cannot_upload_to_unlinked_artwork(self, client, regular_user, artist_and_artwork, test_image):
        """Test that non-admin cannot upload to artwork with no user_id (secure default)."""
        artwork_id = artist_and_artwork['artwork_id']

        response = client.post(
            f'/api/artworks/{artwork_id}/photos',
            data={
                'photo': (test_image, 'test_user.jpg'),
            },
            content_type='multipart/form-data'
        )

        assert response.status_code == 403
        assert 'not linked to a user account' in response.json['error']
        assert 'Only admins' in response.json['error']

    def test_owner_can_upload_to_linked_artwork(self, client, regular_user, artist_and_artwork, test_image):
        """Test that artist owner can upload photos to their own artworks."""
        from create_tbls import init_tables
        from models import init_models

        User, _, _ = init_models(db)
        Artist, _, _, _, _, _, _ = init_tables(db)

        # Get the user ID for the logged-in user
        user = User.query.filter_by(email='user@test.com').first()

        # Link artist to user
        artist = Artist.query.get(artist_and_artwork['artist_id'])
        artist.user_id = user.id
        db.session.commit()

        # Now try to upload
        artwork_id = artist_and_artwork['artwork_id']
        test_image.seek(0)  # Reset image buffer

        response = client.post(
            f'/api/artworks/{artwork_id}/photos',
            data={
                'photo': (test_image, 'test_owner.jpg'),
            },
            content_type='multipart/form-data'
        )

        assert response.status_code == 201
        assert 'Photo uploaded successfully' in response.json['message']

    def test_non_owner_cannot_upload_to_linked_artwork(self, client, artist_and_artwork, test_image):
        """Test that non-owner cannot upload to someone else's artwork."""
        from create_tbls import init_tables
        from models import init_models

        User, _, _ = init_models(db)
        Artist, _, _, _, _, _, _ = init_tables(db)

        # Create and login as owner
        client.post('/auth/register', json={
            'email': 'owner@test.com',
            'password': 'OwnerPassword123!',
            'role': 'visitor'
        })
        client.post('/auth/login', json={
            'email': 'owner@test.com',
            'password': 'OwnerPassword123!'
        })
        owner = User.query.filter_by(email='owner@test.com').first()

        # Link artist to owner
        artist = Artist.query.get(artist_and_artwork['artist_id'])
        artist.user_id = owner.id
        db.session.commit()

        # Logout and login as different user
        client.post('/auth/logout')
        client.post('/auth/register', json={
            'email': 'other@test.com',
            'password': 'OtherPassword123!',
            'role': 'visitor'
        })
        client.post('/auth/login', json={
            'email': 'other@test.com',
            'password': 'OtherPassword123!'
        })

        # Try to upload to someone else's artwork
        artwork_id = artist_and_artwork['artwork_id']
        test_image.seek(0)

        response = client.post(
            f'/api/artworks/{artwork_id}/photos',
            data={
                'photo': (test_image, 'test_other.jpg'),
            },
            content_type='multipart/form-data'
        )

        assert response.status_code == 403
        assert 'do not have permission' in response.json['error']


class TestAdminArtistManagement:
    """Test admin endpoints for managing artist-user relationships."""

    def test_admin_can_assign_artist_to_user(self, client, admin_user, artist_and_artwork):
        """Test that admin can link artist to user."""
        from models import init_models

        User, _, _ = init_models(db)

        # Create a user to assign
        client.post('/auth/register', json={
            'email': 'newartist@test.com',
            'password': 'ArtistPassword123!',
            'role': 'visitor'
        })
        user = User.query.filter_by(email='newartist@test.com').first()

        # Admin assigns artist to user
        artist_id = artist_and_artwork['artist_id']
        response = client.post(
            f'/api/admin/artists/{artist_id}/assign-user',
            json={'user_id': user.id}
        )

        assert response.status_code == 200
        assert 'successfully linked' in response.json['message']
        assert response.json['user']['email'] == 'newartist@test.com'

    def test_non_admin_cannot_assign_artist(self, client, regular_user, artist_and_artwork):
        """Test that non-admin cannot assign artists to users."""
        artist_id = artist_and_artwork['artist_id']

        response = client.post(
            f'/api/admin/artists/{artist_id}/assign-user',
            json={'user_id': 1}
        )

        assert response.status_code == 403

    def test_admin_can_unassign_artist(self, client, admin_user, artist_and_artwork):
        """Test that admin can unlink artist from user."""
        from create_tbls import init_tables
        from models import init_models

        User, _, _ = init_models(db)
        Artist, _, _, _, _, _, _ = init_tables(db)

        # Create and link a user
        client.post('/auth/register', json={
            'email': 'unlink@test.com',
            'password': 'UnlinkPassword123!',
            'role': 'visitor'
        })
        user = User.query.filter_by(email='unlink@test.com').first()

        artist = Artist.query.get(artist_and_artwork['artist_id'])
        artist.user_id = user.id
        db.session.commit()

        # Admin unlinks artist
        artist_id = artist_and_artwork['artist_id']
        response = client.post(f'/api/admin/artists/{artist_id}/unassign-user')

        assert response.status_code == 200
        assert 'successfully unlinked' in response.json['message']

        # Verify artist is now unlinked
        artist = Artist.query.get(artist_id)
        assert artist.user_id is None

    def test_assign_to_nonexistent_user_fails(self, client, admin_user, artist_and_artwork):
        """Test that assigning to non-existent user fails gracefully."""
        artist_id = artist_and_artwork['artist_id']

        response = client.post(
            f'/api/admin/artists/{artist_id}/assign-user',
            json={'user_id': 99999}
        )

        assert response.status_code == 404
        assert 'User not found' in response.json['error']

    def test_assign_nonexistent_artist_fails(self, client, admin_user):
        """Test that assigning non-existent artist fails gracefully."""
        response = client.post(
            '/api/admin/artists/NONEXIST/assign-user',
            json={'user_id': 1}
        )

        assert response.status_code == 404
        assert 'Artist not found' in response.json['error']
