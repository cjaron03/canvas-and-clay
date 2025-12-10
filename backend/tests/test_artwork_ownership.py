"""Tests for artwork ownership and photo upload authorization."""
import pytest
import io
from PIL import Image
import json
from app import app, db, User, Artist, Artwork, Storage
from conftest import find_user_by_email


@pytest.fixture
def client():
    """Create a test client with a fresh database."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}
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

    # Promote the user to admin since registration always defaults to guest
    user = find_user_by_email(User, 'admin@test.com')
    if user:
        user.role = 'admin'
        db.session.commit()

    return response.json


@pytest.fixture
def regular_user(client):
    """Create and log in as regular (non-admin) user."""
    # Register user
    response = client.post('/auth/register', json={
        'email': 'user@test.com',
        'password': 'UserPassword123!',
        'role': 'guest'
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

    # Flush so storage and artist rows exist before inserting artwork (FK safety)
    db.session.flush()

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
        # Get the user ID for the logged-in user
        user = find_user_by_email(User, 'user@test.com')

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
        # Create and login as owner
        client.post('/auth/register', json={
            'email': 'owner@test.com',
            'password': 'OwnerPassword123!',
            'role': 'guest'
        })
        client.post('/auth/login', json={
            'email': 'owner@test.com',
            'password': 'OwnerPassword123!'
        })
        owner = find_user_by_email(User, 'owner@test.com')

        # Link artist to owner
        artist = Artist.query.get(artist_and_artwork['artist_id'])
        artist.user_id = owner.id
        db.session.commit()

        # Logout and login as different user
        client.post('/auth/logout')
        client.post('/auth/register', json={
            'email': 'other@test.com',
            'password': 'OtherPassword123!',
            'role': 'guest'
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
        # Create a user to assign
        client.post('/auth/register', json={
            'email': 'newartist@test.com',
            'password': 'ArtistPassword123!',
            'role': 'guest'
        })
        user = find_user_by_email(User, 'newartist@test.com')

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
        # Create and link a user
        client.post('/auth/register', json={
            'email': 'unlink@test.com',
            'password': 'UnlinkPassword123!',
            'role': 'guest'
        })
        user = find_user_by_email(User, 'unlink@test.com')

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


class TestOrphanedPhotoUploads:
    """Test admin-only orphaned photo uploads."""

    def test_admin_can_upload_orphaned_photo(self, client, admin_user, test_image):
        """Test that admin can upload orphaned photos."""
        response = client.post(
            '/api/photos',
            data={
                'photo': (test_image, 'orphaned_admin.jpg'),
            },
            content_type='multipart/form-data'
        )

        assert response.status_code == 201
        assert 'Photo uploaded successfully' in response.json['message']
        assert 'photo' in response.json
        assert response.json['photo']['filename'] == 'orphaned_admin.jpg'

    def test_regular_user_cannot_upload_orphaned_photo(self, client, regular_user, test_image):
        """Test that non-admin cannot upload orphaned photos (403 Forbidden)."""
        response = client.post(
            '/api/photos',
            data={
                'photo': (test_image, 'orphaned_user.jpg'),
            },
            content_type='multipart/form-data'
        )

        assert response.status_code == 403
        assert 'Admin access required' in response.json['error']

    def test_unauthenticated_cannot_upload_orphaned_photo(self, client, test_image):
        """Test that unauthenticated users cannot upload orphaned photos."""
        response = client.post(
            '/api/photos',
            data={
                'photo': (test_image, 'orphaned_unauth.jpg'),
            },
            content_type='multipart/form-data'
        )

        assert response.status_code == 401
        assert 'error' in response.json

    def test_admin_can_associate_orphaned_photo_with_artwork(self, client, admin_user, artist_and_artwork, test_image):
        """Test that admin can associate an orphaned photo with an artwork."""
        # First, upload an orphaned photo
        upload_response = client.post(
            '/api/photos',
            data={
                'photo': (test_image, 'to_associate.jpg'),
            },
            content_type='multipart/form-data'
        )
        assert upload_response.status_code == 201
        photo_id = upload_response.json['photo']['id']

        # Now associate it with an artwork
        artwork_id = artist_and_artwork['artwork_id']
        associate_response = client.patch(
            f'/api/photos/{photo_id}/associate',
            json={'artwork_id': artwork_id}
        )

        assert associate_response.status_code == 200
        assert 'Photo associated successfully' in associate_response.json['message']
        assert associate_response.json['photo']['artwork_id'] == artwork_id

    def test_regular_user_cannot_associate_orphaned_photo(self, client, admin_user, regular_user, artist_and_artwork, test_image):
        """Test that non-admin cannot associate orphaned photos with artworks."""
        # Logout regular user and login as admin to upload orphaned photo
        client.post('/auth/logout')
        client.post('/auth/login', json={
            'email': 'admin@test.com',
            'password': 'AdminPassword123!'
        })

        # Admin uploads orphaned photo
        upload_response = client.post(
            '/api/photos',
            data={
                'photo': (test_image, 'admin_upload.jpg'),
            },
            content_type='multipart/form-data'
        )
        assert upload_response.status_code == 201
        photo_id = upload_response.json['photo']['id']

        # Logout admin, login as regular user
        client.post('/auth/logout')
        client.post('/auth/login', json={
            'email': 'user@test.com',
            'password': 'UserPassword123!'
        })

        # Regular user tries to associate
        artwork_id = artist_and_artwork['artwork_id']
        associate_response = client.patch(
            f'/api/photos/{photo_id}/associate',
            json={'artwork_id': artwork_id}
        )

        assert associate_response.status_code == 403
        assert 'Admin access required' in associate_response.json['error']

    def test_cannot_associate_already_associated_photo(self, client, admin_user, artist_and_artwork, test_image):
        """Test that photos already associated with artworks cannot be re-associated."""
        # Upload orphaned photo
        upload_response = client.post(
            '/api/photos',
            data={
                'photo': (test_image, 'already_associated.jpg'),
            },
            content_type='multipart/form-data'
        )
        photo_id = upload_response.json['photo']['id']

        # Associate it once
        artwork_id = artist_and_artwork['artwork_id']
        client.patch(
            f'/api/photos/{photo_id}/associate',
            json={'artwork_id': artwork_id}
        )

        # Try to associate again (should fail)
        response = client.patch(
            f'/api/photos/{photo_id}/associate',
            json={'artwork_id': artwork_id}
        )

        assert response.status_code == 400
        assert 'already associated' in response.json['error']

    def test_associate_with_nonexistent_artwork_fails(self, client, admin_user, test_image):
        """Test that associating with non-existent artwork fails gracefully."""
        # Upload orphaned photo
        upload_response = client.post(
            '/api/photos',
            data={
                'photo': (test_image, 'no_artwork.jpg'),
            },
            content_type='multipart/form-data'
        )
        photo_id = upload_response.json['photo']['id']

        # Try to associate with non-existent artwork
        response = client.patch(
            f'/api/photos/{photo_id}/associate',
            json={'artwork_id': 'NONEXIST'}
        )

        assert response.status_code == 404
        assert 'Artwork not found' in response.json['error']

    def test_associate_nonexistent_photo_fails(self, client, admin_user, artist_and_artwork):
        """Test that associating non-existent photo fails gracefully."""
        artwork_id = artist_and_artwork['artwork_id']

        response = client.patch(
            '/api/photos/NOEXIST/associate',
            json={'artwork_id': artwork_id}
        )

        assert response.status_code == 404
        assert 'Photo not found' in response.json['error']
