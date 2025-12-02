"""Tests for Role-Based Access Control (RBAC) and dynamic rate limiting.

These tests verify:
1. Role normalization (visitor → guest)
2. Permission enforcement for artwork/photo mutations
3. Rate limits based on user identity type
4. Audit logging for RBAC denials
"""
import pytest
from app import app, db, User, Artist, Artwork, Storage, ArtworkPhoto, bcrypt
from datetime import datetime, timezone


@pytest.fixture
def client():
    """Test client with in-memory SQLite database."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['RATELIMIT_ENABLED'] = False

    from app import limiter
    limiter.enabled = False

    with app.test_client(use_cookies=True) as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()


@pytest.fixture
def admin_user(client):
    """Create an admin user."""
    with app.app_context():
        hashed = bcrypt.generate_password_hash('AdminPass123').decode('utf-8')
        user = User(
            email='admin@test.com',
            hashed_password=hashed,
            role='admin',
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(user)
        db.session.commit()
        return {'id': user.id, 'email': user.email, 'password': 'AdminPass123'}


@pytest.fixture
def guest_user(client):
    """Create a guest user."""
    with app.app_context():
        hashed = bcrypt.generate_password_hash('GuestPass123').decode('utf-8')
        user = User(
            email='guest@test.com',
            hashed_password=hashed,
            role='guest',
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(user)
        db.session.commit()
        return {'id': user.id, 'email': user.email, 'password': 'GuestPass123'}


@pytest.fixture
def legacy_visitor_user(client):
    """Create a user with legacy 'visitor' role to test backwards compatibility."""
    with app.app_context():
        hashed = bcrypt.generate_password_hash('VisitorPass123').decode('utf-8')
        user = User(
            email='visitor@test.com',
            hashed_password=hashed,
            role='visitor',  # Legacy role
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(user)
        db.session.commit()
        return {'id': user.id, 'email': user.email, 'password': 'VisitorPass123'}


@pytest.fixture
def artist_with_owner(client, guest_user):
    """Create an artist linked to a guest user."""
    with app.app_context():
        artist = Artist(
            artist_id='A0000001',
            artist_fname='Test',
            artist_lname='Artist',
            artist_email='artist@test.com',
            user_id=guest_user['id']  # Link to guest user
        )
        db.session.add(artist)
        db.session.commit()
        return {
            'id': artist.artist_id,
            'name': f"{artist.artist_fname} {artist.artist_lname}",
            'owner_id': guest_user['id']
        }


@pytest.fixture
def unlinked_artist(client):
    """Create an artist not linked to any user."""
    with app.app_context():
        artist = Artist(
            artist_id='A0000002',
            artist_fname='Unlinked',
            artist_lname='Artist',
            artist_email='unlinked@test.com',
            user_id=None  # Not linked
        )
        db.session.add(artist)
        db.session.commit()
        return {'id': artist.artist_id, 'name': f"{artist.artist_fname} {artist.artist_lname}"}


@pytest.fixture
def storage_location(client):
    """Create a storage location."""
    with app.app_context():
        storage = Storage(
            storage_id='S000001',
            storage_loc='Test Storage',
            storage_type='FlatFile'
        )
        db.session.add(storage)
        db.session.commit()
        return {'id': storage.storage_id}


@pytest.fixture
def owned_artwork(client, artist_with_owner, storage_location):
    """Create an artwork owned by the artist (linked to guest user)."""
    with app.app_context():
        artwork = Artwork(
            artwork_num='AW000001',
            artwork_ttl='Owned Artwork',
            artwork_medium='Oil',
            artist_id=artist_with_owner['id'],
            storage_id=storage_location['id']
        )
        db.session.add(artwork)
        db.session.commit()
        return {'id': artwork.artwork_num, 'title': artwork.artwork_ttl}


@pytest.fixture
def unowned_artwork(client, unlinked_artist, storage_location):
    """Create an artwork from an unlinked artist."""
    with app.app_context():
        artwork = Artwork(
            artwork_num='AW000002',
            artwork_ttl='Unowned Artwork',
            artwork_medium='Acrylic',
            artist_id=unlinked_artist['id'],
            storage_id=storage_location['id']
        )
        db.session.add(artwork)
        db.session.commit()
        return {'id': artwork.artwork_num, 'title': artwork.artwork_ttl}


def login_user(client, email, password):
    """Helper to log in a user."""
    return client.post('/auth/login', json={
        'email': email,
        'password': password
    })


class TestRoleNormalization:
    """Test role normalization from 'visitor' to 'guest'."""

    def test_new_user_gets_guest_role(self, client):
        """New registrations should get 'guest' role, not 'visitor'."""
        response = client.post('/auth/register', json={
            'email': 'newuser@test.com',
            'password': 'NewUserPass123'
        })
        assert response.status_code == 201
        data = response.get_json()
        assert data['user']['role'] == 'guest'

    def test_legacy_visitor_normalized_in_session(self, client, legacy_visitor_user):
        """Login response should normalize 'visitor' to 'guest'."""
        response = login_user(client, legacy_visitor_user['email'], legacy_visitor_user['password'])
        assert response.status_code == 200
        data = response.get_json()
        # Session response should show normalized role
        assert data['user']['role'] == 'guest'

    def test_me_endpoint_normalizes_visitor(self, client, legacy_visitor_user):
        """/auth/me should return normalized 'guest' role."""
        login_user(client, legacy_visitor_user['email'], legacy_visitor_user['password'])
        response = client.get('/auth/me')
        assert response.status_code == 200
        data = response.get_json()
        assert data['user']['role'] == 'guest'

    def test_visitor_not_admin(self, client, legacy_visitor_user):
        """Legacy 'visitor' user should not have admin access."""
        login_user(client, legacy_visitor_user['email'], legacy_visitor_user['password'])
        response = client.get('/auth/admin-only')
        assert response.status_code == 403


class TestArtworkOwnershipRBAC:
    """Test RBAC for artwork mutations."""

    def test_admin_can_update_any_artwork(self, client, admin_user, unowned_artwork):
        """Admins can update any artwork."""
        login_user(client, admin_user['email'], admin_user['password'])
        response = client.put(f'/api/artworks/{unowned_artwork["id"]}', json={
            'title': 'Admin Updated Title'
        })
        assert response.status_code == 200

    def test_owner_can_update_own_artwork(self, client, guest_user, owned_artwork):
        """Artist owners can update their own artworks."""
        login_user(client, guest_user['email'], guest_user['password'])
        response = client.put(f'/api/artworks/{owned_artwork["id"]}', json={
            'title': 'Owner Updated Title'
        })
        assert response.status_code == 200

    def test_guest_cannot_update_unowned_artwork(self, client, guest_user, unowned_artwork):
        """Guests cannot update artworks they don't own."""
        login_user(client, guest_user['email'], guest_user['password'])
        response = client.put(f'/api/artworks/{unowned_artwork["id"]}', json={
            'title': 'Unauthorized Update'
        })
        assert response.status_code == 403

    def test_anonymous_cannot_update_artwork(self, client, owned_artwork):
        """Anonymous users cannot update artworks."""
        response = client.put(f'/api/artworks/{owned_artwork["id"]}', json={
            'title': 'Anonymous Update'
        })
        assert response.status_code == 401

    def test_admin_can_delete_any_artwork(self, client, admin_user, unowned_artwork):
        """Admins can delete any artwork."""
        login_user(client, admin_user['email'], admin_user['password'])
        response = client.delete(f'/api/artworks/{unowned_artwork["id"]}')
        assert response.status_code == 200

    def test_owner_can_delete_own_artwork(self, client, guest_user, owned_artwork):
        """Artist owners can delete their own artworks."""
        login_user(client, guest_user['email'], guest_user['password'])
        response = client.delete(f'/api/artworks/{owned_artwork["id"]}')
        assert response.status_code == 200

    def test_guest_cannot_delete_unowned_artwork(self, client, guest_user, unowned_artwork):
        """Guests cannot delete artworks they don't own."""
        login_user(client, guest_user['email'], guest_user['password'])
        response = client.delete(f'/api/artworks/{unowned_artwork["id"]}')
        assert response.status_code == 403

    def test_rbac_denial_logged(self, client, guest_user, unowned_artwork):
        """RBAC denials should be audit logged."""
        from app import AuditLog
        login_user(client, guest_user['email'], guest_user['password'])
        client.put(f'/api/artworks/{unowned_artwork["id"]}', json={
            'title': 'Unauthorized'
        })

        with app.app_context():
            denial_log = AuditLog.query.filter_by(event_type='rbac_denied').first()
            assert denial_log is not None
            assert 'not_owner' in denial_log.details


class TestAdminOnlyEndpoints:
    """Test endpoints that should remain admin-only."""

    def test_create_artwork_admin_only(self, client, guest_user, artist_with_owner, storage_location):
        """Artwork creation requires admin role."""
        login_user(client, guest_user['email'], guest_user['password'])
        response = client.post('/api/artworks', json={
            'title': 'New Artwork',
            'artist_id': artist_with_owner['id'],
            'storage_id': storage_location['id']
        })
        assert response.status_code == 403

    def test_orphaned_photo_upload_admin_only(self, client, guest_user):
        """Orphaned photo upload requires admin role."""
        login_user(client, guest_user['email'], guest_user['password'])
        # Try to upload without a file (would fail validation anyway)
        response = client.post('/api/photos')
        # Should be 403 (admin required) before file validation
        assert response.status_code == 403

    def test_assign_artist_admin_only(self, client, guest_user, unlinked_artist):
        """Artist-user assignment requires admin role."""
        login_user(client, guest_user['email'], guest_user['password'])
        response = client.post(f'/api/admin/artists/{unlinked_artist["id"]}/assign-user', json={
            'user_id': guest_user['id']
        })
        assert response.status_code == 403


class TestPublicReadEndpoints:
    """Test that public read endpoints remain accessible."""

    def test_anonymous_can_list_artworks(self, client):
        """Anonymous users can list artworks."""
        response = client.get('/api/artworks')
        assert response.status_code == 200

    def test_anonymous_can_view_artwork(self, client, owned_artwork):
        """Anonymous users can view artwork details."""
        response = client.get(f'/api/artworks/{owned_artwork["id"]}')
        assert response.status_code == 200


class TestRateLimitConfiguration:
    """Test rate limit configuration (logic only, not actual limiting)."""

    def test_anonymous_rate_limit_function(self, client):
        """Anonymous users should get 300/min rate limit."""
        from app import get_rate_limit_by_identity
        with app.test_request_context():
            limit = get_rate_limit_by_identity()
            assert limit == "300 per minute"

    def test_guest_rate_limit_function(self, client, guest_user):
        """Logged-in guests should get 500/min rate limit."""
        from app import get_rate_limit_by_identity
        login_user(client, guest_user['email'], guest_user['password'])
        with app.test_request_context():
            # Need to set current_user in context
            from flask_login import login_user as flask_login
            with app.app_context():
                user = User.query.get(guest_user['id'])
                flask_login(user)
                limit = get_rate_limit_by_identity()
                assert limit == "500 per minute"

    def test_admin_rate_limit_function(self, client, admin_user):
        """Admins should get 2000/min rate limit."""
        from app import get_rate_limit_by_identity
        login_user(client, admin_user['email'], admin_user['password'])
        with app.test_request_context():
            from flask_login import login_user as flask_login
            with app.app_context():
                user = User.query.get(admin_user['id'])
                flask_login(user)
                limit = get_rate_limit_by_identity()
                assert limit == "2000 per minute"
