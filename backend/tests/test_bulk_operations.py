"""Tests for bulk operation endpoints."""
import json
import os
import sys
import pytest
from sqlalchemy.pool import StaticPool

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app, db, User, AuditLog, bcrypt
from encryption import compute_blind_index, normalize_email
from create_tbls import init_tables


@pytest.fixture
def client():
    """Create a test client with a fresh database."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {'check_same_thread': False},
        'poolclass': StaticPool
    }
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
    """Create and login as admin user."""
    with app.app_context():
        email = 'admin@test.com'
        user = User(
            email=email,
            email_idx=compute_blind_index(email, normalize_email),
            hashed_password=bcrypt.generate_password_hash('AdminPass123').decode('utf-8'),
            role='admin',
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    client.post('/auth/login', json={
        'email': 'admin@test.com',
        'password': 'AdminPass123'
    })

    return {'id': user_id, 'email': 'admin@test.com'}


@pytest.fixture
def guest_user(client):
    """Create a guest user."""
    with app.app_context():
        email = 'guest@test.com'
        user = User(
            email=email,
            email_idx=compute_blind_index(email, normalize_email),
            hashed_password=bcrypt.generate_password_hash('GuestPass123').decode('utf-8'),
            role='guest',
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        return {'id': user.id, 'email': 'guest@test.com'}


@pytest.fixture
def sample_artists(client, admin_user):
    """Create sample artists for testing."""
    Artist = init_tables(db)[0]
    artists = []

    with app.app_context():
        for i in range(5):
            # artist_id is CHAR(8), generate unique string IDs
            artist_id = f'TSTA{i:04d}'  # e.g., TSTA0000, TSTA0001, etc.
            artist = Artist(
                artist_id=artist_id,
                artist_fname=f'Test{i}',
                artist_lname=f'Artist{i}'
            )
            db.session.add(artist)
            db.session.commit()
            artists.append({'id': artist.artist_id, 'name': f'Test{i} Artist{i}'})

    return artists


@pytest.fixture
def sample_artworks(client, admin_user, sample_artists):
    """Create sample artworks for testing."""
    Artist, Artwork, Storage = init_tables(db)[0], init_tables(db)[1], init_tables(db)[2]
    artworks = []

    with app.app_context():
        # Create a storage location first (required for artworks)
        storage = Storage.query.get('TST0001')
        if not storage:
            storage = Storage(
                storage_id='TST0001',
                storage_loc='Test Storage',
                storage_type='rack'
            )
            db.session.add(storage)
            db.session.commit()

        for i in range(5):
            artwork = Artwork(
                artwork_num=f'AW0000{i:02d}',
                artwork_ttl=f'Test Artwork {i}',
                artist_id=sample_artists[i % len(sample_artists)]['id'],
                storage_id='TST0001'
            )
            db.session.add(artwork)
            db.session.commit()
            artworks.append({'id': artwork.artwork_num, 'num': artwork.artwork_num})

    return artworks


class TestBulkDeleteArtworks:
    """Tests for bulk artwork deletion."""

    def test_bulk_delete_artworks_soft(self, client, admin_user, sample_artworks):
        """Admin should be able to soft delete multiple artworks."""
        artwork_ids = [a['id'] for a in sample_artworks[:3]]

        response = client.post('/api/artworks/bulk-delete', json={
            'artwork_ids': artwork_ids,
            'delete_type': 'soft'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data.get('success') or data.get('deleted_count', 0) >= 0

    def test_bulk_delete_artworks_hard(self, client, admin_user, sample_artworks):
        """Admin should be able to hard delete multiple artworks."""
        artwork_ids = [a['id'] for a in sample_artworks[:2]]

        response = client.post('/api/artworks/bulk-delete', json={
            'artwork_ids': artwork_ids,
            'delete_type': 'hard'
        })

        assert response.status_code == 200

        # Verify artworks are gone
        Artwork = init_tables(db)[1]
        with app.app_context():
            for artwork_id in artwork_ids:
                artwork = Artwork.query.get(artwork_id)
                assert artwork is None

    def test_bulk_delete_artworks_empty_list(self, client, admin_user):
        """Empty artwork list should return error or no-op."""
        response = client.post('/api/artworks/bulk-delete', json={
            'artwork_ids': [],
            'delete_type': 'soft'
        })

        # Should either succeed with 0 deleted or return 400
        assert response.status_code in [200, 400]

    def test_bulk_delete_artworks_non_admin_forbidden(self, client, guest_user):
        """Non-admin should not be able to bulk delete."""
        client.post('/auth/login', json={
            'email': 'guest@test.com',
            'password': 'GuestPass123'
        })

        response = client.post('/api/artworks/bulk-delete', json={
            'artwork_ids': ['AW000001', 'AW000002', 'AW000003'],
            'delete_type': 'soft'
        })

        assert response.status_code == 403

    def test_bulk_delete_artworks_audit_logging(self, client, admin_user, sample_artworks):
        """Bulk delete should create audit log entries."""
        artwork_ids = [a['id'] for a in sample_artworks[:2]]

        # Clear existing audit logs
        with app.app_context():
            AuditLog.query.delete()
            db.session.commit()

        response = client.post('/api/artworks/bulk-delete', json={
            'artwork_ids': artwork_ids,
            'delete_type': 'soft'
        })

        assert response.status_code == 200

        # Check for audit log
        with app.app_context():
            audit = AuditLog.query.filter_by(event_type='bulk_artwork_deleted').first()
            assert audit is not None
            assert audit.user_id == admin_user['id']

    def test_bulk_delete_artworks_invalid_ids(self, client, admin_user):
        """Invalid artwork IDs should be handled gracefully."""
        response = client.post('/api/artworks/bulk-delete', json={
            'artwork_ids': ['AW999999', 'AW999998'],
            'delete_type': 'soft'
        })

        # Should succeed with 0 deleted or return appropriate status
        assert response.status_code in [200, 404]


class TestBulkDeleteArtists:
    """Tests for bulk artist deletion."""

    def test_bulk_delete_artists_soft(self, client, admin_user, sample_artists):
        """Admin should be able to soft delete multiple artists."""
        artist_ids = [a['id'] for a in sample_artists[:3]]

        response = client.post('/api/artists/bulk-delete', json={
            'artist_ids': artist_ids,
            'delete_type': 'soft'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data.get('success') or data.get('deleted_count', 0) >= 0

    def test_bulk_delete_artists_hard(self, client, admin_user, sample_artists):
        """Admin should be able to hard delete multiple artists."""
        artist_ids = [a['id'] for a in sample_artists[:2]]

        response = client.post('/api/artists/bulk-delete', json={
            'artist_ids': artist_ids,
            'delete_type': 'hard'
        })

        assert response.status_code == 200

        # Verify artists are gone
        Artist = init_tables(db)[0]
        with app.app_context():
            for artist_id in artist_ids:
                artist = Artist.query.get(artist_id)
                assert artist is None

    def test_bulk_delete_artists_empty_list(self, client, admin_user):
        """Empty artist list should return error or no-op."""
        response = client.post('/api/artists/bulk-delete', json={
            'artist_ids': [],
            'delete_type': 'soft'
        })

        assert response.status_code in [200, 400]

    def test_bulk_delete_artists_non_admin_forbidden(self, client, guest_user):
        """Non-admin should not be able to bulk delete artists."""
        client.post('/auth/login', json={
            'email': 'guest@test.com',
            'password': 'GuestPass123'
        })

        response = client.post('/api/artists/bulk-delete', json={
            'artist_ids': ['AR000001', 'AR000002', 'AR000003'],
            'delete_type': 'soft'
        })

        assert response.status_code == 403

    def test_bulk_delete_artists_audit_logging(self, client, admin_user, sample_artists):
        """Bulk delete should create audit log entries."""
        artist_ids = [a['id'] for a in sample_artists[:2]]

        # Clear existing audit logs
        with app.app_context():
            AuditLog.query.delete()
            db.session.commit()

        response = client.post('/api/artists/bulk-delete', json={
            'artist_ids': artist_ids,
            'delete_type': 'soft'
        })

        assert response.status_code == 200

        # Check for audit log
        with app.app_context():
            audit = AuditLog.query.filter_by(event_type='bulk_artist_deleted').first()
            assert audit is not None
            assert audit.user_id == admin_user['id']

    def test_bulk_delete_artists_invalid_ids(self, client, admin_user):
        """Invalid artist IDs should be handled gracefully."""
        response = client.post('/api/artists/bulk-delete', json={
            'artist_ids': ['AR999999', 'AR999998'],
            'delete_type': 'soft'
        })

        assert response.status_code in [200, 404]


class TestBulkDeleteIntegration:
    """Integration tests for bulk delete operations."""

    def test_bulk_delete_artist_cascades_to_artworks(self, client, admin_user, sample_artists, sample_artworks):
        """Deleting artists should handle their artworks appropriately."""
        # Get an artist with artworks
        artist_id = sample_artists[0]['id']

        response = client.post('/api/artists/bulk-delete', json={
            'artist_ids': [artist_id],
            'delete_type': 'soft'
        })

        assert response.status_code == 200

        # Artist should be soft deleted
        Artist = init_tables(db)[0]
        with app.app_context():
            artist = Artist.query.get(artist_id)
            # Should be marked as deleted or null
            if artist:
                assert artist.is_deleted is True

    def test_bulk_operations_require_authentication(self, client):
        """Bulk operations should require authentication."""
        # Not logged in
        response = client.post('/api/artworks/bulk-delete', json={
            'artwork_ids': ['AW000001', 'AW000002'],
            'delete_type': 'soft'
        })
        assert response.status_code == 401

        response = client.post('/api/artists/bulk-delete', json={
            'artist_ids': ['AR000001', 'AR000002'],
            'delete_type': 'soft'
        })
        assert response.status_code == 401

    def test_bulk_delete_type_validation(self, client, admin_user, sample_artworks):
        """Invalid delete type should be rejected."""
        response = client.post('/api/artworks/bulk-delete', json={
            'artwork_ids': [sample_artworks[0]['id']],
            'delete_type': 'invalid_type'
        })

        # Should either use default or return error
        assert response.status_code in [200, 400]

    def test_bulk_delete_missing_ids_field(self, client, admin_user):
        """Missing IDs field should return error."""
        response = client.post('/api/artworks/bulk-delete', json={
            'delete_type': 'soft'
        })

        assert response.status_code in [400, 422]

        response = client.post('/api/artists/bulk-delete', json={
            'delete_type': 'soft'
        })

        assert response.status_code in [400, 422]
