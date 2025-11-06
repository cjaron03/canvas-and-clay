"""Tests for artwork CRUD endpoints."""
import pytest
from datetime import date
from app import app, db, User, Artist, Artwork, Storage, ArtworkPhoto, AuditLog


@pytest.fixture
def client():
    """Create a test client with a fresh database."""
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
def test_data(client):
    """Create test artists, storage, and artworks."""
    # Create storage locations (unique IDs to avoid conflicts with other test fixtures)
    storage1 = Storage(storage_id='CRUD001', storage_loc='Test Rack 1', storage_type='rack')
    storage2 = Storage(storage_id='CRUD002', storage_loc='Test Rack 2', storage_type='rack')
    db.session.add_all([storage1, storage2])

    # Create artists (unique IDs to avoid conflicts with other test fixtures)
    artist1 = Artist(
        artist_id='CRUDART1',
        artist_fname='Test',
        artist_lname='Artist',
        artist_email='test@artist.com'
    )
    artist2 = Artist(
        artist_id='CRUDART2',
        artist_fname='Another',
        artist_lname='Artist',
        artist_email='another@artist.com'
    )
    db.session.add_all([artist1, artist2])
    db.session.flush()

    # Create some artworks (unique IDs to avoid conflicts with other test fixtures)
    artwork1 = Artwork(
        artwork_num='CRUDAW01',
        artwork_ttl='Test Artwork 1',
        artwork_medium='Oil on Canvas',
        artwork_size='24x36in',
        date_created=date(2024, 1, 1),
        artist_id='CRUDART1',
        storage_id='CRUD001'
    )
    artwork2 = Artwork(
        artwork_num='CRUDAW02',
        artwork_ttl='Test Artwork 2',
        artwork_medium='Watercolor',
        artist_id='CRUDART2',
        storage_id='CRUD002'
    )
    db.session.add_all([artwork1, artwork2])
    db.session.commit()

    return {
        'storage1': storage1,
        'storage2': storage2,
        'artist1': artist1,
        'artist2': artist2,
        'artwork1': artwork1,
        'artwork2': artwork2
    }


@pytest.fixture
def admin_user(client):
    """Create and log in as admin user."""
    client.post('/auth/register', json={
        'email': 'admin@test.com',
        'password': 'AdminPassword123!'
    })

    user = User.query.filter_by(email='admin@test.com').first()
    user.role = 'admin'
    db.session.commit()

    client.post('/auth/login', json={
        'email': 'admin@test.com',
        'password': 'AdminPassword123!'
    })

    return user


@pytest.fixture
def regular_user(client):
    """Create and log in as regular user."""
    client.post('/auth/register', json={
        'email': 'user@test.com',
        'password': 'UserPassword123!'
    })

    client.post('/auth/login', json={
        'email': 'user@test.com',
        'password': 'UserPassword123!'
    })

    return User.query.filter_by(email='user@test.com').first()


class TestListArtworks:
    """Test GET /api/artworks endpoint."""

    def test_list_artworks_success(self, client, test_data):
        """Test listing artworks with default pagination."""
        response = client.get('/api/artworks')

        assert response.status_code == 200
        data = response.json
        assert 'artworks' in data
        assert 'pagination' in data
        assert len(data['artworks']) == 2
        assert data['pagination']['total'] == 2

    def test_list_artworks_pagination(self, client, test_data):
        """Test pagination works correctly."""
        response = client.get('/api/artworks?page=1&per_page=1')

        assert response.status_code == 200
        data = response.json
        assert len(data['artworks']) == 1
        assert data['pagination']['per_page'] == 1
        assert data['pagination']['total_pages'] == 2
        assert data['pagination']['has_next'] is True

    def test_list_artworks_search(self, client, test_data):
        """Test search functionality."""
        response = client.get('/api/artworks?search=Watercolor')

        assert response.status_code == 200
        data = response.json
        assert len(data['artworks']) == 1
        assert data['artworks'][0]['medium'] == 'Watercolor'

    def test_list_artworks_filter_by_artist(self, client, test_data):
        """Test filtering by artist ID."""
        response = client.get('/api/artworks?artist_id=CRUDART1')

        assert response.status_code == 200
        data = response.json
        assert len(data['artworks']) == 1
        assert data['artworks'][0]['artist']['id'] == 'CRUDART1'

    def test_list_artworks_filter_by_medium(self, client, test_data):
        """Test filtering by medium."""
        response = client.get('/api/artworks?medium=Oil')

        assert response.status_code == 200
        data = response.json
        assert len(data['artworks']) == 1
        assert 'Oil' in data['artworks'][0]['medium']


class TestGetArtwork:
    """Test GET /api/artworks/<id> endpoint."""

    def test_get_artwork_success(self, client, test_data):
        """Test getting artwork details."""
        response = client.get('/api/artworks/CRUDAW01')

        assert response.status_code == 200
        data = response.json
        assert data['id'] == 'CRUDAW01'
        assert data['title'] == 'Test Artwork 1'
        assert data['artist']['name'] == 'Test Artist'
        assert data['storage']['location'] == 'Test Rack 1'

    def test_get_artwork_not_found(self, client, test_data):
        """Test getting non-existent artwork."""
        response = client.get('/api/artworks/NONEXIST')

        assert response.status_code == 404
        assert 'not found' in response.json['error']


class TestCreateArtwork:
    """Test POST /api/artworks endpoint."""

    def test_create_artwork_success(self, client, admin_user, test_data):
        """Test creating a new artwork as admin."""
        response = client.post('/api/artworks', json={
            'title': 'New Artwork',
            'artist_id': 'CRUDART1',
            'storage_id': 'CRUD001',
            'medium': 'Acrylic',
            'artwork_size': '12x16in',
            'date_created': '2024-06-01'
        })

        assert response.status_code == 201
        data = response.json
        assert 'artwork' in data
        assert data['artwork']['id'].startswith('AW')  # Auto-generated ID
        assert len(data['artwork']['id']) == 8  # Format: AW000001
        assert data['artwork']['title'] == 'New Artwork'

        # Verify audit log
        audit = AuditLog.query.filter_by(event_type='artwork_created').first()
        assert audit is not None
        assert audit.user_id == admin_user.id

    def test_create_artwork_missing_required_fields(self, client, admin_user, test_data):
        """Test creating artwork without required fields."""
        response = client.post('/api/artworks', json={
            'title': 'Incomplete Artwork'
        })

        assert response.status_code == 400
        assert 'Missing required fields' in response.json['error']

    def test_create_artwork_invalid_artist(self, client, admin_user, test_data):
        """Test creating artwork with non-existent artist."""
        response = client.post('/api/artworks', json={
            'title': 'Bad Artist',
            'artist_id': 'NOEXIST',
            'storage_id': 'CRUD001'
        })

        assert response.status_code == 404
        assert 'Artist not found' in response.json['error']

    def test_create_artwork_invalid_storage(self, client, admin_user, test_data):
        """Test creating artwork with non-existent storage."""
        response = client.post('/api/artworks', json={
            'title': 'Bad Storage',
            'artist_id': 'CRUDART1',
            'storage_id': 'NOEXIST'
        })

        assert response.status_code == 404
        assert 'Storage location not found' in response.json['error']

    def test_create_artwork_regular_user_forbidden(self, client, regular_user, test_data):
        """Test that regular users cannot create artworks."""
        response = client.post('/api/artworks', json={
            'title': 'Unauthorized',
            'artist_id': 'CRUDART1',
            'storage_id': 'CRUD001'
        })

        assert response.status_code == 403

    def test_create_artwork_unauthenticated_forbidden(self, client, test_data):
        """Test that unauthenticated users cannot create artworks."""
        response = client.post('/api/artworks', json={
            'title': 'Unauth',
            'artist_id': 'CRUDART1',
            'storage_id': 'CRUD001'
        })

        assert response.status_code == 401


class TestUpdateArtwork:
    """Test PUT /api/artworks/<id> endpoint."""

    def test_update_artwork_success(self, client, admin_user, test_data):
        """Test updating an artwork as admin."""
        response = client.put('/api/artworks/CRUDAW01', json={
            'title': 'Updated Title',
            'medium': 'Updated Medium'
        })

        assert response.status_code == 200
        data = response.json
        assert data['artwork']['title'] == 'Updated Title'
        assert data['artwork']['medium'] == 'Updated Medium'

        # Verify audit log
        audit = AuditLog.query.filter_by(event_type='artwork_updated').first()
        assert audit is not None
        import json
        details = json.loads(audit.details)
        assert 'title' in details['changes']

    def test_update_artwork_not_found(self, client, admin_user, test_data):
        """Test updating non-existent artwork."""
        response = client.put('/api/artworks/NONEXIST', json={
            'title': 'Not Found'
        })

        assert response.status_code == 404

    def test_update_artwork_no_changes(self, client, admin_user, test_data):
        """Test updating artwork with no actual changes."""
        response = client.put('/api/artworks/CRUDAW01', json={
            'title': 'Test Artwork 1'  # Same as current
        })

        assert response.status_code == 200
        assert 'No changes detected' in response.json['message']

    def test_update_artwork_regular_user_forbidden(self, client, regular_user, test_data):
        """Test that regular users cannot update artworks."""
        response = client.put('/api/artworks/CRUDAW01', json={
            'title': 'Unauthorized Update'
        })

        assert response.status_code == 403


class TestDeleteArtwork:
    """Test DELETE /api/artworks/<id> endpoint."""

    def test_delete_artwork_success(self, client, admin_user, test_data):
        """Test deleting an artwork as admin."""
        response = client.delete('/api/artworks/CRUDAW01')

        assert response.status_code == 200
        data = response.json
        assert 'deleted' in data
        assert data['deleted']['artwork_id'] == 'CRUDAW01'

        # Verify artwork is deleted
        artwork = Artwork.query.get('CRUDAW01')
        assert artwork is None

        # Verify audit log
        audit = AuditLog.query.filter_by(event_type='artwork_deleted').first()
        assert audit is not None
        import json
        details = json.loads(audit.details)
        assert details['artwork_id'] == 'CRUDAW01'

    def test_delete_artwork_not_found(self, client, admin_user, test_data):
        """Test deleting non-existent artwork."""
        response = client.delete('/api/artworks/NONEXIST')

        assert response.status_code == 404

    def test_delete_artwork_regular_user_forbidden(self, client, regular_user, test_data):
        """Test that regular users cannot delete artworks."""
        response = client.delete('/api/artworks/CRUDAW01')

        assert response.status_code == 403

    def test_delete_artwork_unauthenticated_forbidden(self, client, test_data):
        """Test that unauthenticated users cannot delete artworks."""
        response = client.delete('/api/artworks/CRUDAW01')

        assert response.status_code == 401
