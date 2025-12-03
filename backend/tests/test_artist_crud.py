""" Tests for artist CRUD endpoints"""
import pytest
from datetime import date
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app, db, User, Artist, Storage, Artwork, AuditLog


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
    """Create test artists and artworks."""
    artist1 = Artist(
        artist_id='ARTIST01',
        artist_fname='Test',
        artist_lname='Testy',
        artist_email='test@artist.com',
        artist_phone='(123)-456-7890'
    )
    artist2 = Artist(
        artist_id='ARTIST02',
        artist_fname='Another',
        artist_lname='Artist',
        artist_email='another@artist.com'
    )
    db.session.add_all([artist1, artist2])
    db.session.flush()

    storage = Storage(
        storage_id='STOR001',
        storage_loc='Test Storage',
        storage_type='Rack'
    )
    db.session.add(storage)
    db.session.flush()

    # Add one artwork linked to artist1
    artwork = Artwork(
        artwork_num='AW111111',
        artwork_ttl='Linked Artwork',
        artist_id='ARTIST01',
        storage_id='STOR001',
        date_created=date(2024, 5, 1)
    )
    db.session.add(artwork)
    db.session.commit()

    return {
        'artist1': artist1,
        'artist2': artist2,
        'storage': storage,
        'artwork': artwork
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


@pytest.fixture
def artist_user(client, test_data):
    """Create, assign, and log in as an artist user owning ARTIST01."""
    client.post('/auth/register', json={
        'email': 'artist-owner@test.com',
        'password': 'ArtistOwnerPass123!'
    })

    user = User.query.filter_by(email='artist-owner@test.com').first()
    user.role = 'artist'
    test_data['artist1'].user_id = user.id
    db.session.commit()

    client.post('/auth/login', json={
        'email': 'artist-owner@test.com',
        'password': 'ArtistOwnerPass123!'
    })

    return user


@pytest.fixture
def artist_user_unassigned(client, test_data):
    """Create an artist user assigned to a different artist."""
    client.post('/auth/register', json={
        'email': 'artist-other@test.com',
        'password': 'ArtistOtherPass123!'
    })

    user = User.query.filter_by(email='artist-other@test.com').first()
    user.role = 'artist'
    test_data['artist2'].user_id = user.id
    db.session.commit()

    client.post('/auth/login', json={
        'email': 'artist-other@test.com',
        'password': 'ArtistOtherPass123!'
    })

    return user


class TestListArtists:
    """ Test GET /api/artists endpoint."""

    def test_list_artists_success(self, client, test_data):
        """ Testing listing artists with default pagination"""
        response = client.get('/api/artists')
        assert response.status_code == 200
        data = response.get_json()
        assert 'artists' in data
        assert 'pagination' in data
        assert len(data['artists']) == 2
        assert data['pagination']['total_filtered_artists'] == 2

    def test_list_artists_pagination(self, client, test_data):
        """Test pagination works correctly."""
        response = client.get('/api/artists?page=1&per_page=1')
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['artists']) == 1
        assert data['pagination']['per_page'] == 1
        assert data['pagination']['total_pages'] == 2
        assert data['pagination']['has_next'] is True

    def test_list_artists_search(self, client, test_data):
        """Test search functionality."""
        response = client.get('/api/artists?search=Testy')

        assert response.status_code == 200
        data = response.get_json()
        assert len(data['artists']) == 1
        assert data['artists'][0]['first_name'] == 'Test'
        assert data['artists'][0]['last_name'] == 'Testy'
   
    def test_list_artists_sort_by_last_name(self, client, test_data):
        """Sort artists alphabetically using ordering parameter."""
        response = client.get('/api/artists?ordering=name_asc')
        data = response.get_json()
        names = [f"{a['first_name']} {a['last_name']}".strip() for a in data['artists']]
        assert names == ['Another Artist', 'Test Testy']


class TestCreateArtist:
    """Test POST /api/artists endpoint"""

    def test_create_artist_success(self, client, admin_user, test_data):
        """Test creating a new artist as admin."""
        response = client.post('/api/artists', json={
            'artist_fname': 'New',
            'artist_lname': 'Guy',
            'artist_bio': 'I am new artist.'
        })

        assert response.status_code == 201
        data = response.get_json()
        assert 'artist' in data
        assert data['artist']['id'].startswith('A')  # Auto-generated ID
        assert len(data['artist']['id']) == 8  # Format: A0000001
        assert data['artist']['artist_fname'] == 'New'
        assert data['artist']['artist_lname'] == 'Guy'

        # Verify audit log
        audit = AuditLog.query.filter_by(event_type='artist_created').first()
        assert audit is not None
        assert audit.user_id == admin_user.id

    def test_create_artist_missing_required_fields(self, client, admin_user, test_data):
        """Test creating artist without required fields."""
        response = client.post('/api/artists', json={
            'artist_fname': 'Incomplete'
        })

        assert response.status_code == 400
        assert 'Missing required fields' in response.get_json()['error']

   
    def test_create_artist_regular_user_forbidden(self, client, regular_user, test_data):
        """Test that regular users cannot create artists."""
        response = client.post('/api/artists', json={
            'artist_fname': 'Unauthorized',
            'artist_lname': 'Regular'
        })

        assert response.status_code == 403

    def test_create_artist_unauthenticated_forbidden(self, client, test_data):
        """Test that unauthenticated users cannot create artists."""
        response = client.post('/api/artists', json={
            'artist_fname': 'Unauth',
            'artist_lname': 'Unauthenticated'
        })

        assert response.status_code == 401


class TestUpdateArtist:
    """Test PUT /api/artists/<id> endpoint."""

    def test_update_artist_success(self, client, admin_user, test_data):
        """Test updating an artist as admin."""
        response = client.put('/api/artists/ARTIST01', json={
            'artist_fname': 'Updated',
            'artist_phone': '(098)-765-4321'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['artist']['artist_fname'] == 'Updated'
        assert data['artist']['artist_phone'] == '(098)-765-4321'

        # Verify audit log
        audit = AuditLog.query.filter_by(event_type='artist_updated').first()
        assert audit is not None
        import json
        details = json.loads(audit.details)
        assert 'artist_fname' in details['changes']    


    def test_update_artist_not_found(self, client, admin_user, test_data):
        """Test updating non-existent artist."""
        response = client.put('/api/artists/NONEXIST', json={
            'artist_fname': 'Not Found'
        })

        assert response.status_code == 404
   
    def test_update_artist_no_changes(self, client, admin_user, test_data):
        """Test updating artist with no actual changes."""
        response = client.put('/api/artists/ARTIST01', json={
            'phone': '(123)-456-7890'  # Same as current
        })

        assert response.status_code == 200
        assert 'No changes detected' in response.get_json()['message']
   
    def test_update_artist_regular_user_forbidden(self, client, regular_user, test_data):
        """Test that regular users cannot update artists."""
        response = client.put('/api/artists/ARTIST01', json={
            'artist_lname': 'Unauthorized Update'
        })

        assert response.status_code == 403

    def test_update_artist_owner_success(self, client, artist_user, test_data):
        """Assigned artist users can update their own records."""
        response = client.put('/api/artists/ARTIST01', json={
            'artist_bio': 'Owner updated bio'
        })

        assert response.status_code == 200
        assert response.get_json()['artist']['artist_bio'] == 'Owner updated bio'

    def test_update_artist_unassigned_artist_forbidden(self, client, artist_user_unassigned, test_data):
        """Artist users cannot update records they do not own."""
        response = client.put('/api/artists/ARTIST01', json={
            'artist_bio': 'Should fail'
        })

        assert response.status_code == 403


class TestRestoreArtist:
    """Test restoring soft-deleted artists."""

    def test_restore_artist_success(self, client, admin_user, test_data):
        """Restore a soft-deleted artist."""
        artist = test_data['artist1']

        # Soft delete artist
        artist.is_deleted = True
        artist.date_deleted = date.today()
        db.session.commit()

        response = client.put(f'/api/artists/{artist.artist_id}/restore')
        assert response.status_code == 200

        data = response.get_json()
        assert data['restored']['artist_id'] == artist.artist_id
        assert data['restored']['artist_name'] == f"{artist.artist_fname} {artist.artist_lname}"
        assert data['restored']['is_deleted'] is False
        assert data['restored']['date_deleted'] is None

        # Verify audit log
        audit = AuditLog.query.filter_by(event_type='deleted_artist_restored').first()
        assert audit is not None
        import json
        details = json.loads(audit.details)
        assert details['artist_id'] == artist.artist_id
        assert details['artist_name'] == f"{artist.artist_fname} {artist.artist_lname}"

    def test_restore_artist_not_deleted(self, client, admin_user, test_data):
        """Try restoring an artist that isn't deleted."""
        artist = test_data['artist2']
        artist.is_deleted = False
        artist.date_deleted = None
        db.session.commit()

        response = client.put(f'/api/artists/{artist.artist_id}/restore')
        assert response.status_code == 404
        assert 'not deleted' in response.get_json()['error'] or 'not found' in response.get_json()['error']

    def test_restore_artist_not_found(self, client, admin_user):
        """Restore a non-existent artist."""
        response = client.put('/api/artists/NONEXIST/restore')
        assert response.status_code == 404
        assert 'not found' in response.get_json()['error']


class TestDeleteArtist:
    """Test DELETE /api/artists/<id> endpoint."""
    def test_delete_artist_success(self, client, admin_user, test_data):
        """Deleting artist with no artworks."""
        response = client.delete('/api/artists/ARTIST02')
        assert response.status_code == 200
        data = response.get_json()
        assert data['deleted']['artist_id'] == 'ARTIST02'

        # Verify artist is deleted
        artist = Artist.query.get('ARTIST02')
        assert artist.is_deleted is True

        # Verify audit log
        audit = AuditLog.query.filter_by(event_type='artist_deleted').first()
        assert audit is not None
        import json
        details = json.loads(audit.details)
        assert details['artist_id'] == 'ARTIST02'

    def test_delete_artist_with_dependencies(self, client, admin_user, test_data):
        """Deleting artist with artwork dependencies - should prevent."""
        response = client.delete('/api/artists/ARTIST01')

        assert response.status_code == 400
   
    def test_delete_artist_not_found(self, client, admin_user, test_data):
        """Test deleting non-existent artist."""
        response = client.delete('/api/artists/NONEXIST')

        assert response.status_code == 404
   
    def test_delete_artist_regular_user_forbidden(self, client, regular_user, test_data):
        """Test that regular users cannot delete artists."""
        response = client.delete('/api/artists/ARTIST01')

        assert response.status_code == 403
   
    def test_delete_artist_unauthenticated_forbidden(self, client, test_data):
        """Test that unauthenticated users cannot delete artists."""
        response = client.delete('/api/artists/ARTIST01')

        assert response.status_code == 401
