"""
Tests for artist artwork deletion functionality.

This module tests:
- Artist can soft delete their own artwork
- Artist can force hard delete their own artwork
- Artist cannot delete other artist's artwork
- Artist can restore their own soft-deleted artwork
- Artist cannot restore other artist's artwork
- Second delete performs hard delete
- Force delete deletes all photos
- include_deleted query parameter works
"""

import pytest
import json
import sys
import os
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app, db


@pytest.fixture
def client():
    """Create a test client with a fresh database."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}
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
def artist_user_1(client):
    """Create first artist user with linked artist profile."""
    from app import User
    from create_tbls import init_tables
    Artist, _, _, _, _, _, _ = init_tables(db)

    # Register artist user
    client.post('/auth/register', json={
        'email': 'artist1@test.com',
        'password': 'Artist1Pass123!'
    })

    # Update role to artist
    user = User.query.filter_by(email='artist1@test.com').first()
    user.role = 'artist'
    db.session.commit()

    # Create linked artist
    artist = Artist(
        artist_id='ART001',
        artist_fname='Artist',
        artist_lname='One',
        user_id=user.id,
        is_deleted=False
    )
    db.session.add(artist)
    db.session.commit()

    return user, artist


@pytest.fixture
def artist_user_2(client):
    """Create second artist user with linked artist profile."""
    from app import User
    from create_tbls import init_tables
    Artist, _, _, _, _, _, _ = init_tables(db)

    # Register artist user
    client.post('/auth/register', json={
        'email': 'artist2@test.com',
        'password': 'Artist2Pass123!'
    })

    # Update role to artist
    user = User.query.filter_by(email='artist2@test.com').first()
    user.role = 'artist'
    db.session.commit()

    # Create linked artist
    artist = Artist(
        artist_id='ART002',
        artist_fname='Artist',
        artist_lname='Two',
        user_id=user.id,
        is_deleted=False
    )
    db.session.add(artist)
    db.session.commit()

    return user, artist


@pytest.fixture
def artwork_for_artist_1(artist_user_1):
    """Create an artwork for artist 1."""
    from create_tbls import init_tables
    Artist, Artwork, Storage, _, _, _, _ = init_tables(db)

    user, artist = artist_user_1

    # Cleanup
    Artwork.query.filter_by(artwork_num='AW-TEST-001').delete()
    Storage.query.filter_by(storage_id='ST-TEST-001').delete()
    db.session.commit()

    # Create storage
    storage = Storage(
        storage_id='ST-TEST-001',
        storage_loc='Test Location',
        storage_type='flat_file'
    )
    db.session.add(storage)
    db.session.commit()

    # Create artwork
    artwork = Artwork(
        artwork_num='AW-TEST-001',
        artwork_ttl='Test Artwork 1',
        artist_id='ART001',
        storage_id='ST-TEST-001',
        is_deleted=False
    )
    db.session.add(artwork)
    db.session.commit()

    return artwork


@pytest.fixture
def soft_deleted_artwork(artist_user_1):
    """Create a soft-deleted artwork for artist 1."""
    from create_tbls import init_tables
    Artist, Artwork, Storage, _, _, _, _ = init_tables(db)

    user, artist = artist_user_1

    # Cleanup
    Artwork.query.filter_by(artwork_num='AW-TEST-002').delete()
    Storage.query.filter_by(storage_id='ST-TEST-002').delete()
    db.session.commit()

    # Create storage
    storage = Storage(
        storage_id='ST-TEST-002',
        storage_loc='Test Location 2',
        storage_type='flat_file'
    )
    db.session.add(storage)
    db.session.commit()

    # Create soft-deleted artwork
    artwork = Artwork(
        artwork_num='AW-TEST-002',
        artwork_ttl='Test Artwork 2',
        artist_id='ART001',
        storage_id='ST-TEST-002',
        is_deleted=True,
        date_deleted=date.today()
    )
    db.session.add(artwork)
    db.session.commit()

    return artwork


def login_as_user(client, email, password):
    """Helper to login as a user."""
    # Get CSRF token
    csrf_response = client.get('/auth/csrf-token')
    csrf_token = csrf_response.get_json()['csrf_token']

    # Login
    response = client.post('/auth/login', json={
        'email': email,
        'password': password
    }, headers={'X-CSRFToken': csrf_token})

    return response


def test_artist_can_soft_delete_own_artwork(client, artist_user_1, artwork_for_artist_1):
    """Test that an artist can soft delete their own artwork."""
    user, artist = artist_user_1

    # Login as artist 1
    login_as_user(client, 'artist1@test.com', 'Artist1Pass123!')

    # Get CSRF token
    csrf_response = client.get('/auth/csrf-token')
    csrf_token = csrf_response.get_json()['csrf_token']

    # Delete artwork (soft delete)
    response = client.delete(
        f'/api/artworks/{artwork_for_artist_1.artwork_num}',
        headers={'X-CSRFToken': csrf_token}
    )

    assert response.status_code == 200
    data = response.get_json()
    assert 'deleted' in data
    assert data['deleted']['deletion_type'] == 'Soft-deleted'
    assert data['deleted']['artwork_id'] == artwork_for_artist_1.artwork_num

    # Verify artwork is soft deleted
    from create_tbls import init_tables
    _, Artwork, _, _, _, _, _ = init_tables(db)
    artwork = Artwork.query.get(artwork_for_artist_1.artwork_num)
    assert artwork is not None
    assert artwork.is_deleted is True
    assert artwork.date_deleted is not None


def test_artist_can_force_hard_delete_own_artwork(client, artist_user_1, artwork_for_artist_1):
    """Test that an artist can force hard delete their own artwork."""
    user, artist = artist_user_1

    # Login as artist 1
    login_as_user(client, 'artist1@test.com', 'Artist1Pass123!')

    # Get CSRF token
    csrf_response = client.get('/auth/csrf-token')
    csrf_token = csrf_response.get_json()['csrf_token']

    # Force delete artwork
    response = client.delete(
        f'/api/artworks/{artwork_for_artist_1.artwork_num}?force=true',
        headers={'X-CSRFToken': csrf_token}
    )

    assert response.status_code == 200
    data = response.get_json()
    assert 'deleted' in data
    assert data['deleted']['deletion_type'] == 'Force-hard-deleted'
    assert data['deleted']['artwork_id'] == artwork_for_artist_1.artwork_num

    # Verify artwork is hard deleted
    from create_tbls import init_tables
    _, Artwork, _, _, _, _, _ = init_tables(db)
    artwork = Artwork.query.get(artwork_for_artist_1.artwork_num)
    assert artwork is None


def test_artist_cannot_delete_other_artist_artwork(client, artist_user_1, artist_user_2, artwork_for_artist_1):
    """Test that an artist cannot delete another artist's artwork."""
    user2, artist2 = artist_user_2

    # Login as artist 2
    login_as_user(client, 'artist2@test.com', 'Artist2Pass123!')

    # Get CSRF token
    csrf_response = client.get('/auth/csrf-token')
    csrf_token = csrf_response.get_json()['csrf_token']

    # Try to delete artist 1's artwork
    response = client.delete(
        f'/api/artworks/{artwork_for_artist_1.artwork_num}',
        headers={'X-CSRFToken': csrf_token}
    )

    assert response.status_code == 403
    data = response.get_json()
    assert 'error' in data

    # Verify artwork is NOT deleted
    from create_tbls import init_tables
    _, Artwork, _, _, _, _, _ = init_tables(db)
    artwork = Artwork.query.get(artwork_for_artist_1.artwork_num)
    assert artwork is not None
    assert artwork.is_deleted is False


def test_artist_can_restore_own_soft_deleted_artwork(client, artist_user_1, soft_deleted_artwork):
    """Test that an artist can restore their own soft-deleted artwork."""
    user, artist = artist_user_1

    # Login as artist 1
    login_as_user(client, 'artist1@test.com', 'Artist1Pass123!')

    # Get CSRF token
    csrf_response = client.get('/auth/csrf-token')
    csrf_token = csrf_response.get_json()['csrf_token']

    # Restore artwork
    response = client.put(
        f'/api/artworks/{soft_deleted_artwork.artwork_num}/restore',
        headers={'X-CSRFToken': csrf_token}
    )

    assert response.status_code == 200
    data = response.get_json()
    assert 'restored' in data
    assert data['restored']['artwork_id'] == soft_deleted_artwork.artwork_num

    # Verify artwork is restored
    from create_tbls import init_tables
    _, Artwork, _, _, _, _, _ = init_tables(db)
    artwork = Artwork.query.get(soft_deleted_artwork.artwork_num)
    assert artwork is not None
    assert artwork.is_deleted is False
    assert artwork.date_deleted is None


def test_artist_cannot_restore_other_artist_artwork(client, artist_user_1, artist_user_2, soft_deleted_artwork):
    """Test that an artist cannot restore another artist's artwork."""
    user2, artist2 = artist_user_2

    # Login as artist 2
    login_as_user(client, 'artist2@test.com', 'Artist2Pass123!')

    # Get CSRF token
    csrf_response = client.get('/auth/csrf-token')
    csrf_token = csrf_response.get_json()['csrf_token']

    # Try to restore artist 1's artwork
    response = client.put(
        f'/api/artworks/{soft_deleted_artwork.artwork_num}/restore',
        headers={'X-CSRFToken': csrf_token}
    )

    assert response.status_code == 403
    data = response.get_json()
    assert 'error' in data

    # Verify artwork is still soft-deleted
    from create_tbls import init_tables
    _, Artwork, _, _, _, _, _ = init_tables(db)
    artwork = Artwork.query.get(soft_deleted_artwork.artwork_num)
    assert artwork is not None
    assert artwork.is_deleted is True


def test_second_delete_performs_hard_delete(client, artist_user_1, soft_deleted_artwork):
    """Test that deleting a soft-deleted artwork performs hard delete."""
    user, artist = artist_user_1

    # Login as artist 1
    login_as_user(client, 'artist1@test.com', 'Artist1Pass123!')

    # Get CSRF token
    csrf_response = client.get('/auth/csrf-token')
    csrf_token = csrf_response.get_json()['csrf_token']

    # Delete already soft-deleted artwork (should hard delete)
    response = client.delete(
        f'/api/artworks/{soft_deleted_artwork.artwork_num}',
        headers={'X-CSRFToken': csrf_token}
    )

    assert response.status_code == 200
    data = response.get_json()
    assert 'deleted' in data
    assert data['deleted']['deletion_type'] == 'Hard-deleted'
    assert data['deleted']['artwork_id'] == soft_deleted_artwork.artwork_num

    # Verify artwork is hard deleted
    from create_tbls import init_tables
    _, Artwork, _, _, _, _, _ = init_tables(db)
    artwork = Artwork.query.get(soft_deleted_artwork.artwork_num)
    assert artwork is None


def test_include_deleted_query_parameter(client, artist_user_1, artwork_for_artist_1, soft_deleted_artwork):
    """Test that include_deleted parameter returns soft-deleted artworks."""
    user, artist = artist_user_1

    # Login as artist 1
    login_as_user(client, 'artist1@test.com', 'Artist1Pass123!')

    # Get artworks without include_deleted (should only get active)
    response = client.get('/api/artworks?owned=true')
    assert response.status_code == 200
    data = response.get_json()
    artwork_ids = [aw['id'] for aw in data['artworks']]
    assert artwork_for_artist_1.artwork_num in artwork_ids
    assert soft_deleted_artwork.artwork_num not in artwork_ids

    # Get artworks with include_deleted=true (should get all)
    response = client.get('/api/artworks?owned=true&include_deleted=true')
    assert response.status_code == 200
    data = response.get_json()
    artwork_ids = [aw['id'] for aw in data['artworks']]
    assert artwork_for_artist_1.artwork_num in artwork_ids
    assert soft_deleted_artwork.artwork_num in artwork_ids


def test_audit_log_includes_force_delete_flag(client, artist_user_1, artwork_for_artist_1):
    """Test that audit log includes force_delete flag for force deletions."""
    user, artist = artist_user_1

    # Login as artist 1
    login_as_user(client, 'artist1@test.com', 'Artist1Pass123!')

    # Get CSRF token
    csrf_response = client.get('/auth/csrf-token')
    csrf_token = csrf_response.get_json()['csrf_token']

    # Force delete artwork
    response = client.delete(
        f'/api/artworks/{artwork_for_artist_1.artwork_num}?force=true',
        headers={'X-CSRFToken': csrf_token}
    )

    assert response.status_code == 200

    # Check audit log
    from app import AuditLog
    audit = AuditLog.query.filter_by(
        event_type='artwork_deleted',
        user_id=user.id
    ).order_by(AuditLog.created_at.desc()).first()

    assert audit is not None
    details = json.loads(audit.details)
    assert details['force_delete'] is True
    assert details['deletion_type'] == 'Force-hard-deleted'
