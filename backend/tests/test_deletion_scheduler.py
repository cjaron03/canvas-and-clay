""" Tests for 30 day deletion scheduler """
import pytest
from unittest.mock import patch, MagicMock
from datetime import date, datetime, timedelta, timezone
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import db, app, Artist, Artwork, Storage, ArtworkPhoto
from app import start_deletion_scheduler, stop_deletion_scheduler, scheduler
from scheduled_deletes import scheduled_artwork_deletion, scheduled_artist_deletion


@pytest.fixture
def client():
    """Create a test client with a fresh in-memory database."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['RATELIMIT_ENABLED'] = False

    # disable limiter if exists
    from app import limiter
    limiter.enabled = False
   

    with app.test_client() as test_client:
        with app.app_context():
            db.create_all()
            yield test_client
            db.session.remove()
            db.drop_all()


@pytest.fixture
def mock_delete_files(monkeypatch):
    """Mock file deletion so tests don't touch the filesystem."""
    def fake_delete(file_path, thumb_path):
        return True
    monkeypatch.setattr("scheduled_deletes.delete_photo_files", fake_delete)


@pytest.fixture
def test_artist_data(client):
    """Create test data for scheduled_artist_deletion()."""

    # Creating old soft-deleted artist 
    old_date = date.today() - timedelta(days=40)
    old_artist = Artist(
        artist_id='ARTISTOL',
        artist_fname='Old',
        artist_lname='Artist',
        artist_email='old@artist.com',
        artist_phone='(111)-111-1111',
        is_deleted=True,
        date_deleted=old_date
    )

    # Creating recently deleted artist
    recent_date = date.today() - timedelta(days=5)
    recent_artist = Artist(
        artist_id='ARTIST11',
        artist_fname='Recent',
        artist_lname='Artist',
        artist_email='recent@artist.com',
        artist_phone='(222)-222-2222',
        is_deleted=True,
        date_deleted=recent_date
    )
    db.session.add_all([old_artist, recent_artist])
    db.session.flush()

    #  Creating Storage 
    test_artist_storage = Storage(
        storage_id='STOR002',
        storage_loc='Test Storage',
        storage_type='Rack'
    )
    db.session.add(test_artist_storage)
    db.session.flush()

    # Creating artwork for old artist
    old_artwork = Artwork(
        artwork_num='OLDARTW1',
        artwork_ttl='Old Art',
        is_deleted=True,
        date_deleted=old_date,
        artist_id='ARTISTOL',
        storage_id='STOR002'
    )

    # Creating artwork for recent artist
    recent_artwork = Artwork(
        artwork_num='RECARTW1',
        artwork_ttl='Recent Art',
        is_deleted=True,
        date_deleted=recent_date,
        artist_id='ARTIST11',
        storage_id='STOR002'
    )

    db.session.add_all([old_artwork, recent_artwork])
    db.session.flush()

    # Creating photo for old artwork
    old_photo = ArtworkPhoto(
        photo_id='PHOTO111',
        artwork_num='OLDARTW1',
        filename='old_photo.jpg',
        file_path='/fake/path/old_photo.jpg',
        thumbnail_path='/fake/path/thumb-old-photo.jpg',
        file_size=100,
        mime_type='image/jpeg',
        width=100,
        height=100,
        uploaded_at=datetime.now(timezone.utc),
        is_primary=False
    )
    db.session.add(old_photo)
    db.session.flush()


    db.session.commit()

    return {
        "artists": [old_artist, recent_artist],
        "storage": test_artist_storage,
        "artworks": [old_artwork, recent_artwork],
        "photos": [old_photo]
    }


@pytest.fixture
def test_artwork_data(client):
    """ Create test data, including soft deleted artwork older than 30 days, with photos"""
  
    # Creating test artist
    test_artist = Artist(
        artist_id='ARTIST01',
        artist_fname='Test',
        artist_lname='Testy',
        artist_email='test@artist.com',
        artist_phone='(123)-456-7890'
    )
    db.session.add(test_artist)
    db.session.flush()

    # Creating test storage
    test_storage = Storage(
        storage_id='STOR001',
        storage_loc='Test Storage',
        storage_type='Rack'
    )
    db.session.add(test_storage)
    db.session.flush()


    # Creating soft deleted-artwork older than 30 days
    old_date = date.today() - timedelta(days=40)
    old_artwork = Artwork(
        artwork_num='AW100000',
        artwork_ttl='Old Artwork',
        is_viewable=False,
        is_deleted=True,
        date_deleted=old_date,
        artist_id='ARTIST01',
        storage_id='STOR001'
    )

    # Creating recently soft deleted artwork
    recent_date = date.today() - timedelta(days=5)
    recent_artwork = Artwork(
        artwork_num='AW200000',
        artwork_ttl='Reent Artwork',
        is_viewable=False,
        is_deleted=True,
        date_deleted=recent_date,
        artist_id='ARTIST01',
        storage_id='STOR001'
    )
    db.session.add_all([old_artwork, recent_artwork])
    db.session.flush()

    # Creating fake photos in db
    photo1 = ArtworkPhoto(
        photo_id='PHOTO001',
        artwork_num='AW100000',
        filename='photo1.jpg',
        file_path='/fake/path/photo1.jpg',
        thumbnail_path='/fake/path/thumb-photo1.jpg',
        file_size=100,
        mime_type='image/jpeg',
        width=100,
        height=100,
        uploaded_at=datetime.now(timezone.utc),
        is_primary=False
    )
    photo2 = ArtworkPhoto(
        photo_id='PHOTO002',
        artwork_num='AW100000',
        filename='photo2.jpg',
        file_path='/fake/path/photo2.jpg',
        thumbnail_path='/fake/path/thumb-photo2.jpg',
        file_size=100,
        mime_type='image/jpeg',
        width=100,
        height=100,
        uploaded_at=datetime.now(timezone.utc),
        is_primary=False
    )
    db.session.add_all([photo1, photo2])
    db.session.commit()

    return {
        "artist": test_artist,
        "storage": test_storage,
        "artworks": [old_artwork, recent_artwork],
        "photos": [photo1, photo2]
    }


class TestScheduledArtistDeletion:
    """Tests for scheduled_artist_deletion() function."""
    def test_delete_old_soft_deleted_artist(
            self, client, mock_delete_files, test_artist_data
    ):
        """Ensure artists older than 30 days and their photos are deleted.
            And that recently soft-deleted artists remains."""
        # Pre-conditions
        assert Artist.query.count() == 2
        assert Artwork.query.count() == 2
        assert ArtworkPhoto.query.count() == 1

        # run scheduled artsit deletion manually
        scheduled_artist_deletion()

        # Validate deleiton
        assert Artist.query.count() == 1
        assert Artwork.query.count() == 1
        assert ArtworkPhoto.query.count() == 0

        # Ensure recently deleted artist was not included in scheduled deletion
        remaining_artist = Artist.query.first()
        assert remaining_artist.artist_id == 'ARTIST11'

    
    def test_no_error_when_no_old_artists(self, client, mock_delete_files):
        """Deleting when nothing qualifies should not raise errors."""
        # Ensure empty DB
        assert Artist.query.count() == 0
        assert Artwork.query.count() == 0
        assert ArtworkPhoto.query.count() == 0

        # should raise no exceptions
        scheduled_artist_deletion()

        # Ensure DB still empty
        assert Artist.query.count() == 0
        assert Artwork.query.count() == 0
        assert ArtworkPhoto.query.count() == 0

class TestScheduledArtworkDeletion:
    """Tests for scheduled_artwork_deletion() function."""

    def test_delete_old_soft_deleted_artwork(
        self, client, mock_delete_files, test_artwork_data
    ):
        """Ensure artworks older than 30 days and their photos are deleted.
           And that the recently soft-deleted artwork remains.
        """
        # Pre-conditions
        assert Artwork.query.count() == 2
        assert ArtworkPhoto.query.count() == 2

        # Run scheduled job manually
        scheduled_artwork_deletion()

        # Validate deletion
        assert Artwork.query.count() == 1
        assert ArtworkPhoto.query.count() == 0    

        # Ensure that the deletion did not include recent soft-delete
        remaining_artwork = Artwork.query.first()
        assert remaining_artwork.artwork_num == 'AW200000'

    
    def test_no_error_when_no_old_artworks(self, client, mock_delete_files):
        """Deleting when nothing qualifies should not raise errors."""
        # Ensure empty DB
        assert Artwork.query.count() == 0
        assert ArtworkPhoto.query.count() == 0

        # Should run with no exceptions
        scheduled_artwork_deletion()

        # Still empty
        assert Artwork.query.count() == 0
        assert ArtworkPhoto.query.count() == 0


class TestScheduler:
    """Tests for Scheduler creation, deletion, and job registration."""

    def test_scheduler_start_and_job_registration(self, caplog):
        """Test that the deletion scheduler starts and registers the job."""
        global scheduler
        scheduler = None  # reset for test

        with caplog.at_level("INFO"):
            start_deletion_scheduler()

        # No jobs should be added, scheduler should remain None
        assert scheduler is None
        # Logs should show the TESTING message
        assert any("Skipping Deletion Scheduler start in TESTING mode" in r.message for r in caplog.records)


        
     

    def test_scheduler_start_when_already_running(self, caplog):
        """Calling start again does not create another scheduler."""

        start_deletion_scheduler()

        with caplog.at_level("INFO"):
            start_deletion_scheduler()

        assert any("Skipping" in r.message for r in caplog.records)
       

    def test_scheduler_stop(self, caplog):
        """Test that the scheduler can be stopped."""
        global scheduler
        scheduler = MagicMock()  # pretend there’s a scheduler

        with caplog.at_level("INFO"):
            stop_deletion_scheduler()

        # Shutdown should NOT have been called
        scheduler.shutdown.assert_not_called()
        # Logs should show skipping message
        assert any("Skipping Deletion Scheduler Stop in TESTING mode" in r.message for r in caplog.records)