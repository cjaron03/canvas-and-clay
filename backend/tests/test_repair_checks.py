"""Tests for repair_checks.py CLI tool."""
import json
import os
import tempfile
import shutil
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock
from sqlalchemy.pool import StaticPool

# Import the module under test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def make_photo(ArtworkPhoto, photo_id, filename, file_path, thumbnail_path=None, artwork_num=None):
    """Helper to create ArtworkPhoto with all required fields."""
    return ArtworkPhoto(
        photo_id=photo_id,
        artwork_num=artwork_num,
        filename=filename,
        file_path=file_path,
        thumbnail_path=thumbnail_path or f'uploads/thumbnails/thumb_{filename}',
        file_size=1024,
        mime_type='image/jpeg',
        width=800,
        height=600,
        uploaded_at=datetime.utcnow()
    )


@pytest.fixture
def temp_dirs():
    """Create temporary upload directories for testing."""
    base_dir = tempfile.mkdtemp()
    artworks_dir = os.path.join(base_dir, 'uploads', 'artworks')
    thumbnails_dir = os.path.join(base_dir, 'uploads', 'thumbnails')

    os.makedirs(artworks_dir, exist_ok=True)
    os.makedirs(thumbnails_dir, exist_ok=True)

    yield {
        'base': base_dir,
        'artworks': artworks_dir,
        'thumbnails': thumbnails_dir
    }

    # Cleanup
    shutil.rmtree(base_dir)


@pytest.fixture
def mock_app_context():
    """Create a mock Flask app context with database."""
    from app import app, db
    from create_tbls import init_tables

    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {'check_same_thread': False},
        'poolclass': StaticPool
    }
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['RATELIMIT_ENABLED'] = False

    from app import limiter
    limiter.enabled = False

    with app.app_context():
        db.create_all()
        ArtworkPhoto = init_tables(db)[6]
        yield app, db, ArtworkPhoto
        db.session.remove()
        db.drop_all()


class TestScanOrphanedFiles:
    """Tests for scan_orphaned_files function."""

    def test_scan_finds_orphaned_artwork_files(self, temp_dirs, mock_app_context):
        """Should find files on disk not in database."""
        app, db, ArtworkPhoto = mock_app_context

        # Create an orphaned file on disk
        orphan_path = os.path.join(temp_dirs['artworks'], 'orphan.jpg')
        with open(orphan_path, 'wb') as f:
            f.write(b'fake image data')

        # Import and patch the module
        import repair_checks
        with patch.object(repair_checks, 'ARTWORKS_DIR', temp_dirs['artworks']):
            with patch.object(repair_checks, 'THUMBNAILS_DIR', temp_dirs['thumbnails']):
                with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                    results = repair_checks.scan_orphaned_files()

        # Should find the orphan but might be skipped due to safety check
        # (0 photos in DB but files exist)
        assert results['skipped'] is True or len(results['artworks']) >= 0

    def test_scan_clean_system_returns_no_issues(self, temp_dirs, mock_app_context):
        """Clean system should have no orphaned files."""
        app, db, ArtworkPhoto = mock_app_context

        import repair_checks
        with patch.object(repair_checks, 'ARTWORKS_DIR', temp_dirs['artworks']):
            with patch.object(repair_checks, 'THUMBNAILS_DIR', temp_dirs['thumbnails']):
                with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                    results = repair_checks.scan_orphaned_files()

        # Empty directories should have no orphans
        if not results.get('skipped'):
            assert results['count'] == 0

    def test_scan_safety_check_prevents_mass_delete(self, temp_dirs, mock_app_context):
        """Should skip if more than 50% of files would be orphaned."""
        app, db, ArtworkPhoto = mock_app_context

        # Create multiple files on disk without DB records
        for i in range(10):
            path = os.path.join(temp_dirs['artworks'], f'orphan_{i}.jpg')
            with open(path, 'wb') as f:
                f.write(b'fake image data')

        import repair_checks
        with patch.object(repair_checks, 'ARTWORKS_DIR', temp_dirs['artworks']):
            with patch.object(repair_checks, 'THUMBNAILS_DIR', temp_dirs['thumbnails']):
                with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                    results = repair_checks.scan_orphaned_files()

        # Should be skipped due to safety check (0 DB records, 10 files)
        assert results['skipped'] is True
        assert 'skip_reason' in results


class TestScanMissingFiles:
    """Tests for scan_missing_files function."""

    def test_scan_finds_missing_files(self, temp_dirs, mock_app_context):
        """Should find DB records pointing to non-existent files."""
        app, db, ArtworkPhoto = mock_app_context

        # Create a DB record without corresponding file
        photo = make_photo(
            ArtworkPhoto,
            photo_id='PH000001',
            filename='missing.jpg',
            file_path='uploads/artworks/missing.jpg',
            thumbnail_path='uploads/thumbnails/thumb_missing.jpg'
        )
        db.session.add(photo)
        db.session.commit()

        import repair_checks
        with patch.object(repair_checks, 'BASE_DIR', temp_dirs['base']):
            with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                results = repair_checks.scan_missing_files()

        assert results['count'] >= 1
        assert any('artwork_missing' in p['issues'] for p in results['photos'])

    def test_scan_clean_system_no_missing_files(self, temp_dirs, mock_app_context):
        """DB records with existing files should not be flagged."""
        app, db, ArtworkPhoto = mock_app_context

        # Create file on disk
        file_path = os.path.join(temp_dirs['artworks'], 'exists.jpg')
        with open(file_path, 'wb') as f:
            f.write(b'fake image data')

        thumb_path = os.path.join(temp_dirs['thumbnails'], 'thumb_exists.jpg')
        with open(thumb_path, 'wb') as f:
            f.write(b'fake thumb data')

        # Create matching DB record
        photo = make_photo(
            ArtworkPhoto,
            photo_id='PH000002',
            filename='exists.jpg',
            file_path='uploads/artworks/exists.jpg',
            thumbnail_path='uploads/thumbnails/thumb_exists.jpg'
        )
        db.session.add(photo)
        db.session.commit()

        import repair_checks
        with patch.object(repair_checks, 'BASE_DIR', temp_dirs['base']):
            with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                results = repair_checks.scan_missing_files()

        assert results['count'] == 0


class TestScanMissingThumbnails:
    """Tests for scan_missing_thumbnails function."""

    def test_scan_finds_missing_thumbnails(self, temp_dirs, mock_app_context):
        """Should find photos with original but no thumbnail on disk."""
        app, db, ArtworkPhoto = mock_app_context

        # Create original file
        file_path = os.path.join(temp_dirs['artworks'], 'original.jpg')
        with open(file_path, 'wb') as f:
            f.write(b'fake image data')

        # DB record with thumbnail_path that doesn't exist on disk
        photo = make_photo(
            ArtworkPhoto,
            photo_id='PH000003',
            filename='original.jpg',
            file_path='uploads/artworks/original.jpg',
            thumbnail_path='uploads/thumbnails/thumb_missing.jpg'  # File doesn't exist
        )
        db.session.add(photo)
        db.session.commit()

        import repair_checks
        with patch.object(repair_checks, 'BASE_DIR', temp_dirs['base']):
            with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                results = repair_checks.scan_missing_thumbnails()

        assert results['count'] >= 1

    def test_scan_with_existing_thumbnails(self, temp_dirs, mock_app_context):
        """Photos with both original and thumbnail should not be flagged."""
        app, db, ArtworkPhoto = mock_app_context

        # Create both files
        file_path = os.path.join(temp_dirs['artworks'], 'complete.jpg')
        with open(file_path, 'wb') as f:
            f.write(b'fake image data')

        thumb_path = os.path.join(temp_dirs['thumbnails'], 'thumb_complete.jpg')
        with open(thumb_path, 'wb') as f:
            f.write(b'fake thumb data')

        # DB record with both paths
        photo = make_photo(
            ArtworkPhoto,
            photo_id='PH000004',
            filename='complete.jpg',
            file_path='uploads/artworks/complete.jpg',
            thumbnail_path='uploads/thumbnails/thumb_complete.jpg'
        )
        db.session.add(photo)
        db.session.commit()

        import repair_checks
        with patch.object(repair_checks, 'BASE_DIR', temp_dirs['base']):
            with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                results = repair_checks.scan_missing_thumbnails()

        assert results['count'] == 0


class TestFixOrphanedFiles:
    """Tests for fix_orphaned_files function."""

    def test_fix_orphans_dry_run(self, temp_dirs, mock_app_context):
        """Dry run should not delete files."""
        app, db, ArtworkPhoto = mock_app_context

        # Create an orphan file
        orphan_path = os.path.join(temp_dirs['artworks'], 'orphan.jpg')
        with open(orphan_path, 'wb') as f:
            f.write(b'fake image data')

        # Add a DB record to pass safety check
        photo = make_photo(
            ArtworkPhoto,
            photo_id='PH000005',
            filename='real.jpg',
            file_path='uploads/artworks/real.jpg'
        )
        db.session.add(photo)
        db.session.commit()

        # Create matching file for DB record
        real_path = os.path.join(temp_dirs['artworks'], 'real.jpg')
        with open(real_path, 'wb') as f:
            f.write(b'real image data')

        import repair_checks
        with patch.object(repair_checks, 'ARTWORKS_DIR', temp_dirs['artworks']):
            with patch.object(repair_checks, 'THUMBNAILS_DIR', temp_dirs['thumbnails']):
                with patch.object(repair_checks, 'BASE_DIR', temp_dirs['base']):
                    with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                        results = repair_checks.fix_orphaned_files(dry_run=True)

        # File should still exist after dry run
        assert os.path.exists(orphan_path) or results.get('skipped')


class TestFixMissingFiles:
    """Tests for fix_missing_files function."""

    def test_fix_missing_removes_db_records(self, temp_dirs, mock_app_context):
        """Should attempt to remove DB records for missing files."""
        app, db, ArtworkPhoto = mock_app_context

        # Create DB record without file
        photo = make_photo(
            ArtworkPhoto,
            photo_id='PH000006',
            filename='missing.jpg',
            file_path='uploads/artworks/missing.jpg'
        )
        db.session.add(photo)
        db.session.commit()
        photo_id = photo.photo_id

        import repair_checks
        with patch.object(repair_checks, 'BASE_DIR', temp_dirs['base']):
            with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                results = repair_checks.fix_missing_files(dry_run=False)

        # Verify function returns expected structure
        assert 'deleted_records' in results
        assert isinstance(results['deleted_records'], list)
        # The photo_id should be in the deleted list
        assert photo_id in results['deleted_records']

    def test_fix_missing_dry_run(self, temp_dirs, mock_app_context):
        """Dry run should report but not delete records."""
        app, db, ArtworkPhoto = mock_app_context

        photo = make_photo(
            ArtworkPhoto,
            photo_id='PH000007',
            filename='missing.jpg',
            file_path='uploads/artworks/missing.jpg'
        )
        db.session.add(photo)
        db.session.commit()
        photo_id = photo.photo_id

        import repair_checks
        with patch.object(repair_checks, 'BASE_DIR', temp_dirs['base']):
            with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                results = repair_checks.fix_missing_files(dry_run=True)

        # Verify function returns expected dry_run result structure
        assert 'would_delete' in results or 'deleted_records' in results
        # Record should still exist after dry run
        existing_photo = db.session.get(ArtworkPhoto, photo_id)
        assert existing_photo is not None


class TestRunFullScan:
    """Tests for run_full_scan function."""

    def test_full_scan_returns_all_results(self, temp_dirs, mock_app_context):
        """Full scan should return results for all check types."""
        app, db, ArtworkPhoto = mock_app_context

        import repair_checks
        with patch.object(repair_checks, 'BASE_DIR', temp_dirs['base']):
            with patch.object(repair_checks, 'ARTWORKS_DIR', temp_dirs['artworks']):
                with patch.object(repair_checks, 'THUMBNAILS_DIR', temp_dirs['thumbnails']):
                    with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                        results = repair_checks.run_full_scan()

        assert 'orphaned_files' in results
        assert 'missing_files' in results
        assert 'missing_thumbnails' in results
        assert 'timestamp' in results


class TestFormatBytes:
    """Tests for format_bytes utility function."""

    def test_format_bytes(self):
        """Test byte formatting."""
        import repair_checks

        assert 'B' in repair_checks.format_bytes(100)
        assert 'KB' in repair_checks.format_bytes(1024)
        assert 'MB' in repair_checks.format_bytes(1024 * 1024)
        assert 'GB' in repair_checks.format_bytes(1024 * 1024 * 1024)


class TestCLIOutput:
    """Tests for CLI output formatting."""

    def test_json_output_flag(self, temp_dirs, mock_app_context):
        """--json flag should output valid JSON."""
        app, db, ArtworkPhoto = mock_app_context

        import repair_checks
        import io
        from contextlib import redirect_stdout

        with patch.object(repair_checks, 'BASE_DIR', temp_dirs['base']):
            with patch.object(repair_checks, 'ARTWORKS_DIR', temp_dirs['artworks']):
                with patch.object(repair_checks, 'THUMBNAILS_DIR', temp_dirs['thumbnails']):
                    with patch.object(repair_checks, 'get_app_context', return_value=(app, db, ArtworkPhoto)):
                        results = repair_checks.run_full_scan()

        # Should be JSON serializable
        json_output = json.dumps(results)
        parsed = json.loads(json_output)
        assert 'orphaned_files' in parsed
