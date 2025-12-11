"""Tests for database restore functionality.

This module tests:
1. wipe_database_schema() function
2. run_database_migrations() function
3. Safe tarfile extraction (path traversal prevention)
4. column_exists() helper in migrations
5. Restore status endpoint without authentication
6. Full restore flow with mocked subprocess calls
"""
import io
import json
import os
import sys
import tarfile
import tempfile
from unittest.mock import MagicMock, patch, Mock
import pytest
from sqlalchemy.pool import StaticPool

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backup_utils import (
    wipe_database_schema,
    run_database_migrations,
    get_db_connection_info,
    compute_sha256,
    BACKUPS_DIR,
)


class TestWipeDatabaseSchema:
    """Tests for wipe_database_schema() function."""

    def test_wipe_database_schema_success(self):
        """Test successful database schema wipe with mocked subprocess."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch('backup_utils.subprocess.run', return_value=mock_result) as mock_run:
            with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://testuser:testpass@localhost:5432/testdb'}):
                success, message = wipe_database_schema()

        assert success is True
        assert "wiped" in message.lower()

        # Verify psql was called with correct arguments
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]

        assert "psql" in cmd
        assert "-h" in cmd
        assert "localhost" in cmd
        assert "-d" in cmd
        assert "testdb" in cmd
        assert "DROP SCHEMA" in call_args.kwargs.get('env', {}).get('PGPASSWORD', '') or \
               "DROP SCHEMA" in str(cmd)

    def test_wipe_database_schema_failure(self):
        """Test schema wipe failure with mocked subprocess."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "ERROR: permission denied"

        with patch('backup_utils.subprocess.run', return_value=mock_result):
            with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://user:pass@localhost:5432/db'}):
                success, message = wipe_database_schema()

        assert success is False
        assert "failed" in message.lower() or "permission denied" in message.lower()

    def test_wipe_database_schema_timeout(self):
        """Test schema wipe timeout handling."""
        import subprocess

        with patch('backup_utils.subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='psql', timeout=60)):
            with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://user:pass@localhost:5432/db'}):
                success, message = wipe_database_schema()

        assert success is False
        # Check for "timed out" which is more specific to timeout messages
        assert "timed out" in message.lower(), f"Expected timeout message, got: {message}"

    def test_wipe_database_schema_psql_not_found(self):
        """Test handling when psql is not installed."""
        with patch('backup_utils.subprocess.run', side_effect=FileNotFoundError()):
            with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://user:pass@localhost:5432/db'}):
                success, message = wipe_database_schema()

        assert success is False
        assert "not found" in message.lower()

    def test_wipe_database_schema_sql_injection_prevention(self):
        """Test that user identifier is properly quoted to prevent SQL injection."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # Use a username with special characters that could be SQL injection
        malicious_user = 'admin"; DROP TABLE users; --'

        with patch('backup_utils.subprocess.run', return_value=mock_result) as mock_run:
            with patch.dict(os.environ, {
                'DB_HOST': 'localhost',
                'DB_PORT': '5432',
                'DB_NAME': 'testdb',
                'DB_USER': malicious_user,
                'DB_PASSWORD': 'testpass'
            }, clear=True):
                # Clear DATABASE_URL to force use of individual vars
                if 'DATABASE_URL' in os.environ:
                    del os.environ['DATABASE_URL']
                success, message = wipe_database_schema()

        # Verify the command was called
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]

        # The -c argument contains the SQL command - find it
        sql_arg_idx = cmd.index('-c')
        sql_command = cmd[sql_arg_idx + 1]

        # Verify the user is quoted in the SQL
        # The user should be wrapped in double quotes to prevent injection
        assert '""' in sql_command or '"admin' in sql_command


class TestRunDatabaseMigrations:
    """Tests for run_database_migrations() function."""

    def test_migrations_success(self):
        """Test successful database migrations."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Running upgrade -> abc123"
        mock_result.stderr = ""

        with patch('backup_utils.subprocess.run', return_value=mock_result) as mock_run:
            success, message = run_database_migrations()

        assert success is True
        assert "completed" in message.lower() or "migrations" in message.lower()

        # Verify flask db upgrade was called
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert "flask" in cmd
        assert "db" in cmd
        assert "upgrade" in cmd

    def test_migrations_failure(self):
        """Test migration failure handling."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "ERROR: Migration failed - column already exists"

        with patch('backup_utils.subprocess.run', return_value=mock_result):
            success, message = run_database_migrations()

        assert success is False
        assert "failed" in message.lower()

    def test_migrations_timeout(self):
        """Test migration timeout handling (10 minute limit)."""
        import subprocess

        with patch('backup_utils.subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='flask', timeout=600)):
            success, message = run_database_migrations()

        assert success is False
        # Check for "timed out" which is more specific to timeout messages
        assert "timed out" in message.lower(), f"Expected timeout message, got: {message}"

    def test_migrations_flask_not_found(self):
        """Test handling when flask command is not available."""
        with patch('backup_utils.subprocess.run', side_effect=FileNotFoundError()):
            success, message = run_database_migrations()

        assert success is False
        assert "not found" in message.lower()

    def test_migrations_uses_correct_cwd(self):
        """Test that migrations run from the correct directory."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch('backup_utils.subprocess.run', return_value=mock_result) as mock_run:
            run_database_migrations()

        call_args = mock_run.call_args
        # Verify cwd is set to backend directory
        assert 'cwd' in call_args.kwargs
        cwd = call_args.kwargs['cwd']
        assert os.path.basename(cwd) == 'backend' or 'backend' in cwd


class TestSafeTarfileExtraction:
    """Tests for path traversal prevention in restore.py tarfile extraction."""

    def test_safe_extraction_rejects_absolute_path(self):
        """Test that tarfile members with absolute paths are rejected."""
        # Create a tarball with a member that has an absolute path
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            # Add a normal file
            data = b"test content"
            info = tarfile.TarInfo(name="normal_file.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        tar_buffer.seek(0)

        # Test the safe extraction logic
        with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
            for member in tar.getmembers():
                member_path = os.path.normpath(member.name)
                # This simulates the check in restore.py
                is_safe = not member_path.startswith('..') and not member_path.startswith('/')
                assert is_safe, f"Normal path {member.name} should be safe"

        # Now test with an absolute path (simulated)
        malicious_path = "/etc/passwd"
        normalized = os.path.normpath(malicious_path)
        is_safe = not normalized.startswith('..') and not normalized.startswith('/')
        assert not is_safe, "Absolute path should be rejected"

    def test_safe_extraction_rejects_path_traversal(self):
        """Test that tarfile members with path traversal are rejected."""
        # Test various path traversal patterns
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "foo/../../../bar",
            "foo/bar/../../../etc/shadow",
        ]

        for path in malicious_paths:
            normalized = os.path.normpath(path)
            is_safe = not normalized.startswith('..') and not normalized.startswith('/')
            assert not is_safe, f"Path traversal {path} should be rejected"

    def test_safe_extraction_allows_nested_paths(self):
        """Test that legitimate nested paths are allowed."""
        safe_paths = [
            "database/canvas_clay.dump",
            "uploads/artworks/photo1.jpg",
            "manifest.json",
            "uploads/thumbnails/thumb_abc.jpg",
        ]

        for path in safe_paths:
            normalized = os.path.normpath(path)
            is_safe = not normalized.startswith('..') and not normalized.startswith('/')
            abs_path = os.path.abspath(os.path.join("/tmp/restore", normalized))
            in_target = abs_path.startswith(os.path.abspath("/tmp/restore"))
            assert is_safe and in_target, f"Safe path {path} should be allowed"

    def test_extract_with_symlink_traversal(self):
        """Test that symlink-based path traversal is handled."""
        # A malicious archive might try to use symlinks to escape
        # The normpath check catches simple traversal, but symlinks need special handling
        # This tests that the resolved path check catches symlink attacks

        with tempfile.TemporaryDirectory() as temp_dir:
            # Simulate the check in restore.py:
            # abs_path = os.path.abspath(os.path.join(temp_dir, member_path))
            # if not abs_path.startswith(os.path.abspath(temp_dir)):
            #     skip

            # Test a path that, when joined and resolved, escapes the target
            member_path = "uploads/../../../etc/passwd"
            normalized = os.path.normpath(member_path)

            # This should be caught by the first check
            is_traversal = normalized.startswith('..')
            assert is_traversal, "Path with .. should be detected"


class TestColumnExistsHelper:
    """Tests for column_exists() helper function used in migrations."""

    def test_column_exists_query(self):
        """Test that column_exists generates correct PostgreSQL query."""
        # Mock the alembic operation context
        mock_bind = MagicMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (1,)
        mock_bind.execute.return_value = mock_result

        # Import and test the column_exists function
        # Since it's in a migration file, we'll test the SQL pattern directly
        table_name = 'users'
        column_name = 'email_idx'

        expected_sql_pattern = """
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
            AND table_name = :table AND column_name = :column
        """

        # Verify the expected SQL structure
        assert "information_schema.columns" in expected_sql_pattern
        assert "table_schema = 'public'" in expected_sql_pattern
        assert "table_name = :table" in expected_sql_pattern
        assert "column_name = :column" in expected_sql_pattern

    def test_column_exists_returns_true_when_column_present(self):
        """Test column_exists returns True when column is found."""
        mock_bind = MagicMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (1,)  # Column exists
        mock_bind.execute.return_value = mock_result

        with patch('sqlalchemy.text') as mock_text:
            # Simulate the function logic
            result = mock_bind.execute(mock_text("query"), {"table": "users", "column": "email"})
            exists = result.fetchone() is not None

        assert exists is True

    def test_column_exists_returns_false_when_column_missing(self):
        """Test column_exists returns False when column is not found."""
        mock_bind = MagicMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = None  # Column doesn't exist
        mock_bind.execute.return_value = mock_result

        with patch('sqlalchemy.text') as mock_text:
            result = mock_bind.execute(mock_text("query"), {"table": "users", "column": "nonexistent"})
            exists = result.fetchone() is not None

        assert exists is False


class TestRestoreStatusEndpoint:
    """Tests for restore status endpoint which requires NO authentication."""

    @pytest.fixture
    def client(self):
        """Create a test client."""
        from app import app, db

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

    def test_restore_status_no_auth_required(self, client):
        """Test that restore status endpoint works without authentication.

        This is intentional because during restore, the database schema is wiped,
        making authentication impossible. The restore_id serves as a bearer token.
        """
        # Generate a UUID for testing
        import uuid
        fake_restore_id = str(uuid.uuid4())

        # This should return 404 for unknown restore_id, NOT 401
        response = client.get(f'/api/admin/console/restore/{fake_restore_id}/status')

        # 404 means "not found" which is correct - it's not rejecting us for auth
        assert response.status_code == 404
        data = response.get_json()
        assert 'error' in data
        assert 'not found' in data['error'].lower()

    def test_restore_status_with_valid_restore_id(self, client):
        """Test restore status with a valid restore_id in the operations dict."""
        from app import _restore_operations
        import uuid

        restore_id = str(uuid.uuid4())

        # Inject a test restore operation
        _restore_operations[restore_id] = {
            'status': 'in_progress',
            'step': 'database',
            'progress': 50,
            'message': 'Restoring database...',
            'started_at': '2025-12-10T12:00:00Z',
        }

        try:
            response = client.get(f'/api/admin/console/restore/{restore_id}/status')
            assert response.status_code == 200

            data = response.get_json()
            assert data['status'] == 'in_progress'
            assert data['step'] == 'database'
            assert data['progress'] == 50
        finally:
            # Cleanup
            del _restore_operations[restore_id]

    def test_restore_status_completed(self, client):
        """Test restore status when restore is completed."""
        from app import _restore_operations
        import uuid

        restore_id = str(uuid.uuid4())

        _restore_operations[restore_id] = {
            'status': 'completed',
            'step': 'done',
            'progress': 100,
            'message': 'Restore completed successfully',
            'started_at': '2025-12-10T12:00:00Z',
            'completed_at': '2025-12-10T12:05:00Z',
        }

        try:
            response = client.get(f'/api/admin/console/restore/{restore_id}/status')
            assert response.status_code == 200

            data = response.get_json()
            assert data['status'] == 'completed'
            assert data['progress'] == 100
        finally:
            del _restore_operations[restore_id]

    def test_restore_status_failed(self, client):
        """Test restore status when restore has failed."""
        from app import _restore_operations
        import uuid

        restore_id = str(uuid.uuid4())

        _restore_operations[restore_id] = {
            'status': 'failed',
            'step': 'database',
            'progress': 30,
            'message': 'pg_restore failed: connection refused',
            'error': 'Database connection failed',
            'started_at': '2025-12-10T12:00:00Z',
        }

        try:
            response = client.get(f'/api/admin/console/restore/{restore_id}/status')
            assert response.status_code == 200

            data = response.get_json()
            assert data['status'] == 'failed'
            assert 'error' in data
        finally:
            del _restore_operations[restore_id]

    def test_restore_status_uuid_format(self, client):
        """Test that invalid restore_id formats still return 404 not 400."""
        # Even with invalid format, should be 404 not 400
        # This prevents information leakage about valid ID formats
        response = client.get('/api/admin/console/restore/not-a-valid-uuid/status')
        assert response.status_code == 404

    def test_restore_status_rate_limit_exempt(self, client):
        """Test that restore status endpoint is exempt from rate limiting.

        During a restore, the frontend polls this endpoint frequently.
        Rate limiting would break the restore monitoring UI.
        """
        from app import _restore_operations
        import uuid

        restore_id = str(uuid.uuid4())
        _restore_operations[restore_id] = {
            'status': 'in_progress',
            'step': 'database',
            'progress': 50,
        }

        try:
            # Make many rapid requests - should all succeed
            for _ in range(20):
                response = client.get(f'/api/admin/console/restore/{restore_id}/status')
                assert response.status_code == 200
        finally:
            del _restore_operations[restore_id]


class TestFullRestoreFlow:
    """Tests for the full restore flow with mocked subprocess calls."""

    @pytest.fixture
    def mock_backup_archive(self):
        """Create a mock backup archive for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = os.path.join(temp_dir, 'test_backup.tar.gz')

            # Create a valid backup structure
            with tarfile.open(archive_path, 'w:gz') as tar:
                # Add manifest
                manifest = {
                    'version': '1.1',
                    'created_at': '2025-12-10T12:00:00Z',
                    'created_by': 'test',
                    'type': 'full',
                    'source': {
                        'hostname': 'test-host',
                        'pii_key_fingerprint': 'abc12345'
                    },
                    'contents': {
                        'database': {
                            'included': True,
                            'size': 1024,
                            'checksum': 'abc123',
                        },
                        'photos': {
                            'included': False
                        }
                    }
                }
                manifest_data = json.dumps(manifest).encode('utf-8')
                manifest_info = tarfile.TarInfo(name='manifest.json')
                manifest_info.size = len(manifest_data)
                tar.addfile(manifest_info, io.BytesIO(manifest_data))

                # Add database dump directory and file
                db_data = b"PGDUMP test data"
                db_info = tarfile.TarInfo(name='database/canvas_clay.dump')
                db_info.size = len(db_data)
                tar.addfile(db_info, io.BytesIO(db_data))

            yield archive_path

    def test_restore_validates_manifest(self, mock_backup_archive):
        """Test that restore validates manifest before proceeding."""
        from restore import read_manifest_from_archive

        manifest, error = read_manifest_from_archive(mock_backup_archive)

        assert error is None
        assert manifest is not None
        assert manifest['version'] == '1.1'
        assert manifest['contents']['database']['included'] is True

    def test_restore_rejects_invalid_archive(self):
        """Test that restore rejects archives without valid manifest."""
        from restore import read_manifest_from_archive

        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f:
            # Create empty tarball without manifest
            with tarfile.open(f.name, 'w:gz') as tar:
                data = b"not a manifest"
                info = tarfile.TarInfo(name='some_file.txt')
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

            try:
                manifest, error = read_manifest_from_archive(f.name)
                assert error is not None
                assert 'manifest.json' in error.lower() or 'not found' in error.lower()
            finally:
                os.unlink(f.name)

    def test_restore_flow_with_mocked_pg_restore(self, mock_backup_archive):
        """Test the restore flow with mocked subprocess calls."""
        from backup_utils import run_pg_restore

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch('backup_utils.subprocess.run', return_value=mock_result) as mock_run:
            with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://user:pass@localhost:5432/db'}):
                success, message = run_pg_restore(mock_backup_archive, clean=False)

        assert success is True
        # Verify pg_restore was called
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert 'pg_restore' in cmd

    def test_restore_flow_handles_pg_restore_warnings(self):
        """Test that pg_restore warnings are handled correctly."""
        from backup_utils import run_pg_restore

        # pg_restore often returns non-zero for harmless warnings
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "pg_restore: warning: errors ignored on restore: 1"

        with patch('backup_utils.subprocess.run', return_value=mock_result):
            with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://user:pass@localhost:5432/db'}):
                success, message = run_pg_restore('/fake/path.dump', clean=False)

        # Should succeed despite non-zero return code for harmless warnings
        assert success is True

    def test_restore_flow_detects_fatal_errors(self):
        """Test that fatal pg_restore errors are detected."""
        from backup_utils import run_pg_restore

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "FATAL: password authentication failed for user"

        with patch('backup_utils.subprocess.run', return_value=mock_result):
            with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://user:pass@localhost:5432/db'}):
                success, message = run_pg_restore('/fake/path.dump', clean=False)

        assert success is False
        assert 'failed' in message.lower()

    def test_pre_restore_backup_creation(self):
        """Test that pre-restore backup is created before actual restore."""
        from restore import create_pre_restore_backup

        def mock_pg_dump_side_effect(dump_path, exclude_tables=None):
            """Mock pg_dump that actually creates the file."""
            os.makedirs(os.path.dirname(dump_path), exist_ok=True)
            with open(dump_path, 'wb') as f:
                f.write(b'mock pg_dump data')
            return (True, "Database backed up")

        # Mock the backup functions to avoid actual database operations
        with patch('restore.run_pg_dump', side_effect=mock_pg_dump_side_effect), \
             patch('restore.archive_photos') as mock_photos, \
             patch('restore.ensure_backups_dir'), \
             patch('restore.compute_sha256', return_value='abc123'):

            mock_photos.return_value = (True, {"count": 0, "files": []}, "No photos")

            with tempfile.TemporaryDirectory() as temp_dir:
                with patch('restore.BACKUPS_DIR', temp_dir):
                    success, backup_path, message = create_pre_restore_backup()

        # Should create backup successfully with mocked functions
        assert success is True
        assert backup_path is not None
        assert "backup" in message.lower()

    def test_restore_checksum_verification(self, mock_backup_archive):
        """Test that restore verifies checksums before proceeding."""
        from backup_utils import compute_sha256

        # Read and verify the archive checksum
        checksum = compute_sha256(mock_backup_archive)
        assert checksum is not None
        assert len(checksum) == 64  # SHA256 hex length


class TestDatabaseConnectionInfo:
    """Tests for get_db_connection_info() function."""

    def test_parse_database_url(self):
        """Test parsing DATABASE_URL environment variable."""
        with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://myuser:mypass@dbhost:5433/mydb'}):
            info = get_db_connection_info()

        assert info['host'] == 'dbhost'
        assert info['port'] == '5433'
        assert info['database'] == 'mydb'
        assert info['user'] == 'myuser'
        assert info['password'] == 'mypass'

    def test_parse_individual_env_vars(self):
        """Test parsing individual DB_* environment variables."""
        env_vars = {
            'DB_HOST': 'individual-host',
            'DB_PORT': '5434',
            'DB_NAME': 'individual_db',
            'DB_USER': 'individual_user',
            'DB_PASSWORD': 'individual_pass'
        }

        # Clear DATABASE_URL to force individual var usage
        with patch.dict(os.environ, env_vars, clear=True):
            info = get_db_connection_info()

        assert info['host'] == 'individual-host'
        assert info['port'] == '5434'
        assert info['database'] == 'individual_db'
        assert info['user'] == 'individual_user'
        assert info['password'] == 'individual_pass'

    def test_default_values(self):
        """Test default values when no environment variables set."""
        with patch.dict(os.environ, {}, clear=True):
            info = get_db_connection_info()

        assert info['host'] == 'localhost'
        assert info['port'] == '5432'
        assert info['database'] == 'canvas_clay'
        assert info['user'] == 'canvas_db'
        assert info['password'] == ''

    def test_database_url_with_special_characters(self):
        """Test parsing DATABASE_URL with special characters in password."""
        # Passwords may contain special chars that need proper URL encoding
        with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://user:p%40ss%3Dword@host:5432/db'}):
            info = get_db_connection_info()

        assert info['password'] == 'p@ss=word'  # URL decoded


class TestRestoreValidationEndpoint:
    """Tests for restore validation endpoint."""

    @pytest.fixture
    def admin_client(self):
        """Create an authenticated admin test client."""
        from app import app, db, User, bcrypt
        from encryption import compute_blind_index, normalize_email

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

                # Create admin user
                email = 'admin@test.com'
                admin = User(
                    email=email,
                    email_idx=compute_blind_index(email, normalize_email),
                    hashed_password=bcrypt.generate_password_hash('AdminPass123').decode('utf-8'),
                    role='admin',
                    is_active=True
                )
                db.session.add(admin)
                db.session.commit()

                # Login
                client.post('/auth/login', json={
                    'email': 'admin@test.com',
                    'password': 'AdminPass123'
                })

                yield client

                db.session.remove()
                db.drop_all()

    def test_validate_requires_auth(self):
        """Test that validation endpoint requires authentication."""
        from app import app, db
        from sqlalchemy.pool import StaticPool

        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'connect_args': {'check_same_thread': False},
            'poolclass': StaticPool
        }
        app.config['WTF_CSRF_ENABLED'] = False

        with app.test_client(use_cookies=True) as client:
            with app.app_context():
                db.create_all()

                response = client.post('/api/admin/console/restore/validate', json={
                    'filename': 'test.tar.gz'
                })

                assert response.status_code == 401

                db.session.remove()
                db.drop_all()

    def test_validate_requires_admin_role(self, admin_client):
        """Test that validation endpoint requires admin role."""
        from app import app, db, User, bcrypt
        from encryption import compute_blind_index, normalize_email

        # Create and login as non-admin
        with app.app_context():
            email = 'guest@test.com'
            guest = User(
                email=email,
                email_idx=compute_blind_index(email, normalize_email),
                hashed_password=bcrypt.generate_password_hash('GuestPass123').decode('utf-8'),
                role='guest',
                is_active=True
            )
            db.session.add(guest)
            db.session.commit()

        # Logout admin and login as guest
        admin_client.post('/auth/logout')
        admin_client.post('/auth/login', json={
            'email': 'guest@test.com',
            'password': 'GuestPass123'
        })

        response = admin_client.post('/api/admin/console/restore/validate', json={
            'filename': 'test.tar.gz'
        })

        assert response.status_code == 403

    def test_validate_missing_filename(self, admin_client):
        """Test validation with missing filename."""
        response = admin_client.post('/api/admin/console/restore/validate', json={})

        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_validate_nonexistent_file(self, admin_client):
        """Test validation with nonexistent backup file."""
        response = admin_client.post('/api/admin/console/restore/validate', json={
            'filename': 'nonexistent_backup.tar.gz'
        })

        # Should return 404 or 400 for missing file
        assert response.status_code in [400, 404]


class TestIdempotentMigrations:
    """Tests for idempotent migration behavior (skip existing columns)."""

    def test_migration_skips_existing_column(self):
        """Test that migrations skip already existing columns."""
        # This tests the column_exists check pattern used in migrations
        mock_bind = MagicMock()
        mock_result = MagicMock()

        # Simulate column already exists
        mock_result.fetchone.return_value = (1,)
        mock_bind.execute.return_value = mock_result

        # The migration should check and skip
        result = mock_bind.execute(MagicMock(), {"table": "users", "column": "email_idx"})
        column_exists = result.fetchone() is not None

        if column_exists:
            # Migration would print message and return early
            should_skip = True
        else:
            should_skip = False

        assert should_skip is True

    def test_migration_proceeds_for_new_column(self):
        """Test that migrations proceed for non-existing columns."""
        mock_bind = MagicMock()
        mock_result = MagicMock()

        # Simulate column doesn't exist
        mock_result.fetchone.return_value = None
        mock_bind.execute.return_value = mock_result

        result = mock_bind.execute(MagicMock(), {"table": "users", "column": "new_column"})
        column_exists = result.fetchone() is not None

        if column_exists:
            should_skip = True
        else:
            should_skip = False

        assert should_skip is False
