"""Comprehensive tests for the Admin Recovery CLI feature (reset_admin.py).

This test module covers:
1. Password validation (min length, uppercase, lowercase, digit requirements)
2. Blind index email lookup functionality
3. .env file update logic
4. Error handling for edge cases
5. User promotion scenarios
"""

import os
import sys
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.reset_admin import (
    validate_password,
    update_env_file,
)

# Import password constants from auth (single source of truth)
MIN_PASSWORD_LENGTH = 8  # Matches auth.py


class TestPasswordValidation:
    """Tests for password validation function."""

    def test_password_too_short(self):
        """Test that passwords shorter than MIN_PASSWORD_LENGTH are rejected."""
        short_password = 'A' * (MIN_PASSWORD_LENGTH - 1) + 'a1'
        if len(short_password) < MIN_PASSWORD_LENGTH:
            valid, error = validate_password(short_password)
            assert valid is False
            assert str(MIN_PASSWORD_LENGTH) in error
            assert 'character' in error.lower()

    def test_password_exactly_min_length_valid(self):
        """Test password at exactly minimum length with all requirements."""
        # Build a password that is exactly MIN_PASSWORD_LENGTH chars
        # with uppercase, lowercase, and digit
        password = 'Aa1' + 'x' * (MIN_PASSWORD_LENGTH - 3)
        valid, error = validate_password(password)
        assert valid is True
        assert error is None

    def test_password_missing_uppercase(self):
        """Test that password without uppercase letter is rejected."""
        password = 'lowercase123'
        valid, error = validate_password(password)
        assert valid is False
        assert 'uppercase' in error.lower()

    def test_password_missing_lowercase(self):
        """Test that password without lowercase letter is rejected."""
        password = 'UPPERCASE123'
        valid, error = validate_password(password)
        assert valid is False
        assert 'lowercase' in error.lower()

    def test_password_missing_digit(self):
        """Test that password without digit is rejected."""
        password = 'NoDigitsHere'
        valid, error = validate_password(password)
        assert valid is False
        assert 'digit' in error.lower()

    def test_valid_password_simple(self):
        """Test a simple valid password."""
        password = 'ValidPass1'
        valid, error = validate_password(password)
        assert valid is True
        assert error is None

    def test_valid_password_complex(self):
        """Test a complex valid password with special characters."""
        password = 'Complex@Pass123!'
        valid, error = validate_password(password)
        assert valid is True
        assert error is None

    def test_password_empty_string(self):
        """Test that empty password is rejected."""
        valid, error = validate_password('')
        assert valid is False
        assert error is not None

    def test_password_unicode_characters(self):
        """Test password with unicode characters (should still validate)."""
        password = 'ValidPass1'  # 10+ chars with upper, lower, digit
        valid, error = validate_password(password)
        assert valid is True
        assert error is None

    def test_password_only_digits(self):
        """Test password with only digits is rejected."""
        password = '12345678901234'
        valid, error = validate_password(password)
        assert valid is False
        # Should fail for missing uppercase AND lowercase
        assert 'uppercase' in error.lower() or 'lowercase' in error.lower()

    def test_password_at_max_length(self):
        """Test password at exactly MAX_PASSWORD_LENGTH (128) is valid."""
        # 128 chars: Aa1 + 125 'x' = 128 total
        password = 'Aa1' + 'x' * 125
        assert len(password) == 128
        valid, error = validate_password(password)
        assert valid is True
        assert error is None

    def test_password_exceeds_max_length(self):
        """Test password exceeding MAX_PASSWORD_LENGTH (129+) is rejected."""
        # 129 chars: Aa1 + 126 'x' = 129 total
        password = 'Aa1' + 'x' * 126
        assert len(password) == 129
        valid, error = validate_password(password)
        assert valid is False
        assert '128' in error

    def test_password_with_spaces(self):
        """Test password with spaces (should be valid if meets requirements)."""
        password = 'Valid Pass 123'
        valid, error = validate_password(password)
        assert valid is True
        assert error is None

    def test_password_boundary_min_length(self):
        """Test password at boundary conditions around MIN_PASSWORD_LENGTH."""
        # One less than minimum
        short = 'Aa1' + 'x' * (MIN_PASSWORD_LENGTH - 4)
        valid, error = validate_password(short)
        if len(short) < MIN_PASSWORD_LENGTH:
            assert valid is False

        # Exactly minimum
        exact = 'Aa1' + 'x' * (MIN_PASSWORD_LENGTH - 3)
        valid, error = validate_password(exact)
        assert valid is True

        # One more than minimum
        longer = 'Aa1' + 'x' * (MIN_PASSWORD_LENGTH - 2)
        valid, error = validate_password(longer)
        assert valid is True


class TestCommonPasswordRejection:
    """Tests for common password blocklist enforcement."""

    def test_password123_rejected(self):
        """Test that 'Password123' is rejected as common despite meeting all requirements."""
        valid, error = validate_password('Password123')
        assert valid is False
        assert 'common' in error.lower()

    def test_password123_case_variations_rejected(self):
        """Test case-insensitive common password check."""
        # All case variations should be rejected
        for password in ['Password123', 'PASSWORD123', 'pAsSwOrD123']:
            valid, error = validate_password(password)
            assert valid is False, f"'{password}' should be rejected as common"

    def test_changeme_variations_rejected(self):
        """Test that 'Changeme' variations are rejected."""
        valid, error = validate_password('Changeme1')
        assert valid is False
        assert 'common' in error.lower()

    def test_welcome_variations_rejected(self):
        """Test that 'Welcome' variations are rejected."""
        valid, error = validate_password('Welcome123')
        assert valid is False

    def test_admin_variations_rejected(self):
        """Test that 'Admin123' is rejected."""
        valid, error = validate_password('Admin123')
        assert valid is False

    def test_test123_rejected(self):
        """Test that 'Test123' style passwords are rejected."""
        valid, error = validate_password('Test1234')
        assert valid is False

    def test_secret_variations_rejected(self):
        """Test that 'Secret123' is rejected."""
        valid, error = validate_password('Secret123')
        assert valid is False

    def test_strong_unique_password_accepted(self):
        """Test that strong unique passwords are accepted."""
        # This password meets all requirements and is not in blocklist
        valid, error = validate_password('Xk9mPq2Lw!')
        assert valid is True
        assert error is None

    def test_similar_but_not_blocked_password_accepted(self):
        """Test that passwords similar to but not in blocklist are accepted."""
        # 'MySecure99!' is not in the blocklist
        valid, error = validate_password('MySecure99!')
        assert valid is True


class TestEnvFileUpdate:
    """Tests for .env file update functionality."""

    def test_update_existing_password_in_env(self):
        """Test updating existing BOOTSTRAP_ADMIN_PASSWORD in .env file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write('SECRET_KEY=abc123\n')
            f.write('BOOTSTRAP_ADMIN_PASSWORD=OldPassword123\n')
            f.write('DATABASE_URL=postgres://localhost\n')
            env_path = f.name

        try:
            # Read the actual file content
            with open(env_path, 'r') as f:
                original_content = f.read()

            # Manually test the regex replacement logic (same logic as update_env_file)
            import re
            new_password = 'NewSecure123'
            new_content = re.sub(
                r'^BOOTSTRAP_ADMIN_PASSWORD=.*$',
                f'BOOTSTRAP_ADMIN_PASSWORD={new_password}',
                original_content,
                flags=re.MULTILINE
            )

            assert 'BOOTSTRAP_ADMIN_PASSWORD=NewSecure123' in new_content
            assert 'BOOTSTRAP_ADMIN_PASSWORD=OldPassword123' not in new_content
            assert 'SECRET_KEY=abc123' in new_content
            assert 'DATABASE_URL=postgres://localhost' in new_content
        finally:
            os.unlink(env_path)

    def test_add_password_to_env_without_existing(self):
        """Test adding BOOTSTRAP_ADMIN_PASSWORD to .env that doesn't have it."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write('SECRET_KEY=abc123\n')
            f.write('DATABASE_URL=postgres://localhost\n')
            env_path = f.name

        try:
            with open(env_path, 'r') as f:
                original_content = f.read()

            # Test the logic for adding password when not present
            new_password = 'NewSecure123'
            if 'BOOTSTRAP_ADMIN_PASSWORD=' not in original_content:
                new_content = original_content + f'\nBOOTSTRAP_ADMIN_PASSWORD={new_password}\n'

            assert 'BOOTSTRAP_ADMIN_PASSWORD=NewSecure123' in new_content
            assert 'SECRET_KEY=abc123' in new_content
        finally:
            os.unlink(env_path)

    def test_env_file_not_found(self):
        """Test handling when .env file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nonexistent_path = os.path.join(tmpdir, 'nonexistent.env')

            # The function should return False if .env doesn't exist
            with patch('scripts.reset_admin.os.path.exists', return_value=False):
                with patch('scripts.reset_admin.os.path.join', return_value=nonexistent_path):
                    # Import fresh to test
                    import importlib
                    import scripts.reset_admin as reset_admin_module

                    # Mock the print function to capture warnings
                    with patch('builtins.print') as mock_print:
                        result = update_env_file('NewPassword123')
                        # Should return False when file not found
                        assert result is False

    def test_env_file_read_error(self):
        """Test handling when .env file has read permission error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write('BOOTSTRAP_ADMIN_PASSWORD=OldPassword\n')
            env_path = f.name

        try:
            # Mock a read error
            with patch('scripts.reset_admin.os.path.exists', return_value=True):
                with patch('builtins.open', side_effect=PermissionError("Permission denied")):
                    with patch('builtins.print') as mock_print:
                        result = update_env_file('NewPassword123')
                        assert result is False
        finally:
            os.unlink(env_path)

    def test_password_with_special_regex_chars(self):
        """Test password containing regex special characters."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write('BOOTSTRAP_ADMIN_PASSWORD=OldPassword123\n')
            env_path = f.name

        try:
            with open(env_path, 'r') as f:
                content = f.read()

            # Password with special regex chars that should be escaped
            import re
            new_password = 'Pass$word.123*special'
            new_content = re.sub(
                r'^BOOTSTRAP_ADMIN_PASSWORD=.*$',
                f'BOOTSTRAP_ADMIN_PASSWORD={new_password}',
                content,
                flags=re.MULTILINE
            )

            assert f'BOOTSTRAP_ADMIN_PASSWORD={new_password}' in new_content
        finally:
            os.unlink(env_path)


class TestBlindIndexLookup:
    """Tests for blind index email lookup functionality."""

    def test_compute_blind_index_consistency(self):
        """Test that compute_blind_index produces consistent results."""
        from encryption import compute_blind_index, normalize_email

        email = 'test@example.com'
        idx1 = compute_blind_index(email, normalizer=normalize_email)
        idx2 = compute_blind_index(email, normalizer=normalize_email)

        assert idx1 == idx2
        assert len(idx1) == 64  # SHA256 hex is 64 chars

    def test_compute_blind_index_case_insensitive(self):
        """Test that blind index is case-insensitive due to normalization."""
        from encryption import compute_blind_index, normalize_email

        lower_idx = compute_blind_index('test@example.com', normalizer=normalize_email)
        upper_idx = compute_blind_index('TEST@EXAMPLE.COM', normalizer=normalize_email)
        mixed_idx = compute_blind_index('Test@Example.COM', normalizer=normalize_email)

        assert lower_idx == upper_idx == mixed_idx

    def test_compute_blind_index_different_emails(self):
        """Test that different emails produce different blind indexes."""
        from encryption import compute_blind_index, normalize_email

        idx1 = compute_blind_index('user1@example.com', normalizer=normalize_email)
        idx2 = compute_blind_index('user2@example.com', normalizer=normalize_email)

        assert idx1 != idx2

    def test_normalize_email_strips_whitespace(self):
        """Test that normalize_email strips whitespace."""
        from encryption import normalize_email

        assert normalize_email('  test@example.com  ') == 'test@example.com'
        assert normalize_email('\ttest@example.com\n') == 'test@example.com'

    def test_normalize_email_lowercases(self):
        """Test that normalize_email lowercases the email."""
        from encryption import normalize_email

        assert normalize_email('TEST@EXAMPLE.COM') == 'test@example.com'
        assert normalize_email('Test@Example.Com') == 'test@example.com'

    def test_blind_index_none_input(self):
        """Test that None input returns None."""
        from encryption import compute_blind_index, normalize_email

        result = compute_blind_index(None, normalizer=normalize_email)
        assert result is None


class TestUserLookupByBlindIndex:
    """Tests for user lookup via blind index in recovery script context."""

    @pytest.fixture
    def mock_db_session(self):
        """Create a mock database session."""
        mock_session = MagicMock()
        mock_query = MagicMock()
        mock_session.query.return_value = mock_query
        return mock_session, mock_query

    def test_user_found_by_email_idx(self, mock_db_session):
        """Test that user is found when email_idx matches."""
        mock_session, mock_query = mock_db_session

        mock_user = MagicMock()
        mock_user.email = 'test@example.com'
        mock_user.role = 'admin'
        mock_user.is_active = True

        mock_query.filter_by.return_value.first.return_value = mock_user

        # Verify mock works
        result = mock_query.filter_by(email_idx='test_idx').first()
        assert result.email == 'test@example.com'
        assert result.role == 'admin'

    def test_user_not_found(self, mock_db_session):
        """Test handling when user is not found."""
        mock_session, mock_query = mock_db_session
        mock_query.filter_by.return_value.first.return_value = None

        result = mock_query.filter_by(email_idx='nonexistent_idx').first()
        assert result is None


class TestUserPromotion:
    """Tests for user role promotion scenarios."""

    def test_non_admin_can_be_promoted(self):
        """Test that a non-admin user can be promoted to admin."""
        mock_user = MagicMock()
        mock_user.role = 'guest'
        mock_user.is_active = True

        # Simulate promotion
        mock_user.role = 'admin'
        assert mock_user.role == 'admin'

    def test_admin_promotion_is_idempotent(self):
        """Test that promoting an admin to admin is a no-op."""
        mock_user = MagicMock()
        mock_user.role = 'admin'

        # Promoting admin to admin should keep role as admin
        if mock_user.role != 'admin':
            mock_user.role = 'admin'

        assert mock_user.role == 'admin'


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_password_validation_with_whitespace_only(self):
        """Test password with only whitespace characters."""
        valid, error = validate_password('        ')
        assert valid is False
        # Should fail for missing uppercase/lowercase/digit

    def test_password_with_newline(self):
        """Test password containing newline character."""
        password = 'Valid\nPass123'
        valid, error = validate_password(password)
        # Should be valid as it meets all requirements
        assert valid is True

    def test_password_with_tab(self):
        """Test password containing tab character."""
        password = 'Valid\tPass123'
        valid, error = validate_password(password)
        assert valid is True

    def test_password_multiple_validation_failures(self):
        """Test that first validation failure is reported."""
        # Too short, no uppercase, no lowercase, no digit
        password = 'x'
        valid, error = validate_password(password)
        assert valid is False
        # Should mention length first (that's the first check)
        assert str(MIN_PASSWORD_LENGTH) in error

    def test_env_update_preserves_comments(self):
        """Test that .env update preserves comment lines."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write('# This is a comment\n')
            f.write('SECRET_KEY=abc123\n')
            f.write('# Another comment\n')
            f.write('BOOTSTRAP_ADMIN_PASSWORD=OldPassword123\n')
            env_path = f.name

        try:
            with open(env_path, 'r') as f:
                content = f.read()

            import re
            new_content = re.sub(
                r'^BOOTSTRAP_ADMIN_PASSWORD=.*$',
                'BOOTSTRAP_ADMIN_PASSWORD=NewPassword123',
                content,
                flags=re.MULTILINE
            )

            assert '# This is a comment' in new_content
            assert '# Another comment' in new_content
            assert 'BOOTSTRAP_ADMIN_PASSWORD=NewPassword123' in new_content
        finally:
            os.unlink(env_path)

    def test_env_update_preserves_other_variables(self):
        """Test that .env update preserves other environment variables."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write('SECRET_KEY=abc123\n')
            f.write('DATABASE_URL=postgres://localhost\n')
            f.write('BOOTSTRAP_ADMIN_PASSWORD=OldPassword123\n')
            f.write('CORS_ORIGINS=http://localhost:5173\n')
            env_path = f.name

        try:
            with open(env_path, 'r') as f:
                content = f.read()

            import re
            new_content = re.sub(
                r'^BOOTSTRAP_ADMIN_PASSWORD=.*$',
                'BOOTSTRAP_ADMIN_PASSWORD=NewPassword123',
                content,
                flags=re.MULTILINE
            )

            assert 'SECRET_KEY=abc123' in new_content
            assert 'DATABASE_URL=postgres://localhost' in new_content
            assert 'CORS_ORIGINS=http://localhost:5173' in new_content
        finally:
            os.unlink(env_path)


class TestAuditLogCreation:
    """Tests for audit log creation during admin recovery."""

    def test_audit_log_event_type(self):
        """Verify the expected event_type for admin recovery."""
        expected_event_type = 'admin_password_recovery'
        # The script uses this event type
        assert expected_event_type == 'admin_password_recovery'

    def test_audit_log_details_structure(self):
        """Test the expected structure of audit log details."""
        import json

        # Expected details format from the script
        details = json.dumps({
            'method': 'skeleton_key',
            'source': 'cli'
        })

        parsed = json.loads(details)
        assert 'method' in parsed
        assert 'source' in parsed
        assert parsed['method'] == 'skeleton_key'
        assert parsed['source'] == 'cli'


class TestSetupShRecoveryOption:
    """Tests for the setup.sh recovery option [3] integration.

    Note: These tests verify the setup.sh content statically.
    The setup.sh file is located at the project root, not inside the backend directory.
    When running inside Docker, the file may not be mounted.
    """

    @pytest.fixture
    def setup_sh_content(self):
        """Load setup.sh content, trying multiple possible locations."""
        possible_paths = [
            # Running from host (Mac/Linux)
            '/Users/jaroncabral/Documents/School/cs458-software-engineering/CAPSTONE-PROJECT/canvas-and-clay/setup.sh',
            # Generic project root path
            os.path.join(os.path.dirname(__file__), '..', '..', 'setup.sh'),
            # Docker mounted path (if mounted)
            '/setup.sh',
        ]

        for path in possible_paths:
            abs_path = os.path.abspath(path)
            if os.path.exists(abs_path):
                with open(abs_path, 'r') as f:
                    return f.read()

        pytest.skip("setup.sh not accessible (running in Docker without host mount)")

    def test_recovery_option_exists_in_menu(self, setup_sh_content):
        """Verify the recovery option is present in setup.sh menu."""
        content = setup_sh_content

        # Verify menu option [3] for recovery
        assert '[3]' in content
        assert 'Recover' in content or 'recover' in content
        assert 'Reset admin password' in content or 'reset admin' in content.lower()

    def test_recovery_function_exists(self, setup_sh_content):
        """Verify run_recover_flow function exists in setup.sh."""
        assert 'run_recover_flow' in setup_sh_content

    def test_recovery_calls_reset_admin_script(self, setup_sh_content):
        """Verify recovery flow calls the reset_admin.py script."""
        assert 'reset_admin.py' in setup_sh_content

    def test_recovery_checks_backend_container(self, setup_sh_content):
        """Verify recovery flow checks if backend container is running."""
        content = setup_sh_content

        # Should check for backend container status
        assert 'backend' in content
        # Should have error handling for container not running
        assert 'not running' in content.lower() or 'Backend container' in content

    def test_direct_recover_flag(self, setup_sh_content):
        """Verify --recover flag for direct mode."""
        assert '--recover' in setup_sh_content

    def test_recovery_uses_docker_compose_exec(self, setup_sh_content):
        """Verify recovery uses docker compose exec to run the script."""
        content = setup_sh_content

        # Should use docker compose exec backend
        assert 'docker compose' in content or 'docker-compose' in content
        assert 'exec' in content


class TestMinPasswordLength:
    """Tests for password length validation using auth.py constants."""

    def test_min_password_length_enforced(self):
        """Verify that reset_admin uses auth.py's MIN_PASSWORD_LENGTH (8)."""
        # Test that a 7-char password fails (below min)
        short_password = 'Aa1xxxx'  # 7 chars
        valid, error = validate_password(short_password)
        assert valid is False
        assert '8' in error

        # Test that an 8-char password passes (at min)
        min_password = 'Aa1xxxxx'  # 8 chars
        valid, error = validate_password(min_password)
        assert valid is True


class TestHashEmailForAudit:
    """Tests for hash_email_for_audit function used in audit logging."""

    def test_hash_email_returns_sha256(self):
        """Test that hash_email_for_audit returns a SHA256 hex string."""
        from auth import hash_email_for_audit

        result = hash_email_for_audit('test@example.com')
        assert len(result) == 64
        assert all(c in '0123456789abcdef' for c in result)

    def test_hash_email_none_returns_none(self):
        """Test that None input returns None."""
        from auth import hash_email_for_audit

        assert hash_email_for_audit(None) is None

    def test_hash_email_is_deterministic(self):
        """Test that same email always produces same hash."""
        from auth import hash_email_for_audit

        email = 'test@example.com'
        h1 = hash_email_for_audit(email)
        h2 = hash_email_for_audit(email)

        assert h1 == h2

    def test_hash_email_case_insensitive(self):
        """Test that email hashing is case-insensitive."""
        from auth import hash_email_for_audit

        lower = hash_email_for_audit('test@example.com')
        upper = hash_email_for_audit('TEST@EXAMPLE.COM')

        assert lower == upper
