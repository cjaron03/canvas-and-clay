"""Tests for backup encryption module."""
import os
import tempfile
import pytest

# Import the module under test
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backup_encryption import (
    validate_passphrase,
    encrypt_backup,
    decrypt_backup,
    is_encrypted_backup,
    read_encrypted_header,
    PassphraseValidationError,
    DecryptionError,
    InvalidBackupFormatError,
    MAGIC_BYTES,
    MIN_PASSPHRASE_LENGTH,
)


class TestPassphraseValidation:
    """Test passphrase validation logic."""

    def test_valid_passphrase(self):
        """Test that a valid passphrase passes validation."""
        is_valid, errors = validate_passphrase("SecurePass123!")
        assert is_valid is True
        assert len(errors) == 0

    def test_empty_passphrase(self):
        """Test that empty passphrase fails."""
        is_valid, errors = validate_passphrase("")
        assert is_valid is False
        assert "empty" in errors[0].lower()

    def test_short_passphrase(self):
        """Test that short passphrase fails."""
        is_valid, errors = validate_passphrase("Short1!")
        assert is_valid is False
        assert any("12 characters" in e for e in errors)

    def test_no_uppercase(self):
        """Test that passphrase without uppercase fails."""
        is_valid, errors = validate_passphrase("alllowercase123!")
        assert is_valid is False
        assert any("uppercase" in e.lower() for e in errors)

    def test_no_lowercase(self):
        """Test that passphrase without lowercase fails."""
        is_valid, errors = validate_passphrase("ALLUPPERCASE123!")
        assert is_valid is False
        assert any("lowercase" in e.lower() for e in errors)

    def test_no_digit_or_special(self):
        """Test that passphrase without digit or special char fails."""
        is_valid, errors = validate_passphrase("OnlyLettersHere")
        assert is_valid is False
        assert any("digit" in e.lower() or "special" in e.lower() for e in errors)

    def test_passphrase_with_special_char(self):
        """Test that passphrase with special char (no digit) passes."""
        is_valid, errors = validate_passphrase("SecurePass!!!")
        assert is_valid is True

    def test_passphrase_with_digit(self):
        """Test that passphrase with digit (no special) passes."""
        is_valid, errors = validate_passphrase("SecurePass1234")
        assert is_valid is True


class TestEncryptDecrypt:
    """Test encrypt/decrypt round-trip."""

    @pytest.fixture
    def sample_file(self):
        """Create a sample file for testing."""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.tar.gz', delete=False) as f:
            # Write some test data
            f.write(b"This is test backup data\n" * 1000)
            f.flush()
            yield f.name
        # Cleanup
        if os.path.exists(f.name):
            os.remove(f.name)

    @pytest.fixture
    def output_file(self):
        """Create path for encrypted output."""
        fd, path = tempfile.mkstemp(suffix='.tar.gz.enc')
        os.close(fd)
        yield path
        if os.path.exists(path):
            os.remove(path)

    @pytest.fixture
    def decrypted_file(self):
        """Create path for decrypted output."""
        fd, path = tempfile.mkstemp(suffix='.tar.gz')
        os.close(fd)
        yield path
        if os.path.exists(path):
            os.remove(path)

    def test_encrypt_decrypt_round_trip(self, sample_file, output_file, decrypted_file):
        """Test that encrypt -> decrypt produces original file."""
        passphrase = "SecureTestPass123!"

        # Get original content
        with open(sample_file, 'rb') as f:
            original_content = f.read()

        # Encrypt
        encrypt_info = encrypt_backup(sample_file, output_file, passphrase)
        assert encrypt_info['original_size'] == len(original_content)
        assert encrypt_info['algorithm'] == 'AES-256-GCM'
        assert encrypt_info['kdf'] == 'argon2id'

        # Verify encrypted file exists and is different
        assert os.path.exists(output_file)
        with open(output_file, 'rb') as f:
            encrypted_content = f.read()
        assert encrypted_content != original_content
        assert encrypted_content.startswith(MAGIC_BYTES)

        # Decrypt
        decrypt_info = decrypt_backup(output_file, decrypted_file, passphrase)
        assert decrypt_info['checksum_verified'] is True

        # Verify decrypted content matches original
        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        assert decrypted_content == original_content

    def test_wrong_passphrase_fails(self, sample_file, output_file, decrypted_file):
        """Test that wrong passphrase raises DecryptionError."""
        passphrase = "SecureTestPass123!"
        wrong_passphrase = "WrongPassword123!"

        # Encrypt
        encrypt_backup(sample_file, output_file, passphrase)

        # Decrypt with wrong passphrase
        with pytest.raises(DecryptionError):
            decrypt_backup(output_file, decrypted_file, wrong_passphrase)

    def test_weak_passphrase_rejected(self, sample_file, output_file):
        """Test that weak passphrase is rejected during encryption."""
        weak_passphrase = "weak"

        with pytest.raises(PassphraseValidationError):
            encrypt_backup(sample_file, output_file, weak_passphrase)

    def test_skip_passphrase_validation(self, sample_file, output_file, decrypted_file):
        """Test that passphrase validation can be skipped (for env key)."""
        # This simulates using an env key which shouldn't be validated as passphrase
        env_key = "not-a-valid-passphrase"

        # Encrypt with validation disabled
        encrypt_info = encrypt_backup(sample_file, output_file, env_key, validate_pass=False)
        assert encrypt_info['algorithm'] == 'AES-256-GCM'

        # Decrypt
        decrypt_info = decrypt_backup(output_file, decrypted_file, env_key)
        assert decrypt_info['checksum_verified'] is True


class TestEncryptedBackupDetection:
    """Test encrypted backup detection."""

    @pytest.fixture
    def sample_encrypted_file(self):
        """Create an encrypted sample file."""
        # Create source file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.tar.gz', delete=False) as src:
            src.write(b"Test data")
            src.flush()
            src_path = src.name

        # Create encrypted file
        fd, enc_path = tempfile.mkstemp(suffix='.tar.gz.enc')
        os.close(fd)

        encrypt_backup(src_path, enc_path, "SecureTestPass123!")
        os.remove(src_path)

        yield enc_path

        if os.path.exists(enc_path):
            os.remove(enc_path)

    @pytest.fixture
    def sample_unencrypted_file(self):
        """Create an unencrypted sample file."""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.tar.gz', delete=False) as f:
            # Write something that looks like a tar.gz
            f.write(b'\x1f\x8b\x08\x00')  # gzip magic bytes
            f.write(b'\x00' * 100)
            f.flush()
            yield f.name
        if os.path.exists(f.name):
            os.remove(f.name)

    def test_detect_encrypted_backup(self, sample_encrypted_file):
        """Test that encrypted backups are detected."""
        assert is_encrypted_backup(sample_encrypted_file) is True

    def test_detect_unencrypted_backup(self, sample_unencrypted_file):
        """Test that unencrypted backups are not detected as encrypted."""
        assert is_encrypted_backup(sample_unencrypted_file) is False

    def test_detect_nonexistent_file(self):
        """Test that non-existent files return False."""
        assert is_encrypted_backup("/nonexistent/file.tar.gz.enc") is False

    def test_read_encrypted_header(self, sample_encrypted_file):
        """Test reading header from encrypted backup."""
        header = read_encrypted_header(sample_encrypted_file)

        assert header is not None
        assert header['version'] == 1
        assert header['algorithm'] == 'AES-256-GCM'
        assert header['kdf'] == 'argon2id'
        assert 'nonce' in header
        assert 'kdf_params' in header
        assert 'salt' in header['kdf_params']
        assert 'original_checksum' in header

    def test_read_header_from_unencrypted(self, sample_unencrypted_file):
        """Test that reading header from unencrypted file returns None."""
        header = read_encrypted_header(sample_unencrypted_file)
        assert header is None


class TestCorruptedFiles:
    """Test handling of corrupted files."""

    @pytest.fixture
    def corrupted_encrypted_file(self):
        """Create a corrupted encrypted file."""
        fd, path = tempfile.mkstemp(suffix='.tar.gz.enc')
        with os.fdopen(fd, 'wb') as f:
            # Write magic bytes but corrupted content
            f.write(MAGIC_BYTES)
            f.write(b'\x00' * 4)  # Header length
            f.write(b'not valid json')
        yield path
        if os.path.exists(path):
            os.remove(path)

    def test_corrupted_header(self, corrupted_encrypted_file):
        """Test that corrupted header raises error."""
        with pytest.raises(InvalidBackupFormatError):
            read_encrypted_header(corrupted_encrypted_file)
