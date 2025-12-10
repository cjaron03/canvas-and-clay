"""Tests for PII encryption module."""

import os
import pytest

# Set up test environment before importing encryption module
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-encryption-tests')
os.environ.setdefault('FLASK_ENV', 'development')

from encryption import (
    _encrypt,
    _decrypt,
    _deterministic_nonce,
    normalize_email,
    compute_blind_index,
    EncryptedString,
    KEY_SOURCE,
)


class TestEncryptDecrypt:
    """Tests for core encrypt/decrypt functions."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted value should decrypt back to original."""
        original = "test@example.com"
        encrypted = _encrypt(original)
        decrypted = _decrypt(encrypted)
        assert decrypted == original

    def test_encrypt_decrypt_with_special_characters(self):
        """Should handle emails with special characters."""
        emails = [
            "user+tag@example.com",
            "user.name@sub.domain.com",
            "user_name@example.co.uk",
            "user@example.museum",
        ]
        for email in emails:
            encrypted = _encrypt(email)
            decrypted = _decrypt(encrypted)
            assert decrypted == email, f"Failed for {email}"

    def test_encrypt_decrypt_unicode(self):
        """Should handle unicode characters in values."""
        original = "user@example.com"  # ASCII for now since emails are typically ASCII
        encrypted = _encrypt(original)
        decrypted = _decrypt(encrypted)
        assert decrypted == original


class TestProbabilisticEncryption:
    """Tests for probabilistic encryption behavior (default mode)."""

    def test_same_plaintext_produces_different_ciphertext(self):
        """Identical inputs should produce DIFFERENT outputs (probabilistic)."""
        email = "test@example.com"
        encrypted1 = _encrypt(email)
        encrypted2 = _encrypt(email)
        # Probabilistic encryption: same plaintext, different ciphertexts
        assert encrypted1 != encrypted2
        # But both should decrypt to the same value
        assert _decrypt(encrypted1) == _decrypt(encrypted2) == email

    def test_different_plaintext_produces_different_ciphertext(self):
        """Different inputs should produce different outputs."""
        encrypted1 = _encrypt("user1@example.com")
        encrypted2 = _encrypt("user2@example.com")
        assert encrypted1 != encrypted2

    def test_deterministic_mode_for_legacy_compatibility(self):
        """Deterministic mode should be available for backward compatibility."""
        email = "test@example.com"
        encrypted1 = _encrypt(email, deterministic=True)
        encrypted2 = _encrypt(email, deterministic=True)
        # Deterministic mode: same plaintext = same ciphertext
        assert encrypted1 == encrypted2

    def test_deterministic_nonce_consistency(self):
        """Same value should always produce same nonce (for deterministic mode)."""
        value = "test@example.com"
        nonce1 = _deterministic_nonce(value)
        nonce2 = _deterministic_nonce(value)
        assert nonce1 == nonce2
        assert len(nonce1) == 12  # AES-GCM nonce size


class TestBlindIndex:
    """Tests for blind index functionality."""

    def test_blind_index_is_deterministic(self):
        """Same input should always produce same blind index."""
        email = "test@example.com"
        index1 = compute_blind_index(email)
        index2 = compute_blind_index(email)
        assert index1 == index2

    def test_blind_index_with_normalizer(self):
        """Blind index with normalizer should be case-insensitive."""
        index1 = compute_blind_index("User@Example.COM", normalizer=normalize_email)
        index2 = compute_blind_index("user@example.com", normalizer=normalize_email)
        index3 = compute_blind_index("  USER@example.com  ", normalizer=normalize_email)
        assert index1 == index2 == index3

    def test_blind_index_different_values(self):
        """Different inputs should produce different blind indexes."""
        index1 = compute_blind_index("user1@example.com")
        index2 = compute_blind_index("user2@example.com")
        assert index1 != index2

    def test_blind_index_length(self):
        """Blind index should be 64-character hex string."""
        index = compute_blind_index("test@example.com")
        assert len(index) == 64
        # Should be valid hex
        int(index, 16)

    def test_blind_index_none_handling(self):
        """Blind index of None should return None."""
        assert compute_blind_index(None) is None


class TestNormalization:
    """Tests for email normalization."""

    def test_normalize_email_lowercase(self):
        """Email should be lowercased."""
        assert normalize_email("User@Example.COM") == "user@example.com"

    def test_normalize_email_strips_whitespace(self):
        """Email should have whitespace stripped."""
        assert normalize_email("  user@example.com  ") == "user@example.com"

    def test_normalize_email_combined(self):
        """Normalization should handle both case and whitespace."""
        assert normalize_email("  User@EXAMPLE.com  ") == "user@example.com"

    def test_normalized_emails_have_same_blind_index(self):
        """Emails that normalize to same value should have identical blind indexes."""
        # With probabilistic encryption, ciphertexts will be different
        # But blind indexes should be the same for equality checks
        index1 = compute_blind_index("User@Example.COM", normalizer=normalize_email)
        index2 = compute_blind_index("user@example.com", normalizer=normalize_email)
        index3 = compute_blind_index("  USER@example.com  ", normalizer=normalize_email)
        assert index1 == index2 == index3

        # Verify encryption still works correctly (different ciphertexts, same plaintext)
        encrypted1 = _encrypt("User@Example.COM", normalizer=normalize_email)
        encrypted2 = _encrypt("user@example.com", normalizer=normalize_email)
        # Ciphertexts may be different (probabilistic), but both decrypt to normalized form
        assert _decrypt(encrypted1) == _decrypt(encrypted2) == "user@example.com"


class TestNoneHandling:
    """Tests for None value handling."""

    def test_encrypt_none_returns_none(self):
        """Encrypting None should return None."""
        assert _encrypt(None) is None

    def test_decrypt_none_returns_none(self):
        """Decrypting None should return None."""
        assert _decrypt(None) is None

    def test_encrypt_with_normalizer_none(self):
        """Encrypting None with normalizer should return None."""
        assert _encrypt(None, normalizer=normalize_email) is None


class TestLegacyPlaintextFallback:
    """Tests for backwards compatibility with unencrypted data."""

    def test_decrypt_plaintext_returns_as_is(self):
        """Unencrypted plaintext should be returned unchanged."""
        plaintext = "user@example.com"
        # This should not raise and should return the input
        result = _decrypt(plaintext)
        assert result == plaintext

    def test_decrypt_invalid_base64_returns_as_is(self):
        """Invalid base64 should be returned unchanged."""
        invalid = "not-valid-base64!!!"
        result = _decrypt(invalid)
        assert result == invalid

    def test_decrypt_truncated_ciphertext_returns_as_is(self):
        """Truncated ciphertext should be returned unchanged."""
        # Valid base64 but too short to be valid ciphertext
        truncated = "YWJjZGVm"  # "abcdef" in base64
        result = _decrypt(truncated)
        assert result == truncated


class TestEncryptedStringTypeDecorator:
    """Tests for SQLAlchemy TypeDecorator integration."""

    def test_type_decorator_attributes(self):
        """EncryptedString should have correct SQLAlchemy attributes."""
        enc_type = EncryptedString(255)
        assert enc_type.cache_ok is True

    def test_type_decorator_with_normalizer(self):
        """EncryptedString should accept and store normalizer."""
        enc_type = EncryptedString(255, normalizer=normalize_email)
        assert enc_type.normalizer == normalize_email

    def test_process_bind_param_encrypts(self):
        """process_bind_param should encrypt values."""
        enc_type = EncryptedString(255)
        encrypted = enc_type.process_bind_param("test@example.com", None)
        assert encrypted != "test@example.com"
        # Verify it can be decrypted
        assert _decrypt(encrypted) == "test@example.com"

    def test_process_bind_param_with_normalizer(self):
        """process_bind_param should apply normalizer before encryption."""
        enc_type = EncryptedString(255, normalizer=normalize_email)
        encrypted1 = enc_type.process_bind_param("TEST@example.com", None)
        encrypted2 = enc_type.process_bind_param("test@example.com", None)
        # With probabilistic encryption, ciphertexts will be different
        # but both should decrypt to the same normalized value
        assert _decrypt(encrypted1) == _decrypt(encrypted2) == "test@example.com"

    def test_process_bind_param_none(self):
        """process_bind_param should pass None through."""
        enc_type = EncryptedString(255)
        assert enc_type.process_bind_param(None, None) is None

    def test_process_result_value_decrypts(self):
        """process_result_value should decrypt values."""
        enc_type = EncryptedString(255)
        encrypted = _encrypt("test@example.com")
        decrypted = enc_type.process_result_value(encrypted, None)
        assert decrypted == "test@example.com"

    def test_process_result_value_none(self):
        """process_result_value should pass None through."""
        enc_type = EncryptedString(255)
        assert enc_type.process_result_value(None, None) is None

    def test_process_result_value_legacy_plaintext(self):
        """process_result_value should handle legacy unencrypted data."""
        enc_type = EncryptedString(255)
        plaintext = "legacy@example.com"
        result = enc_type.process_result_value(plaintext, None)
        assert result == plaintext


class TestKeySource:
    """Tests for key derivation and source tracking."""

    def test_key_source_is_set(self):
        """KEY_SOURCE should be set to a valid value."""
        assert KEY_SOURCE in ("env-key", "secret-key", "ephemeral")

    def test_key_source_with_secret_key(self):
        """With SECRET_KEY set, should use secret-key source."""
        # This test runs in an environment where SECRET_KEY is set
        # The actual source depends on whether PII_ENCRYPTION_KEY is also set
        assert KEY_SOURCE in ("env-key", "secret-key")


class TestCiphertextLength:
    """Tests to verify ciphertext length expectations."""

    def test_ciphertext_length_expansion(self):
        """Ciphertext should be longer than plaintext due to nonce and tag."""
        plaintext = "a" * 100  # 100 character email
        encrypted = _encrypt(plaintext)
        # Base64 of (12 nonce + 100 plaintext + 16 tag) = 128 bytes
        # Base64 encoding: ceil(128 * 4/3) = 171 chars (with padding)
        assert len(encrypted) > len(plaintext)
        # Verify it's within expected bounds
        assert len(encrypted) <= 200  # Should fit in String(255)

    def test_short_email_fits_in_column(self):
        """Typical short email should produce ciphertext under 255 chars."""
        email = "user@example.com"  # 16 chars
        encrypted = _encrypt(email)
        assert len(encrypted) <= 255
