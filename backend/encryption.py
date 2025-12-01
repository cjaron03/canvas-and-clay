"""Lightweight deterministic encryption helpers for PII-at-rest.

THREAT MODEL
============
This module protects PII (e.g., user emails) from exposure in database dumps,
backups, and direct database access. It does NOT protect against:
- Attackers with access to the running application (they can query decrypted data)
- Attackers who can observe ciphertext patterns (deterministic encryption leaks equality)

DETERMINISTIC ENCRYPTION TRADE-OFFS
===================================
This implementation uses deterministic encryption (nonce derived from plaintext)
which enables:
- Unique constraints on encrypted columns
- Equality comparisons (WHERE email = ?)
- Index lookups

However, identical plaintexts produce identical ciphertexts. An attacker with
database access can:
- Detect when two users have the same email
- Build a dictionary by encrypting known values and matching ciphertexts

For higher security requirements, consider randomized encryption with a
separate hash column for lookups.

KEY MANAGEMENT
==============
- Set PII_ENCRYPTION_KEY environment variable in production
- Falls back to SECRET_KEY if PII_ENCRYPTION_KEY is not set
- Generates ephemeral key in development mode only (data lost on restart)
- Key rotation supported via rotate_encryption_key.py script

COLUMN SIZING
=============
Encrypted values are longer than plaintext due to:
- 12-byte nonce prefix
- 16-byte authentication tag
- Base64 encoding (~4/3x expansion)

Formula: ceil((len(plaintext) + 12 + 16) * 4 / 3)
Example: 100-char email -> ~176 chars encrypted
Recommendation: Use String(255) or larger for encrypted email columns.
"""

import base64
import os
import secrets
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.types import TypeDecorator, String


def _is_test_environment():
    """Check if running in a test environment (pytest, CI, etc.)."""
    import sys
    # Check for pytest environment variable
    if os.getenv('PYTEST_CURRENT_TEST') is not None:
        return True
    # Check for CI environment (GitHub Actions, etc.)
    if os.getenv('CI') is not None:
        return True
    # Check if pytest is in sys.modules
    if 'pytest' in sys.modules:
        return True
    return False


def _derive_key():
    """Derive a 32-byte AES key from environment variables.

    Key sources (in priority order):
    1. PII_ENCRYPTION_KEY - Recommended for production
    2. SECRET_KEY - Fallback, but not recommended (shared with sessions)
    3. Ephemeral random key - Development/test only, raises in production

    Returns:
        tuple: (32-byte key, source identifier string)

    Raises:
        RuntimeError: If no key is configured and not in development/test mode
    """
    key_env = os.getenv("PII_ENCRYPTION_KEY")
    secret_env = os.getenv("SECRET_KEY")
    flask_env = os.getenv("FLASK_ENV", "production")
    is_dev = flask_env == "development"
    is_test = _is_test_environment()

    if key_env:
        source = "env-key"
        raw = key_env
    elif secret_env:
        source = "secret-key"
        raw = secret_env
    else:
        if not is_dev and not is_test:
            raise RuntimeError(
                "PII_ENCRYPTION_KEY or SECRET_KEY must be set in production. "
                "Set FLASK_ENV=development to use ephemeral dev key."
            )
        source = "ephemeral"
        raw = secrets.token_urlsafe(32)

    # Normalize to 32 bytes using SHA-256 to handle arbitrary input length
    return sha256(raw.encode("utf-8")).digest(), source


_KEY, _KEY_SOURCE = _derive_key()
KEY_SOURCE = _KEY_SOURCE  # exported for status logging


def _deterministic_nonce(value: str) -> bytes:
    """Derive a deterministic 12-byte nonce from the plaintext.

    WARNING: This makes encryption deterministic - identical plaintexts produce
    identical ciphertexts. This is intentional to support unique constraints
    and equality comparisons, but leaks equality patterns to attackers with
    database access.

    Args:
        value: The plaintext string to derive nonce from

    Returns:
        12-byte nonce suitable for AES-GCM
    """
    return sha256(value.encode("utf-8")).digest()[:12]


def _encrypt(value: str, normalizer=None) -> str:
    """Encrypt a string value using AES-GCM.

    Args:
        value: Plaintext string to encrypt (None passes through unchanged)
        normalizer: Optional function to normalize value before encryption
                   (e.g., lowercase email). Applied before nonce derivation
                   to ensure consistent ciphertext for equivalent inputs.

    Returns:
        URL-safe base64-encoded ciphertext (nonce || ciphertext || tag),
        or None if input was None
    """
    if value is None:
        return None
    normalized = normalizer(value) if normalizer else value
    aes = AESGCM(_KEY)
    nonce = _deterministic_nonce(normalized)
    ciphertext = aes.encrypt(nonce, normalized.encode("utf-8"), associated_data=None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")


def _decrypt(token: str) -> str:
    """Decrypt a ciphertext token back to plaintext.

    Args:
        token: Base64-encoded ciphertext from _encrypt(), or legacy plaintext

    Returns:
        Decrypted plaintext string, or the original token if decryption fails
        (supports graceful migration from unencrypted data)
    """
    if token is None:
        return None
    try:
        data = base64.urlsafe_b64decode(token.encode("utf-8"))
        nonce, ct = data[:12], data[12:]
        aes = AESGCM(_KEY)
        plaintext = aes.decrypt(nonce, ct, associated_data=None)
        return plaintext.decode("utf-8")
    except Exception:
        # If the value was stored before encryption was enabled, return it as-is.
        # This supports graceful migration: old plaintext data continues to work
        # while new data is encrypted.
        return token


def normalize_email(value: str) -> str:
    """Normalize email for consistent encryption.

    Strips whitespace and lowercases to ensure:
    - "User@Example.com" and "user@example.com" produce same ciphertext
    - Leading/trailing spaces don't cause duplicate entries

    Args:
        value: Raw email string

    Returns:
        Normalized email (stripped, lowercased)
    """
    return value.strip().lower()


class EncryptedString(TypeDecorator):
    """SQLAlchemy type that transparently encrypts string columns at rest.

    Uses AES-GCM with deterministic nonce derived from plaintext, enabling:
    - Unique constraints on encrypted columns
    - Equality comparisons in WHERE clauses
    - Index lookups

    SECURITY NOTE: Deterministic encryption leaks equality patterns.
    See module docstring for threat model details.

    Example usage:
        email = Column(EncryptedString(255, normalizer=normalize_email),
                      unique=True, nullable=False)

    Args:
        length: Maximum column length (should account for ciphertext expansion)
        normalizer: Optional function applied before encryption (e.g., normalize_email)
    """

    impl = String
    cache_ok = True

    def __init__(self, length=None, normalizer=None, **kwargs):
        super().__init__(length=length, **kwargs)
        self.normalizer = normalizer

    def process_bind_param(self, value, dialect):
        """Encrypt value before storing in database."""
        if value is None:
            return None
        return _encrypt(str(value), self.normalizer)

    def process_result_value(self, value, dialect):
        """Decrypt value when reading from database."""
        if value is None:
            return None
        return _decrypt(value)
