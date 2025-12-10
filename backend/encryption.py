"""Probabilistic encryption with blind index for PII-at-rest.

THREAT MODEL
============
This module protects PII (e.g., user emails) from exposure in database dumps,
backups, and direct database access. It uses:
- Probabilistic encryption (random nonce) - same plaintext produces different ciphertexts
- Blind index for lookups - keyed HMAC allows searching without revealing patterns

SECURITY PROPERTIES
===================
- Identical plaintexts produce DIFFERENT ciphertexts (random nonce)
- Attackers cannot detect when two users have the same email from ciphertext alone
- Lookups use blind index (HMAC) which is one-way and keyed
- Separate keys for encryption and blind index (defense in depth)

BLIND INDEX
===========
The blind index is a keyed HMAC-SHA256 truncated to 32 bytes (hex-encoded to 64 chars).
It enables:
- Equality comparisons (WHERE email_idx = ?)
- Unique constraints
- Index lookups

The blind index does NOT reveal:
- The plaintext value
- Whether two different tables have the same value (different keys possible)

KEY MANAGEMENT
==============
- Set PII_ENCRYPTION_KEY environment variable in production
- Set PII_BLIND_INDEX_KEY for blind index (falls back to derived key if not set)
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

Blind index is fixed at 64 characters (32-byte HMAC, hex-encoded).
"""

import base64
import hmac
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


def _derive_blind_index_key():
    """Derive a separate key for blind index computation.

    Uses PII_BLIND_INDEX_KEY if set, otherwise derives from encryption key
    with a domain separator to ensure the keys are different.

    Returns:
        32-byte key for HMAC operations
    """
    blind_key_env = os.getenv("PII_BLIND_INDEX_KEY")
    if blind_key_env:
        return sha256(blind_key_env.encode("utf-8")).digest()
    # Derive from encryption key with domain separator
    return sha256(b"blind-index:" + _KEY).digest()


_BLIND_INDEX_KEY = _derive_blind_index_key()


def _random_nonce() -> bytes:
    """Generate a cryptographically random 12-byte nonce.

    Returns:
        12-byte random nonce suitable for AES-GCM
    """
    return secrets.token_bytes(12)


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


def compute_blind_index(value: str, normalizer=None) -> str:
    """Compute a blind index for a plaintext value.

    The blind index is a keyed HMAC that allows equality lookups without
    revealing the plaintext. It is deterministic (same input = same output)
    but cannot be reversed to recover the plaintext.

    Args:
        value: Plaintext string to index (None passes through unchanged)
        normalizer: Optional function to normalize value before hashing
                   (e.g., normalize_email for case-insensitive matching)

    Returns:
        64-character hex string (32-byte HMAC), or None if input was None
    """
    if value is None:
        return None
    normalized = normalizer(value) if normalizer else value
    return hmac.new(
        _BLIND_INDEX_KEY,
        normalized.encode("utf-8"),
        "sha256"
    ).hexdigest()


def _encrypt(value: str, normalizer=None, deterministic=False) -> str:
    """Encrypt a string value using AES-GCM.

    By default uses probabilistic encryption (random nonce) which is more
    secure. Set deterministic=True only for backward compatibility during
    migration.

    Args:
        value: Plaintext string to encrypt (None passes through unchanged)
        normalizer: Optional function to normalize value before encryption
                   (e.g., lowercase email).
        deterministic: If True, use deterministic nonce (LEGACY - avoid in new code)

    Returns:
        URL-safe base64-encoded ciphertext (nonce || ciphertext || tag),
        or None if input was None
    """
    if value is None:
        return None
    normalized = normalizer(value) if normalizer else value
    aes = AESGCM(_KEY)
    if deterministic:
        nonce = _deterministic_nonce(normalized)
    else:
        nonce = _random_nonce()
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
    """Normalize email for consistent blind index computation.

    Strips whitespace and lowercases to ensure:
    - "User@Example.com" and "user@example.com" produce same blind index
    - Leading/trailing spaces don't cause duplicate entries

    Args:
        value: Raw email string

    Returns:
        Normalized email (stripped, lowercased)
    """
    return value.strip().lower()


class EncryptedString(TypeDecorator):
    """SQLAlchemy type that transparently encrypts string columns at rest.

    Uses AES-GCM with RANDOM nonce (probabilistic encryption). This means:
    - Same plaintext produces DIFFERENT ciphertexts each time
    - Cannot use for equality comparisons or unique constraints
    - Must use a separate blind index column for lookups

    For searchable encrypted fields, pair with a blind index column:
        email = Column(EncryptedString(255, normalizer=normalize_email))
        email_idx = Column(String(64), unique=True, index=True)

    Then compute the index with compute_blind_index() when inserting/querying.

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
        """Encrypt value before storing in database (probabilistic)."""
        if value is None:
            return None
        return _encrypt(str(value), self.normalizer, deterministic=False)

    def process_result_value(self, value, dialect):
        """Decrypt value when reading from database."""
        if value is None:
            return None
        return _decrypt(value)
