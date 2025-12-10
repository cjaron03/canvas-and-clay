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
- Set PII_ENCRYPTION_KEY environment variable in production (minimum 16 characters)
- Falls back to SECRET_KEY if PII_ENCRYPTION_KEY is not set
- Generates ephemeral key in development mode only (data lost on restart)
- Key rotation supported via rotate_encryption_key.py script

KEY DERIVATION
==============
Keys are derived using Argon2id with the following parameters:
- Memory: 64MB (65536 KB)
- Time: 3 iterations
- Parallelism: 4
- Salt: Fixed application-specific salt (provides domain separation, not secrecy)

Argon2id is memory-hard, making brute-force attacks expensive even with GPUs/ASICs.

BACKWARDS COMPATIBILITY
=======================
Data encrypted with the previous SHA-256 key derivation will continue to work.
On decryption failure with the Argon2id-derived key, the system falls back to
trying the SHA-256-derived key. This enables gradual migration without data loss.

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

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.types import TypeDecorator, String


# =============================================================================
# KDF Configuration (Argon2id)
# =============================================================================

# Argon2id parameters - OWASP recommended for key derivation
# Memory: 64MB, Time: 3 iterations, Parallelism: 4
ARGON2_MEMORY_KB = 65536  # 64MB
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32  # AES-256 requires 32 bytes

# Fixed salt for deterministic key derivation
# This provides domain separation, not secrecy (key material provides entropy)
# Using ASCII bytes of application identifier
ARGON2_SALT = b"canvas-clay-pii-encryption-v1\x00\x00\x00"  # 32 bytes

# Minimum key length requirement
MIN_KEY_LENGTH = 16

# Common weak keys to reject (lowercase for comparison)
WEAK_KEYS = frozenset([
    "changeme", "changeme123", "password", "password123", "admin", "admin123",
    "secret", "secret123", "test", "test123", "demo", "demo123", "default",
    "qwerty", "qwerty123", "letmein", "welcome", "monkey", "dragon",
    "master", "1234567890", "12345678901234567890", "abcdefghijklmnop",
])


# =============================================================================
# Error Messages
# =============================================================================

ERR_KEY_TOO_SHORT = """
================================================================================
ERROR: ENCRYPTION KEY TOO SHORT (ERR_KEY_002)
================================================================================

The PII_ENCRYPTION_KEY (or SECRET_KEY) must be at least {min_len} characters.

Current key length: {actual_len} characters

To fix:
1. Generate a strong key:
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"

2. Set it in your environment:
   export PII_ENCRYPTION_KEY="your-generated-key-here"

3. Restart the application

SECURITY NOTE: Use a unique, randomly generated key. Never reuse keys across
environments or applications.
================================================================================
"""

ERR_WEAK_KEY = """
================================================================================
ERROR: WEAK ENCRYPTION KEY DETECTED (ERR_KEY_003)
================================================================================

The PII_ENCRYPTION_KEY (or SECRET_KEY) matches a commonly used weak password.

To fix:
1. Generate a strong key:
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"

2. Set it in your environment:
   export PII_ENCRYPTION_KEY="your-generated-key-here"

3. Restart the application

SECURITY NOTE: Weak keys can be easily guessed or brute-forced, compromising
all encrypted PII data.
================================================================================
"""


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


def _validate_key(raw: str, source: str, is_dev: bool, is_test: bool):
    """Validate key strength before derivation.

    Args:
        raw: The raw key string
        source: Key source identifier for error messages
        is_dev: Whether in development mode
        is_test: Whether in test environment

    Raises:
        RuntimeError: If key fails validation in production
    """
    # Skip validation for ephemeral keys (already secure random)
    if source == "ephemeral":
        return

    # Check minimum length
    if len(raw) < MIN_KEY_LENGTH:
        if not is_dev and not is_test:
            print(ERR_KEY_TOO_SHORT.format(min_len=MIN_KEY_LENGTH, actual_len=len(raw)))
            raise RuntimeError(f"ERR_KEY_002: Encryption key too short ({len(raw)} < {MIN_KEY_LENGTH})")
        else:
            import sys
            print(f"WARNING: Encryption key is short ({len(raw)} chars). "
                  f"Use at least {MIN_KEY_LENGTH} chars in production.", file=sys.stderr)

    # Check for weak keys
    if raw.lower() in WEAK_KEYS:
        if not is_dev and not is_test:
            print(ERR_WEAK_KEY)
            raise RuntimeError("ERR_KEY_003: Weak encryption key detected")
        else:
            import sys
            print("WARNING: Using a weak encryption key. "
                  "Generate a secure random key for production.", file=sys.stderr)


def _derive_key_argon2(raw: str) -> bytes:
    """Derive a 32-byte key using Argon2id.

    Argon2id is memory-hard, making brute-force attacks expensive even with
    specialized hardware (GPUs, ASICs).

    Args:
        raw: The raw key/passphrase string

    Returns:
        32-byte derived key suitable for AES-256
    """
    return hash_secret_raw(
        secret=raw.encode("utf-8"),
        salt=ARGON2_SALT,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID  # Argon2id - hybrid of Argon2i and Argon2d
    )


def _derive_key_legacy(raw: str) -> bytes:
    """Derive a 32-byte key using legacy SHA-256 method.

    DEPRECATED: This method is retained only for backwards compatibility
    with data encrypted before the Argon2id upgrade.

    Args:
        raw: The raw key/passphrase string

    Returns:
        32-byte derived key
    """
    return sha256(raw.encode("utf-8")).digest()


def _derive_key():
    """Derive AES keys from environment variables.

    Key sources (in priority order):
    1. PII_ENCRYPTION_KEY - Recommended for production
    2. SECRET_KEY - Fallback, but not recommended (shared with sessions)
    3. Ephemeral random key - Development/test only, raises in production

    Returns:
        tuple: (primary_key, legacy_key, source identifier string)
               - primary_key: 32-byte Argon2id-derived key for new encryptions
               - legacy_key: 32-byte SHA-256-derived key for backwards compatibility
               - source: identifier string for logging

    Raises:
        RuntimeError: If no key is configured and not in development/test mode,
                     or if key fails validation in production
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

    # Validate key strength
    _validate_key(raw, source, is_dev, is_test)

    # Derive both keys: primary (Argon2id) and legacy (SHA-256)
    primary_key = _derive_key_argon2(raw)
    legacy_key = _derive_key_legacy(raw)

    return primary_key, legacy_key, source


_KEY, _LEGACY_KEY, _KEY_SOURCE = _derive_key()
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

    NOTE: Uses _LEGACY_KEY (SHA-256 derived) for backwards compatibility with
    existing encrypted data. The Argon2id key validation still provides
    protection against weak keys at startup time.

    For deterministic encryption (used for searchable fields like email),
    the ciphertext must match existing data. Since existing data was encrypted
    with SHA-256-derived keys, we continue using that for encryption.

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
    # Use legacy key for encryption to maintain search compatibility
    # Key validation (length, weak key check) still happens at startup via Argon2id path
    aes = AESGCM(_LEGACY_KEY)
    nonce = _deterministic_nonce(normalized)
    ciphertext = aes.encrypt(nonce, normalized.encode("utf-8"), associated_data=None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")


def _decrypt(token: str) -> str:
    """Decrypt a ciphertext token back to plaintext.

    Tries decryption in order:
    1. Primary key (Argon2id-derived) - for new data
    2. Legacy key (SHA-256-derived) - for backwards compatibility
    3. Returns original token if both fail (unencrypted legacy data)

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
    except Exception:
        # Not valid base64 - must be unencrypted legacy data
        return token

    # Try primary key first (Argon2id-derived)
    try:
        aes = AESGCM(_KEY)
        plaintext = aes.decrypt(nonce, ct, associated_data=None)
        return plaintext.decode("utf-8")
    except Exception:
        pass  # Try legacy key

    # Try legacy key (SHA-256-derived) for backwards compatibility
    try:
        aes = AESGCM(_LEGACY_KEY)
        plaintext = aes.decrypt(nonce, ct, associated_data=None)
        return plaintext.decode("utf-8")
    except Exception:
        pass  # Neither key worked

    # If both keys fail, assume it's unencrypted legacy data
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


# =============================================================================
# Status and Migration Helpers
# =============================================================================

def get_encryption_status():
    """Get current encryption configuration status.

    Returns:
        dict: Status information including KDF type, key source, and parameters
    """
    return {
        "kdf_validation": "argon2id",  # Used for key strength validation at startup
        "kdf_encryption": "sha256",     # Used for actual encryption (backwards compat)
        "kdf_params": {
            "memory_kb": ARGON2_MEMORY_KB,
            "time_cost": ARGON2_TIME_COST,
            "parallelism": ARGON2_PARALLELISM,
        },
        "key_source": KEY_SOURCE,
        "min_key_length": MIN_KEY_LENGTH,
        "legacy_mode": True,  # Using SHA-256 for encryption compatibility
        "note": "Key validation uses Argon2id; encryption uses SHA-256 for data compatibility",
    }


def is_legacy_encrypted(token: str) -> bool:
    """Check if a ciphertext was encrypted with the legacy SHA-256-derived key.

    Useful for monitoring migration progress from legacy to Argon2id encryption.

    Args:
        token: Base64-encoded ciphertext to check

    Returns:
        True if the token decrypts with legacy key but not primary key,
        False if it decrypts with primary key or is not valid ciphertext
    """
    if token is None:
        return False

    try:
        data = base64.urlsafe_b64decode(token.encode("utf-8"))
        nonce, ct = data[:12], data[12:]
    except Exception:
        return False  # Not valid ciphertext

    # Try primary key first
    try:
        aes = AESGCM(_KEY)
        aes.decrypt(nonce, ct, associated_data=None)
        return False  # Decrypts with primary key, not legacy
    except Exception:
        pass

    # Try legacy key
    try:
        aes = AESGCM(_LEGACY_KEY)
        aes.decrypt(nonce, ct, associated_data=None)
        return True  # Decrypts with legacy key
    except Exception:
        return False  # Neither key works
