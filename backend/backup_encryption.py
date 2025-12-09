#!/usr/bin/env python3
"""Backup encryption module for Canvas & Clay.

Provides password-based encryption for backup archives using:
- AES-256-GCM for authenticated encryption
- Argon2id for key derivation (memory-hard, GPU-resistant)

ENCRYPTED FILE FORMAT
=====================
Magic bytes (8):     "CCBKENC\x01" (Canvas & Clay Backup Encrypted, version 1)
Header length (4):   Little-endian uint32
Header (JSON):       Encryption metadata (algorithm, KDF params, nonce, etc.)
Ciphertext:          AES-256-GCM encrypted data + 16-byte auth tag

The entire .tar.gz is encrypted as a single blob, hiding file structure.

USAGE
=====
    # Encrypt a backup
    encrypt_backup("backup.tar.gz", "backup.tar.gz.enc", "my-passphrase")

    # Decrypt a backup
    decrypt_backup("backup.tar.gz.enc", "backup.tar.gz", "my-passphrase")

    # Check if file is encrypted
    if is_encrypted_backup("backup.tar.gz.enc"):
        header = read_encrypted_header("backup.tar.gz.enc")

KEY DERIVATION
==============
Uses Argon2id with conservative parameters suitable for self-hosted hardware:
- Memory: 64 MB (protects against GPU attacks)
- Time: 3 iterations
- Parallelism: 4 threads
- Salt: 16 random bytes (unique per backup)
- Output: 32 bytes (AES-256 key)

SECURITY NOTES
==============
- Passphrase is NOT stored in the file
- Each backup has a unique salt (different key even with same passphrase)
- Authentication tag prevents tampering detection
- Original file checksum stored in header for integrity verification
"""

import base64
import json
import os
import struct
from hashlib import sha256
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Check for Argon2id availability
ARGON2_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id, Type  # noqa: F401
    ARGON2_AVAILABLE = True
except ImportError:
    try:
        import argon2  # noqa: F401
        ARGON2_AVAILABLE = True
    except ImportError:
        pass

# Constants
MAGIC_BYTES = b"CCBKENC\x01"  # Canvas & Clay Backup Encrypted, version 1
HEADER_VERSION = 1
CHUNK_SIZE = 64 * 1024  # 64KB chunks for streaming

# Argon2id parameters (conservative for self-hosted hardware)
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_TIME_COST = 3        # 3 iterations
ARGON2_PARALLELISM = 4      # 4 threads
ARGON2_SALT_LENGTH = 16     # 16 bytes
ARGON2_KEY_LENGTH = 32      # 32 bytes (AES-256)

# AES-GCM parameters
AES_NONCE_LENGTH = 12       # 12 bytes (96 bits, recommended for GCM)
AES_TAG_LENGTH = 16         # 16 bytes (128 bits)

# Passphrase requirements
MIN_PASSPHRASE_LENGTH = 12


class BackupEncryptionError(Exception):
    """Base exception for backup encryption errors."""
    pass


class PassphraseValidationError(BackupEncryptionError):
    """Raised when passphrase doesn't meet requirements."""
    pass


class DecryptionError(BackupEncryptionError):
    """Raised when decryption fails (wrong passphrase or corrupted file)."""
    pass


class InvalidBackupFormatError(BackupEncryptionError):
    """Raised when encrypted backup file format is invalid."""
    pass


def validate_passphrase(passphrase: str) -> Tuple[bool, list]:
    """Validate passphrase meets security requirements.

    Requirements:
    - Minimum 12 characters
    - Contains uppercase letter
    - Contains lowercase letter
    - Contains digit or special character

    Args:
        passphrase: The passphrase to validate

    Returns:
        Tuple of (is_valid: bool, errors: list of error messages)
    """
    errors = []

    if not passphrase:
        errors.append("Passphrase cannot be empty")
        return False, errors

    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        errors.append(f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")

    if not any(c.isupper() for c in passphrase):
        errors.append("Passphrase must contain at least one uppercase letter")

    if not any(c.islower() for c in passphrase):
        errors.append("Passphrase must contain at least one lowercase letter")

    if not any(c.isdigit() or not c.isalnum() for c in passphrase):
        errors.append("Passphrase must contain at least one digit or special character")

    return len(errors) == 0, errors


def _derive_key_argon2id(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from passphrase using Argon2id.

    Args:
        passphrase: User-provided passphrase
        salt: Random salt (16 bytes)

    Returns:
        32-byte derived key suitable for AES-256
    """
    if not ARGON2_AVAILABLE:
        raise BackupEncryptionError(
            "Argon2id not available. Install cryptography >= 43.0.0 or argon2-cffi"
        )

    # Try cryptography's Argon2id first
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id, Type  # noqa: F811
        kdf = Argon2id(
            salt=salt,
            length=ARGON2_KEY_LENGTH,
            iterations=ARGON2_TIME_COST,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_COST,
            ad=None,
            secret=None,
            type=Type.ID,
        )
        return kdf.derive(passphrase.encode('utf-8'))
    except ImportError:
        pass

    # Fallback to argon2-cffi
    try:
        import argon2  # noqa: F811
        # argon2-cffi's low-level API for raw key derivation
        return argon2.low_level.hash_secret_raw(
            secret=passphrase.encode('utf-8'),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_KEY_LENGTH,
            type=argon2.Type.ID,
        )
    except ImportError:
        raise BackupEncryptionError(
            "Argon2id not available. Install cryptography >= 43.0.0 or argon2-cffi"
        )


def _compute_file_checksum(filepath: str) -> str:
    """Compute SHA-256 checksum of a file.

    Args:
        filepath: Path to file

    Returns:
        Hex-encoded SHA-256 checksum
    """
    hasher = sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def is_encrypted_backup(filepath: str) -> bool:
    """Check if a file is an encrypted backup.

    Args:
        filepath: Path to file to check

    Returns:
        True if file has encrypted backup magic bytes
    """
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(len(MAGIC_BYTES))
            return magic == MAGIC_BYTES
    except (IOError, OSError):
        return False


def read_encrypted_header(filepath: str) -> Optional[dict]:
    """Read the header from an encrypted backup file.

    Args:
        filepath: Path to encrypted backup

    Returns:
        Header dictionary or None if not a valid encrypted backup

    Raises:
        InvalidBackupFormatError: If file format is invalid
    """
    try:
        with open(filepath, 'rb') as f:
            # Read and verify magic bytes
            magic = f.read(len(MAGIC_BYTES))
            if magic != MAGIC_BYTES:
                return None

            # Read header length (4 bytes, little-endian)
            header_len_bytes = f.read(4)
            if len(header_len_bytes) < 4:
                raise InvalidBackupFormatError("Truncated header length")

            header_len = struct.unpack('<I', header_len_bytes)[0]

            # Sanity check header length (max 1MB)
            if header_len > 1024 * 1024:
                raise InvalidBackupFormatError("Header too large")

            # Read and parse header JSON
            header_bytes = f.read(header_len)
            if len(header_bytes) < header_len:
                raise InvalidBackupFormatError("Truncated header")

            return json.loads(header_bytes.decode('utf-8'))

    except json.JSONDecodeError as e:
        raise InvalidBackupFormatError(f"Invalid header JSON: {e}")
    except (IOError, OSError) as e:
        raise InvalidBackupFormatError(f"Error reading file: {e}")


def encrypt_backup(
    input_path: str,
    output_path: str,
    passphrase: str,
    validate_pass: bool = True
) -> dict:
    """Encrypt a backup archive.

    Args:
        input_path: Path to unencrypted .tar.gz backup
        output_path: Path for encrypted output (.tar.gz.enc)
        passphrase: Encryption passphrase
        validate_pass: Whether to validate passphrase strength (default True)

    Returns:
        dict with encryption info:
        - original_size: Size of unencrypted file
        - encrypted_size: Size of encrypted file
        - original_checksum: SHA-256 of unencrypted file
        - algorithm: Encryption algorithm used
        - kdf: Key derivation function used

    Raises:
        PassphraseValidationError: If passphrase doesn't meet requirements
        BackupEncryptionError: If encryption fails
    """
    # Validate passphrase
    if validate_pass:
        is_valid, errors = validate_passphrase(passphrase)
        if not is_valid:
            raise PassphraseValidationError("; ".join(errors))

    # Verify input file exists
    if not os.path.isfile(input_path):
        raise BackupEncryptionError(f"Input file not found: {input_path}")

    # Compute checksum of original file
    original_checksum = _compute_file_checksum(input_path)
    original_size = os.path.getsize(input_path)

    # Generate random salt and nonce
    salt = os.urandom(ARGON2_SALT_LENGTH)
    nonce = os.urandom(AES_NONCE_LENGTH)

    # Derive key from passphrase
    key = _derive_key_argon2id(passphrase, salt)

    # Create header
    header = {
        "version": HEADER_VERSION,
        "algorithm": "AES-256-GCM",
        "kdf": "argon2id",
        "kdf_params": {
            "memory_cost": ARGON2_MEMORY_COST,
            "time_cost": ARGON2_TIME_COST,
            "parallelism": ARGON2_PARALLELISM,
            "salt": base64.b64encode(salt).decode('ascii'),
        },
        "nonce": base64.b64encode(nonce).decode('ascii'),
        "original_size": original_size,
        "original_checksum": original_checksum,
    }
    header_bytes = json.dumps(header, separators=(',', ':')).encode('utf-8')

    # Read entire file into memory for encryption
    # (AES-GCM needs to process all data for authentication tag)
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # Encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Write encrypted file
    with open(output_path, 'wb') as f:
        # Write magic bytes
        f.write(MAGIC_BYTES)
        # Write header length (4 bytes, little-endian)
        f.write(struct.pack('<I', len(header_bytes)))
        # Write header
        f.write(header_bytes)
        # Write ciphertext (includes auth tag)
        f.write(ciphertext)

    encrypted_size = os.path.getsize(output_path)

    return {
        "original_size": original_size,
        "encrypted_size": encrypted_size,
        "original_checksum": original_checksum,
        "algorithm": "AES-256-GCM",
        "kdf": "argon2id",
    }


def decrypt_backup(
    input_path: str,
    output_path: str,
    passphrase: str,
    verify_checksum: bool = True
) -> dict:
    """Decrypt an encrypted backup archive.

    Args:
        input_path: Path to encrypted .tar.gz.enc backup
        output_path: Path for decrypted output (.tar.gz)
        passphrase: Decryption passphrase
        verify_checksum: Whether to verify checksum after decryption (default True)

    Returns:
        dict with decryption info:
        - original_size: Size of decrypted file
        - checksum_verified: Whether checksum was verified

    Raises:
        DecryptionError: If decryption fails (wrong passphrase or corrupted)
        InvalidBackupFormatError: If file format is invalid
    """
    # Read and validate header
    header = read_encrypted_header(input_path)
    if header is None:
        raise InvalidBackupFormatError("Not a valid encrypted backup file")

    # Validate header version
    if header.get("version", 0) > HEADER_VERSION:
        raise InvalidBackupFormatError(
            f"Unsupported backup version: {header.get('version')}"
        )

    # Extract KDF parameters
    kdf_params = header.get("kdf_params", {})
    salt = base64.b64decode(kdf_params.get("salt", ""))
    nonce = base64.b64decode(header.get("nonce", ""))

    if len(salt) != ARGON2_SALT_LENGTH:
        raise InvalidBackupFormatError("Invalid salt length")
    if len(nonce) != AES_NONCE_LENGTH:
        raise InvalidBackupFormatError("Invalid nonce length")

    # Derive key from passphrase
    # Use stored KDF parameters for compatibility
    key = _derive_key_argon2id(passphrase, salt)

    # Read ciphertext
    with open(input_path, 'rb') as f:
        # Skip magic bytes
        f.seek(len(MAGIC_BYTES))
        # Read header length
        header_len = struct.unpack('<I', f.read(4))[0]
        # Skip header
        f.seek(len(MAGIC_BYTES) + 4 + header_len)
        # Read ciphertext
        ciphertext = f.read()

    # Decrypt
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        # Don't reveal whether it was wrong passphrase or corrupted file
        raise DecryptionError("Decryption failed - wrong passphrase or corrupted file")

    # Write decrypted file
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    # Verify checksum
    checksum_verified = False
    if verify_checksum and "original_checksum" in header:
        actual_checksum = _compute_file_checksum(output_path)
        expected_checksum = header["original_checksum"]
        if actual_checksum != expected_checksum:
            # Remove potentially corrupted output
            os.remove(output_path)
            raise DecryptionError("Checksum verification failed - file may be corrupted")
        checksum_verified = True

    return {
        "original_size": os.path.getsize(output_path),
        "checksum_verified": checksum_verified,
    }


def get_backup_key_fingerprint(key_source: str = "env") -> Optional[str]:
    """Get fingerprint of backup encryption key.

    Args:
        key_source: "env" to use BACKUP_ENCRYPTION_KEY env var

    Returns:
        First 8 characters of SHA-256 hash, or None if not configured
    """
    if key_source == "env":
        key = os.getenv("BACKUP_ENCRYPTION_KEY")
        if not key:
            return None
        return sha256(key.encode('utf-8')).hexdigest()[:8]
    return None


def encrypt_backup_with_env_key(input_path: str, output_path: str) -> dict:
    """Encrypt backup using BACKUP_ENCRYPTION_KEY environment variable.

    Args:
        input_path: Path to unencrypted backup
        output_path: Path for encrypted output

    Returns:
        Encryption info dict (see encrypt_backup)

    Raises:
        BackupEncryptionError: If BACKUP_ENCRYPTION_KEY not set
    """
    key = os.getenv("BACKUP_ENCRYPTION_KEY")
    if not key:
        raise BackupEncryptionError(
            "BACKUP_ENCRYPTION_KEY environment variable not set"
        )

    # When using env key, skip passphrase validation (it's a key, not a passphrase)
    return encrypt_backup(input_path, output_path, key, validate_pass=False)


def decrypt_backup_with_env_key(input_path: str, output_path: str) -> dict:
    """Decrypt backup using BACKUP_ENCRYPTION_KEY environment variable.

    Args:
        input_path: Path to encrypted backup
        output_path: Path for decrypted output

    Returns:
        Decryption info dict (see decrypt_backup)

    Raises:
        BackupEncryptionError: If BACKUP_ENCRYPTION_KEY not set
    """
    key = os.getenv("BACKUP_ENCRYPTION_KEY")
    if not key:
        raise BackupEncryptionError(
            "BACKUP_ENCRYPTION_KEY environment variable not set"
        )

    return decrypt_backup(input_path, output_path, key)


if __name__ == "__main__":
    # Simple CLI for testing
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="Encrypt/decrypt backup files")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a backup")
    encrypt_parser.add_argument("input", help="Input file (.tar.gz)")
    encrypt_parser.add_argument("output", help="Output file (.tar.gz.enc)")
    encrypt_parser.add_argument(
        "--use-env-key", action="store_true",
        help="Use BACKUP_ENCRYPTION_KEY env var instead of passphrase"
    )

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a backup")
    decrypt_parser.add_argument("input", help="Input file (.tar.gz.enc)")
    decrypt_parser.add_argument("output", help="Output file (.tar.gz)")
    decrypt_parser.add_argument(
        "--use-env-key", action="store_true",
        help="Use BACKUP_ENCRYPTION_KEY env var instead of passphrase"
    )

    # Check command
    check_parser = subparsers.add_parser("check", help="Check if file is encrypted")
    check_parser.add_argument("file", help="File to check")

    args = parser.parse_args()

    if args.command == "encrypt":
        if args.use_env_key:
            result = encrypt_backup_with_env_key(args.input, args.output)
        else:
            passphrase = getpass.getpass("Enter passphrase: ")
            confirm = getpass.getpass("Confirm passphrase: ")
            if passphrase != confirm:
                print("Error: Passphrases do not match")
                exit(1)
            result = encrypt_backup(args.input, args.output, passphrase)
        print(f"Encrypted successfully: {result['encrypted_size']} bytes")
        print(f"Original checksum: {result['original_checksum']}")

    elif args.command == "decrypt":
        if args.use_env_key:
            result = decrypt_backup_with_env_key(args.input, args.output)
        else:
            passphrase = getpass.getpass("Enter passphrase: ")
            result = decrypt_backup(args.input, args.output, passphrase)
        print(f"Decrypted successfully: {result['original_size']} bytes")
        if result['checksum_verified']:
            print("Checksum verified")

    elif args.command == "check":
        if is_encrypted_backup(args.file):
            header = read_encrypted_header(args.file)
            print(f"Encrypted backup (version {header.get('version', '?')})")
            print(f"Algorithm: {header.get('algorithm', '?')}")
            print(f"KDF: {header.get('kdf', '?')}")
            print(f"Original size: {header.get('original_size', '?')} bytes")
        else:
            print("Not an encrypted backup")
