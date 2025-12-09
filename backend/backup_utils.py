#!/usr/bin/env python3
"""Shared utilities for backup and restore operations.

This module provides common functions used by backup.py and restore.py:
- File checksum calculation
- Manifest generation and validation
- PostgreSQL dump/restore wrappers
- Photo archive operations
"""

import hashlib
import json
import os
import subprocess
import tarfile
from datetime import datetime, timezone
from hashlib import sha256

# Default paths
UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
BACKUPS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')

# Manifest version for compatibility checking
# 1.0 - Initial version
# 1.1 - Added encryption support
MANIFEST_VERSION = "1.1"


def compute_sha256(file_path):
    """Calculate SHA256 checksum of a file.

    Args:
        file_path: Path to the file

    Returns:
        Hex string of SHA256 hash
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(8192), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_pii_key_fingerprint():
    """Get fingerprint of the current PII encryption key.

    Returns first 8 characters of SHA256 hash of the key.
    Used to verify encryption key compatibility during restore.
    """
    key_env = os.getenv("PII_ENCRYPTION_KEY") or os.getenv("SECRET_KEY") or ""
    if not key_env:
        return "ephemeral"
    return sha256(key_env.encode()).hexdigest()[:8]


def get_db_connection_info():
    """Get database connection info from environment.

    Returns:
        Dict with host, port, database, user, password
    """
    database_url = os.getenv("DATABASE_URL")

    if database_url:
        # Parse DATABASE_URL format: postgresql://user:pass@host:port/dbname
        from urllib.parse import urlparse
        parsed = urlparse(database_url)
        return {
            "host": parsed.hostname or "localhost",
            "port": str(parsed.port or 5432),
            "database": parsed.path.lstrip("/") if parsed.path else "canvas_clay",
            "user": parsed.username or "canvas_db",
            "password": parsed.password or ""
        }
    else:
        # Use individual env vars
        return {
            "host": os.getenv("DB_HOST", "localhost"),
            "port": os.getenv("DB_PORT", "5432"),
            "database": os.getenv("DB_NAME", "canvas_clay"),
            "user": os.getenv("DB_USER", "canvas_db"),
            "password": os.getenv("DB_PASSWORD", "")
        }


def run_pg_dump(output_path, exclude_tables=None):
    """Run pg_dump to backup the database.

    Args:
        output_path: Path for the output dump file
        exclude_tables: List of table names to exclude

    Returns:
        Tuple of (success: bool, message: str)
    """
    db_info = get_db_connection_info()
    exclude_tables = exclude_tables or []

    cmd = [
        "pg_dump",
        "-h", db_info["host"],
        "-p", db_info["port"],
        "-U", db_info["user"],
        "-d", db_info["database"],
        "-Fc",  # Custom format for compression
        "-f", output_path
    ]

    for table in exclude_tables:
        cmd.extend(["--exclude-table", table])

    env = os.environ.copy()
    env["PGPASSWORD"] = db_info["password"]

    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )

        if result.returncode != 0:
            return False, f"pg_dump failed: {result.stderr}"

        return True, f"Database backed up to {output_path}"

    except subprocess.TimeoutExpired:
        return False, "pg_dump timed out after 10 minutes"
    except FileNotFoundError:
        return False, "pg_dump not found. Ensure PostgreSQL client tools are installed."
    except Exception as e:
        return False, f"pg_dump error: {str(e)}"


def run_pg_restore(input_path, clean=True):
    """Run pg_restore to restore the database.

    Args:
        input_path: Path to the dump file
        clean: Whether to drop existing objects before restore

    Returns:
        Tuple of (success: bool, message: str)
    """
    db_info = get_db_connection_info()

    cmd = [
        "pg_restore",
        "-h", db_info["host"],
        "-p", db_info["port"],
        "-U", db_info["user"],
        "-d", db_info["database"],
        "--no-owner",  # Don't try to set ownership
        "--no-privileges",  # Don't try to set privileges
    ]

    if clean:
        cmd.append("--clean")
        cmd.append("--if-exists")

    cmd.append(input_path)

    env = os.environ.copy()
    env["PGPASSWORD"] = db_info["password"]

    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=600
        )

        # pg_restore returns non-zero for warnings too, check stderr for real failures
        # Look for fatal errors, not just warnings about existing objects or version mismatches
        stderr_lower = result.stderr.lower()

        # These indicate actual connection/auth failures
        fatal_indicators = [
            "fatal",
            "could not connect",
            "password authentication failed",
            "connection refused",
            "no pg_hba.conf entry",
            "database .* does not exist"
        ]

        # These are harmless warnings (version mismatches, already exists, etc.)
        harmless_patterns = [
            "errors ignored on restore",
            "unrecognized configuration parameter",
            "transaction_timeout",
            "already exists",
            "does not exist, skipping"
        ]

        if result.returncode != 0:
            # Check if it's a real failure or just warnings
            has_fatal = any(indicator in stderr_lower for indicator in fatal_indicators)
            all_harmless = all(
                any(pattern in line.lower() for pattern in harmless_patterns)
                for line in result.stderr.strip().split('\n')
                if line.strip() and 'error' in line.lower()
            )

            if has_fatal or (not all_harmless and 'error' in stderr_lower):
                return False, f"pg_restore failed: {result.stderr}"
            # Non-zero but only harmless warnings = success

        return True, "Database restored successfully"

    except subprocess.TimeoutExpired:
        return False, "pg_restore timed out after 10 minutes"
    except FileNotFoundError:
        return False, "pg_restore not found. Ensure PostgreSQL client tools are installed."
    except Exception as e:
        return False, f"pg_restore error: {str(e)}"


def is_thumbnail(filename):
    """Check if file is a thumbnail."""
    return '_thumb' in filename or filename.startswith('thumb_')


def get_uploads_stats(include_thumbnails=False):
    """Get statistics about files in uploads directory.

    Args:
        include_thumbnails: Whether to include thumbnail files

    Returns:
        Dict with count and total_size
    """
    if not os.path.exists(UPLOADS_DIR):
        return {"count": 0, "total_size": 0}

    count = 0
    total_size = 0

    for root, dirs, files in os.walk(UPLOADS_DIR):
        files = [f for f in files if f != '.gitkeep']
        for filename in files:
            if not include_thumbnails and is_thumbnail(filename):
                continue
            filepath = os.path.join(root, filename)
            count += 1
            total_size += os.path.getsize(filepath)

    return {"count": count, "total_size": total_size}


def archive_photos(output_path, include_thumbnails=False, progress_callback=None):
    """Archive photos from uploads directory.

    Args:
        output_path: Path for output archive (will be a tar within the backup)
        include_thumbnails: Whether to include thumbnail files
        progress_callback: Optional callback(current, total) for progress

    Returns:
        Tuple of (success: bool, manifest: dict, message: str)
    """
    if not os.path.exists(UPLOADS_DIR):
        return True, {"count": 0, "files": []}, "No uploads directory, skipping photos"

    files_manifest = []
    count = 0
    total_size = 0

    # First pass: count files for progress
    total_files = 0
    for root, dirs, files in os.walk(UPLOADS_DIR):
        files = [f for f in files if f != '.gitkeep']
        for filename in files:
            if not include_thumbnails and is_thumbnail(filename):
                continue
            total_files += 1

    try:
        with tarfile.open(output_path, "w:gz") as tar:
            for root, dirs, files in os.walk(UPLOADS_DIR):
                files = [f for f in files if f != '.gitkeep']
                for filename in files:
                    if not include_thumbnails and is_thumbnail(filename):
                        continue

                    filepath = os.path.join(root, filename)
                    arcname = os.path.relpath(filepath, UPLOADS_DIR)
                    file_size = os.path.getsize(filepath)
                    checksum = compute_sha256(filepath)

                    tar.add(filepath, arcname=arcname)

                    files_manifest.append({
                        "path": arcname,
                        "size": file_size,
                        "checksum": checksum
                    })

                    count += 1
                    total_size += file_size

                    if progress_callback:
                        progress_callback(count, total_files)

        manifest = {
            "count": count,
            "total_size": total_size,
            "include_thumbnails": include_thumbnails,
            "files": files_manifest
        }

        return True, manifest, f"Archived {count} photos"

    except Exception as e:
        return False, {}, f"Failed to archive photos: {str(e)}"


def extract_photos(archive_path, progress_callback=None):
    """Extract photos from archive to uploads directory.

    Args:
        archive_path: Path to the photos archive
        progress_callback: Optional callback(current, total) for progress

    Returns:
        Tuple of (success: bool, message: str)
    """
    if not os.path.exists(archive_path):
        return False, f"Archive not found: {archive_path}"

    # Ensure uploads directory exists
    os.makedirs(UPLOADS_DIR, exist_ok=True)

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getmembers()
            total = len(members)

            for i, member in enumerate(members):
                # Security: prevent path traversal
                member_path = os.path.normpath(member.name)
                if member_path.startswith('..') or member_path.startswith('/'):
                    continue

                tar.extract(member, UPLOADS_DIR)

                if progress_callback:
                    progress_callback(i + 1, total)

        return True, f"Extracted {total} files to {UPLOADS_DIR}"

    except Exception as e:
        return False, f"Failed to extract photos: {str(e)}"


def create_manifest(backup_type, created_by, db_manifest=None, photos_manifest=None):
    """Create a backup manifest.

    Args:
        backup_type: 'full', 'db_only', or 'photos_only'
        created_by: Email of user who created backup
        db_manifest: Database backup info
        photos_manifest: Photos archive info

    Returns:
        Dict manifest
    """
    manifest = {
        "version": MANIFEST_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": created_by or "system",
        "type": backup_type,
        "source": {
            "hostname": os.getenv("HOSTNAME", "unknown"),
            "pii_key_fingerprint": get_pii_key_fingerprint()
        },
        "contents": {
            "database": db_manifest or {"included": False},
            "photos": photos_manifest or {"included": False}
        }
    }

    return manifest


def validate_manifest(manifest):
    """Validate a backup manifest.

    Args:
        manifest: Dict manifest to validate

    Returns:
        Tuple of (valid: bool, warnings: list, errors: list)
    """
    warnings = []
    errors = []

    # Check version
    if manifest.get("version") != MANIFEST_VERSION:
        warnings.append(f"Manifest version mismatch: {manifest.get('version')} vs {MANIFEST_VERSION}")

    # Check required fields
    required = ["version", "created_at", "type", "contents"]
    for field in required:
        if field not in manifest:
            errors.append(f"Missing required field: {field}")

    # Check PII key compatibility
    source_fingerprint = manifest.get("source", {}).get("pii_key_fingerprint")
    current_fingerprint = get_pii_key_fingerprint()

    if source_fingerprint and source_fingerprint != current_fingerprint:
        warnings.append(
            f"PII encryption key differs. Source: {source_fingerprint}, "
            f"Current: {current_fingerprint}. Encrypted fields may need re-encryption."
        )

    return len(errors) == 0, warnings, errors


def verify_archive_checksums(archive_path, manifest):
    """Verify file checksums in a photos archive.

    Args:
        archive_path: Path to the photos archive
        manifest: Manifest with file checksums

    Returns:
        Tuple of (valid: bool, errors: list)
    """
    errors = []
    files_manifest = manifest.get("contents", {}).get("photos", {}).get("files", [])

    if not files_manifest:
        return True, []

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            for file_info in files_manifest:
                member = tar.getmember(file_info["path"])
                f = tar.extractfile(member)
                if f:
                    actual_checksum = hashlib.sha256(f.read()).hexdigest()
                    expected_checksum = file_info.get("checksum")

                    if expected_checksum and actual_checksum != expected_checksum:
                        errors.append(f"Checksum mismatch for {file_info['path']}")

    except Exception as e:
        errors.append(f"Error verifying archive: {str(e)}")

    return len(errors) == 0, errors


def ensure_backups_dir():
    """Ensure backups directory exists."""
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    return BACKUPS_DIR


def list_backups():
    """List available backup files.

    Returns:
        List of dicts with backup info, including encrypted status
    """
    ensure_backups_dir()
    backups = []

    # Import encryption detection lazily to avoid circular imports
    try:
        from backup_encryption import is_encrypted_backup, read_encrypted_header
        encryption_available = True
    except ImportError:
        encryption_available = False

    for filename in os.listdir(BACKUPS_DIR):
        # Support both .tar.gz and .tar.gz.enc files
        if filename.endswith('.tar.gz') or filename.endswith('.tar.gz.enc'):
            filepath = os.path.join(BACKUPS_DIR, filename)
            stat = os.stat(filepath)

            # Check if encrypted
            encrypted = False
            encryption_info = None
            if encryption_available:
                encrypted = is_encrypted_backup(filepath)
                if encrypted:
                    try:
                        header = read_encrypted_header(filepath)
                        encryption_info = {
                            "algorithm": header.get("algorithm", "unknown"),
                            "kdf": header.get("kdf", "unknown"),
                            "original_size": header.get("original_size"),
                        }
                    except Exception:
                        encryption_info = {"algorithm": "unknown"}

            # Try to read manifest (only possible for unencrypted backups)
            manifest = None
            if not encrypted:
                try:
                    with tarfile.open(filepath, "r:gz") as tar:
                        manifest_member = tar.getmember("manifest.json")
                        f = tar.extractfile(manifest_member)
                        if f:
                            manifest = json.loads(f.read().decode('utf-8'))
                except Exception:
                    pass

            backups.append({
                "filename": filename,
                "filepath": filepath,
                "size": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "manifest": manifest,
                "encrypted": encrypted,
                "encryption_info": encryption_info
            })

    # Sort by creation time, newest first
    backups.sort(key=lambda x: x["created_at"], reverse=True)
    return backups


def delete_backup(filename):
    """Delete a backup file.

    Args:
        filename: Name of backup file to delete (can be .tar.gz or .tar.gz.enc)

    Returns:
        Tuple of (success: bool, message: str)
    """
    # Security: prevent path traversal
    if '/' in filename or '\\' in filename or '..' in filename:
        return False, "Invalid filename"

    # Validate file extension
    if not (filename.endswith('.tar.gz') or filename.endswith('.tar.gz.enc')):
        return False, "Invalid backup file extension"

    filepath = os.path.join(BACKUPS_DIR, filename)

    if not os.path.exists(filepath):
        return False, f"Backup not found: {filename}"

    try:
        os.remove(filepath)
        return True, f"Deleted {filename}"
    except Exception as e:
        return False, f"Failed to delete: {str(e)}"


def get_backup_key_fingerprint():
    """Get fingerprint of the backup encryption key if configured.

    Returns first 8 characters of SHA256 hash of BACKUP_ENCRYPTION_KEY,
    or None if not configured.
    """
    key_env = os.getenv("BACKUP_ENCRYPTION_KEY")
    if not key_env:
        return None
    return sha256(key_env.encode()).hexdigest()[:8]


def is_backup_encryption_configured():
    """Check if backup encryption key is configured in environment.

    Returns:
        bool: True if BACKUP_ENCRYPTION_KEY is set
    """
    return bool(os.getenv("BACKUP_ENCRYPTION_KEY"))


def generate_backup_filename(backup_type="full"):
    """Generate a timestamped backup filename.

    Args:
        backup_type: Type of backup (full, db_only, photos_only)

    Returns:
        Filename string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return f"backup_{backup_type}_{timestamp}.tar.gz"
