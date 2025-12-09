#!/usr/bin/env python3
"""Restore the Canvas & Clay database and photos from a backup archive.

Usage:
    python3 restore.py --input /app/backups/backup.tar.gz --dry-run
    python3 restore.py --input backup.tar.gz
    python3 restore.py --input backup.tar.gz --db-only
    python3 restore.py --input backup.tar.gz --photos-only
    python3 restore.py --input backup.tar.gz --force

    # Encrypted backups
    python3 restore.py --input backup.tar.gz.enc --passphrase "MySecurePass123!"
    python3 restore.py --input backup.tar.gz.enc --use-env-key

Features:
    - Validates backup integrity before restore
    - Checks PII encryption key compatibility
    - Creates automatic pre-restore backup (safety)
    - Supports dry-run mode to preview restore
    - Uses pg_restore for database restoration
    - Supports decryption of AES-256-GCM encrypted backups
"""

import argparse
import json
import os
import sys
import tarfile
import tempfile
from datetime import datetime

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv  # noqa: E402
load_dotenv()

from backup_utils import (  # noqa: E402
    run_pg_restore,
    extract_photos,
    validate_manifest,
    ensure_backups_dir,
    run_pg_dump,
    archive_photos,
    create_manifest,
    compute_sha256,
    BACKUPS_DIR,
)
from backup_encryption import (  # noqa: E402
    decrypt_backup,
    decrypt_backup_with_env_key,
    is_encrypted_backup,
    read_encrypted_header,
    DecryptionError,
    InvalidBackupFormatError,
    BackupEncryptionError,
)


def print_progress(current, total, prefix="Progress"):
    """Print a progress bar to stdout."""
    bar_length = 40
    progress = current / total if total > 0 else 1
    filled = int(bar_length * progress)
    bar = "=" * filled + "-" * (bar_length - filled)
    percent = progress * 100
    print(f"\r{prefix}: [{bar}] {percent:.1f}% ({current}/{total})", end="", flush=True)
    if current >= total:
        print()


def format_size(size_bytes):
    """Format bytes as human readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def read_manifest_from_archive(archive_path):
    """Read and parse manifest from backup archive.

    Args:
        archive_path: Path to the backup archive

    Returns:
        Tuple of (manifest: dict or None, error: str or None)
    """
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            manifest_member = tar.getmember("manifest.json")
            f = tar.extractfile(manifest_member)
            if f:
                return json.loads(f.read().decode('utf-8')), None
            return None, "Could not read manifest.json"
    except KeyError:
        return None, "manifest.json not found in archive"
    except json.JSONDecodeError as e:
        return None, f"Invalid manifest.json: {e}"
    except Exception as e:
        return None, f"Error reading archive: {e}"


def create_pre_restore_backup():
    """Create a backup of current state before restoring.

    Returns:
        Tuple of (success: bool, backup_path: str or None, message: str)
    """
    print("Creating pre-restore safety backup...")
    ensure_backups_dir()

    output_path = os.path.join(
        BACKUPS_DIR,
        f"pre_restore_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.tar.gz"
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        db_manifest = {"included": False}
        photos_manifest = {"included": False}

        # Backup database
        db_dump_path = os.path.join(temp_dir, "database", "canvas_clay.dump")
        os.makedirs(os.path.dirname(db_dump_path), exist_ok=True)

        success, message = run_pg_dump(db_dump_path)
        if success:
            db_size = os.path.getsize(db_dump_path)
            db_checksum = compute_sha256(db_dump_path)
            db_manifest = {
                "included": True,
                "size": db_size,
                "checksum": db_checksum,
                "tables_excluded": []
            }
        else:
            print(f"  Warning: Could not backup database: {message}")

        # Backup photos
        photos_archive_path = os.path.join(temp_dir, "uploads.tar.gz")
        success, manifest, message = archive_photos(photos_archive_path)

        if success and manifest.get("count", 0) > 0:
            photos_size = os.path.getsize(photos_archive_path)
            photos_checksum = compute_sha256(photos_archive_path)
            photos_manifest = {
                "included": True,
                "count": manifest["count"],
                "size": photos_size,
                "checksum": photos_checksum,
                "files": manifest.get("files", [])
            }

        # Create manifest
        manifest = create_manifest(
            backup_type="pre_restore",
            created_by="system",
            db_manifest=db_manifest,
            photos_manifest=photos_manifest
        )

        manifest_path = os.path.join(temp_dir, "manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        # Create archive
        with tarfile.open(output_path, "w:gz") as tar:
            tar.add(manifest_path, arcname="manifest.json")

            if db_manifest["included"]:
                tar.add(db_dump_path, arcname="database/canvas_clay.dump")

            if photos_manifest["included"] and os.path.exists(photos_archive_path):
                tar.add(photos_archive_path, arcname="uploads.tar.gz")

    print(f"  Pre-restore backup: {output_path}")
    return True, output_path, "Pre-restore backup created"


def restore_backup(
    input_path,
    db_only=False,
    photos_only=False,
    dry_run=False,
    force=False,
    no_pre_backup=False,
    passphrase=None,
    use_env_key=False
):
    """Restore from a backup archive.

    Args:
        input_path: Path to the backup archive (can be encrypted .tar.gz.enc)
        db_only: Only restore database
        photos_only: Only restore photos
        dry_run: Preview restore without making changes
        force: Skip confirmation prompts
        no_pre_backup: Skip creating pre-restore backup
        passphrase: Decryption passphrase (required if encrypted and not use_env_key)
        use_env_key: Use BACKUP_ENCRYPTION_KEY env var for decryption

    Returns:
        Tuple of (success: bool, message: str)
    """
    # Verify archive exists
    if not os.path.exists(input_path):
        return False, f"Backup file not found: {input_path}"

    # Check if backup is encrypted
    encrypted = is_encrypted_backup(input_path)
    decrypted_path = None
    temp_decrypt_dir = None

    if encrypted:
        print("Detected encrypted backup")

        # Show encryption info
        try:
            header = read_encrypted_header(input_path)
            if header:
                print(f"  Algorithm: {header.get('algorithm', 'Unknown')}")
                print(f"  KDF: {header.get('kdf', 'Unknown')}")
        except InvalidBackupFormatError as e:
            return False, f"Invalid encrypted backup: {e}"

        # Validate decryption parameters
        if use_env_key:
            if not os.getenv("BACKUP_ENCRYPTION_KEY"):
                return False, "BACKUP_ENCRYPTION_KEY environment variable not set"
        elif not passphrase:
            return False, "Passphrase required for encrypted backup (or use --use-env-key)"

        # Decrypt to temp file
        print("Decrypting backup...")
        temp_decrypt_dir = tempfile.mkdtemp()
        decrypted_path = os.path.join(temp_decrypt_dir, "decrypted_backup.tar.gz")

        try:
            if use_env_key:
                decrypt_info = decrypt_backup_with_env_key(input_path, decrypted_path)
            else:
                decrypt_info = decrypt_backup(input_path, decrypted_path, passphrase)

            if decrypt_info.get('checksum_verified'):
                print("  Decryption successful, checksum verified")
            else:
                print("  Decryption successful")

            # Use decrypted file for the rest of the restore
            archive_path = decrypted_path
        except DecryptionError as e:
            if temp_decrypt_dir and os.path.exists(temp_decrypt_dir):
                import shutil
                shutil.rmtree(temp_decrypt_dir)
            return False, f"Decryption failed: {e}"
        except BackupEncryptionError as e:
            if temp_decrypt_dir and os.path.exists(temp_decrypt_dir):
                import shutil
                shutil.rmtree(temp_decrypt_dir)
            return False, f"Decryption error: {e}"
    else:
        archive_path = input_path

    # Read manifest (from decrypted archive if applicable)
    print("Reading backup manifest...")
    manifest, error = read_manifest_from_archive(archive_path)
    if error:
        return False, error

    # Validate manifest
    valid, warnings, errors = validate_manifest(manifest)
    if errors:
        for e in errors:
            print(f"  Error: {e}")
        return False, "Manifest validation failed"

    for w in warnings:
        print(f"  Warning: {w}")

    # Display backup info
    print("\nBackup Information:")
    print(f"  Created: {manifest.get('created_at', 'Unknown')}")
    print(f"  Type: {manifest.get('type', 'Unknown')}")
    print(f"  Created by: {manifest.get('created_by', 'Unknown')}")
    if encrypted:
        print("  Encrypted: Yes")

    contents = manifest.get("contents", {})
    db_info = contents.get("database", {})
    photos_info = contents.get("photos", {})

    if db_info.get("included"):
        print(f"  Database: {format_size(db_info.get('size', 0))}")
        if db_info.get("tables_excluded"):
            print(f"    Excluded tables: {', '.join(db_info['tables_excluded'])}")
    else:
        print("  Database: Not included")

    if photos_info.get("included"):
        print(f"  Photos: {photos_info.get('count', 0)} files, {format_size(photos_info.get('size', 0))}")
    else:
        print("  Photos: Not included")

    # Determine what to restore
    restore_db = not photos_only and db_info.get("included", False)
    restore_photos = not db_only and photos_info.get("included", False)

    if not restore_db and not restore_photos:
        return False, "Nothing to restore based on options and backup contents"

    print("\nRestore Plan:")
    if restore_db:
        print("  - Database: WILL BE RESTORED (current data will be replaced)")
    if restore_photos:
        print("  - Photos: WILL BE RESTORED (existing files may be overwritten)")

    # Dry run stops here
    if dry_run:
        print("\nDRY RUN - No changes made")
        return True, "Dry run complete"

    # Confirmation
    if not force:
        print("\n" + "=" * 60)
        print("WARNING: This will replace your current data!")
        print("=" * 60)
        response = input("\nType 'RESTORE' to confirm: ")
        if response != "RESTORE":
            return False, "Restore cancelled by user"

    # Create pre-restore backup
    if not no_pre_backup:
        success, backup_path, message = create_pre_restore_backup()
        if not success:
            print(f"Warning: {message}")
            if not force:
                response = input("Continue without pre-restore backup? (y/N): ")
                if response.lower() != 'y':
                    return False, "Restore cancelled"

    # Helper function to clean up decrypted temp file
    def cleanup_decrypted():
        if temp_decrypt_dir and os.path.exists(temp_decrypt_dir):
            import shutil
            shutil.rmtree(temp_decrypt_dir)

    # Extract archive to temp directory
    print("\nExtracting backup archive...")
    with tempfile.TemporaryDirectory() as temp_dir:
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(temp_dir)

        # Restore database
        if restore_db:
            print("\nRestoring database...")
            db_dump_path = os.path.join(temp_dir, "database", "canvas_clay.dump")

            if not os.path.exists(db_dump_path):
                cleanup_decrypted()
                return False, "Database dump not found in archive"

            # Verify checksum
            if db_info.get("checksum"):
                actual_checksum = compute_sha256(db_dump_path)
                if actual_checksum != db_info["checksum"]:
                    cleanup_decrypted()
                    return False, "Database dump checksum mismatch"
                print("  Checksum verified")

            success, message = run_pg_restore(db_dump_path)
            if not success:
                cleanup_decrypted()
                return False, f"Database restore failed: {message}"
            print("  Database restored successfully")

        # Restore photos
        if restore_photos:
            print("\nRestoring photos...")
            photos_archive_path = os.path.join(temp_dir, "uploads.tar.gz")

            if not os.path.exists(photos_archive_path):
                cleanup_decrypted()
                return False, "Photos archive not found in backup"

            # Verify checksum
            if photos_info.get("checksum"):
                actual_checksum = compute_sha256(photos_archive_path)
                if actual_checksum != photos_info["checksum"]:
                    cleanup_decrypted()
                    return False, "Photos archive checksum mismatch"
                print("  Checksum verified")

            success, message = extract_photos(
                photos_archive_path,
                progress_callback=lambda c, t: print_progress(c, t, "  Extracting")
            )
            if not success:
                cleanup_decrypted()
                return False, f"Photos restore failed: {message}"
            print("  Photos restored successfully")

    # Clean up decrypted temp file
    cleanup_decrypted()
    return True, "Restore completed successfully"


def main():
    import getpass

    parser = argparse.ArgumentParser(
        description="Restore Canvas & Clay database and photos from backup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to backup archive file"
    )
    parser.add_argument(
        "--db-only",
        action="store_true",
        help="Only restore database (skip photos)"
    )
    parser.add_argument(
        "--photos-only",
        action="store_true",
        help="Only restore photos (skip database)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview restore without making changes"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompts"
    )
    parser.add_argument(
        "--no-pre-backup",
        action="store_true",
        help="Skip creating pre-restore safety backup"
    )
    # Decryption arguments
    parser.add_argument(
        "--passphrase",
        help="Decryption passphrase (will prompt if encrypted backup detected)"
    )
    parser.add_argument(
        "--use-env-key",
        action="store_true",
        help="Use BACKUP_ENCRYPTION_KEY environment variable for decryption"
    )

    args = parser.parse_args()

    # Validate mutually exclusive options
    if args.db_only and args.photos_only:
        parser.error("Cannot specify both --db-only and --photos-only")

    # Check if backup is encrypted and prompt for passphrase if needed
    passphrase = args.passphrase
    if is_encrypted_backup(args.input) and not args.use_env_key and not passphrase:
        # Prompt for passphrase interactively
        passphrase = getpass.getpass("Enter decryption passphrase: ")

    print(f"\n{'=' * 60}")
    print("Canvas & Clay Restore")
    print(f"{'=' * 60}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Input: {args.input}")
    print()

    success, message = restore_backup(
        input_path=args.input,
        db_only=args.db_only,
        photos_only=args.photos_only,
        dry_run=args.dry_run,
        force=args.force,
        no_pre_backup=args.no_pre_backup,
        passphrase=passphrase,
        use_env_key=args.use_env_key
    )

    if success:
        print(f"\n{message}")
        sys.exit(0)
    else:
        print(f"\nError: {message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
