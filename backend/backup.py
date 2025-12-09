#!/usr/bin/env python3
"""Create a backup of the Canvas & Clay database and uploaded photos.

Usage:
    python3 backup.py --output /app/backups/backup.tar.gz
    python3 backup.py --output backup.tar.gz --db-only
    python3 backup.py --output backup.tar.gz --photos-only
    python3 backup.py --output backup.tar.gz --exclude-audit-logs
    python3 backup.py --output backup.tar.gz --include-thumbnails

    # Encrypted backups
    python3 backup.py --output backup.tar.gz.enc --encrypt --passphrase "MySecurePass123!"
    python3 backup.py --output backup.tar.gz.enc --encrypt --use-env-key

Features:
    - Creates a combined backup archive (.tar.gz)
    - Uses pg_dump for database (custom format for compression)
    - Archives photos from /app/uploads
    - Generates manifest.json with metadata and checksums
    - Supports dry-run mode to preview backup contents
    - Optional AES-256-GCM encryption with Argon2id key derivation
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
    run_pg_dump,
    archive_photos,
    create_manifest,
    compute_sha256,
    get_uploads_stats,
    ensure_backups_dir,
    generate_backup_filename,
    BACKUPS_DIR,
)
from backup_encryption import (  # noqa: E402
    encrypt_backup,
    encrypt_backup_with_env_key,
    validate_passphrase,
    PassphraseValidationError,
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
        print()  # Newline when complete


def format_size(size_bytes):
    """Format bytes as human readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def create_backup(
    output_path,
    db_only=False,
    photos_only=False,
    include_thumbnails=False,
    exclude_audit_logs=False,
    dry_run=False,
    created_by=None,
    encrypt=False,
    passphrase=None,
    use_env_key=False
):
    """Create a backup archive.

    Args:
        output_path: Path for the output .tar.gz file (or .tar.gz.enc if encrypted)
        db_only: Only backup database
        photos_only: Only backup photos
        include_thumbnails: Include thumbnail files
        exclude_audit_logs: Exclude audit_log table from database backup
        dry_run: Preview backup without creating it
        created_by: Email of user creating backup
        encrypt: Whether to encrypt the backup
        passphrase: Encryption passphrase (required if encrypt=True and not use_env_key)
        use_env_key: Use BACKUP_ENCRYPTION_KEY env var instead of passphrase

    Returns:
        Tuple of (success: bool, message: str, encryption_info: dict or None)
    """
    # Validate encryption parameters
    if encrypt:
        if use_env_key:
            if not os.getenv("BACKUP_ENCRYPTION_KEY"):
                return False, "BACKUP_ENCRYPTION_KEY environment variable not set", None
        elif not passphrase:
            return False, "Passphrase required for encryption (or use --use-env-key)", None
        else:
            # Validate passphrase strength
            is_valid, errors = validate_passphrase(passphrase)
            if not is_valid:
                return False, f"Passphrase validation failed: {'; '.join(errors)}", None

    # Determine backup type
    if db_only:
        backup_type = "db_only"
        include_db = True
        include_photos = False
    elif photos_only:
        backup_type = "photos_only"
        include_db = False
        include_photos = True
    else:
        backup_type = "full"
        include_db = True
        include_photos = True

    print(f"Backup type: {backup_type}")
    if encrypt:
        key_source = "environment variable" if use_env_key else "passphrase"
        print(f"Encryption: enabled (key source: {key_source})")
    print("-" * 60)

    # Dry run mode - just show what would be backed up
    if dry_run:
        print("DRY RUN - No backup will be created\n")

        if include_db:
            print("Database:")
            exclude_tables = ["audit_log"] if exclude_audit_logs else []
            print("  - Tables to backup: all" +
                  (f" (excluding: {', '.join(exclude_tables)})" if exclude_tables else ""))

        if include_photos:
            stats = get_uploads_stats(include_thumbnails)
            print("\nPhotos:")
            print(f"  - Files: {stats['count']}")
            print(f"  - Total size: {format_size(stats['total_size'])}")
            print(f"  - Include thumbnails: {include_thumbnails}")

        if encrypt:
            print("\nEncryption:")
            print("  - Algorithm: AES-256-GCM")
            print("  - KDF: Argon2id")
            key_source = "BACKUP_ENCRYPTION_KEY env var" if use_env_key else "user passphrase"
            print(f"  - Key source: {key_source}")

        print(f"\nOutput would be: {output_path}")
        return True, "Dry run complete", None

    # Create temporary directory for staging
    with tempfile.TemporaryDirectory() as temp_dir:
        db_manifest = {"included": False}
        photos_manifest = {"included": False}

        # Backup database
        if include_db:
            print("Backing up database...")
            db_dump_path = os.path.join(temp_dir, "database", "canvas_clay.dump")
            os.makedirs(os.path.dirname(db_dump_path), exist_ok=True)

            exclude_tables = ["audit_log"] if exclude_audit_logs else []
            success, message = run_pg_dump(db_dump_path, exclude_tables)

            if not success:
                return False, message

            db_size = os.path.getsize(db_dump_path)
            db_checksum = compute_sha256(db_dump_path)

            db_manifest = {
                "included": True,
                "size": db_size,
                "checksum": db_checksum,
                "tables_excluded": exclude_tables
            }
            print(f"  Database: {format_size(db_size)}")

        # Backup photos
        if include_photos:
            print("Backing up photos...")
            photos_archive_path = os.path.join(temp_dir, "uploads.tar.gz")

            success, manifest, message = archive_photos(
                photos_archive_path,
                include_thumbnails=include_thumbnails,
                progress_callback=lambda c, t: print_progress(c, t, "  Archiving")
            )

            if not success:
                return False, message

            if manifest.get("count", 0) > 0:
                photos_size = os.path.getsize(photos_archive_path)
                photos_checksum = compute_sha256(photos_archive_path)

                photos_manifest = {
                    "included": True,
                    "count": manifest["count"],
                    "size": photos_size,
                    "checksum": photos_checksum,
                    "include_thumbnails": include_thumbnails,
                    "files": manifest.get("files", [])
                }
                print(f"  Photos: {manifest['count']} files, {format_size(photos_size)}")
            else:
                print("  No photos to backup")

        # Create manifest
        manifest = create_manifest(
            backup_type=backup_type,
            created_by=created_by,
            db_manifest=db_manifest,
            photos_manifest=photos_manifest
        )

        manifest_path = os.path.join(temp_dir, "manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        # Create final archive
        print("Creating backup archive...")

        # Ensure output directory exists
        output_dir = os.path.dirname(os.path.abspath(output_path))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Determine paths - if encrypting, create tar.gz first then encrypt
        if encrypt:
            # Create tar.gz in temp directory, then encrypt to final output
            temp_tar_path = os.path.join(temp_dir, "backup.tar.gz")
            tar_output_path = temp_tar_path
        else:
            tar_output_path = output_path

        with tarfile.open(tar_output_path, "w:gz") as tar:
            # Add manifest
            tar.add(manifest_path, arcname="manifest.json")

            # Add database dump
            if include_db and os.path.exists(db_dump_path):
                tar.add(db_dump_path, arcname="database/canvas_clay.dump")

            # Add photos archive
            if include_photos and os.path.exists(photos_archive_path):
                tar.add(photos_archive_path, arcname="uploads.tar.gz")

        encryption_info = None

        # Encrypt if requested
        if encrypt:
            print("Encrypting backup...")
            try:
                if use_env_key:
                    encryption_info = encrypt_backup_with_env_key(
                        temp_tar_path,
                        output_path
                    )
                else:
                    encryption_info = encrypt_backup(
                        temp_tar_path,
                        output_path,
                        passphrase
                    )
                print("  Encryption: AES-256-GCM with Argon2id")
            except (PassphraseValidationError, BackupEncryptionError) as e:
                return False, f"Encryption failed: {str(e)}", None

        final_size = os.path.getsize(output_path)
        print("-" * 60)
        print(f"Backup created: {output_path}")
        print(f"Total size: {format_size(final_size)}")
        if encrypt:
            print(f"Encrypted: Yes (original: {format_size(encryption_info['original_size'])})")

        return True, f"Backup created successfully: {output_path}", encryption_info


def main():
    import getpass

    parser = argparse.ArgumentParser(
        description="Create a backup of Canvas & Clay database and photos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--output", "-o",
        help="Output backup file path. If not specified, generates timestamped name in backups/"
    )
    parser.add_argument(
        "--db-only",
        action="store_true",
        help="Only backup database (no photos)"
    )
    parser.add_argument(
        "--photos-only",
        action="store_true",
        help="Only backup photos (no database)"
    )
    parser.add_argument(
        "--include-thumbnails",
        action="store_true",
        help="Include thumbnail files in photo backup"
    )
    parser.add_argument(
        "--exclude-audit-logs",
        action="store_true",
        help="Exclude audit_log table from database backup"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be backed up without creating archive"
    )
    parser.add_argument(
        "--user",
        help="Email of user creating backup (for audit trail)"
    )
    # Encryption arguments
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt the backup with AES-256-GCM"
    )
    parser.add_argument(
        "--passphrase",
        help="Encryption passphrase (will prompt if --encrypt is used without this)"
    )
    parser.add_argument(
        "--use-env-key",
        action="store_true",
        help="Use BACKUP_ENCRYPTION_KEY environment variable for encryption"
    )

    args = parser.parse_args()

    # Validate mutually exclusive options
    if args.db_only and args.photos_only:
        parser.error("Cannot specify both --db-only and --photos-only")

    # Handle encryption
    encrypt = args.encrypt
    passphrase = args.passphrase
    use_env_key = args.use_env_key

    if encrypt and not use_env_key and not passphrase:
        # Prompt for passphrase interactively
        passphrase = getpass.getpass("Enter encryption passphrase: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            print("Error: Passphrases do not match", file=sys.stderr)
            sys.exit(1)

    # Generate output path if not specified
    if args.output:
        output_path = args.output
    else:
        ensure_backups_dir()
        backup_type = "db_only" if args.db_only else ("photos_only" if args.photos_only else "full")
        filename = generate_backup_filename(backup_type)
        if encrypt:
            filename += ".enc"  # Add .enc for encrypted backups
        output_path = os.path.join(BACKUPS_DIR, filename)

    # Ensure correct extension
    if encrypt:
        if not output_path.endswith('.tar.gz.enc'):
            if output_path.endswith('.tar.gz'):
                output_path += '.enc'
            else:
                output_path += '.tar.gz.enc'
    else:
        if not output_path.endswith('.tar.gz'):
            output_path += '.tar.gz'

    print(f"\n{'=' * 60}")
    print("Canvas & Clay Backup")
    print(f"{'=' * 60}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Output: {output_path}")
    if encrypt:
        print("Encryption: Enabled")
    print()

    success, message, encryption_info = create_backup(
        output_path=output_path,
        db_only=args.db_only,
        photos_only=args.photos_only,
        include_thumbnails=args.include_thumbnails,
        exclude_audit_logs=args.exclude_audit_logs,
        dry_run=args.dry_run,
        created_by=args.user,
        encrypt=encrypt,
        passphrase=passphrase,
        use_env_key=use_env_key
    )

    if success:
        print(f"\n{message}")
        sys.exit(0)
    else:
        print(f"\nError: {message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
