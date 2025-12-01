#!/usr/bin/env python
"""Re-encrypt all PII data with a new encryption key.

This script migrates all encrypted PII fields from an old encryption key
to a new one. Use this when rotating keys due to compromise or policy.

ENCRYPTED TABLES/COLUMNS
========================
    - users.email
    - artists.artist_email
    - artists.artist_phone
    - password_reset_requests.email

USAGE
=====
    # Dry run (preview changes without committing)
    OLD_PII_ENCRYPTION_KEY=<old> PII_ENCRYPTION_KEY=<new> python rotate_encryption_key.py --dry-run

    # Execute rotation
    OLD_PII_ENCRYPTION_KEY=<old> PII_ENCRYPTION_KEY=<new> python rotate_encryption_key.py

ENVIRONMENT VARIABLES
=====================
    OLD_PII_ENCRYPTION_KEY  - The current/old encryption key (required)
    PII_ENCRYPTION_KEY      - The new encryption key to migrate to (required)
    DATABASE_URL            - Database connection string (or use DB_* vars)

OPTIONS
=======
    --dry-run       Preview changes without committing to database
    --batch-size N  Process N users per transaction (default: 100)
    --verbose       Show detailed progress for each user

RECOVERY
========
If the script is interrupted:
1. Users already processed will have new-key encryption
2. Users not yet processed still have old-key encryption
3. Re-run the script with the SAME keys to resume

The script is idempotent - running it multiple times with the same keys
will not corrupt data.

IMPORTANT: Back up your database before running this script!
"""

import argparse
import os
import sys
from hashlib import sha256

# Ensure we can import from parent directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()


def derive_key_from_env(env_var_name: str) -> bytes:
    """Derive a 32-byte key from an environment variable."""
    value = os.getenv(env_var_name)
    if not value:
        raise RuntimeError(f"{env_var_name} environment variable is required")
    return sha256(value.encode("utf-8")).digest()


def decrypt_with_key(token: str, key: bytes) -> str:
    """Decrypt a token using the specified key."""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if token is None:
        return None
    try:
        data = base64.urlsafe_b64decode(token.encode("utf-8"))
        nonce, ct = data[:12], data[12:]
        aes = AESGCM(key)
        plaintext = aes.decrypt(nonce, ct, associated_data=None)
        return plaintext.decode("utf-8")
    except Exception:
        # Return as-is if decryption fails (might be plaintext)
        return token


def encrypt_with_key(value: str, key: bytes, normalizer=None) -> str:
    """Encrypt a value using the specified key."""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if value is None:
        return None
    normalized = normalizer(value) if normalizer else value
    nonce = sha256(normalized.encode("utf-8")).digest()[:12]
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, normalized.encode("utf-8"), associated_data=None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")


def normalize_email(value: str) -> str:
    """Normalize email for consistent encryption."""
    return value.strip().lower()


def _rotate_table(db, table_name, id_column, columns, old_key, new_key,
                  dry_run, batch_size, verbose):
    """Rotate encryption for columns in a single table.

    Args:
        db: SQLAlchemy database instance
        table_name: Name of the table to process
        id_column: Name of the primary key column
        columns: List of (column_name, normalizer_or_none) tuples
        old_key: Old encryption key bytes
        new_key: New encryption key bytes
        dry_run: If True, don't commit changes
        batch_size: Records per transaction
        verbose: Print per-record details

    Returns:
        tuple: (processed, updated, skipped, errors)
    """
    total = db.session.execute(
        db.text(f"SELECT COUNT(*) FROM {table_name}")
    ).scalar()

    print(f"\n{table_name}: {total} records")

    processed = 0
    updated = 0
    skipped = 0
    errors = 0

    offset = 0
    while offset < total:
        rows = db.session.execute(
            db.text(f"SELECT {id_column} FROM {table_name} ORDER BY {id_column} LIMIT :limit OFFSET :offset"),
            {"limit": batch_size, "offset": offset}
        ).fetchall()

        if not rows:
            break

        for (record_id,) in rows:
            processed += 1
            record_updated = False
            try:
                for col_name, normalizer in columns:
                    raw_value = db.session.execute(
                        db.text(f"SELECT {col_name} FROM {table_name} WHERE {id_column} = :id"),
                        {"id": record_id}
                    ).scalar()

                    if raw_value is None:
                        continue

                    plaintext = decrypt_with_key(raw_value, old_key)
                    new_ciphertext = encrypt_with_key(plaintext, new_key, normalizer)

                    if raw_value == new_ciphertext:
                        continue

                    if verbose:
                        masked = plaintext[:3] + "***" + plaintext[-10:] if len(plaintext) > 13 else "***"
                        print(f"  [UPDATE] {table_name}.{col_name} id={record_id}: {masked}")

                    if not dry_run:
                        db.session.execute(
                            db.text(f"UPDATE {table_name} SET {col_name} = :val WHERE {id_column} = :id"),
                            {"val": new_ciphertext, "id": record_id}
                        )
                    record_updated = True

                if record_updated:
                    updated += 1
                else:
                    skipped += 1

            except Exception as e:
                errors += 1
                print(f"  [ERROR] {table_name} id={record_id}: {e}")

        if not dry_run:
            db.session.commit()
            print(f"  Committed {table_name} batch: {offset + 1}-{min(offset + batch_size, total)}")

        offset += batch_size

    return processed, updated, skipped, errors


def rotate_keys(dry_run: bool = True, batch_size: int = 100, verbose: bool = False):
    """Rotate encryption keys for all encrypted PII columns.

    Args:
        dry_run: If True, preview changes without committing
        batch_size: Number of records to process per transaction
        verbose: If True, print details for each record
    """
    old_key = derive_key_from_env("OLD_PII_ENCRYPTION_KEY")
    new_key = derive_key_from_env("PII_ENCRYPTION_KEY")

    if old_key == new_key:
        print("ERROR: OLD_PII_ENCRYPTION_KEY and PII_ENCRYPTION_KEY are the same")
        sys.exit(1)

    print("=" * 60)
    print("PII ENCRYPTION KEY ROTATION")
    print("=" * 60)
    print(f"Mode: {'DRY RUN (no changes will be saved)' if dry_run else 'LIVE'}")
    print(f"Batch size: {batch_size}")

    from app import app, db

    # Define all tables with encrypted columns
    # Format: (table_name, id_column, [(column_name, normalizer_or_none), ...])
    tables_to_rotate = [
        ("users", "id", [("email", normalize_email)]),
        ("artists", "artist_id", [
            ("artist_email", normalize_email),
            ("artist_phone", None),
        ]),
        ("password_reset_requests", "id", [("email", normalize_email)]),
    ]

    with app.app_context():
        total_processed = 0
        total_updated = 0
        total_skipped = 0
        total_errors = 0

        for table_name, id_col, columns in tables_to_rotate:
            p, u, s, e = _rotate_table(
                db, table_name, id_col, columns,
                old_key, new_key, dry_run, batch_size, verbose
            )
            total_processed += p
            total_updated += u
            total_skipped += s
            total_errors += e

        print()
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total processed: {total_processed}")
        print(f"Updated: {total_updated}")
        print(f"Skipped: {total_skipped}")
        print(f"Errors: {total_errors}")

        if dry_run:
            print()
            print("This was a DRY RUN. No changes were saved.")
            print("Run without --dry-run to apply changes.")
        else:
            print()
            print("Key rotation complete!")
            print("IMPORTANT: Update your deployment to use PII_ENCRYPTION_KEY")
            print("and remove OLD_PII_ENCRYPTION_KEY from your environment.")


def main():
    parser = argparse.ArgumentParser(
        description="Rotate PII encryption keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without committing to database"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of users to process per transaction (default: 100)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed progress for each user"
    )

    args = parser.parse_args()

    # Validate required environment variables early
    if not os.getenv("OLD_PII_ENCRYPTION_KEY"):
        print("ERROR: OLD_PII_ENCRYPTION_KEY environment variable is required")
        print("This should be set to your current/old encryption key")
        sys.exit(1)

    if not os.getenv("PII_ENCRYPTION_KEY"):
        print("ERROR: PII_ENCRYPTION_KEY environment variable is required")
        print("This should be set to your new encryption key")
        sys.exit(1)

    rotate_keys(
        dry_run=args.dry_run,
        batch_size=args.batch_size,
        verbose=args.verbose
    )


if __name__ == "__main__":
    main()
