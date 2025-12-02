#!/usr/bin/env python
"""Migrate existing plaintext PII data to encrypted format.

This script encrypts all PII fields that were stored as plaintext before
encryption was enabled. It's idempotent - running it multiple times is safe.

USAGE
=====
    # Dry run (preview changes without committing)
    python migrate_to_encryption.py --dry-run

    # Execute migration
    python migrate_to_encryption.py

ENCRYPTED TABLES/COLUMNS
========================
    - users.email
    - artists.artist_email
    - artists.artist_phone
    - password_reset_requests.email

HOW IT WORKS
============
1. For each record, attempt to decrypt the current value
2. If decryption succeeds and produces different plaintext, it's already encrypted
3. If decryption fails or returns the same value, it's plaintext - encrypt it
4. Update the record with the encrypted value

IMPORTANT: Back up your database before running this script!
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()


def migrate_table(db, table_name, id_column, columns, dry_run, batch_size, verbose):
    """Migrate plaintext values to encrypted format in a single table.

    Args:
        db: SQLAlchemy database instance
        table_name: Name of the table to process
        id_column: Name of the primary key column
        columns: List of (column_name, normalizer_or_none) tuples
        dry_run: If True, don't commit changes
        batch_size: Records per transaction
        verbose: Print per-record details

    Returns:
        tuple: (processed, migrated, already_encrypted, errors)
    """
    # Import encryption functions
    from encryption import _encrypt, _decrypt

    # Check if table exists
    try:
        total = db.session.execute(
            db.text(f"SELECT COUNT(*) FROM {table_name}")
        ).scalar()
    except Exception as e:
        if 'does not exist' in str(e) or 'UndefinedTable' in str(type(e).__name__):
            print(f"\n{table_name}: TABLE DOES NOT EXIST (skipping)")
            db.session.rollback()
            return 0, 0, 0, 0
        raise

    print(f"\n{table_name}: {total} records")

    processed = 0
    migrated = 0
    already_encrypted = 0
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
            record_migrated = False
            try:
                for col_name, normalizer in columns:
                    raw_value = db.session.execute(
                        db.text(f"SELECT {col_name} FROM {table_name} WHERE {id_column} = :id"),
                        {"id": record_id}
                    ).scalar()

                    if raw_value is None:
                        continue

                    # Try to decrypt - if it fails or returns same value, it's plaintext
                    decrypted = _decrypt(raw_value)

                    # If decrypted is different from raw, it was already encrypted
                    if decrypted != raw_value:
                        if verbose:
                            print(f"  [SKIP] {table_name}.{col_name} id={record_id}: already encrypted")
                        continue

                    # Value is plaintext - encrypt it
                    encrypted = _encrypt(raw_value, normalizer)

                    if verbose:
                        masked = raw_value[:3] + "***" + raw_value[-10:] if len(raw_value) > 13 else "***"
                        print(f"  [MIGRATE] {table_name}.{col_name} id={record_id}: {masked}")

                    if not dry_run:
                        db.session.execute(
                            db.text(f"UPDATE {table_name} SET {col_name} = :val WHERE {id_column} = :id"),
                            {"val": encrypted, "id": record_id}
                        )
                    record_migrated = True

                if record_migrated:
                    migrated += 1
                else:
                    already_encrypted += 1

            except Exception as e:
                errors += 1
                print(f"  [ERROR] {table_name} id={record_id}: {e}")

        if not dry_run:
            db.session.commit()
            print(f"  Committed {table_name} batch: {offset + 1}-{min(offset + batch_size, total)}")

        offset += batch_size

    return processed, migrated, already_encrypted, errors


def migrate_to_encryption(dry_run: bool = True, batch_size: int = 100, verbose: bool = False):
    """Migrate all plaintext PII to encrypted format.

    Args:
        dry_run: If True, preview changes without committing
        batch_size: Number of records to process per transaction
        verbose: If True, print details for each record
    """
    from encryption import normalize_email

    print("=" * 60)
    print("PII ENCRYPTION MIGRATION")
    print("=" * 60)
    print(f"Mode: {'DRY RUN (no changes will be saved)' if dry_run else 'LIVE'}")
    print(f"Batch size: {batch_size}")

    from app import app, db

    # Define all tables with encrypted columns
    tables_to_migrate = [
        ("users", "id", [("email", normalize_email)]),
        ("artists", "artist_id", [
            ("artist_email", normalize_email),
            ("artist_phone", None),
        ]),
        ("password_reset_requests", "id", [("email", normalize_email)]),
    ]

    with app.app_context():
        total_processed = 0
        total_migrated = 0
        total_already_encrypted = 0
        total_errors = 0

        for table_name, id_col, columns in tables_to_migrate:
            p, m, a, e = migrate_table(
                db, table_name, id_col, columns,
                dry_run, batch_size, verbose
            )
            total_processed += p
            total_migrated += m
            total_already_encrypted += a
            total_errors += e

        print()
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total processed: {total_processed}")
        print(f"Migrated to encrypted: {total_migrated}")
        print(f"Already encrypted: {total_already_encrypted}")
        print(f"Errors: {total_errors}")

        if dry_run:
            print()
            print("This was a DRY RUN. No changes were saved.")
            print("Run without --dry-run to apply changes.")
        else:
            print()
            print("Migration complete!")


def main():
    parser = argparse.ArgumentParser(
        description="Migrate plaintext PII to encrypted format",
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
        help="Number of records to process per transaction (default: 100)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed progress for each record"
    )

    args = parser.parse_args()

    migrate_to_encryption(
        dry_run=args.dry_run,
        batch_size=args.batch_size,
        verbose=args.verbose
    )


if __name__ == "__main__":
    main()
