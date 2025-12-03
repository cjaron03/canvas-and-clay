#!/usr/bin/env python3
"""Import users from a JSON export file.

This script imports users exported by export_users.py and re-encrypts
emails using the current deployment's PII_ENCRYPTION_KEY.

Password Handling Options:
1. --keep-passwords: Use the hashed passwords from export
   (users can login if bcrypt versions/cost factors match)
2. --set-password <pwd>: Set all imported users to this password
   (for dev/testing environments)

Usage:
    # Preview import (dry run)
    python3 import_users.py --input users.json --keep-passwords --dry-run

    # Import keeping password hashes
    python3 import_users.py --input users.json --keep-passwords

    # Import with new password (for dev/testing)
    python3 import_users.py --input users.json --set-password "TempPassword123"
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv  # noqa: E402
load_dotenv()

from app import app, db, User, bcrypt  # noqa: E402
from create_tbls import init_tables  # noqa: E402


def import_users(input_file, password_mode, new_password=None, dry_run=False):
    """Import users from JSON file.

    Args:
        input_file: Path to JSON file from export_users.py
        password_mode: 'keep' to use existing hashes, 'set' to set new password
        new_password: New password when password_mode is 'set'
        dry_run: If True, preview without making changes
    """
    with open(input_file, 'r') as f:
        data = json.load(f)

    metadata = data.get("metadata", {})
    users_data = data.get("users", [])

    print("=" * 60)
    print("USER IMPORT")
    print("=" * 60)
    print(f"Import file: {input_file}")
    print(f"Exported at: {metadata.get('exported_at', 'unknown')}")
    print(f"Source key fingerprint: {metadata.get('source_key_fingerprint', 'unknown')}")
    print(f"Total users in file: {len(users_data)}")
    print(f"Password mode: {password_mode}")
    if dry_run:
        print("MODE: DRY RUN - no changes will be made")
    print("-" * 60)

    with app.app_context():
        Artist, _, _, _, _, _, _ = init_tables(db)

        created = 0
        updated = 0
        skipped = 0
        errors = 0

        for user_data in users_data:
            email = user_data.get("email", "").strip().lower()
            if not email:
                print("Skipping entry with no email")
                skipped += 1
                continue

            try:
                # Check if user already exists
                existing_user = User.query.filter_by(email=email).first()

                # Determine password hash
                if password_mode == "keep":
                    password_hash = user_data.get("hashed_password")
                    if not password_hash:
                        print(f"Warning: No password hash for {email}, skipping")
                        skipped += 1
                        continue
                elif password_mode == "set":
                    password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
                else:
                    print(f"Unknown password mode: {password_mode}")
                    errors += 1
                    continue

                role = user_data.get("role", "guest")
                is_active = user_data.get("is_active", True)
                artist_link = user_data.get("artist_link")

                if existing_user:
                    if not dry_run:
                        existing_user.role = role
                        existing_user.hashed_password = password_hash
                        existing_user.is_active = is_active

                        # Handle artist link for artist role
                        if artist_link and role == "artist":
                            artist_id = artist_link.get("artist_id")
                            artist = db.session.get(Artist, artist_id)
                            if artist and not artist.is_deleted:
                                # Unlink any previous artist from this user
                                Artist.query.filter_by(user_id=existing_user.id).update({'user_id': None})
                                artist.user_id = existing_user.id
                            elif artist_id:
                                print(f"  Warning: Artist {artist_id} not found or deleted")

                        db.session.commit()

                    print(f"Updated: {email} (role={role})")
                    updated += 1
                else:
                    if not dry_run:
                        new_user = User(
                            email=email,  # EncryptedString encrypts with current key
                            hashed_password=password_hash,
                            role=role,
                            is_active=is_active,
                            created_at=datetime.now(timezone.utc)
                        )
                        db.session.add(new_user)
                        db.session.flush()

                        # Handle artist link for artist role
                        if artist_link and role == "artist":
                            artist_id = artist_link.get("artist_id")
                            artist = db.session.get(Artist, artist_id)
                            if artist and not artist.is_deleted:
                                artist.user_id = new_user.id
                            elif artist_id:
                                print(f"  Warning: Artist {artist_id} not found or deleted")

                        db.session.commit()

                    print(f"Created: {email} (role={role})")
                    if artist_link:
                        print(f"  -> Artist link: {artist_link.get('artist_id')}")
                    created += 1

            except Exception as e:
                print(f"Error importing {email}: {e}")
                errors += 1
                if not dry_run:
                    db.session.rollback()

        print("-" * 60)
        print(f"Summary: {created} created, {updated} updated, {skipped} skipped, {errors} errors")
        if dry_run:
            print("(DRY RUN - no changes were made)")


def main():
    parser = argparse.ArgumentParser(
        description="Import users from JSON export",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Input JSON file path"
    )

    password_group = parser.add_mutually_exclusive_group(required=True)
    password_group.add_argument(
        "--keep-passwords",
        action="store_true",
        help="Keep hashed passwords from export"
    )
    password_group.add_argument(
        "--set-password",
        metavar="PASSWORD",
        help="Set all users to this password"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without applying"
    )

    args = parser.parse_args()

    if args.keep_passwords:
        password_mode = "keep"
        new_password = None
    else:
        password_mode = "set"
        new_password = args.set_password

    import_users(args.input, password_mode, new_password, args.dry_run)


if __name__ == "__main__":
    main()
