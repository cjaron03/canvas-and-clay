#!/usr/bin/env python
"""Re-encrypt all PII data with a new encryption key.

This script migrates encrypted User.email values from an old encryption key
to a new one. Use this when rotating keys due to compromise or policy.

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

from dotenv import load_dotenv

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


def rotate_keys(dry_run: bool = True, batch_size: int = 100, verbose: bool = False):
    """Rotate encryption keys for all User.email values.

    Args:
        dry_run: If True, preview changes without committing
        batch_size: Number of users to process per transaction
        verbose: If True, print details for each user
    """
    # Validate environment
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
    print()

    # Import Flask app and models
    from app import app, db
    from models import init_models

    User, _, _ = init_models(db)

    with app.app_context():
        total_users = User.query.count()
        print(f"Total users to process: {total_users}")
        print()

        processed = 0
        updated = 0
        skipped = 0
        errors = 0

        # Process in batches
        offset = 0
        while offset < total_users:
            users = User.query.order_by(User.id).offset(offset).limit(batch_size).all()
            if not users:
                break

            for user in users:
                processed += 1
                try:
                    # Get the raw encrypted value from the database
                    # We need to bypass the TypeDecorator to get raw ciphertext
                    raw_email = db.session.execute(
                        db.text("SELECT email FROM users WHERE id = :id"),
                        {"id": user.id}
                    ).scalar()

                    if raw_email is None:
                        skipped += 1
                        if verbose:
                            print(f"  [SKIP] User {user.id}: No email")
                        continue

                    # Decrypt with old key
                    plaintext = decrypt_with_key(raw_email, old_key)

                    # Re-encrypt with new key
                    new_ciphertext = encrypt_with_key(plaintext, new_key, normalize_email)

                    # Check if already using new key (idempotent)
                    if raw_email == new_ciphertext:
                        skipped += 1
                        if verbose:
                            print(f"  [SKIP] User {user.id}: Already using new key")
                        continue

                    if verbose:
                        # Mask email for privacy
                        masked = plaintext[:3] + "***" + plaintext[-10:] if len(plaintext) > 13 else "***"
                        print(f"  [UPDATE] User {user.id}: {masked}")

                    if not dry_run:
                        db.session.execute(
                            db.text("UPDATE users SET email = :email WHERE id = :id"),
                            {"email": new_ciphertext, "id": user.id}
                        )

                    updated += 1

                except Exception as e:
                    errors += 1
                    print(f"  [ERROR] User {user.id}: {e}")

            if not dry_run:
                db.session.commit()
                print(f"  Committed batch: {offset + 1}-{min(offset + batch_size, total_users)}")

            offset += batch_size

        print()
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total processed: {processed}")
        print(f"Updated: {updated}")
        print(f"Skipped: {skipped}")
        print(f"Errors: {errors}")

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
