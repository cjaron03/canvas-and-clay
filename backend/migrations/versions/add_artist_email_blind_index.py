"""Add artist email blind index for probabilistic encryption

Revision ID: add_artist_email_idx
Revises: add_email_blind_idx
Create Date: 2025-12-10

This migration:
1. Adds artist_email_idx column for blind index lookups on Artist
2. Populates blind index for existing artists with email
3. Adds unique constraint to artist_email_idx (nullable ok)
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session

# revision identifiers, used by Alembic.
revision = 'add_artist_email_idx'
down_revision = 'add_email_blind_idx'
branch_labels = None
depends_on = None

# Error codes for clear diagnostics
ERR_NO_ENCRYPTION_KEY = """
================================================================================
ERROR: MIGRATION FAILED - NO ENCRYPTION KEY CONFIGURED (ERR_NO_KEY_001)
================================================================================

This migration requires a stable encryption key to compute blind indexes.
You are running with an EPHEMERAL (temporary) key that will be lost on restart.

To fix this, set one of these environment variables BEFORE running migrations:

    PII_ENCRYPTION_KEY=<your-secure-random-key>

    OR

    SECRET_KEY=<your-secure-random-key>

Generate a secure key with:
    python -c "import secrets; print(secrets.token_urlsafe(32))"

Then restart the container/application and run migrations again.

WARNING: If you proceed without a stable key, all encrypted data will become
         UNRECOVERABLE after the application restarts.
================================================================================
"""

ERR_DECRYPTION_FAILED = """
================================================================================
ERROR: MIGRATION FAILED - DECRYPTION KEY MISMATCH (ERR_KEY_MISMATCH_003)
================================================================================

Failed to decrypt email for artist ID: {artist_id}

The current encryption key cannot decrypt existing encrypted artist emails.
This likely means:
  1. PII_ENCRYPTION_KEY changed since emails were encrypted
  2. The key was derived from SECRET_KEY which has changed
  3. Data was encrypted with a different key

Original value (first 20 chars): {preview}...

To fix this:
  1. Locate the original encryption key used to encrypt the emails
  2. Set it as PII_ENCRYPTION_KEY before running migrations
  3. Run migrations again

WARNING: Proceeding without the correct key will make artist lookups FAIL.
================================================================================
"""

ERR_DUPLICATE_EMAILS = """
================================================================================
ERROR: MIGRATION FAILED - DUPLICATE ARTIST EMAILS DETECTED (ERR_DUP_EMAIL_001)
================================================================================

Found {count} artists sharing duplicate email addresses.
Cannot create unique constraint on artist_email_idx.

Duplicate emails found:
{duplicates}

To fix this:
  1. Manually resolve duplicate artist emails before running this migration
  2. Use the artist IDs listed above to identify affected artists
  3. Update or remove duplicate emails so each artist has a unique email
  4. Run migrations again

NOTE: Previously artist_email had no unique constraint. This migration adds one
      to enable blind index lookups with probabilistic encryption.
================================================================================
"""


def upgrade():
    # SAFETY CHECK: Ensure we have a stable encryption key
    # Import here to avoid circular imports and ensure fresh check
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from encryption import KEY_SOURCE

    if KEY_SOURCE == "ephemeral":
        print(ERR_NO_ENCRYPTION_KEY)
        raise RuntimeError("ERR_NO_KEY_001: Cannot migrate with ephemeral key")

    # Step 1: Add artist_email_idx column (nullable - artist email is optional)
    with op.batch_alter_table('artist', schema=None) as batch_op:
        batch_op.add_column(sa.Column('artist_email_idx', sa.String(64), nullable=True))

    # Step 2: Populate blind index for existing artists with email
    bind = op.get_bind()
    session = Session(bind=bind)

    # Import encryption functions (path already set up above)
    from encryption import compute_blind_index, normalize_email, _decrypt

    # Get all artists with email and compute their blind index
    result = session.execute(sa.text("SELECT artist_id, artist_email FROM artist WHERE artist_email IS NOT NULL"))
    artists_to_update = []
    for row in result:
        artist_id = row[0]
        encrypted_email = row[1]

        if not encrypted_email:
            continue  # Skip NULL emails

        # Decrypt the email (handles both encrypted and legacy plaintext)
        decrypted_email = _decrypt(encrypted_email)

        # Validate decryption succeeded - a valid email must contain '@'
        # If _decrypt fails (wrong key), it returns the original ciphertext
        # which won't be a valid email format
        if not decrypted_email or '@' not in decrypted_email:
            # Check if this might be legacy plaintext (contains @ but failed decryption)
            if encrypted_email and '@' in encrypted_email:
                # This is plaintext email, use it directly
                decrypted_email = encrypted_email
            else:
                # Decryption failed - key mismatch
                print(ERR_DECRYPTION_FAILED.format(
                    artist_id=artist_id,
                    preview=encrypted_email[:20] if encrypted_email else 'NULL'
                ))
                raise RuntimeError(
                    f"ERR_KEY_MISMATCH_003: Cannot decrypt email for artist {artist_id}. "
                    "Check PII_ENCRYPTION_KEY matches the key used to encrypt data."
                )

        # Compute blind index
        blind_idx = compute_blind_index(decrypted_email, normalizer=normalize_email)
        artists_to_update.append({"idx": blind_idx, "id": artist_id, "email": decrypted_email})

    # Check for duplicate emails before applying unique constraint
    # Group all artists by their blind index to catch all duplicates
    index_groups = {}
    for artist in artists_to_update:
        idx = artist["idx"]
        if idx not in index_groups:
            index_groups[idx] = []
        index_groups[idx].append(artist)

    # Find groups with more than one artist (duplicates)
    duplicates = [(artists[0]["email"], [a["id"] for a in artists])
                  for artists in index_groups.values() if len(artists) > 1]

    if duplicates:
        # Format duplicates for error message (mask email for PII protection)
        def mask_email(email):
            if '@' in email:
                local, domain = email.split('@', 1)
                masked_local = local[0] + '***' if len(local) > 0 else '***'
                return f"{masked_local}@{domain}"
            return '***'

        dup_lines = []
        for email, artist_ids in duplicates:
            dup_lines.append(f"  - '{mask_email(email)}' used by artist IDs: {artist_ids}")
        print(ERR_DUPLICATE_EMAILS.format(
            count=len(duplicates),
            duplicates="\n".join(dup_lines)
        ))
        raise RuntimeError(
            f"ERR_DUP_EMAIL_001: Found {len(duplicates)} duplicate artist emails. "
            "Resolve duplicates before running migration."
        )

    # Batch update all artists
    for artist in artists_to_update:
        session.execute(
            sa.text("UPDATE artist SET artist_email_idx = :idx WHERE artist_id = :id"),
            artist
        )

    session.commit()

    # Step 3: Add unique constraint and index to artist_email_idx
    # Note: artist_email_idx stays nullable since artist_email is optional
    with op.batch_alter_table('artist', schema=None) as batch_op:
        batch_op.create_unique_constraint('uq_artist_email_idx', ['artist_email_idx'])
        batch_op.create_index('ix_artist_email_idx', ['artist_email_idx'])


def downgrade():
    bind = op.get_bind()

    # Check if uq_artist_email_idx constraint exists
    constraint_exists = bind.execute(sa.text("""
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_artist_email_idx' AND conrelid = 'artist'::regclass
    """)).fetchone() is not None

    # Check if ix_artist_email_idx index exists
    index_exists = bind.execute(sa.text("""
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'ix_artist_email_idx' AND tablename = 'artist'
    """)).fetchone() is not None

    with op.batch_alter_table('artist', schema=None) as batch_op:
        # Remove artist_email_idx unique constraint and index (only if they exist)
        if constraint_exists:
            batch_op.drop_constraint('uq_artist_email_idx', type_='unique')
        if index_exists:
            batch_op.drop_index('ix_artist_email_idx')

        # Drop artist_email_idx column
        batch_op.drop_column('artist_email_idx')
