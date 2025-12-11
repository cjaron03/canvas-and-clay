"""Add email blind index for probabilistic encryption

Revision ID: add_email_blind_idx
Revises: 1ae401cd5eab
Create Date: 2025-12-09

This migration:
1. Adds email_idx column for blind index lookups
2. Populates blind index for existing users
3. Removes unique constraint from email column (now probabilistic)
4. Adds unique constraint to email_idx
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session

# revision identifiers, used by Alembic.
revision = 'add_email_blind_idx'
down_revision = '1ae401cd5eab'
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
ERROR: MIGRATION FAILED - DECRYPTION KEY MISMATCH (ERR_KEY_MISMATCH_002)
================================================================================

Failed to decrypt email for user ID: {user_id}

The current encryption key cannot decrypt existing encrypted emails.
This likely means:
  1. PII_ENCRYPTION_KEY changed since emails were encrypted
  2. The key was derived from SECRET_KEY which has changed
  3. Data was encrypted with a different key

Original value (first 20 chars): {preview}...

To fix this:
  1. Locate the original encryption key used to encrypt the emails
  2. Set it as PII_ENCRYPTION_KEY before running migrations
  3. Run migrations again

WARNING: Proceeding without the correct key will make user lookups FAIL.
================================================================================
"""


def column_exists(table_name, column_name):
    """Check if a column exists in a table (PostgreSQL)."""
    bind = op.get_bind()
    result = bind.execute(sa.text("""
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
        AND table_name = :table AND column_name = :column
    """), {"table": table_name, "column": column_name})
    return result.fetchone() is not None


def upgrade():
    # Check if email_idx column already exists (idempotent migration)
    if column_exists('users', 'email_idx'):
        print("email_idx column already exists, skipping migration")
        return

    # SAFETY CHECK: Ensure we have a stable encryption key
    # Import here to avoid circular imports and ensure fresh check
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from encryption import KEY_SOURCE

    if KEY_SOURCE == "ephemeral":
        print(ERR_NO_ENCRYPTION_KEY)
        raise RuntimeError("ERR_NO_KEY_001: Cannot migrate with ephemeral key")

    # Step 1: Add email_idx column (nullable initially)
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email_idx', sa.String(64), nullable=True))

    # Step 2: Populate blind index for existing users
    # We need to decrypt existing emails and compute their blind index
    bind = op.get_bind()
    session = Session(bind=bind)

    # Import encryption functions (path already set up above)
    from encryption import compute_blind_index, normalize_email, _decrypt

    # Get all users and compute their blind index
    result = session.execute(sa.text("SELECT id, email FROM users"))
    users_to_update = []
    for row in result:
        user_id = row[0]
        encrypted_email = row[1]

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
                    user_id=user_id,
                    preview=encrypted_email[:20] if encrypted_email else 'NULL'
                ))
                raise RuntimeError(
                    f"ERR_KEY_MISMATCH_002: Cannot decrypt email for user {user_id}. "
                    "Check PII_ENCRYPTION_KEY matches the key used to encrypt data."
                )

        # Compute blind index
        blind_idx = compute_blind_index(decrypted_email, normalizer=normalize_email)
        users_to_update.append({"idx": blind_idx, "id": user_id})

    # Batch update all users
    for user in users_to_update:
        session.execute(
            sa.text("UPDATE users SET email_idx = :idx WHERE id = :id"),
            user
        )

    session.commit()

    # Step 3: Make email_idx non-nullable and add unique constraint
    # First, check what constraints/indexes exist (PostgreSQL-specific)
    bind = op.get_bind()

    # Check if users_email_key constraint exists
    constraint_exists = bind.execute(sa.text("""
        SELECT 1 FROM pg_constraint
        WHERE conname = 'users_email_key' AND conrelid = 'users'::regclass
    """)).fetchone() is not None

    # Check if ix_users_email index exists
    index_exists = bind.execute(sa.text("""
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'ix_users_email' AND tablename = 'users'
    """)).fetchone() is not None

    with op.batch_alter_table('users', schema=None) as batch_op:
        # Drop the old unique constraint on email (only if it exists)
        if constraint_exists:
            batch_op.drop_constraint('users_email_key', type_='unique')

        # Drop the old index on email (only if it exists)
        if index_exists:
            batch_op.drop_index('ix_users_email')

        # Make email_idx non-nullable
        batch_op.alter_column('email_idx',
                              existing_type=sa.String(64),
                              nullable=False)

        # Add unique constraint and index to email_idx
        batch_op.create_unique_constraint('uq_users_email_idx', ['email_idx'])
        batch_op.create_index('ix_users_email_idx', ['email_idx'])


def downgrade():
    bind = op.get_bind()

    # Check if uq_users_email_idx constraint exists
    constraint_exists = bind.execute(sa.text("""
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_users_email_idx' AND conrelid = 'users'::regclass
    """)).fetchone() is not None

    # Check if ix_users_email_idx index exists
    index_exists = bind.execute(sa.text("""
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'ix_users_email_idx' AND tablename = 'users'
    """)).fetchone() is not None

    with op.batch_alter_table('users', schema=None) as batch_op:
        # Remove email_idx unique constraint and index (only if they exist)
        if constraint_exists:
            batch_op.drop_constraint('uq_users_email_idx', type_='unique')
        if index_exists:
            batch_op.drop_index('ix_users_email_idx')

        # Drop email_idx column
        batch_op.drop_column('email_idx')

        # Restore unique constraint and index on email
        batch_op.create_unique_constraint('users_email_key', ['email'])
        batch_op.create_index('ix_users_email', ['email'])
