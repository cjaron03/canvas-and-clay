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
    for row in result:
        user_id = row[0]
        encrypted_email = row[1]

        # Decrypt the email (handles both encrypted and legacy plaintext)
        decrypted_email = _decrypt(encrypted_email)
        if decrypted_email:
            # Compute blind index
            blind_idx = compute_blind_index(decrypted_email, normalizer=normalize_email)
            session.execute(
                sa.text("UPDATE users SET email_idx = :idx WHERE id = :id"),
                {"idx": blind_idx, "id": user_id}
            )

    session.commit()

    # Step 3: Make email_idx non-nullable and add unique constraint
    with op.batch_alter_table('users', schema=None) as batch_op:
        # Drop the old unique constraint on email (if exists)
        # Note: In SQLite batch mode, constraints are handled differently
        try:
            batch_op.drop_constraint('users_email_key', type_='unique')
        except Exception:
            pass  # Constraint might not exist or have different name

        # Drop the old index on email (if exists)
        try:
            batch_op.drop_index('ix_users_email')
        except Exception:
            pass  # Index might not exist

        # Make email_idx non-nullable
        batch_op.alter_column('email_idx',
                              existing_type=sa.String(64),
                              nullable=False)

        # Add unique constraint and index to email_idx
        batch_op.create_unique_constraint('uq_users_email_idx', ['email_idx'])
        batch_op.create_index('ix_users_email_idx', ['email_idx'])


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        # Remove email_idx unique constraint and index
        try:
            batch_op.drop_constraint('uq_users_email_idx', type_='unique')
        except Exception:
            pass
        try:
            batch_op.drop_index('ix_users_email_idx')
        except Exception:
            pass

        # Drop email_idx column
        batch_op.drop_column('email_idx')

        # Restore unique constraint and index on email
        batch_op.create_unique_constraint('users_email_key', ['email'])
        batch_op.create_index('ix_users_email', ['email'])
