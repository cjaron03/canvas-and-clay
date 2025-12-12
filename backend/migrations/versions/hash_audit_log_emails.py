"""Hash audit log emails for security

Revision ID: hash_audit_log_emails
Revises: add_artist_email_idx
Create Date: 2025-12-11

SECURITY FIX: Replace plaintext email column with SHA256 hash.

This migration:
1. Adds email_hash column (64 char hex string)
2. Populates it with SHA256(lowercase(email)) using PostgreSQL crypto
3. Drops the plaintext email column

This protects user emails if the database is compromised while
still allowing equality searches (hash the input, compare).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'hash_audit_log_emails'
down_revision = 'add_artist_email_idx'
branch_labels = None
depends_on = None


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
    # Check if email_hash column already exists (idempotent migration)
    if column_exists('audit_logs', 'email_hash'):
        print("email_hash column already exists in audit_logs, skipping migration")
        return

    # Step 1: Add email_hash column (nullable initially)
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email_hash', sa.String(length=64), nullable=True))

    # Step 2: Populate email_hash from existing email values using PostgreSQL's pgcrypto
    # SHA256 produces 32 bytes -> 64 hex characters
    # Note: pgcrypto extension may need to be enabled: CREATE EXTENSION IF NOT EXISTS pgcrypto;
    bind = op.get_bind()

    # First, try to enable pgcrypto extension (may already exist)
    try:
        bind.execute(sa.text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
    except Exception as e:
        print(f"Note: Could not create pgcrypto extension (may already exist): {e}")

    # Populate email_hash from existing emails
    bind.execute(sa.text("""
        UPDATE audit_logs
        SET email_hash = encode(digest(lower(email), 'sha256'), 'hex')
        WHERE email IS NOT NULL
    """))

    # Step 3: Create index on email_hash
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.create_index('ix_audit_logs_email_hash', ['email_hash'], unique=False)

    # Step 4: Drop the old email column and its index
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_index('ix_audit_logs_email')
        batch_op.drop_column('email')

    print("Migration complete: audit_logs.email replaced with audit_logs.email_hash")


def downgrade():
    # Check if we can downgrade (email column doesn't exist)
    if column_exists('audit_logs', 'email'):
        print("email column already exists in audit_logs, skipping downgrade")
        return

    # Step 1: Add back the email column (we can't recover original values)
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(length=120), nullable=True))

    # Step 2: Create index on email
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.create_index('ix_audit_logs_email', ['email'], unique=False)

    # Step 3: Drop email_hash column and its index
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_index('ix_audit_logs_email_hash')
        batch_op.drop_column('email_hash')

    print("WARNING: Downgrade complete but original emails are LOST (hashing is one-way)")
