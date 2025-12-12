"""Hash emails in failed_login_attempts table for privacy protection.

This migration converts the plaintext email column to email_hash (SHA256).
This protects user identity if the database is compromised while still
allowing rate limiting lookups.

Revision ID: hash_failed_login_emails
Revises: hash_audit_log_emails
Create Date: 2025-01-XX

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'hash_failed_login_emails'
down_revision = 'hash_audit_log_emails'
branch_labels = None
depends_on = None


def upgrade():
    """Add email_hash column, migrate data, drop email column."""
    bind = op.get_bind()

    # Check if we're on SQLite (testing) vs PostgreSQL (production)
    is_sqlite = bind.dialect.name == 'sqlite'

    if is_sqlite:
        # SQLite: recreate table with new schema
        # First check if email_hash column already exists
        result = bind.execute(sa.text(
            "SELECT COUNT(*) FROM pragma_table_info('failed_login_attempts') WHERE name='email_hash'"
        ))
        if result.scalar() > 0:
            # Column already exists, skip migration
            return

        # Create new table with email_hash instead of email
        op.execute("""
            CREATE TABLE failed_login_attempts_new (
                id INTEGER PRIMARY KEY,
                email_hash VARCHAR(64) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                attempted_at DATETIME NOT NULL,
                user_agent VARCHAR(255)
            )
        """)

        # Copy data with hashed emails (SQLite doesn't have pgcrypto, use Python)
        # For existing data, we'll hash it in Python
        result = bind.execute(sa.text("SELECT id, email, ip_address, attempted_at, user_agent FROM failed_login_attempts"))
        rows = result.fetchall()

        import hashlib
        for row in rows:
            email = row[1] or ''
            email_hash = hashlib.sha256(email.lower().strip().encode('utf-8')).hexdigest()
            bind.execute(
                sa.text("""
                    INSERT INTO failed_login_attempts_new (id, email_hash, ip_address, attempted_at, user_agent)
                    VALUES (:id, :email_hash, :ip_address, :attempted_at, :user_agent)
                """),
                {'id': row[0], 'email_hash': email_hash, 'ip_address': row[2], 'attempted_at': row[3], 'user_agent': row[4]}
            )

        # Swap tables
        op.execute("DROP TABLE failed_login_attempts")
        op.execute("ALTER TABLE failed_login_attempts_new RENAME TO failed_login_attempts")

        # Recreate indexes
        op.create_index('ix_failed_login_attempts_email_hash', 'failed_login_attempts', ['email_hash'])
        op.create_index('ix_failed_login_attempts_ip_address', 'failed_login_attempts', ['ip_address'])
        op.create_index('ix_failed_login_attempts_attempted_at', 'failed_login_attempts', ['attempted_at'])
    else:
        # PostgreSQL: use ALTER TABLE
        # Check if email_hash column already exists
        result = bind.execute(sa.text("""
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = 'failed_login_attempts' AND column_name = 'email_hash'
        """))
        if result.scalar() > 0:
            # Column already exists, skip migration
            return

        # Step 1: Add email_hash column
        op.add_column('failed_login_attempts', sa.Column('email_hash', sa.String(length=64), nullable=True))

        # Step 2: Populate email_hash from existing email values using PostgreSQL's pgcrypto
        try:
            bind.execute(sa.text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
        except Exception as e:
            print(f"Note: Could not create pgcrypto extension (may already exist): {e}")

        # Hash existing emails
        bind.execute(sa.text("""
            UPDATE failed_login_attempts
            SET email_hash = encode(digest(lower(trim(COALESCE(email, ''))), 'sha256'), 'hex')
            WHERE email_hash IS NULL
        """))

        # Step 3: Make email_hash NOT NULL and create index
        op.alter_column('failed_login_attempts', 'email_hash', nullable=False)
        op.create_index('ix_failed_login_attempts_email_hash', 'failed_login_attempts', ['email_hash'])

        # Step 4: Drop the old email column and its index
        op.drop_index('ix_failed_login_attempts_email', table_name='failed_login_attempts')
        op.drop_column('failed_login_attempts', 'email')


def downgrade():
    """Restore email column (data will be empty - hashes are one-way)."""
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == 'sqlite'

    if is_sqlite:
        # SQLite: recreate table with old schema
        op.execute("""
            CREATE TABLE failed_login_attempts_new (
                id INTEGER PRIMARY KEY,
                email VARCHAR(120) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                attempted_at DATETIME NOT NULL,
                user_agent VARCHAR(255)
            )
        """)

        # Copy data (email will be placeholder since hash is irreversible)
        op.execute("""
            INSERT INTO failed_login_attempts_new (id, email, ip_address, attempted_at, user_agent)
            SELECT id, 'redacted@privacy.local', ip_address, attempted_at, user_agent
            FROM failed_login_attempts
        """)

        op.execute("DROP TABLE failed_login_attempts")
        op.execute("ALTER TABLE failed_login_attempts_new RENAME TO failed_login_attempts")

        op.create_index('ix_failed_login_attempts_email', 'failed_login_attempts', ['email'])
        op.create_index('ix_failed_login_attempts_ip_address', 'failed_login_attempts', ['ip_address'])
        op.create_index('ix_failed_login_attempts_attempted_at', 'failed_login_attempts', ['attempted_at'])
    else:
        # PostgreSQL
        # Add email column back (empty - hashes are one-way)
        op.add_column('failed_login_attempts', sa.Column('email', sa.String(length=120), nullable=True))

        # Fill with placeholder value
        bind.execute(sa.text("UPDATE failed_login_attempts SET email = 'redacted@privacy.local'"))

        op.alter_column('failed_login_attempts', 'email', nullable=False)
        op.create_index('ix_failed_login_attempts_email', 'failed_login_attempts', ['email'])

        # Drop email_hash
        op.drop_index('ix_failed_login_attempts_email_hash', table_name='failed_login_attempts')
        op.drop_column('failed_login_attempts', 'email_hash')
