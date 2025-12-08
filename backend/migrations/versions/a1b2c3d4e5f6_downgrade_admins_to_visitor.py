"""downgrade admins to visitor except bootstrap

Revision ID: a1b2c3d4e5f6
Revises: d6c8e4bd5a0a
Create Date: 2025-10-27 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
import os


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = 'd6c8e4bd5a0a'
branch_labels = None
depends_on = None


def upgrade():
    # get bootstrap admin email from environment
    bootstrap_email = os.getenv('BOOTSTRAP_ADMIN_EMAIL', 'admin@canvas-clay.local')

    connection = op.get_bind()

    # check if users table exists using dialect-agnostic inspection
    from sqlalchemy import inspect
    inspector = inspect(connection)
    table_exists = 'users' in inspector.get_table_names()

    # only run downgrade if users table exists
    if table_exists:
        # downgrade all admin users to visitor except the bootstrap admin
        connection.execute(
            sa.text("""
                UPDATE users
                SET role = 'visitor'
                WHERE role = 'admin'
                AND email != :bootstrap_email
            """),
            {'bootstrap_email': bootstrap_email}
        )


def downgrade():
    # cannot reliably restore previous admin roles
    # manual intervention required if rollback needed
    pass

