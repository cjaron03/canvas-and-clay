"""add_user_sessions_table

Revision ID: 084342f753c8
Revises: fedcba987654
Create Date: 2025-12-08 00:53:17.071818

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '084342f753c8'
down_revision = 'fedcba987654'
branch_labels = None
depends_on = None


def upgrade():
    """Create user_sessions table for multi-account session tracking."""
    op.create_table('user_sessions',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('session_token', sa.String(length=255), nullable=False),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_active_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_sessions_session_token'), ['session_token'], unique=True)
        batch_op.create_index(batch_op.f('ix_user_sessions_user_id'), ['user_id'], unique=False)


def downgrade():
    """Drop user_sessions table."""
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_sessions_user_id'))
        batch_op.drop_index(batch_op.f('ix_user_sessions_session_token'))

    op.drop_table('user_sessions')
