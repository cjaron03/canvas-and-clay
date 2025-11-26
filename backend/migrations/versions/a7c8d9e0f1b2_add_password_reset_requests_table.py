"""add_password_reset_requests_table

Revision ID: a7c8d9e0f1b2
Revises: a9b8c7d6e5f4
Create Date: 2024-05-16 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a7c8d9e0f1b2'
down_revision = '6756a6a19a92'
branch_labels = None
depends_on = None


def upgrade():
    """Create password_reset_requests table for manual admin workflows."""
    op.create_table(
        'password_reset_requests',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('email', sa.String(length=254), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('user_message', sa.Text(), nullable=True),
        sa.Column('admin_message', sa.Text(), nullable=True),
        sa.Column('reset_code_hash', sa.String(length=255), nullable=True),
        sa.Column('reset_code_hint', sa.String(length=12), nullable=True),
        sa.Column('approved_by_id', sa.Integer(), nullable=True),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['approved_by_id'], ['users.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_password_reset_requests_email', 'password_reset_requests', ['email'], unique=False)
    op.create_index('ix_password_reset_requests_status', 'password_reset_requests', ['status'], unique=False)
    op.create_index('ix_password_reset_requests_user_id', 'password_reset_requests', ['user_id'], unique=False)


def downgrade():
    """Drop password_reset_requests table."""
    op.drop_index('ix_password_reset_requests_user_id', table_name='password_reset_requests')
    op.drop_index('ix_password_reset_requests_status', table_name='password_reset_requests')
    op.drop_index('ix_password_reset_requests_email', table_name='password_reset_requests')
    op.drop_table('password_reset_requests')
