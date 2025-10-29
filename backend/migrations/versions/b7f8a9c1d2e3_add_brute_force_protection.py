"""add brute force protection and audit logging

Revision ID: b7f8a9c1d2e3
Revises: a1b2c3d4e5f6
Create Date: 2025-10-27 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b7f8a9c1d2e3'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    # create failed_login_attempts table
    op.create_table('failed_login_attempts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('attempted_at', sa.DateTime(), nullable=False),
    sa.Column('user_agent', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('failed_login_attempts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_failed_login_attempts_email'), ['email'], unique=False)
        batch_op.create_index(batch_op.f('ix_failed_login_attempts_ip_address'), ['ip_address'], unique=False)
        batch_op.create_index(batch_op.f('ix_failed_login_attempts_attempted_at'), ['attempted_at'], unique=False)
    
    # create audit_logs table
    op.create_table('audit_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('event_type', sa.String(length=50), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('email', sa.String(length=120), nullable=True),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('user_agent', sa.String(length=255), nullable=True),
    sa.Column('details', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_logs_event_type'), ['event_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_email'), ['email'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_ip_address'), ['ip_address'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_created_at'), ['created_at'], unique=False)


def downgrade():
    # drop audit_logs table
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_logs_created_at'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_ip_address'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_email'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_user_id'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_event_type'))
    
    op.drop_table('audit_logs')
    
    # drop failed_login_attempts table
    with op.batch_alter_table('failed_login_attempts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_failed_login_attempts_attempted_at'))
        batch_op.drop_index(batch_op.f('ix_failed_login_attempts_ip_address'))
        batch_op.drop_index(batch_op.f('ix_failed_login_attempts_email'))
    
    op.drop_table('failed_login_attempts')

