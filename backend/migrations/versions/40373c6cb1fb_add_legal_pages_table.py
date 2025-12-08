"""add legal_pages table

Revision ID: 40373c6cb1fb
Revises: 084342f753c8
Create Date: 2025-12-08 03:05:42.385239

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '40373c6cb1fb'
down_revision = '084342f753c8'
branch_labels = None
depends_on = None


def upgrade():
    # Create the legal_pages table for storing editable legal content
    op.create_table('legal_pages',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('page_type', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('last_updated', sa.DateTime(), nullable=False),
        sa.Column('updated_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('legal_pages', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_legal_pages_page_type'), ['page_type'], unique=True)


def downgrade():
    with op.batch_alter_table('legal_pages', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_legal_pages_page_type'))

    op.drop_table('legal_pages')
