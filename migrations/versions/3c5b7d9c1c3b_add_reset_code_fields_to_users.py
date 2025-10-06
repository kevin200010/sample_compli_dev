"""Add reset code fields to users

Revision ID: 3c5b7d9c1c3b
Revises: b3b2d9a9d1e7
Create Date: 2025-05-18 00:00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '3c5b7d9c1c3b'
down_revision = 'b3b2d9a9d1e7'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reset_code_hash', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('reset_code_expires_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('reset_code_expires_at')
        batch_op.drop_column('reset_code_hash')
