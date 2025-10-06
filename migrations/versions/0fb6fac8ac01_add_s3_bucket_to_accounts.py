"""Add s3_bucket to Accounts

Revision ID: 0fb6fac8ac01
Revises: 7f5f5ea74070
Create Date: 2025-08-12 15:59:51.604775

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0fb6fac8ac01'
down_revision = '7f5f5ea74070'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('accounts', sa.Column('s3_bucket', sa.String(length=80), nullable=True))


def downgrade():
    op.drop_column('accounts', 's3_bucket')
