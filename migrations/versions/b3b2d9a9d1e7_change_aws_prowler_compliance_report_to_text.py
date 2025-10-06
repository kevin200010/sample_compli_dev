"""Change aws_prowler_compliance_report to Text

Revision ID: b3b2d9a9d1e7
Revises: 7f5f5ea74070
Create Date: 2025-03-01 00:00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b3b2d9a9d1e7'
down_revision = '7f5f5ea74070'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('accounts', schema=None) as batch_op:
        batch_op.alter_column('aws_prowler_compliance_report',
                              existing_type=sa.String(length=80),
                              type_=sa.Text(),
                              existing_nullable=True)

def downgrade():
    with op.batch_alter_table('accounts', schema=None) as batch_op:
        batch_op.alter_column('aws_prowler_compliance_report',
                              existing_type=sa.Text(),
                              type_=sa.String(length=80),
                              existing_nullable=True)
