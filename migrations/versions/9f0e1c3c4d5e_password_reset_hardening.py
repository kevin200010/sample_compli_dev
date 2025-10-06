"""Add password reset attempt tracking and metadata

Revision ID: 9f0e1c3c4d5e
Revises: 3c5b7d9c1c3b
Create Date: 2025-02-12 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "9f0e1c3c4d5e"
down_revision = "3c5b7d9c1c3b"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("reset_code_attempts", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("reset_token_jti", sa.String(length=64), nullable=True))
        batch_op.add_column(
            sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.alter_column(
            "reset_code_expires_at",
            existing_type=sa.DateTime(),
            type_=sa.DateTime(timezone=True),
            existing_nullable=True,
        )

    op.create_index(
        "ix_users_reset_token_jti", "users", ["reset_token_jti"], unique=False
    )

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column(
            "reset_code_attempts",
            existing_type=sa.Integer(),
            server_default=None,
        )


def downgrade():
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column(
            "reset_code_expires_at",
            existing_type=sa.DateTime(timezone=True),
            type_=sa.DateTime(),
            existing_nullable=True,
        )
        batch_op.drop_column("password_changed_at")
        batch_op.drop_column("reset_token_jti")
        batch_op.drop_column("reset_code_attempts")

    op.drop_index("ix_users_reset_token_jti", table_name="users")
