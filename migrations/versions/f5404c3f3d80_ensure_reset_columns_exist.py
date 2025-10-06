"""Ensure password reset tracking columns exist

Revision ID: f5404c3f3d80
Revises: 9f0e1c3c4d5e
Create Date: 2025-09-30 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "f5404c3f3d80"
down_revision = "9f0e1c3c4d5e"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    user_columns = inspector.get_columns("users")
    columns = {column["name"] for column in user_columns}
    indexes = {index["name"] for index in inspector.get_indexes("users")}
    reset_code_expires_at = next(
        (column for column in user_columns if column["name"] == "reset_code_expires_at"),
        None,
    )

    added_reset_code_attempts = False

    with op.batch_alter_table("users") as batch_op:
        if "reset_code_attempts" not in columns:
            batch_op.add_column(
                sa.Column(
                    "reset_code_attempts", sa.Integer(), nullable=False, server_default="0"
                )
            )
            added_reset_code_attempts = True
        if "reset_token_jti" not in columns:
            batch_op.add_column(sa.Column("reset_token_jti", sa.String(length=64), nullable=True))
        if "password_changed_at" not in columns:
            batch_op.add_column(
                sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True)
            )
        if reset_code_expires_at is not None:
            existing_type = reset_code_expires_at["type"]
            has_timezone = getattr(existing_type, "timezone", False)
            if not has_timezone:
                batch_op.alter_column(
                    "reset_code_expires_at",
                    existing_type=existing_type,
                    type_=sa.DateTime(timezone=True),
                    existing_nullable=True,
                )

    if added_reset_code_attempts:
        with op.batch_alter_table("users") as batch_op:
            batch_op.alter_column(
                "reset_code_attempts",
                existing_type=sa.Integer(),
                server_default=None,
            )

    if "ix_users_reset_token_jti" not in indexes:
        op.create_index("ix_users_reset_token_jti", "users", ["reset_token_jti"], unique=False)


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    user_columns = inspector.get_columns("users")
    columns = {column["name"] for column in user_columns}
    indexes = {index["name"] for index in inspector.get_indexes("users")}
    reset_code_expires_at = next(
        (column for column in user_columns if column["name"] == "reset_code_expires_at"),
        None,
    )

    if "ix_users_reset_token_jti" in indexes:
        op.drop_index("ix_users_reset_token_jti", table_name="users")

    with op.batch_alter_table("users") as batch_op:
        if "password_changed_at" in columns:
            batch_op.drop_column("password_changed_at")
        if "reset_token_jti" in columns:
            batch_op.drop_column("reset_token_jti")
        if "reset_code_attempts" in columns:
            batch_op.drop_column("reset_code_attempts")

    if reset_code_expires_at is not None:
        existing_type = reset_code_expires_at["type"]
        has_timezone = getattr(existing_type, "timezone", False)
        if has_timezone:
            with op.batch_alter_table("users") as batch_op:
                batch_op.alter_column(
                    "reset_code_expires_at",
                    existing_type=existing_type,
                    type_=sa.DateTime(),
                    existing_nullable=True,
                )
