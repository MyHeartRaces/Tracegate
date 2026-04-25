"""add bot_message_ref table

Revision ID: b7e6a1f4c2d9
Revises: 4c2a0f3d3b1a
Create Date: 2026-02-11 19:35:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "b7e6a1f4c2d9"
down_revision: Union[str, Sequence[str], None] = "4c2a0f3d3b1a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "bot_message_ref",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("telegram_id", sa.BigInteger(), nullable=False),
        sa.Column("chat_id", sa.BigInteger(), nullable=False),
        sa.Column("message_id", sa.BigInteger(), nullable=False),
        sa.Column("connection_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revision_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("chat_id", "message_id", name="uq_bot_message_ref_chat_msg"),
    )
    op.create_index(op.f("ix_bot_message_ref_telegram_id"), "bot_message_ref", ["telegram_id"], unique=False)
    op.create_index(op.f("ix_bot_message_ref_chat_id"), "bot_message_ref", ["chat_id"], unique=False)
    op.create_index(op.f("ix_bot_message_ref_connection_id"), "bot_message_ref", ["connection_id"], unique=False)
    op.create_index(op.f("ix_bot_message_ref_device_id"), "bot_message_ref", ["device_id"], unique=False)
    op.create_index(op.f("ix_bot_message_ref_revision_id"), "bot_message_ref", ["revision_id"], unique=False)
    op.create_index(op.f("ix_bot_message_ref_removed_at"), "bot_message_ref", ["removed_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_bot_message_ref_removed_at"), table_name="bot_message_ref")
    op.drop_index(op.f("ix_bot_message_ref_revision_id"), table_name="bot_message_ref")
    op.drop_index(op.f("ix_bot_message_ref_device_id"), table_name="bot_message_ref")
    op.drop_index(op.f("ix_bot_message_ref_connection_id"), table_name="bot_message_ref")
    op.drop_index(op.f("ix_bot_message_ref_chat_id"), table_name="bot_message_ref")
    op.drop_index(op.f("ix_bot_message_ref_telegram_id"), table_name="bot_message_ref")
    op.drop_table("bot_message_ref")
