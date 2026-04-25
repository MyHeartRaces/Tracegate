"""add mtproto access grants

Revision ID: f2b8c1d4e9aa
Revises: d3f4a9c0b1e2
Create Date: 2026-04-17

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f2b8c1d4e9aa"
down_revision: Union[str, Sequence[str], None] = "d3f4a9c0b1e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mtproto_access_grant",
        sa.Column("telegram_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.Enum("ACTIVE", "REVOKED", name="mtproto_access_status"), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=True),
        sa.Column("issued_by", sa.String(length=64), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["telegram_id"], ["tg_user.telegram_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("telegram_id"),
    )
    op.create_index(op.f("ix_mtproto_access_grant_status"), "mtproto_access_grant", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_mtproto_access_grant_status"), table_name="mtproto_access_grant")
    op.drop_table("mtproto_access_grant")
    sa.Enum(name="mtproto_access_status").drop(op.get_bind(), checkfirst=True)
