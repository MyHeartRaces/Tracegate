"""v0.3 user profile, timed bot blocks and integrity guards

Revision ID: 8f2d6f1eab44
Revises: b7e6a1f4c2d9
Create Date: 2026-02-12

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "8f2d6f1eab44"
down_revision: Union[str, Sequence[str], None] = "b7e6a1f4c2d9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Telegram profile snapshot fields (for aliases and admin UX).
    op.add_column("tg_user", sa.Column("telegram_username", sa.String(length=64), nullable=True))
    op.add_column("tg_user", sa.Column("telegram_first_name", sa.String(length=128), nullable=True))
    op.add_column("tg_user", sa.Column("telegram_last_name", sa.String(length=128), nullable=True))
    op.create_index(op.f("ix_tg_user_telegram_username"), "tg_user", ["telegram_username"], unique=False)

    # Timed bot-level block (separate from billing entitlement semantics).
    op.add_column("tg_user", sa.Column("bot_blocked_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tg_user", sa.Column("bot_block_reason", sa.String(length=255), nullable=True))
    op.create_index(op.f("ix_tg_user_bot_blocked_until"), "tg_user", ["bot_blocked_until"], unique=False)

    # Clean up pre-v0.3 duplicates before enabling stricter unique guards.
    op.execute(
        """
        WITH ranked AS (
          SELECT
            id,
            row_number() OVER (
              PARTITION BY connection_id, slot
              ORDER BY created_at DESC, id DESC
            ) AS rn
          FROM connection_revision
          WHERE status = 'ACTIVE'
        )
        UPDATE connection_revision AS cr
        SET status = 'REVOKED'
        FROM ranked AS r
        WHERE cr.id = r.id AND r.rn > 1;
        """
    )
    op.execute(
        """
        WITH ranked AS (
          SELECT
            id,
            row_number() OVER (
              PARTITION BY pool_id, owner_type, owner_id
              ORDER BY updated_at DESC, created_at DESC, id DESC
            ) AS rn
          FROM ipam_lease
          WHERE status = 'ACTIVE'
        )
        UPDATE ipam_lease AS l
        SET status = 'RELEASED',
            quarantined_until = NULL
        FROM ranked AS r
        WHERE l.id = r.id AND r.rn > 1;
        """
    )

    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_connection_revision_active_slot
        ON connection_revision (connection_id, slot)
        WHERE status = 'ACTIVE';
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_ipam_lease_active_owner
        ON ipam_lease (pool_id, owner_type, owner_id)
        WHERE status = 'ACTIVE';
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_ipam_lease_active_owner;")
    op.execute("DROP INDEX IF EXISTS uq_connection_revision_active_slot;")

    op.drop_index(op.f("ix_tg_user_bot_blocked_until"), table_name="tg_user")
    op.drop_column("tg_user", "bot_block_reason")
    op.drop_column("tg_user", "bot_blocked_until")

    op.drop_index(op.f("ix_tg_user_telegram_username"), table_name="tg_user")
    op.drop_column("tg_user", "telegram_last_name")
    op.drop_column("tg_user", "telegram_first_name")
    op.drop_column("tg_user", "telegram_username")
