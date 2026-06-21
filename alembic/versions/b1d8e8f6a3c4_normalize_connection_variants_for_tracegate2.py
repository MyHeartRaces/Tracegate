"""normalize connection variants for Tracegate 2

Revision ID: b1d8e8f6a3c4
Revises: a6c2e4b8d913
Create Date: 2026-04-21

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "b1d8e8f6a3c4"
down_revision: Union[str, Sequence[str], None] = "a6c2e4b8d913"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _rename_variant(old_label: str, new_label: str) -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1
            FROM pg_type t
            JOIN pg_enum e ON t.oid = e.enumtypid
            WHERE t.typname = 'connection_variant' AND e.enumlabel = '{old_label}'
          ) AND NOT EXISTS (
            SELECT 1
            FROM pg_type t
            JOIN pg_enum e ON t.oid = e.enumtypid
            WHERE t.typname = 'connection_variant' AND e.enumlabel = '{new_label}'
          ) THEN
            ALTER TYPE connection_variant RENAME VALUE '{old_label}' TO '{new_label}';
          END IF;
        END
        $$;
        """
    )


def upgrade() -> None:
    _rename_variant("B1", "V1")
    _rename_variant("B2", "V2")
    _rename_variant("B3", "V3")
    _rename_variant("B4", "V4")

    # Tracegate 2 does not support legacy WireGuard rows. Remove them so the
    # new enum-backed ORM models never try to deserialize unsupported B5/WG
    # records left over from old deployments.
    op.execute(
        """
        DELETE FROM connection_revision
        WHERE connection_id IN (
          SELECT id
          FROM connection
          WHERE protocol = 'WIREGUARD' OR variant = 'B5'
        );
        """
    )
    op.execute("DELETE FROM connection WHERE protocol = 'WIREGUARD' OR variant = 'B5';")
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1
            FROM pg_class
            WHERE relname = 'wireguard_peer' AND relkind = 'r'
          ) THEN
            DELETE FROM wireguard_peer;
          END IF;
        END
        $$;
        """
    )
    op.execute("DELETE FROM outbox_event WHERE event_type IN ('WG_PEER_UPSERT', 'WG_PEER_REMOVE');")


def downgrade() -> None:
    # PostgreSQL enum rewrites are intentionally kept one-way here. The
    # Tracegate 2 runtime expects V1..V4 and no longer supports WireGuard rows.
    pass
