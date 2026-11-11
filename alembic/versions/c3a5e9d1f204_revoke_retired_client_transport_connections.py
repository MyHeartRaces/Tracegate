"""Revoke retired WGWS and client SS2022-ShadowTLS connections

Revision ID: c3a5e9d1f204
Revises: 7b31d4e9a205
Create Date: 2026-11-11

Retires the two removed client transport families (WireGuard over WebSocket
and client Shadowsocks-2022 inside ShadowTLS v3) by revoking every connection
and connection revision still carrying those protocols. Additive and
idempotent: rows already revoked are left untouched, no enum types are
altered and nothing is dropped. The bridge uses the same SS2022+ShadowTLS
carrier but is not represented by connection rows, so it is unaffected.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "c3a5e9d1f204"
down_revision: Union[str, Sequence[str], None] = "7b31d4e9a205"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_RETIRED_PROTOCOLS = ("WIREGUARD_WSTUNNEL", "SHADOWSOCKS2022_SHADOWTLS")


def upgrade() -> None:
    # The WHERE status <> 'REVOKED' guard makes the update idempotent.
    op.execute(
        """
        UPDATE connection_revision
        SET status = 'REVOKED'
        WHERE status <> 'REVOKED'
          AND connection_id IN (
            SELECT id FROM connection
            WHERE protocol IN ('WIREGUARD_WSTUNNEL', 'SHADOWSOCKS2022_SHADOWTLS')
          );
        """
    )
    op.execute(
        """
        UPDATE connection
        SET status = 'REVOKED'
        WHERE status <> 'REVOKED'
          AND protocol IN ('WIREGUARD_WSTUNNEL', 'SHADOWSOCKS2022_SHADOWTLS');
        """
    )


def downgrade() -> None:
    # No-op: revoking retired-protocol rows is a one-way data retirement;
    # the previous row states are not recoverable.
    pass
