"""Revoke retired VLESS WebSocket-TLS and VLESS gRPC-TLS connections

Revision ID: d4b6f0e2a315
Revises: c3a5e9d1f204
Create Date: 2026-11-15

Retires the VLESS over WebSocket-TLS and VLESS over gRPC-TLS client families
(the Direct "Backup" profiles and the legacy V5 Chain variants) by revoking
every connection and connection revision still carrying those protocols.
Additive and idempotent: rows already revoked are left untouched, no enum
types are altered and nothing is dropped, so the rows still load and display.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "d4b6f0e2a315"
down_revision: Union[str, Sequence[str], None] = "c3a5e9d1f204"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_RETIRED_PROTOCOLS = ("VLESS_WS_TLS", "VLESS_GRPC_TLS")


def upgrade() -> None:
    # The WHERE status <> 'REVOKED' guard makes the update idempotent.
    op.execute(
        """
        UPDATE connection_revision
        SET status = 'REVOKED'
        WHERE status <> 'REVOKED'
          AND connection_id IN (
            SELECT id FROM connection
            WHERE protocol IN ('VLESS_WS_TLS', 'VLESS_GRPC_TLS')
          );
        """
    )
    op.execute(
        """
        UPDATE connection
        SET status = 'REVOKED'
        WHERE status <> 'REVOKED'
          AND protocol IN ('VLESS_WS_TLS', 'VLESS_GRPC_TLS');
        """
    )


def downgrade() -> None:
    # No-op: revoking retired-protocol rows is a one-way data retirement;
    # the previous row states are not recoverable.
    pass
