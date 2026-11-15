"""Revoke retired Chain Hysteria connections

Revision ID: a8c3e5f17b42
Revises: d4b6f0e2a315
Create Date: 2026-11-15

Retires Chain Hysteria (HYSTERIA2 in Chain mode, terminated on the Entry
Hysteria listener) by revoking every connection and connection revision still
carrying protocol HYSTERIA2 with mode CHAIN. Direct Hysteria is untouched.
Additive and idempotent: rows already revoked are left untouched, no enum
types are altered and nothing is dropped, so the rows still load and display.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "a8c3e5f17b42"
down_revision: Union[str, Sequence[str], None] = "d4b6f0e2a315"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_RETIRED_PROTOCOL = "HYSTERIA2"
_RETIRED_MODE = "CHAIN"


def upgrade() -> None:
    # The WHERE status <> 'REVOKED' guard makes the update idempotent.
    op.execute(
        """
        UPDATE connection_revision
        SET status = 'REVOKED'
        WHERE status <> 'REVOKED'
          AND connection_id IN (
            SELECT id FROM connection
            WHERE protocol = 'HYSTERIA2'
              AND mode = 'CHAIN'
          );
        """
    )
    op.execute(
        """
        UPDATE connection
        SET status = 'REVOKED'
        WHERE status <> 'REVOKED'
          AND protocol = 'HYSTERIA2'
          AND mode = 'CHAIN';
        """
    )


def downgrade() -> None:
    # No-op: revoking retired Chain Hysteria rows is a one-way data retirement;
    # the previous row states are not recoverable.
    pass
