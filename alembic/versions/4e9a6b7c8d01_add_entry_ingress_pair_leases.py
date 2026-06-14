"""add entry ingress pair leases

Revision ID: 4e9a6b7c8d01
Revises: 0d4b3f7a9c12
Create Date: 2026-06-15

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "4e9a6b7c8d01"
down_revision: Union[str, Sequence[str], None] = "0d4b3f7a9c12"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("connection_revision", sa.Column("ingress_pair_key", sa.String(length=64), nullable=True))
    op.add_column("connection_revision", sa.Column("ingress_shard_id", sa.String(length=64), nullable=True))
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_connection_revision_active_ingress_pair
        ON connection_revision (ingress_pair_key)
        WHERE status = 'ACTIVE' AND ingress_pair_key IS NOT NULL;
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_connection_revision_active_ingress_pair;")
    op.drop_column("connection_revision", "ingress_shard_id")
    op.drop_column("connection_revision", "ingress_pair_key")
