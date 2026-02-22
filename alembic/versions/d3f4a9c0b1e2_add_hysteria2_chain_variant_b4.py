"""add hysteria2 chain variant B4

Revision ID: d3f4a9c0b1e2
Revises: c4d9b7a8ef01
Create Date: 2026-02-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "d3f4a9c0b1e2"
down_revision: Union[str, Sequence[str], None] = "c4d9b7a8ef01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE connection_variant ADD VALUE IF NOT EXISTS 'B4';")


def downgrade() -> None:
    # PostgreSQL enums do not support DROP VALUE safely in-place.
    pass
