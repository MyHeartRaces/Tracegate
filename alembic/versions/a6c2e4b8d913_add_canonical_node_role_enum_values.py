"""add canonical node role enum values

Revision ID: a6c2e4b8d913
Revises: f2b8c1d4e9aa
Create Date: 2026-04-21

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "a6c2e4b8d913"
down_revision: Union[str, Sequence[str], None] = "f2b8c1d4e9aa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE node_role ADD VALUE IF NOT EXISTS 'TRANSIT';")
    op.execute("ALTER TYPE node_role ADD VALUE IF NOT EXISTS 'ENTRY';")
    op.execute("ALTER TYPE outbox_role_target ADD VALUE IF NOT EXISTS 'TRANSIT';")
    op.execute("ALTER TYPE outbox_role_target ADD VALUE IF NOT EXISTS 'ENTRY';")


def downgrade() -> None:
    # PostgreSQL cannot drop enum values in-place. Keeping the added aliases is
    # safe and preserves compatibility with already-written Tracegate 2 rows.
    pass
