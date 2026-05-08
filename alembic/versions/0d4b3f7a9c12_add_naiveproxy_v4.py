"""add naiveproxy v4 protocol and role

Revision ID: 0d4b3f7a9c12
Revises: f6b7c8d9e012
Create Date: 2026-05-07

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "0d4b3f7a9c12"
down_revision: Union[str, Sequence[str], None] = "f6b7c8d9e012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE connection_protocol ADD VALUE IF NOT EXISTS 'NAIVEPROXY';")
    op.execute("ALTER TYPE node_role ADD VALUE IF NOT EXISTS 'NAIVEPROXY';")
    op.execute("ALTER TYPE outbox_role_target ADD VALUE IF NOT EXISTS 'NAIVEPROXY';")


def downgrade() -> None:
    # PostgreSQL cannot drop enum values safely in-place.
    pass
