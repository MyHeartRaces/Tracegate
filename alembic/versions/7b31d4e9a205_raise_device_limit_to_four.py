"""raise account device limit to four

Revision ID: 7b31d4e9a205
Revises: 4e9a6b7c8d01
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7b31d4e9a205"
down_revision: Union[str, Sequence[str], None] = "4e9a6b7c8d01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column("tg_user", "devices_max", server_default=sa.text("4"), existing_type=sa.Integer(), nullable=False)
    op.execute("UPDATE tg_user SET devices_max = 4 WHERE devices_max < 4")


def downgrade() -> None:
    op.alter_column("tg_user", "devices_max", server_default=sa.text("3"), existing_type=sa.Integer(), nullable=False)
