"""add bot welcome acceptance

Revision ID: a9e7c3b2d6f1
Revises: e1c7a4b9d2f0
Create Date: 2026-04-25

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "a9e7c3b2d6f1"
down_revision: Union[str, Sequence[str], None] = "e1c7a4b9d2f0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("tg_user", sa.Column("bot_welcome_accepted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tg_user", sa.Column("bot_welcome_version", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("tg_user", "bot_welcome_version")
    op.drop_column("tg_user", "bot_welcome_accepted_at")
