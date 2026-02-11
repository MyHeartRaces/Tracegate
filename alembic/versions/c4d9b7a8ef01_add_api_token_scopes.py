"""add api token scopes

Revision ID: c4d9b7a8ef01
Revises: 8f2d6f1eab44
Create Date: 2026-02-12

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c4d9b7a8ef01"
down_revision: Union[str, Sequence[str], None] = "8f2d6f1eab44"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "api_token",
        sa.Column("scopes", sa.JSON(), nullable=False, server_default=sa.text("'[\"*\"]'::json")),
    )
    op.execute("UPDATE api_token SET scopes = '[\"*\"]'::json WHERE scopes IS NULL")


def downgrade() -> None:
    op.drop_column("api_token", "scopes")
