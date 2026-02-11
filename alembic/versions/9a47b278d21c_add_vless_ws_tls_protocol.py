"""add vless ws tls protocol

Revision ID: 9a47b278d21c
Revises: 92b17df9933b
Create Date: 2026-02-11 01:33:59.976005

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a47b278d21c'
down_revision: Union[str, Sequence[str], None] = '92b17df9933b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add enum value without breaking existing DBs.
    op.execute(
        "DO $$ BEGIN "
        "ALTER TYPE connection_protocol ADD VALUE IF NOT EXISTS 'VLESS_WS_TLS'; "
        "EXCEPTION WHEN undefined_object THEN NULL; "
        "END $$;"
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Postgres does not support dropping enum values safely in-place.
    # If you really need to downgrade, you must create a new enum type and cast.
    pass
