"""add Tracegate 2.1 connection profiles

Revision ID: e1c7a4b9d2f0
Revises: b1d8e8f6a3c4
Create Date: 2026-04-24

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e1c7a4b9d2f0"
down_revision: Union[str, Sequence[str], None] = "b1d8e8f6a3c4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_enum_value(type_name: str, value: str) -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM pg_type t
            JOIN pg_enum e ON t.oid = e.enumtypid
            WHERE t.typname = '{type_name}' AND e.enumlabel = '{value}'
          ) THEN
            ALTER TYPE {type_name} ADD VALUE '{value}';
          END IF;
        END
        $$;
        """
    )


def upgrade() -> None:
    _add_enum_value("connection_protocol", "VLESS_GRPC_TLS")
    _add_enum_value("connection_protocol", "SHADOWSOCKS2022_SHADOWTLS")
    _add_enum_value("connection_protocol", "WIREGUARD_WSTUNNEL")
    _add_enum_value("connection_variant", "V5")
    _add_enum_value("connection_variant", "V6")
    _add_enum_value("connection_variant", "V7")


def downgrade() -> None:
    # PostgreSQL enum value removal requires a full type rewrite and is not
    # worth the downgrade risk for production rows. Keep this migration one-way.
    pass
