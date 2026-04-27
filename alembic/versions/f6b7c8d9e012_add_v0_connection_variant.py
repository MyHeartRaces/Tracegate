"""add v0 connection variant for Tracegate 2.2 other profiles

Revision ID: f6b7c8d9e012
Revises: a9e7c3b2d6f1
Create Date: 2026-04-28 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "f6b7c8d9e012"
down_revision = "a9e7c3b2d6f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "device",
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.create_index(
        "uq_device_active_per_user",
        "device",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE' AND is_active"),
    )
    op.execute(
        """
        UPDATE device
        SET is_active = true
        WHERE id IN (
            SELECT DISTINCT ON (user_id) id
            FROM device
            WHERE status = 'ACTIVE'
            ORDER BY user_id, created_at ASC
        );
        """
    )
    op.alter_column("device", "is_active", server_default=None)

    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE connection_variant ADD VALUE IF NOT EXISTS 'V0';")
    op.execute(
        """
        UPDATE connection
        SET variant = 'V0', profile_name = 'v0-ws-vless'
        WHERE protocol = 'vless_ws_tls';
        """
    )
    op.execute(
        """
        UPDATE connection
        SET variant = 'V0', profile_name = 'v0-grpc-vless'
        WHERE protocol = 'vless_grpc_tls';
        """
    )
    op.execute(
        """
        UPDATE connection
        SET variant = 'V1', profile_name = 'v1-chain-reality-vless'
        WHERE protocol = 'vless_reality' AND mode = 'chain';
        """
    )
    op.execute(
        """
        UPDATE connection
        SET variant = 'V1', profile_name = 'v1-direct-reality-vless'
        WHERE protocol = 'vless_reality' AND mode = 'direct';
        """
    )
    op.execute(
        """
        UPDATE connection
        SET variant = 'V2', profile_name = 'v2-direct-quic-hysteria'
        WHERE protocol = 'hysteria2' AND mode = 'direct';
        """
    )
    op.execute(
        """
        UPDATE connection
        SET variant = 'V2', profile_name = 'v2-chain-quic-hysteria'
        WHERE protocol = 'hysteria2' AND mode = 'chain';
        """
    )
    op.execute(
        """
        UPDATE connection
        SET variant = 'V3', profile_name = 'v3-direct-shadowtls-shadowsocks'
        WHERE protocol = 'shadowsocks2022_shadowtls' AND mode = 'direct';
        """
    )
    op.execute(
        """
        UPDATE connection
        SET variant = 'V3', profile_name = 'v3-chain-shadowtls-shadowsocks'
        WHERE protocol = 'shadowsocks2022_shadowtls' AND mode = 'chain';
        """
    )
    op.execute(
        """
        UPDATE connection
        SET variant = 'V0', profile_name = 'v0-wgws-wireguard'
        WHERE protocol = 'wireguard_wstunnel';
        """
    )


def downgrade() -> None:
    # PostgreSQL cannot remove enum values safely. Existing V0/V1/V2/V3 rows are
    # intentionally left in the normalized Tracegate 2.2 shape.
    pass
