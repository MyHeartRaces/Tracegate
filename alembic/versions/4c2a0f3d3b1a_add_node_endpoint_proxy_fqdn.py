"""add node endpoint proxy fqdn

Revision ID: 4c2a0f3d3b1a
Revises: 9a47b278d21c
Create Date: 2026-02-10

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "4c2a0f3d3b1a"
down_revision: Union[str, Sequence[str], None] = "9a47b278d21c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Used for WS+TLS via an L7 proxy (e.g. Cloudflare orange cloud). Keep nullable for backward compatibility.
    op.execute("ALTER TABLE node_endpoint ADD COLUMN IF NOT EXISTS proxy_fqdn VARCHAR(255);")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("ALTER TABLE node_endpoint DROP COLUMN IF EXISTS proxy_fqdn;")

