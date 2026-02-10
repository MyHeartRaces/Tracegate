from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection


async def migrate(conn: AsyncConnection) -> None:
    # Add new OutboxEventType enum value (Postgres).
    # If the enum type does not exist yet (fresh DB), create_all will handle it.
    await conn.execute(
        text("DO $$ BEGIN ALTER TYPE outbox_event_type ADD VALUE IF NOT EXISTS 'REVOKE_CONNECTION'; EXCEPTION WHEN undefined_object THEN NULL; END $$;")
    )
