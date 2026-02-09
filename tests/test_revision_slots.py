import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, RecordStatus
from tracegate.models import Connection, ConnectionRevision
from tracegate.services.revisions import _compact_slots


def test_compact_slots_keeps_only_three_active() -> None:
    conn = Connection(
        id=uuid4(),
        user_id=uuid4(),
        device_id=uuid4(),
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.B1,
        profile_name="B1",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    conn.revisions = [
        ConnectionRevision(
            id=uuid4(),
            connection_id=conn.id,
            slot=i,
            status=RecordStatus.ACTIVE,
            effective_config_json={},
            created_at=datetime.now(timezone.utc),
        )
        for i in range(5)
    ]

    asyncio.run(_compact_slots(conn))

    active = [rev for rev in conn.revisions if rev.status == RecordStatus.ACTIVE]
    revoked = [rev for rev in conn.revisions if rev.status == RecordStatus.REVOKED]

    assert len(active) == 3
    assert sorted([rev.slot for rev in active]) == [0, 1, 2]
    assert len(revoked) == 2
