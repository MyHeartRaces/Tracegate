from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tracegate.enums import ConnectionProtocol, RecordStatus
from tracegate.services import revisions as revisions_service
from tracegate.services.revisions import RevisionError


class _FakeSession:
    def __init__(self, revision: SimpleNamespace | None) -> None:
        self._revision = revision
        self.flush_calls = 0

    async def get(self, _model, revision_id):
        if self._revision is None:
            return None
        if revision_id == self._revision.id:
            return self._revision
        return None

    async def flush(self) -> None:
        self.flush_calls += 1


class _CheckingSession(_FakeSession):
    def __init__(self, revision: SimpleNamespace | None, *, connection: SimpleNamespace) -> None:
        super().__init__(revision)
        self._connection = connection

    async def flush(self) -> None:
        await super().flush()
        if self.flush_calls == 1:
            active_rows = [row for row in self._connection.revisions if row.status == RecordStatus.ACTIVE]
            assert all(row.slot >= 10 for row in active_rows)


def _rev(*, connection_id, slot: int, status: RecordStatus) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        connection_id=connection_id,
        slot=slot,
        status=status,
        created_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_activate_revision_uses_two_phase_shift_and_compacts_slots(monkeypatch: pytest.MonkeyPatch) -> None:
    connection_id = uuid4()
    active0 = _rev(connection_id=connection_id, slot=0, status=RecordStatus.ACTIVE)
    active1 = _rev(connection_id=connection_id, slot=1, status=RecordStatus.ACTIVE)
    active2 = _rev(connection_id=connection_id, slot=2, status=RecordStatus.ACTIVE)
    target = _rev(connection_id=connection_id, slot=2, status=RecordStatus.REVOKED)

    connection = SimpleNamespace(
        id=connection_id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        user_id=1,
        revisions=[active0, active1, active2, target],
    )
    session = _FakeSession(target)

    async def _load_connection(_session, _connection_id):
        return connection

    captured: dict = {}

    async def _emit_apply(*_args, **_kwargs) -> None:
        captured.update(_kwargs)
        return None

    monkeypatch.setattr(revisions_service, "_load_connection", _load_connection)
    monkeypatch.setattr(revisions_service, "_emit_apply_for_revision", _emit_apply)

    out = await revisions_service.activate_revision(session, target.id)
    assert out is target
    assert session.flush_calls == 2

    assert target.status == RecordStatus.ACTIVE
    assert target.slot == 0

    active_rows = [row for row in connection.revisions if row.status == RecordStatus.ACTIVE]
    assert len(active_rows) == 3
    assert sorted([row.slot for row in active_rows]) == [0, 1, 2]

    revoked_rows = [row for row in connection.revisions if row.status == RecordStatus.REVOKED]
    assert len(revoked_rows) == 1
    assert isinstance(captured.get("op_ts"), datetime)
    assert captured["op_ts"] >= target.created_at


@pytest.mark.asyncio
async def test_activate_revision_shifts_active_target_before_compaction(monkeypatch: pytest.MonkeyPatch) -> None:
    connection_id = uuid4()
    active0 = _rev(connection_id=connection_id, slot=0, status=RecordStatus.ACTIVE)
    active1 = _rev(connection_id=connection_id, slot=1, status=RecordStatus.ACTIVE)
    target = _rev(connection_id=connection_id, slot=2, status=RecordStatus.ACTIVE)
    connection = SimpleNamespace(
        id=connection_id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        user_id=1,
        revisions=[active0, active1, target],
    )
    session = _CheckingSession(target, connection=connection)

    async def _load_connection(_session, _connection_id):
        return connection

    async def _emit_apply(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setattr(revisions_service, "_load_connection", _load_connection)
    monkeypatch.setattr(revisions_service, "_emit_apply_for_revision", _emit_apply)

    out = await revisions_service.activate_revision(session, target.id)
    assert out is target
    assert session.flush_calls == 2
    assert target.slot == 0
    active_rows = [row for row in connection.revisions if row.status == RecordStatus.ACTIVE]
    assert sorted([row.slot for row in active_rows]) == [0, 1, 2]


@pytest.mark.asyncio
async def test_activate_revision_not_found() -> None:
    session = _FakeSession(None)
    with pytest.raises(RevisionError, match="Revision not found"):
        await revisions_service.activate_revision(session, uuid4())


@pytest.mark.asyncio
async def test_revoke_revision_promote_emits_fresh_op_ts(monkeypatch: pytest.MonkeyPatch) -> None:
    connection_id = uuid4()
    revoked = _rev(connection_id=connection_id, slot=0, status=RecordStatus.ACTIVE)
    promoted = _rev(connection_id=connection_id, slot=1, status=RecordStatus.ACTIVE)
    connection = SimpleNamespace(
        id=connection_id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        user_id=1,
        revisions=[revoked, promoted],
    )
    session = _FakeSession(revoked)
    captured: dict = {}

    async def _load_connection(_session, _connection_id):
        return connection

    async def _compact_slots(_connection) -> None:
        # Mimic compaction result: promoted becomes slot0 active.
        promoted.slot = 0
        promoted.status = RecordStatus.ACTIVE

    async def _emit_apply(*_args, **_kwargs) -> None:
        captured.update(_kwargs)
        return None

    monkeypatch.setattr(revisions_service, "_load_connection", _load_connection)
    monkeypatch.setattr(revisions_service, "_compact_slots", _compact_slots)
    monkeypatch.setattr(revisions_service, "_emit_apply_for_revision", _emit_apply)

    out = await revisions_service.revoke_revision(session, revoked.id)
    assert out is revoked
    assert revoked.status == RecordStatus.REVOKED
    assert captured.get("revision") is promoted
    assert isinstance(captured.get("op_ts"), datetime)
    assert captured["op_ts"] >= promoted.created_at
