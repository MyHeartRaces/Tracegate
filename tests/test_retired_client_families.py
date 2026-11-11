"""Retired client families: WireGuard over WebSocket and client SS2022 + ShadowTLS.

New issuance is impossible, but rows that already exist must still load,
display and be revocable, and the bridge that shares the SS2022 + ShadowTLS
carrier must not be affected.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import re
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, NodeRole, OutboxEventType, RecordStatus
from tracegate.services import connections as connections_service
from tracegate.services.connection_profiles import (
    connection_profile_display_label,
    connection_profile_label,
    is_supported_profile,
    supported_profile_specs,
)
from tracegate.services.role_targeting import target_roles_for_connection

REPO_ROOT = Path(__file__).resolve().parents[1]

RETIRED = (
    (ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionMode.DIRECT, ConnectionVariant.V3),
    (ConnectionProtocol.WIREGUARD_WSTUNNEL, ConnectionMode.DIRECT, ConnectionVariant.V0),
)


@pytest.mark.parametrize(("protocol", "mode", "variant"), RETIRED)
def test_retired_families_cannot_be_issued(protocol, mode, variant) -> None:
    assert not is_supported_profile(protocol, mode, variant)
    assert (protocol, mode, variant) not in set(supported_profile_specs().values())


def test_retired_enum_members_remain_for_existing_rows() -> None:
    assert ConnectionProtocol("shadowsocks2022_shadowtls") is ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS
    assert ConnectionProtocol("wireguard_wstunnel") is ConnectionProtocol.WIREGUARD_WSTUNNEL


def test_legacy_rows_keep_their_labels() -> None:
    ss, wg = RETIRED
    assert connection_profile_label(*ss) == "v3-direct-shadowtls-shadowsocks"
    assert connection_profile_display_label(*ss) == "Tracegate-Experimental(SS2022)"
    assert connection_profile_label(*wg) == "v0-wgws-wireguard"
    assert connection_profile_display_label(*wg) == "Tracegate-Experimental(WGWS)"


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    def __init__(self, connection, revisions):
        self.connection = connection
        self.revisions = revisions

    async def get(self, _model, key):
        return self.connection if key == self.connection.id else None

    async def execute(self, _statement):
        return _FakeResult(self.revisions)


@pytest.mark.parametrize(("protocol", "mode", "variant"), RETIRED)
def test_legacy_rows_can_still_be_revoked(monkeypatch, protocol, mode, variant) -> None:
    events: list[dict] = []

    async def _fake_outbox(_session, **kwargs):
        events.append(kwargs)

    monkeypatch.setattr(connections_service, "create_outbox_event", _fake_outbox)
    connection = SimpleNamespace(
        id=uuid4(),
        user_id=101,
        device_id=uuid4(),
        protocol=protocol,
        mode=mode,
        variant=variant,
        status=RecordStatus.ACTIVE,
    )
    revision = SimpleNamespace(status=RecordStatus.ACTIVE)

    asyncio.run(connections_service.revoke_connection(_FakeSession(connection, [revision]), connection.id))

    assert connection.status == RecordStatus.REVOKED
    assert revision.status == RecordStatus.REVOKED
    assert [event["role_target"] for event in events] == target_roles_for_connection(protocol, variant, mode)
    assert all(event["event_type"] == OutboxEventType.REVOKE_CONNECTION for event in events)
    assert NodeRole.TRANSIT in {event["role_target"] for event in events}


def test_retirement_migration_only_touches_the_two_retired_protocols() -> None:
    migration = next((REPO_ROOT / "alembic" / "versions").glob("*_revoke_retired_client_transport_connections.py"))
    text = migration.read_text(encoding="utf-8")
    sql = "\n".join(re.findall(r'"""(.*?)"""', text, flags=re.S)[1:])

    assert set(re.findall(r"'([A-Z0-9_]+)'", sql)) == {"REVOKED", "WIREGUARD_WSTUNNEL", "SHADOWSOCKS2022_SHADOWTLS"}
    assert "DROP" not in sql.upper()
    assert "ALTER TYPE" not in sql.upper()
    assert "DELETE" not in sql.upper()


def test_bridge_inbound_survives_and_client_inbound_is_gone() -> None:
    import json

    base = json.loads((REPO_ROOT / "bundles" / "base-transit" / "xray-ss2022.json").read_text(encoding="utf-8"))
    tags = {inbound.get("tag") for inbound in base["inbounds"]}
    assert "ss2022-backhaul-in" in tags
    assert "ss2022-in" not in tags
    for rule in base.get("routing", {}).get("rules", []):
        assert "ss2022-in" not in (rule.get("inboundTag") or [])

    units = REPO_ROOT / "deploy" / "systemd"
    for bridge_unit in (
        "tracegate-xray-ss2022.service",
        "tracegate-shadowtls-backhaul.service",
        "tracegate-shadowtls-backhaul2.service",
        "tracegate-shadowtls-entry.service",
        "tracegate-shadowtls-entry2.service",
    ):
        assert (units / bridge_unit).is_file()
    for retired_unit in (
        "tracegate-shadowtls.service",
        "tracegate-wireguard.service",
        "tracegate-wireguard-sync.service",
        "tracegate-wstunnel-wireguard.service",
    ):
        assert not (units / retired_unit).exists()
