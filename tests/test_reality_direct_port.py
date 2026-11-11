from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, EntitlementStatus, RecordStatus
from tracegate.models import Connection, ConnectionRevision, Device, User
from tracegate.services import revisions as revisions_service
from tracegate.services.config_builder import EndpointSet, build_effective_config
from tracegate.services.sni_catalog import SniCatalogEntry
from tracegate.settings import Settings

_SNI = SniCatalogEntry(id=1, fqdn="camouflage.example", enabled=True, is_test=False, providers=[], note=None)


def _user() -> User:
    return User(
        telegram_id=1,
        devices_max=5,
        entitlement_status=EntitlementStatus.ACTIVE,
        grace_ends_at=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _connection(*, mode: ConnectionMode, device: Device, user: User) -> Connection:
    connection = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=mode,
        variant=ConnectionVariant.V1,
        profile_name="v1-direct-reality-vless" if mode == ConnectionMode.DIRECT else "v1-chain-reality-vless",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    connection.device = device
    connection.revisions = []
    return connection


def _endpoints(**kwargs) -> EndpointSet:
    return EndpointSet(
        transit_host="transit.tracegate.test",
        entry_host="entry.tracegate.test",
        reality_public_key_transit="pub-t",
        reality_short_id_transit="sid-t",
        reality_public_key_entry="pub-e",
        reality_short_id_entry="sid-e",
        **kwargs,
    )


def test_direct_reality_builder_uses_configured_port_and_chain_stays_443() -> None:
    user = _user()
    device = Device(id=uuid4(), user_id=user.telegram_id, name="phone", status=RecordStatus.ACTIVE)
    direct = _connection(mode=ConnectionMode.DIRECT, device=device, user=user)
    chain = _connection(mode=ConnectionMode.CHAIN, device=device, user=user)

    direct_default = build_effective_config(
        user=user, device=device, connection=direct, selected_sni=_SNI, endpoints=_endpoints()
    )
    direct_legacy = build_effective_config(
        user=user, device=device, connection=direct, selected_sni=_SNI, endpoints=_endpoints(reality_direct_port=443)
    )
    chain_cfg = build_effective_config(
        user=user, device=device, connection=chain, selected_sni=_SNI, endpoints=_endpoints(reality_direct_port=8443)
    )

    assert direct_default["port"] == 8443
    assert direct_default["design_constraints"]["fixed_port_tcp"] == 8443
    assert direct_legacy["port"] == 443
    assert direct_legacy["design_constraints"]["fixed_port_tcp"] == 443
    assert chain_cfg["port"] == 443
    assert chain_cfg["design_constraints"]["fixed_port_tcp"] == 443


def test_reality_direct_port_setting_defaults_to_8443_and_is_validated() -> None:
    assert Settings().reality_direct_port == 8443
    assert Settings(reality_direct_port=443).reality_direct_port == 443
    with pytest.raises(ValueError):
        Settings(reality_direct_port=0)
    with pytest.raises(ValueError):
        Settings(reality_direct_port=70000)


class _Session:
    async def flush(self) -> None:
        return None


async def _issue(monkeypatch: pytest.MonkeyPatch, connection: Connection, user: User) -> ConnectionRevision:
    settings = Settings(reality_direct_port=8443)

    async def _load_connection(_session, _connection_id):
        return connection

    async def _load_user(_session, _user_id):
        return user

    async def _resolve_sni(*_args, **_kwargs):
        return _SNI

    async def _resolve_endpoints(*_args, **_kwargs):
        return _endpoints(reality_direct_port=settings.reality_direct_port)

    async def _emit(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setattr(revisions_service, "get_settings", lambda: settings)
    monkeypatch.setattr(revisions_service, "_load_connection", _load_connection)
    monkeypatch.setattr(revisions_service, "_load_user", _load_user)
    monkeypatch.setattr(revisions_service, "_resolve_sni", _resolve_sni)
    monkeypatch.setattr(revisions_service, "_resolve_endpoints", _resolve_endpoints)
    monkeypatch.setattr(revisions_service, "_emit_apply_for_revision", _emit)
    monkeypatch.setattr(revisions_service, "ensure_can_issue_new_config", lambda *_args, **_kwargs: None)
    return await revisions_service.create_revision(
        _Session(), connection_id=connection.id, camouflage_sni_id=None, force=False
    )


@pytest.mark.asyncio
async def test_new_direct_reality_connection_is_issued_on_8443(monkeypatch: pytest.MonkeyPatch) -> None:
    user = _user()
    device = Device(id=uuid4(), user_id=user.telegram_id, name="phone", status=RecordStatus.ACTIVE)
    connection = _connection(mode=ConnectionMode.DIRECT, device=device, user=user)

    first = await _issue(monkeypatch, connection, user)
    second = await _issue(monkeypatch, connection, user)

    assert first.effective_config_json["port"] == 8443
    assert second.effective_config_json["port"] == 8443


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_config", [{"protocol": "vless", "port": 443}, {"protocol": "vless"}])
async def test_reissue_of_connection_first_issued_on_443_switches_to_8443(
    monkeypatch: pytest.MonkeyPatch, legacy_config: dict
) -> None:
    user = _user()
    device = Device(id=uuid4(), user_id=user.telegram_id, name="phone", status=RecordStatus.ACTIVE)
    connection = _connection(mode=ConnectionMode.DIRECT, device=device, user=user)
    connection.revisions.append(
        ConnectionRevision(
            id=uuid4(),
            connection_id=connection.id,
            slot=0,
            status=RecordStatus.REVOKED,
            effective_config_json={**legacy_config, "transport": "reality_raw"},
            created_at=datetime.now(timezone.utc) - timedelta(days=30),
        )
    )

    revision = await _issue(monkeypatch, connection, user)

    assert revision.effective_config_json["port"] == 8443
    assert revision.effective_config_json["design_constraints"]["fixed_port_tcp"] == 8443


@pytest.mark.asyncio
async def test_chain_reality_revision_stays_on_443_with_direct_port_8443(monkeypatch: pytest.MonkeyPatch) -> None:
    user = _user()
    device = Device(id=uuid4(), user_id=user.telegram_id, name="phone", status=RecordStatus.ACTIVE)
    connection = _connection(mode=ConnectionMode.CHAIN, device=device, user=user)

    revision = await _issue(monkeypatch, connection, user)

    assert revision.effective_config_json["port"] == 443


def test_ws_and_grpc_backups_stay_on_443_with_direct_port_8443() -> None:
    user = _user()
    device = Device(id=uuid4(), user_id=user.telegram_id, name="phone", status=RecordStatus.ACTIVE)
    for protocol in (ConnectionProtocol.VLESS_WS_TLS, ConnectionProtocol.VLESS_GRPC_TLS):
        connection = Connection(
            id=uuid4(),
            user_id=user.telegram_id,
            device_id=device.id,
            protocol=protocol,
            mode=ConnectionMode.DIRECT,
            variant=ConnectionVariant.V0,
            profile_name="v0-backup",
            custom_overrides_json={},
            status=RecordStatus.ACTIVE,
        )
        cfg = build_effective_config(
            user=user,
            device=device,
            connection=connection,
            selected_sni=None,
            endpoints=_endpoints(transit_server_name="transit.tracegate.test", reality_direct_port=8443),
        )
        assert cfg["port"] == 443
        assert cfg["design_constraints"]["fixed_port_tcp"] == 443
