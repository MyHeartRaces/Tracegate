from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import yaml

from tracegate.client_export.config import ClientConfigExportError, export_client_config
from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, EntitlementStatus, RecordStatus
from tracegate.models import Connection, Device, User
from tracegate.services.config_builder import EndpointSet, build_effective_config
from tracegate.services.hysteria_hopping import (
    HysteriaHopRangeError,
    parse_hop_range,
    validate_hop_intervals,
    validate_hop_ranges,
)
from tracegate.settings import Settings

_RESERVED = (443, 4443, 8443, 8444)


# --- range validation ---------------------------------------------------


def test_parse_hop_range_accepts_valid_and_empty_values() -> None:
    assert parse_hop_range("") is None
    assert parse_hop_range(None) is None
    assert parse_hop_range("20000-29999") == (20000, 29999)
    assert parse_hop_range(" 1024 - 1100 ") == (1024, 1100)


@pytest.mark.parametrize(
    "raw",
    ["20000", "29999-20000", "20000-20000", "1000-2000", "60000-65536", "20000-50000", "a-b", "20000:29999"],
)
def test_parse_hop_range_rejects_invalid_values(raw: str) -> None:
    with pytest.raises(HysteriaHopRangeError):
        parse_hop_range(raw)


def test_hop_range_size_limit_is_inclusive_of_30000_ports() -> None:
    assert parse_hop_range("20000-49999") == (20000, 49999)
    with pytest.raises(HysteriaHopRangeError):
        parse_hop_range("20000-50000")


def test_validate_hop_ranges_rejects_overlaps_and_reserved_ports() -> None:
    parsed = validate_hop_ranges(
        {"gecko": "20000-29999", "salamander": "30000-39999"}, reserved_udp_ports=_RESERVED
    )
    assert parsed == {"gecko": (20000, 29999), "salamander": (30000, 39999)}
    with pytest.raises(HysteriaHopRangeError, match="overlaps salamander"):
        validate_hop_ranges({"gecko": "20000-30000", "salamander": "30000-39999"}, reserved_udp_ports=_RESERVED)
    for reserved_range in ("4000-5000", "8000-9000", "8444-9000"):
        with pytest.raises(HysteriaHopRangeError, match="reserved UDP port"):
            validate_hop_ranges({"gecko": reserved_range}, reserved_udp_ports=_RESERVED)


def test_validate_hop_intervals() -> None:
    assert validate_hop_intervals(20, 60) == (20, 60)
    with pytest.raises(HysteriaHopRangeError):
        validate_hop_intervals(4, 60)
    with pytest.raises(HysteriaHopRangeError):
        validate_hop_intervals(30, 30)


def test_settings_validate_hop_ranges_and_defaults() -> None:
    settings = Settings()
    assert settings.hysteria_gecko_hop_ports == ""
    assert settings.hysteria_salamander_hop_ports == ""
    assert (settings.hysteria_hop_min_interval_s, settings.hysteria_hop_max_interval_s) == (20, 60)
    assert settings.hysteria_tls_verify is True
    assert settings.hysteria_default_obfs == "gecko"

    Settings(hysteria_gecko_hop_ports="20000-29999", hysteria_salamander_hop_ports="30000-39999")
    with pytest.raises(ValueError):
        Settings(hysteria_gecko_hop_ports="8000-9000")
    with pytest.raises(ValueError):
        Settings(hysteria_gecko_hop_ports="20000-30000", hysteria_salamander_hop_ports="25000-35000")
    with pytest.raises(ValueError):
        Settings(hysteria_hop_min_interval_s=3)
    with pytest.raises(ValueError):
        Settings(hysteria_hop_min_interval_s=60, hysteria_hop_max_interval_s=60)
    with pytest.raises(ValueError):
        Settings(hysteria_default_obfs="mimic")


# --- effective config ---------------------------------------------------


def _user() -> User:
    return User(
        telegram_id=1,
        devices_max=5,
        entitlement_status=EntitlementStatus.ACTIVE,
        grace_ends_at=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _hysteria(mode: ConnectionMode, overrides: dict | None = None) -> tuple[User, Device, Connection]:
    user = _user()
    device = Device(id=uuid4(), user_id=user.telegram_id, name="phone", status=RecordStatus.ACTIVE)
    connection = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=mode,
        variant=ConnectionVariant.V2,
        profile_name="v2-hysteria",
        custom_overrides_json=overrides or {},
        status=RecordStatus.ACTIVE,
    )
    return user, device, connection


def _build(mode: ConnectionMode, *, overrides: dict | None = None, **endpoint_kwargs) -> dict:
    user, device, connection = _hysteria(mode, overrides)
    endpoints = EndpointSet(
        transit_host="token.r1.endpoint.test",
        transit_server_name="endpoint.test",
        entry_host="entry.test",
        entry_server_name="entry.test",
        hysteria_salamander_password_transit="transit-obfs",
        hysteria_salamander_password_entry="entry-obfs",
        **endpoint_kwargs,
    )
    return build_effective_config(
        user=user, device=device, connection=connection, selected_sni=None, endpoints=endpoints
    )


def test_direct_hysteria_records_hop_range_for_its_obfs_listener_only() -> None:
    cfg = _build(
        ConnectionMode.DIRECT,
        hysteria_gecko_hop_ports="20000-29999",
        hysteria_salamander_hop_ports="30000-39999",
        hysteria_hop_min_interval_s=25,
        hysteria_hop_max_interval_s=90,
    )
    assert cfg["port"] == 443
    assert cfg["port_hopping"] == {"ports": "20000-29999", "min_interval_s": 25, "max_interval_s": 90}

    salamander = _build(
        ConnectionMode.DIRECT,
        overrides={"hysteria_obfs": "salamander"},
        hysteria_gecko_hop_ports="20000-29999",
    )
    assert salamander["port"] == 8444
    assert "port_hopping" not in salamander

    no_hop = _build(ConnectionMode.DIRECT)
    assert "port_hopping" not in no_hop


def test_chain_hysteria_never_records_port_hopping() -> None:
    cfg = _build(ConnectionMode.CHAIN, hysteria_gecko_hop_ports="20000-29999")
    assert "port_hopping" not in cfg
    assert cfg["obfs"]["type"] == "gecko"


def test_default_obfs_setting_applies_to_direct_only_and_override_wins() -> None:
    assert _build(ConnectionMode.DIRECT)["obfs"]["type"] == "gecko"
    salamander_default = _build(ConnectionMode.DIRECT, hysteria_default_obfs="salamander")
    assert salamander_default["obfs"]["type"] == "salamander"
    assert salamander_default["port"] == 8444
    override = _build(
        ConnectionMode.DIRECT, overrides={"hysteria_obfs": "gecko"}, hysteria_default_obfs="salamander"
    )
    assert override["obfs"]["type"] == "gecko"
    assert _build(ConnectionMode.CHAIN, hysteria_default_obfs="salamander")["obfs"]["type"] == "gecko"


def test_tls_verify_new_vs_legacy_behaviour() -> None:
    # New revisions: host (shard alias) != SNI no longer disables verification.
    assert _build(ConnectionMode.DIRECT)["tls"]["insecure"] is False
    # Legacy heuristic kept behind the setting for operators that need it.
    assert _build(ConnectionMode.DIRECT, hysteria_tls_verify=False)["tls"]["insecure"] is True
    # Explicit override and IP-literal server names still skip verification.
    assert _build(ConnectionMode.DIRECT, overrides={"tls_insecure": True})["tls"]["insecure"] is True
    assert _build(ConnectionMode.DIRECT, hysteria_server_name_transit="192.0.2.30")["tls"]["insecure"] is True
    # No pinning and no ECH unless explicitly configured.
    cfg = _build(ConnectionMode.DIRECT)
    assert set(cfg["tls"]) == {"server_name", "insecure", "alpn"}


# --- exports ------------------------------------------------------------


def _effective(obfs_type: str, *, hopping: bool) -> dict:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 443 if obfs_type == "gecko" else 8444,
        "sni": "endpoint.example.com",
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "obfs": {"type": obfs_type, "password": "obfs-secret"},
        "tls": {"server_name": "endpoint.example.com", "insecure": False, "alpn": ["h3"]},
        "profile": "v2-direct-quic-hysteria",
    }
    if hopping:
        effective["port_hopping"] = {"ports": "20000-29999", "min_interval_s": 20, "max_interval_s": 60}
    return effective


def test_hysteria_uri_uses_official_multiport_syntax_only_with_hopping() -> None:
    plain = export_client_config(_effective("gecko", hopping=False))
    hopping = export_client_config(_effective("gecko", hopping=True))

    assert plain.content.startswith("hysteria2://u%3Ap@t.example.com:443/?")
    assert hopping.content.startswith("hysteria2://u%3Ap@t.example.com:443,20000-29999/?")
    assert "hop" not in hopping.content.lower().split("#")[0].split("?")[1]


def test_hysteria_gecko_yaml_uses_multiport_server_and_hop_interval_window() -> None:
    plain = yaml.safe_load(export_client_config(_effective("gecko", hopping=False)).attachment_content)
    hopping = yaml.safe_load(export_client_config(_effective("gecko", hopping=True)).attachment_content)

    assert plain["server"] == "t.example.com:443"
    assert "transport" not in plain
    assert hopping["server"] == "t.example.com:443,20000-29999"
    assert hopping["transport"] == {"type": "udp", "udp": {"minHopInterval": "20s", "maxHopInterval": "60s"}}


def test_hysteria_salamander_singbox_uses_server_ports_and_fixed_hop_interval() -> None:
    plain = json.loads(export_client_config(_effective("salamander", hopping=False)).attachment_content)
    hopping = json.loads(export_client_config(_effective("salamander", hopping=True)).attachment_content)

    plain_outbound = plain["outbounds"][0]
    hop_outbound = hopping["outbounds"][0]
    assert plain_outbound["server_port"] == 8444
    assert "server_ports" not in plain_outbound
    assert "hop_interval" not in plain_outbound
    assert "server_port" not in hop_outbound
    assert hop_outbound["server_ports"] == ["20000:29999"]
    assert hop_outbound["hop_interval"] == "20s"
    assert "hop_interval_max" not in hop_outbound
    assert {key: value for key, value in hop_outbound.items() if key not in {"server_ports", "hop_interval"}} == {
        key: value for key, value in plain_outbound.items() if key != "server_port"
    }


def test_hysteria_export_without_hopping_is_unchanged_by_slice() -> None:
    effective = _effective("gecko", hopping=False)
    first = export_client_config(effective)
    effective["port_hopping"] = None
    second = export_client_config(effective)
    assert first.content == second.content
    assert first.attachment_content == second.attachment_content


def test_hysteria_export_rejects_malformed_hopping_block() -> None:
    effective = _effective("gecko", hopping=True)
    effective["port_hopping"] = {"ports": "29999-20000", "min_interval_s": 20, "max_interval_s": 60}
    with pytest.raises(ClientConfigExportError):
        export_client_config(effective)


# --- re-issue of an existing connection keeps its scheme -----------------


def _with_previous(connection: Connection, previous: dict) -> Connection:
    from tracegate.models import ConnectionRevision

    connection.revisions = [
        ConnectionRevision(
            id=uuid4(),
            connection_id=connection.id,
            slot=0,
            status=RecordStatus.REVOKED,
            effective_config_json=previous,
            created_at=datetime.now(timezone.utc),
        )
    ]
    return connection


def _new_scheme_endpoints() -> EndpointSet:
    return EndpointSet(
        transit_host="token.r1.endpoint.test",
        entry_host="entry.test",
        hysteria_gecko_hop_ports="20000-29999",
        hysteria_salamander_hop_ports="30000-39999",
        hysteria_tls_verify=True,
        hysteria_default_obfs="salamander",
    )


def test_reissue_of_legacy_hysteria_connection_keeps_obfs_but_uses_current_tls_and_hop() -> None:
    from tracegate.services.revisions import _sticky_hysteria_endpoints

    _, _, connection = _hysteria(ConnectionMode.DIRECT)
    _with_previous(
        connection,
        {"protocol": "hysteria2", "obfs": {"type": "gecko"}, "tls": {"insecure": True}, "port": 443},
    )
    sticky = _sticky_hysteria_endpoints(connection, _new_scheme_endpoints())
    assert sticky.hysteria_default_obfs == "gecko"
    assert sticky.hysteria_tls_verify is True
    assert sticky.hysteria_gecko_hop_ports == "20000-29999"
    assert sticky.hysteria_salamander_hop_ports == "30000-39999"


def test_reissue_follows_current_tls_verify_and_hop_range_but_keeps_stored_obfs() -> None:
    from tracegate.services.revisions import _sticky_hysteria_endpoints

    _, _, connection = _hysteria(ConnectionMode.DIRECT)
    _with_previous(
        connection,
        {
            "protocol": "hysteria2",
            "obfs": {"type": "salamander"},
            "tls": {"insecure": False},
            "port_hopping": {"ports": "30000-39999", "min_interval_s": 20, "max_interval_s": 60},
        },
    )
    sticky = _sticky_hysteria_endpoints(connection, _new_scheme_endpoints())
    assert sticky.hysteria_default_obfs == "salamander"
    assert sticky.hysteria_tls_verify is True
    assert sticky.hysteria_gecko_hop_ports == "20000-29999"
    assert sticky.hysteria_salamander_hop_ports == "30000-39999"


def test_explicit_obfs_override_wins_over_sticky_default() -> None:
    from tracegate.services.revisions import _sticky_hysteria_endpoints

    _, _, connection = _hysteria(ConnectionMode.DIRECT, overrides={"hysteria_obfs": "salamander"})
    _with_previous(connection, {"protocol": "hysteria2", "obfs": {"type": "gecko"}, "tls": {"insecure": True}})
    sticky = _sticky_hysteria_endpoints(connection, _new_scheme_endpoints())
    cfg = build_effective_config(
        user=_user(), device=Device(id=uuid4(), user_id=1, name="phone", status=RecordStatus.ACTIVE),
        connection=connection, selected_sni=None, endpoints=sticky,
    )
    assert cfg["obfs"]["type"] == "salamander"
    assert cfg["port_hopping"]["ports"] == "30000-39999"
    assert cfg["tls"]["insecure"] is False


def test_first_hysteria_issue_uses_current_settings() -> None:
    from tracegate.services.revisions import _sticky_hysteria_endpoints

    _, _, connection = _hysteria(ConnectionMode.DIRECT)
    connection.revisions = []
    endpoints = _new_scheme_endpoints()
    assert _sticky_hysteria_endpoints(connection, endpoints) == endpoints
