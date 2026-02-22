from datetime import datetime, timezone
from uuid import uuid4

import pytest

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, EntitlementStatus, RecordStatus
from tracegate.models import Connection, Device, User
from tracegate.services.config_builder import EndpointSet, build_effective_config
from tracegate.services.sni_catalog import SniCatalogEntry


def _user() -> User:
    return User(
        telegram_id=1,
        devices_max=5,
        entitlement_status=EntitlementStatus.ACTIVE,
        grace_ends_at=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _device(user_id):
    return Device(id=uuid4(), user_id=user_id, name="phone", status=RecordStatus.ACTIVE)


def test_chain_reality_enters_via_vps_e_and_points_to_vps_t_transit() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.B2,
        profile_name="B2",
        custom_overrides_json={"local_socks_port": 1080},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="google.com", enabled=True, is_test=False, providers=[], note=None)

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=sni,
        endpoints=EndpointSet(
            vps_t_host="vps-t.example.com",
            vps_e_host="vps-e.example.com",
            reality_public_key_vps_t="pub-t",
            reality_short_id_vps_t="sid-t",
            reality_public_key_vps_e="pub-e",
            reality_short_id_vps_e="sid-e",
        ),
    )

    assert cfg["sni"] == "google.com"
    assert cfg["server"] == "vps-e.example.com"
    assert cfg["reality"]["public_key"] == "pub-e"
    assert cfg["reality"]["short_id"] == "sid-e"
    assert cfg["xhttp"]["mode"] == "packet-up"
    assert cfg["xhttp"]["path"] == "/api/v1/update"
    assert cfg["chain"]["type"] == "tcp_forward"
    assert cfg["chain"]["upstream"] == "vps-t.example.com"
    assert cfg["chain"]["port"] == 443


def test_direct_reality_uses_vps_t_reality_keys() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.B1,
        profile_name="B1",
        custom_overrides_json={"local_socks_port": 1080},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="splitter.wb.ru", enabled=True, is_test=False, providers=[], note=None)

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=sni,
        endpoints=EndpointSet(
            vps_t_host="vps-t.example.com",
            vps_e_host="vps-e.example.com",
            reality_public_key_vps_t="pub-t",
            reality_short_id_vps_t="sid-t",
            reality_public_key_vps_e="pub-e",
            reality_short_id_vps_e="sid-e",
        ),
    )

    assert cfg["server"] == "vps-t.example.com"
    assert cfg["reality"]["public_key"] == "pub-t"
    assert cfg["reality"]["short_id"] == "sid-t"


def test_wireguard_uses_fixed_port_51820() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.WIREGUARD,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.B5,
        profile_name="B5",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(vps_t_host="vps-t.example.com", vps_e_host="vps-e.example.com", wireguard_server_public_key="wgpub"),
    )

    assert cfg["endpoint"].endswith(":51820")


def test_hysteria_chain_b4_enters_via_vps_e_and_marks_backhaul() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.B4,
        profile_name="B4",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(vps_t_host="myheartraces.space", vps_e_host="entry.myheartraces.space"),
    )

    assert cfg["protocol"] == "hysteria2"
    assert cfg["server"] == "entry.myheartraces.space"
    assert cfg["sni"] == "entry.myheartraces.space"
    assert cfg["auth"]["username"].startswith("b4_1_")
    assert " " not in cfg["auth"]["username"]
    assert cfg["chain"]["type"] == "hysteria_entry_xray_backhaul"
    assert cfg["chain"]["transit"] == "myheartraces.space"
    assert cfg["design_constraints"]["entry_via_vps_e"] is True


def test_ws_tls_chain_is_rejected() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_WS_TLS,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.B2,
        profile_name="B2",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    with pytest.raises(ValueError, match="VLESS\\+WS\\+TLS supports only B1 direct"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=None,
            endpoints=EndpointSet(
                vps_t_host="vps-t.example.com",
                vps_e_host="vps-e.example.com",
            ),
        )


def test_ws_tls_direct_ignores_proxy_host_and_uses_vps_t_host() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_WS_TLS,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.B1,
        profile_name="B1",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            vps_t_host="vps-t.example.com",
            vps_e_host="vps-e.example.com",
            vps_t_proxy_host="proxy-vps-t.example.com",
        ),
    )

    assert cfg["server"] == "vps-t.example.com"
    assert cfg["sni"] == "vps-t.example.com"
    assert cfg["ws"]["host"] == "vps-t.example.com"


def test_ws_tls_direct_uses_vps_t_host_without_proxy() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_WS_TLS,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.B1,
        profile_name="B1",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            vps_t_host="myheartraces.space",
            vps_e_host="entry.myheartraces.space",
        ),
    )

    assert cfg["server"] == "myheartraces.space"
    assert cfg["sni"] == "myheartraces.space"
    assert cfg["ws"]["host"] == "myheartraces.space"
