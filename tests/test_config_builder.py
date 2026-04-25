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


def test_chain_reality_enters_via_entry_and_points_to_transit() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.V2,
        profile_name="V2",
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
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            reality_public_key_transit="pub-t",
            reality_short_id_transit="sid-t",
            reality_public_key_entry="pub-e",
            reality_short_id_entry="sid-e",
        ),
    )

    assert cfg["sni"] == "google.com"
    assert cfg["profile"] == "V2-VLESS-Reality-Chain"
    assert cfg["server"] == "entry.example.com"
    assert cfg["reality"]["public_key"] == "pub-e"
    assert cfg["reality"]["short_id"] == "sid-e"
    assert cfg["xhttp"]["mode"] == "packet-up"
    assert cfg["xhttp"]["path"] == "/api/v1/update"
    assert cfg["chain"]["type"] == "entry_transit_private_relay"
    assert cfg["chain"]["entry"] == "entry.example.com"
    assert cfg["chain"]["transit"] == "transit.example.com"
    assert cfg["chain"]["carrier"] == "mieru"
    assert cfg["chain"]["optional_packet_shaping"] == "zapret2-scoped"
    assert cfg["chain"]["managed_by"] == "link-crypto"
    assert cfg["chain"]["selected_profiles"] == ["V2", "V4", "V6"]
    assert cfg["chain"]["inner_transport"] == "vless-reality-xhttp"
    assert cfg["chain"]["xray_backhaul"] is False
    assert cfg["design_constraints"]["private_interconnect"] == "mieru-zapret2"
    assert cfg["design_constraints"]["backhaul_outside_xray"] is True
    assert cfg["local_socks"]["auth"]["required"] is True
    assert cfg["local_socks"]["auth"]["mode"] == "username_password"
    assert cfg["local_socks"]["auth"]["username"].startswith("tg_v2_")
    assert cfg["local_socks"]["auth"]["password"]


def test_direct_reality_uses_transit_reality_keys() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        profile_name="V1",
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
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            reality_public_key_transit="pub-t",
            reality_short_id_transit="sid-t",
            reality_public_key_entry="pub-e",
            reality_short_id_entry="sid-e",
        ),
    )

    assert cfg["server"] == "transit.example.com"
    assert cfg["profile"] == "V1-VLESS-Reality-Direct"
    assert cfg["reality"]["public_key"] == "pub-t"
    assert cfg["reality"]["short_id"] == "sid-t"
    assert cfg["local_socks"]["auth"]["required"] is True
    assert cfg["local_socks"]["auth"]["username"].startswith("tg_v1_")


def test_local_socks_credentials_can_be_connection_scoped_overrides() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        profile_name="V1",
        custom_overrides_json={
            "local_socks_port": 18081,
            "local_socks_username": "incy-user",
            "local_socks_password": "incy-pass_01",
        },
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="splitter.wb.ru", enabled=True, is_test=False, providers=[], note=None)

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=sni,
        endpoints=EndpointSet(
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            reality_public_key_transit="pub-t",
            reality_short_id_transit="sid-t",
        ),
    )

    assert cfg["local_socks"]["listen"] == "127.0.0.1:18081"
    assert cfg["local_socks"]["auth"] == {
        "mode": "username_password",
        "required": True,
        "username": "incy-user",
        "password": "incy-pass_01",
    }


def test_local_socks_credential_override_pair_is_required_in_builder() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        profile_name="V1",
        custom_overrides_json={"local_socks_username": "incy-user"},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="splitter.wb.ru", enabled=True, is_test=False, providers=[], note=None)

    with pytest.raises(ValueError, match="provided together"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=sni,
            endpoints=EndpointSet(
                transit_host="transit.example.com",
                entry_host="entry.example.com",
                reality_public_key_transit="pub-t",
                reality_short_id_transit="sid-t",
            ),
        )


def test_default_local_socks_port_is_stable_high_port() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_GRPC_TLS,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        profile_name="V1",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg1 = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(transit_host="transit.example.com", entry_host="entry.example.com"),
    )
    cfg2 = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(transit_host="transit.example.com", entry_host="entry.example.com"),
    )

    assert cfg1["local_socks"]["listen"] == cfg2["local_socks"]["listen"]
    assert cfg1["local_socks"]["listen"].startswith("127.0.0.1:")
    port = int(cfg1["local_socks"]["listen"].rsplit(":", 1)[-1])
    assert 20000 <= port < 60000
    assert port != 1080


def test_hysteria_uses_fixed_port_443() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V3,
        profile_name="V3",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(transit_host="transit.example.com", entry_host="entry.example.com"),
    )

    assert cfg["port"] == 443
    assert cfg["profile"] == "V3-Hysteria2-QUIC-Direct"
    assert cfg["local_socks"]["auth"]["required"] is True
    assert cfg["local_socks"]["auth"]["username"].startswith("tg_v3_")


def test_hysteria_rejects_non_loopback_local_socks_listener() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V3,
        profile_name="V3",
        custom_overrides_json={"socks_listen": "0.0.0.0:1080"},
        status=RecordStatus.ACTIVE,
    )

    with pytest.raises(ValueError, match="local_socks.listen must be bound to loopback"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=None,
            endpoints=EndpointSet(transit_host="transit.example.com", entry_host="entry.example.com"),
        )


def test_hysteria_rejects_non_socks_client_mode() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V3,
        profile_name="V3",
        custom_overrides_json={"client_mode": "tun"},
        status=RecordStatus.ACTIVE,
    )

    with pytest.raises(ValueError, match="local SOCKS5 auth is required"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=None,
            endpoints=EndpointSet(transit_host="transit.example.com", entry_host="entry.example.com"),
        )


def test_hysteria_chain_v4_enters_via_entry_and_marks_backhaul() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.V4,
        profile_name="V4",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(transit_host="myheartraces.space", entry_host="entry.myheartraces.space"),
    )

    assert cfg["protocol"] == "hysteria2"
    assert cfg["profile"] == "V4-Hysteria2-QUIC-Chain"
    assert cfg["server"] == "entry.myheartraces.space"
    assert cfg["sni"] == "entry.myheartraces.space"
    assert cfg["auth"]["type"] == "userpass"
    assert cfg["auth"]["username"].startswith("v4_1_")
    assert " " not in cfg["auth"]["username"]
    assert cfg["auth"]["token"].startswith(cfg["auth"]["username"] + ":")
    assert cfg["chain"]["type"] == "entry_transit_private_relay"
    assert cfg["chain"]["carrier"] == "mieru"
    assert cfg["chain"]["optional_packet_shaping"] == "zapret2-scoped"
    assert cfg["chain"]["managed_by"] == "link-crypto"
    assert cfg["chain"]["selected_profiles"] == ["V2", "V4", "V6"]
    assert cfg["chain"]["inner_transport"] == "hysteria2-quic"
    assert cfg["chain"]["xray_backhaul"] is False
    assert cfg["chain"]["transit"] == "myheartraces.space"
    assert cfg["design_constraints"]["entry_role_required"] is True
    assert cfg["design_constraints"]["private_interconnect"] == "mieru-zapret2"
    assert cfg["design_constraints"]["backhaul_outside_xray"] is True
    assert cfg["design_constraints"]["udp_over_private_relay"] is True


def test_hysteria_can_emit_token_auth_payload_for_future_runtime() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V3,
        profile_name="V3",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            hysteria_auth_mode="token",
        ),
    )

    assert cfg["auth"]["type"] == "token"
    assert cfg["auth"]["client_id"].startswith("v3_1_")
    assert cfg["auth"]["token"].startswith(cfg["auth"]["client_id"] + "-")
    assert ":" not in cfg["auth"]["token"]


def test_hysteria_direct_uses_transit_ech_hints() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V3,
        profile_name="V3",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            hysteria_ech_config_list_transit="transit-ech-config",
            hysteria_ech_force_query_transit="full",
        ),
    )

    assert cfg["tls"] == {
        "server_name": "transit.example.com",
        "insecure": False,
        "alpn": ["h3"],
        "ech_config_list": "transit-ech-config",
        "ech_force_query": "full",
    }


def test_hysteria_chain_uses_entry_ech_hints() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.V4,
        profile_name="V4",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            hysteria_ech_config_list_entry="entry-ech-config",
            hysteria_ech_force_query_entry="half",
        ),
    )

    assert cfg["tls"] == {
        "server_name": "entry.example.com",
        "insecure": False,
        "alpn": ["h3"],
        "ech_config_list": "entry-ech-config",
        "ech_force_query": "half",
    }


def test_ws_tls_chain_is_rejected() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_WS_TLS,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.V2,
        profile_name="V2",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    with pytest.raises(ValueError, match="VLESS TLS compatibility profiles support only V1 direct"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=None,
            endpoints=EndpointSet(
                transit_host="transit.example.com",
                entry_host="entry.example.com",
            ),
        )


def test_ws_tls_direct_ignores_proxy_host_and_uses_transit_host() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_WS_TLS,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        profile_name="V1",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            transit_proxy_host="proxy-transit.example.com",
        ),
    )

    assert cfg["server"] == "transit.example.com"
    assert cfg["profile"] == "V1-VLESS-WS-TLS-Direct"
    assert cfg["sni"] == "transit.example.com"
    assert cfg["ws"]["host"] == "transit.example.com"


def test_ws_tls_direct_uses_transit_host_without_proxy() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_WS_TLS,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        profile_name="V1",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="myheartraces.space",
            entry_host="entry.myheartraces.space",
        ),
    )

    assert cfg["server"] == "myheartraces.space"
    assert cfg["profile"] == "V1-VLESS-WS-TLS-Direct"
    assert cfg["sni"] == "myheartraces.space"
    assert cfg["ws"]["host"] == "myheartraces.space"


def test_grpc_tls_direct_uses_transit_host_and_service_name() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_GRPC_TLS,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        profile_name="V1",
        custom_overrides_json={"grpc_service_name": "tracegate.custom.Edge"},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            vless_grpc_service_name="tracegate.v1.Edge",
        ),
    )

    assert cfg["protocol"] == "vless"
    assert cfg["transport"] == "grpc_tls"
    assert cfg["profile"] == "V1-VLESS-gRPC-TLS-Direct"
    assert cfg["server"] == "transit.example.com"
    assert cfg["sni"] == "transit.example.com"
    assert cfg["grpc"] == {
        "service_name": "tracegate.custom.Edge",
        "authority": "transit.example.com",
    }
    assert cfg["local_socks"]["auth"]["required"] is True


def test_shadowsocks2022_shadowtls_direct_v5_config_requires_local_socks_auth() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V5,
        profile_name="V5",
        custom_overrides_json={"local_socks_port": 18081},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=2, fqdn="www.microsoft.com", enabled=True, is_test=False, providers=[], note=None)

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=sni,
        endpoints=EndpointSet(transit_host="transit.example.com", entry_host="entry.example.com"),
    )

    assert cfg["protocol"] == "shadowsocks2022"
    assert cfg["transport"] == "shadowtls_v3"
    assert cfg["profile"] == "V5-Shadowsocks2022-ShadowTLS-Direct"
    assert cfg["server"] == "transit.example.com"
    assert cfg["sni"] == "www.microsoft.com"
    assert cfg["shadowtls"]["version"] == 3
    assert cfg["password"]
    assert cfg["local_socks"]["listen"] == "127.0.0.1:18081"
    assert cfg["local_socks"]["auth"]["required"] is True
    assert cfg["local_socks"]["auth"]["username"].startswith("tg_v5_")


def test_shadowsocks2022_shadowtls_chain_v6_marks_private_interconnect() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.V6,
        profile_name="V6",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            shadowtls_server_name_entry="cdn.example.com",
        ),
    )

    assert cfg["profile"] == "V6-Shadowsocks2022-ShadowTLS-Chain"
    assert cfg["server"] == "entry.example.com"
    assert cfg["sni"] == "cdn.example.com"
    assert cfg["chain"]["type"] == "entry_transit_private_relay"
    assert cfg["chain"]["carrier"] == "mieru"
    assert cfg["chain"]["preferred_outer"] == "mieru"
    assert cfg["chain"]["optional_packet_shaping"] == "zapret2-scoped"
    assert cfg["chain"]["managed_by"] == "link-crypto"
    assert cfg["chain"]["selected_profiles"] == ["V2", "V4", "V6"]
    assert cfg["chain"]["inner_transport"] == "shadowsocks2022-shadowtls-v3"
    assert cfg["chain"]["xray_backhaul"] is False
    assert cfg["design_constraints"]["private_interconnect"] == "mieru-zapret2"
    assert cfg["local_socks"]["auth"]["username"].startswith("tg_v6_")


def test_wireguard_wstunnel_v7_config_requires_local_socks_auth() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.WIREGUARD_WSTUNNEL,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V7,
        profile_name="V7",
        custom_overrides_json={
            "wireguard_private_key": "client-private",
            "wireguard_public_key": "client-public",
            "wireguard_preshared_key": "wg-psk",
            "wireguard_address": "10.70.0.2/32",
            "wstunnel_path": "/cdn/ws",
        },
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="transit.example.com",
            entry_host="entry.example.com",
            transit_proxy_host="edge.example.com",
            wireguard_server_public_key="server-public",
        ),
    )

    assert cfg["protocol"] == "wireguard"
    assert cfg["transport"] == "wstunnel"
    assert cfg["profile"] == "V7-WireGuard-WSTunnel-Direct"
    assert cfg["server"] == "edge.example.com"
    assert cfg["wstunnel"]["url"] == "wss://edge.example.com:443/cdn/ws"
    assert cfg["wireguard"]["private_key"] == "client-private"
    assert cfg["wireguard"]["public_key"] == "client-public"
    assert cfg["wireguard"]["preshared_key"] == "wg-psk"
    assert cfg["wireguard"]["server_public_key"] == "server-public"
    assert cfg["wireguard"]["address"] == "10.70.0.2/32"
    assert cfg["local_socks"]["auth"]["required"] is True
    assert cfg["local_socks"]["auth"]["username"].startswith("tg_v7_")


def test_wireguard_rejects_non_loopback_local_udp_listener() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.WIREGUARD_WSTUNNEL,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V7,
        profile_name="V7",
        custom_overrides_json={
            "wireguard_private_key": "client-private",
            "wireguard_public_key": "client-public",
            "wireguard_address": "10.70.0.2/32",
            "local_udp_listen": "0.0.0.0:51820",
        },
        status=RecordStatus.ACTIVE,
    )

    with pytest.raises(ValueError, match="wstunnel.local_udp_listen must be bound to loopback"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=None,
            endpoints=EndpointSet(
                transit_host="transit.example.com",
                entry_host="entry.example.com",
                wireguard_server_public_key="server-public",
            ),
        )


def test_wireguard_rejects_non_absolute_wstunnel_path() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.WIREGUARD_WSTUNNEL,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V7,
        profile_name="V7",
        custom_overrides_json={
            "wireguard_private_key": "client-private",
            "wireguard_public_key": "client-public",
            "wireguard_address": "10.70.0.2/32",
            "wstunnel_path": "cdn/ws",
        },
        status=RecordStatus.ACTIVE,
    )

    with pytest.raises(ValueError, match="wstunnel.path must be an absolute HTTP path"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=None,
            endpoints=EndpointSet(
                transit_host="transit.example.com",
                entry_host="entry.example.com",
                wireguard_server_public_key="server-public",
            ),
        )


def test_wireguard_rejects_unsafe_mtu_override() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.WIREGUARD_WSTUNNEL,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V7,
        profile_name="V7",
        custom_overrides_json={
            "wireguard_private_key": "client-private",
            "wireguard_public_key": "client-public",
            "wireguard_address": "10.70.0.2/32",
            "mtu": 9000,
        },
        status=RecordStatus.ACTIVE,
    )

    with pytest.raises(ValueError, match="wireguard.mtu must be in 1200..1420"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=None,
            endpoints=EndpointSet(
                transit_host="transit.example.com",
                entry_host="entry.example.com",
                wireguard_server_public_key="server-public",
            ),
        )
