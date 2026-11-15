from datetime import datetime, timezone
from uuid import uuid4

import pytest

from tracegate.constants import (
    TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT,
    TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT,
    TRACEGATE_PUBLIC_UDP_PORT,
)
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
        variant=ConnectionVariant.V1,
        profile_name="v1-chain-reality-vless",
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
    assert cfg["profile"] == "v1-chain-reality-vless"
    assert cfg["server"] == "entry.example.com"
    assert cfg["reality"]["public_key"] == "pub-e"
    assert cfg["reality"]["short_id"] == "sid-e"
    assert cfg["transport"] == "reality_raw"
    assert cfg["flow"] == "xtls-rprx-vision"
    assert cfg["chain"]["type"] == "entry_transit_private_relay"
    assert cfg["chain"]["entry"] == "entry.example.com"
    assert cfg["chain"]["transit"] == "transit.example.com"
    assert cfg["chain"]["carrier"] == "vless-reality-raw"
    assert cfg["chain"]["optional_packet_shaping"] is None
    assert cfg["chain"]["managed_by"] == "xray"
    assert cfg["chain"]["selected_profiles"] == ["V1", "V3"]
    assert cfg["chain"]["inner_transport"] == "vless-reality-raw"
    assert cfg["chain"]["xray_backhaul"] is True
    assert cfg["design_constraints"]["private_interconnect"] == "vless-reality-raw"
    assert cfg["design_constraints"]["backhaul_outside_xray"] is False
    assert cfg["local_socks"]["auth"]["required"] is True
    assert cfg["local_socks"]["auth"]["mode"] == "username_password"
    assert cfg["local_socks"]["auth"]["username"].startswith("tg_v1_")
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
        profile_name="v1-direct-reality-vless",
        custom_overrides_json={"local_socks_port": 1080},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="splitter.front-m.example.net", enabled=True, is_test=False, providers=[], note=None)

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
    assert cfg["profile"] == "v1-direct-reality-vless"
    assert cfg["reality"]["public_key"] == "pub-t"
    assert cfg["reality"]["short_id"] == "sid-t"
    assert cfg["local_socks"]["auth"]["required"] is True
    assert cfg["local_socks"]["auth"]["username"].startswith("tg_v1_")


def test_vless_encryption_profile_is_rejected() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V0,
        profile_name="v0-encrypted-reality-vless",
        custom_overrides_json={"vless_encryption": True},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="front-g.example.net", enabled=True, is_test=False, providers=[], note=None)

    with pytest.raises(ValueError, match="Encrypted VLESS was removed"):
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


def test_vless_encryption_is_opt_in_for_reality_profiles() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        profile_name="v1-direct-reality-vless",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="front-g.example.net", enabled=True, is_test=False, providers=[], note=None)

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
            vless_encryption_enabled=True,
            vless_encryption="mlkem768x25519plus.native.0rtt.CLIENT",
            vless_encryption_reality_sni="passport.front-g.example.net",
        ),
    )

    assert cfg["sni"] == "front-g.example.net"
    assert "vless_encryption" not in cfg


def test_v0_reality_requires_vless_encryption_override() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V0,
        profile_name="v0-encrypted-reality-vless",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="front-g.example.net", enabled=True, is_test=False, providers=[], note=None)

    with pytest.raises(ValueError, match="Encrypted VLESS was removed"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=sni,
            endpoints=EndpointSet(transit_host="transit.example.com", entry_host="entry.example.com"),
        )


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
        profile_name="v1-direct-reality-vless",
        custom_overrides_json={
            "local_socks_port": 18081,
            "local_socks_username": "incy-user",
            "local_socks_password": "incy-pass_01",
        },
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="splitter.front-m.example.net", enabled=True, is_test=False, providers=[], note=None)

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
        profile_name="v1-direct-reality-vless",
        custom_overrides_json={"local_socks_username": "incy-user"},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="splitter.front-m.example.net", enabled=True, is_test=False, providers=[], note=None)

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
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        profile_name="v1-direct-reality-vless",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="google.com", enabled=True, is_test=False, providers=[], note=None)

    cfg1 = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=sni,
        endpoints=EndpointSet(
            transit_host="token.r1.endpoint.example",
            transit_server_name="endpoint.example",
            entry_host="entry.example.com",
        ),
    )
    cfg2 = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=sni,
        endpoints=EndpointSet(
            transit_host="token.r1.endpoint.example",
            transit_server_name="endpoint.example",
            entry_host="entry.example.com",
        ),
    )

    assert cfg1["local_socks"]["listen"] == cfg2["local_socks"]["listen"]
    assert cfg1["local_socks"]["listen"].startswith("127.0.0.1:")
    port = int(cfg1["local_socks"]["listen"].rsplit(":", 1)[-1])
    assert 20000 <= port < 60000
    assert port != 1080


def test_hysteria_uses_fixed_public_udp_port_and_gecko() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
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

    assert cfg["port"] == TRACEGATE_PUBLIC_UDP_PORT
    assert cfg["profile"] == "v2-direct-quic-hysteria"
    assert cfg["up_mbps"] == 100
    assert cfg["down_mbps"] == 100
    assert cfg["rate_limit"]["enabled"] is False
    assert cfg["tls"]["insecure"] is False
    assert cfg["obfs"] == {
        "type": "gecko",
        "password": "REPLACE_HYSTERIA2_GECKO_PASSWORD",
        "required": True,
        "min_packet_size": 512,
        "max_packet_size": 1200,
    }
    assert cfg["client_requirements"] == {
        "hysteria": ">=2.9.2",
        "sing_box": ">=1.14.0",
        "reason": "gecko-obfs",
    }
    assert cfg["design_constraints"]["fixed_port_udp"] == TRACEGATE_PUBLIC_UDP_PORT
    assert cfg["design_constraints"]["gecko_required"] is True
    assert cfg["design_constraints"]["masquerade_required"] is True
    assert cfg["design_constraints"]["hygiene_required"] is True
    assert cfg["design_constraints"]["server_sni_guard"] == "dns-san"
    assert cfg["design_constraints"]["auth_backend"] == "http-loopback"
    assert cfg["design_constraints"]["anonymous_rejected"] is True
    assert cfg["masquerade"] == {
        "type": "file",
        "mode": "server_file_decoy",
        "required": True,
        "serves_decoy": True,
    }
    assert cfg["hygiene"]["required"] is True
    assert cfg["hygiene"]["required_layers"] == [
        "hysteria2",
        "gecko",
        "file-masquerade",
        "dns-san-sni-guard",
        "http-auth-loopback",
        "reject-anonymous",
        "traffic-stats-loopback",
        "udp-enabled",
        "quic-pmtu",
        "udp-idle-timeout",
        "sniff",
    ]
    assert cfg["hygiene"]["server"]["sni_guard"] == "dns-san"
    assert cfg["hygiene"]["server"]["auth_backend"] == "http-loopback"
    assert cfg["hygiene"]["server"]["masquerade"] == "file-decoy"
    assert cfg["hygiene"]["udp"]["public_port"] == TRACEGATE_PUBLIC_UDP_PORT
    assert cfg["hygiene"]["udp"]["anti_replay"] is True
    assert cfg["hygiene"]["udp"]["anti_amplification"] is True
    assert cfg["hygiene"]["udp"]["mtu"] == {"mode": "clamp", "max_packet_size": 1252}
    # Direct Hysteria terminates on Endpoint, where TCP/8443 is a declared
    # public listener; only UDP/8443 stays dropped there.
    assert cfg["hygiene"]["forbidden_public_ports"] == [
        {"protocol": "udp", "port": TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, "action": "drop"},
    ]
    assert TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT not in {
        row["port"] for row in cfg["hygiene"]["forbidden_public_ports"] if row["protocol"] == "tcp"
    }
    assert cfg["local_socks"]["auth"]["required"] is True
    assert cfg["local_socks"]["auth"]["username"].startswith("tg_v2_")


def test_hysteria_direct_can_select_salamander_on_independent_listener() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
        custom_overrides_json={"hysteria_obfs": "salamander"},
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
            hysteria_salamander_udp_port=8444,
            hysteria_salamander_password_transit="shared-obfs-secret",
        ),
    )

    assert cfg["port"] == 8444
    assert cfg["obfs"] == {
        "type": "salamander",
        "password": "shared-obfs-secret",
        "required": True,
    }
    assert cfg["client_requirements"]["reason"] == "salamander-obfs"
    assert cfg["design_constraints"]["gecko_required"] is False
    assert cfg["design_constraints"]["salamander_required"] is True
    assert cfg["hygiene"]["required_layers"][1] == "salamander"


def test_hysteria_direct_uses_endpoint_password_and_ignores_retired_entry_password() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
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
            hysteria_salamander_password_entry="entry-obfs-secret",
            hysteria_salamander_password_transit="transit-obfs-secret",
        ),
    )

    assert cfg["server"] == "transit.example.com"
    assert cfg["obfs"]["password"] == "transit-obfs-secret"
    assert cfg["chain"] is None


@pytest.mark.parametrize("variant", [ConnectionVariant.V2, ConnectionVariant.V4])
def test_hysteria_chain_is_never_built_after_retirement(variant) -> None:
    # Chain Hysteria (Hysteria on Entry) was retired in Tracegate 4.1.2.
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.CHAIN,
        variant=variant,
        profile_name="v2-chain-quic-hysteria",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    with pytest.raises(ValueError, match="retired in Tracegate 4.1.2"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=None,
            endpoints=EndpointSet(
                transit_host="transit.example.com",
                entry_host="entry.example.com",
                hysteria_salamander_password_entry="entry-obfs-secret",
            ),
        )


def test_hysteria_ip_endpoint_defaults_to_insecure_tls() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(transit_host="198.51.100.105", entry_host="entry.example.com"),
    )

    assert cfg["sni"] == "198.51.100.105"
    assert cfg["tls"]["insecure"] is True


def test_hysteria_rejects_non_loopback_local_socks_listener() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
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
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
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


def test_hysteria_can_emit_token_auth_payload_for_future_runtime() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
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
    assert cfg["auth"]["client_id"].startswith("v2_1_")
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
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
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


def test_hysteria_direct_connects_to_endpoint_shard_with_canonical_tls_name() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="token.r1.endpoint.example",
            transit_server_name="endpoint.example",
            entry_host="entry.example",
            hysteria_salamander_password_transit="salamander-secret",
            # Legacy (pre-slice-4) heuristic: insecure whenever host != SNI.
            hysteria_tls_verify=False,
        ),
    )

    assert cfg["server"] == "token.r1.endpoint.example"
    assert cfg["sni"] == "endpoint.example"
    assert cfg["tls"]["server_name"] == "endpoint.example"
    assert cfg["tls"]["insecure"] is True


def test_hysteria_direct_allows_operator_sni_override() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(
            transit_host="token.r1.endpoint.example",
            transit_server_name="endpoint.example",
            entry_host="entry.example",
            hysteria_server_name_transit="hysteria-front.ru",
            hysteria_salamander_password_transit="salamander-secret",
            # Legacy (pre-slice-4) heuristic: insecure whenever host != SNI.
            hysteria_tls_verify=False,
        ),
    )

    assert cfg["server"] == "token.r1.endpoint.example"
    assert cfg["sni"] == "hysteria-front.ru"
    assert cfg["tls"]["server_name"] == "hysteria-front.ru"
    assert cfg["tls"]["insecure"] is True


@pytest.mark.parametrize(
    ("protocol", "mode", "variant", "profile_name"),
    [
        (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0, "v0-ws-vless"),
        (ConnectionProtocol.VLESS_GRPC_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0, "v0-grpc-vless"),
        (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.CHAIN, ConnectionVariant.V5, "v5-entry-ws"),
        (ConnectionProtocol.VLESS_GRPC_TLS, ConnectionMode.CHAIN, ConnectionVariant.V5, "v5-universal-entry"),
        (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.CHAIN, ConnectionVariant.V0, "v0-ws-vless"),
    ],
)
def test_retired_vless_ws_grpc_profiles_are_never_built(protocol, mode, variant, profile_name) -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=protocol,
        mode=mode,
        variant=variant,
        profile_name=profile_name,
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    with pytest.raises(ValueError, match="retired in Tracegate 4.1.1"):
        build_effective_config(
            user=user,
            device=device,
            connection=conn,
            selected_sni=SniCatalogEntry(id=1, fqdn="google.com", enabled=True, is_test=False, providers=[], note=None),
            endpoints=EndpointSet(
                transit_host="transit.example.com",
                entry_host="entry.example.com",
                transit_proxy_host="proxy.example.com",
                entry_proxy_host="entry-proxy.example.com",
            ),
        )
