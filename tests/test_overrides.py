import pytest

from tracegate.enums import ConnectionProtocol
from tracegate.services.overrides import OverrideValidationError, validate_overrides


def test_vless_overrides_whitelist() -> None:
    result = validate_overrides(
        ConnectionProtocol.VLESS_REALITY,
        {
            "camouflage_sni_id": 1,
            "connect_timeout_ms": 5000,
            "local_socks_port": 1080,
        },
    )
    assert result["camouflage_sni_id"] == 1


def test_vless_port_override_rejected() -> None:
    with pytest.raises(OverrideValidationError):
        validate_overrides(ConnectionProtocol.VLESS_REALITY, {"port": 8443})


def test_local_socks_port_override_must_be_valid_user_port() -> None:
    with pytest.raises(OverrideValidationError, match="local_socks_port"):
        validate_overrides(ConnectionProtocol.VLESS_REALITY, {"local_socks_port": 80})
    with pytest.raises(OverrideValidationError, match="port number"):
        validate_overrides(ConnectionProtocol.VLESS_REALITY, {"local_socks_port": "127.0.0.1:1080"})


@pytest.mark.parametrize(
    "protocol",
    [
        ConnectionProtocol.VLESS_REALITY,
        ConnectionProtocol.VLESS_WS_TLS,
        ConnectionProtocol.VLESS_GRPC_TLS,
        ConnectionProtocol.HYSTERIA2,
        ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        ConnectionProtocol.WIREGUARD_WSTUNNEL,
    ],
)
def test_local_socks_credential_overrides_are_allowed_only_as_required_pair(protocol: ConnectionProtocol) -> None:
    result = validate_overrides(
        protocol,
        {"local_socks_username": "incy-user", "local_socks_password": "incy-pass_01"},
    )
    assert result["local_socks_username"] == "incy-user"
    assert result["local_socks_password"] == "incy-pass_01"

    with pytest.raises(OverrideValidationError, match="provided together"):
        validate_overrides(protocol, {"local_socks_username": "incy-user"})

    with pytest.raises(OverrideValidationError, match="must not be empty"):
        validate_overrides(protocol, {"local_socks_username": "incy-user", "local_socks_password": ""})

    with pytest.raises(OverrideValidationError, match="unsupported characters"):
        validate_overrides(protocol, {"local_socks_username": "incy user", "local_socks_password": "incy-pass"})


def test_vless_grpc_overrides_whitelist() -> None:
    result = validate_overrides(
        ConnectionProtocol.VLESS_GRPC_TLS,
        {"grpc_service_name": "tracegate.v1.Edge", "tls_server_name": "edge.example.com"},
    )

    assert result["grpc_service_name"] == "tracegate.v1.Edge"


def test_hysteria_security_override_rejected() -> None:
    with pytest.raises(OverrideValidationError):
        validate_overrides(ConnectionProtocol.HYSTERIA2, {"traffic_stats_secret": "bad"})


def test_hysteria_local_listener_overrides_must_be_loopback() -> None:
    result = validate_overrides(ConnectionProtocol.HYSTERIA2, {"socks_listen": "localhost:18080"})
    assert result["socks_listen"] == "localhost:18080"

    with pytest.raises(OverrideValidationError, match="loopback"):
        validate_overrides(ConnectionProtocol.HYSTERIA2, {"socks_listen": "0.0.0.0:1080"})


def test_hysteria_client_mode_must_keep_authenticated_socks() -> None:
    result = validate_overrides(ConnectionProtocol.HYSTERIA2, {"client_mode": "socks"})
    assert result["client_mode"] == "socks"

    with pytest.raises(OverrideValidationError, match="local SOCKS5 auth is required"):
        validate_overrides(ConnectionProtocol.HYSTERIA2, {"client_mode": "tun"})


def test_shadowsocks2022_shadowtls_overrides_whitelist() -> None:
    result = validate_overrides(
        ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        {"method": "2022-blake3-aes-128-gcm", "shadowtls_server_name": "cdn.example.com"},
    )
    assert result["shadowtls_server_name"] == "cdn.example.com"


def test_wireguard_wstunnel_port_override_rejected() -> None:
    with pytest.raises(OverrideValidationError):
        validate_overrides(ConnectionProtocol.WIREGUARD_WSTUNNEL, {"wstunnel_port": 8443})


def test_wireguard_wstunnel_peer_key_overrides_are_allowed() -> None:
    result = validate_overrides(
        ConnectionProtocol.WIREGUARD_WSTUNNEL,
        {"wireguard_public_key": "client-public", "wireguard_preshared_key": "wg-psk"},
    )

    assert result["wireguard_public_key"] == "client-public"


def test_wireguard_local_udp_listener_override_must_be_loopback() -> None:
    result = validate_overrides(ConnectionProtocol.WIREGUARD_WSTUNNEL, {"local_udp_listen": "127.0.0.1:51820"})
    assert result["local_udp_listen"] == "127.0.0.1:51820"

    with pytest.raises(OverrideValidationError, match="loopback"):
        validate_overrides(ConnectionProtocol.WIREGUARD_WSTUNNEL, {"local_udp_listen": "0.0.0.0:51820"})


def test_wireguard_wstunnel_path_override_must_be_absolute_http_path() -> None:
    result = validate_overrides(ConnectionProtocol.WIREGUARD_WSTUNNEL, {"wstunnel_path": "/cdn/ws"})
    assert result["wstunnel_path"] == "/cdn/ws"

    with pytest.raises(OverrideValidationError, match="absolute HTTP path"):
        validate_overrides(ConnectionProtocol.WIREGUARD_WSTUNNEL, {"wstunnel_path": "cdn/ws"})

    with pytest.raises(OverrideValidationError, match="clean HTTP path"):
        validate_overrides(ConnectionProtocol.WIREGUARD_WSTUNNEL, {"wstunnel_path": "/cdn ws"})


def test_wireguard_wstunnel_stability_overrides_are_bounded() -> None:
    result = validate_overrides(ConnectionProtocol.WIREGUARD_WSTUNNEL, {"mtu": 1280, "persistent_keepalive": 25})
    assert result["mtu"] == 1280
    assert result["persistent_keepalive"] == 25

    with pytest.raises(OverrideValidationError, match="mtu must be in 1200..1420"):
        validate_overrides(ConnectionProtocol.WIREGUARD_WSTUNNEL, {"mtu": 9000})

    with pytest.raises(OverrideValidationError, match="persistent_keepalive must be in 0..60"):
        validate_overrides(ConnectionProtocol.WIREGUARD_WSTUNNEL, {"persistent_keepalive": 300})
