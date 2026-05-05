import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest

from tracegate.client_export.v2rayn import V2RayNExportError, export_v2rayn


def _extra_content(out, title: str) -> str:
    by_title = dict(out.extra_messages)
    assert title in by_title
    return by_title[title]


def test_export_vless_reality_uri() -> None:
    effective = {
        "protocol": "vless",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "google.com",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "xhttp": {"mode": "auto", "path": "/api/v1/update"},
        "profile": "V1-VLESS-Reality-Direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@t.example.com:443?")
    assert "security=reality" in out.content
    assert "type=xhttp" in out.content
    assert "mode=auto" in out.content
    assert "path=/api/v1/update" in out.content
    assert "sni=google.com" in out.content
    assert "pbk=PUBKEY" in out.content
    assert "sid=abcd" in out.content
    assert out.attachment_filename == "v1-vless-reality-direct.xray.json"
    assert out.attachment_mime == "application/json"
    local_socks = _extra_content(out, "Local SOCKS5 credentials")
    assert "Host: 127.0.0.1" in local_socks
    assert "Username: tg_" in local_socks
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert attachment["inbounds"][0]["settings"]["auth"] == "password"
    assert attachment["inbounds"][0]["settings"]["accounts"][0]["user"].startswith("tg_")
    assert attachment["inbounds"][0]["settings"]["accounts"][0]["pass"]
    assert attachment["outbounds"][0]["streamSettings"]["network"] == "xhttp"
    assert attachment["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] == "google.com"


def test_export_hysteria2_uri() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 4443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "obfs": {"type": "salamander", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert out.content.startswith("hysteria2://u:p@t.example.com:4443/")
    assert "insecure=0" not in out.content
    assert "obfs=salamander" in out.content
    assert "obfs-password=obfs-secret" in out.content
    assert "alpn=" not in out.content
    assert "sni=t.example.com" in out.content
    assert "peer=t.example.com" not in out.content
    assert "#V3-Hysteria2-QUIC-Direct" in out.content
    assert out.alternate_title is None
    assert out.alternate_content is None
    assert "Local SOCKS5 credentials" in dict(out.extra_messages)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert out.attachment_filename == "v3-hysteria2-quic-direct.singbox.json"
    assert attachment["inbounds"][0]["users"][0]["username"].startswith("tg_")
    assert attachment["inbounds"][0]["users"][0]["password"]
    assert attachment["outbounds"][0]["type"] == "hysteria2"
    assert attachment["outbounds"][0]["up_mbps"] == 100
    assert attachment["outbounds"][0]["down_mbps"] == 100
    assert attachment["outbounds"][0]["password"] == "u:p"
    assert attachment["outbounds"][0]["obfs"] == {"type": "salamander", "password": "obfs-secret"}
    assert attachment["outbounds"][0]["tls"]["alpn"] == ["h3"]


def test_export_hysteria2_rejects_missing_salamander() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 4443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }

    with pytest.raises(V2RayNExportError, match="Salamander"):
        export_v2rayn(effective)


def test_export_hysteria2_token_uri() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 4443,
        "auth": {
            "type": "token",
            "token": "client-token:device-token",
            "client_id": "client-token",
        },
        "obfs": {"type": "salamander", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert out.content.startswith("hysteria2://client-token%3Adevice-token@t.example.com:4443/")
    assert "insecure=0" not in out.content
    assert "alpn=" not in out.content
    assert "sni=t.example.com" in out.content
    assert "peer=t.example.com" not in out.content
    assert "#V3-Hysteria2-QUIC-Direct" in out.content
    assert out.alternate_title is None
    assert out.alternate_content is None
    assert "Local SOCKS5 credentials" in dict(out.extra_messages)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert attachment["inbounds"][0]["users"][0]["username"].startswith("tg_")
    assert attachment["outbounds"][0]["password"] == "client-token:device-token"
    assert attachment["outbounds"][0]["type"] == "hysteria2"


def test_export_hysteria2_token_uri_falls_back_to_raw_token_when_it_is_not_splitable() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 4443,
        "auth": {"type": "token", "token": "opaque-token", "client_id": "client-token"},
        "obfs": {"type": "salamander", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }
    out = export_v2rayn(effective)
    assert out.content.startswith("hysteria2://opaque-token@t.example.com:4443/")


def test_export_hysteria2_ip_sni_forces_insecure_tls() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "198.51.100.105",
        "port": 4443,
        "sni": "198.51.100.105",
        "tls": {"server_name": "198.51.100.105", "insecure": False},
        "auth": {"type": "token", "token": "opaque-token", "client_id": "client-token"},
        "obfs": {"type": "salamander", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }

    out = export_v2rayn(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))

    assert "insecure=1" in out.content
    assert attachment["outbounds"][0]["tls"]["insecure"] is True


def test_export_mtproto_tls_link() -> None:
    effective = {
        "protocol": "mtproto",
        "server": "proxied.tracegate.test",
        "port": 443,
        "secret": "95f0d81f7539ecbe1bd880f48b6a739a",
        "transport": "tls",
        "domain": "proxied.tracegate.test",
        "profile": "MTProto-FakeTLS-Direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert out.title == "Telegram Proxy link · MTProto-FakeTLS-Direct"
    assert out.content.startswith("https://t.me/proxy?server=proxied.tracegate.test&port=443&secret=ee95f0")


def test_export_vless_ws_tls_uri() -> None:
    effective = {
        "protocol": "vless",
        "transport": "ws_tls",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "t.example.com",
        "ws": {"path": "/ws", "host": "t.example.com"},
        "tls": {"server_name": "t.example.com", "insecure": True},
        "profile": "V1-VLESS-WS-TLS-Direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@t.example.com:443?")
    assert "security=tls" in out.content
    assert "type=ws" in out.content
    assert "alpn=" not in out.content
    assert "fp=" not in out.content
    assert "path=/ws" in out.content
    assert "host=t.example.com" in out.content
    assert "allowInsecure=1" in out.content
    assert out.attachment_filename == "v1-vless-ws-tls-direct.xray.json"
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert attachment["inbounds"][0]["settings"]["auth"] == "password"
    assert attachment["inbounds"][0]["settings"]["accounts"][0]["user"].startswith("tg_")
    assert attachment["outbounds"][0]["streamSettings"]["wsSettings"]["path"] == "/ws"
    assert attachment["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] == ["http/1.1"]


def test_export_vless_ws_tls_can_use_alternate_connect_host_with_domain_sni() -> None:
    effective = {
        "protocol": "vless",
        "transport": "ws_tls",
        "server": "endpoint.tracegate.test",
        "connect_host": "edge-connect.tracegate.test",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "endpoint.tracegate.test",
        "ws": {"path": "/ws", "host": "endpoint.tracegate.test"},
        "profile": "V0-WS-VLESS",
    }

    out = export_v2rayn(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))

    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@edge-connect.tracegate.test:443?")
    assert "sni=endpoint.tracegate.test" in out.content
    assert "host=endpoint.tracegate.test" in out.content
    assert attachment["outbounds"][0]["settings"]["vnext"][0]["address"] == "edge-connect.tracegate.test"
    assert attachment["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] == "endpoint.tracegate.test"


def test_export_vless_grpc_tls_uri() -> None:
    effective = {
        "protocol": "vless",
        "transport": "grpc_tls",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "t.example.com",
        "grpc": {"service_name": "tracegate.v1.Edge", "authority": "t.example.com"},
        "tls": {"server_name": "t.example.com", "insecure": False},
        "profile": "V1-VLESS-gRPC-TLS-Direct",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@t.example.com:443?")
    assert "security=tls" in out.content
    assert "type=grpc" in out.content
    assert "alpn=" not in out.content
    assert "fp=" not in out.content
    assert "serviceName=tracegate.v1.Edge" in out.content
    assert "mode=gun" in out.content
    assert "authority=" not in out.content
    assert out.attachment_filename == "v1-vless-grpc-tls-direct.xray.json"
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert attachment["inbounds"][0]["settings"]["auth"] == "password"
    assert attachment["outbounds"][0]["streamSettings"]["network"] == "grpc"
    assert attachment["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] == ["h2"]
    assert attachment["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"] == "tracegate.v1.Edge"


def test_export_vless_grpc_tls_can_use_alternate_connect_host_with_domain_sni() -> None:
    effective = {
        "protocol": "vless",
        "transport": "grpc_tls",
        "server": "endpoint.tracegate.test",
        "connect_host": "edge-connect.tracegate.test",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "endpoint.tracegate.test",
        "grpc": {"service_name": "tracegate.v1.Edge", "authority": "endpoint.tracegate.test"},
        "profile": "V0-gRPC-VLESS",
    }

    out = export_v2rayn(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))

    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@edge-connect.tracegate.test:443?")
    assert "sni=endpoint.tracegate.test" in out.content
    assert "serviceName=tracegate.v1.Edge" in out.content
    assert attachment["outbounds"][0]["settings"]["vnext"][0]["address"] == "edge-connect.tracegate.test"
    assert attachment["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] == "endpoint.tracegate.test"


def test_export_uses_explicit_local_socks_credentials() -> None:
    effective = {
        "protocol": "vless",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "google.com",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "profile": "V1-VLESS-Reality-Direct",
        "local_socks": {
            "listen": "127.0.0.1:18080",
            "auth": {"username": "tracegate-local", "password": "local-secret"},
        },
    }

    out = export_v2rayn(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))

    assert attachment["inbounds"][0]["port"] == 18080
    assert attachment["inbounds"][0]["settings"]["accounts"] == [{"user": "tracegate-local", "pass": "local-secret"}]
    local_socks = _extra_content(out, "Local SOCKS5 credentials")
    assert "Port: 18080" in local_socks
    assert "Username: tracegate-local" in local_socks
    assert "Password: local-secret" in local_socks


def test_export_rejects_non_loopback_local_socks_listener() -> None:
    effective = {
        "protocol": "vless",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "google.com",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "profile": "V1-VLESS-Reality-Direct",
        "local_socks": {
            "listen": "0.0.0.0:1080",
            "auth": {"required": True, "mode": "username_password", "username": "u", "password": "p"},
        },
    }

    with pytest.raises(V2RayNExportError, match="loopback"):
        export_v2rayn(effective)


def test_export_rejects_disabled_local_socks_auth() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 4443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "obfs": {"type": "salamander", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
        "local_socks": {
            "listen": "127.0.0.1:1080",
            "auth": {"required": False, "mode": "username_password", "username": "u", "password": "p"},
        },
    }

    with pytest.raises(V2RayNExportError, match="explicitly disabled"):
        export_v2rayn(effective)


def test_export_rejects_client_side_xray_handler_service() -> None:
    effective = {
        "protocol": "vless",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "google.com",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "profile": "V1-VLESS-Reality-Direct",
        "xray_api": {"enabled": True, "services": ["HandlerService"]},
    }

    with pytest.raises(V2RayNExportError, match="HandlerService"):
        export_v2rayn(effective)


def test_export_shadowsocks2022_shadowtls_single_line_uri() -> None:
    effective = {
        "protocol": "shadowsocks2022",
        "transport": "shadowtls_v3",
        "server": "t.example.com",
        "port": 443,
        "method": "2022-blake3-aes-128-gcm",
        "password": "server-password:user-password",
        "shadowtls": {
            "version": 3,
            "server_name": "www.microsoft.com",
            "password": "shadowtls-password",
        },
        "profile": "V5-Shadowsocks2022-ShadowTLS-Direct",
        "local_socks": {
            "listen": "127.0.0.1:18082",
            "auth": {"username": "local-user", "password": "local-pass"},
        },
    }

    out = export_v2rayn(effective)

    assert out.kind == "uri"
    assert out.content.startswith("ss://")
    assert "\n" not in out.content
    assert "shadow-tls=" not in out.content
    assert "@t.example.com:443" in out.content
    assert "#V5-Shadowsocks2022-ShadowTLS-Direct" in out.content
    assert out.title == "Shadowsocks-2022 + ShadowTLS"
    assert out.alternate_content is None
    assert out.attachment_content is None
    assert out.extra_messages == ()

    parsed = urlparse(out.content)
    assert base64.urlsafe_b64decode(f"{parsed.username}==").decode("utf-8") == (
        "2022-blake3-aes-128-gcm:server-password:user-password"
    )
    assert parse_qs(parsed.query) == {
        "plugin": ["shadow-tls;host=www.microsoft.com;password=shadowtls-password;version=3"]
    }


def test_export_wireguard_wstunnel_attachment_requires_local_auth() -> None:
    effective = {
        "protocol": "wireguard",
        "transport": "wstunnel",
        "server": "edge.example.com",
        "port": 443,
        "profile": "V7-WireGuard-WSTunnel-Direct",
        "wstunnel": {
            "url": "wss://edge.example.com:443/cdn/ws",
            "local_udp_listen": "127.0.0.1:51820",
        },
        "wireguard": {
            "private_key": "client-private",
            "server_public_key": "server-public",
            "preshared_key": "wg-psk",
            "address": "10.70.0.2/32",
            "mtu": 1280,
        },
        "local_socks": {
            "listen": "127.0.0.1:18083",
            "auth": {"username": "wg-local", "password": "wg-pass"},
        },
    }

    out = export_v2rayn(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))

    assert out.kind == "attachment"
    assert out.attachment_filename == "v7-wireguard-wstunnel-direct.singbox.json"
    assert dict(out.extra_messages)["WSTunnel target"] == "wss://edge.example.com:443/cdn/ws"
    assert "Local SOCKS5 credentials" in dict(out.extra_messages)
    assert attachment["inbounds"][0]["listen_port"] == 18083
    assert attachment["inbounds"][0]["users"] == [{"username": "wg-local", "password": "wg-pass"}]
    assert attachment["outbounds"][0]["type"] == "wireguard"
    assert attachment["outbounds"][0]["server"] == "127.0.0.1"
    assert attachment["outbounds"][0]["server_port"] == 51820
    assert attachment["outbounds"][0]["local_address"] == ["10.70.0.2/32"]
    assert attachment["outbounds"][0]["pre_shared_key"] == "wg-psk"


def test_export_wireguard_wstunnel_rejects_invalid_wstunnel_target() -> None:
    effective = {
        "protocol": "wireguard",
        "transport": "wstunnel",
        "server": "edge.example.com",
        "profile": "V7-WireGuard-WSTunnel-Direct",
        "wstunnel": {"url": "http://edge.example.com/cdn/ws", "local_udp_listen": "127.0.0.1:51820"},
        "wireguard": {
            "private_key": "client-private",
            "server_public_key": "server-public",
            "address": "10.70.0.2/32",
        },
        "local_socks": {
            "listen": "127.0.0.1:18083",
            "auth": {"username": "wg-local", "password": "wg-pass"},
        },
    }

    with pytest.raises(V2RayNExportError, match="wss://host:443/path"):
        export_v2rayn(effective)


@pytest.mark.parametrize("url", ["wss://edge.example.com:443/cdn ws", "wss://edge.example.com:443/cdn/ws?debug=1"])
def test_export_wireguard_wstunnel_rejects_unclean_wstunnel_target(url: str) -> None:
    effective = {
        "protocol": "wireguard",
        "transport": "wstunnel",
        "server": "edge.example.com",
        "profile": "V7-WireGuard-WSTunnel-Direct",
        "wstunnel": {"url": url, "local_udp_listen": "127.0.0.1:51820"},
        "wireguard": {
            "private_key": "client-private",
            "server_public_key": "server-public",
            "address": "10.70.0.2/32",
        },
        "local_socks": {
            "listen": "127.0.0.1:18083",
            "auth": {"username": "wg-local", "password": "wg-pass"},
        },
    }

    with pytest.raises(V2RayNExportError, match="wss://host:443/path"):
        export_v2rayn(effective)


def test_export_wireguard_wstunnel_rejects_non_loopback_local_udp() -> None:
    effective = {
        "protocol": "wireguard",
        "transport": "wstunnel",
        "server": "edge.example.com",
        "profile": "V7-WireGuard-WSTunnel-Direct",
        "wstunnel": {"url": "wss://edge.example.com:443/cdn/ws", "local_udp_listen": "0.0.0.0:51820"},
        "wireguard": {
            "private_key": "client-private",
            "server_public_key": "server-public",
            "address": "10.70.0.2/32",
        },
        "local_socks": {
            "listen": "127.0.0.1:18083",
            "auth": {"username": "wg-local", "password": "wg-pass"},
        },
    }

    with pytest.raises(V2RayNExportError, match="loopback"):
        export_v2rayn(effective)


def test_export_wireguard_wstunnel_rejects_unsafe_mtu() -> None:
    effective = {
        "protocol": "wireguard",
        "transport": "wstunnel",
        "server": "edge.example.com",
        "profile": "V7-WireGuard-WSTunnel-Direct",
        "wstunnel": {"url": "wss://edge.example.com:443/cdn/ws", "local_udp_listen": "127.0.0.1:51820"},
        "wireguard": {
            "private_key": "client-private",
            "server_public_key": "server-public",
            "address": "10.70.0.2/32",
            "mtu": 1500,
        },
        "local_socks": {
            "listen": "127.0.0.1:18083",
            "auth": {"username": "wg-local", "password": "wg-pass"},
        },
    }

    with pytest.raises(V2RayNExportError, match="1200..1420"):
        export_v2rayn(effective)


@pytest.mark.parametrize(
    "effective",
    [
        {
            "protocol": "vless",
            "transport": "reality",
            "server": "t.example.com",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "sni": "google.com",
            "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
            "profile": "V1-VLESS-Reality-Direct",
        },
        {
            "protocol": "vless",
            "transport": "grpc_tls",
            "server": "t.example.com",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "sni": "t.example.com",
            "grpc": {"service_name": "tracegate.v1.Edge"},
            "profile": "V1-VLESS-gRPC-TLS-Direct",
        },
        {
            "protocol": "vless",
            "transport": "ws_tls",
            "server": "t.example.com",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "sni": "t.example.com",
            "ws": {"path": "/ws"},
            "profile": "V1-VLESS-WS-TLS-Direct",
        },
        {
            "protocol": "hysteria2",
            "server": "t.example.com",
            "port": 4443,
            "auth": {"type": "userpass", "username": "u", "password": "p"},
            "obfs": {"type": "salamander", "password": "obfs-secret"},
            "profile": "V3-Hysteria2-QUIC-Direct",
        },
        {
            "protocol": "wireguard",
            "server": "edge.example.com",
            "profile": "V7-WireGuard-WSTunnel-Direct",
            "wstunnel": {"url": "wss://edge.example.com:443/cdn/ws", "local_udp_listen": "127.0.0.1:51820"},
            "wireguard": {
                "private_key": "client-private",
                "server_public_key": "server-public",
                "address": "10.70.0.2/32",
            },
        },
    ],
)
def test_exported_local_proxy_attachments_always_require_auth(effective: dict) -> None:
    out = export_v2rayn(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    inbound = attachment["inbounds"][0]

    if inbound.get("protocol") == "socks":
        assert inbound["settings"]["auth"] == "password"
        assert 20000 <= int(inbound["port"]) < 60000
        account = inbound["settings"]["accounts"][0]
        assert account["user"].startswith("tg_")
        assert account["pass"]
        return

    assert inbound["type"] in {"mixed", "socks"}
    assert 20000 <= int(inbound["listen_port"]) < 60000
    user = inbound["users"][0]
    assert user["username"].startswith("tg_")
    assert user["password"]


def test_export_rejects_unsupported_protocol() -> None:
    effective = {"protocol": "unknown"}
    with pytest.raises(V2RayNExportError, match="Unsupported protocol"):
        export_v2rayn(effective)


def test_export_vless_reality_uri_defaults_to_xhttp_without_xhttp_block() -> None:
    effective = {
        "protocol": "vless",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "google.com",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "profile": "legacy-vless",
    }
    out = export_v2rayn(effective)
    assert out.kind == "uri"
    assert "security=reality" in out.content
    assert "type=xhttp" in out.content
    assert "mode=auto" in out.content
    assert "path=/api/v1/update" in out.content
