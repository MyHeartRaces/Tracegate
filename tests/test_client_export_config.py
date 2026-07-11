import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest

from tracegate.client_export.config import ClientConfigExportError, export_client_config


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
        "sni": "yandex.ru",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "transport": "reality_raw",
        "flow": "xtls-rprx-vision",
        "profile": "V1-VLESS-Reality-Direct",
    }
    out = export_client_config(effective)
    assert out.kind == "uri"
    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@t.example.com:443?")
    assert "security=reality" in out.content
    assert "type=tcp" in out.content
    assert "flow=xtls-rprx-vision" in out.content
    assert "sni=yandex.ru" in out.content
    assert "pbk=PUBKEY" in out.content
    assert "sid=abcd" in out.content
    assert "#Direct-VLESS" in out.content
    assert out.attachment_filename == "direct-vless.xray.json"
    assert out.attachment_mime == "application/json"
    local_socks = _extra_content(out, "Local SOCKS5 credentials")
    assert "Host: 127.0.0.1" in local_socks
    assert "Username: tg_" in local_socks
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert attachment["inbounds"][0]["settings"]["auth"] == "password"
    assert attachment["inbounds"][0]["settings"]["accounts"][0]["user"].startswith("tg_")
    assert attachment["inbounds"][0]["settings"]["accounts"][0]["pass"]
    assert attachment["outbounds"][0]["streamSettings"]["network"] == "raw"
    assert attachment["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert attachment["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] == "yandex.ru"
    assert attachment["outbounds"][0]["streamSettings"]["realitySettings"]["password"] == "PUBKEY"
    assert "publicKey" not in attachment["outbounds"][0]["streamSettings"]["realitySettings"]


def test_export_vless_reality_rejects_removed_vless_encryption() -> None:
    encryption = "mlkem768x25519plus.native.0rtt.CLIENT"
    effective = {
        "protocol": "vless",
        "transport": "reality",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "passport.old-forbidden.tracegate-sni.ru",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "xhttp": {"mode": "auto", "path": "/api/v1/update"},
        "profile": "V1-VLESS-Reality-Direct",
        "vless_encryption": {"enabled": True, "encryption": encryption},
    }

    with pytest.raises(ClientConfigExportError, match="Encrypted VLESS was removed"):
        export_client_config(effective)


def test_export_hysteria2_uri() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 4443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "obfs": {"type": "gecko", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }
    out = export_client_config(effective)
    assert out.kind == "uri"
    assert out.content.startswith("hysteria2://u%3Ap@t.example.com:4443/")
    assert "insecure=0" not in out.content
    assert "obfs=gecko" in out.content
    assert "obfs-password=obfs-secret" in out.content
    assert "alpn=" not in out.content
    assert "sni=t.example.com" in out.content
    assert "peer=t.example.com" not in out.content
    assert "#Direct-Hysteria" in out.content
    assert out.alternate_title is None
    assert out.alternate_content is None
    assert "Local SOCKS5 credentials" in dict(out.extra_messages)
    assert "sing-box 1.14.0+" in dict(out.extra_messages)["Client compatibility"]
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert out.attachment_filename == "direct-hysteria.singbox.json"
    assert attachment["inbounds"][0]["users"][0]["username"].startswith("tg_")
    assert attachment["inbounds"][0]["users"][0]["password"]
    assert attachment["outbounds"][0]["type"] == "hysteria2"
    assert attachment["outbounds"][0]["up_mbps"] == 100
    assert attachment["outbounds"][0]["down_mbps"] == 100
    assert attachment["outbounds"][0]["password"] == "u:p"
    assert attachment["outbounds"][0]["obfs"] == {
        "type": "gecko",
        "password": "obfs-secret",
        "min_packet_size": 512,
        "max_packet_size": 1200,
    }
    assert attachment["outbounds"][0]["tls"]["alpn"] == ["h3"]


def test_export_hysteria2_salamander_uri_and_singbox_attachment() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 8444,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "obfs": {"type": "salamander", "password": "obfs-secret"},
        "profile": "V2-Hysteria2-QUIC-Direct",
    }

    out = export_client_config(effective)

    assert "@t.example.com:8444/" in out.content
    assert "obfs=salamander" in out.content
    assert "broadly compatible" in dict(out.extra_messages)["Client compatibility"]
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert attachment["outbounds"][0]["obfs"] == {
        "type": "salamander",
        "password": "obfs-secret",
    }


def test_export_hysteria2_chain_caps_stale_bandwidth_to_chain_limit() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "entry.example.com",
        "port": 4443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "obfs": {"type": "gecko", "password": "obfs-secret"},
        "profile": "V2-Chain-QUIC-Hysteria",
        "up_mbps": 100,
        "down_mbps": 100,
        "rate_limit": {"enabled": True, "max_mbit": 10},
        "design_constraints": {"chain_client_rate_limit_mbit": 10},
        "chain": {"type": "entry-transit"},
    }

    out = export_client_config(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))

    assert attachment["outbounds"][0]["up_mbps"] == 10
    assert attachment["outbounds"][0]["down_mbps"] == 10


def test_export_hysteria2_direct_keeps_explicit_bandwidth_override() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "endpoint.example.com",
        "port": 4443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "obfs": {"type": "gecko", "password": "obfs-secret"},
        "profile": "V2-Direct-QUIC-Hysteria",
        "up_mbps": 200,
        "down_mbps": 200,
        "rate_limit": {"enabled": False},
    }

    out = export_client_config(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))

    assert attachment["outbounds"][0]["up_mbps"] == 200
    assert attachment["outbounds"][0]["down_mbps"] == 200


def test_export_hysteria2_rejects_missing_obfs() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 4443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }

    with pytest.raises(ClientConfigExportError, match="Gecko or Salamander"):
        export_client_config(effective)


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
        "obfs": {"type": "gecko", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }
    out = export_client_config(effective)
    assert out.kind == "uri"
    assert out.content.startswith("hysteria2://client-token%3Adevice-token@t.example.com:4443/")
    assert "insecure=0" not in out.content
    assert "alpn=" not in out.content
    assert "sni=t.example.com" in out.content
    assert "peer=t.example.com" not in out.content
    assert "#Direct-Hysteria" in out.content
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
        "obfs": {"type": "gecko", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }
    out = export_client_config(effective)
    assert out.content.startswith("hysteria2://opaque-token@t.example.com:4443/")


def test_export_hysteria2_ip_sni_forces_insecure_tls() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "198.51.100.105",
        "port": 4443,
        "sni": "198.51.100.105",
        "tls": {"server_name": "198.51.100.105", "insecure": False},
        "auth": {"type": "token", "token": "opaque-token", "client_id": "client-token"},
        "obfs": {"type": "gecko", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
    }

    out = export_client_config(effective)
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
    out = export_client_config(effective)
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
    out = export_client_config(effective)
    assert out.kind == "uri"
    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@t.example.com:443?")
    assert "security=tls" in out.content
    assert "type=ws" in out.content
    assert "alpn=" not in out.content
    assert "fp=" not in out.content
    assert "path=/ws" in out.content
    assert "host=t.example.com" in out.content
    assert "allowInsecure=1" in out.content
    assert "#Backup-VLESS%2BWebSocket" in out.content
    assert out.attachment_filename == "backup-vless-websocket.xray.json"
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert attachment["inbounds"][0]["settings"]["auth"] == "password"
    assert attachment["inbounds"][0]["settings"]["accounts"][0]["user"].startswith("tg_")
    assert attachment["outbounds"][0]["streamSettings"]["wsSettings"]["path"] == "/ws"
    assert attachment["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] == ["http/1.1"]
    assert "allowInsecure" not in attachment["outbounds"][0]["streamSettings"]["tlsSettings"]


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

    out = export_client_config(effective)
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
    out = export_client_config(effective)
    assert out.kind == "uri"
    assert out.content.startswith("vless://11111111-2222-3333-4444-555555555555@t.example.com:443?")
    assert "security=tls" in out.content
    assert "type=grpc" in out.content
    assert "alpn=" not in out.content
    assert "fp=" not in out.content
    assert "serviceName=tracegate.v1.Edge" in out.content
    assert "mode=gun" in out.content
    assert "authority=" not in out.content
    assert "#Backup-VLESS%2BgRPC" in out.content
    assert out.attachment_filename == "backup-vless-grpc.xray.json"
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

    out = export_client_config(effective)
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
        "sni": "yandex.ru",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "profile": "V1-VLESS-Reality-Direct",
        "local_socks": {
            "listen": "127.0.0.1:18080",
            "auth": {"username": "tracegate-local", "password": "local-secret"},
        },
    }

    out = export_client_config(effective)
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
        "sni": "yandex.ru",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "profile": "V1-VLESS-Reality-Direct",
        "local_socks": {
            "listen": "0.0.0.0:1080",
            "auth": {"required": True, "mode": "username_password", "username": "u", "password": "p"},
        },
    }

    with pytest.raises(ClientConfigExportError, match="loopback"):
        export_client_config(effective)


def test_export_rejects_disabled_local_socks_auth() -> None:
    effective = {
        "protocol": "hysteria2",
        "server": "t.example.com",
        "port": 4443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "obfs": {"type": "gecko", "password": "obfs-secret"},
        "profile": "V3-Hysteria2-QUIC-Direct",
        "local_socks": {
            "listen": "127.0.0.1:1080",
            "auth": {"required": False, "mode": "username_password", "username": "u", "password": "p"},
        },
    }

    with pytest.raises(ClientConfigExportError, match="explicitly disabled"):
        export_client_config(effective)


def test_export_rejects_client_side_xray_handler_service() -> None:
    effective = {
        "protocol": "vless",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "yandex.ru",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "profile": "V1-VLESS-Reality-Direct",
        "xray_api": {"enabled": True, "services": ["HandlerService"]},
    }

    with pytest.raises(ClientConfigExportError, match="HandlerService"):
        export_client_config(effective)


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
            "server_name": "www.rbc.ru",
            "password": "shadowtls-password",
        },
        "profile": "V5-Shadowsocks2022-ShadowTLS-Direct",
        "local_socks": {
            "listen": "127.0.0.1:18082",
            "auth": {"username": "local-user", "password": "local-pass"},
        },
    }

    out = export_client_config(effective)

    assert out.kind == "uri"
    assert out.content.startswith("ss://")
    assert "\n" not in out.content
    assert "shadow-tls=" not in out.content
    assert "@t.example.com:443" in out.content
    assert "#Backup-Shadowsocks" in out.content
    assert out.title == "Shadowsocks-2022 + ShadowTLS"
    assert out.alternate_content is None
    assert out.attachment_filename == "backup-shadowsocks.singbox.json"
    assert out.attachment_mime == "application/json"
    assert dict(out.extra_messages)["Shadowsocks import note"].startswith("Use the attached sing-box JSON first.")

    parsed = urlparse(out.content)
    assert base64.urlsafe_b64decode(f"{parsed.username}==").decode("utf-8") == (
        "2022-blake3-aes-128-gcm:server-password:user-password"
    )
    assert parse_qs(parsed.query) == {
        "plugin": ["shadow-tls;host=www.rbc.ru;password=shadowtls-password;version=3"]
    }
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    assert attachment["dns"] == {
        "servers": [{"type": "udp", "tag": "cloudflare", "server": "1.1.1.1", "server_port": 53}],
        "final": "cloudflare",
        "strategy": "ipv4_only",
    }
    assert attachment["route"] == {
        "auto_detect_interface": True,
        "default_domain_resolver": "cloudflare",
        "final": "proxy",
    }
    assert attachment["inbounds"][0]["users"] == [{"username": "local-user", "password": "local-pass"}]
    assert attachment["outbounds"][0] == {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": "t.example.com",
        "server_port": 443,
        "method": "2022-blake3-aes-128-gcm",
        "password": "server-password:user-password",
        "detour": "shadowtls-out",
    }
    assert attachment["outbounds"][1] == {
        "type": "shadowtls",
        "tag": "shadowtls-out",
        "server": "t.example.com",
        "server_port": 443,
        "version": 3,
        "password": "shadowtls-password",
        "tls": {
            "enabled": True,
            "server_name": "www.rbc.ru",
            "alpn": ["h2", "http/1.1"],
            "utls": {
                "enabled": True,
                "fingerprint": "chrome",
            },
        },
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

    out = export_client_config(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))

    assert out.kind == "attachment"
    assert out.attachment_filename == "backup-wgws.wgws.json"
    assert dict(out.extra_messages)["WGWS transport"] == "wss://edge.example.com:443/cdn/ws"
    assert dict(out.extra_messages)["WG local UDP"] == "127.0.0.1:51820"
    assert "Local SOCKS5 credentials" in dict(out.extra_messages)
    assert attachment["type"] == "wgws"
    assert attachment["schema"] == "tracegate.wgws-client.v1"
    assert attachment["endpoint"] == "edge.example.com:443"
    assert attachment["wireguard"]["local_address"] == ["10.70.0.2/32"]
    assert attachment["wireguard"]["peer_public_key"] == "server-public"
    assert attachment["wireguard"]["pre_shared_key"] == "wg-psk"
    assert attachment["wireguard"]["allowed_ips"] == ["0.0.0.0/0"]
    assert attachment["websocket"] == {
        "server": "edge.example.com",
        "server_port": 443,
        "tls": True,
        "sni": "edge.example.com",
        "host": "edge.example.com",
        "path": "/cdn/ws",
        "headers": {},
    }
    assert attachment["wstunnel"]["local_udp_listen"] == "127.0.0.1:51820"
    assert attachment["wstunnel"]["http_upgrade_path_prefix"] == "cdn/ws"
    assert attachment["wstunnel"]["client_command"] == (
        "wstunnel client --http-upgrade-path-prefix cdn/ws "
        "-H 'Host: edge.example.com' "
        "-L udp://127.0.0.1:51820:127.0.0.1:51820 "
        "wss://edge.example.com:443"
    )
    assert attachment["singbox"]["inbounds"][0]["listen_port"] == 18083
    assert attachment["singbox"]["inbounds"][0]["users"] == [{"username": "wg-local", "password": "wg-pass"}]
    assert attachment["singbox"]["dns"] == {
        "servers": [{"type": "udp", "tag": "cloudflare", "server": "1.1.1.1", "server_port": 53}],
        "final": "cloudflare",
        "strategy": "ipv4_only",
    }
    endpoint = attachment["singbox"]["endpoints"][0]
    assert endpoint["type"] == "wireguard"
    assert endpoint["address"] == ["10.70.0.2/32"]
    assert endpoint["peers"][0]["address"] == "127.0.0.1"
    assert endpoint["peers"][0]["port"] == 51820
    assert endpoint["peers"][0]["pre_shared_key"] == "wg-psk"
    assert endpoint["peers"][0]["allowed_ips"] == ["0.0.0.0/0"]


def test_export_wireguard_wstunnel_client_command_uses_canonical_tls_name() -> None:
    effective = {
        "protocol": "wireguard",
        "transport": "wstunnel",
        "server": "token.r2.example.com",
        "sni": "endpoint.example.com",
        "profile": "V7-WireGuard-WSTunnel-Direct",
        "wstunnel": {
            "url": "wss://token.r2.example.com:443/wgws",
            "tls_server_name": "endpoint.example.com",
            "local_udp_listen": "127.0.0.1:51820",
        },
        "wireguard": {
            "private_key": "client-private",
            "server_public_key": "server-public",
            "address": "10.70.0.2/32",
        },
    }

    out = export_client_config(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))

    assert attachment["websocket"]["sni"] == "endpoint.example.com"
    assert attachment["websocket"]["host"] == "endpoint.example.com"
    assert attachment["websocket"]["headers"] == {"Host": "endpoint.example.com"}
    assert attachment["wstunnel"]["client_command"] == (
        "wstunnel client --http-upgrade-path-prefix wgws "
        "--tls-sni-override endpoint.example.com "
        "-H 'Host: endpoint.example.com' "
        "-L udp://127.0.0.1:51820:127.0.0.1:51820 "
        "wss://token.r2.example.com:443"
    )


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

    with pytest.raises(ClientConfigExportError, match="wss://host:443/path"):
        export_client_config(effective)


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

    with pytest.raises(ClientConfigExportError, match="wss://host:443/path"):
        export_client_config(effective)


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

    with pytest.raises(ClientConfigExportError, match="loopback"):
        export_client_config(effective)


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

    with pytest.raises(ClientConfigExportError, match="1200..1420"):
        export_client_config(effective)


@pytest.mark.parametrize(
    "effective",
    [
        {
            "protocol": "vless",
            "transport": "reality",
            "server": "t.example.com",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "sni": "yandex.ru",
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
            "obfs": {"type": "gecko", "password": "obfs-secret"},
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
    out = export_client_config(effective)
    attachment = json.loads((out.attachment_content or b"").decode("utf-8"))
    inbound = (attachment.get("singbox") or attachment)["inbounds"][0]

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
    with pytest.raises(ClientConfigExportError, match="Unsupported protocol"):
        export_client_config(effective)


def test_export_vless_reality_uri_defaults_to_raw_vision() -> None:
    effective = {
        "protocol": "vless",
        "server": "t.example.com",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "sni": "yandex.ru",
        "reality": {"public_key": "PUBKEY", "short_id": "abcd"},
        "profile": "legacy-vless",
    }
    out = export_client_config(effective)
    assert out.kind == "uri"
    assert "security=reality" in out.content
    assert "type=tcp" in out.content
    assert "flow=xtls-rprx-vision" in out.content
