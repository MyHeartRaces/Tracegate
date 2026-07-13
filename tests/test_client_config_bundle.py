import base64
from datetime import datetime, timezone

from tracegate.client_export.bundle import (
    ClientConfigBundleItem,
    build_client_config_bundle,
    render_subscription_base64,
    render_subscription_text,
)


def _item(index: int, effective_config: dict) -> ClientConfigBundleItem:
    return ClientConfigBundleItem(
        revision_id=f"rev-{index}",
        connection_id=f"conn-{index}",
        device_id="dev-1",
        effective_config=effective_config,
        protocol=str(effective_config.get("protocol") or ""),
        mode="direct",
        variant=f"V{index}",
        profile_name=str(effective_config.get("profile") or f"profile-{index}"),
    )


def test_client_config_bundle_collects_universal_links_artifacts_and_singbox() -> None:
    bundle = build_client_config_bundle(
        [
            _item(
                1,
                {
                    "protocol": "vless",
                    "transport": "ws_tls",
                    "server": "edge.example.com",
                    "port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "sni": "front.example.com",
                    "ws": {"path": "/ws", "host": "front.example.com"},
                    "profile": "VLESS-WS",
                },
            ),
            _item(
                2,
                {
                    "protocol": "hysteria2",
                    "server": "hy.example.com",
                    "port": 4443,
                    "auth": {"type": "userpass", "username": "u", "password": "p"},
                    "obfs": {"type": "gecko", "password": "obfs-secret"},
                    "profile": "Hysteria2",
                },
            ),
            _item(
                3,
                {
                    "protocol": "shadowsocks2022",
                    "transport": "shadowtls_v3",
                    "server": "ss.example.com",
                    "port": 443,
                    "method": "2022-blake3-aes-128-gcm",
                    "password": "server-password:user-password",
                    "shadowtls": {
                        "version": 3,
                        "server_name": "www.microsoft.com",
                        "password": "shadowtls-password",
                    },
                    "profile": "SS2022-ShadowTLS",
                },
            ),
            _item(
                4,
                {
                    "protocol": "wireguard",
                    "transport": "wstunnel",
                    "server": "edge.example.com",
                    "port": 443,
                    "profile": "WGWS",
                    "wstunnel": {
                        "url": "wss://edge.example.com:443/cdn/ws",
                        "local_udp_listen": "127.0.0.1:51820",
                    },
                    "wireguard": {
                        "private_key": "client-private",
                        "server_public_key": "server-public",
                        "address": "10.70.0.2/32",
                    },
                },
            ),
        ],
        subject_type="device",
        subject_id="dev-1",
        generated_at=datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc),
    )

    assert bundle["schema"] == "tracegate.client-config-bundle.v1"
    assert bundle["generatedAt"] == "2026-05-19T12:00:00Z"
    assert bundle["subject"] == {"type": "device", "id": "dev-1"}
    assert bundle["counts"] == {
        "profiles": 4,
        "links": 3,
        "singboxOutbounds": 3,
        "errors": 0,
    }
    assert render_subscription_text(bundle) == "\n".join(bundle["subscription"]["links"])
    assert render_subscription_base64(bundle) == bundle["subscription"]["base64"]
    assert base64.b64decode(bundle["subscription"]["base64"]).decode("utf-8") == render_subscription_text(bundle)

    links = bundle["subscription"]["links"]
    assert any(link.startswith("vless://11111111-2222-3333-4444-555555555555@") for link in links)
    assert any(link.startswith("hysteria2://u%3Ap@hy.example.com:4443/") for link in links)
    assert any(link.startswith("ss://") for link in links)

    selector = bundle["singbox"]["outbounds"][0]
    assert selector["type"] == "selector"
    assert selector["tag"] == "proxy"
    assert selector["default"] in selector["outbounds"]
    assert all("protocol" not in outbound for outbound in bundle["singbox"]["outbounds"])
    assert any(outbound["type"] == "vless" and outbound["transport"]["type"] == "ws" for outbound in bundle["singbox"]["outbounds"])
    assert not any(outbound["type"] == "wireguard" for outbound in bundle["singbox"]["outbounds"])
    assert bundle["singbox"]["route"] == {
        "auto_detect_interface": True,
        "final": "proxy",
        "rules": [{"domain": ["edge.example.com", "hy.example.com", "ss.example.com"], "outbound": "direct"}],
    }

    ss_outbound = next(outbound for outbound in bundle["singbox"]["outbounds"] if outbound["type"] == "shadowsocks")
    assert ss_outbound["detour"].startswith("tg-2-tracegate-experimental-ss2022-")
    assert any(outbound["tag"] == ss_outbound["detour"] for outbound in bundle["singbox"]["outbounds"])

    profiles = {profile["profile"]: profile for profile in bundle["profiles"]}
    assert profiles["Tracegate-Backup(WebSocket)"]["singbox"]["supported"] is True
    assert profiles["Tracegate-Experimental(SS2022)"]["artifacts"][0]["kind"] == "sing-box-config"
    assert profiles["Tracegate-Experimental(WGWS)"]["singbox"]["supported"] is False
    assert profiles["Tracegate-Experimental(WGWS)"]["artifacts"][0]["kind"] == "wgws-config"
    assert profiles["Tracegate-Experimental(WGWS)"]["artifacts"][0]["json"]["type"] == "wgws"
    assert profiles["Tracegate-Experimental(WGWS)"]["warnings"] == ["wireguard_wstunnel_requires_wgws_transport"]


def test_client_config_bundle_routes_connect_host_direct_without_fake_sni_bypass() -> None:
    bundle = build_client_config_bundle(
        [
            _item(
                1,
                {
                    "protocol": "vless",
                    "transport": "ws_tls",
                    "server": "logical.example.com",
                    "connect_host": "edge-connect.example.com",
                    "port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "sni": "borrowed-sni.example.net",
                    "ws": {"path": "/ws", "host": "borrowed-sni.example.net"},
                    "profile": "VLESS-WS",
                },
            )
        ],
        subject_type="device",
        subject_id="dev-1",
        generated_at=datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc),
    )

    assert bundle["singbox"]["outbounds"][1]["server"] == "edge-connect.example.com"
    assert bundle["singbox"]["route"]["rules"] == [{"domain": ["edge-connect.example.com"], "outbound": "direct"}]


def test_client_config_bundle_rejects_removed_vless_encryption() -> None:
    bundle = build_client_config_bundle(
        [
            _item(
                1,
                {
                    "protocol": "vless",
                    "transport": "ws_tls",
                    "server": "edge.example.com",
                    "port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "sni": "front.example.com",
                    "ws": {"path": "/ws-enc", "host": "front.example.com"},
                    "profile": "VLESS-WS-Encrypted",
                    "vless_encryption": {
                        "enabled": True,
                        "encryption": "mlkem768x25519plus.native.0rtt.CLIENT",
                    },
                },
            )
        ],
        subject_type="device",
        subject_id="dev-1",
        generated_at=datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc),
    )

    assert bundle["counts"]["singboxOutbounds"] == 0
    assert bundle["counts"]["profiles"] == 0
    assert bundle["counts"]["errors"] == 1
    assert "Encrypted VLESS was removed" in bundle["errors"][0]["error"]


def test_client_config_bundle_records_profile_export_errors() -> None:
    bundle = build_client_config_bundle(
        [_item(1, {"protocol": "unknown", "profile": "Broken"})],
        subject_type="revision",
        subject_id="rev-1",
        generated_at=datetime(2026, 5, 19, 12, 0, tzinfo=timezone.utc),
    )

    assert bundle["counts"]["profiles"] == 0
    assert bundle["counts"]["errors"] == 1
    assert bundle["errors"][0]["revisionId"] == "rev-1"
    assert "Unsupported protocol" in bundle["errors"][0]["error"]
    assert bundle["singbox"]["outbounds"][0]["outbounds"] == ["direct"]
