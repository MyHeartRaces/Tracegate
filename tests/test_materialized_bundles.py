import json
from pathlib import Path

import pytest

from tracegate.services.materialized_bundles import (
    MaterializedBundleRenderContext,
    MaterializedBundleRenderError,
    host_from_dest,
    render_materialized_bundles,
)


def _base_env(tmp_path: Path) -> dict[str, str]:
    repo_root = Path(__file__).resolve().parents[1]
    return {
        "BUNDLE_SOURCE_ROOT": str(repo_root / "bundles"),
        "BUNDLE_MATERIALIZED_ROOT": str(tmp_path / "materialized"),
        "DEFAULT_ENTRY_HOST": "entry.tracegate.test",
        "DEFAULT_TRANSIT_HOST": "transit.tracegate.test",
        "VLESS_WS_PATH": "/stealth/ws",
        "HYSTERIA_BOOTSTRAP_PASSWORD": "bootstrap-secret",
        "HYSTERIA_GECKO_PASSWORD_ENTRY": "entry-gecko-secret",
        "HYSTERIA_GECKO_PASSWORD_TRANSIT": "transit-gecko-secret",
        "HYSTERIA_STATS_SECRET_ENTRY": "entry-stats-secret",
        "HYSTERIA_STATS_SECRET_TRANSIT": "transit-stats-secret",
        "HYSTERIA_LISTEN_HOST_ENTRY": "192.0.2.10",
        "HYSTERIA_LISTEN_HOST_TRANSIT": "192.0.2.20",
        "HYSTERIA_TLS_CERT_FILE_ENTRY": "/etc/tls/entry.crt",
        "HYSTERIA_TLS_KEY_FILE_ENTRY": "/etc/tls/entry.key",
        "HYSTERIA_TLS_CERT_FILE_TRANSIT": "/etc/tls/transit.crt",
        "HYSTERIA_TLS_KEY_FILE_TRANSIT": "/etc/tls/transit.key",
        "REALITY_PUBLIC_KEY_TRANSIT": "transit-public-key",
        "REALITY_SHORT_ID_ENTRY": "entry-short-id",
        "REALITY_SHORT_ID_TRANSIT": "transit-short-id",
        "REALITY_PRIVATE_KEY_ENTRY": "entry-private-key",
        "REALITY_PRIVATE_KEY_TRANSIT": "transit-private-key",
        "REALITY_DEST_ENTRY": "origin-entry.example:443",
        "REALITY_DEST_TRANSIT": "origin-transit.example:443",
        "ENTRY_TLS_SERVER_NAME": "tls-entry.example",
        "TRANSIT_TLS_SERVER_NAME": "tls-transit.example",
        "SHADOWTLS_SERVER_NAME_TRANSIT": "shadowtls.example",
        "SHADOWSOCKS2022_PASSWORD_TRANSIT": "ss2022-server-key",
        "MTPROTO_DOMAIN": "proxied.tracegate.test",
        "XRAY_CENTRIC_DECOY_DIR": "/srv/decoy",
    }


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.mark.parametrize(
    ("dest", "expected"),
    [
        ("old-mtproto-a.tracegate-sni.ru:443", "old-mtproto-a.tracegate-sni.ru"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("edge.example.com", "edge.example.com"),
    ],
)
def test_host_from_dest_extracts_host(dest: str, expected: str) -> None:
    assert host_from_dest(dest) == expected


def test_context_uses_shared_defaults_and_fallback_values(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env.pop("VLESS_WS_PATH")
    env["REALITY_PUBLIC_KEY"] = "shared-public-key"
    env["REALITY_SHORT_ID"] = "shared-short-id"
    env["REALITY_DEST"] = "shared-origin.example:443"
    env.pop("REALITY_PUBLIC_KEY_TRANSIT")
    env.pop("REALITY_SHORT_ID_ENTRY")
    env.pop("REALITY_SHORT_ID_TRANSIT")
    env.pop("REALITY_DEST_ENTRY")
    env.pop("REALITY_DEST_TRANSIT")
    env.pop("ENTRY_TLS_SERVER_NAME")
    env.pop("TRANSIT_TLS_SERVER_NAME")
    env.pop("XRAY_CENTRIC_DECOY_DIR")

    ctx = MaterializedBundleRenderContext.from_environ(env)

    assert ctx.ws_path == "/ws"
    assert ctx.runtime_profile == "tracegate-3"
    assert ctx.hysteria_udp_port == 443
    assert ctx.entry_hysteria_salamander_password == "entry-gecko-secret"
    assert ctx.transit_hysteria_salamander_password == "transit-gecko-secret"
    assert ctx.entry_hysteria_stats_secret == "entry-stats-secret"
    assert ctx.transit_hysteria_stats_secret == "transit-stats-secret"
    assert ctx.entry_hysteria_auth_url == "http://127.0.0.1:8070/v1/hysteria/auth"
    assert ctx.transit_hysteria_auth_url == "http://127.0.0.1:8070/v1/hysteria/auth"
    assert ctx.entry_hysteria_listen_host == "192.0.2.10"
    assert ctx.transit_hysteria_listen_host == "192.0.2.20"
    assert ctx.entry_hysteria_tls_cert_file == "/etc/tls/entry.crt"
    assert ctx.transit_hysteria_tls_key_file == "/etc/tls/transit.key"
    assert ctx.hysteria_chain_client_rate_limit_enabled is True
    assert ctx.hysteria_chain_client_max_mbit == 10
    assert ctx.hysteria_chain_client_require_declared_tx is True
    assert ctx.reality_public_key_transit == "shared-public-key"
    assert ctx.reality_short_id_entry == "shared-short-id"
    assert ctx.reality_short_id_transit == "shared-short-id"
    assert ctx.reality_dest_entry == "shared-origin.example:443"
    assert ctx.reality_dest_transit == "shared-origin.example:443"
    assert ctx.reality_server_name_entry == "shared-origin.example"
    assert ctx.reality_server_name_transit == "shared-origin.example"
    assert ctx.reality_multi_inbound_groups == ()
    assert ctx.entry_tls_server_name == "entry.tracegate.test"
    assert ctx.transit_tls_server_name == "transit.tracegate.test"
    assert ctx.shadowtls_server_name_transit == "shadowtls.example"
    assert ctx.shadowsocks2022_password_transit == "ss2022-server-key"
    assert ctx.mtproto_domain == "proxied.tracegate.test"
    assert ctx.mtproto_tls_domain == "proxied.tracegate.test"
    assert ctx.mtproto_upstream == "127.0.0.1:9443"
    assert ctx.decoy_dir == "/var/www/decoy"
    assert ctx.transit_decoy_agent_upstream == "http://127.0.0.1:8070"
    assert ctx.transit_decoy_secret_path == "/vault/mtproto/"
    assert ctx.tls_cert_file == "/etc/tracegate/tls/ws.crt"
    assert ctx.tls_key_file == "/etc/tracegate/tls/ws.key"


def test_context_does_not_require_legacy_transit_stats_secret(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["AGENT_RUNTIME_PROFILE"] = "xray-centric"

    ctx = MaterializedBundleRenderContext.from_environ(env)

    assert ctx.bootstrap_password == "bootstrap-secret"


def test_context_rejects_bracketed_reality_sni_group(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["REALITY_MULTI_INBOUND_GROUPS"] = json.dumps(
        [{"id": "broken", "port": 2501, "dest": "example.com:443", "snis": ["[example.com]"]}]
    )

    with pytest.raises(MaterializedBundleRenderError, match="invalid SNI"):
        MaterializedBundleRenderContext.from_environ(env)


def test_context_loads_private_hysteria_feature_files(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    entry_finalmask_path = tmp_path / "entry-finalmask.json"
    transit_ech_path = tmp_path / "transit-ech.txt"
    entry_finalmask_path.write_text('{"udp":[{"type":"fragment","settings":{"packets":"1-3"}}]}\n', encoding="utf-8")
    transit_ech_path.write_text("transit-ech-server-key\n", encoding="utf-8")
    env["XRAY_HYSTERIA_FINALMASK_ENTRY_FILE"] = str(entry_finalmask_path)
    env["XRAY_HYSTERIA_ECH_SERVER_KEYS_TRANSIT_FILE"] = str(transit_ech_path)

    ctx = MaterializedBundleRenderContext.from_environ(env)

    assert ctx.entry_finalmask == {"udp": [{"type": "fragment", "settings": {"packets": "1-3"}}]}
    assert ctx.transit_ech_server_keys == "transit-ech-server-key"


@pytest.mark.parametrize(
    ("missing_key", "message"),
    [
        ("REALITY_PUBLIC_KEY_TRANSIT", "REALITY_PUBLIC_KEY_TRANSIT or REALITY_PUBLIC_KEY"),
        ("REALITY_SHORT_ID_ENTRY", "REALITY_SHORT_ID_ENTRY or REALITY_SHORT_ID"),
        ("REALITY_SHORT_ID_TRANSIT", "REALITY_SHORT_ID_TRANSIT or REALITY_SHORT_ID"),
    ],
)
def test_context_requires_runtime_reality_material(tmp_path: Path, missing_key: str, message: str) -> None:
    env = _base_env(tmp_path)
    env.pop(missing_key)

    with pytest.raises(MaterializedBundleRenderError, match=message):
        MaterializedBundleRenderContext.from_environ(env)


def test_render_materialized_bundles_rewrites_runtime_files(tmp_path: Path) -> None:
    ctx = MaterializedBundleRenderContext.from_environ(_base_env(tmp_path))

    render_materialized_bundles(ctx)

    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    transit_xray = json.loads((ctx.materialized_root / "base-transit" / "xray.json").read_text(encoding="utf-8"))
    transit_ss2022_xray = json.loads(
        (ctx.materialized_root / "base-transit" / "xray-ss2022.json").read_text(encoding="utf-8")
    )
    entry_haproxy = (ctx.materialized_root / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8")
    transit_haproxy = (ctx.materialized_root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8")
    entry_nginx = (ctx.materialized_root / "base-entry" / "nginx.conf").read_text(encoding="utf-8")
    transit_nginx = (ctx.materialized_root / "base-transit" / "nginx.conf").read_text(encoding="utf-8")
    entry_nftables = (ctx.materialized_root / "base-entry" / "nftables.conf").read_text(encoding="utf-8")
    transit_nftables = (ctx.materialized_root / "base-transit" / "nftables.conf").read_text(encoding="utf-8")
    entry_hysteria = (ctx.materialized_root / "base-entry" / "hysteria" / "server.yaml").read_text(encoding="utf-8")
    transit_hysteria = (ctx.materialized_root / "base-transit" / "hysteria" / "server.yaml").read_text(
        encoding="utf-8"
    )

    entry_inbound = next(inbound for inbound in entry_xray["inbounds"] if inbound["tag"] == "entry-in")
    entry_ws_inbound = next(inbound for inbound in entry_xray["inbounds"] if inbound["tag"] == "vless-ws-in")
    entry_grpc_inbound = next(inbound for inbound in entry_xray["inbounds"] if inbound["tag"] == "vless-grpc-in")
    to_transit = next(outbound for outbound in entry_xray["outbounds"] if outbound["tag"] == "to-transit")
    transit_reality_inbound = next(inbound for inbound in transit_xray["inbounds"] if inbound["tag"] == "vless-reality-in")
    transit_ws_inbound = next(inbound for inbound in transit_xray["inbounds"] if inbound["tag"] == "vless-ws-in")
    transit_grpc_inbound = next(inbound for inbound in transit_xray["inbounds"] if inbound["tag"] == "vless-grpc-in")
    transit_ss2022_inbound = next(
        inbound for inbound in transit_ss2022_xray["inbounds"] if inbound["tag"] == "ss2022-in"
    )

    assert entry_inbound["streamSettings"]["realitySettings"]["dest"] == "origin-entry.example:443"
    assert entry_inbound["streamSettings"]["realitySettings"]["serverNames"] == ["origin-entry.example"]
    assert entry_inbound["streamSettings"]["realitySettings"]["privateKey"] == "entry-private-key"
    assert entry_inbound["streamSettings"]["realitySettings"]["shortIds"] == ["entry-short-id"]
    assert entry_inbound["streamSettings"]["network"] == "raw"
    assert entry_xray["policy"]["levels"]["0"]["handshake"] == 4
    assert entry_xray["policy"]["levels"]["0"]["connIdle"] == 300
    assert entry_xray["policy"]["levels"]["0"]["uplinkOnly"] == 2
    assert entry_xray["policy"]["levels"]["0"]["downlinkOnly"] == 5
    assert entry_ws_inbound["streamSettings"]["wsSettings"]["path"] == "/stealth/ws"
    assert entry_ws_inbound["streamSettings"]["wsSettings"]["heartbeatPeriod"] == 15
    assert entry_grpc_inbound["streamSettings"]["grpcSettings"]["serviceName"] == "tracegate.v1.Edge"
    assert to_transit["settings"]["vnext"][0]["address"] == "transit.tracegate.test"
    assert to_transit["streamSettings"]["realitySettings"]["serverName"] == "origin-transit.example"
    assert to_transit["streamSettings"]["realitySettings"]["publicKey"] == "transit-public-key"
    assert to_transit["streamSettings"]["realitySettings"]["shortId"] == "transit-short-id"
    assert to_transit["streamSettings"]["network"] == "raw"
    assert "xhttpSettings" not in to_transit["streamSettings"]

    assert transit_reality_inbound["streamSettings"]["realitySettings"]["dest"] == "origin-transit.example:443"
    assert transit_reality_inbound["streamSettings"]["realitySettings"]["serverNames"] == ["origin-transit.example"]
    assert transit_reality_inbound["streamSettings"]["realitySettings"]["privateKey"] == "transit-private-key"
    assert transit_reality_inbound["streamSettings"]["realitySettings"]["shortIds"] == ["transit-short-id"]
    assert transit_xray["policy"]["levels"]["0"]["handshake"] == 4
    assert transit_xray["policy"]["levels"]["0"]["connIdle"] == 300
    assert transit_xray["policy"]["levels"]["0"]["uplinkOnly"] == 2
    assert transit_xray["policy"]["levels"]["0"]["downlinkOnly"] == 5
    assert transit_ws_inbound["streamSettings"]["wsSettings"]["path"] == "/stealth/ws"
    assert transit_ws_inbound["streamSettings"]["wsSettings"]["heartbeatPeriod"] == 15
    assert transit_grpc_inbound["streamSettings"]["grpcSettings"]["serviceName"] == "tracegate.v1.Edge"
    assert transit_ss2022_inbound["listen"] == "127.0.0.1"
    assert transit_ss2022_inbound["port"] == 18443
    assert transit_ss2022_inbound["settings"] == {
        "network": "tcp",
        "method": "2022-blake3-aes-128-gcm",
        "password": "ss2022-server-key",
        "clients": [],
    }

    assert "hy2-in" not in {inbound["tag"] for inbound in entry_xray["inbounds"]}
    assert "hy2-in" not in {inbound["tag"] for inbound in transit_xray["inbounds"]}
    assert "listen: \"192.0.2.10:443\"" in entry_hysteria
    assert "cert: \"/etc/tls/entry.crt\"" in entry_hysteria
    assert "key: \"/etc/tls/entry.key\"" in entry_hysteria
    assert "type: gecko" in entry_hysteria
    assert "minPacketSize: 512" in entry_hysteria
    assert "maxPacketSize: 1200" in entry_hysteria
    assert "url: \"http://127.0.0.1:8070/v1/hysteria/auth\"" in entry_hysteria
    assert "password: \"entry-gecko-secret\"" in entry_hysteria
    assert "secret: \"entry-stats-secret\"" in entry_hysteria
    assert "dir: \"/srv/decoy\"" in entry_hysteria
    assert "bandwidth:\n  up: 10 mbps\n  down: 10 mbps" in entry_hysteria
    assert "ignoreClientBandwidth: false" in entry_hysteria
    assert "password: \"transit-gecko-secret\"" in transit_hysteria
    assert "secret: \"transit-stats-secret\"" in transit_hysteria
    assert "listen: \"192.0.2.20:443\"" in transit_hysteria
    assert "cert: \"/etc/tls/transit.crt\"" in transit_hysteria
    assert "key: \"/etc/tls/transit.key\"" in transit_hysteria
    assert "server mtproto transit.tracegate.test:9445 check-send-proxy send-proxy-v2" in entry_haproxy
    assert "bandwidth:" not in transit_hysteria
    assert "ignoreClientBandwidth: true" in transit_hysteria
    assert any(
        rule.get("protocol") == ["bittorrent"] and rule.get("outboundTag") == "block"
        for rule in entry_xray["routing"]["rules"]
        if isinstance(rule, dict)
    )
    assert any(
        rule.get("inboundTag") == ["entry-in", "vless-ws-in", "vless-grpc-in"]
        and rule.get("protocol") == ["bittorrent"]
        and rule.get("outboundTag") == "block"
        for rule in entry_xray["routing"]["rules"]
        if isinstance(rule, dict)
    )
    assert any(
        rule.get("inboundTag") == ["vless-reality-in", "vless-ws-in", "vless-grpc-in"]
        and rule.get("protocol") == ["bittorrent"]
        and rule.get("outboundTag") == "block"
        for rule in transit_xray["routing"]["rules"]
        if isinstance(rule, dict)
    )
    assert any(
        rule.get("inboundTag") == ["ss2022-in"]
        and rule.get("protocol") == ["bittorrent"]
        and rule.get("outboundTag") == "block"
        for rule in transit_ss2022_xray["routing"]["rules"]
        if isinstance(rule, dict)
    )
    assert not (ctx.materialized_root / "base-entry" / "hysteria.yaml").exists()
    assert not (ctx.materialized_root / "base-transit" / "hysteria.yaml").exists()

    assert "REPLACE_TLS_SERVER_NAME" not in entry_haproxy
    assert "REPLACE_ENTRY_BIND_HOST" not in entry_haproxy
    assert "bind 192.0.2.10:443" in entry_haproxy
    assert "REPLACE_TLS_SERVER_NAME" not in transit_haproxy
    assert "REPLACE_TLS_SERVER_NAME" not in entry_nginx
    assert "REPLACE_ENTRY_BIND_HOST" not in entry_nginx
    assert "listen 192.0.2.10:10444 ssl http2;" in entry_nginx
    assert "ip saddr 192.0.2.20 tcp dport 10444 accept" in entry_nftables
    assert "tcp dport 10444 drop" in entry_nftables
    assert "ip saddr 192.0.2.10 tcp dport { 9443, 9444, 9445, 9446 } accept" in transit_nftables
    assert "tcp dport { 9443, 9444, 9445, 9446 } drop" in transit_nftables
    assert "REPLACE_TLS_SERVER_NAME" not in transit_nginx
    assert "tls-entry.example" in entry_haproxy
    assert "tls-entry.example" in entry_nginx
    assert "tls-transit.example" in transit_haproxy
    assert "proxied.tracegate.test" not in transit_haproxy
    assert "be_transit_mtproto" not in transit_haproxy
    assert "127.0.0.1:9443" not in transit_haproxy
    assert "acl mtproto_tls_sni req.ssl_sni -i proxied.tracegate.test" in entry_haproxy
    assert "acl shadowtls_sni req.ssl_sni -i shadowtls.example" in transit_haproxy
    assert "use_backend be_transit_shadowtls if shadowtls_sni" in transit_haproxy
    assert "server transit_shadowtls 127.0.0.1:14443 check" in transit_haproxy
    assert "tls-transit.example" in transit_nginx
    assert "location ^~ /v1/decoy/" in transit_nginx
    assert "proxy_pass http://127.0.0.1:8070;" in transit_nginx
    assert "location = /vault/mtproto" in transit_nginx
    assert "return 302 /vault/mtproto/;" in transit_nginx
    assert "root /srv/decoy;" in entry_nginx
    assert "root /srv/decoy;" in transit_nginx
    assert "grpc_pass grpc://127.0.0.1:10001;" in entry_nginx
    assert "grpc_pass grpc://127.0.0.1:10001;" in transit_nginx
    assert "client_max_body_size 0;" in entry_nginx
    assert "client_max_body_size 0;" in transit_nginx

    manifest = json.loads((ctx.materialized_root / ".tracegate-deploy-manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == 1
    assert manifest["runtimeProfile"] == "tracegate-3"
    assert manifest["materializedRoot"] == str(ctx.materialized_root)

    bundles = {row["role"]: row for row in manifest["bundles"]}
    assert set(bundles) == {"ENTRY", "TRANSIT"}
    assert bundles["ENTRY"]["publicUnits"] == [
        "tracegate-xray@entry",
        "tracegate-hysteria@entry",
        "tracegate-haproxy@entry",
        "tracegate-nginx@entry",
    ]
    assert bundles["ENTRY"]["privateCompanions"] == ["tracegate-obfuscation@entry"]
    assert bundles["ENTRY"]["features"]["standaloneHysteriaEnabled"] is True
    assert bundles["ENTRY"]["features"]["hysteriaGeckoEnabled"] is True
    assert bundles["ENTRY"]["features"]["finalMaskEnabled"] is False
    assert bundles["ENTRY"]["features"]["echEnabled"] is False
    assert bundles["TRANSIT"]["features"]["mtprotoFrontingEnabled"] is True
    assert bundles["TRANSIT"]["features"]["mtprotoDomain"] == "proxied.tracegate.test"
    assert bundles["TRANSIT"]["privateCompanions"] == [
        "tracegate-obfuscation@transit",
        "tracegate-mtproto@transit",
    ]
    transit_files = {row["path"] for row in bundles["TRANSIT"]["files"]}
    assert "xray.json" in transit_files
    assert "hysteria/server.yaml" in transit_files
    assert "haproxy.cfg" in transit_files
    assert "nginx.conf" in transit_files
    assert not any(path.startswith("decoy/") for path in transit_files)


def test_render_materialized_bundles_routes_entry_local_mtproto_through_endpoint_ws_backhaul(
    tmp_path: Path,
) -> None:
    env = _base_env(tmp_path)
    env["MTPROTO_ROUTE_MODE"] = "entry-local-endpoint-egress"
    env["MTPROTO_TLS_DOMAIN"] = "2gis.example"
    env["MTPROTO_EGRESS_SOCKS_PORT"] = "11084"
    env["MTPROTO_ENTRY_BACKHAUL_UUID"] = "11111111-1111-4111-8111-111111111111"

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    transit_xray = json.loads((ctx.materialized_root / "base-transit" / "xray.json").read_text(encoding="utf-8"))
    entry_haproxy = (ctx.materialized_root / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8")
    transit_haproxy = (ctx.materialized_root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8")
    manifest = json.loads((ctx.materialized_root / ".tracegate-deploy-manifest.json").read_text(encoding="utf-8"))

    entry_inbounds = {row["tag"]: row for row in entry_xray["inbounds"]}
    entry_outbounds = {row["tag"]: row for row in entry_xray["outbounds"]}
    mtproto_socks = entry_inbounds["mtproto-egress-socks-in"]
    mtproto_backhaul = entry_outbounds["mtproto-egress-endpoint-ws"]
    transit_ws = next(row for row in transit_xray["inbounds"] if row["tag"] == "vless-ws-in")

    assert mtproto_socks["listen"] == "127.0.0.1"
    assert mtproto_socks["port"] == 11084
    assert mtproto_socks["protocol"] == "socks"
    assert mtproto_backhaul["settings"]["vnext"][0]["address"] == "transit.tracegate.test"
    assert mtproto_backhaul["settings"]["vnext"][0]["users"][0]["id"] == "11111111-1111-4111-8111-111111111111"
    assert mtproto_backhaul["streamSettings"]["network"] == "ws"
    assert mtproto_backhaul["streamSettings"]["tlsSettings"]["serverName"] == "tls-transit.example"
    assert mtproto_backhaul["streamSettings"]["wsSettings"]["path"] == "/stealth/ws"
    assert {
        "id": "11111111-1111-4111-8111-111111111111",
        "email": "mtproto-entry-egress",
    } in transit_ws["settings"]["clients"]
    assert entry_xray["routing"]["rules"][0] == {
        "type": "field",
        "inboundTag": ["mtproto-egress-socks-in"],
        "outboundTag": "mtproto-egress-endpoint-ws",
    }
    assert "acl mtproto_tls_sni req.ssl_sni -i 2gis.example" in entry_haproxy
    assert "use_backend be_mtproto_tls if mtproto_tls_sni" in entry_haproxy
    assert "server mtproto 127.0.0.1:9443 check send-proxy-v2" in entry_haproxy
    assert "be_transit_mtproto" not in transit_haproxy

    bundles = {row["role"]: row for row in manifest["bundles"]}
    assert "tracegate-mtproto@entry" in bundles["ENTRY"]["privateCompanions"]
    assert "tracegate-mtproto@transit" not in bundles["TRANSIT"]["privateCompanions"]
    assert bundles["ENTRY"]["features"]["mtprotoFrontingEnabled"] is True
    assert bundles["TRANSIT"]["features"]["mtprotoFrontingEnabled"] is False


def test_render_materialized_bundles_materializes_prod_style_reality_groups_and_haproxy_demux(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["REALITY_MULTI_INBOUND_GROUPS"] = json.dumps(
        [
            {
                "id": "shared-a",
                "port": 2501,
                "dest": "old-mtproto-a.tracegate-sni.ru",
                "snis": ["old-mtproto-a.tracegate-sni.ru"],
            },
            {
                "id": "shared-b",
                "port": 2502,
                "dest": "old-mtproto-b.tracegate-sni.ru:443",
                "snis": ["old-mtproto-b.tracegate-sni.ru", "st-2.tracegate-sni.ru"],
            },
        ]
    )

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    transit_xray = json.loads((ctx.materialized_root / "base-transit" / "xray.json").read_text(encoding="utf-8"))
    entry_haproxy = (ctx.materialized_root / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8")
    transit_haproxy = (ctx.materialized_root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8")

    entry_inbounds = {str(row.get("tag")): row for row in entry_xray["inbounds"]}
    transit_inbounds = {str(row.get("tag")): row for row in transit_xray["inbounds"]}

    assert ctx.reality_multi_inbound_groups[0].id == "shared-a"
    assert ctx.reality_multi_inbound_groups[1].dest_host == "old-mtproto-b.tracegate-sni.ru"

    assert entry_inbounds["entry-in-shared-a"]["port"] == 2501
    assert entry_inbounds["entry-in-shared-b"]["port"] == 2502
    assert transit_inbounds["vless-reality-in-shared-a"]["port"] == 2501
    assert transit_inbounds["vless-reality-in-shared-b"]["port"] == 2502

    assert entry_inbounds["entry-in-shared-a"]["settings"]["clients"] == []
    assert entry_inbounds["entry-in-shared-b"]["settings"]["clients"] == []
    assert transit_inbounds["vless-reality-in-shared-a"]["settings"]["clients"] == []
    assert transit_inbounds["vless-reality-in-shared-b"]["settings"]["clients"] == []
    assert transit_inbounds["vless-reality-in"]["settings"]["clients"] == [
        {"id": "00000000-0000-4000-8000-000000000123", "email": "entry-transit"}
    ]

    assert entry_inbounds["entry-in-shared-a"]["streamSettings"]["realitySettings"]["dest"] == "old-mtproto-a.tracegate-sni.ru:443"
    assert entry_inbounds["entry-in-shared-b"]["streamSettings"]["realitySettings"]["serverNames"] == [
        "old-mtproto-b.tracegate-sni.ru",
        "st-2.tracegate-sni.ru",
    ]
    assert transit_inbounds["vless-reality-in-shared-b"]["streamSettings"]["realitySettings"]["dest"] == "old-mtproto-b.tracegate-sni.ru:443"

    entry_route_tags = [
        tuple(rule.get("inboundTag") or [])
        for rule in entry_xray["routing"]["rules"]
        if isinstance(rule, dict) and "entry-in" in (rule.get("inboundTag") or [])
    ]
    transit_route_tags = [
        tuple(rule.get("inboundTag") or [])
        for rule in transit_xray["routing"]["rules"]
        if isinstance(rule, dict) and "vless-reality-in" in (rule.get("inboundTag") or [])
    ]
    assert any("entry-in-shared-a" in tags and "entry-in-shared-b" in tags for tags in entry_route_tags)
    assert any("vless-reality-in-shared-a" in tags and "vless-reality-in-shared-b" in tags for tags in transit_route_tags)

    assert "acl reality_shared_a_sni req.ssl_sni -i old-mtproto-a.tracegate-sni.ru" in entry_haproxy
    assert "acl reality_shared_b_sni req.ssl_sni -i old-mtproto-b.tracegate-sni.ru st-2.tracegate-sni.ru" in entry_haproxy
    assert "use_backend be_entry_reality_shared_a if reality_shared_a_sni" in entry_haproxy
    assert "server entry_reality_shared_b 127.0.0.1:2502 check" in entry_haproxy
    assert "acl reality_shared_b_sni req.ssl_sni -i old-mtproto-b.tracegate-sni.ru st-2.tracegate-sni.ru" in transit_haproxy
    assert "use_backend be_transit_reality_shared_b if reality_shared_b_sni" in transit_haproxy
    assert "server transit_reality_shared_a 127.0.0.1:2501 check" in transit_haproxy


def test_render_materialized_bundles_omits_mtproto_route_without_domain(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env.pop("MTPROTO_DOMAIN")

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    transit_haproxy = (ctx.materialized_root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8")
    manifest = json.loads((ctx.materialized_root / ".tracegate-deploy-manifest.json").read_text(encoding="utf-8"))
    transit_bundle = next(row for row in manifest["bundles"] if row["role"] == "TRANSIT")

    assert "be_transit_mtproto" not in transit_haproxy
    assert "127.0.0.1:9443" not in transit_haproxy
    assert transit_bundle["features"]["mtprotoFrontingEnabled"] is False
    assert transit_bundle["privateCompanions"] == ["tracegate-obfuscation@transit"]


def test_render_materialized_bundles_uses_configured_mtproto_link_upstream(tmp_path: Path) -> None:
    # entry-endpoint-tunnel mode: the Entry relays the client FakeTLS to the Telemt
    # link on the Endpoint. The relay target is configurable and preserves the real
    # client address via PROXY v2; the Endpoint public :443 has no MTProto backend.
    env = _base_env(tmp_path)
    env["MTPROTO_ENTRY_LINK_UPSTREAM"] = "198.51.100.109:9445"

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    entry_haproxy = (ctx.materialized_root / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8")
    transit_haproxy = (ctx.materialized_root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8")

    assert "server mtproto 198.51.100.109:9445 check-send-proxy send-proxy-v2" in entry_haproxy
    assert "be_transit_mtproto" not in transit_haproxy


def test_render_materialized_bundles_injects_hysteria_finalmask_and_ech(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["AGENT_RUNTIME_PROFILE"] = "xray-centric"
    entry_finalmask_path = tmp_path / "entry-finalmask.json"
    transit_finalmask_path = tmp_path / "transit-finalmask.json"
    transit_ech_path = tmp_path / "transit-ech.txt"
    entry_finalmask_path.write_text('{"udp":[{"type":"sudoku","settings":{"pad":2}}]}\n', encoding="utf-8")
    transit_finalmask_path.write_text('{"udp":[{"type":"fragment","settings":{"packets":"2-4"}}]}\n', encoding="utf-8")
    transit_ech_path.write_text("transit-ech-server-key\n", encoding="utf-8")
    env["XRAY_HYSTERIA_FINALMASK_ENTRY_FILE"] = str(entry_finalmask_path)
    env["XRAY_HYSTERIA_FINALMASK_TRANSIT_FILE"] = str(transit_finalmask_path)
    env["XRAY_HYSTERIA_ECH_SERVER_KEYS_TRANSIT_FILE"] = str(transit_ech_path)

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    transit_xray = json.loads((ctx.materialized_root / "base-transit" / "xray.json").read_text(encoding="utf-8"))
    entry_hy2_inbound = next(inbound for inbound in entry_xray["inbounds"] if inbound["tag"] == "hy2-in")
    transit_hy2_inbound = next(inbound for inbound in transit_xray["inbounds"] if inbound["tag"] == "hy2-in")
    manifest = json.loads((ctx.materialized_root / ".tracegate-deploy-manifest.json").read_text(encoding="utf-8"))
    bundles = {row["role"]: row for row in manifest["bundles"]}

    assert entry_hy2_inbound["streamSettings"]["finalmask"] == {"udp": [{"type": "sudoku", "settings": {"pad": 2}}]}
    assert transit_hy2_inbound["streamSettings"]["finalmask"] == {
        "udp": [{"type": "fragment", "settings": {"packets": "2-4"}}]
    }
    assert transit_hy2_inbound["streamSettings"]["tlsSettings"]["echServerKeys"] == "transit-ech-server-key"
    assert bundles["ENTRY"]["features"]["finalMaskEnabled"] is True
    assert bundles["ENTRY"]["features"]["echEnabled"] is False
    assert bundles["TRANSIT"]["features"]["finalMaskEnabled"] is True
    assert bundles["TRANSIT"]["features"]["echEnabled"] is True


def test_render_materialized_bundles_applies_private_overlays(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    overlay_root = tmp_path / "private-overlays"
    env["BUNDLE_PRIVATE_OVERLAY_ROOT"] = str(overlay_root)

    _write(
        overlay_root / "entry" / "xray.merge.json",
        '{"log": {"loglevel": "debug"}, "stats": {"operatorOverlay": true}}\n',
    )
    _write(
        overlay_root / "transit" / "xray.merge.json",
        '{"routing": {"domainStrategy": "IPOnDemand"}}\n',
    )
    _write(
        overlay_root / "entry" / "haproxy.cfg",
        "frontend private_entry\n  bind :443\n",
    )
    _write(
        overlay_root / "entry" / "nftables.conf",
        "table inet filter { chain input { type filter hook input priority 0; policy drop;\n"
        "    ip protocol icmp accept\n  } }\n",
    )
    _write(
        overlay_root / "transit" / "decoy" / "index.html",
        "<html><body>private transit decoy</body></html>\n",
    )

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    transit_xray = json.loads((ctx.materialized_root / "base-transit" / "xray.json").read_text(encoding="utf-8"))
    entry_haproxy = (ctx.materialized_root / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8")
    entry_nftables = (ctx.materialized_root / "base-entry" / "nftables.conf").read_text(encoding="utf-8")
    transit_decoy = (ctx.materialized_root / "base-transit" / "decoy" / "index.html").read_text(encoding="utf-8")

    assert entry_xray["log"]["loglevel"] == "debug"
    assert entry_xray["stats"]["operatorOverlay"] is True
    assert transit_xray["routing"]["domainStrategy"] == "IPOnDemand"
    assert entry_haproxy == "frontend private_entry\n  bind :443\n"
    assert "ip saddr 192.0.2.20 tcp dport 10444 accept" in entry_nftables
    assert "tcp dport 10444 drop" in entry_nftables
    assert transit_decoy == "<html><body>private transit decoy</body></html>\n"


def test_entry_mask_firewall_uses_endpoint_primary_source_address(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["MTPROTO_ENTRY_LINK_UPSTREAM"] = "198.51.100.25:9445"

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    entry_nftables = (ctx.materialized_root / "base-entry" / "nftables.conf").read_text(encoding="utf-8")
    assert "ip saddr 198.51.100.25 tcp dport 10444 accept" in entry_nftables
    assert "ip saddr 192.0.2.20 tcp dport 10444 accept" not in entry_nftables


def test_render_materialized_bundles_does_not_emit_legacy_hysteria_yaml(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["AGENT_RUNTIME_PROFILE"] = "xray-centric"

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    assert not (ctx.materialized_root / "base-entry" / "hysteria.yaml").exists()
    assert not (ctx.materialized_root / "base-transit" / "hysteria.yaml").exists()
    assert not (ctx.materialized_root / "base-entry" / "hysteria" / "server.yaml").exists()
    assert not (ctx.materialized_root / "base-transit" / "hysteria" / "server.yaml").exists()


def test_render_materialized_bundles_supports_custom_transit_secret_path_and_agent_upstream(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["BUNDLE_PRIVATE_OVERLAY_ROOT"] = str(tmp_path / "private-overlays")
    env["AGENT_PORT"] = "9080"
    env["TRANSIT_DECOY_SECRET_PATH"] = "/hidden/vault/"
    _write(tmp_path / "private-overlays" / "transit" / "decoy" / "vault" / "mtproto" / "index.html", "<html>vault</html>\n")

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    transit_nginx = (ctx.materialized_root / "base-transit" / "nginx.conf").read_text(encoding="utf-8")

    assert "proxy_pass http://127.0.0.1:9080;" in transit_nginx
    assert "return 302 /hidden/vault/;" in transit_nginx
    assert (ctx.materialized_root / "base-transit" / "decoy" / "hidden" / "vault" / "index.html").read_text(
        encoding="utf-8"
    ) == "<html>vault</html>\n"


def _entry_outbound_tags(ctx: MaterializedBundleRenderContext) -> list[str]:
    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    return [str(o.get("tag") or "") for o in entry_xray.get("outbounds", [])]


def test_backhaul_pool_omitted_without_ss2022_key(tmp_path: Path) -> None:
    # Staging default: with no SS2022 backhaul key the Entry runtime must stay on
    # the REALITY-RAW leg only, never emitting a placeholder SS2022 password.
    ctx = MaterializedBundleRenderContext.from_environ(_base_env(tmp_path))
    render_materialized_bundles(ctx)

    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    assert "to-transit-ss" not in _entry_outbound_tags(ctx)
    assert "to-transit-ss2" not in _entry_outbound_tags(ctx)
    assert "observatory" not in entry_xray
    to_transit = next(o for o in entry_xray["outbounds"] if o.get("tag") == "to-transit")
    assert to_transit["settings"]["vnext"][0]["port"] == 9446
    # single-transport mode: no balancer/observatory, Chain routes straight at to-transit.
    assert not entry_xray["routing"].get("balancers")
    assert not any("balancerTag" in r for r in entry_xray["routing"]["rules"] if isinstance(r, dict))
    assert any(
        r.get("outboundTag") == "to-transit" and "entry-in" in (r.get("inboundTag") or [])
        for r in entry_xray["routing"]["rules"]
        if isinstance(r, dict)
    )

    ss2022 = json.loads((ctx.materialized_root / "base-transit" / "xray-ss2022.json").read_text(encoding="utf-8"))
    assert all(i.get("tag") != "ss2022-backhaul-in" for i in ss2022["inbounds"])
    blob = json.dumps(entry_xray) + json.dumps(ss2022)
    assert "REPLACE_" not in blob


def test_backhaul_pool_provisioned_with_ss2022_key(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["SHADOWSOCKS2022_BACKHAUL_KEY"] = "backhaul-256-key"
    env["SHADOWTLS_BACKHAUL2_SNI"] = "leg2-front.example"
    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    outbounds = {str(o.get("tag") or ""): o for o in entry_xray["outbounds"]}
    # Pool = two SS2022+ShadowTLS legs (loopback 15443 / 15444) + the REALITY-RAW leg.
    assert "to-transit-ss" in outbounds
    assert "to-transit-ss2" in outbounds
    for leg, loopback in (("to-transit-ss", 15443), ("to-transit-ss2", 15444)):
        ss_server = outbounds[leg]["settings"]["servers"][0]
        assert ss_server["password"] == "backhaul-256-key"
        assert ss_server["method"] == "2022-blake3-aes-256-gcm"
        assert ss_server["address"] == "127.0.0.1"
        assert ss_server["port"] == loopback
    assert entry_xray["observatory"]["subjectSelector"] == ["to-transit"]
    assert "ObservatoryService" in entry_xray["api"]["services"]
    # REALITY-RAW leg lands on the dedicated source-gated port (default 9446).
    assert outbounds["to-transit"]["settings"]["vnext"][0]["port"] == 9446
    # Chain prefers the ShadowTLS legs; REALITY is used only when all primary
    # candidates are unavailable.
    balancers = {b["tag"]: b for b in entry_xray["routing"].get("balancers", [])}
    assert "backhaul-balancer" in balancers
    assert balancers["backhaul-balancer"]["selector"] == ["to-transit-ss"]
    assert balancers["backhaul-balancer"]["fallbackTag"] == "to-transit"
    assert balancers["backhaul-balancer"]["strategy"]["type"] == "leastPing"
    assert any(
        r.get("balancerTag") == "backhaul-balancer" and "entry-in" in (r.get("inboundTag") or [])
        for r in entry_xray["routing"]["rules"]
        if isinstance(r, dict)
    )
    # Endpoint terminates the REALITY backhaul leg on the dedicated source-gated port.
    transit_haproxy = (ctx.materialized_root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8")
    assert "frontend fe_transit_reality_backhaul" in transit_haproxy
    assert "bind :9446" in transit_haproxy

    ss2022 = json.loads((ctx.materialized_root / "base-transit" / "xray-ss2022.json").read_text(encoding="utf-8"))
    backhaul_in = next(i for i in ss2022["inbounds"] if i.get("tag") == "ss2022-backhaul-in")
    assert backhaul_in["settings"]["password"] == "backhaul-256-key"
    assert backhaul_in["settings"]["method"] == "2022-blake3-aes-256-gcm"
    assert backhaul_in["port"] == 18444
