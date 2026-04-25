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
        "REALITY_PUBLIC_KEY_TRANSIT": "transit-public-key",
        "REALITY_SHORT_ID_ENTRY": "entry-short-id",
        "REALITY_SHORT_ID_TRANSIT": "transit-short-id",
        "REALITY_PRIVATE_KEY_ENTRY": "entry-private-key",
        "REALITY_PRIVATE_KEY_TRANSIT": "transit-private-key",
        "REALITY_DEST_ENTRY": "origin-entry.example:443",
        "REALITY_DEST_TRANSIT": "origin-transit.example:443",
        "ENTRY_TLS_SERVER_NAME": "tls-entry.example",
        "TRANSIT_TLS_SERVER_NAME": "tls-transit.example",
        "MTPROTO_DOMAIN": "proxied.tracegate.test",
        "XRAY_CENTRIC_DECOY_DIR": "/srv/decoy",
    }


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.mark.parametrize(
    ("dest", "expected"),
    [
        ("splitter.wb.ru:443", "splitter.wb.ru"),
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
    assert ctx.mtproto_domain == "proxied.tracegate.test"
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
    entry_haproxy = (ctx.materialized_root / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8")
    transit_haproxy = (ctx.materialized_root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8")
    entry_nginx = (ctx.materialized_root / "base-entry" / "nginx.conf").read_text(encoding="utf-8")
    transit_nginx = (ctx.materialized_root / "base-transit" / "nginx.conf").read_text(encoding="utf-8")

    entry_inbound = next(inbound for inbound in entry_xray["inbounds"] if inbound["tag"] == "entry-in")
    entry_ws_inbound = next(inbound for inbound in entry_xray["inbounds"] if inbound["tag"] == "vless-ws-in")
    entry_grpc_inbound = next(inbound for inbound in entry_xray["inbounds"] if inbound["tag"] == "vless-grpc-in")
    entry_hy2_inbound = next(inbound for inbound in entry_xray["inbounds"] if inbound["tag"] == "hy2-in")
    to_transit = next(outbound for outbound in entry_xray["outbounds"] if outbound["tag"] == "to-transit")
    transit_reality_inbound = next(inbound for inbound in transit_xray["inbounds"] if inbound["tag"] == "vless-reality-in")
    transit_ws_inbound = next(inbound for inbound in transit_xray["inbounds"] if inbound["tag"] == "vless-ws-in")
    transit_grpc_inbound = next(inbound for inbound in transit_xray["inbounds"] if inbound["tag"] == "vless-grpc-in")
    transit_hy2_inbound = next(inbound for inbound in transit_xray["inbounds"] if inbound["tag"] == "hy2-in")

    assert entry_inbound["streamSettings"]["realitySettings"]["dest"] == "origin-entry.example:443"
    assert entry_inbound["streamSettings"]["realitySettings"]["serverNames"] == ["origin-entry.example"]
    assert entry_inbound["streamSettings"]["realitySettings"]["privateKey"] == "entry-private-key"
    assert entry_inbound["streamSettings"]["realitySettings"]["shortIds"] == ["entry-short-id"]
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

    assert entry_hy2_inbound["protocol"] == "hysteria"
    assert entry_hy2_inbound["streamSettings"]["hysteriaSettings"]["auth"] == "bootstrap-secret"
    assert entry_hy2_inbound["streamSettings"]["hysteriaSettings"]["masquerade"]["dir"] == "/srv/decoy"
    assert entry_hy2_inbound["streamSettings"]["tlsSettings"]["certificates"] == [
        {"certificateFile": "/etc/tracegate/tls/ws.crt", "keyFile": "/etc/tracegate/tls/ws.key"}
    ]
    assert entry_hy2_inbound["streamSettings"]["tlsSettings"]["alpn"] == ["h3"]
    assert transit_hy2_inbound["protocol"] == "hysteria"
    assert transit_hy2_inbound["streamSettings"]["hysteriaSettings"]["auth"] == "bootstrap-secret"
    assert transit_hy2_inbound["streamSettings"]["hysteriaSettings"]["masquerade"]["dir"] == "/srv/decoy"
    assert transit_hy2_inbound["streamSettings"]["tlsSettings"]["certificates"] == [
        {"certificateFile": "/etc/tracegate/tls/ws.crt", "keyFile": "/etc/tracegate/tls/ws.key"}
    ]
    assert transit_hy2_inbound["streamSettings"]["tlsSettings"]["alpn"] == ["h3"]
    assert any(
        rule.get("protocol") == ["bittorrent"] and rule.get("outboundTag") == "block"
        for rule in entry_xray["routing"]["rules"]
        if isinstance(rule, dict)
    )
    assert any(
        rule.get("inboundTag") == ["entry-in", "vless-ws-in", "vless-grpc-in", "hy2-in"]
        and rule.get("protocol") == ["bittorrent"]
        and rule.get("outboundTag") == "block"
        for rule in entry_xray["routing"]["rules"]
        if isinstance(rule, dict)
    )
    assert any(
        rule.get("inboundTag") == ["vless-reality-in", "vless-ws-in", "vless-grpc-in", "hy2-in"]
        and rule.get("protocol") == ["bittorrent"]
        and rule.get("outboundTag") == "block"
        for rule in transit_xray["routing"]["rules"]
        if isinstance(rule, dict)
    )
    assert not (ctx.materialized_root / "base-entry" / "hysteria.yaml").exists()
    assert not (ctx.materialized_root / "base-transit" / "hysteria.yaml").exists()

    assert "REPLACE_TLS_SERVER_NAME" not in entry_haproxy
    assert "REPLACE_TLS_SERVER_NAME" not in transit_haproxy
    assert "REPLACE_TLS_SERVER_NAME" not in entry_nginx
    assert "REPLACE_TLS_SERVER_NAME" not in transit_nginx
    assert "tls-entry.example" in entry_haproxy
    assert "tls-entry.example" in entry_nginx
    assert "tls-transit.example" in transit_haproxy
    assert "proxied.tracegate.test" in transit_haproxy
    assert "be_transit_mtproto" in transit_haproxy
    assert "127.0.0.1:9443" in transit_haproxy
    assert "tls-transit.example" in transit_nginx
    assert "location ^~ /v1/decoy/" in transit_nginx
    assert "proxy_pass http://127.0.0.1:8070;" in transit_nginx
    assert "location = /vault/mtproto" in transit_nginx
    assert "return 302 /vault/mtproto/;" in transit_nginx
    assert "root /srv/decoy;" in entry_nginx
    assert "root /srv/decoy;" in transit_nginx
    assert "grpc_pass grpc://127.0.0.1:10001;" in entry_nginx
    assert "grpc_pass grpc://127.0.0.1:10001;" in transit_nginx

    manifest = json.loads((ctx.materialized_root / ".tracegate-deploy-manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == 1
    assert manifest["runtimeProfile"] == "xray-centric"
    assert manifest["materializedRoot"] == str(ctx.materialized_root)

    bundles = {row["role"]: row for row in manifest["bundles"]}
    assert set(bundles) == {"ENTRY", "TRANSIT"}
    assert bundles["ENTRY"]["publicUnits"] == [
        "tracegate-xray@entry",
        "tracegate-haproxy@entry",
        "tracegate-nginx@entry",
    ]
    assert bundles["ENTRY"]["privateCompanions"] == ["tracegate-obfuscation@entry"]
    assert bundles["ENTRY"]["features"]["finalMaskEnabled"] is False
    assert bundles["ENTRY"]["features"]["echEnabled"] is False
    assert bundles["TRANSIT"]["features"]["mtprotoFrontingEnabled"] is True
    assert bundles["TRANSIT"]["features"]["mtprotoDomain"] == "proxied.tracegate.test"
    assert bundles["TRANSIT"]["privateCompanions"] == [
        "tracegate-obfuscation@transit",
        "tracegate-fronting@transit",
        "tracegate-mtproto@transit",
    ]
    transit_files = {row["path"] for row in bundles["TRANSIT"]["files"]}
    assert "xray.json" in transit_files
    assert "haproxy.cfg" in transit_files
    assert "nginx.conf" in transit_files
    assert not any(path.startswith("decoy/") for path in transit_files)


def test_render_materialized_bundles_materializes_prod_style_reality_groups_and_haproxy_demux(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["REALITY_MULTI_INBOUND_GROUPS"] = json.dumps(
        [
            {
                "id": "shared-a",
                "port": 2501,
                "dest": "splitter.wb.ru",
                "snis": ["splitter.wb.ru"],
            },
            {
                "id": "shared-b",
                "port": 2502,
                "dest": "st.ozone.ru:443",
                "snis": ["st.ozone.ru", "st-2.ozone.ru"],
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
    assert ctx.reality_multi_inbound_groups[1].dest_host == "st.ozone.ru"

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

    assert entry_inbounds["entry-in-shared-a"]["streamSettings"]["realitySettings"]["dest"] == "splitter.wb.ru:443"
    assert entry_inbounds["entry-in-shared-b"]["streamSettings"]["realitySettings"]["serverNames"] == [
        "st-2.ozone.ru",
        "st.ozone.ru",
    ]
    assert transit_inbounds["vless-reality-in-shared-b"]["streamSettings"]["realitySettings"]["dest"] == "st.ozone.ru:443"

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

    assert "acl reality_shared_a_sni req.ssl_sni -i splitter.wb.ru" in entry_haproxy
    assert "acl reality_shared_b_sni req.ssl_sni -i st-2.ozone.ru st.ozone.ru" in entry_haproxy
    assert "use_backend be_entry_reality_shared_a if reality_shared_a_sni" in entry_haproxy
    assert "server entry_reality_shared_b 127.0.0.1:2502 check" in entry_haproxy
    assert "acl reality_shared_b_sni req.ssl_sni -i st-2.ozone.ru st.ozone.ru" in transit_haproxy
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


def test_render_materialized_bundles_uses_configured_mtproto_upstream(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["MTPROTO_HAPROXY_UPSTREAM"] = "185.105.108.109:9443"

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    transit_haproxy = (ctx.materialized_root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8")

    assert "server transit_mtproto 185.105.108.109:9443 check" in transit_haproxy


def test_render_materialized_bundles_injects_hysteria_finalmask_and_ech(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
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
        overlay_root / "transit" / "decoy" / "index.html",
        "<html><body>private transit decoy</body></html>\n",
    )

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    transit_xray = json.loads((ctx.materialized_root / "base-transit" / "xray.json").read_text(encoding="utf-8"))
    entry_haproxy = (ctx.materialized_root / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8")
    transit_decoy = (ctx.materialized_root / "base-transit" / "decoy" / "index.html").read_text(encoding="utf-8")

    assert entry_xray["log"]["loglevel"] == "debug"
    assert entry_xray["stats"]["operatorOverlay"] is True
    assert transit_xray["routing"]["domainStrategy"] == "IPOnDemand"
    assert entry_haproxy == "frontend private_entry\n  bind :443\n"
    assert transit_decoy == "<html><body>private transit decoy</body></html>\n"


def test_render_materialized_bundles_does_not_emit_legacy_hysteria_yaml(tmp_path: Path) -> None:
    env = _base_env(tmp_path)
    env["AGENT_RUNTIME_PROFILE"] = "xray-centric"

    ctx = MaterializedBundleRenderContext.from_environ(env)
    render_materialized_bundles(ctx)

    assert not (ctx.materialized_root / "base-entry" / "hysteria.yaml").exists()
    assert not (ctx.materialized_root / "base-transit" / "hysteria.yaml").exists()


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
