import json
import os
from pathlib import Path

import pytest

from tracegate.agent.reconcile import _xray_structural_reload_required, reconcile_all
from tracegate.services.runtime_preflight import (
    load_fronting_runtime_state,
    load_mtproto_gateway_state,
    load_mtproto_public_profile,
    load_obfuscation_runtime_env,
    load_obfuscation_runtime_state,
    validate_fronting_runtime_state,
    validate_mtproto_gateway_state,
    validate_obfuscation_runtime_env,
    validate_obfuscation_runtime_state,
)
from tracegate.settings import Settings


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _fingerprint(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {"sizeBytes": int(stat.st_size), "mtimeNs": int(stat.st_mtime_ns)}


def _write_k3s_reload_marker(root: Path, *, component: str, role: str, include_summary_schema: bool = True) -> Path:
    role_lower = role.lower()
    component_dir = {"profiles": "profiles", "link-crypto": "link-crypto"}[component]
    state_path = root / component_dir / role_lower / "desired-state.json"
    env_path = root / component_dir / role_lower / "desired-state.env"
    marker_path = root / "runtime" / f"{component}-{role_lower}-last-reload.json"
    marker = {
        "schema": "tracegate.k3s-private-reload.v1",
        "component": component,
        "role": role.upper(),
        "summary": {"sources": {"state": _fingerprint(state_path), "env": _fingerprint(env_path)}},
    }
    if component == "link-crypto":
        router_root = root / "router" / role_lower
        router_sources = {
            "state": router_root / "desired-state.json",
            "env": router_root / "desired-state.env",
            "clientBundle": router_root / "client-bundle.json",
            "clientEnv": router_root / "client-bundle.env",
        }
        if all(path.exists() for path in router_sources.values()):
            marker["summary"]["router"] = {
                "sources": {key: _fingerprint(path) for key, path in router_sources.items()}
            }
    if include_summary_schema:
        marker["summarySchema"] = "tracegate.k3s-private-reload-summary.v1"
    _write(marker_path, json.dumps(marker) + "\n")
    return marker_path


def test_xray_structural_reload_required_ignores_live_managed_client_lists() -> None:
    current = {
        "inbounds": [
            {"protocol": "vless", "settings": {"clients": [{"id": "old"}]}},
            {"protocol": "hysteria", "settings": {"clients": [{"auth": "old"}]}},
        ]
    }
    desired = {
        "inbounds": [
            {"protocol": "vless", "settings": {"clients": [{"id": "new"}]}},
            {"protocol": "hysteria", "settings": {"clients": [{"auth": "new"}]}},
        ]
    }

    assert _xray_structural_reload_required(current, desired) is False


def test_xray_structural_reload_required_detects_reality_server_name_changes() -> None:
    current = {
        "inbounds": [
            {
                "protocol": "vless",
                "settings": {"clients": [{"id": "c1"}]},
                "streamSettings": {"security": "reality", "realitySettings": {"serverNames": ["splitter.wb.ru"]}},
            }
        ]
    }
    desired = {
        "inbounds": [
            {
                "protocol": "vless",
                "settings": {"clients": [{"id": "c2"}]},
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {"serverNames": ["splitter.wb.ru", "www.wildberries.ru"]},
                },
            }
        ]
    }

    assert _xray_structural_reload_required(current, desired) is True


def test_xray_structural_reload_required_detects_routing_rule_changes() -> None:
    current = {
        "inbounds": [{"protocol": "vless", "settings": {"clients": [{"id": "c1"}]}}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["vless-reality-in"], "outboundTag": "direct"}]},
    }
    desired = {
        "inbounds": [{"protocol": "vless", "settings": {"clients": [{"id": "c2"}]}}],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["vless-reality-in", "hy2-in"],
                    "protocol": ["bittorrent"],
                    "outboundTag": "block",
                },
                {"type": "field", "inboundTag": ["vless-reality-in"], "outboundTag": "direct"},
            ]
        },
    }

    assert _xray_structural_reload_required(current, desired) is True


def test_reconcile_xray_centric_updates_vless_and_hysteria_inbounds(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
    )

    # Seed base configs (simulates initContainer behaviour).
    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "vless-reality-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "reality", "realitySettings": {"serverNames": []}},
                    },
                    {
                        "tag": "vless-ws-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "tls", "network": "ws"},
                    },
                    {
                        "tag": "vless-grpc-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "none", "network": "grpc"},
                    },
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "none",
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": "/var/www/decoy"},
                            },
                        },
                    }
                ],
                "outbounds": [{"protocol": "freedom"}],
            }
        ),
    )

    # Existing artifacts.
    _write(
        tmp_path / "users/u1/connection-c1.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "c1",
                "revision_id": "r1",
                "protocol": "vless_reality",
                "config": {"uuid": "c1", "sni": "splitter.wb.ru"},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-c2.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "c2",
                "revision_id": "r2",
                "protocol": "hysteria2",
                "config": {"auth": {"type": "userpass", "username": "u1", "password": "d1"}},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-c3.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "c3",
                "revision_id": "r3",
                "protocol": "vless_ws_tls",
                "config": {"uuid": "c3", "sni": "t.example.com", "ws": {"path": "/ws"}},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-c4.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "c4",
                "revision_id": "r4",
                "protocol": "vless_grpc_tls",
                "config": {"uuid": "c4", "sni": "t.example.com", "grpc": {"service_name": "tracegate.v1.Edge"}},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray"]

    rendered_xray = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert rendered_xray["inbounds"][0]["settings"]["clients"][0]["id"] == "c1"
    assert "splitter.wb.ru" in rendered_xray["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"]
    assert rendered_xray["inbounds"][1]["settings"]["clients"][0]["id"] == "c3"
    assert rendered_xray["inbounds"][2]["settings"]["clients"][0]["id"] == "c4"
    assert rendered_xray["inbounds"][3]["settings"]["clients"] == [{"auth": "u1:d1", "email": "V? - u1 - c2"}]
    assert not (tmp_path / "runtime/hysteria/config.yaml").exists()

    # Second run should be a no-op (no unnecessary reload triggers).
    changed2 = reconcile_all(settings)
    assert changed2 == []


def test_reconcile_entry_updates_xray_only_in_xray_centric_runtime(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "entry-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "reality", "realitySettings": {"serverNames": []}},
                    }
                ],
                "outbounds": [{"protocol": "freedom"}],
            }
        ),
    )
    _write(
        tmp_path / "users/u2/connection-c1.json",
        json.dumps(
            {
                "user_id": "u2",
                "device_id": "d2",
                "connection_id": "c1",
                "revision_id": "r1",
                "protocol": "vless_reality",
                "config": {"uuid": "c1", "sni": "vk.com"},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray"]
    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert rendered["inbounds"][0]["streamSettings"]["realitySettings"]["dest"] == "vk.com:443"
    assert not (tmp_path / "runtime/hysteria/config.yaml").exists()


def test_reconcile_proxy_passthrough_components(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="ENTRY",
    )

    _write(tmp_path / "base/haproxy/haproxy.cfg", "frontend fe\n  bind :443\n")
    _write(tmp_path / "base/nginx/nginx.conf", "events {}\nhttp {}\n")

    changed = reconcile_all(settings)

    assert "haproxy" in changed
    assert "nginx" in changed
    assert (tmp_path / "runtime/haproxy/haproxy.cfg").read_text(encoding="utf-8") == "frontend fe\n  bind :443\n"
    assert (tmp_path / "runtime/nginx/nginx.conf").read_text(encoding="utf-8") == "events {}\nhttp {}\n"

    changed2 = reconcile_all(settings)
    assert "haproxy" not in changed2
    assert "nginx" not in changed2

    runtime_nginx = tmp_path / "runtime/nginx/nginx.conf"
    runtime_inode = runtime_nginx.stat().st_ino
    _write(tmp_path / "base/nginx/nginx.conf", "events {}\nhttp { client_max_body_size 0; }\n")

    changed3 = reconcile_all(settings)

    assert "nginx" in changed3
    assert runtime_nginx.read_text(encoding="utf-8") == "events {}\nhttp { client_max_body_size 0; }\n"
    assert runtime_nginx.stat().st_ino == runtime_inode


def test_reconcile_syncs_base_decoy_tree_into_active_runtime_root(tmp_path: Path) -> None:
    decoy_root = tmp_path / "public-decoy"
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "none",
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": str(decoy_root)},
                            },
                        },
                    }
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "direct"}]},
            }
        ),
    )
    _write(
        tmp_path / "base/nginx/nginx.conf",
        (
            "events {}\n"
            "http {\n"
            "  server {\n"
            f"    root {decoy_root};\n"
            "  }\n"
            "}\n"
        ),
    )
    _write(tmp_path / "base/decoy/index.html", "<html>Tracegate</html>\n")
    _write(tmp_path / "base/decoy/auth/index.html", "<html>Vault</html>\n")

    changed = reconcile_all(settings)

    assert changed == ["xray", "nginx", "decoy"]
    assert (decoy_root / "index.html").read_text(encoding="utf-8") == "<html>Tracegate</html>\n"
    assert (decoy_root / "auth/index.html").read_text(encoding="utf-8") == "<html>Vault</html>\n"
    assert (decoy_root.stat().st_mode & 0o777) == 0o755
    assert ((decoy_root / "auth").stat().st_mode & 0o777) == 0o755
    assert ((decoy_root / "index.html").stat().st_mode & 0o777) == 0o644
    assert ((decoy_root / "auth/index.html").stat().st_mode & 0o777) == 0o644
    manifest = json.loads((decoy_root / ".tracegate-sync-manifest.json").read_text(encoding="utf-8"))
    assert manifest == {"version": 1, "files": ["auth/index.html", "index.html"]}
    assert ((decoy_root / ".tracegate-sync-manifest.json").stat().st_mode & 0o777) == 0o644

    changed2 = reconcile_all(settings)
    assert changed2 == []


def test_reconcile_tracegate22_passthroughs_standalone_hysteria_and_strips_xray_hy2(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="tracegate-2.2",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {"tag": "vless-reality-in", "protocol": "vless", "settings": {"clients": []}},
                    {"tag": "hy2-in", "protocol": "hysteria", "settings": {"clients": []}},
                ],
                "routing": {
                    "rules": [
                        {
                            "type": "field",
                            "inboundTag": ["vless-reality-in", "hy2-in"],
                            "protocol": ["bittorrent"],
                            "outboundTag": "block",
                        }
                    ]
                },
                "outbounds": [{"protocol": "freedom"}],
            }
        ),
    )
    _write(tmp_path / "base/hysteria/server.yaml", "listen: :443\nobfs:\n  type: salamander\n")

    changed = reconcile_all(settings)

    assert "xray" in changed
    assert "hysteria" in changed
    rendered_xray = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert [row["tag"] for row in rendered_xray["inbounds"]] == ["vless-reality-in"]
    assert rendered_xray["routing"]["rules"][0]["inboundTag"] == ["vless-reality-in"]
    assert (tmp_path / "runtime/hysteria/server.yaml").read_text(encoding="utf-8") == (
        "listen: :443\nobfs:\n  type: salamander\n"
    )


def test_reconcile_prunes_stale_managed_decoy_files(tmp_path: Path) -> None:
    decoy_root = tmp_path / "public-decoy"
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "none",
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": str(decoy_root)},
                            },
                        },
                    }
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "direct"}]},
            }
        ),
    )
    _write(
        tmp_path / "base/nginx/nginx.conf",
        (
            "events {}\n"
            "http {\n"
            "  server {\n"
            f"    root {decoy_root};\n"
            "  }\n"
            "}\n"
        ),
    )
    _write(tmp_path / "base/decoy/index.html", "<html>Fresh</html>\n")
    _write(decoy_root / "legacy/index.html", "<html>Legacy</html>\n")
    _write(
        decoy_root / ".tracegate-sync-manifest.json",
        json.dumps({"version": 1, "files": ["legacy/index.html"]}, ensure_ascii=True, indent=2) + "\n",
    )

    changed = reconcile_all(settings)

    assert changed == ["xray", "nginx", "decoy"]
    assert not (decoy_root / "legacy/index.html").exists()
    assert (decoy_root / "index.html").read_text(encoding="utf-8") == "<html>Fresh</html>\n"


def test_reconcile_xray_populates_xray_native_hysteria_inbound_clients(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "none",
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": "/var/www/decoy"},
                            },
                        },
                    }
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "direct"}]},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-c2.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "c2",
                "revision_id": "r2",
                "variant": "V3",
                "protocol": "hysteria2",
                "config": {
                    "auth": {
                        "type": "userpass",
                        "username": "v3_u1_c2",
                        "password": "d1",
                        "token": "v3_u1_c2:d1",
                    }
                },
            }
        ),
    )

    changed = reconcile_all(settings)

    assert changed == ["xray"]
    rendered_xray = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    hy2_in = next(inbound for inbound in rendered_xray["inbounds"] if inbound["tag"] == "hy2-in")
    assert hy2_in["settings"]["clients"] == [{"auth": "v3_u1_c2:d1", "email": "V3 - u1 - c2"}]

    changed2 = reconcile_all(settings)
    assert changed2 == []


def test_reconcile_xray_populates_xray_native_shadowsocks2022_clients(tmp_path: Path) -> None:
    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "ss2022-in",
                        "listen": "127.0.0.1",
                        "port": 18443,
                        "protocol": "shadowsocks",
                        "settings": {
                            "network": "tcp",
                            "method": "2022-blake3-aes-128-gcm",
                            "password": "server-key",
                            "clients": [],
                        },
                    }
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            }
        ),
    )
    _write(
        tmp_path / "users/123/connection-conn-v3.json",
        json.dumps(
            {
                "user_id": "123",
                "connection_id": "conn-v3",
                "revision_id": "rev-v3",
                "protocol": "shadowsocks2022_shadowtls",
                "variant": "V3",
                "mode": "direct",
                "config": {
                    "password": "server-key:user-key",
                    "method": "2022-blake3-aes-128-gcm",
                },
            }
        ),
    )
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_role="TRANSIT",
        agent_runtime_profile="tracegate-2.2",
    )

    changed = reconcile_all(settings)

    assert "xray" in changed
    runtime = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    inbound = next(row for row in runtime["inbounds"] if row.get("tag") == "ss2022-in")
    assert inbound["settings"]["clients"] == [
        {
            "password": "user-key",
            "email": "V3 - 123 - conn-v3",
        }
    ]
    assert reconcile_all(settings) == []


def test_reconcile_xray_centric_prunes_stale_hysteria_runtime_state(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "none",
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": "/var/www/decoy"},
                            },
                        },
                    }
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "direct"}]},
            }
        ),
    )
    _write(tmp_path / "runtime/hysteria/config.yaml", "listen: :4443\n")
    _write(
        tmp_path / "runtime/hysteria/auth.json",
        json.dumps({"legacy-user": {"password": "secret", "id": "legacy-user", "token": "legacy-token"}}),
    )

    changed = reconcile_all(settings)

    assert changed == ["xray"]
    assert (tmp_path / "runtime/xray/config.json").exists()
    assert not (tmp_path / "runtime/hysteria/config.yaml").exists()
    assert not (tmp_path / "runtime/hysteria/auth.json").exists()

    runtime_contract = json.loads((tmp_path / "runtime/runtime-contract.json").read_text(encoding="utf-8"))
    assert runtime_contract["runtimeProfile"] == "xray-centric"
    assert runtime_contract["localSocksAuth"] == "required"
    assert runtime_contract["contract"]["managedComponents"] == ["xray", "haproxy", "nginx"]
    assert runtime_contract["transportProfiles"]["localSocks"] == {
        "auth": "required",
        "allowAnonymousLocalhost": False,
    }
    assert runtime_contract["decoy"]["splitHysteriaMasqueradeDirs"] == []
    assert runtime_contract["decoy"]["xrayHysteriaMasqueradeDirs"] == ["/var/www/decoy"]
    assert runtime_contract["xray"]["hysteriaInboundTags"] == ["hy2-in"]


def test_reconcile_runtime_contract_exposes_private_wrapper_state(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        mtproto_domain="proxied.tracegate.test",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
                "inbounds": [
                    {
                        "tag": "api",
                        "listen": "127.0.0.1",
                        "port": 8080,
                        "protocol": "dokodemo-door",
                        "settings": {"address": "127.0.0.1"},
                    },
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "none",
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": "/srv/decoy"},
                            },
                            "finalmask": {"udp": [{"mode": "split", "packets": 2}]},
                        },
                    },
                    {
                        "tag": "vless-ws-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "security": "tls",
                            "network": "ws",
                            "tlsSettings": {"echServerKeys": "ech-server-key"},
                        },
                    },
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "direct"}]},
            }
        ),
    )
    _write(
        tmp_path / "base/nginx/nginx.conf",
        (
            "events {}\n"
            "http {\n"
            "  server {\n"
            "    root /srv/decoy;\n"
            "  }\n"
            "}\n"
        ),
    )
    _write(tmp_path / "base/haproxy/haproxy.cfg", "frontend fe\n  bind :443\n")

    changed = reconcile_all(settings)

    assert changed == ["xray", "haproxy", "nginx"]
    runtime_contract = json.loads((tmp_path / "runtime/runtime-contract.json").read_text(encoding="utf-8"))
    assert runtime_contract["role"] == "TRANSIT"
    assert runtime_contract["runtimeProfile"] == "xray-centric"
    assert runtime_contract["localSocksAuth"] == "required"
    assert runtime_contract["contract"]["hysteriaAuthMode"] == "token"
    assert runtime_contract["contract"]["hysteriaMetricsSource"] == "xray_stats"
    assert runtime_contract["contract"]["expectedPorts"] == [
        {"protocol": "tcp", "port": 443, "name": "listen tcp/443"},
        {"protocol": "udp", "port": 4443, "name": "listen udp/4443"},
    ]
    assert runtime_contract["contract"]["forbiddenPorts"] == [
        {"protocol": "tcp", "port": 8443, "name": "blocked tcp/8443"},
        {"protocol": "udp", "port": 8443, "name": "blocked udp/8443"},
    ]
    assert runtime_contract["rollout"] == {
        "gatewayStrategy": "RollingUpdate",
        "allowRecreateStrategy": False,
        "maxUnavailable": "0",
        "maxSurge": "1",
        "progressDeadlineSeconds": 600,
        "pdbMinAvailable": "1",
        "probesEnabled": True,
        "privatePreflightEnabled": True,
        "privatePreflightForbidPlaceholders": True,
    }
    assert runtime_contract["fronting"] == {
        "tcp443Owner": "haproxy",
        "publicUdpPort": 4443,
        "publicUdpOwner": "xray",
        "udp443Owner": "xray",
        "udpPublicPort": 4443,
        "forbiddenUdp443": False,
        "forbiddenTcp8443": True,
        "forbiddenPublicPorts": [
            {"protocol": "tcp", "port": 8443, "action": "drop"},
        ],
        "touchUdp443": False,
        "mtprotoDomain": "proxied.tracegate.test",
        "mtprotoPublicPort": 443,
        "mtprotoFrontingMode": "dedicated-dns-only",
    }
    assert runtime_contract["transportProfiles"]["clientNames"] == [
        "V1-VLESS-Reality-Direct",
        "V1-VLESS-gRPC-TLS-Direct",
        "V1-VLESS-WS-TLS-Direct",
        "V2-VLESS-Reality-Chain",
        "V3-Hysteria2-QUIC-Direct",
        "V4-Hysteria2-QUIC-Chain",
        "V5-Shadowsocks2022-ShadowTLS-Direct",
        "V6-Shadowsocks2022-ShadowTLS-Chain",
        "V7-WireGuard-WSTunnel-Direct",
        "MTProto-FakeTLS-Direct",
    ]
    assert runtime_contract["transportProfiles"]["localSocks"]["auth"] == "required"
    assert runtime_contract["linkCrypto"]["enabled"] is True
    assert runtime_contract["linkCrypto"]["classes"] == ["entry-transit"]
    assert runtime_contract["linkCrypto"]["counts"] == {
        "total": 1,
        "entryTransit": 1,
        "routerEntry": 0,
        "routerTransit": 0,
    }
    assert runtime_contract["linkCrypto"]["outerCarrier"] == {
        "enabled": True,
        "mode": "wss",
        "protocol": "websocket-tls",
        "serverName": "bridge.example.com",
        "publicPort": 443,
        "publicPath": "/cdn-cgi/tracegate-link",
        "url": "wss://bridge.example.com:443/cdn-cgi/tracegate-link",
        "verifyTls": True,
        "secretMaterial": False,
        "tlsPinning": {
            "required": True,
            "mode": "spki-sha256",
            "profileSource": "private-file-reference",
            "profileRef": {
                "kind": "file",
                "path": "/etc/tracegate/private/link-crypto/outer-wss-spki.env",
                "secretMaterial": True,
            },
            "secretMaterial": False,
        },
        "admission": {
            "required": True,
            "mode": "hmac-sha256-generation-bound",
            "carrier": "websocket-subprotocol",
            "header": "Sec-WebSocket-Protocol",
            "profileSource": "private-file-reference",
            "profileRef": {
                "kind": "file",
                "path": "/etc/tracegate/private/link-crypto/outer-wss-admission.env",
                "secretMaterial": True,
            },
            "rejectUnauthenticated": True,
            "secretMaterial": False,
        },
        "localPorts": {
            "entryClient": 14081,
            "transitServer": 14082,
        },
        "endpoints": {
            "entryClientListen": "127.0.0.1:14081",
            "transitServerListen": "127.0.0.1:14082",
            "transitTarget": "127.0.0.1:10882",
        },
    }
    assert runtime_contract["linkCrypto"]["localPorts"] == {"entry-transit": 10882}
    assert runtime_contract["linkCrypto"]["selectedProfiles"] == {"entry-transit": ["V1", "V3"]}
    assert runtime_contract["linkCrypto"]["dpiResistance"]["mode"] == "mieru-wss-spki-hmac-zapret2-scoped"
    assert runtime_contract["linkCrypto"]["dpiResistance"]["outerCarrier"] == {
        "required": True,
        "spkiPinningRequired": True,
        "hmacAdmissionRequired": True,
    }
    assert runtime_contract["linkCrypto"]["zapret2"]["enabled"] is True
    assert runtime_contract["linkCrypto"]["zapret2"]["required"] is True
    assert runtime_contract["linkCrypto"]["zapret2"]["hostWideInterception"] is False
    assert runtime_contract["paths"]["xrayConfig"].endswith("/runtime/xray/config.json")
    assert runtime_contract["paths"]["nginxConfig"].endswith("/runtime/nginx/nginx.conf")
    assert runtime_contract["decoy"]["nginxRoots"] == ["/srv/decoy"]
    assert runtime_contract["decoy"]["xrayHysteriaMasqueradeDirs"] == ["/srv/decoy"]
    assert runtime_contract["xray"]["configPaths"] == [str(tmp_path / "runtime/xray/config.json")]
    assert runtime_contract["xray"]["hysteriaInboundTags"] == ["hy2-in"]
    assert runtime_contract["xray"]["apiServices"] == ["HandlerService", "StatsService"]
    assert runtime_contract["xray"]["apiInbounds"] == [
        {"tag": "api", "listen": "127.0.0.1", "port": 8080, "protocol": "dokodemo-door"}
    ]
    assert runtime_contract["xray"]["finalMaskEnabled"] is True
    assert runtime_contract["xray"]["echEnabled"] is True


def test_reconcile_materializes_private_runtime_handoff_surfaces_for_transit(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        default_transit_host="nlconn.tracegate.test",
        mtproto_domain="proxied.tracegate.test",
        private_mtproto_secret_file=str(tmp_path / "secrets" / "mtproto.txt"),
    )

    _write(tmp_path / "secrets" / "mtproto.txt", "00112233445566778899aabbccddeeff")
    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "tls",
                            "tlsSettings": {
                                "echServerKeys": "ech-server-key",
                            },
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": "/srv/decoy"},
                            },
                            "finalmask": {"udp": [{"mode": "split", "packets": 2}]},
                        },
                    },
                    {
                        "tag": "vless-ws-in",
                        "listen": "127.0.0.1",
                        "port": 10000,
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "ws",
                            "security": "none",
                            "wsSettings": {"path": "/ws"},
                        },
                    },
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["hy2-in", "vless-ws-in"], "outboundTag": "direct"}]},
            }
        ),
    )
    _write(
        tmp_path / "base/nginx/nginx.conf",
        (
            "events {}\n"
            "http {\n"
            "  server {\n"
            "    root /srv/decoy;\n"
            "  }\n"
            "}\n"
        ),
    )
    _write(tmp_path / "base/haproxy/haproxy.cfg", "frontend fe\n  bind :443\n")

    changed = reconcile_all(settings)
    assert changed == ["xray", "haproxy", "nginx"]

    runtime_contract_path = tmp_path / "runtime" / "runtime-contract.json"
    runtime_contract = json.loads(runtime_contract_path.read_text(encoding="utf-8"))
    private_root = tmp_path / "private"

    transit_runtime_state = load_obfuscation_runtime_state(private_root / "obfuscation" / "transit" / "runtime-state.json")
    transit_runtime_env = load_obfuscation_runtime_env(private_root / "obfuscation" / "transit" / "runtime-state.env")
    fronting_state = load_fronting_runtime_state(private_root / "fronting" / "last-action.json")
    mtproto_state = load_mtproto_gateway_state(private_root / "mtproto" / "last-action.json")
    public_profile = load_mtproto_public_profile(private_root / "mtproto" / "public-profile.json")
    assert public_profile.profile_name == "MTProto-FakeTLS-Direct"

    assert validate_obfuscation_runtime_state(
        state=transit_runtime_state,
        contract=runtime_contract,
        expected_role="TRANSIT",
        contract_path=runtime_contract_path,
    ) == []
    assert validate_obfuscation_runtime_env(
        env=transit_runtime_env,
        contract=runtime_contract,
        expected_role="TRANSIT",
        runtime_state=transit_runtime_state,
        contract_path=runtime_contract_path,
    ) == []
    assert validate_fronting_runtime_state(
        state=fronting_state,
        transit_contract=runtime_contract,
        transit_runtime_state=transit_runtime_state,
    ) == []
    assert validate_mtproto_gateway_state(
        state=mtproto_state,
        transit_contract=runtime_contract,
        transit_runtime_state=transit_runtime_state,
        public_profile=public_profile,
    ) == []

    fronting_cfg = (private_root / "fronting" / "runtime" / "haproxy.cfg").read_text(encoding="utf-8")
    assert "acl mtproto_sni req.ssl_sni -i proxied.tracegate.test" in fronting_cfg
    assert "acl ws_tls_sni req.ssl_sni -i nlconn.tracegate.test" in fronting_cfg

    assert mtproto_state.issued_state_file == str(private_root / "mtproto" / "issued.json")
    issued = json.loads((private_root / "mtproto" / "issued.json").read_text(encoding="utf-8"))
    assert issued == {"version": 1, "entries": []}


def test_reconcile_preserves_existing_mtproto_issued_state(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        default_transit_host="nlconn.tracegate.test",
        mtproto_domain="proxied.tracegate.test",
        private_mtproto_secret_file=str(tmp_path / "secrets" / "mtproto.txt"),
    )

    _write(tmp_path / "secrets" / "mtproto.txt", "00112233445566778899aabbccddeeff")
    _write(
        tmp_path / "base/xray/config.json",
        json.dumps({"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}], "routing": {"rules": []}}),
    )
    _write(
        tmp_path / "base/nginx/nginx.conf",
        (
            "events {}\n"
            "http {\n"
            "  server {\n"
            "    root /srv/decoy;\n"
            "  }\n"
            "}\n"
        ),
    )
    _write(tmp_path / "base/haproxy/haproxy.cfg", "frontend fe\n  bind :443\n")

    issued_path = tmp_path / "private" / "mtproto" / "issued.json"
    _write(
        issued_path,
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "telegramId": 255761416,
                        "secretHex": "95d7ed79d0ab4494cab81c5f4acba241",
                        "issuedAt": "2026-04-21T08:34:24.303499Z",
                        "updatedAt": "2026-04-21T08:34:24.303499Z",
                        "label": "@sengokubatsu",
                        "issuedBy": "bot",
                    }
                ],
            }
        ),
    )

    reconcile_all(settings)

    issued = json.loads(issued_path.read_text(encoding="utf-8"))
    assert issued["entries"] == [
        {
            "telegramId": 255761416,
            "secretHex": "95d7ed79d0ab4494cab81c5f4acba241",
            "issuedAt": "2026-04-21T08:34:24.303499Z",
            "updatedAt": "2026-04-21T08:34:24.303499Z",
            "label": "@sengokubatsu",
            "issuedBy": "bot",
        }
    ]


def test_reconcile_emits_obfuscation_change_only_when_reload_hook_is_configured(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        agent_reload_obfuscation_cmd="reload-obfuscation",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "none",
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": "/srv/decoy"},
                            },
                        },
                    }
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "direct"}]},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray", "obfuscation"]

    changed2 = reconcile_all(settings)
    assert changed2 == []


def test_reconcile_emits_private_helper_changes_for_fronting_and_mtproto_when_hooks_are_configured(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        agent_reload_obfuscation_cmd="reload-obfuscation",
        agent_reload_mtproto_cmd="reload-mtproto",
        agent_reload_fronting_cmd="reload-fronting",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "none",
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": "/srv/decoy"},
                            },
                        },
                    }
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "direct"}]},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray", "obfuscation", "mtproto", "fronting"]

    changed2 = reconcile_all(settings)
    assert changed2 == []


def _write_tracegate21_profile_artifacts(root: Path) -> None:
    base_local_socks = {
        "enabled": True,
        "listen": "127.0.0.1:1080",
        "auth": {
            "mode": "username_password",
            "required": True,
            "username": "tg_v5_user",
            "password": "local-secret",
        },
    }
    _write(
        root / "users/101/connection-v5.json",
        json.dumps(
            {
                "user_id": "101",
                "user_display": "@alpha",
                "device_id": "dev-a",
                "device_name": "Laptop",
                "connection_id": "v3-direct",
                "revision_id": "rev-v3-direct",
                "protocol": "shadowsocks2022_shadowtls",
                "mode": "direct",
                "variant": "V3",
                "config": {
                    "profile": "v3-direct-shadowtls-shadowsocks",
                    "server": "transit.tracegate.test",
                    "port": 443,
                    "sni": "cdn.tracegate.test",
                    "method": "2022-blake3-aes-128-gcm",
                    "password": "ss-server-secret:ss-v5-secret",
                    "shadowtls": {
                        "version": 3,
                        "server_name": "cdn.tracegate.test",
                        "password": "shadowtls-v5-secret",
                        "alpn": ["h2", "http/1.1"],
                    },
                    "local_socks": base_local_socks,
                    "chain": None,
                },
            }
        ),
    )
    _write(
        root / "users/102/connection-v6.json",
        json.dumps(
            {
                "user_id": "102",
                "user_display": "@beta",
                "device_id": "dev-b",
                "device_name": "Phone",
                "connection_id": "v3-chain",
                "revision_id": "rev-v3-chain",
                "protocol": "shadowsocks2022_shadowtls",
                "mode": "chain",
                "variant": "V3",
                "config": {
                    "profile": "v3-chain-shadowtls-shadowsocks",
                    "server": "entry.tracegate.test",
                    "port": 443,
                    "sni": "front.tracegate.test",
                    "method": "2022-blake3-aes-128-gcm",
                    "password": "ss-server-secret:ss-v6-secret",
                    "shadowtls": {
                        "version": 3,
                        "server_name": "front.tracegate.test",
                        "password": "shadowtls-v6-secret",
                    },
                    "local_socks": {
                        **base_local_socks,
                        "auth": {**base_local_socks["auth"], "username": "tg_v3_chain_user"},
                    },
                    "chain": {
                        "type": "entry_transit_private_relay",
                        "entry": "entry.tracegate.test",
                        "transit": "transit.tracegate.test",
                        "link_class": "entry-transit",
                        "carrier": "xray-vless-reality",
                        "preferred_outer": "reality-xhttp",
                        "outer_carrier": "tcp-reality-xhttp",
                        "optional_packet_shaping": None,
                        "managed_by": "xray-chain",
                        "selected_profiles": ["V1", "V3"],
                        "inner_transport": "shadowsocks2022-shadowtls-v3",
                        "xray_backhaul": False,
                    },
                },
            }
        ),
    )
    _write(
        root / "users/103/connection-v7.json",
        json.dumps(
            {
                "user_id": "103",
                "user_display": "@gamma",
                "device_id": "dev-c",
                "device_name": "Router",
                "connection_id": "v0-wgws",
                "revision_id": "rev-v0-wgws",
                "protocol": "wireguard_wstunnel",
                "mode": "direct",
                "variant": "V0",
                "config": {
                    "profile": "v0-wgws-wireguard",
                    "server": "transit.tracegate.test",
                    "port": 443,
                    "sni": "transit.tracegate.test",
                    "wstunnel": {
                        "mode": "wireguard-over-websocket",
                        "url": "wss://transit.tracegate.test:443/cdn-cgi/tracegate",
                        "path": "/cdn-cgi/tracegate",
                        "tls_server_name": "transit.tracegate.test",
                        "local_udp_listen": "127.0.0.1:51820",
                    },
                    "wireguard": {
                        "private_key": "client-private",
                        "public_key": "client-public",
                        "server_public_key": "server-public",
                        "preshared_key": "wg-psk",
                        "address": "10.7.0.10/32",
                        "allowed_ips": ["0.0.0.0/0", "::/0"],
                        "dns": "1.1.1.1",
                        "mtu": 1280,
                        "persistent_keepalive": 25,
                    },
                    "local_socks": {
                        **base_local_socks,
                        "auth": {**base_local_socks["auth"], "username": "tg_v0_user"},
                    },
                    "chain": None,
                },
            }
        ),
    )


def test_reconcile_materializes_private_profile_handoff_for_transit(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_profiles_cmd="reload-profiles",
    )
    _write_tracegate21_profile_artifacts(tmp_path)

    changed = reconcile_all(settings)
    assert changed == ["profiles"]

    profile_path = tmp_path / "private" / "profiles" / "transit" / "desired-state.json"
    env_path = tmp_path / "private" / "profiles" / "transit" / "desired-state.env"
    state = json.loads(profile_path.read_text(encoding="utf-8"))
    env = env_path.read_text(encoding="utf-8")

    assert state["schema"] == "tracegate.private-profiles.v1"
    assert state["secretMaterial"] is True
    assert state["transportProfiles"]["localSocks"] == {"auth": "required", "allowAnonymousLocalhost": False}
    assert "V7-WireGuard-WSTunnel-Direct" in state["transportProfiles"]["clientNames"]
    assert state["counts"] == {
        "total": 3,
        "shadowsocks2022ShadowTLS": 2,
        "wireguardWSTunnel": 1,
    }
    shadowtls_by_mode = {row["mode"]: row for row in state["shadowsocks2022ShadowTLS"]}
    assert sorted(row["profile"] for row in state["shadowsocks2022ShadowTLS"]) == [
        "v3-chain-shadowtls-shadowsocks",
        "v3-direct-shadowtls-shadowsocks",
    ]
    assert shadowtls_by_mode["direct"]["stage"] == "direct-transit-public"
    assert shadowtls_by_mode["chain"]["stage"] == "transit-private-terminator"
    assert shadowtls_by_mode["chain"]["chain"]["preferredOuter"] == "reality-xhttp"
    assert shadowtls_by_mode["chain"]["chain"]["outerCarrier"] == "tcp-reality-xhttp"
    assert shadowtls_by_mode["chain"]["chain"]["managedBy"] == "xray-chain"
    assert shadowtls_by_mode["chain"]["chain"]["selectedProfiles"] == ["V1", "V3"]
    assert shadowtls_by_mode["chain"]["chain"]["xrayBackhaul"] is False
    assert "password" not in shadowtls_by_mode["direct"]["shadowtls"]
    assert shadowtls_by_mode["direct"]["shadowtls"]["credentialScope"] == "node-static"
    assert shadowtls_by_mode["direct"]["shadowtls"]["profileRef"] == {
        "kind": "file",
        "path": "/etc/tracegate/private/shadowtls/transit-config.yaml",
        "secretMaterial": True,
    }
    assert shadowtls_by_mode["direct"]["shadowtls"]["manageUsers"] is False
    assert shadowtls_by_mode["direct"]["shadowtls"]["restartOnUserChange"] is False
    assert shadowtls_by_mode["chain"]["localSocks"]["auth"]["required"] is True
    assert state["wireguardWSTunnel"][0]["wireguard"]["clientPublicKey"] == "client-public"
    assert state["wireguardWSTunnel"][0]["wireguard"]["allowedIps"] == ["10.7.0.10/32"]
    assert state["wireguardWSTunnel"][0]["wireguard"]["clientRouteAllowedIps"] == ["0.0.0.0/0", "::/0"]
    assert state["wireguardWSTunnel"][0]["sync"] == {
        "strategy": "wg-set",
        "interface": "wg",
        "applyMode": "live-peer-sync",
        "removeStalePeers": True,
        "restartWireGuard": False,
        "restartWSTunnel": False,
    }
    assert state["wireguardWSTunnel"][0]["obfuscation"]["packetShaping"] == "none"
    assert state["wireguardWSTunnel"][0]["obfuscation"]["hostWideInterception"] is False
    assert "TRACEGATE_PROFILE_COUNT='3'" in env
    assert profile_path.stat().st_mode & 0o777 == 0o600
    assert env_path.stat().st_mode & 0o777 == 0o600

    changed2 = reconcile_all(settings)
    assert changed2 == []


def test_reconcile_materializes_only_chain_profile_handoff_for_entry(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_profiles_cmd="reload-profiles",
    )
    _write_tracegate21_profile_artifacts(tmp_path)

    changed = reconcile_all(settings)
    assert changed == ["profiles"]

    state = json.loads(
        (tmp_path / "private" / "profiles" / "entry" / "desired-state.json").read_text(encoding="utf-8")
    )
    assert state["counts"] == {
        "total": 1,
        "shadowsocks2022ShadowTLS": 1,
        "wireguardWSTunnel": 0,
    }
    assert state["shadowsocks2022ShadowTLS"][0]["profile"] == "v3-chain-shadowtls-shadowsocks"
    assert state["shadowsocks2022ShadowTLS"][0]["stage"] == "entry-public-to-transit-relay"
    assert state["shadowsocks2022ShadowTLS"][0]["shadowtls"]["profileRef"]["path"] == "/etc/tracegate/private/shadowtls/entry-config.yaml"
    assert state["shadowsocks2022ShadowTLS"][0]["shadowtls"]["restartOnUserChange"] is False
    assert state["shadowsocks2022ShadowTLS"][0]["obfuscation"] == {
        "scope": "entry-transit-private-relay",
        "outer": "reality-xhttp",
        "packetShaping": "none",
        "hostWideInterception": False,
    }


def test_reconcile_k3s_revalidates_private_profiles_when_reload_marker_is_missing_or_stale(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="TRANSIT",
        agent_runtime_profile="tracegate-2.1",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_profiles_cmd="reload-profiles",
    )
    _write_tracegate21_profile_artifacts(tmp_path)

    changed = reconcile_all(settings)
    assert changed == ["profiles"]

    changed_without_marker = reconcile_all(settings)
    assert changed_without_marker == ["profiles"]

    _write(tmp_path / "private/runtime/profiles-transit-last-reload.json", "{}\n")
    changed_with_invalid_marker = reconcile_all(settings)
    assert changed_with_invalid_marker == ["profiles"]

    marker_path = _write_k3s_reload_marker(tmp_path / "private", component="profiles", role="TRANSIT")
    changed_with_marker = reconcile_all(settings)
    assert changed_with_marker == []

    env_path = tmp_path / "private/profiles/transit/desired-state.env"
    newer_mtime_ns = marker_path.stat().st_mtime_ns + 1_000_000
    os.utime(env_path, ns=(newer_mtime_ns, newer_mtime_ns))

    changed_with_stale_marker = reconcile_all(settings)
    assert changed_with_stale_marker == ["profiles"]


def test_reconcile_materializes_link_crypto_handoff_without_private_secrets(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_link_crypto_cmd="reload-link-crypto",
        default_transit_host="transit.tracegate.test",
        private_link_crypto_generation=7,
    )

    changed = reconcile_all(settings)
    assert changed == ["link-crypto"]

    state_path = tmp_path / "private" / "link-crypto" / "entry" / "desired-state.json"
    env_path = tmp_path / "private" / "link-crypto" / "entry" / "desired-state.env"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    env = env_path.read_text(encoding="utf-8")

    assert state["schema"] == "tracegate.link-crypto.v1"
    assert state["secretMaterial"] is False
    assert state["transportProfiles"]["localSocks"] == {"auth": "required", "allowAnonymousLocalhost": False}
    assert "V6-Shadowsocks2022-ShadowTLS-Chain" in state["transportProfiles"]["clientNames"]
    assert state["counts"] == {
        "total": 1,
        "entryTransit": 1,
        "routerEntry": 0,
        "routerTransit": 0,
    }
    assert state["links"][0]["class"] == "entry-transit"
    assert state["links"][0]["side"] == "client"
    assert state["links"][0]["carrier"] == "mieru"
    assert state["links"][0]["managedBy"] == "link-crypto"
    assert state["links"][0]["xrayBackhaul"] is False
    assert state["links"][0]["generation"] == 7
    assert state["links"][0]["remote"]["endpoint"] == "transit.tracegate.test:443"
    assert state["links"][0]["outerCarrier"] == {
        "enabled": True,
        "mode": "wss",
        "protocol": "websocket-tls",
        "serverName": "bridge.example.com",
        "publicPort": 443,
        "publicPath": "/cdn-cgi/tracegate-link",
        "url": "wss://bridge.example.com:443/cdn-cgi/tracegate-link",
        "verifyTls": True,
        "secretMaterial": False,
        "tlsPinning": {
            "required": True,
            "mode": "spki-sha256",
            "profileSource": "private-file-reference",
            "profileRef": {
                "kind": "file",
                "path": "/etc/tracegate/private/link-crypto/outer-wss-spki.env",
                "secretMaterial": True,
            },
            "secretMaterial": False,
        },
        "admission": {
            "required": True,
            "mode": "hmac-sha256-generation-bound",
            "carrier": "websocket-subprotocol",
            "header": "Sec-WebSocket-Protocol",
            "profileSource": "private-file-reference",
            "profileRef": {
                "kind": "file",
                "path": "/etc/tracegate/private/link-crypto/outer-wss-admission.env",
                "secretMaterial": True,
            },
            "rejectUnauthenticated": True,
            "secretMaterial": False,
        },
        "side": "client",
        "localEndpoint": "127.0.0.1:14081",
        "entryClientListen": "127.0.0.1:14081",
        "transitServerListen": "127.0.0.1:14082",
        "transitTarget": "127.0.0.1:10882",
    }
    assert state["links"][0]["profileRef"] == {
        "kind": "file",
        "path": "/etc/tracegate/private/mieru/client.json",
        "secretMaterial": True,
    }
    assert state["links"][0]["local"]["auth"]["required"] is True
    assert state["links"][0]["local"]["auth"]["mode"] == "private-profile"
    assert state["links"][0]["dpiResistance"]["mode"] == "mieru-wss-spki-hmac-zapret2-scoped"
    assert state["links"][0]["dpiResistance"]["trafficShaping"]["required"] is True
    assert state["links"][0]["zapret2"]["enabled"] is True
    assert state["links"][0]["zapret2"]["required"] is True
    assert state["links"][0]["zapret2"]["hostWideInterception"] is False
    assert state["links"][0]["zapret2"]["nfqueue"] is False
    assert state["links"][0]["rotation"]["restartExisting"] is False
    assert state["udpCounts"] == {
        "total": 1,
        "entryTransitUdp": 1,
        "routerEntryUdp": 0,
        "routerTransitUdp": 0,
    }
    assert state["udpLinks"][0]["class"] == "entry-transit-udp"
    assert state["udpLinks"][0]["side"] == "client"
    assert state["udpLinks"][0]["carrier"] == "hysteria2"
    assert state["udpLinks"][0]["transport"] == "udp-quic"
    assert state["udpLinks"][0]["managedBy"] == "link-crypto"
    assert state["udpLinks"][0]["xrayBackhaul"] is False
    assert state["udpLinks"][0]["remote"] == {
        "role": "TRANSIT",
        "endpoint": "transit.tracegate.test:443",
        "protocol": "udp-quic",
    }
    assert state["udpLinks"][0]["local"]["protocol"] == "udp"
    assert state["udpLinks"][0]["obfs"] == {
        "type": "salamander",
        "required": True,
        "profileRef": {
            "kind": "file",
            "path": "/etc/tracegate/private/udp-link/salamander.env",
            "secretMaterial": True,
        },
    }
    assert state["udpLinks"][0]["pairedObfs"]["enabled"] is False
    assert state["udpLinks"][0]["hardening"] == {
        "enabled": True,
        "failClosed": True,
        "requirePrivateAuth": True,
        "rejectAnonymous": True,
        "antiReplay": {"enabled": True, "windowPackets": 4096},
        "antiAmplification": {"enabled": True, "maxUnvalidatedBytes": 1200},
        "rateLimit": {"enabled": True, "handshakePerMinute": 120, "newSessionPerMinute": 60},
        "mtu": {"mode": "clamp", "maxPacketSize": 1252},
        "keyRotation": {
            "enabled": True,
            "strategy": "generation-drain",
            "maxAgeSeconds": 3600,
            "overlapSeconds": 120,
        },
        "sourceValidation": {"enabled": True, "mode": "profile-bound-remote"},
    }
    assert state["udpLinks"][0]["selectedProfiles"] == ["V2"]
    assert state["udpLinks"][0]["stability"] == {
        "failOpen": False,
        "bypassOnFailure": False,
        "dropUnrelatedTraffic": False,
    }
    assert "TRACEGATE_LINK_CRYPTO_SECRET_MATERIAL='false'" in env
    assert "TRACEGATE_LINK_CRYPTO_CLASSES='entry-transit'" in env
    assert "TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_MODE='wss'" in env
    assert "TRACEGATE_LINK_CRYPTO_OUTER_WSS_PATH='/cdn-cgi/tracegate-link'" in env
    assert "TRACEGATE_LINK_CRYPTO_OUTER_WSS_SPKI_PINNING_REQUIRED='true'" in env
    assert "TRACEGATE_LINK_CRYPTO_OUTER_WSS_ADMISSION_REQUIRED='true'" in env
    assert "TRACEGATE_LINK_CRYPTO_TCP_DPI_RESISTANCE_REQUIRED='true'" in env
    assert "TRACEGATE_LINK_CRYPTO_TCP_TRAFFIC_SHAPING_REQUIRED='true'" in env
    assert "TRACEGATE_LINK_CRYPTO_PROMOTION_PREFLIGHT_REQUIRED='true'" in env
    assert "TRACEGATE_LINK_CRYPTO_ZAPRET2_REQUIRED='true'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_COUNT='1'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_CLASSES='entry-transit-udp'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_CARRIER='hysteria2'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_REMOTE_PORT='443'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_SALAMANDER_REQUIRED='true'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_HARDENING_ENABLED='true'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_ANTI_REPLAY_ENABLED='true'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_MTU_MODE='clamp'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_SOURCE_VALIDATION_MODE='profile-bound-remote'" in env

    changed2 = reconcile_all(settings)
    assert changed2 == []


def test_reconcile_k3s_revalidates_link_crypto_when_reload_marker_is_missing_or_stale(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
        agent_runtime_profile="tracegate-2.1",
        private_runtime_root=str(tmp_path / "private"),
        private_link_crypto_enabled=True,
        agent_reload_link_crypto_cmd="reload-link-crypto",
    )

    changed = reconcile_all(settings)
    assert changed == ["link-crypto"]

    changed_without_marker = reconcile_all(settings)
    assert changed_without_marker == ["link-crypto"]

    _write(tmp_path / "private/runtime/link-crypto-entry-last-reload.json", "{}\n")
    changed_with_invalid_marker = reconcile_all(settings)
    assert changed_with_invalid_marker == ["link-crypto"]

    _write_k3s_reload_marker(tmp_path / "private", component="link-crypto", role="ENTRY", include_summary_schema=False)
    changed_with_legacy_marker = reconcile_all(settings)
    assert changed_with_legacy_marker == ["link-crypto"]

    marker_path = _write_k3s_reload_marker(tmp_path / "private", component="link-crypto", role="ENTRY")
    changed_with_marker = reconcile_all(settings)
    assert changed_with_marker == []

    router_client_env_path = tmp_path / "private/router/entry/client-bundle.env"
    newer_mtime_ns = marker_path.stat().st_mtime_ns + 1_000_000
    os.utime(router_client_env_path, ns=(newer_mtime_ns, newer_mtime_ns))

    changed_with_stale_router_marker = reconcile_all(settings)
    assert changed_with_stale_router_marker == ["link-crypto"]

    marker_path = _write_k3s_reload_marker(tmp_path / "private", component="link-crypto", role="ENTRY")
    state_path = tmp_path / "private/link-crypto/entry/desired-state.json"
    newer_mtime_ns = marker_path.stat().st_mtime_ns + 1_000_000
    os.utime(state_path, ns=(newer_mtime_ns, newer_mtime_ns))

    changed_with_stale_marker = reconcile_all(settings)
    assert changed_with_stale_marker == ["link-crypto"]


def test_reconcile_materializes_router_entry_link_crypto_with_server_profile(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_link_crypto_cmd="reload-link-crypto",
        default_entry_host="entry.tracegate.test",
        default_transit_host="transit.tracegate.test",
        private_link_crypto_router_entry_enabled=True,
        private_mieru_client_profile="client-private.json",
        private_mieru_server_profile="server-private.json",
    )

    changed = reconcile_all(settings)
    assert changed == ["link-crypto"]

    state_path = tmp_path / "private" / "link-crypto" / "entry" / "desired-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    by_class = {row["class"]: row for row in state["links"]}

    assert state["counts"] == {
        "total": 2,
        "entryTransit": 1,
        "routerEntry": 1,
        "routerTransit": 0,
    }
    assert by_class["entry-transit"]["side"] == "client"
    assert by_class["entry-transit"]["managedBy"] == "link-crypto"
    assert by_class["entry-transit"]["xrayBackhaul"] is False
    assert by_class["entry-transit"]["profileRef"]["path"] == "/etc/tracegate/private/mieru/client-private.json"
    assert by_class["router-entry"]["side"] == "server"
    assert by_class["router-entry"]["profileRef"]["path"] == "/etc/tracegate/private/mieru/server-private.json"
    assert by_class["router-entry"]["remote"]["endpoint"] == "entry.tracegate.test:443"
    router_state = json.loads((tmp_path / "private" / "router" / "entry" / "desired-state.json").read_text(encoding="utf-8"))
    router_env = (tmp_path / "private" / "router" / "entry" / "desired-state.env").read_text(encoding="utf-8")
    router_client_bundle = json.loads(
        (tmp_path / "private" / "router" / "entry" / "client-bundle.json").read_text(encoding="utf-8")
    )
    router_client_env = (tmp_path / "private" / "router" / "entry" / "client-bundle.env").read_text(encoding="utf-8")
    assert router_state["schema"] == "tracegate.router-handoff.v1"
    assert router_state["secretMaterial"] is False
    assert router_state["placement"] == "personal-router-before-entry"
    assert router_state["contract"] == {
        "routerIsEntryReplacement": False,
        "requiresServerSideLinkCrypto": True,
        "requiresPrivateRouterProfile": True,
        "noHostWideInterception": True,
        "noNfqueue": True,
    }
    assert router_state["classes"] == {"tcp": ["router-entry"], "udp": []}
    assert router_state["counts"] == {"total": 1, "tcp": 1, "udp": 0}
    assert router_state["routes"]["tcp"][0]["class"] == "router-entry"
    assert router_state["routes"]["tcp"][0]["publicEndpoint"] == "entry.tracegate.test:443"
    assert router_state["routes"]["tcp"][0]["profileRef"]["path"] == "/etc/tracegate/private/mieru/server-private.json"
    assert router_state["routes"]["tcp"][0]["routerClient"]["requiresPrivateProfile"] is True
    assert router_state["routes"]["tcp"][0]["routerClient"]["hostWideInterception"] is False
    assert router_state["routes"]["tcp"][0]["routerClient"]["profileRefs"]["mieruClient"] == {
        "kind": "file",
        "path": "/etc/tracegate/private/router/entry/router-entry/mieru-client.json",
        "secretMaterial": True,
    }
    assert "TRACEGATE_ROUTER_HANDOFF_ENABLED='true'" in router_env
    assert "TRACEGATE_ROUTER_CLIENT_BUNDLE_JSON=" in router_env
    assert "TRACEGATE_ROUTER_HANDOFF_TCP_CLASSES='router-entry'" in router_env
    assert "TRACEGATE_ROUTER_HANDOFF_ROUTER_IS_ENTRY_REPLACEMENT='false'" in router_env
    assert router_client_bundle["schema"] == "tracegate.router-client-bundle.v1"
    assert router_client_bundle["secretMaterial"] is False
    assert router_client_bundle["requirements"] == {
        "routerIsEntryReplacement": False,
        "requiresPrivateProfile": True,
        "requiresServerSideLinkCrypto": True,
        "requiresBothSides": True,
        "failClosed": True,
        "noHostWideInterception": True,
        "noNfqueue": True,
        "profileDistribution": "external-private-files",
    }
    assert router_client_bundle["routes"]["tcp"][0]["serverEndpoint"] == "entry.tracegate.test:443"
    assert router_client_bundle["routes"]["tcp"][0]["routerSide"]["failClosed"] is True
    assert router_client_bundle["routes"]["tcp"][0]["routerSide"]["profileRefs"]["mieruClient"]["path"].endswith(
        "/entry/router-entry/mieru-client.json"
    )
    assert "TRACEGATE_ROUTER_CLIENT_BUNDLE_COMPONENTS='mieru-client'" in router_client_env
    assert "TRACEGATE_ROUTER_CLIENT_BUNDLE_FAIL_CLOSED='true'" in router_client_env


def test_reconcile_treats_router_handoff_only_change_as_link_crypto_reload(tmp_path: Path) -> None:
    initial = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_link_crypto_cmd="reload-link-crypto",
        default_entry_host="entry.tracegate.test",
        default_transit_host="transit.tracegate.test",
        private_link_crypto_enabled=False,
        private_link_crypto_router_entry_enabled=True,
        private_router_mieru_client_profile="mieru-client-a.json",
    )
    assert reconcile_all(initial) == ["link-crypto"]
    assert reconcile_all(initial) == []

    changed_router_profile = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_link_crypto_cmd="reload-link-crypto",
        default_entry_host="entry.tracegate.test",
        default_transit_host="transit.tracegate.test",
        private_link_crypto_enabled=False,
        private_link_crypto_router_entry_enabled=True,
        private_router_mieru_client_profile="mieru-client-b.json",
    )

    assert reconcile_all(changed_router_profile) == ["link-crypto"]


def test_reconcile_materializes_router_entry_link_crypto_without_entry_transit(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_link_crypto_cmd="reload-link-crypto",
        default_entry_host="entry.tracegate.test",
        default_transit_host="transit.tracegate.test",
        private_link_crypto_enabled=False,
        private_link_crypto_router_entry_enabled=True,
        private_mieru_client_profile="client-private.json",
        private_mieru_server_profile="server-private.json",
    )

    changed = reconcile_all(settings)
    assert changed == ["link-crypto"]

    state_path = tmp_path / "private" / "link-crypto" / "entry" / "desired-state.json"
    env_path = tmp_path / "private" / "link-crypto" / "entry" / "desired-state.env"
    state = json.loads(state_path.read_text(encoding="utf-8"))

    assert state["counts"] == {
        "total": 1,
        "entryTransit": 0,
        "routerEntry": 1,
        "routerTransit": 0,
    }
    assert [row["class"] for row in state["links"]] == ["router-entry"]
    link = state["links"][0]
    assert link["side"] == "server"
    assert link["profileRef"]["path"] == "/etc/tracegate/private/mieru/server-private.json"
    assert link["remote"]["endpoint"] == "entry.tracegate.test:443"
    assert link["selectedProfiles"] == ["V1", "V3"]
    assert "TRACEGATE_LINK_CRYPTO_COUNT='1'" in env_path.read_text(encoding="utf-8")
    assert "TRACEGATE_LINK_CRYPTO_CLASSES='router-entry'" in env_path.read_text(encoding="utf-8")
    runtime_contract = json.loads((tmp_path / "runtime/runtime-contract.json").read_text(encoding="utf-8"))
    assert runtime_contract["linkCrypto"]["classes"] == ["router-entry"]
    assert runtime_contract["linkCrypto"]["udp"]["enabled"] is False
    assert runtime_contract["linkCrypto"]["counts"] == {
        "total": 1,
        "entryTransit": 0,
        "routerEntry": 1,
        "routerTransit": 0,
    }
    assert runtime_contract["linkCrypto"]["localPorts"] == {"router-entry": 10883}


def test_reconcile_materializes_router_transit_link_crypto_without_entry_transit(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_link_crypto_cmd="reload-link-crypto",
        default_entry_host="entry.tracegate.test",
        default_transit_host="transit.tracegate.test",
        private_link_crypto_enabled=False,
        private_link_crypto_router_transit_enabled=True,
        private_mieru_client_profile="client-private.json",
        private_mieru_server_profile="server-private.json",
    )

    changed = reconcile_all(settings)
    assert changed == ["link-crypto"]

    state_path = tmp_path / "private" / "link-crypto" / "transit" / "desired-state.json"
    env_path = tmp_path / "private" / "link-crypto" / "transit" / "desired-state.env"
    state = json.loads(state_path.read_text(encoding="utf-8"))

    assert state["counts"] == {
        "total": 1,
        "entryTransit": 0,
        "routerEntry": 0,
        "routerTransit": 1,
    }
    assert [row["class"] for row in state["links"]] == ["router-transit"]
    link = state["links"][0]
    assert link["side"] == "server"
    assert link["profileRef"]["path"] == "/etc/tracegate/private/mieru/server-private.json"
    assert link["remote"]["endpoint"] == "transit.tracegate.test:443"
    assert link["selectedProfiles"] == ["V0", "V1", "V3"]
    assert "TRACEGATE_LINK_CRYPTO_COUNT='1'" in env_path.read_text(encoding="utf-8")
    assert "TRACEGATE_LINK_CRYPTO_CLASSES='router-transit'" in env_path.read_text(encoding="utf-8")
    runtime_contract = json.loads((tmp_path / "runtime/runtime-contract.json").read_text(encoding="utf-8"))
    assert runtime_contract["linkCrypto"]["classes"] == ["router-transit"]
    assert runtime_contract["linkCrypto"]["udp"]["enabled"] is False
    assert runtime_contract["linkCrypto"]["counts"] == {
        "total": 1,
        "entryTransit": 0,
        "routerEntry": 0,
        "routerTransit": 1,
    }
    assert runtime_contract["linkCrypto"]["localPorts"] == {"router-transit": 10884}


@pytest.mark.parametrize(
    ("role", "flag_name", "expected_class", "remote_endpoint", "selected_profiles", "local_port"),
    [
        (
            "ENTRY",
            "private_udp_link_router_entry_enabled",
            "router-entry-udp",
            "entry.tracegate.test:443",
            ["V2"],
            14483,
        ),
        (
            "TRANSIT",
            "private_udp_link_router_transit_enabled",
            "router-transit-udp",
            "transit.tracegate.test:443",
            ["V2"],
            14484,
        ),
    ],
)
def test_reconcile_materializes_router_udp_link_without_entry_transit(
    tmp_path: Path,
    role: str,
    flag_name: str,
    expected_class: str,
    remote_endpoint: str,
    selected_profiles: list[str],
    local_port: int,
) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role=role,
        agent_runtime_profile="xray-centric",
        private_runtime_root=str(tmp_path / "private"),
        agent_reload_link_crypto_cmd="reload-link-crypto",
        default_entry_host="entry.tracegate.test",
        default_transit_host="transit.tracegate.test",
        private_link_crypto_enabled=False,
        private_udp_link_paired_obfs_enabled=True,
        **{flag_name: True},
    )

    changed = reconcile_all(settings)
    assert changed == ["link-crypto"]

    role_lower = role.lower()
    state_path = tmp_path / "private" / "link-crypto" / role_lower / "desired-state.json"
    env_path = tmp_path / "private" / "link-crypto" / role_lower / "desired-state.env"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    env = env_path.read_text(encoding="utf-8")

    assert state["counts"] == {
        "total": 0,
        "entryTransit": 0,
        "routerEntry": 0,
        "routerTransit": 0,
    }
    assert state["links"] == []
    assert state["udpCounts"] == {
        "total": 1,
        "entryTransitUdp": 0,
        "routerEntryUdp": 1 if expected_class == "router-entry-udp" else 0,
        "routerTransitUdp": 1 if expected_class == "router-transit-udp" else 0,
    }
    assert [row["class"] for row in state["udpLinks"]] == [expected_class]
    udp_link = state["udpLinks"][0]
    assert udp_link["side"] == "server"
    assert udp_link["carrier"] == "hysteria2"
    assert udp_link["transport"] == "udp-quic"
    assert udp_link["remote"]["role"] == "ROUTER"
    assert udp_link["remote"]["endpoint"] == remote_endpoint
    assert udp_link["local"] == {
        "listen": f"127.0.0.1:{local_port}",
        "protocol": "udp",
        "auth": {"required": True, "mode": "private-profile"},
    }
    assert udp_link["obfs"]["type"] == "salamander"
    assert udp_link["obfs"]["required"] is True
    assert udp_link["pairedObfs"] == {
        "enabled": True,
        "backend": "udp2raw",
        "mode": "udp2raw-faketcp",
        "requiresBothSides": True,
        "failClosed": True,
        "noHostWideInterception": True,
        "noNfqueue": True,
        "profileRef": {
            "kind": "file",
            "path": "/etc/tracegate/private/udp-link/paired-obfs.env",
            "secretMaterial": True,
        },
    }
    assert udp_link["hardening"]["failClosed"] is True
    assert udp_link["hardening"]["antiReplay"] == {"enabled": True, "windowPackets": 4096}
    assert udp_link["hardening"]["mtu"] == {"mode": "clamp", "maxPacketSize": 1252}
    assert udp_link["hardening"]["sourceValidation"] == {"enabled": True, "mode": "profile-bound-remote"}
    assert udp_link["selectedProfiles"] == selected_profiles
    assert "TRACEGATE_LINK_CRYPTO_COUNT='0'" in env
    assert f"TRACEGATE_LINK_CRYPTO_UDP_CLASSES='{expected_class}'" in env
    assert "TRACEGATE_LINK_CRYPTO_UDP_PAIRED_OBFS_ENABLED='true'" in env
    router_state = json.loads((tmp_path / "private" / "router" / role_lower / "desired-state.json").read_text(encoding="utf-8"))
    router_env = (tmp_path / "private" / "router" / role_lower / "desired-state.env").read_text(encoding="utf-8")
    router_client_bundle = json.loads(
        (tmp_path / "private" / "router" / role_lower / "client-bundle.json").read_text(encoding="utf-8")
    )
    router_client_env = (tmp_path / "private" / "router" / role_lower / "client-bundle.env").read_text(encoding="utf-8")
    assert router_state["secretMaterial"] is False
    assert router_state["placement"] == (
        "personal-router-before-entry" if role == "ENTRY" else "personal-router-before-transit"
    )
    assert router_state["classes"] == {"tcp": [], "udp": [expected_class]}
    assert router_state["counts"] == {"total": 1, "tcp": 0, "udp": 1}
    assert router_state["routes"]["udp"][0]["class"] == expected_class
    assert router_state["routes"]["udp"][0]["publicEndpoint"] == remote_endpoint
    assert router_state["routes"]["udp"][0]["pairedObfs"]["enabled"] is True
    assert router_state["routes"]["udp"][0]["pairedObfs"]["noHostWideInterception"] is True
    assert router_state["routes"]["udp"][0]["hardening"]["failClosed"] is True
    assert router_state["routes"]["udp"][0]["routerClient"]["profileRefs"]["hysteriaClient"]["path"].endswith(
        f"/{role_lower}/{expected_class}/hysteria-client.yaml"
    )
    assert router_state["routes"]["udp"][0]["routerClient"]["profileRefs"]["salamander"]["path"].endswith(
        f"/{role_lower}/{expected_class}/salamander.env"
    )
    assert router_state["routes"]["udp"][0]["routerClient"]["profileRefs"]["pairedObfs"]["path"].endswith(
        f"/{role_lower}/{expected_class}/paired-obfs.env"
    )
    assert "TRACEGATE_ROUTER_HANDOFF_UDP_COUNT='1'" in router_env
    assert f"TRACEGATE_ROUTER_HANDOFF_UDP_CLASSES='{expected_class}'" in router_env
    assert "TRACEGATE_ROUTER_HANDOFF_PAIRED_OBFS_ENABLED='true'" in router_env
    assert "TRACEGATE_ROUTER_HANDOFF_REQUIRES_PRIVATE_PROFILE='true'" in router_env
    assert router_client_bundle["schema"] == "tracegate.router-client-bundle.v1"
    assert router_client_bundle["routes"]["udp"][0]["serverEndpoint"] == remote_endpoint
    assert router_client_bundle["routes"]["udp"][0]["routerSide"]["profileRefs"]["pairedObfs"]["path"].endswith(
        f"/{role_lower}/{expected_class}/paired-obfs.env"
    )
    assert router_client_bundle["components"][1]["name"] == "hysteria2-client"
    assert router_client_bundle["components"][1]["required"] is True
    assert router_client_bundle["components"][2]["name"] == "paired-udp-obfs"
    assert router_client_bundle["components"][2]["required"] is True
    assert "TRACEGATE_ROUTER_CLIENT_BUNDLE_COMPONENTS='hysteria2-client:paired-udp-obfs'" in router_client_env
    assert "TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_NFQUEUE='true'" in router_client_env

    runtime_contract = json.loads((tmp_path / "runtime/runtime-contract.json").read_text(encoding="utf-8"))
    assert runtime_contract["linkCrypto"]["enabled"] is True
    assert runtime_contract["linkCrypto"]["classes"] == []
    assert runtime_contract["linkCrypto"]["udp"]["enabled"] is True
    assert runtime_contract["linkCrypto"]["udp"]["classes"] == [expected_class]
    assert runtime_contract["linkCrypto"]["udp"]["localPorts"] == {expected_class: local_port}
    assert runtime_contract["linkCrypto"]["udp"]["selectedProfiles"] == {expected_class: selected_profiles}
    assert runtime_contract["linkCrypto"]["udp"]["obfs"] == {"type": "salamander", "required": True}
    assert runtime_contract["linkCrypto"]["udp"]["pairedObfs"] == {
        "enabled": True,
        "backend": "udp2raw",
        "mode": "udp2raw-faketcp",
        "requiresBothSides": True,
        "failClosed": True,
        "noHostWideInterception": True,
        "noNfqueue": True,
    }
    assert runtime_contract["linkCrypto"]["udp"]["hardening"]["failClosed"] is True
    assert runtime_contract["linkCrypto"]["udp"]["hardening"]["antiAmplification"] == {
        "enabled": True,
        "maxUnvalidatedBytes": 1200,
    }


def test_reconcile_xray_centric_live_sync_passes_hysteria_user_specs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tracegate.agent import xray_api

    captured: list[tuple[str, dict[str, dict[str, str]]]] = []

    monkeypatch.setattr(
        xray_api,
        "sync_inbound_users",
        lambda _settings, *, inbound_tag, desired_email_to_user: captured.append((inbound_tag, desired_email_to_user)) or True,
    )

    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        agent_xray_api_enabled=True,
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "hy2-in",
                        "listen": "0.0.0.0",
                        "port": 443,
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "none",
                            "hysteriaSettings": {
                                "version": 2,
                                "auth": "bootstrap-password",
                                "masquerade": {"type": "file", "dir": "/var/www/decoy"},
                            },
                        },
                    }
                ],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "direct"}]},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-c2.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "c2",
                "revision_id": "r2",
                "variant": "V3",
                "protocol": "hysteria2",
                "config": {
                    "auth": {
                        "type": "userpass",
                        "username": "v3_u1_c2",
                        "password": "d1",
                        "token": "v3_u1_c2:d1",
                    }
                },
            }
        ),
    )

    changed = reconcile_all(settings)

    assert changed == ["xray"]
    assert captured == [
        ("hy2-in", {"V3 - u1 - c2": {"protocol": "hysteria", "auth": "v3_u1_c2:d1"}})
    ]


def test_reconcile_entry_forces_transit_port_443(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
        default_transit_host="tracegate.test",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "entry-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "reality", "realitySettings": {"serverNames": []}},
                    }
                ],
                "outbounds": [
                    {
                        "tag": "to-transit",
                        "protocol": "vless",
                        "settings": {"vnext": [{"address": "transit.example.com", "port": 50000, "users": []}]},
                    }
                ],
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray"]

    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert rendered["outbounds"][0]["settings"]["vnext"][0]["address"] == "tracegate.test"
    assert rendered["outbounds"][0]["settings"]["vnext"][0]["port"] == 443


def test_reconcile_entry_adds_sticky_transit_outbounds_per_v2_connection(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "entry-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "reality", "realitySettings": {"serverNames": []}},
                    }
                ],
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom"},
                    {
                        "tag": "to-transit",
                        "protocol": "vless",
                        "settings": {"vnext": [{"address": "transit.example.com", "port": 443, "users": []}]},
                        "streamSettings": {"network": "xhttp", "security": "reality"},
                    },
                ],
                "routing": {
                    "rules": [
                        {"type": "field", "inboundTag": ["entry-in"], "domain": ["regexp:(?i)\\.ru$"], "outboundTag": "direct"},
                        {"type": "field", "inboundTag": ["entry-in"], "outboundTag": "to-transit"},
                    ]
                },
            }
        ),
    )
    for connection_id, path_name, host in (
        ("a", "public_ipv4", "203.0.113.10"),
        ("b", "manual", "10.200.0.1"),
    ):
        _write(
            tmp_path / f"users/u1/connection-{connection_id}.json",
            json.dumps(
                {
                    "user_id": "u1",
                    "device_id": "d1",
                    "connection_id": connection_id,
                    "revision_id": f"r-{connection_id}",
                    "protocol": "vless_reality",
                    "variant": "V2",
                    "config": {
                        "uuid": connection_id,
                        "sni": "splitter.wb.ru",
                        "transit": {
                            "mode": "sticky",
                            "scope": "connection",
                            "selected_path": {"name": path_name, "host": host, "port": 443},
                        },
                    },
                }
            ),
        )

    changed = reconcile_all(settings)
    assert changed == ["xray"]

    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    outbounds = {str(row.get("tag")): row for row in rendered["outbounds"]}
    assert outbounds["to-transit"]["settings"]["vnext"][0]["address"] == "transit.example.com"
    assert outbounds["to-transit"]["settings"]["vnext"][0]["port"] == 443
    assert set(outbounds) == {"direct", "to-transit"}


def test_reconcile_entry_reality_dest_follows_latest_selected_sni(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "entry-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "security": "reality",
                            "realitySettings": {
                                "dest": "splitter.wb.ru:443",
                                "serverNames": [],
                            },
                        },
                    }
                ],
                "outbounds": [{"protocol": "freedom"}],
            }
        ),
    )
    _write(
        tmp_path / "users/u2/connection-old.json",
        json.dumps(
            {
                "user_id": "u2",
                "device_id": "d2",
                "connection_id": "old",
                "revision_id": "r1",
                "op_ts": "2026-02-20T22:00:00+00:00",
                "protocol": "vless_reality",
                "config": {"uuid": "old", "sni": "www.wildberries.ru"},
            }
        ),
    )
    _write(
        tmp_path / "users/u2/connection-new.json",
        json.dumps(
            {
                "user_id": "u2",
                "device_id": "d2",
                "connection_id": "new",
                "revision_id": "r2",
                "op_ts": "2026-02-20T22:05:00+00:00",
                "protocol": "vless_reality",
                "config": {"uuid": "new", "sni": "st.ozone.ru"},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray"]

    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    reality = rendered["inbounds"][0]["streamSettings"]["realitySettings"]
    assert reality["dest"] == "st.ozone.ru:443"
    assert "www.wildberries.ru" in reality["serverNames"]
    assert "st.ozone.ru" in reality["serverNames"]


def test_reconcile_keeps_static_base_reality_clients(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="TRANSIT",
    )
    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "vless-reality-in",
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {
                                    "id": "00000000-0000-4000-8000-000000000123",
                                    "email": "entry-transit",
                                }
                            ]
                        },
                        "streamSettings": {"security": "reality", "realitySettings": {"serverNames": []}},
                    }
                ],
                "outbounds": [{"protocol": "freedom"}],
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-c1.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "c1",
                "revision_id": "r1",
                "protocol": "vless_reality",
                "config": {"uuid": "11111111-1111-4111-8111-111111111111", "sni": "splitter.wb.ru"},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert "xray" in changed

    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    ids = {row.get("id") for row in rendered["inbounds"][0]["settings"]["clients"]}
    assert "00000000-0000-4000-8000-000000000123" in ids
    assert "11111111-1111-4111-8111-111111111111" in ids


def test_reconcile_entry_ignores_ws_direct_artifacts_not_targeted_to_role(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "entry-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "reality", "realitySettings": {"serverNames": []}},
                    },
                    {
                        "tag": "vless-ws-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"network": "ws", "security": "none"},
                    },
                ],
                "outbounds": [{"protocol": "freedom"}],
            }
        ),
    )

    # V1 WS+TLS is direct and should be reconciled only on Transit.
    _write(
        tmp_path / "users/u1/connection-ws-v1.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "ws-v1",
                "revision_id": "r-ws",
                "protocol": "vless_ws_tls",
                "variant": "V1",
                "config": {"uuid": "ws-v1"},
            }
        ),
    )
    # V2 chain reality should still be present on Entry.
    _write(
        tmp_path / "users/u1/connection-chain-v2.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "chain-v2",
                "revision_id": "r-chain",
                "protocol": "vless_reality",
                "variant": "V2",
                "config": {"uuid": "chain-v2", "sni": "splitter.wb.ru"},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert "xray" in changed

    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    entry_clients = rendered["inbounds"][0]["settings"]["clients"]
    ws_clients = rendered["inbounds"][1]["settings"]["clients"]
    assert [row.get("id") for row in entry_clients] == ["chain-v2"]
    assert ws_clients == []


def test_reconcile_transit_ignores_chain_public_xray_clients_but_keeps_link_crypto(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="TRANSIT",
        agent_runtime_profile="tracegate-2.1",
        private_runtime_root=str(tmp_path / "private"),
        private_link_crypto_enabled=True,
        agent_reload_link_crypto_cmd="reload-link-crypto",
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "vless-reality-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "reality", "realitySettings": {"serverNames": []}},
                    },
                    {
                        "tag": "hy2-in",
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {"network": "hysteria", "security": "none"},
                    },
                ],
                "outbounds": [{"protocol": "freedom"}],
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-chain-v2.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "chain-v2",
                "revision_id": "r-chain-v2",
                "protocol": "vless_reality",
                "variant": "V2",
                "config": {"uuid": "chain-v2", "sni": "splitter.wb.ru"},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-chain-v4.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "chain-v4",
                "revision_id": "r-chain-v4",
                "protocol": "hysteria2",
                "variant": "V4",
                "config": {"auth": {"type": "userpass", "username": "u1", "password": "d1"}},
            }
        ),
    )

    changed = reconcile_all(settings)

    assert "xray" in changed
    assert "link-crypto" in changed
    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert rendered["inbounds"][0]["settings"]["clients"] == []
    assert rendered["inbounds"][1]["settings"]["clients"] == []
    link_crypto = json.loads((tmp_path / "private/link-crypto/transit/desired-state.json").read_text(encoding="utf-8"))
    assert link_crypto["transportProfiles"]["localSocks"]["auth"] == "required"
    assert link_crypto["links"][0]["class"] == "entry-transit"
    assert link_crypto["links"][0]["selectedProfiles"] == ["V1", "V3"]
    assert link_crypto["links"][0]["managedBy"] == "link-crypto"
    assert link_crypto["links"][0]["xrayBackhaul"] is False
    assert link_crypto["links"][0]["local"]["auth"]["mode"] == "private-profile"


def test_reconcile_tracegate21_strips_legacy_xray_backhaul_from_runtime(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
        agent_runtime_profile="tracegate-2.1",
        private_runtime_root=str(tmp_path / "private"),
        private_link_crypto_enabled=True,
        agent_reload_link_crypto_cmd="reload-link-crypto",
    )
    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "vless-reality-in",
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "reality", "realitySettings": {"serverNames": []}},
                    },
                    {
                        "tag": "hy2-in",
                        "protocol": "hysteria",
                        "settings": {"clients": []},
                        "streamSettings": {"network": "hysteria", "security": "none"},
                    },
                ],
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom"},
                    {
                        "tag": "to-transit",
                        "protocol": "vless",
                        "settings": {"vnext": [{"address": "transit.example.com", "port": 443, "users": []}]},
                    },
                    {
                        "tag": "to-transit-public-ipv4",
                        "protocol": "vless",
                        "settings": {"vnext": [{"address": "203.0.113.10", "port": 443, "users": []}]},
                    },
                ],
                "routing": {
                    "rules": [
                        {"type": "field", "inboundTag": ["vless-reality-in"], "outboundTag": "to-transit"},
                        {"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "to-transit-public-ipv4"},
                        {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                    ]
                },
            }
        ),
    )

    changed = reconcile_all(settings)

    assert "xray" in changed
    assert "link-crypto" in changed
    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert {str(row.get("tag")) for row in rendered["outbounds"]} == {"direct"}
    assert all(not str(row.get("outboundTag") or "").startswith("to-transit") for row in rendered["routing"]["rules"])
    runtime_contract = json.loads((tmp_path / "runtime/runtime-contract.json").read_text(encoding="utf-8"))
    assert runtime_contract["runtimeProfile"] == "tracegate-2.1"
    assert runtime_contract["localSocksAuth"] == "required"
    assert runtime_contract["contract"]["xrayBackhaulAllowed"] is False
    assert runtime_contract["transportProfiles"]["clientNames"] == [
        "V1-VLESS-Reality-Direct",
        "V1-VLESS-gRPC-TLS-Direct",
        "V1-VLESS-WS-TLS-Direct",
        "V2-VLESS-Reality-Chain",
        "V3-Hysteria2-QUIC-Direct",
        "V4-Hysteria2-QUIC-Chain",
        "V5-Shadowsocks2022-ShadowTLS-Direct",
        "V6-Shadowsocks2022-ShadowTLS-Chain",
        "V7-WireGuard-WSTunnel-Direct",
        "MTProto-FakeTLS-Direct",
    ]
    assert runtime_contract["transportProfiles"]["localSocks"] == {
        "auth": "required",
        "allowAnonymousLocalhost": False,
    }
    assert runtime_contract["transportProfiles"]["clientExposure"] == {
        "defaultMode": "vpn-tun",
        "localProxyExports": "advanced-only",
        "lanSharing": "forbidden",
        "unauthenticatedLocalProxy": "forbidden",
    }
    assert runtime_contract["network"]["egressIsolation"]["required"] is True
    assert runtime_contract["network"]["egressIsolation"]["mode"] == "dedicated-egress-ip"
    assert runtime_contract["network"]["egressIsolation"]["forbidIngressIpAsEgress"] is True
    assert runtime_contract["network"]["egressIsolation"]["enforcement"]["ingressPublicIpOutbound"] == "forbidden"
    assert runtime_contract["linkCrypto"]["carrier"] == "mieru"
    assert runtime_contract["linkCrypto"]["manager"] == "link-crypto"
    assert runtime_contract["linkCrypto"]["profileSource"] == "private-file-reference"
    assert runtime_contract["linkCrypto"]["secretMaterial"] is False
    assert runtime_contract["linkCrypto"]["xrayBackhaul"] is False
    assert runtime_contract["linkCrypto"]["classes"] == ["entry-transit"]
    assert runtime_contract["linkCrypto"]["outerCarrier"]["mode"] == "wss"
    assert runtime_contract["linkCrypto"]["outerCarrier"]["url"] == "wss://bridge.example.com:443/cdn-cgi/tracegate-link"
    assert runtime_contract["rollout"]["gatewayStrategy"] == "RollingUpdate"
    assert runtime_contract["rollout"]["maxUnavailable"] == "0"
    assert runtime_contract["rollout"]["privatePreflightForbidPlaceholders"] is True


def test_reconcile_reality_multi_inbound_groups_assign_by_sni_and_keep_fallback(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
        reality_multi_inbound_groups=[
            {
                "id": "shared-a",
                "port": 2501,
                "dest": "splitter.wb.ru",
                "snis": ["splitter.wb.ru"],
            },
            {
                "id": "shared-b",
                "port": 2502,
                "dest": "st.ozone.ru",
                "snis": ["st.ozone.ru"],
            },
        ],
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "entry-in",
                        "protocol": "vless",
                        "port": 2443,
                        "settings": {"clients": []},
                        "streamSettings": {
                            "security": "reality",
                            "realitySettings": {"dest": "splitter.wb.ru:443", "serverNames": ["splitter.wb.ru"]},
                        },
                    }
                ],
                "outbounds": [{"protocol": "freedom"}],
                "routing": {
                    "rules": [
                        {"type": "field", "inboundTag": ["entry-in"], "outboundTag": "direct"},
                    ]
                },
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-a.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "a",
                "revision_id": "r1",
                "protocol": "vless_reality",
                "config": {"uuid": "a", "sni": "splitter.wb.ru"},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-b.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "b",
                "revision_id": "r2",
                "protocol": "vless_reality",
                "config": {"uuid": "b", "sni": "st.ozone.ru"},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-legacy.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "legacy",
                "revision_id": "r3",
                "protocol": "vless_reality",
                "config": {"uuid": "legacy", "sni": "legacy.example.com"},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray"]

    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    inbounds = {str(row.get("tag")): row for row in rendered["inbounds"]}
    assert "entry-in" in inbounds
    assert "entry-in-shared-a" in inbounds
    assert "entry-in-shared-b" in inbounds
    assert inbounds["entry-in-shared-a"]["port"] == 2501
    assert inbounds["entry-in-shared-b"]["port"] == 2502

    fallback_ids = {row.get("id") for row in inbounds["entry-in"]["settings"]["clients"]}
    shared_a_ids = {row.get("id") for row in inbounds["entry-in-shared-a"]["settings"]["clients"]}
    shared_b_ids = {row.get("id") for row in inbounds["entry-in-shared-b"]["settings"]["clients"]}
    assert fallback_ids == {"a", "b", "legacy"}
    assert shared_a_ids == {"a"}
    assert shared_b_ids == {"b"}

    reality_a = inbounds["entry-in-shared-a"]["streamSettings"]["realitySettings"]
    reality_b = inbounds["entry-in-shared-b"]["streamSettings"]["realitySettings"]
    reality_fallback = inbounds["entry-in"]["streamSettings"]["realitySettings"]
    assert reality_a["dest"] == "splitter.wb.ru:443"
    assert reality_b["dest"] == "st.ozone.ru:443"
    assert "legacy.example.com" in reality_fallback["serverNames"]

    route_tags = rendered["routing"]["rules"][0]["inboundTag"]
    assert "entry-in" in route_tags
    assert "entry-in-shared-a" in route_tags
    assert "entry-in-shared-b" in route_tags


def test_reconcile_reality_multi_inbound_groups_is_idempotent_with_materialized_grouped_base(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
        reality_multi_inbound_groups=[
            {
                "id": "shared-a",
                "port": 2501,
                "dest": "splitter.wb.ru",
                "snis": ["splitter.wb.ru"],
            },
            {
                "id": "shared-b",
                "port": 2502,
                "dest": "st.ozone.ru",
                "snis": ["st.ozone.ru"],
            },
        ],
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "entry-in",
                        "protocol": "vless",
                        "port": 2443,
                        "settings": {"clients": []},
                        "streamSettings": {
                            "security": "reality",
                            "realitySettings": {"dest": "splitter.wb.ru:443", "serverNames": ["splitter.wb.ru"]},
                        },
                    },
                    {
                        "tag": "entry-in-shared-a",
                        "protocol": "vless",
                        "port": 2501,
                        "settings": {"clients": []},
                        "streamSettings": {
                            "security": "reality",
                            "realitySettings": {"dest": "splitter.wb.ru:443", "serverNames": ["splitter.wb.ru"]},
                        },
                    },
                    {
                        "tag": "entry-in-shared-b",
                        "protocol": "vless",
                        "port": 2502,
                        "settings": {"clients": []},
                        "streamSettings": {
                            "security": "reality",
                            "realitySettings": {"dest": "st.ozone.ru:443", "serverNames": ["st.ozone.ru"]},
                        },
                    },
                ],
                "outbounds": [{"protocol": "freedom"}],
                "routing": {
                    "rules": [
                        {
                            "type": "field",
                            "inboundTag": ["entry-in", "entry-in-shared-a", "entry-in-shared-b"],
                            "outboundTag": "direct",
                        },
                    ]
                },
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-a.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "a",
                "revision_id": "r1",
                "protocol": "vless_reality",
                "config": {"uuid": "a", "sni": "splitter.wb.ru"},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-b.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "b",
                "revision_id": "r2",
                "protocol": "vless_reality",
                "config": {"uuid": "b", "sni": "st.ozone.ru"},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray"]

    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    tags = [str(row.get("tag")) for row in rendered["inbounds"]]
    assert tags.count("entry-in") == 1
    assert tags.count("entry-in-shared-a") == 1
    assert tags.count("entry-in-shared-b") == 1
    assert {row.get("id") for row in next(row for row in rendered["inbounds"] if row["tag"] == "entry-in-shared-a")["settings"]["clients"]} == {"a"}
    assert {row.get("id") for row in next(row for row in rendered["inbounds"] if row["tag"] == "entry-in-shared-b")["settings"]["clients"]} == {"b"}


def test_reconcile_entry_v2_split_backend_moves_reality_inbounds_to_sidecar(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="ENTRY",
        agent_entry_v2_split_backend_enabled=True,
        reality_multi_inbound_groups=[
            {
                "id": "shared-a",
                "port": 2501,
                "dest": "splitter.wb.ru",
                "snis": ["splitter.wb.ru"],
            },
            {
                "id": "shared-b",
                "port": 2502,
                "dest": "st.ozone.ru",
                "snis": ["st.ozone.ru"],
            },
        ],
    )

    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "api",
                        "protocol": "dokodemo-door",
                        "port": 8080,
                        "settings": {"address": "127.0.0.1"},
                    },
                    {
                        "tag": "entry-in",
                        "protocol": "vless",
                        "port": 2443,
                        "settings": {"clients": []},
                        "streamSettings": {
                            "security": "reality",
                            "realitySettings": {"dest": "splitter.wb.ru:443", "serverNames": ["splitter.wb.ru"]},
                        },
                    },
                    {
                        "tag": "vless-ws-in",
                        "protocol": "vless",
                        "port": 10000,
                        "settings": {"clients": []},
                        "streamSettings": {"network": "ws", "security": "none"},
                    },
                ],
                "outbounds": [{"protocol": "freedom"}],
                "routing": {
                    "rules": [
                        {"type": "field", "inboundTag": ["entry-in"], "outboundTag": "direct"},
                    ]
                },
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-a.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "a",
                "revision_id": "r1",
                "protocol": "vless_reality",
                "config": {"uuid": "a", "sni": "splitter.wb.ru"},
            }
        ),
    )
    _write(
        tmp_path / "users/u1/connection-b.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "b",
                "revision_id": "r2",
                "protocol": "vless_reality",
                "config": {"uuid": "b", "sni": "st.ozone.ru"},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray"]

    rendered_main = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    main_tags = {str(row.get("tag")) for row in rendered_main["inbounds"]}
    assert main_tags == {"api", "vless-ws-in"}

    rendered_v2 = json.loads((tmp_path / "runtime/xray-v2/config.json").read_text(encoding="utf-8"))
    v2_inbounds = {str(row.get("tag")): row for row in rendered_v2["inbounds"]}
    assert set(v2_inbounds) == {"entry-in", "entry-in-shared-a", "entry-in-shared-b"}
    assert {row.get("id") for row in v2_inbounds["entry-in-shared-a"]["settings"]["clients"]} == {"a"}
    assert {row.get("id") for row in v2_inbounds["entry-in-shared-b"]["settings"]["clients"]} == {"b"}
