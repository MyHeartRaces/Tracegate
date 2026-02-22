import json
from pathlib import Path

from tracegate.agent.reconcile import reconcile_all
from tracegate.settings import Settings


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_reconcile_xray_and_hysteria(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="VPS_T",
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
                    }
                ],
                "outbounds": [{"protocol": "freedom"}],
            }
        ),
    )
    _write(
        tmp_path / "base/hysteria/config.yaml",
        "listen: :443\nauth:\n  type: userpass\n  userpass:\n    bootstrap: bootstrap\n",
    )
    _write(tmp_path / "base/wireguard/wg0.conf", "[Interface]\nListenPort = 51820\nPrivateKey = x\nAddress = 10.70.0.1/24\n\n")

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

    changed = reconcile_all(settings)
    assert set(changed) >= {"xray", "hysteria", "wireguard"}

    rendered_xray = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert rendered_xray["inbounds"][0]["settings"]["clients"][0]["id"] == "c1"
    assert "splitter.wb.ru" in rendered_xray["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"]
    assert rendered_xray["inbounds"][1]["settings"]["clients"][0]["id"] == "c3"

    rendered_hy = (tmp_path / "runtime/hysteria/config.yaml").read_text(encoding="utf-8")
    assert "bootstrap: bootstrap" in rendered_hy
    assert "u1: d1" in rendered_hy

    # Second run should be a no-op (no unnecessary reload triggers).
    changed2 = reconcile_all(settings)
    assert changed2 == []


def test_reconcile_vps_e_updates_xray_and_hysteria_only(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="VPS_E",
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
    _write(tmp_path / "base/hysteria/config.yaml", "listen: :443\n")
    _write(tmp_path / "base/wireguard/wg0.conf", "[Interface]\nListenPort = 51820\n")
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
    assert changed == ["xray", "hysteria"]
    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert rendered["inbounds"][0]["streamSettings"]["realitySettings"]["dest"] == "vk.com:443"
    assert (tmp_path / "runtime/hysteria/config.yaml").exists()
    assert not (tmp_path / "runtime/wireguard/wg0.conf").exists()


def test_reconcile_hysteria_adds_legacy_and_ios_safe_userpass_aliases(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="VPS_T",
    )

    _write(
        tmp_path / "base/hysteria/config.yaml",
        "listen: :443\nauth:\n  type: userpass\n  userpass:\n    bootstrap: bootstrap\n",
    )
    _write(
        tmp_path / "users/255761416/connection-b3.json",
        json.dumps(
            {
                "user_id": "255761416",
                "connection_id": "531ce66a-9265-477b-bfab-1dccf53bac6f",
                "variant": "B3",
                "protocol": "hysteria2",
                "config": {
                    "auth": {
                        "type": "userpass",
                        "username": "b3_255761416_531ce66a9265477bbfab1dccf53bac6f",
                        "password": "dev-pass",
                    }
                },
            }
        ),
    )

    changed = reconcile_all(settings)
    assert "hysteria" in changed

    rendered_hy = (tmp_path / "runtime/hysteria/config.yaml").read_text(encoding="utf-8")
    assert "bootstrap: bootstrap" in rendered_hy
    assert "b3_255761416_531ce66a9265477bbfab1dccf53bac6f: dev-pass" in rendered_hy
    assert "B3 - 255761416 - 531ce66a-9265-477b-bfab-1dccf53bac6f: dev-pass" in rendered_hy


def test_reconcile_vps_e_forces_transit_port_443(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="VPS_E",
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
                        "settings": {"vnext": [{"address": "vps-t.example.com", "port": 50000, "users": []}]},
                    }
                ],
            }
        ),
    )

    changed = reconcile_all(settings)
    assert changed == ["xray"]

    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert rendered["outbounds"][0]["settings"]["vnext"][0]["port"] == 443


def test_reconcile_vps_e_reality_dest_follows_latest_selected_sni(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="VPS_E",
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
                                "dest": "splitter.wb.ru:8443",
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
        agent_role="VPS_T",
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
                                    "email": "vps-e-transit",
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


def test_reconcile_vps_e_ignores_ws_direct_artifacts_not_targeted_to_role(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="VPS_E",
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

    # B1 WS+TLS is direct and should be reconciled only on VPS-T.
    _write(
        tmp_path / "users/u1/connection-ws-b1.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "ws-b1",
                "revision_id": "r-ws",
                "protocol": "vless_ws_tls",
                "variant": "B1",
                "config": {"uuid": "ws-b1"},
            }
        ),
    )
    # B2 chain reality should still be present on VPS-E.
    _write(
        tmp_path / "users/u1/connection-chain-b2.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "chain-b2",
                "revision_id": "r-chain",
                "protocol": "vless_reality",
                "variant": "B2",
                "config": {"uuid": "chain-b2", "sni": "splitter.wb.ru"},
            }
        ),
    )

    changed = reconcile_all(settings)
    assert "xray" in changed

    rendered = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    entry_clients = rendered["inbounds"][0]["settings"]["clients"]
    ws_clients = rendered["inbounds"][1]["settings"]["clients"]
    assert [row.get("id") for row in entry_clients] == ["chain-b2"]
    assert ws_clients == []


def test_reconcile_reality_multi_inbound_groups_assign_by_sni_and_keep_fallback(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="kubernetes",
        agent_role="VPS_E",
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
    assert fallback_ids == {"legacy"}
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
