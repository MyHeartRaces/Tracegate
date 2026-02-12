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


def test_reconcile_vps_e_updates_only_xray(tmp_path: Path) -> None:
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
    assert changed == ["xray"]
    assert (tmp_path / "runtime/xray/config.json").exists()
    assert not (tmp_path / "runtime/hysteria/config.yaml").exists()
    assert not (tmp_path / "runtime/wireguard/wg0.conf").exists()


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
