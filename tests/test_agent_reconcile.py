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

    changed = reconcile_all(settings)
    assert set(changed) >= {"xray", "hysteria", "wireguard"}

    rendered_xray = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert rendered_xray["inbounds"][0]["settings"]["clients"][0]["id"] == "c1"
    assert "splitter.wb.ru" in rendered_xray["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"]

    rendered_hy = (tmp_path / "runtime/hysteria/config.yaml").read_text(encoding="utf-8")
    assert "bootstrap: bootstrap" in rendered_hy
    assert "u1: d1" in rendered_hy
