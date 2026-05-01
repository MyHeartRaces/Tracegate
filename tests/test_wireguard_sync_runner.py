import json
import subprocess
from pathlib import Path

from tracegate.cli import wireguard_sync_runner


def test_wireguard_sync_runner_applies_desired_peers_and_removes_stale(tmp_path: Path, monkeypatch) -> None:
    state_path = tmp_path / "desired-state.json"
    state_path.write_text(
        json.dumps(
            {
                "wireguardWSTunnel": [
                    {
                        "wireguard": {
                            "clientPublicKey": "client-public",
                            "presharedKey": "client-psk",
                            "allowedIps": ["10.70.1.2/32"],
                            "persistentKeepalive": 25,
                        },
                        "sync": {"interface": "wg0"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def fake_run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        if args == ["show", "wg0"]:
            return subprocess.CompletedProcess(["wg", *args], 0, "", "")
        if args == ["show", "wg0", "peers"]:
            return subprocess.CompletedProcess(["wg", *args], 0, "stale-public\nclient-public\n", "")
        calls.append(args)
        if "preshared-key" in args:
            psk_path = Path(args[args.index("preshared-key") + 1])
            assert psk_path.read_text(encoding="utf-8") == "client-psk\n"
        return subprocess.CompletedProcess(["wg", *args], 0, "", "")

    monkeypatch.setattr(wireguard_sync_runner, "_run_wg", fake_run)

    summary = wireguard_sync_runner.sync_once(state_path=state_path, interface="wg0")

    assert summary == {"ready": 1, "desired": 1, "applied": 1, "removed": 1}
    assert calls[0][:4] == ["set", "wg0", "peer", "client-public"]
    assert calls[0][-4:] == ["allowed-ips", "10.70.1.2/32", "persistent-keepalive", "25"]
    assert calls[1] == ["set", "wg0", "peer", "stale-public", "remove"]


def test_wireguard_sync_runner_waits_for_interface(tmp_path: Path, monkeypatch) -> None:
    def fake_run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        assert args == ["show", "wg0"]
        return subprocess.CompletedProcess(["wg", *args], 1, "", "missing")

    monkeypatch.setattr(wireguard_sync_runner, "_run_wg", fake_run)

    assert wireguard_sync_runner.sync_once(state_path=tmp_path / "missing.json", interface="wg0") == {
        "ready": 0,
        "desired": 0,
        "applied": 0,
        "removed": 0,
    }
