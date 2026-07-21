from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


SCRIPT = Path(__file__).parents[1] / "deploy/systemd/tracegate-backhaul-fragment-config"


def test_fragment_config_uses_byte_preserving_stream_slicing(tmp_path: Path) -> None:
    target = tmp_path / "1.json"
    env = {
        **os.environ,
        "SHADOWTLS_BACKHAUL_TARGET": "endpoint.example:9443",
        "SHADOWTLS_BACKHAUL_FRAGMENT1_LISTEN": "127.0.0.1:16443",
        "TRACEGATE_BACKHAUL_FRAGMENT_CONFIG_FILE": str(target),
    }
    subprocess.run([sys.executable, str(SCRIPT), "1"], env=env, check=True)

    payload = json.loads(target.read_text(encoding="utf-8"))
    inbound = payload["inbounds"][0]
    outbound = payload["outbounds"][0]
    assert inbound["listen"] == "127.0.0.1"
    assert inbound["port"] == 16443
    assert inbound["settings"] == {"address": "endpoint.example", "port": 9443, "network": "tcp"}
    assert outbound["settings"]["fragment"] == {
        "packets": "1-1",
        "length": "1-4",
        "interval": "1-2",
    }
    assert target.stat().st_mode & 0o777 == 0o600


def test_fragment_config_rejects_tls_record_rewriting(tmp_path: Path) -> None:
    env = {
        **os.environ,
        "SHADOWTLS_BACKHAUL_TARGET": "endpoint.example:9443",
        "SHADOWTLS_BACKHAUL_FRAGMENT_PACKETS": "tlshello",
        "TRACEGATE_BACKHAUL_FRAGMENT_CONFIG_FILE": str(tmp_path / "1.json"),
    }
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "1"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "integer or integer range" in completed.stderr


def test_fragment_config_rejects_non_loopback_listener(tmp_path: Path) -> None:
    env = {
        **os.environ,
        "SHADOWTLS_BACKHAUL2_TARGET": "endpoint.example:9444",
        "SHADOWTLS_BACKHAUL_FRAGMENT2_LISTEN": "0.0.0.0:16444",
        "TRACEGATE_BACKHAUL_FRAGMENT_CONFIG_FILE": str(tmp_path / "2.json"),
    }
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "2"],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "loopback" in completed.stderr


def test_fragment_config_supports_independent_leg_slicing(tmp_path: Path) -> None:
    target = tmp_path / "2.json"
    env = {
        **os.environ,
        "SHADOWTLS_BACKHAUL2_TARGET": "endpoint.example:9444",
        "SHADOWTLS_BACKHAUL_FRAGMENT_PACKETS": "1-1",
        "SHADOWTLS_BACKHAUL_FRAGMENT_LENGTH": "1-4",
        "SHADOWTLS_BACKHAUL_FRAGMENT_INTERVAL_MS": "1-2",
        "SHADOWTLS_BACKHAUL_FRAGMENT2_PACKETS": "1-2",
        "SHADOWTLS_BACKHAUL_FRAGMENT2_LENGTH": "2-8",
        "SHADOWTLS_BACKHAUL_FRAGMENT2_INTERVAL_MS": "3-5",
        "TRACEGATE_BACKHAUL_FRAGMENT_CONFIG_FILE": str(target),
    }
    subprocess.run([sys.executable, str(SCRIPT), "2"], env=env, check=True)
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["outbounds"][0]["settings"]["fragment"] == {
        "packets": "1-2",
        "length": "2-8",
        "interval": "3-5",
    }
