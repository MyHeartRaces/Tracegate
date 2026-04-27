from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tracegate.cli.paired_udp_obfs_runner import main
from tracegate.services.paired_udp_obfs_runner import (
    PairedUdpObfsRunnerError,
    build_paired_udp_obfs_runner_plan,
    exec_paired_udp_obfs,
)


def _write_profile(path: Path, **overrides: object) -> Path:
    payload: dict[str, object] = {
        "TRACEGATE_UDP_OBFS_BACKEND": "udp2raw",
        "TRACEGATE_UDP_OBFS_MODE": "udp2raw-faketcp",
        "TRACEGATE_UDP_OBFS_SIDE": "client",
        "TRACEGATE_UDP_OBFS_LISTEN": "127.0.0.1:18443",
        "TRACEGATE_UDP_OBFS_TARGET": "transit.example.com:18443",
        "TRACEGATE_UDP_OBFS_KEY": "private-secret-0001",
        "TRACEGATE_UDP_OBFS_UDP2RAW_BIN": "/usr/local/bin/udp2raw",
        "TRACEGATE_UDP_OBFS_CIPHER_MODE": "aes128cbc",
        "TRACEGATE_UDP_OBFS_AUTH_MODE": "md5",
        "TRACEGATE_UDP_OBFS_REQUIRES_BOTH_SIDES": "true",
        "TRACEGATE_UDP_OBFS_FAIL_CLOSED": "true",
        "TRACEGATE_UDP_OBFS_NO_HOST_WIDE_INTERCEPTION": "true",
        "TRACEGATE_UDP_OBFS_NO_NFQUEUE": "true",
        "TRACEGATE_UDP_OBFS_PUBLIC_UDP_PORT": "8443",
        "TRACEGATE_UDP_OBFS_FORBID_UDP_443": "true",
        "TRACEGATE_UDP_OBFS_FORBID_TCP_8443": "true",
        "TRACEGATE_UDP_OBFS_DPI_MODE": "salamander-plus-scoped-paired-obfs",
        "TRACEGATE_UDP_OBFS_PACKET_SHAPE": "bounded-profile",
        "TRACEGATE_UDP_OBFS_MTU_MODE": "clamp",
        "TRACEGATE_UDP_OBFS_MAX_PACKET_SIZE": "1252",
        "TRACEGATE_UDP_OBFS_AUTO_FIREWALL": "false",
    }
    payload.update(overrides)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"{key}={value}" for key, value in payload.items()) + "\n", encoding="utf-8")
    return path


def test_paired_udp_obfs_runner_builds_redacted_udp2raw_client_plan(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path / "paired-obfs.env")

    plan = build_paired_udp_obfs_runner_plan(action="plan", profile_path=profile)

    assert plan["schema"] == "tracegate.paired-udp-obfs-runner-plan.v1"
    assert plan["mode"] == "udp2raw-faketcp"
    assert plan["side"] == "client"
    assert plan["security"]["secretMaterialInline"] is False
    assert plan["security"]["requiresBothSides"] is True
    assert plan["security"]["failClosed"] is True
    assert plan["security"]["forbiddenPublicPorts"] == [
        {"protocol": "udp", "port": 443, "action": "drop"},
        {"protocol": "tcp", "port": 8443, "action": "drop"},
    ]
    assert plan["dpiResistance"] == {
        "enabled": True,
        "mode": "salamander-plus-scoped-paired-obfs",
        "portSplit": {
            "publicUdpPort": 8443,
            "forbidUdp443": True,
            "forbidTcp8443": True,
        },
        "packetShape": {
            "strategy": "bounded-profile",
            "mtuMode": "clamp",
            "maxPacketSize": 1252,
        },
    }
    assert plan["command"] == [
        "/usr/local/bin/udp2raw",
        "-c",
        "-l",
        "127.0.0.1:18443",
        "-r",
        "transit.example.com:18443",
        "-k",
        "REDACTED",
        "--raw-mode",
        "faketcp",
        "--cipher-mode",
        "aes128cbc",
        "--auth-mode",
        "md5",
    ]
    assert "private-secret-0001" not in json.dumps(plan)


def test_paired_udp_obfs_runner_accepts_server_loopback_target(tmp_path: Path) -> None:
    profile = _write_profile(
        tmp_path / "paired-obfs.env",
        TRACEGATE_UDP_OBFS_SIDE="server",
        TRACEGATE_UDP_OBFS_MODE="udp2raw-icmp",
        TRACEGATE_UDP_OBFS_LISTEN="0.0.0.0:18443",
        TRACEGATE_UDP_OBFS_TARGET="127.0.0.1:14482",
    )

    plan = build_paired_udp_obfs_runner_plan(action="validate", profile_path=profile, udp2raw_bin="/opt/udp2raw")

    assert plan["command"][0] == "/opt/udp2raw"
    assert "-s" in plan["command"]
    assert plan["command"][plan["command"].index("--raw-mode") + 1] == "icmp"
    assert "-a" not in plan["command"]
    assert plan["security"]["autoFirewall"] is False


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"TRACEGATE_UDP_OBFS_KEY": "CHANGE_ME"}, "non-placeholder secret"),
        ({"TRACEGATE_UDP_OBFS_REQUIRES_BOTH_SIDES": "false"}, "REQUIRES_BOTH_SIDES"),
        ({"TRACEGATE_UDP_OBFS_FAIL_CLOSED": "false"}, "FAIL_CLOSED"),
        ({"TRACEGATE_UDP_OBFS_CIPHER_MODE": "none"}, "CIPHER_MODE"),
        ({"TRACEGATE_UDP_OBFS_AUTO_FIREWALL": "true"}, "AUTO_FIREWALL"),
        ({"TRACEGATE_UDP_OBFS_PUBLIC_UDP_PORT": "443"}, "PUBLIC_UDP_PORT"),
        ({"TRACEGATE_UDP_OBFS_FORBID_UDP_443": "false"}, "FORBID_UDP_443"),
        ({"TRACEGATE_UDP_OBFS_FORBID_TCP_8443": "false"}, "FORBID_TCP_8443"),
        ({"TRACEGATE_UDP_OBFS_DPI_MODE": "plain"}, "DPI_MODE"),
        ({"TRACEGATE_UDP_OBFS_PACKET_SHAPE": "none"}, "PACKET_SHAPE"),
        ({"TRACEGATE_UDP_OBFS_MTU_MODE": "auto"}, "MTU_MODE"),
        ({"TRACEGATE_UDP_OBFS_MAX_PACKET_SIZE": "1500"}, "MAX_PACKET_SIZE"),
        ({"TRACEGATE_UDP_OBFS_SIDE": "client", "TRACEGATE_UDP_OBFS_LISTEN": "0.0.0.0:18443"}, "loopback"),
        ({"TRACEGATE_UDP_OBFS_SIDE": "server", "TRACEGATE_UDP_OBFS_TARGET": "198.51.100.10:14482"}, "loopback"),
    ],
)
def test_paired_udp_obfs_runner_rejects_unsafe_profiles(
    tmp_path: Path,
    overrides: dict[str, object],
    message: str,
) -> None:
    profile = _write_profile(tmp_path / "paired-obfs.env", **overrides)

    with pytest.raises(PairedUdpObfsRunnerError, match=message):
        build_paired_udp_obfs_runner_plan(action="plan", profile_path=profile)


def test_paired_udp_obfs_cli_prints_json_plan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    profile = _write_profile(tmp_path / "paired-obfs.env")

    main(["validate", str(profile), "--json"])

    out = json.loads(capsys.readouterr().out)
    assert out["action"] == "validate"
    assert out["command"][out["command"].index("-k") + 1] == "REDACTED"


def test_paired_udp_obfs_start_execs_udp2raw_without_shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _write_profile(tmp_path / "paired-obfs.env")
    captured: dict[str, list[str] | str] = {}

    def _fake_execvp(file: str, args: list[str]) -> None:
        captured["file"] = file
        captured["args"] = args
        raise RuntimeError("stop")

    monkeypatch.setattr(os, "execvp", _fake_execvp)

    with pytest.raises(RuntimeError, match="stop"):
        exec_paired_udp_obfs(profile, udp2raw_bin="/opt/udp2raw")

    assert captured["file"] == "/opt/udp2raw"
    assert captured["args"] == [
        "/opt/udp2raw",
        "-c",
        "-l",
        "127.0.0.1:18443",
        "-r",
        "transit.example.com:18443",
        "-k",
        "private-secret-0001",
        "--raw-mode",
        "faketcp",
        "--cipher-mode",
        "aes128cbc",
        "--auth-mode",
        "md5",
    ]
