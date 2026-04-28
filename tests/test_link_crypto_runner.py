from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from tracegate.cli.link_crypto_runner import main
from tracegate.services import link_crypto_runner as runner_mod
from tracegate.services.link_crypto_runner import (
    LinkCryptoRunnerError,
    LinkCryptoRunnerPaths,
    build_link_crypto_runner_plan,
)
from tracegate.services.runtime_contract import TRACEGATE22_CLIENT_PROFILES


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def _udp_hardening() -> dict:
    return {
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


def _udp_dpi_resistance() -> dict:
    return {
        "enabled": True,
        "mode": "salamander-plus-scoped-paired-obfs",
        "portSplit": {"publicUdpPort": 8443, "forbidUdp443": True, "forbidTcp8443": True},
        "requiredLayers": [
            "hysteria2-quic",
            "salamander",
            "private-auth",
            "anti-replay",
            "anti-amplification",
            "mtu-clamp",
            "source-validation",
        ],
        "pairedObfs": {
            "supported": True,
            "enabled": False,
            "backend": "udp2raw",
            "requiresBothSides": True,
            "failClosed": True,
        },
        "packetShape": {"strategy": "bounded-profile", "mtuMode": "clamp", "maxPacketSize": 1252},
    }


def _private_file_ref(path: str) -> dict:
    return {"kind": "file", "path": path, "secretMaterial": True}


def _tcp_zapret2_policy() -> dict:
    return {
        "enabled": True,
        "required": True,
        "profileFile": "/tmp/tracegate-private/zapret/entry-transit.env",
        "profileSource": "private-file-reference",
        "profileRef": _private_file_ref("/tmp/tracegate-private/zapret/entry-transit.env"),
        "packetShaping": "zapret2-scoped",
        "applyMode": "marked-flow-only",
        "scope": "link-crypto-flow-only",
        "targetSurfaces": ["tcp/443", "entry-transit", "router-link-crypto"],
        "hostWideInterception": False,
        "nfqueue": False,
        "failOpen": True,
    }


def _tcp_dpi_resistance(*, require_outer_carrier: bool = True) -> dict:
    required_layers = [
        "mieru-private-auth",
        "scoped-zapret2",
        "private-zapret2-profile",
        "loopback-only",
        "generation-drain",
        "no-direct-backhaul",
    ]
    if require_outer_carrier:
        required_layers.extend(["outer-wss-tls", "spki-sha256-pin", "hmac-admission"])
    return {
        "enabled": True,
        "mode": "mieru-wss-spki-hmac-zapret2-scoped" if require_outer_carrier else "mieru-zapret2-scoped",
        "requiredLayers": required_layers,
        "outerCarrier": {
            "required": require_outer_carrier,
            "spkiPinningRequired": require_outer_carrier,
            "hmacAdmissionRequired": require_outer_carrier,
        },
        "zapret2": {
            "required": True,
            "enabled": True,
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref("/tmp/tracegate-private/zapret/entry-transit.env"),
            "packetShaping": "zapret2-scoped",
            "applyMode": "marked-flow-only",
            "scope": "link-crypto-flow-only",
            "hostWideInterception": False,
            "nfqueue": False,
        },
        "trafficShaping": {
            "required": True,
            "strategy": "private-zapret2-profile",
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref("/tmp/tracegate-private/link-crypto/tcp-shaping.env"),
            "scope": "marked-flow-only",
            "target": "tcp/443-outer-wss" if require_outer_carrier else "tcp/443-link-crypto",
            "secretMaterial": False,
        },
        "promotionPreflight": {
            "required": True,
            "failClosed": True,
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref("/tmp/tracegate-private/link-crypto/promotion-preflight.env"),
            "checks": [
                "mieru-private-auth",
                "zapret2-scoped-profile",
                "no-direct-backhaul",
            ]
            + (["spki-pin", "hmac-admission"] if require_outer_carrier else []),
            "secretMaterial": False,
        },
    }


def _contract(path: Path) -> dict:
    payload = {
        "role": "ENTRY",
        "runtimeProfile": "tracegate-2.2",
        "contract": {"managedComponents": ["xray"], "xrayBackhaulAllowed": False},
        "transportProfiles": {
            "clientNames": list(TRACEGATE22_CLIENT_PROFILES),
            "localSocks": {"auth": "required", "allowAnonymousLocalhost": False},
        },
        "linkCrypto": {
            "enabled": True,
            "carrier": "mieru",
            "manager": "link-crypto",
            "profileSource": "private-file-reference",
            "secretMaterial": False,
            "xrayBackhaul": False,
            "generation": 1,
            "remotePort": 443,
            "outerCarrier": {
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
                    "profileRef": _private_file_ref("/tmp/tracegate-private/link-crypto/outer-wss-spki.env"),
                    "secretMaterial": False,
                },
                "admission": {
                    "required": True,
                    "mode": "hmac-sha256-generation-bound",
                    "carrier": "websocket-subprotocol",
                    "header": "Sec-WebSocket-Protocol",
                    "profileSource": "private-file-reference",
                    "profileRef": _private_file_ref("/tmp/tracegate-private/link-crypto/outer-wss-admission.env"),
                    "rejectUnauthenticated": True,
                    "secretMaterial": False,
                },
                "localPorts": {"entryClient": 14081, "transitServer": 14082},
                "endpoints": {
                    "entryClientListen": "127.0.0.1:14081",
                    "transitServerListen": "127.0.0.1:14082",
                    "transitTarget": "127.0.0.1:10882",
                },
            },
            "classes": ["entry-transit"],
            "counts": {"total": 1, "entryTransit": 1, "routerEntry": 0, "routerTransit": 0},
            "localPorts": {"entry-transit": 10881},
            "selectedProfiles": {"entry-transit": ["V1", "V3"]},
            "dpiResistance": _tcp_dpi_resistance(),
            "udp": {
                "enabled": True,
                "carrier": "hysteria2",
                "transport": "udp-quic",
                "manager": "link-crypto",
                "profileSource": "private-file-reference",
                "secretMaterial": False,
                "xrayBackhaul": False,
                "remotePort": 8443,
                "obfs": {"type": "salamander", "required": True},
                "pairedObfs": {
                    "enabled": False,
                    "backend": "udp2raw",
                    "mode": "udp2raw-faketcp",
                    "requiresBothSides": True,
                    "failClosed": True,
                    "noHostWideInterception": True,
                    "noNfqueue": True,
                },
                "hardening": _udp_hardening(),
                "dpiResistance": _udp_dpi_resistance(),
                "classes": ["entry-transit-udp"],
                "counts": {"total": 1, "entryTransitUdp": 1, "routerEntryUdp": 0, "routerTransitUdp": 0},
                "localPorts": {"entry-transit-udp": 14481},
                "selectedProfiles": {"entry-transit-udp": ["V2"]},
            },
            "zapret2": _tcp_zapret2_policy(),
        },
    }
    _write_json(path, payload)
    return payload


def _state(path: Path, *, contract: dict, contract_path: Path, paired_obfs_enabled: bool = False) -> dict:
    paired_obfs = {
        "enabled": paired_obfs_enabled,
        "backend": "udp2raw",
        "mode": "udp2raw-faketcp",
        "requiresBothSides": True,
        "failClosed": True,
        "noHostWideInterception": True,
        "noNfqueue": True,
        "profileRef": {
            "kind": "file",
            "path": "/tmp/tracegate-private/udp-link/paired-obfs.env",
            "secretMaterial": True,
        },
    }
    payload = {
        "schema": "tracegate.link-crypto.v1",
        "version": 1,
        "role": "ENTRY",
        "runtimeProfile": contract["runtimeProfile"],
        "runtimeContractPath": str(contract_path),
        "transportProfiles": contract["transportProfiles"],
        "secretMaterial": False,
        "counts": {"total": 1, "entryTransit": 1, "routerEntry": 0, "routerTransit": 0},
        "links": [
            {
                "class": "entry-transit",
                "enabled": True,
                "role": "ENTRY",
                "side": "client",
                "carrier": "mieru",
                "managedBy": "link-crypto",
                "xrayBackhaul": False,
                "generation": 1,
                "profileRef": {
                    "kind": "file",
                    "path": "/tmp/tracegate-private/mieru/client.json",
                    "secretMaterial": True,
                },
                "local": {"listen": "127.0.0.1:10881", "auth": {"required": True, "mode": "private-profile"}},
                "remote": {"role": "TRANSIT", "endpoint": "transit.example.com:443"},
                "outerCarrier": {
                    **contract["linkCrypto"]["outerCarrier"],
                    "side": "client",
                    "localEndpoint": "127.0.0.1:14081",
                    "entryClientListen": "127.0.0.1:14081",
                    "transitServerListen": "127.0.0.1:14082",
                    "transitTarget": "127.0.0.1:10882",
                },
                "selectedProfiles": ["V1", "V3"],
                "zapret2": _tcp_zapret2_policy(),
                "dpiResistance": _tcp_dpi_resistance(),
                "rotation": {"strategy": "generation-drain", "restartExisting": False},
                "stability": {"failOpen": True, "bypassOnFailure": True, "dropUnrelatedTraffic": False},
            }
        ],
        "udpCounts": {"total": 1, "entryTransitUdp": 1, "routerEntryUdp": 0, "routerTransitUdp": 0},
        "udpLinks": [
            {
                "class": "entry-transit-udp",
                "enabled": True,
                "role": "ENTRY",
                "side": "client",
                "carrier": "hysteria2",
                "transport": "udp-quic",
                "managedBy": "link-crypto",
                "xrayBackhaul": False,
                "generation": 1,
                "profileRef": {
                    "kind": "file",
                    "path": "/tmp/tracegate-private/udp-link/client.yaml",
                    "secretMaterial": True,
                },
                "local": {"listen": "127.0.0.1:14481", "protocol": "udp", "auth": {"required": True, "mode": "private-profile"}},
                "remote": {"role": "TRANSIT", "endpoint": "transit.example.com:8443", "protocol": "udp-quic"},
                "datagram": {"udpCapable": True, "innerTransports": ["hysteria2-quic"], "preferredForProfiles": ["V2"]},
                "obfs": {
                    "type": "salamander",
                    "required": True,
                    "profileRef": {
                        "kind": "file",
                        "path": "/tmp/tracegate-private/udp-link/salamander.env",
                        "secretMaterial": True,
                    },
                },
                "pairedObfs": paired_obfs,
                "hardening": _udp_hardening(),
                "dpiResistance": _udp_dpi_resistance() | {
                    "pairedObfs": {
                        **_udp_dpi_resistance()["pairedObfs"],
                        "enabled": paired_obfs_enabled,
                    }
                },
                "selectedProfiles": ["V2"],
                "rotation": {"strategy": "generation-drain", "restartExisting": False},
                "stability": {"failOpen": False, "bypassOnFailure": False, "dropUnrelatedTraffic": False},
            }
        ],
    }
    _write_json(path, payload)
    return payload


def test_link_crypto_runner_builds_mieru_and_hysteria_plan(tmp_path: Path) -> None:
    contract_path = tmp_path / "runtime-contract.json"
    contract = _contract(contract_path)
    state_path = tmp_path / "desired-state.json"
    _state(state_path, contract=contract, contract_path=contract_path)

    plan = build_link_crypto_runner_plan(
        action="plan",
        role="ENTRY",
        paths=LinkCryptoRunnerPaths(
            state_json=state_path,
            runtime_dir=tmp_path / "runtime",
            plan_file=tmp_path / "runner-plan.json",
        ),
        mieru_bin="/usr/bin/mieru",
        hysteria_bin="/usr/local/bin/hysteria",
    )

    assert plan["schema"] == "tracegate.link-crypto-runner-plan.v1"
    assert plan["counts"] == {"mieru": 1, "hysteria2": 1, "pairedUdpObfs": 0}
    assert plan["security"]["secretMaterialInline"] is False
    assert plan["security"]["udpFailClosed"] is True
    assert plan["security"]["udpDpiResistanceRequired"] is True
    assert plan["security"]["tcpDpiResistanceRequired"] is True
    assert plan["security"]["tcpZapret2Required"] is True
    assert plan["security"]["tcpPromotionPreflightRequired"] is True
    by_kind = {row["kind"]: row for row in plan["processes"]}
    assert by_kind["mieru"]["command"] == ["/usr/bin/mieru", "run", "-c", "/tmp/tracegate-private/mieru/client.json"]
    assert by_kind["mieru"]["hardening"]["scope"] == "link-crypto-flow-only"
    assert by_kind["mieru"]["dpiResistance"]["mode"] == "mieru-wss-spki-hmac-zapret2-scoped"
    assert by_kind["hysteria2"]["command"] == [
        "/usr/local/bin/hysteria",
        "client",
        "-c",
        "/tmp/tracegate-private/udp-link/client.yaml",
    ]
    assert by_kind["hysteria2"]["hardening"]["sourceValidation"] == {
        "enabled": True,
        "mode": "profile-bound-remote",
    }
    assert by_kind["hysteria2"]["dpiResistance"]["portSplit"] == {
        "publicUdpPort": 8443,
        "forbidUdp443": True,
        "forbidTcp8443": True,
    }


def test_link_crypto_runner_models_paired_obfs_as_private_runner(tmp_path: Path) -> None:
    contract_path = tmp_path / "runtime-contract.json"
    contract = _contract(contract_path)
    contract["linkCrypto"]["udp"]["pairedObfs"]["enabled"] = True
    _write_json(contract_path, contract)
    state_path = tmp_path / "desired-state.json"
    _state(state_path, contract=contract, contract_path=contract_path, paired_obfs_enabled=True)

    plan = build_link_crypto_runner_plan(
        action="plan",
        role="ENTRY",
        paths=LinkCryptoRunnerPaths(
            state_json=state_path,
            runtime_dir=tmp_path / "runtime",
            plan_file=tmp_path / "runner-plan.json",
        ),
        paired_obfs_runner="/opt/link-crypto-private/udp-obfs-runner",
    )

    assert plan["counts"]["pairedUdpObfs"] == 1
    paired = next(row for row in plan["processes"] if row["kind"] == "paired-udp-obfs")
    assert paired["startable"] is True
    assert paired["command"] == [
        "/opt/link-crypto-private/udp-obfs-runner",
        "plan",
        "/tmp/tracegate-private/udp-link/paired-obfs.env",
    ]
    assert paired["preflightCommand"] == [
        "/opt/link-crypto-private/udp-obfs-runner",
        "validate",
        "/tmp/tracegate-private/udp-link/paired-obfs.env",
    ]


def test_link_crypto_runner_stops_hysteria_before_paired_obfs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract_path = tmp_path / "runtime-contract.json"
    contract = _contract(contract_path)
    contract["linkCrypto"]["udp"]["pairedObfs"]["enabled"] = True
    _write_json(contract_path, contract)
    state_path = tmp_path / "desired-state.json"
    _state(state_path, contract=contract, contract_path=contract_path, paired_obfs_enabled=True)
    plan = build_link_crypto_runner_plan(
        action="stop",
        role="ENTRY",
        paths=LinkCryptoRunnerPaths(
            state_json=state_path,
            runtime_dir=tmp_path / "runtime",
            plan_file=tmp_path / "runner-plan.json",
        ),
        paired_obfs_runner="/opt/link-crypto-private/udp-obfs-runner",
    )

    stopped: list[str] = []

    def _record_stop(process: dict) -> str:
        stopped.append(str(process.get("kind") or ""))
        return "stopped"

    monkeypatch.setattr(runner_mod, "_stop_process", _record_stop)

    result = runner_mod.apply_link_crypto_runner_plan(plan)

    assert result["action"] == "stop"
    assert stopped == ["hysteria2", "paired-udp-obfs", "mieru"]


def test_link_crypto_runner_validates_paired_obfs_before_starting_udp_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract_path = tmp_path / "runtime-contract.json"
    contract = _contract(contract_path)
    contract["linkCrypto"]["udp"]["pairedObfs"]["enabled"] = True
    _write_json(contract_path, contract)
    state_path = tmp_path / "desired-state.json"
    state = _state(state_path, contract=contract, contract_path=contract_path, paired_obfs_enabled=True)
    paired_profile = tmp_path / "paired-obfs.env"
    hysteria_profile = tmp_path / "client.yaml"
    paired_profile.write_text("TRACEGATE_UDP_OBFS_KEY=bad\n", encoding="utf-8")
    hysteria_profile.write_text("client: true\n", encoding="utf-8")
    state["udpLinks"][0]["pairedObfs"]["profileRef"]["path"] = str(paired_profile)
    state["udpLinks"][0]["profileRef"]["path"] = str(hysteria_profile)
    _write_json(state_path, state)
    plan = build_link_crypto_runner_plan(
        action="start",
        role="ENTRY",
        paths=LinkCryptoRunnerPaths(
            state_json=state_path,
            runtime_dir=tmp_path / "runtime",
            plan_file=tmp_path / "runner-plan.json",
        ),
        paired_obfs_runner="/opt/link-crypto-private/udp-obfs-runner",
        include_mieru=False,
    )

    def _fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        assert command == ["/opt/link-crypto-private/udp-obfs-runner", "validate", str(paired_profile)]
        return subprocess.CompletedProcess(command, 1, stdout="TRACEGATE_UDP_OBFS_FAIL_CLOSED must stay true")

    def _unexpected_popen(*_: object, **__: object) -> object:
        raise AssertionError("paired obfs validation must fail before spawning UDP processes")

    monkeypatch.setattr(runner_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(runner_mod.subprocess, "Popen", _unexpected_popen)

    with pytest.raises(LinkCryptoRunnerError, match="paired UDP obfs preflight failed"):
        runner_mod.apply_link_crypto_runner_plan(plan)


def test_link_crypto_runner_fails_closed_when_paired_obfs_exits_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract_path = tmp_path / "runtime-contract.json"
    contract = _contract(contract_path)
    contract["linkCrypto"]["udp"]["pairedObfs"]["enabled"] = True
    _write_json(contract_path, contract)
    state_path = tmp_path / "desired-state.json"
    state = _state(state_path, contract=contract, contract_path=contract_path, paired_obfs_enabled=True)
    paired_profile = tmp_path / "paired-obfs.env"
    hysteria_profile = tmp_path / "client.yaml"
    paired_profile.write_text("TRACEGATE_UDP_OBFS_KEY=private-secret-value\n", encoding="utf-8")
    hysteria_profile.write_text("client: true\n", encoding="utf-8")
    state["udpLinks"][0]["pairedObfs"]["profileRef"]["path"] = str(paired_profile)
    state["udpLinks"][0]["profileRef"]["path"] = str(hysteria_profile)
    _write_json(state_path, state)
    plan = build_link_crypto_runner_plan(
        action="start",
        role="ENTRY",
        paths=LinkCryptoRunnerPaths(
            state_json=state_path,
            runtime_dir=tmp_path / "runtime",
            plan_file=tmp_path / "runner-plan.json",
        ),
        paired_obfs_runner="/opt/link-crypto-private/udp-obfs-runner",
        include_mieru=False,
    )
    spawned: list[list[str]] = []

    def _fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="OK\n")

    class _ExitedProcess:
        pid = 4242

        def poll(self) -> int:
            return 2

    def _fake_popen(command: list[str], **_: object) -> _ExitedProcess:
        spawned.append(command)
        return _ExitedProcess()

    monkeypatch.setattr(runner_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(runner_mod.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(runner_mod.time, "sleep", lambda _: None)

    with pytest.raises(LinkCryptoRunnerError, match="paired UDP obfs exited immediately"):
        runner_mod.apply_link_crypto_runner_plan(plan)

    assert spawned == [["/opt/link-crypto-private/udp-obfs-runner", "start", str(paired_profile)]]
    paired = next(row for row in plan["processes"] if row["kind"] == "paired-udp-obfs")
    assert not Path(paired["pidFile"]).exists()


def test_link_crypto_runner_rolls_back_started_udp_processes_on_later_start_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract_path = tmp_path / "runtime-contract.json"
    contract = _contract(contract_path)
    contract["linkCrypto"]["udp"]["pairedObfs"]["enabled"] = True
    _write_json(contract_path, contract)
    state_path = tmp_path / "desired-state.json"
    state = _state(state_path, contract=contract, contract_path=contract_path, paired_obfs_enabled=True)
    paired_profile = tmp_path / "paired-obfs.env"
    hysteria_profile = tmp_path / "client.yaml"
    paired_profile.write_text("TRACEGATE_UDP_OBFS_KEY=private-secret-value\n", encoding="utf-8")
    hysteria_profile.write_text("client: true\n", encoding="utf-8")
    state["udpLinks"][0]["pairedObfs"]["profileRef"]["path"] = str(paired_profile)
    state["udpLinks"][0]["profileRef"]["path"] = str(hysteria_profile)
    _write_json(state_path, state)
    plan = build_link_crypto_runner_plan(
        action="start",
        role="ENTRY",
        paths=LinkCryptoRunnerPaths(
            state_json=state_path,
            runtime_dir=tmp_path / "runtime",
            plan_file=tmp_path / "runner-plan.json",
        ),
        paired_obfs_runner="/opt/link-crypto-private/udp-obfs-runner",
        include_mieru=False,
    )
    spawned: list[list[str]] = []
    stopped: list[str] = []

    def _fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="OK\n")

    class _RunningProcess:
        pid = 4243

        def poll(self) -> None:
            return None

    def _fake_popen(command: list[str], **_: object) -> _RunningProcess:
        spawned.append(command)
        if command[1] == "client":
            raise OSError("hysteria missing")
        return _RunningProcess()

    def _record_stop(process: dict) -> str:
        stopped.append(str(process.get("kind") or ""))
        return "stopped"

    monkeypatch.setattr(runner_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(runner_mod.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(runner_mod.time, "sleep", lambda _: None)
    monkeypatch.setattr(runner_mod, "_stop_process", _record_stop)

    with pytest.raises(LinkCryptoRunnerError, match="failed to start link-crypto process hysteria2"):
        runner_mod.apply_link_crypto_runner_plan(plan)

    assert spawned == [
        ["/opt/link-crypto-private/udp-obfs-runner", "start", str(paired_profile)],
        ["hysteria", "client", "-c", str(hysteria_profile)],
    ]
    assert stopped == ["paired-udp-obfs"]


def test_link_crypto_runner_rejects_unsafe_udp_state(tmp_path: Path) -> None:
    contract_path = tmp_path / "runtime-contract.json"
    contract = _contract(contract_path)
    state_path = tmp_path / "desired-state.json"
    state = _state(state_path, contract=contract, contract_path=contract_path)
    state["udpLinks"][0]["stability"]["failOpen"] = True
    _write_json(state_path, state)

    with pytest.raises(LinkCryptoRunnerError, match="fail closed"):
        build_link_crypto_runner_plan(
            action="plan",
            role="ENTRY",
            paths=LinkCryptoRunnerPaths(
                state_json=state_path,
                runtime_dir=tmp_path / "runtime",
                plan_file=tmp_path / "runner-plan.json",
            ),
        )


def test_link_crypto_runner_cli_writes_plan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    contract_path = tmp_path / "runtime-contract.json"
    contract = _contract(contract_path)
    state_path = tmp_path / "desired-state.json"
    _state(state_path, contract=contract, contract_path=contract_path)
    plan_path = tmp_path / "runner-plan.json"

    main(
        [
            "plan",
            "--role",
            "ENTRY",
            "--state-json",
            str(state_path),
            "--runtime-dir",
            str(tmp_path / "runtime"),
            "--plan-file",
            str(plan_path),
            "--json",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert output["action"] == "plan"
    assert output["planFile"] == str(plan_path)
    assert plan["counts"]["hysteria2"] == 1
