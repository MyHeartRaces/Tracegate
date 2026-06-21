from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
from typing import Any

from tracegate.services.runtime_preflight import (
    LinkCryptoState,
    RuntimePreflightFinding,
    load_link_crypto_state,
    validate_link_crypto_state,
)


class LinkCryptoRunnerError(RuntimeError):
    pass


_RUNNER_PLAN_SCHEMA = "tracegate.link-crypto-runner-plan.v1"
_PID_STALE_GRACE_SECONDS = 2.0
_PAIRED_OBFS_VALIDATE_TIMEOUT_SECONDS = 10.0
_PAIRED_OBFS_START_GRACE_SECONDS = 0.25


@dataclass(frozen=True, slots=True)
class LinkCryptoRunnerPaths:
    state_json: Path
    runtime_dir: Path
    plan_file: Path
    runtime_contract: Path | None = None


def _load_contract(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LinkCryptoRunnerError(f"runtime contract is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise LinkCryptoRunnerError(f"runtime contract is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise LinkCryptoRunnerError(f"runtime contract must be a JSON object: {path}")
    return payload


def _error_findings(findings: list[RuntimePreflightFinding]) -> list[RuntimePreflightFinding]:
    return [finding for finding in findings if finding.severity == "error"]


def _raise_for_errors(findings: list[RuntimePreflightFinding]) -> None:
    errors = _error_findings(findings)
    if not errors:
        return
    details = "; ".join(f"{finding.code}: {finding.message}" for finding in errors[:5])
    if len(errors) > 5:
        details += f"; ... {len(errors) - 5} more"
    raise LinkCryptoRunnerError(f"link-crypto runner validation failed: {details}")


def _row_dict(row: dict[str, Any], key: str) -> dict[str, Any]:
    value = row.get(key)
    return value if isinstance(value, dict) else {}


def _row_string(row: dict[str, Any], key: str) -> str:
    return str(row.get(key) or "").strip()


def _enabled(row: dict[str, Any]) -> bool:
    return bool(row.get("enabled", True))


def _slug(value: object) -> str:
    raw = str(value or "").strip()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")
    return slug or "profile"


def _profile_path(row: dict[str, Any], *, label: str) -> str:
    profile_ref = _row_dict(row, "profileRef")
    if _row_string(profile_ref, "kind") != "file":
        raise LinkCryptoRunnerError(f"{label} profileRef must be file")
    profile_path = _row_string(profile_ref, "path")
    if not profile_path:
        raise LinkCryptoRunnerError(f"{label} profileRef path is missing")
    if not bool(profile_ref.get("secretMaterial", False)):
        raise LinkCryptoRunnerError(f"{label} profileRef must point at secret material")
    return profile_path


def _secret_profile_ref(row: dict[str, Any], *, label: str) -> str:
    if _row_string(row, "kind") != "file":
        raise LinkCryptoRunnerError(f"{label} profileRef must be file")
    profile_path = _row_string(row, "path")
    if not profile_path:
        raise LinkCryptoRunnerError(f"{label} profileRef path is missing")
    if not bool(row.get("secretMaterial", False)):
        raise LinkCryptoRunnerError(f"{label} profileRef must point at secret material")
    return profile_path


def _pid_file(runtime_dir: Path, *, kind: str, link_class: str, side: str, profile_path: str) -> str:
    slug = _slug(f"{kind}-{link_class}-{side}-{profile_path}")
    return str(runtime_dir / f"{slug}.pid")


def _log_file(runtime_dir: Path, *, kind: str, link_class: str, side: str) -> str:
    slug = _slug(f"{kind}-{link_class}-{side}")
    return str(runtime_dir / f"{slug}.log")


def _process_running(pid_file: str | Path) -> bool:
    try:
        raw_pid = Path(pid_file).read_text(encoding="utf-8").strip()
        pid = int(raw_pid)
    except (FileNotFoundError, TypeError, ValueError):
        return False
    if pid < 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _binary_command(binary: str, fallback: str) -> str:
    return str(binary or "").strip() or fallback


def _process_spec(
    *,
    kind: str,
    link_class: str,
    side: str,
    profile_path: str,
    runtime_dir: Path,
    command: list[str],
    local: dict[str, Any],
    remote: dict[str, Any],
    hardening: dict[str, Any] | None = None,
    dpi_resistance: dict[str, Any] | None = None,
    startable: bool = True,
    preflight_command: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "class": link_class,
        "side": side,
        "profileRef": {
            "kind": "file",
            "path": profile_path,
            "secretMaterial": True,
        },
        "local": {
            "listen": _row_string(local, "listen"),
            "protocol": _row_string(local, "protocol") or ("udp" if kind == "hysteria2" else ""),
        },
        "remote": {
            "role": _row_string(remote, "role"),
            "endpoint": _row_string(remote, "endpoint"),
            "protocol": _row_string(remote, "protocol"),
        },
        "pidFile": _pid_file(runtime_dir, kind=kind, link_class=link_class, side=side, profile_path=profile_path),
        "logFile": _log_file(runtime_dir, kind=kind, link_class=link_class, side=side),
        "command": command,
        "preflightCommand": preflight_command or [],
        "startable": startable,
        "hardening": hardening or {},
        "dpiResistance": dpi_resistance or {},
    }


def _validate_state(
    *,
    state: LinkCryptoState,
    expected_role: str,
    runtime_contract_path: Path | None,
) -> dict[str, Any]:
    contract_path = runtime_contract_path or Path(state.runtime_contract_path)
    contract = _load_contract(contract_path)
    findings = validate_link_crypto_state(
        state=state,
        contract=contract,
        expected_role=expected_role,
        contract_path=contract_path,
    )
    _raise_for_errors(findings)
    return contract


def build_link_crypto_runner_plan(
    *,
    action: str,
    role: str,
    paths: LinkCryptoRunnerPaths,
    mieru_bin: str = "mieru",
    hysteria_bin: str = "hysteria",
    paired_obfs_runner: str = "",
    include_mieru: bool = True,
    include_udp: bool = True,
) -> dict[str, Any]:
    action_normalized = str(action or "").strip().lower()
    if action_normalized == "reload":
        action_normalized = "start"
    if action_normalized not in {"plan", "validate", "start", "stop"}:
        raise LinkCryptoRunnerError(f"unsupported link-crypto runner action: {action}")

    role_upper = str(role or "").strip().upper()
    if role_upper not in {"ENTRY", "TRANSIT"}:
        raise LinkCryptoRunnerError(f"role must be ENTRY or TRANSIT, got: {role}")

    state = load_link_crypto_state(paths.state_json)
    _validate_state(state=state, expected_role=role_upper, runtime_contract_path=paths.runtime_contract)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    processes: list[dict[str, Any]] = []

    for row in (state.links if include_mieru else ()):
        if not _enabled(row):
            continue
        link_class = _row_string(row, "class")
        side = _row_string(row, "side")
        profile_path = _profile_path(row, label=f"{link_class} Mieru")
        processes.append(
            _process_spec(
                kind="mieru",
                link_class=link_class,
                side=side,
                profile_path=profile_path,
                runtime_dir=paths.runtime_dir,
                command=[_binary_command(mieru_bin, "mieru"), "run", "-c", profile_path],
                local=_row_dict(row, "local"),
                remote=_row_dict(row, "remote"),
                hardening=_row_dict(row, "zapret2"),
                dpi_resistance=_row_dict(row, "dpiResistance"),
            )
        )

    for row in (state.udp_links if include_udp else ()):
        if not _enabled(row):
            continue
        link_class = _row_string(row, "class")
        side = _row_string(row, "side")
        local = _row_dict(row, "local")
        remote = _row_dict(row, "remote")
        profile_path = _profile_path(row, label=f"{link_class} Hysteria2")
        paired_obfs = _row_dict(row, "pairedObfs")
        if bool(paired_obfs.get("enabled", False)):
            paired_profile = _secret_profile_ref(_row_dict(paired_obfs, "profileRef"), label=f"{link_class} pairedObfs")
            paired_command = (
                [_binary_command(paired_obfs_runner, ""), action_normalized, paired_profile]
                if str(paired_obfs_runner or "").strip()
                else []
            )
            paired_preflight_command = (
                [_binary_command(paired_obfs_runner, ""), "validate", paired_profile]
                if str(paired_obfs_runner or "").strip()
                else []
            )
            processes.append(
                _process_spec(
                    kind="paired-udp-obfs",
                    link_class=link_class,
                    side=side,
                    profile_path=paired_profile,
                    runtime_dir=paths.runtime_dir,
                    command=paired_command,
                    preflight_command=paired_preflight_command,
                    local=local,
                    remote=remote,
                    hardening=_row_dict(row, "hardening"),
                    dpi_resistance=_row_dict(row, "dpiResistance"),
                    startable=bool(paired_command),
                )
            )
        hysteria_mode = "client" if side == "client" else "server"
        processes.append(
            _process_spec(
                kind="hysteria2",
                link_class=link_class,
                side=side,
                profile_path=profile_path,
                runtime_dir=paths.runtime_dir,
                command=[_binary_command(hysteria_bin, "hysteria"), hysteria_mode, "-c", profile_path],
                local=local,
                remote=remote,
                hardening=_row_dict(row, "hardening"),
                dpi_resistance=_row_dict(row, "dpiResistance"),
            )
        )

    return {
        "schema": _RUNNER_PLAN_SCHEMA,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "action": action_normalized,
        "role": role_upper,
        "desiredState": str(paths.state_json),
        "runtimeContract": str(paths.runtime_contract or state.runtime_contract_path),
        "runtimeDir": str(paths.runtime_dir),
        "counts": {
            "mieru": len([row for row in processes if row["kind"] == "mieru"]),
            "hysteria2": len([row for row in processes if row["kind"] == "hysteria2"]),
            "pairedUdpObfs": len([row for row in processes if row["kind"] == "paired-udp-obfs"]),
        },
        "scope": {
            "mieru": include_mieru,
            "udp": include_udp,
        },
        "security": {
            "secretMaterialInline": False,
            "restartExisting": False,
            "udpFailClosed": all(not bool(_row_dict(row, "stability").get("failOpen", True)) for row in state.udp_links),
            "udpSalamanderRequired": all(bool(_row_dict(row, "obfs").get("required", False)) for row in state.udp_links),
            "udpDpiResistanceRequired": all(bool(_row_dict(row, "dpiResistance").get("enabled", False)) for row in state.udp_links),
            "tcpDpiResistanceRequired": all(bool(_row_dict(row, "dpiResistance").get("enabled", False)) for row in state.links),
            "tcpZapret2Required": all(bool(_row_dict(row, "zapret2").get("required", False)) and bool(_row_dict(row, "zapret2").get("enabled", False)) for row in state.links),
            "tcpPromotionPreflightRequired": all(bool(_row_dict(_row_dict(row, "dpiResistance"), "promotionPreflight").get("required", False)) for row in state.links),
        },
        "processes": processes,
    }


def write_link_crypto_runner_plan(plan: dict[str, Any], path: Path) -> None:
    if plan.get("schema") != _RUNNER_PLAN_SCHEMA:
        raise LinkCryptoRunnerError("refusing to write unsupported link-crypto runner plan")
    _write_json_atomic(path, plan)


def _ensure_profile_file(profile_path: str) -> None:
    if not Path(profile_path).is_file():
        raise LinkCryptoRunnerError(f"link-crypto profile is missing: {profile_path}")


def _command_text(command: list[Any]) -> list[str]:
    return [str(item) for item in command]


def _validate_paired_obfs_process(process: dict[str, Any]) -> None:
    if _row_string(process, "kind") != "paired-udp-obfs":
        return
    preflight_command = process.get("preflightCommand") if isinstance(process.get("preflightCommand"), list) else []
    if not preflight_command or not str(preflight_command[0] or "").strip():
        raise LinkCryptoRunnerError(
            f"link-crypto process {process.get('kind')}:{process.get('class')} has no preflight command"
        )
    try:
        completed = subprocess.run(
            _command_text(preflight_command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=_PAIRED_OBFS_VALIDATE_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise LinkCryptoRunnerError(f"paired UDP obfs runner is not installed: {preflight_command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise LinkCryptoRunnerError("paired UDP obfs preflight timed out") from exc
    if completed.returncode == 0:
        return
    output = str(completed.stdout or "").strip()
    if len(output) > 1000:
        output = output[:1000] + "..."
    detail = f": {output}" if output else ""
    raise LinkCryptoRunnerError(f"paired UDP obfs preflight failed{detail}")


def _ensure_paired_obfs_stayed_running(process: dict[str, Any], child: subprocess.Popen[Any], pid_file: Path) -> None:
    if _row_string(process, "kind") != "paired-udp-obfs":
        return
    time.sleep(_PAIRED_OBFS_START_GRACE_SECONDS)
    return_code = child.poll()
    if return_code is None:
        return
    pid_file.unlink(missing_ok=True)
    raise LinkCryptoRunnerError(
        f"paired UDP obfs exited immediately with code {return_code}; check logFile={_row_string(process, 'logFile')}"
    )


def _start_process(process: dict[str, Any]) -> str:
    pid_file = Path(_row_string(process, "pidFile"))
    if _process_running(pid_file):
        return "already-running"
    if not bool(process.get("startable", True)):
        raise LinkCryptoRunnerError(
            f"link-crypto process {process.get('kind')}:{process.get('class')} requires a private runner"
        )
    command = process.get("command") if isinstance(process.get("command"), list) else []
    if not command or not str(command[0] or "").strip():
        raise LinkCryptoRunnerError(f"link-crypto process {process.get('kind')}:{process.get('class')} has no command")
    _ensure_profile_file(_row_string(_row_dict(process, "profileRef"), "path"))
    _validate_paired_obfs_process(process)
    log_file = Path(_row_string(process, "logFile"))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("ab") as log_handle:
        try:
            child = subprocess.Popen(
                _command_text(command),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as exc:
            raise LinkCryptoRunnerError(f"failed to start link-crypto process {process.get('kind')}:{process.get('class')}: {exc}") from exc
    pid_file.write_text(f"{child.pid}\n", encoding="utf-8")
    _ensure_paired_obfs_stayed_running(process, child, pid_file)
    return "started"


def _stop_process(process: dict[str, Any]) -> str:
    pid_file = Path(_row_string(process, "pidFile"))
    try:
        raw_pid = pid_file.read_text(encoding="utf-8").strip()
        pid = int(raw_pid)
    except (FileNotFoundError, TypeError, ValueError):
        return "not-running"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        return "not-running"
    except PermissionError as exc:
        raise LinkCryptoRunnerError(f"cannot stop link-crypto process pid={pid}: permission denied") from exc

    deadline = time.monotonic() + _PID_STALE_GRACE_SECONDS
    while time.monotonic() < deadline:
        if not _process_running(pid_file):
            pid_file.unlink(missing_ok=True)
            return "stopped"
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    pid_file.unlink(missing_ok=True)
    return "stopped"


def apply_link_crypto_runner_plan(plan: dict[str, Any]) -> dict[str, Any]:
    if plan.get("schema") != _RUNNER_PLAN_SCHEMA:
        raise LinkCryptoRunnerError("unsupported link-crypto runner plan")
    action = _row_string(plan, "action")
    if action == "validate" or action == "plan":
        return {"action": action, "results": []}
    if action not in {"start", "stop"}:
        raise LinkCryptoRunnerError(f"unsupported link-crypto runner plan action: {action}")
    results: list[dict[str, str]] = []
    processes = plan.get("processes") if isinstance(plan.get("processes"), list) else []
    ordered_processes = reversed(processes) if action == "stop" else processes
    started_processes: list[dict[str, Any]] = []
    for process in ordered_processes:
        if not isinstance(process, dict):
            continue
        try:
            status = _start_process(process) if action == "start" else _stop_process(process)
        except LinkCryptoRunnerError:
            if action == "start":
                for started in reversed(started_processes):
                    _stop_process(started)
            raise
        if action == "start" and status == "started":
            started_processes.append(process)
        results.append(
            {
                "kind": _row_string(process, "kind"),
                "class": _row_string(process, "class"),
                "side": _row_string(process, "side"),
                "status": status,
            }
        )
    return {"action": action, "results": results}
