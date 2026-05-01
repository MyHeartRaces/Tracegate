from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx

from tracegate.services.bundle_files import decode_bundle_file_content
from tracegate.services.runtime_contract import resolve_runtime_contract


def _safe_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if root.resolve() not in path.parents and path != root.resolve():
        raise ValueError(f"unsafe path outside root: {relative}")
    return path


def atomic_write(root: Path, relative: str, content: Any) -> None:
    path = _safe_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(decode_bundle_file_content(content))
    tmp.replace(path)


def apply_files(root: Path, files: dict[str, Any]) -> None:
    for relative, content in files.items():
        atomic_write(root, relative, content)


def run_command(cmd: str, dry_run: bool, *, timeout_seconds: int = 30) -> tuple[bool, str]:
    if dry_run:
        return True, f"dry-run: {cmd}"
    if "\n" in cmd or "\r" in cmd:
        return False, "multiline commands are not allowed"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout_seconds}s"
    output = (proc.stdout + "\n" + proc.stderr).strip()
    return proc.returncode == 0, output


def _proc_net_tables(protocol: str) -> tuple[str, ...]:
    normalized = str(protocol or "").strip().lower()
    if normalized == "tcp":
        return ("tcp", "tcp6")
    if normalized == "udp":
        return ("udp", "udp6")
    return ()


def _proc_net_has_listener(protocol: str, port: int, *, proc_net_root: Path = Path("/proc/net")) -> tuple[bool, str]:
    tables = _proc_net_tables(protocol)
    if not tables:
        return False, f"unsupported protocol: {protocol}"

    try:
        expected_port = f"{int(port):04X}"
    except (TypeError, ValueError):
        return False, f"invalid port: {port}"

    inspected: list[str] = []
    for table in tables:
        path = proc_net_root / table
        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        except OSError as exc:
            inspected.append(f"{table}: {exc}")
            continue
        inspected.append(table)
        for line in content.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or ":" not in parts[1]:
                continue
            local_port = parts[1].rsplit(":", 1)[-1].upper()
            state = parts[3].upper()
            if local_port != expected_port:
                continue
            if protocol == "tcp" and state != "0A":
                continue
            return True, f"/proc/net/{table} port={port} state={state}"

    details = ", ".join(inspected) if inspected else "no proc net tables"
    return False, f"{protocol}/{port} is not listening ({details})"


def _ss_local_port(line: str) -> int | None:
    parts = line.split()
    if len(parts) < 5:
        return None
    local = parts[4]
    if ":" not in local:
        return None
    raw_port = local.rsplit(":", 1)[-1].strip("[]")
    try:
        return int(raw_port)
    except ValueError:
        return None


def check_port(protocol: str, port: int) -> tuple[bool, str]:
    # Be strict: the generic ss -lntup output mixes TCP/UDP, which can cause false positives.
    normalized = str(protocol or "").strip().lower()
    cmd = ["ss", "-ltn"] if normalized == "tcp" else ["ss", "-lun"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return _proc_net_has_listener(normalized, port)
    if proc.returncode != 0:
        ok, details = _proc_net_has_listener(normalized, port)
        if ok:
            return ok, details
        return False, f"cannot run ss: {proc.stderr.strip() or details}"

    try:
        expected_port = int(port)
    except (TypeError, ValueError):
        return False, f"invalid port: {port}"

    for line in proc.stdout.splitlines():
        if _ss_local_port(line) == expected_port:
            return True, line.strip()
    return _proc_net_has_listener(normalized, port)


def check_port_blocked(protocol: str, port: int) -> tuple[bool, str]:
    listening, details = check_port(protocol, port)
    if listening:
        return False, f"forbidden {protocol}/{port} is listening: {details}"
    return True, details


def check_systemd(unit: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
    except FileNotFoundError:
        return False, "systemctl not found"
    result = proc.stdout.strip() or proc.stderr.strip()
    return proc.returncode == 0 and result == "active", result


def _proc_has_process(name: str, *, proc_root: Path = Path("/proc")) -> tuple[bool, str]:
    needle = str(name or "").strip()
    if not needle:
        return False, "process name is empty"
    try:
        entries = list(proc_root.iterdir())
    except OSError as exc:
        return False, f"cannot inspect proc: {exc}"

    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            comm = ""
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except OSError:
            cmdline = ""
        if comm == needle or (cmdline and needle in cmdline):
            details = cmdline or comm or needle
            return True, f"pid={entry.name} {details}"
    return False, f"process '{needle}' not found"


def check_process(name: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(["pgrep", "-fa", name], capture_output=True, text=True)
    except FileNotFoundError:
        return _proc_has_process(name)
    if proc.returncode != 0:
        ok, details = _proc_has_process(name)
        if ok:
            return ok, details
        return False, f"process '{name}' not found"
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return True, lines[0] if lines else f"process '{name}' found"


async def check_hysteria_stats_secret(url: str, secret: str) -> tuple[bool, str]:
    if not secret:
        return False, "stats secret is empty"

    async with httpx.AsyncClient() as client:
        try:
            # Hysteria2 Traffic Stats API expects the raw secret in the Authorization header.
            authorized = await client.get(url, headers={"Authorization": secret}, timeout=5)
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    authorized_ok = authorized.status_code < 400
    return authorized_ok, f"auth={authorized.status_code}"


async def gather_health_checks(
    stats_url: str,
    stats_secret: str,
    role: str,
    runtime_mode: str,  # kept for backward compatibility with legacy container deployments
    runtime_profile: str = "tracegate-2.2",
) -> list[dict]:
    contract = resolve_runtime_contract(runtime_profile)
    checks: list[dict] = []

    for protocol, port, name in contract.expected_ports(role):
        ok, details = check_port(protocol, port)
        checks.append({"name": name, "ok": ok, "details": details})

    for protocol, port, name in contract.forbidden_ports(role):
        ok, details = check_port_blocked(protocol, port)
        checks.append({"name": name, "ok": ok, "details": details})

    for process_check in contract.process_checks(role):
        if process_check.mode == "any":
            attempts = [check_process(name) for name in process_check.process_names]
            ok = any(row[0] for row in attempts)
            details = next((row[1] for row in attempts if row[0]), attempts[0][1] if attempts else "no process checks")
        else:
            attempts = [check_process(name) for name in process_check.process_names]
            ok = all(row[0] for row in attempts)
            details = " | ".join(row[1] for row in attempts if row[1])
        checks.append({"name": process_check.name, "ok": ok, "details": details})

    if contract.requires_transit_stats_secret(role):
        ok, details = await check_hysteria_stats_secret(stats_url, stats_secret)
        checks.append({"name": "hysteria stats API auth", "ok": ok, "details": details})

    return checks


def dump_json(path: Path, payload: dict) -> None:
    atomic_write(path.parent, path.name, json.dumps(payload, ensure_ascii=True, indent=2))
