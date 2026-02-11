from __future__ import annotations

import json
import subprocess
from pathlib import Path

import httpx


def _safe_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if root.resolve() not in path.parents and path != root.resolve():
        raise ValueError(f"unsafe path outside root: {relative}")
    return path


def atomic_write(root: Path, relative: str, content: str) -> None:
    path = _safe_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def apply_files(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        atomic_write(root, relative, content)


def run_command(cmd: str, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, f"dry-run: {cmd}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = (proc.stdout + "\n" + proc.stderr).strip()
    return proc.returncode == 0, output


def check_port(protocol: str, port: int) -> tuple[bool, str]:
    # Be strict: the generic ss -lntup output mixes TCP/UDP, which can cause false positives.
    cmd = "ss -ltn" if protocol == "tcp" else "ss -lun"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, f"cannot run ss: {proc.stderr.strip()}"

    needle = f":{port}"
    for line in proc.stdout.splitlines():
        if needle in line:
            return True, line.strip()
    return False, f"{protocol}/{port} is not listening"


def check_systemd(unit: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
    except FileNotFoundError:
        return False, "systemctl not found"
    result = proc.stdout.strip() or proc.stderr.strip()
    return proc.returncode == 0 and result == "active", result


def check_process(name: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(["pgrep", "-fa", name], capture_output=True, text=True)
    except FileNotFoundError:
        return False, "pgrep not found"
    if proc.returncode != 0:
        return False, f"process '{name}' not found"
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return True, lines[0] if lines else f"process '{name}' found"


async def check_hysteria_stats_secret(url: str, secret: str) -> tuple[bool, str]:
    async with httpx.AsyncClient() as client:
        try:
            unauthorized = await client.get(url, timeout=5)
            # Hysteria2 Traffic Stats API expects the raw secret in the Authorization header.
            # Using a Bearer scheme will be rejected (401/403).
            authorized = await client.get(url, headers={"Authorization": secret}, timeout=5)
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    unauthorized_ok = unauthorized.status_code in {401, 403}
    authorized_ok = authorized.status_code < 400
    return unauthorized_ok and authorized_ok, (
        f"unauth={unauthorized.status_code}, auth={authorized.status_code}"
    )


def check_wg_listen_port(interface: str, expected: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(["wg", "show", interface, "listen-port"], capture_output=True, text=True)
    except FileNotFoundError:
        return False, "wg not found"
    if proc.returncode != 0:
        return False, proc.stderr.strip() or "wg show failed"

    actual = proc.stdout.strip()
    return actual == str(expected), f"expected={expected}, actual={actual}"


async def gather_health_checks(
    stats_url: str,
    stats_secret: str,
    wg_interface: str,
    wg_port: int,
    role: str,
    runtime_mode: str,  # kept for backward compatibility; k3s-only pipeline ignores it
) -> list[dict]:
    checks: list[dict] = []

    expected_ports: list[tuple[str, int, str]] = [("tcp", 443, "listen tcp/443")]
    if role == "VPS_T":
        expected_ports.extend(
            [
                ("udp", 443, "listen udp/443"),
                ("udp", wg_port, f"listen udp/{wg_port}"),
            ]
        )

    for protocol, port, name in expected_ports:
        ok, details = check_port(protocol, port)
        checks.append({"name": name, "ok": ok, "details": details})

    # k3s-only pipeline: the agent runs in a pod with shareProcessNamespace and checks sidecar processes directly.
    if role == "VPS_E":
        # VPS-E can be implemented as an L4 forwarder (haproxy) or as xray.
        ok_x, det_x = check_process("xray")
        ok_h, det_h = check_process("haproxy")
        ok = ok_x or ok_h
        details = det_x if ok_x else det_h
        checks.append({"name": "process entry", "ok": ok, "details": details})
    else:
        for process_name in ["xray", "hysteria"]:
            ok, details = check_process(process_name)
            checks.append({"name": f"process {process_name}", "ok": ok, "details": details})

    if role == "VPS_T":
        ok, details = await check_hysteria_stats_secret(stats_url, stats_secret)
        checks.append({"name": "hysteria stats API auth", "ok": ok, "details": details})

        ok, details = check_wg_listen_port(wg_interface, wg_port)
        checks.append({"name": "wireguard listen-port policy", "ok": ok, "details": details})

    return checks


def dump_json(path: Path, payload: dict) -> None:
    atomic_write(path.parent, path.name, json.dumps(payload, ensure_ascii=True, indent=2))
