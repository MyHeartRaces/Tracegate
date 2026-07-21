from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from typing import Iterable

from cryptography import x509
import yaml

from tracegate.agent.xray_api import query_outbound_observations
from tracegate.settings import Settings


_FQDN_RE = re.compile(
    r"(?=^.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
_RANGE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")
_TRANSACTION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_SSH_TARGET_RE = re.compile(
    r"^(?:[A-Za-z0-9._-]+@)?(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])$"
)
_CHANNELS = {1: "shadowtls-primary-a", 2: "shadowtls-primary-b"}
_OUTBOUND_TAGS = {"shadowtls-primary-a": "to-transit-ss", "shadowtls-primary-b": "to-transit-ss2", "reality-fallback": "to-transit"}


@dataclass(frozen=True)
class CandidateProbe:
    fqdn: str
    addresses: list[str]
    neighbor_prefix_bits: int
    tls_version: str
    http_status: int
    latency_ms: int


def _fqdn(value: str) -> str:
    normalized = str(value or "").strip().rstrip(".").lower()
    if not _FQDN_RE.fullmatch(normalized):
        raise ValueError(f"invalid FQDN: {value!r}")
    return normalized


def _ssh_target(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or normalized.startswith("-") or not _SSH_TARGET_RE.fullmatch(normalized):
        raise ValueError(f"invalid SSH target: {value!r}")
    return normalized


def _bounded_range(value: str | None, *, label: str, minimum: int, maximum: int) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    match = _RANGE_RE.fullmatch(normalized)
    if match is None:
        raise ValueError(f"{label} must be an integer or integer range")
    lower = int(match.group(1))
    upper = int(match.group(2) or lower)
    if not minimum <= lower <= upper <= maximum:
        raise ValueError(f"{label} must stay within {minimum}-{maximum}")
    return normalized


def _common_prefix_bits(left: ipaddress.IPv4Address, right: ipaddress.IPv4Address) -> int:
    return 32 - (int(left) ^ int(right)).bit_length()


def _resolve_ipv4(fqdn: str) -> list[ipaddress.IPv4Address]:
    rows = socket.getaddrinfo(fqdn, 443, type=socket.SOCK_STREAM)
    return sorted(
        {
            ipaddress.IPv4Address(row[4][0])
            for row in rows
            if row[0] == socket.AF_INET
        },
        key=int,
    )


def _probe_candidate(fqdn: str, entry_ip: ipaddress.IPv4Address, *, timeout: float) -> CandidateProbe:
    normalized = _fqdn(fqdn)
    addresses = _resolve_ipv4(normalized)
    if not addresses:
        raise RuntimeError("no IPv4 addresses")
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    failures: list[str] = []
    for address in addresses:
        started = time.monotonic()
        try:
            with socket.create_connection((str(address), 443), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=normalized) as tls:
                    tls.settimeout(timeout)
                    request = (
                        f"HEAD / HTTP/1.1\r\nHost: {normalized}\r\n"
                        "User-Agent: Tracegate-Front-Probe/1\r\nConnection: close\r\n\r\n"
                    )
                    tls.sendall(request.encode("ascii"))
                    first_line = tls.recv(512).split(b"\r\n", 1)[0].decode("ascii", "replace")
                    match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})\b", first_line)
                    if match is None:
                        raise RuntimeError("no HTTP response")
                    status = int(match.group(1))
                    if not 100 <= status < 500:
                        raise RuntimeError(f"HTTP status {status}")
                    latency_ms = max(1, round((time.monotonic() - started) * 1000))
                    return CandidateProbe(
                        fqdn=normalized,
                        addresses=[str(item) for item in addresses],
                        neighbor_prefix_bits=max(
                            _common_prefix_bits(entry_ip, item) for item in addresses
                        ),
                        tls_version=str(tls.version() or "TLSv1.3"),
                        http_status=status,
                        latency_ms=latency_ms,
                    )
        except Exception as exc:
            failures.append(f"{address}: {type(exc).__name__}")
    raise RuntimeError("; ".join(failures) or "probe failed")


def _certificate_names_for_ip(address: ipaddress.IPv4Address, *, timeout: float) -> set[str]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((str(address), 443), timeout=timeout) as raw:
        with context.wrap_socket(raw) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        return set()
    certificate = x509.load_der_x509_certificate(der)
    try:
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    result: set[str] = set()
    for name in names:
        if str(name).startswith("*."):
            continue
        try:
            result.add(_fqdn(str(name)))
        except ValueError:
            continue
    return result


def _neighbor_network(entry_ip: ipaddress.IPv4Address, raw: str | None) -> ipaddress.IPv4Network:
    network = ipaddress.IPv4Network(raw, strict=False) if raw else ipaddress.IPv4Network(f"{entry_ip}/24", strict=False)
    if network.num_addresses > 256:
        raise ValueError("neighbor scan is limited to at most 256 IPv4 addresses")
    if entry_ip not in network:
        raise ValueError("neighbor CIDR must contain the Entry IP")
    return network


def _scan_neighbor_names(
    entry_ip: ipaddress.IPv4Address,
    *,
    network: ipaddress.IPv4Network,
    timeout: float,
    workers: int,
) -> set[str]:
    addresses = [item for item in network.hosts() if item != entry_ip]
    result: set[str] = set()
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 32))) as executor:
        futures = {
            executor.submit(_certificate_names_for_ip, address, timeout=timeout): address
            for address in addresses
        }
        for future in as_completed(futures):
            try:
                result.update(future.result())
            except Exception:
                continue
    return result


def _catalog_candidates(path: Path) -> set[str]:
    if not path.exists():
        raise FileNotFoundError(path)
    if path.suffix.lower() in {".yaml", ".yml"}:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        rows = payload if isinstance(payload, list) else []
        values = [row.get("fqdn") for row in rows if isinstance(row, dict) and row.get("enabled", True)]
    else:
        values = [line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines()]
    result: set[str] = set()
    for value in values:
        if not value:
            continue
        result.add(_fqdn(str(value)))
    return result


def _discover(args: argparse.Namespace) -> int:
    entry_ip = ipaddress.IPv4Address(args.entry_ip)
    candidates = {_fqdn(value) for value in args.candidate}
    for raw_path in args.candidate_file:
        candidates.update(_catalog_candidates(Path(raw_path)))
    scanned_network = ""
    if args.scan_neighbors:
        network = _neighbor_network(entry_ip, args.neighbor_cidr)
        scanned_network = str(network)
        candidates.update(
            _scan_neighbor_names(
                entry_ip,
                network=network,
                timeout=args.timeout,
                workers=args.workers,
            )
        )

    probes: list[CandidateProbe] = []
    failures = 0
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 32))) as executor:
        futures = {
            executor.submit(_probe_candidate, value, entry_ip, timeout=args.timeout): value
            for value in sorted(candidates)
        }
        for future in as_completed(futures):
            try:
                probes.append(future.result())
            except Exception:
                failures += 1
    probes.sort(key=lambda row: (-row.neighbor_prefix_bits, row.latency_ms, row.fqdn))
    payload = {
        "schema": "tracegate.backhaul-front-candidates.v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "entryIp": str(entry_ip),
        "scannedNeighborCidr": scanned_network,
        "candidateCount": len(candidates),
        "failedCount": failures,
        "candidates": [asdict(row) for row in probes],
    }
    rendered = json.dumps(payload, ensure_ascii=True, indent=2) + "\n"
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if probes else 3


def _transaction(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        raw = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if not _TRANSACTION_RE.fullmatch(raw):
        raise ValueError("invalid transaction id")
    return raw


def _env_path(role: str, override: str | None) -> Path:
    if override:
        return Path(override)
    return Path("/etc/tracegate/tracegate-entry.env" if role == "entry" else "/etc/tracegate/tracegate.env")


def _backup_path(transaction: str, role: str) -> Path:
    return Path("/var/lib/tracegate/deploy-state/backhaul-front-rotation") / transaction / f"{role}.env"


def _update_env(path: Path, updates: dict[str, str]) -> None:
    original = path.read_text(encoding="utf-8").splitlines()
    pending = dict(updates)
    rendered: list[str] = []
    for line in original:
        match = re.match(r"^([A-Z][A-Z0-9_]*)=", line)
        if match is None or match.group(1) not in updates:
            rendered.append(line)
            continue
        key = match.group(1)
        if key in pending:
            rendered.append(f"{key}={pending.pop(key)}")
    if rendered and rendered[-1] != "":
        rendered.append("")
    rendered.extend(f"{key}={pending[key]}" for key in sorted(pending))
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text("\n".join(rendered).rstrip() + "\n", encoding="utf-8")
    os.chmod(temporary, path.stat().st_mode & 0o777)
    os.replace(temporary, path)


def _run_checked(command: Iterable[str]) -> None:
    subprocess.run(list(command), check=True)


def _activate_local(role: str, leg: int) -> None:
    runtime = Path("/opt/tracegate/current/deploy/systemd")
    if role == "entry":
        renderer = runtime / ("tracegate-shadowtls-entry-env" if leg == 1 else "tracegate-shadowtls-entry2-env")
        _run_checked([str(renderer)])
        _run_checked(["systemctl", "restart", f"tracegate-backhaul-fragment@{leg}.service"])
        unit = "tracegate-shadowtls-entry.service" if leg == 1 else "tracegate-shadowtls-entry2.service"
    else:
        renderer = runtime / ("tracegate-shadowtls-backhaul-env" if leg == 1 else "tracegate-shadowtls-backhaul2-env")
        _run_checked([str(renderer)])
        unit = "tracegate-shadowtls-backhaul.service" if leg == 1 else "tracegate-shadowtls-backhaul2.service"
    _run_checked(["systemctl", "restart", unit])
    _run_checked(["systemctl", "is-active", "--quiet", unit])


def _local_apply(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError("local-apply must run as root")
    role = str(args.role)
    leg = int(args.leg)
    sni = _fqdn(args.sni)
    transaction = _transaction(args.transaction)
    path = _env_path(role, args.env_file)
    backup = _backup_path(transaction, role)
    backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup.parent.chmod(0o700)
    if backup.exists():
        raise FileExistsError(f"transaction backup already exists: {backup}")
    shutil.copy2(path, backup)
    os.chmod(backup, 0o600)
    base = "SHADOWTLS_BACKHAUL" if leg == 1 else "SHADOWTLS_BACKHAUL2"
    updates = {f"{base}_SNI": sni}
    if role == "endpoint":
        updates[f"{base}_TLS_TARGET"] = f"{sni}:443"
    else:
        slicing = {
            f"SHADOWTLS_BACKHAUL_FRAGMENT{leg}_PACKETS": _bounded_range(args.packets, label="packets", minimum=1, maximum=3),
            f"SHADOWTLS_BACKHAUL_FRAGMENT{leg}_LENGTH": _bounded_range(args.length, label="length", minimum=1, maximum=512),
            f"SHADOWTLS_BACKHAUL_FRAGMENT{leg}_INTERVAL_MS": _bounded_range(args.interval_ms, label="interval-ms", minimum=0, maximum=100),
        }
        updates.update({key: value for key, value in slicing.items() if value is not None})
    try:
        _update_env(path, updates)
        _activate_local(role, leg)
    except Exception:
        shutil.copy2(backup, path)
        os.chmod(path, 0o600)
        _activate_local(role, leg)
        raise
    print(json.dumps({"ok": True, "transaction": transaction, "role": role, "leg": leg, "sni": sni}))
    return 0


def _local_rollback(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError("local-rollback must run as root")
    role = str(args.role)
    leg = int(args.leg)
    transaction = _transaction(args.transaction)
    backup = _backup_path(transaction, role)
    if not backup.exists():
        raise FileNotFoundError(backup)
    path = _env_path(role, args.env_file)
    shutil.copy2(backup, path)
    os.chmod(path, 0o600)
    _activate_local(role, leg)
    print(json.dumps({"ok": True, "rolledBack": True, "transaction": transaction, "role": role, "leg": leg}))
    return 0


def _probe(args: argparse.Namespace) -> int:
    entry_ip = ipaddress.IPv4Address(args.entry_ip) if args.entry_ip else ipaddress.IPv4Address("127.0.0.1")
    probe = _probe_candidate(args.sni, entry_ip, timeout=args.timeout)
    print(json.dumps(asdict(probe), ensure_ascii=True))
    return 0


def _local_status(args: argparse.Namespace) -> int:
    channel = str(args.channel)
    outbound_tag = _OUTBOUND_TAGS[channel]
    deadline = time.monotonic() + max(0, int(args.wait_seconds))
    settings = Settings(agent_xray_api_server="127.0.0.1:8080", agent_xray_api_timeout_seconds=3)
    last: dict[str, int | bool] = {}
    while True:
        observations = query_outbound_observations(settings)
        row = observations.get(outbound_tag)
        last = row if isinstance(row, dict) else {}
        fresh = int(last.get("last_try_time") or 0) >= int(args.after_timestamp or 0)
        if bool(last.get("alive")) and fresh:
            print(json.dumps({"ok": True, "channel": channel, "delayMs": int(last.get("delay_ms") or 0)}))
            return 0
        if time.monotonic() >= deadline:
            print(json.dumps({"ok": False, "channel": channel}), file=sys.stderr)
            return 4
        time.sleep(2)


def _ssh_command(args: argparse.Namespace, target: str, remote: list[str]) -> None:
    command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if args.ssh_key:
        command.extend(["-i", str(args.ssh_key)])
    command.append(_ssh_target(target))
    command.extend(remote)
    _run_checked(command)


def _remote_cli() -> str:
    return "/opt/tracegate/current/venv/bin/tracegate-backhaul-fronts"


def _rotate(args: argparse.Namespace) -> int:
    sni = _fqdn(args.sni)
    leg = int(args.leg)
    transaction = _transaction(args.transaction)
    started_at = int(time.time())
    common_probe = [_remote_cli(), "probe", "--sni", sni, "--timeout", str(args.timeout)]
    _ssh_command(args, args.endpoint_ssh, common_probe)
    _ssh_command(args, args.entry_ssh, common_probe)

    applied: list[tuple[str, str]] = []
    try:
        endpoint_apply = [
            _remote_cli(), "local-apply", "--role", "endpoint", "--leg", str(leg),
            "--sni", sni, "--transaction", transaction,
        ]
        _ssh_command(args, args.endpoint_ssh, endpoint_apply)
        applied.append((args.endpoint_ssh, "endpoint"))

        entry_apply = [
            _remote_cli(), "local-apply", "--role", "entry", "--leg", str(leg),
            "--sni", sni, "--transaction", transaction,
        ]
        for flag, value in (("--packets", args.packets), ("--length", args.length), ("--interval-ms", args.interval_ms)):
            if value is not None:
                entry_apply.extend([flag, str(value)])
        _ssh_command(args, args.entry_ssh, entry_apply)
        applied.append((args.entry_ssh, "entry"))

        _ssh_command(
            args,
            args.entry_ssh,
            [
                _remote_cli(), "local-status", "--channel", _CHANNELS[leg],
                "--wait-seconds", str(args.wait_seconds), "--after-timestamp", str(started_at),
            ],
        )
    except Exception:
        for target, role in reversed(applied):
            try:
                _ssh_command(
                    args,
                    target,
                    [
                        _remote_cli(), "local-rollback", "--role", role, "--leg", str(leg),
                        "--transaction", transaction,
                    ],
                )
            except Exception:
                print(f"rollback failed for {role}; use transaction {transaction}", file=sys.stderr)
        raise
    print(json.dumps({"ok": True, "transaction": transaction, "leg": leg, "sni": sni, "ipRotated": False}))
    return 0


def _add_slicing_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--packets")
    parser.add_argument("--length")
    parser.add_argument("--interval-ms")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Discover and safely rotate Tracegate ShadowTLS backhaul fronts")
    sub = parser.add_subparsers(dest="command", required=True)

    discover = sub.add_parser("discover")
    discover.add_argument("--entry-ip", required=True)
    discover.add_argument("--candidate", action="append", default=[])
    discover.add_argument("--candidate-file", action="append", default=[])
    discover.add_argument("--scan-neighbors", action="store_true")
    discover.add_argument("--neighbor-cidr")
    discover.add_argument("--workers", type=int, default=16)
    discover.add_argument("--timeout", type=float, default=2.0)
    discover.add_argument("--output")
    discover.set_defaults(handler=_discover)

    probe = sub.add_parser("probe")
    probe.add_argument("--sni", required=True)
    probe.add_argument("--entry-ip")
    probe.add_argument("--timeout", type=float, default=4.0)
    probe.set_defaults(handler=_probe)

    local_apply = sub.add_parser("local-apply")
    local_apply.add_argument("--role", choices=("entry", "endpoint"), required=True)
    local_apply.add_argument("--leg", type=int, choices=(1, 2), required=True)
    local_apply.add_argument("--sni", required=True)
    local_apply.add_argument("--transaction")
    local_apply.add_argument("--env-file")
    _add_slicing_arguments(local_apply)
    local_apply.set_defaults(handler=_local_apply)

    rollback = sub.add_parser("local-rollback")
    rollback.add_argument("--role", choices=("entry", "endpoint"), required=True)
    rollback.add_argument("--leg", type=int, choices=(1, 2), required=True)
    rollback.add_argument("--transaction", required=True)
    rollback.add_argument("--env-file")
    rollback.set_defaults(handler=_local_rollback)

    status = sub.add_parser("local-status")
    status.add_argument("--channel", choices=tuple(_OUTBOUND_TAGS), required=True)
    status.add_argument("--wait-seconds", type=int, default=0)
    status.add_argument("--after-timestamp", type=int, default=0)
    status.set_defaults(handler=_local_status)

    rotate = sub.add_parser("rotate")
    rotate.add_argument("--entry-ssh", required=True)
    rotate.add_argument("--endpoint-ssh", required=True)
    rotate.add_argument("--ssh-key")
    rotate.add_argument("--leg", type=int, choices=(1, 2), required=True)
    rotate.add_argument("--sni", required=True)
    rotate.add_argument("--transaction")
    rotate.add_argument("--timeout", type=float, default=4.0)
    rotate.add_argument("--wait-seconds", type=int, default=40)
    _add_slicing_arguments(rotate)
    rotate.set_defaults(handler=_rotate)
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    try:
        raise SystemExit(int(args.handler(args)))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"tracegate backhaul fronts: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
