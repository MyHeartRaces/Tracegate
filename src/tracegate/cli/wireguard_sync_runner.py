from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WireGuardPeer:
    public_key: str
    allowed_ips: tuple[str, ...]
    preshared_key: str
    persistent_keepalive: int


def _env(name: str, default: str) -> str:
    return str(os.environ.get(name) or default).strip() or default


def _run_wg(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["wg", *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _int_value(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _string_list(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    raw = str(value or "").strip()
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.replace(";", ",").split(",") if item.strip())


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _load_desired_peers(path: Path, *, interface: str) -> dict[str, WireGuardPeer]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("wireguardWSTunnel")
    if not isinstance(rows, list):
        return {}

    peers: dict[str, WireGuardPeer] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        sync = _mapping(row.get("sync"))
        sync_interface = str(sync.get("interface") or interface).strip() or interface
        if sync_interface != interface:
            continue
        wireguard = _mapping(row.get("wireguard"))
        public_key = str(wireguard.get("clientPublicKey") or "").strip()
        allowed_ips = _string_list(wireguard.get("allowedIps"))
        if not public_key or not allowed_ips:
            continue
        peers[public_key] = WireGuardPeer(
            public_key=public_key,
            allowed_ips=allowed_ips,
            preshared_key=str(wireguard.get("presharedKey") or "").strip(),
            persistent_keepalive=max(0, min(60, _int_value(wireguard.get("persistentKeepalive"), 25))),
        )
    return peers


def _current_peers(interface: str) -> set[str]:
    result = _run_wg(["show", interface, "peers"], check=False)
    if result.returncode != 0:
        return set()
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _interface_ready(interface: str) -> bool:
    return _run_wg(["show", interface], check=False).returncode == 0


def _apply_peer(interface: str, peer: WireGuardPeer) -> None:
    cmd = [
        "set",
        interface,
        "peer",
        peer.public_key,
        "allowed-ips",
        ",".join(peer.allowed_ips),
        "persistent-keepalive",
        str(peer.persistent_keepalive),
    ]
    psk_path: str | None = None
    if peer.preshared_key:
        fd, psk_path = tempfile.mkstemp(prefix="tracegate-wg-psk-", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(peer.preshared_key)
                handle.write("\n")
            os.chmod(psk_path, 0o600)
            cmd[4:4] = ["preshared-key", psk_path]
            _run_wg(cmd)
        finally:
            if psk_path:
                try:
                    os.unlink(psk_path)
                except FileNotFoundError:
                    pass
        return
    _run_wg(cmd)


def sync_once(
    *,
    state_path: Path,
    interface: str,
    remove_stale_peers: bool = True,
) -> dict[str, int]:
    if not _interface_ready(interface):
        return {"ready": 0, "desired": 0, "applied": 0, "removed": 0}

    desired = _load_desired_peers(state_path, interface=interface)
    applied = 0
    for peer in desired.values():
        _apply_peer(interface, peer)
        applied += 1

    removed = 0
    if remove_stale_peers:
        for public_key in sorted(_current_peers(interface) - set(desired)):
            _run_wg(["set", interface, "peer", public_key, "remove"])
            removed += 1

    return {"ready": 1, "desired": len(desired), "applied": applied, "removed": removed}


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synchronize Tracegate WireGuard peers with wg set.")
    parser.add_argument("--state", default=_env("WIREGUARD_SYNC_STATE", "/var/lib/tracegate/private/profiles/transit/desired-state.json"))
    parser.add_argument("--interface", default=_env("WIREGUARD_SYNC_INTERFACE", "wg"))
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=float(_env("WIREGUARD_SYNC_INTERVAL_SECONDS", "2")),
    )
    parser.add_argument("--once", action="store_true", default=_env("WIREGUARD_SYNC_ONCE", "false").lower() == "true")
    parser.add_argument(
        "--keep-stale-peers",
        action="store_true",
        default=_env("WIREGUARD_SYNC_KEEP_STALE_PEERS", "false").lower() == "true",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    state_path = Path(args.state)
    interval = max(0.5, float(args.interval_seconds))
    remove_stale = not bool(args.keep_stale_peers)

    while True:
        try:
            summary = sync_once(state_path=state_path, interface=str(args.interface), remove_stale_peers=remove_stale)
            print(
                "tracegate wireguard sync: "
                f"ready={summary['ready']} desired={summary['desired']} "
                f"applied={summary['applied']} removed={summary['removed']}",
                flush=True,
            )
        except Exception as exc:
            print(f"tracegate wireguard sync error: {exc}", file=sys.stderr, flush=True)
            if args.once:
                raise
        if args.once:
            return
        time.sleep(interval)


if __name__ == "__main__":
    main()
