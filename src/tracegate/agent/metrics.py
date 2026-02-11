from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from prometheus_client import REGISTRY
from prometheus_client.core import GaugeMetricFamily

from tracegate.settings import Settings

_REGISTERED = False


def _load_wg_peer_map(root: Path) -> dict[str, dict[str, str]]:
    """
    Map WireGuard peer public keys -> labels (user_id/device_id).

    Source of truth is agent artifacts created from WG_PEER_* events:
      <agent_data_root>/wg-peers/peer-*.json
    """
    out: dict[str, dict[str, str]] = {}
    peers_dir = root / "wg-peers"
    if not peers_dir.exists():
        return out
    for path in peers_dir.glob("peer-*.json"):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        pub = str(row.get("peer_public_key") or "").strip()
        if not pub:
            continue
        out[pub] = {
            "user_id": str(row.get("user_id") or "").strip(),
            "user_display": str(row.get("user_display") or "").strip(),
            "device_id": str(row.get("device_id") or "").strip(),
            "device_name": str(row.get("device_name") or "").strip(),
            "connection_alias": str(row.get("connection_alias") or "").strip(),
        }
    return out


def _wg_dump(interface: str) -> list[list[str]]:
    """
    `wg show <iface> dump` lines split by tabs.

    First line is interface, subsequent lines are peers:
      peer_public_key, preshared_key, endpoint, allowed_ips, latest_handshake,
      transfer_rx, transfer_tx, persistent_keepalive
    """
    proc = subprocess.run(["wg", "show", interface, "dump"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "wg show dump failed")
    rows: list[list[str]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(line.split("\t"))
    return rows


def _read_loadavg() -> tuple[float, float, float] | None:
    try:
        one, five, fifteen = os.getloadavg()
    except Exception:
        return None
    return float(one), float(five), float(fifteen)


def _parse_meminfo(text: str) -> tuple[int, int] | None:
    total_kib: int | None = None
    available_kib: int | None = None
    try:
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2:
                    total_kib = int(parts[1])
            elif line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) >= 2:
                    available_kib = int(parts[1])
            if total_kib is not None and available_kib is not None:
                break
    except Exception:
        return None
    if total_kib is None or available_kib is None:
        return None
    return total_kib * 1024, available_kib * 1024


def _read_meminfo() -> tuple[int, int] | None:
    """
    Read memory totals from `/proc/meminfo`.

    Returns `(mem_total_bytes, mem_available_bytes)`.
    """
    path = Path("/proc/meminfo")
    if not path.exists():
        return None
    try:
        return _parse_meminfo(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _parse_netdev(text: str) -> list[tuple[str, int, int]]:
    rows: list[tuple[str, int, int]] = []
    try:
        for raw in text.splitlines()[2:]:
            left, sep, right = raw.partition(":")
            if not sep:
                continue
            iface = left.strip()
            fields = right.split()
            if len(fields) < 16:
                continue
            rx_bytes = int(fields[0])
            tx_bytes = int(fields[8])
            rows.append((iface, rx_bytes, tx_bytes))
    except Exception:
        return []
    return rows


def _read_network_totals() -> list[tuple[str, int, int]]:
    """
    Parse `/proc/net/dev` and return `(iface, rx_bytes, tx_bytes)` rows.
    """
    path = Path("/proc/net/dev")
    if not path.exists():
        return []
    try:
        return _parse_netdev(path.read_text(encoding="utf-8"))
    except Exception:
        return []


class AgentMetricsCollector:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = Path(settings.agent_data_root)

    def collect(self):  # noqa: ANN201
        info = GaugeMetricFamily("tracegate_agent_info", "Tracegate agent info", labels=["role"])
        info.add_metric([str(self.settings.agent_role)], 1)
        yield info

        artifacts = GaugeMetricFamily(
            "tracegate_agent_artifacts_total",
            "Number of on-disk artifacts managed by the agent",
            labels=["kind"],
        )
        artifacts.add_metric(["users"], sum(1 for _ in (self.root / "users").rglob("connection-*.json")) if (self.root / "users").exists() else 0)
        artifacts.add_metric(["wg_peers"], sum(1 for _ in (self.root / "wg-peers").glob("peer-*.json")) if (self.root / "wg-peers").exists() else 0)
        yield artifacts

        load_rows = _read_loadavg()
        if load_rows is not None:
            host_load = GaugeMetricFamily(
                "tracegate_host_load_average",
                "Host load average by rolling window",
                labels=["window"],
            )
            host_load.add_metric(["1m"], load_rows[0])
            host_load.add_metric(["5m"], load_rows[1])
            host_load.add_metric(["15m"], load_rows[2])
            yield host_load

        mem_rows = _read_meminfo()
        if mem_rows is not None:
            host_memory = GaugeMetricFamily(
                "tracegate_host_memory_bytes",
                "Host memory totals from /proc/meminfo",
                labels=["kind"],
            )
            host_memory.add_metric(["total"], mem_rows[0])
            host_memory.add_metric(["available"], mem_rows[1])
            yield host_memory

        net_rows = _read_network_totals()
        if net_rows:
            host_net = GaugeMetricFamily(
                "tracegate_host_network_bytes_total",
                "Host network byte counters from /proc/net/dev",
                labels=["interface", "direction"],
            )
            for iface, rx_bytes, tx_bytes in net_rows:
                host_net.add_metric([iface, "rx"], rx_bytes)
                host_net.add_metric([iface, "tx"], tx_bytes)
            yield host_net

        if str(self.settings.agent_role) != "VPS_T":
            return

        # WireGuard per-peer traffic stats (bytes are counters from the kernel).
        ok_metric = GaugeMetricFamily("tracegate_wg_scrape_ok", "WireGuard scrape status (1=ok, 0=error)")
        rx = GaugeMetricFamily(
            "tracegate_wg_peer_rx_bytes",
            "WireGuard peer received bytes",
            labels=["user_id", "user_display", "device_id", "device_name", "connection_alias", "peer_public_key"],
        )
        tx = GaugeMetricFamily(
            "tracegate_wg_peer_tx_bytes",
            "WireGuard peer transmitted bytes",
            labels=["user_id", "user_display", "device_id", "device_name", "connection_alias", "peer_public_key"],
        )
        hs = GaugeMetricFamily(
            "tracegate_wg_peer_latest_handshake_seconds",
            "WireGuard peer latest handshake timestamp (unix seconds)",
            labels=["user_id", "user_display", "device_id", "device_name", "connection_alias", "peer_public_key"],
        )

        try:
            peer_map = _load_wg_peer_map(self.root)
            dump_rows = _wg_dump(self.settings.agent_wg_interface)
            ok_metric.add_metric([], 1)
        except Exception:
            ok_metric.add_metric([], 0)
            yield ok_metric
            return

        # Skip interface header row.
        for row in dump_rows[1:]:
            if len(row) < 7:
                continue
            peer_pub = (row[0] or "").strip()
            latest_handshake = int(row[4] or 0)
            transfer_rx = int(row[5] or 0)
            transfer_tx = int(row[6] or 0)

            labels = peer_map.get(peer_pub) or {}
            user_id = labels.get("user_id") or ""
            user_display = labels.get("user_display") or user_id
            device_id = labels.get("device_id") or ""
            device_name = labels.get("device_name") or device_id
            conn_alias = labels.get("connection_alias") or ""
            metric_labels = [user_id, user_display, device_id, device_name, conn_alias, peer_pub]
            rx.add_metric(metric_labels, transfer_rx)
            tx.add_metric(metric_labels, transfer_tx)
            hs.add_metric(metric_labels, latest_handshake)

        yield ok_metric
        yield rx
        yield tx
        yield hs


def register_agent_metrics(settings: Settings) -> None:
    global _REGISTERED  # noqa: PLW0603
    if _REGISTERED:
        return
    REGISTRY.register(AgentMetricsCollector(settings))
    _REGISTERED = True
