from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

from prometheus_client import REGISTRY
from prometheus_client.core import GaugeMetricFamily

from tracegate.services.hysteria_markers import normalize_hysteria_connection_marker
from tracegate.services.pseudonym import wg_peer_pid
from tracegate.settings import Settings

_REGISTERED = False


def _query_xray_user_traffic_bytes(settings: Settings) -> dict[str, dict[str, int]]:
    # Local import keeps agent startup lighter when Xray isn't present/enabled.
    from .xray_api import query_user_traffic_bytes

    return query_user_traffic_bytes(settings, reset=False)


def _fetch_hysteria_traffic_bytes(url: str, secret: str) -> dict[str, dict[str, int]]:
    """
    Fetch Hysteria2 traffic stats API response.

    Expected response (best-effort parsing):
      { "<client_id>": {"tx": <bytes>, "rx": <bytes>}, ... }
    """
    import httpx

    url_s = str(url or "").strip()
    secret_s = str(secret or "").strip()
    if not url_s or not secret_s:
        raise ValueError("AGENT_STATS_URL/AGENT_STATS_SECRET are required for hysteria stats scrape")

    r = httpx.get(url_s, headers={"Authorization": secret_s}, timeout=5)
    r.raise_for_status()
    data = r.json()

    out: dict[str, dict[str, int]] = {}
    if not isinstance(data, dict):
        return out
    for key, value in data.items():
        marker = str(key or "").strip()
        if not marker or not isinstance(value, dict):
            continue
        try:
            tx = int(value.get("tx") or 0)
            rx = int(value.get("rx") or 0)
        except Exception:
            continue
        out[marker] = {"tx": tx, "rx": rx}
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

        # Xray per-connection traffic stats (bytes are counters exported by StatsService).
        xray_ok = GaugeMetricFamily("tracegate_xray_stats_scrape_ok", "Xray stats scrape status (1=ok, 0=error)")
        xray_rx = GaugeMetricFamily(
            "tracegate_xray_connection_rx_bytes",
            "Xray connection received bytes (uplink, server RX)",
            labels=["connection_marker"],
        )
        xray_tx = GaugeMetricFamily(
            "tracegate_xray_connection_tx_bytes",
            "Xray connection transmitted bytes (downlink, server TX)",
            labels=["connection_marker"],
        )
        try:
            traffic = _query_xray_user_traffic_bytes(self.settings)
            xray_ok.add_metric([], 1)
        except Exception:
            xray_ok.add_metric([], 0)
            traffic = {}

        for marker, row in (traffic or {}).items():
            marker_s = str(marker or "").strip()
            if not marker_s or not isinstance(row, dict):
                continue
            # Xray uses "uplink/downlink" naming for user stats.
            # Map to server RX/TX to match WG/Hysteria dashboards.
            try:
                rx_bytes = int(row.get("uplink") or 0)
                tx_bytes = int(row.get("downlink") or 0)
            except Exception:
                continue
            xray_rx.add_metric([marker_s], rx_bytes)
            xray_tx.add_metric([marker_s], tx_bytes)

        yield xray_ok
        yield xray_rx
        yield xray_tx

        is_vps_t = str(self.settings.agent_role) == "VPS_T"
        if not is_vps_t:
            return

        # Hysteria2 per-connection traffic stats (bytes are counters reported by Traffic Stats API).
        hyst_ok = GaugeMetricFamily("tracegate_hysteria_stats_scrape_ok", "Hysteria2 stats scrape status (1=ok, 0=error)")
        hyst_rx = GaugeMetricFamily(
            "tracegate_hysteria_connection_rx_bytes",
            "Hysteria2 connection received bytes (server RX)",
            labels=["connection_marker"],
        )
        hyst_tx = GaugeMetricFamily(
            "tracegate_hysteria_connection_tx_bytes",
            "Hysteria2 connection transmitted bytes (server TX)",
            labels=["connection_marker"],
        )
        try:
            traffic = _fetch_hysteria_traffic_bytes(self.settings.agent_stats_url, self.settings.agent_stats_secret)
            hyst_ok.add_metric([], 1)
        except Exception:
            hyst_ok.add_metric([], 0)
            traffic = {}

        for marker, row in (traffic or {}).items():
            marker_s = normalize_hysteria_connection_marker(marker)
            if not marker_s or not isinstance(row, dict):
                continue
            try:
                rx_bytes = int(row.get("rx") or 0)
                tx_bytes = int(row.get("tx") or 0)
            except Exception:
                continue
            hyst_rx.add_metric([marker_s], rx_bytes)
            hyst_tx.add_metric([marker_s], tx_bytes)

        yield hyst_ok
        yield hyst_rx
        yield hyst_tx

        # WireGuard per-peer traffic stats (bytes are counters from the kernel).
        ok_metric = GaugeMetricFamily("tracegate_wg_scrape_ok", "WireGuard scrape status (1=ok, 0=error)")
        rx = GaugeMetricFamily(
            "tracegate_wg_peer_rx_bytes",
            "WireGuard peer received bytes",
            labels=["peer_pid"],
        )
        tx = GaugeMetricFamily(
            "tracegate_wg_peer_tx_bytes",
            "WireGuard peer transmitted bytes",
            labels=["peer_pid"],
        )
        hs = GaugeMetricFamily(
            "tracegate_wg_peer_latest_handshake_seconds",
            "WireGuard peer latest handshake timestamp (unix seconds)",
            labels=["peer_pid"],
        )

        try:
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
            if not peer_pub:
                continue
            try:
                peer_id = wg_peer_pid(self.settings, peer_pub)
            except Exception:
                # Best-effort fallback if PSEUDONYM_SECRET (or its fallbacks) is missing.
                # Still avoids exposing the raw public key.
                peer_id = hashlib.sha256(peer_pub.encode("utf-8")).hexdigest()[:20]
            latest_handshake = int(row[4] or 0)
            transfer_rx = int(row[5] or 0)
            transfer_tx = int(row[6] or 0)

            rx.add_metric([peer_id], transfer_rx)
            tx.add_metric([peer_id], transfer_tx)
            hs.add_metric([peer_id], latest_handshake)

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
