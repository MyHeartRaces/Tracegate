from __future__ import annotations

import json
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
            "device_id": str(row.get("device_id") or "").strip(),
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

        if str(self.settings.agent_role) != "VPS_T":
            return

        # WireGuard per-peer traffic stats (bytes are counters from the kernel).
        ok_metric = GaugeMetricFamily("tracegate_wg_scrape_ok", "WireGuard scrape status (1=ok, 0=error)")
        rx = GaugeMetricFamily(
            "tracegate_wg_peer_rx_bytes",
            "WireGuard peer received bytes",
            labels=["user_id", "device_id", "peer_public_key"],
        )
        tx = GaugeMetricFamily(
            "tracegate_wg_peer_tx_bytes",
            "WireGuard peer transmitted bytes",
            labels=["user_id", "device_id", "peer_public_key"],
        )
        hs = GaugeMetricFamily(
            "tracegate_wg_peer_latest_handshake_seconds",
            "WireGuard peer latest handshake timestamp (unix seconds)",
            labels=["user_id", "device_id", "peer_public_key"],
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
            device_id = labels.get("device_id") or ""
            rx.add_metric([user_id, device_id, peer_pub], transfer_rx)
            tx.add_metric([user_id, device_id, peer_pub], transfer_tx)
            hs.add_metric([user_id, device_id, peer_pub], latest_handshake)

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
