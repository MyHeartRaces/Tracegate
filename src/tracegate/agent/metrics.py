from __future__ import annotations

import json
import os
from pathlib import Path
import re

from prometheus_client import REGISTRY
from prometheus_client.core import GaugeMetricFamily

from tracegate.services.hysteria_markers import normalize_hysteria_connection_marker
from tracegate.services.runtime_contract import resolve_runtime_contract
from tracegate.settings import Settings, effective_private_runtime_root

_REGISTERED = False
_MARKER_VARIANT_RE = re.compile(r"^[Vv]([0-9]+)\b")


def _marker_variant(marker: str) -> str:
    raw = str(marker or "").strip()
    m = _MARKER_VARIANT_RE.match(raw)
    if m is None:
        return ""
    return f"V{m.group(1)}"


def _marker_belongs_to_hysteria(marker: str) -> bool:
    return _marker_variant(marker) in {"V2", "V3", "V4"}


def _inbound_belongs_to_hysteria(inbound_tag: str) -> bool:
    raw = str(inbound_tag or "").strip().lower()
    return bool(raw) and (raw.startswith("hy2") or "hysteria" in raw)


def _query_xray_user_traffic_bytes(settings: Settings) -> dict[str, dict[str, int]]:
    # Local import keeps agent startup lighter when Xray isn't present/enabled.
    from .xray_api import query_user_traffic_bytes

    return query_user_traffic_bytes(settings, reset=False)


def _query_xray_inbound_traffic_bytes(settings: Settings) -> dict[str, dict[str, int]]:
    # Local import keeps agent startup lighter when Xray isn't present/enabled.
    from .xray_api import query_inbound_traffic_bytes

    return query_inbound_traffic_bytes(settings, reset=False)


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


def _load_json_mapping(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _mapping_value(payload: dict[str, object] | None, key: str) -> dict[str, object]:
    if not isinstance(payload, dict):
        return {}
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def _runtime_contract_payload(root: Path) -> dict[str, object] | None:
    return _load_json_mapping(root / "runtime" / "runtime-contract.json")


def _obfuscation_runtime_state(settings: Settings) -> dict[str, object] | None:
    role_lower = str(settings.agent_role or "").strip().lower()
    if not role_lower:
        return None
    path = Path(effective_private_runtime_root(settings)) / "obfuscation" / role_lower / "runtime-state.json"
    return _load_json_mapping(path)


class AgentMetricsCollector:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = Path(settings.agent_data_root)
        self.runtime_contract = resolve_runtime_contract(settings.agent_runtime_profile)

    def collect(self):  # noqa: ANN201
        role_label = str(self.settings.agent_role)
        info = GaugeMetricFamily("tracegate_agent_info", "Tracegate agent info", labels=["role"])
        info.add_metric([role_label], 1)
        yield info

        artifacts = GaugeMetricFamily(
            "tracegate_agent_artifacts_total",
            "Number of on-disk artifacts managed by the agent",
            labels=["kind"],
        )
        artifacts.add_metric(["users"], sum(1 for _ in (self.root / "users").rglob("connection-*.json")) if (self.root / "users").exists() else 0)
        yield artifacts

        runtime_contract = _runtime_contract_payload(self.root)
        xray_block = _mapping_value(runtime_contract, "xray")
        fronting_block = _mapping_value(runtime_contract, "fronting")
        obfuscation_state = _obfuscation_runtime_state(self.settings)

        runtime_contract_present = GaugeMetricFamily(
            "tracegate_runtime_contract_present",
            "Whether runtime-contract.json is present and parseable",
            labels=["role"],
        )
        runtime_contract_present.add_metric([role_label], 1 if runtime_contract is not None else 0)
        yield runtime_contract_present

        runtime_profile = GaugeMetricFamily(
            "tracegate_runtime_profile_info",
            "Runtime profile advertised by the current agent",
            labels=["role", "profile"],
        )
        profile_label = str(runtime_contract.get("runtimeProfile") if runtime_contract else "").strip() or self.runtime_contract.name
        runtime_profile.add_metric([role_label, profile_label], 1)
        yield runtime_profile

        runtime_features = GaugeMetricFamily(
            "tracegate_runtime_feature_enabled",
            "Boolean runtime feature flags derived from runtime-contract.json",
            labels=["role", "feature"],
        )
        runtime_features.add_metric([role_label, "finalmask"], 1 if bool(xray_block.get("finalMaskEnabled", False)) else 0)
        runtime_features.add_metric([role_label, "ech"], 1 if bool(xray_block.get("echEnabled", False)) else 0)
        runtime_features.add_metric([role_label, "mtproto_domain"], 1 if str(fronting_block.get("mtprotoDomain") or "").strip() else 0)
        runtime_features.add_metric([role_label, "touch_udp_443"], 1 if bool(fronting_block.get("touchUdp443", False)) else 0)
        yield runtime_features

        fronting_owner = GaugeMetricFamily(
            "tracegate_fronting_owner_info",
            "Advertised TCP/UDP owner for public runtime ports in runtime-contract.json",
            labels=["role", "protocol", "owner"],
        )
        tcp_owner = str(fronting_block.get("tcp443Owner") or "").strip()
        udp_owner = str(fronting_block.get("publicUdpOwner") or fronting_block.get("udp443Owner") or "").strip()
        if tcp_owner:
            fronting_owner.add_metric([role_label, "tcp", tcp_owner], 1)
        if udp_owner:
            fronting_owner.add_metric([role_label, "udp", udp_owner], 1)
        yield fronting_owner

        obfuscation_state_present = GaugeMetricFamily(
            "tracegate_obfuscation_runtime_state_present",
            "Whether the private obfuscation runtime-state.json handoff is present and parseable",
            labels=["role"],
        )
        obfuscation_state_present.add_metric([role_label], 1 if obfuscation_state is not None else 0)
        yield obfuscation_state_present

        obfuscation_backend = GaugeMetricFamily(
            "tracegate_obfuscation_backend_info",
            "Private obfuscation backend advertised by runtime-state.json",
            labels=["role", "backend"],
        )
        backend = str(obfuscation_state.get("backend") if obfuscation_state else "").strip()
        if backend:
            obfuscation_backend.add_metric([role_label, backend], 1)
        yield obfuscation_backend

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
            xray_scrape_ok = True
        except Exception:
            xray_ok.add_metric([], 0)
            xray_scrape_ok = False
            traffic = {}

        for marker, row in (traffic or {}).items():
            marker_s = str(marker or "").strip()
            if not marker_s or not isinstance(row, dict):
                continue
            if self.runtime_contract.hysteria_metrics_source == "xray_stats" and _marker_belongs_to_hysteria(marker_s):
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

        is_transit = str(self.settings.agent_role) == "TRANSIT"
        if not is_transit and self.runtime_contract.hysteria_metrics_source != "xray_stats":
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
        hyst_inbound_rx = GaugeMetricFamily(
            "tracegate_hysteria_inbound_rx_bytes",
            "Hysteria2 inbound received bytes (server RX)",
            labels=["inbound_tag"],
        )
        hyst_inbound_tx = GaugeMetricFamily(
            "tracegate_hysteria_inbound_tx_bytes",
            "Hysteria2 inbound transmitted bytes (server TX)",
            labels=["inbound_tag"],
        )
        if self.runtime_contract.hysteria_metrics_source == "xray_stats":
            try:
                inbound_traffic = _query_xray_inbound_traffic_bytes(self.settings)
                inbound_scrape_ok = True
            except Exception:
                inbound_scrape_ok = False
                inbound_traffic = {}

            hyst_ok.add_metric([], 1 if xray_scrape_ok and inbound_scrape_ok else 0)
            for marker, row in (traffic or {}).items():
                marker_s = normalize_hysteria_connection_marker(marker)
                if not marker_s or not isinstance(row, dict) or not _marker_belongs_to_hysteria(marker_s):
                    continue
                try:
                    rx_bytes = int(row.get("uplink") or 0)
                    tx_bytes = int(row.get("downlink") or 0)
                except Exception:
                    continue
                hyst_rx.add_metric([marker_s], rx_bytes)
                hyst_tx.add_metric([marker_s], tx_bytes)
            for inbound_tag, row in (inbound_traffic or {}).items():
                inbound_tag_s = str(inbound_tag or "").strip()
                if not inbound_tag_s or not isinstance(row, dict) or not _inbound_belongs_to_hysteria(inbound_tag_s):
                    continue
                try:
                    rx_bytes = int(row.get("uplink") or 0)
                    tx_bytes = int(row.get("downlink") or 0)
                except Exception:
                    continue
                hyst_inbound_rx.add_metric([inbound_tag_s], rx_bytes)
                hyst_inbound_tx.add_metric([inbound_tag_s], tx_bytes)
        else:
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
        yield hyst_inbound_rx
        yield hyst_inbound_tx


def register_agent_metrics(settings: Settings) -> None:
    global _REGISTERED  # noqa: PLW0603
    if _REGISTERED:
        return
    REGISTRY.register(AgentMetricsCollector(settings))
    _REGISTERED = True
