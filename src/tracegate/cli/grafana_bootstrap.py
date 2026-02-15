from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx


def _env(name: str, default: str | None = None) -> str:
    v = os.getenv(name)
    if v is None:
        if default is None:
            raise RuntimeError(f"{name} is required")
        return default
    return v


async def _wait_grafana(client: httpx.AsyncClient, seconds: int = 120) -> None:
    for _ in range(seconds):
        try:
            r = await client.get("/api/health")
            if r.status_code == 200:
                return
        except Exception:
            pass
        await asyncio.sleep(1)
    raise RuntimeError("Grafana is not ready")


async def _ensure_prometheus_datasource(client: httpx.AsyncClient, prometheus_url: str) -> str:
    r = await client.get("/api/datasources/name/Prometheus")
    if r.status_code == 200:
        body = r.json()
        uid = body.get("uid")
        if uid:
            return str(uid)

    r = await client.post(
        "/api/datasources",
        json={
            "name": "Prometheus",
            "type": "prometheus",
            "access": "proxy",
            "url": prometheus_url,
            "isDefault": True,
        },
    )
    r.raise_for_status()
    body = r.json()
    uid = body.get("uid") or body.get("datasource", {}).get("uid")
    if not uid:
        # Fallback: lookup again
        rr = await client.get("/api/datasources/name/Prometheus")
        rr.raise_for_status()
        uid = rr.json().get("uid")
    if not uid:
        raise RuntimeError("cannot determine Prometheus datasource uid")
    return str(uid)


async def _ensure_folder(client: httpx.AsyncClient, *, uid: str, title: str) -> str:
    r = await client.get(f"/api/folders/{uid}")
    if r.status_code == 200:
        return uid
    if r.status_code != 404:
        r.raise_for_status()

    r = await client.post("/api/folders", json={"uid": uid, "title": title})
    if r.status_code not in {200, 201}:
        r.raise_for_status()
    return uid


def _ds(uid: str) -> dict[str, str]:
    return {"type": "prometheus", "uid": uid}


def _dashboard_user(ds_uid: str) -> dict[str, Any]:
    return {
        "uid": "tracegate-user",
        "title": "Tracegate (User)",
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "panels": [
            {
                "id": 1,
                "type": "table",
                "title": "Active connections",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'max by (connection_pid, connection_marker, protocol, mode, variant, device_name, profile_name, connection_label) (tracegate_connection_active{user_pid="$__user.login"})',
                        "instant": True,
                    }
                ],
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 0},
            },
            {
                "id": 2,
                "type": "timeseries",
                "title": "WireGuard RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_marker) (rate(tracegate_wg_peer_rx_bytes[5m]) * on(peer_pid) group_left(connection_marker) max by (peer_pid, connection_marker) (tracegate_wg_peer_info{user_pid="$__user.login"}))',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            },
            {
                "id": 3,
                "type": "timeseries",
                "title": "WireGuard TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_marker) (rate(tracegate_wg_peer_tx_bytes[5m]) * on(peer_pid) group_left(connection_marker) max by (peer_pid, connection_marker) (tracegate_wg_peer_info{user_pid="$__user.login"}))',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
            },
            {
                "id": 4,
                "type": "timeseries",
                "title": "WireGuard handshake age (seconds) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'time() - max by (connection_marker) (tracegate_wg_peer_latest_handshake_seconds * on(peer_pid) group_left(connection_marker) max by (peer_pid, connection_marker) (tracegate_wg_peer_info{user_pid="$__user.login"}))',
                    }
                ],
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 16},
            },
            {
                "id": 11,
                "type": "timeseries",
                "title": "VLESS RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_marker) (rate(tracegate_xray_connection_rx_bytes[5m]) * on(connection_marker) group_left max by (connection_marker) (tracegate_connection_active{user_pid="$__user.login", protocol=~"vless_.*"}))',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
            },
            {
                "id": 12,
                "type": "timeseries",
                "title": "VLESS TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_marker) (rate(tracegate_xray_connection_tx_bytes[5m]) * on(connection_marker) group_left max by (connection_marker) (tracegate_connection_active{user_pid="$__user.login", protocol=~"vless_.*"}))',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
            },
            {
                "id": 13,
                "type": "timeseries",
                "title": "Hysteria2 RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_marker) (rate(tracegate_hysteria_connection_rx_bytes[5m]) * on(connection_marker) group_left max by (connection_marker) (tracegate_connection_active{user_pid="$__user.login", protocol="hysteria2"}))',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 32},
            },
            {
                "id": 14,
                "type": "timeseries",
                "title": "Hysteria2 TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_marker) (rate(tracegate_hysteria_connection_tx_bytes[5m]) * on(connection_marker) group_left max by (connection_marker) (tracegate_connection_active{user_pid="$__user.login", protocol="hysteria2"}))',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 32},
            },
            {
                "id": 5,
                "type": "timeseries",
                "title": "Node CPU usage (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 40},
            },
            {
                "id": 6,
                "type": "timeseries",
                "title": "Node memory available (bytes)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {"refId": "A", "expr": "node_memory_MemAvailable_bytes"},
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 40},
            },
            {
                "id": 7,
                "type": "timeseries",
                "title": "Root disk used (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": '100 - (max by (instance) (node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}) / max by (instance) (node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}) * 100)',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 48},
            },
            {
                "id": 8,
                "type": "timeseries",
                "title": "Total node network RX/TX (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (instance) (rate(node_network_receive_bytes_total{device!~"lo"}[5m]))',
                    },
                    {
                        "refId": "B",
                        "expr": 'sum by (instance) (rate(node_network_transmit_bytes_total{device!~"lo"}[5m]))',
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 48},
            },
            {
                "id": 9,
                "type": "timeseries",
                "title": "Host load average (agent)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {"refId": "A", "expr": 'tracegate_host_load_average{window="1m"}'},
                    {"refId": "B", "expr": 'tracegate_host_load_average{window="5m"}'},
                    {"refId": "C", "expr": 'tracegate_host_load_average{window="15m"}'},
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 56},
            },
            {
                "id": 10,
                "type": "timeseries",
                "title": "Host memory used (%) (agent)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": '(1 - (tracegate_host_memory_bytes{kind="available"} / tracegate_host_memory_bytes{kind="total"})) * 100',
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 56},
            },
        ],
    }


def _dashboard_admin(ds_uid: str) -> dict[str, Any]:
    return {
        "uid": "tracegate-admin-dashboard",
        "title": "Tracegate (Admin)",
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "panels": [
            {
                "id": 1,
                "type": "timeseries",
                "title": "WireGuard RX rate (bytes/s) by user alias + connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum by (user_handle, connection_marker) (rate(tracegate_wg_peer_rx_bytes[5m]) * on(peer_pid) group_left(user_handle, connection_marker) max by (peer_pid, user_handle, connection_marker) (tracegate_wg_peer_info))",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
            },
            {
                "id": 2,
                "type": "timeseries",
                "title": "WireGuard TX rate (bytes/s) by user alias + connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum by (user_handle, connection_marker) (rate(tracegate_wg_peer_tx_bytes[5m]) * on(peer_pid) group_left(user_handle, connection_marker) max by (peer_pid, user_handle, connection_marker) (tracegate_wg_peer_info))",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
            },
            {
                "id": 11,
                "type": "timeseries",
                "title": "VLESS RX rate (bytes/s) by user alias + connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (user_handle, connection_marker) (rate(tracegate_xray_connection_rx_bytes[5m]) * on(connection_marker) group_left(user_handle, connection_marker) max by (connection_marker, user_handle) (tracegate_connection_active{protocol=~"vless_.*"}))',
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            },
            {
                "id": 12,
                "type": "timeseries",
                "title": "VLESS TX rate (bytes/s) by user alias + connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (user_handle, connection_marker) (rate(tracegate_xray_connection_tx_bytes[5m]) * on(connection_marker) group_left(user_handle, connection_marker) max by (connection_marker, user_handle) (tracegate_connection_active{protocol=~"vless_.*"}))',
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
            },
            {
                "id": 13,
                "type": "timeseries",
                "title": "Hysteria2 RX rate (bytes/s) by user alias + connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (user_handle, connection_marker) (rate(tracegate_hysteria_connection_rx_bytes[5m]) * on(connection_marker) group_left(user_handle, connection_marker) max by (connection_marker, user_handle) (tracegate_connection_active{protocol="hysteria2"}))',
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
            },
            {
                "id": 14,
                "type": "timeseries",
                "title": "Hysteria2 TX rate (bytes/s) by user alias + connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (user_handle, connection_marker) (rate(tracegate_hysteria_connection_tx_bytes[5m]) * on(connection_marker) group_left(user_handle, connection_marker) max by (connection_marker, user_handle) (tracegate_connection_active{protocol="hysteria2"}))',
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
            },
            {
                "id": 3,
                "type": "timeseries",
                "title": "Total node network RX/TX (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum(rate(node_network_receive_bytes_total{device!~"lo"}[5m]))',
                    },
                    {
                        "refId": "B",
                        "expr": 'sum(rate(node_network_transmit_bytes_total{device!~"lo"}[5m]))',
                    },
                ],
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 24},
            },
            {
                "id": 4,
                "type": "timeseries",
                "title": "Node CPU usage (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 32},
            },
            {
                "id": 5,
                "type": "timeseries",
                "title": "Root disk used (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": '100 - (max by (instance) (node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}) / max by (instance) (node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}) * 100)',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 32},
            },
            {
                "id": 6,
                "type": "table",
                "title": "Per-connection throughput table (bytes/s, WireGuard)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum by (user_handle, connection_marker) (rate(tracegate_wg_peer_rx_bytes[5m]) * on(peer_pid) group_left(user_handle, connection_marker) max by (peer_pid, user_handle, connection_marker) (tracegate_wg_peer_info))",
                        "legendFormat": "rx",
                    },
                    {
                        "refId": "B",
                        "expr": "sum by (user_handle, connection_marker) (rate(tracegate_wg_peer_tx_bytes[5m]) * on(peer_pid) group_left(user_handle, connection_marker) max by (peer_pid, user_handle, connection_marker) (tracegate_wg_peer_info))",
                        "legendFormat": "tx",
                    },
                ],
                "gridPos": {"h": 10, "w": 24, "x": 0, "y": 48},
            },
            {
                "id": 9,
                "type": "table",
                "title": "Active connections (all protocols)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (connection_pid, connection_marker, user_pid, user_handle, protocol, mode, variant, device_name, profile_name, connection_label) (tracegate_connection_active)",
                        "instant": True,
                    }
                ],
                "gridPos": {"h": 10, "w": 24, "x": 0, "y": 58},
            },
            {
                "id": 7,
                "type": "timeseries",
                "title": "Host load average (agent)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {"refId": "A", "expr": 'avg by (instance) (tracegate_host_load_average{window="1m"})'},
                    {"refId": "B", "expr": 'avg by (instance) (tracegate_host_load_average{window="5m"})'},
                    {"refId": "C", "expr": 'avg by (instance) (tracegate_host_load_average{window="15m"})'},
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 40},
            },
            {
                "id": 8,
                "type": "timeseries",
                "title": "Host memory used (%) (agent)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'avg by (instance) ((1 - (tracegate_host_memory_bytes{kind="available"} / tracegate_host_memory_bytes{kind="total"})) * 100)',
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 40},
            },
        ],
    }


async def _upsert_dashboard(client: httpx.AsyncClient, dashboard: dict[str, Any], *, folder_uid: str) -> None:
    r = await client.post(
        "/api/dashboards/db",
        json={"dashboard": dashboard, "folderUid": folder_uid, "overwrite": True},
    )
    r.raise_for_status()


async def _restrict_folder_to_admins(client: httpx.AsyncClient, *, folder_uid: str) -> None:
    # Remove Viewer/Editor permissions; Admins always have access.
    r = await client.post(f"/api/folders/{folder_uid}/permissions", json={"items": []})
    if r.status_code not in {200, 201}:
        r.raise_for_status()


async def bootstrap() -> None:
    base_url = _env("GRAFANA_BASE_URL")
    admin_user = _env("GRAFANA_ADMIN_USER", "admin")
    admin_password = _env("GRAFANA_ADMIN_PASSWORD")
    prometheus_url = _env("PROMETHEUS_URL")

    async with httpx.AsyncClient(base_url=base_url.rstrip("/"), auth=(admin_user, admin_password), timeout=10) as client:
        await _wait_grafana(client)

        ds_uid = await _ensure_prometheus_datasource(client, prometheus_url)
        user_folder_uid = await _ensure_folder(client, uid="tracegate", title="Tracegate")
        admin_folder_uid = await _ensure_folder(client, uid="tracegate-admin", title="Tracegate Admin")

        await _upsert_dashboard(client, _dashboard_user(ds_uid), folder_uid=user_folder_uid)
        await _upsert_dashboard(client, _dashboard_admin(ds_uid), folder_uid=admin_folder_uid)
        await _restrict_folder_to_admins(client, folder_uid=admin_folder_uid)


def main() -> None:
    asyncio.run(bootstrap())
