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
                "type": "timeseries",
                "title": "WireGuard RX rate (bytes/s) by device",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (device_id) (rate(tracegate_wg_peer_rx_bytes{user_id="$__user.login"}[5m]))',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
            },
            {
                "id": 2,
                "type": "timeseries",
                "title": "WireGuard TX rate (bytes/s) by device",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (device_id) (rate(tracegate_wg_peer_tx_bytes{user_id="$__user.login"}[5m]))',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
            },
            {
                "id": 3,
                "type": "timeseries",
                "title": "WireGuard handshake age (seconds) by device",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'time() - max by (device_id) (tracegate_wg_peer_latest_handshake_seconds{user_id="$__user.login"})',
                    }
                ],
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
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
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
            },
            {
                "id": 5,
                "type": "timeseries",
                "title": "Node memory available (bytes)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {"refId": "A", "expr": "node_memory_MemAvailable_bytes"},
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
            },
            {
                "id": 6,
                "type": "timeseries",
                "title": "Root disk used (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": '100 - (max by (instance) (node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}) / max by (instance) (node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}) * 100)',
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
            },
            {
                "id": 7,
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
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
            },
        ],
    }


def _dashboard_admin(ds_uid: str) -> dict[str, Any]:
    return {
        "uid": "tracegate-admin",
        "title": "Tracegate (Admin)",
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "panels": [
            {
                "id": 1,
                "type": "timeseries",
                "title": "WireGuard RX rate (bytes/s) by user+device",
                "datasource": _ds(ds_uid),
                "targets": [
                    {"refId": "A", "expr": "sum by (user_id, device_id) (rate(tracegate_wg_peer_rx_bytes[5m]))"},
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
            },
            {
                "id": 2,
                "type": "timeseries",
                "title": "WireGuard TX rate (bytes/s) by user+device",
                "datasource": _ds(ds_uid),
                "targets": [
                    {"refId": "A", "expr": "sum by (user_id, device_id) (rate(tracegate_wg_peer_tx_bytes[5m]))"},
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
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
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
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
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
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
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
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
