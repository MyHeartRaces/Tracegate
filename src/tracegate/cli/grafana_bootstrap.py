from __future__ import annotations

import asyncio
import os
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx


def _env(name: str, default: str | None = None) -> str:
    v = os.getenv(name)
    if v is None:
        if default is None:
            raise RuntimeError(f"{name} is required")
        return default
    return v


def _env_optional(name: str) -> str | None:
    v = os.getenv(name)
    if v is None:
        return None
    s = v.strip()
    return s or None


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


def _append_query_param(url: str, key: str, value: str) -> str:
    split = urlsplit(url)
    query = list(parse_qsl(split.query, keep_blank_values=True))
    query = [(k, v) for (k, v) in query if k != key]
    query.append((key, value))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))


def _alert_query_prometheus(ref_id: str, ds_uid: str, expr: str, *, from_seconds: int = 600) -> dict[str, Any]:
    return {
        "refId": ref_id,
        "queryType": "",
        "relativeTimeRange": {"from": from_seconds, "to": 0},
        "datasourceUid": ds_uid,
        "model": {
            "datasource": {"type": "prometheus", "uid": ds_uid},
            "editorMode": "code",
            "expr": expr,
            "instant": True,
            "intervalMs": 1000,
            "maxDataPoints": 43200,
            "range": False,
            "refId": ref_id,
        },
    }


def _alert_query_classic_condition(
    ref_id: str,
    input_ref_id: str,
    *,
    evaluator: str,
    threshold: float,
) -> dict[str, Any]:
    return {
        "refId": ref_id,
        "queryType": "",
        "relativeTimeRange": {"from": 0, "to": 0},
        "datasourceUid": "-100",
        "model": {
            "conditions": [
                {
                    "evaluator": {"params": [threshold], "type": evaluator},
                    "operator": {"type": "and"},
                    "query": {"params": [input_ref_id]},
                    "reducer": {"params": [], "type": "last"},
                    "type": "query",
                }
            ],
            "datasource": {"name": "Expression", "type": "__expr__", "uid": "-100"},
            "intervalMs": 1000,
            "maxDataPoints": 43200,
            "refId": ref_id,
            "type": "classic_conditions",
        },
    }


def _slo_alert_rule(
    *,
    uid: str,
    title: str,
    folder_uid: str,
    group: str,
    ds_uid: str,
    expr: str,
    evaluator: str,
    threshold: float,
    annotations: dict[str, str],
    labels: dict[str, str],
    for_duration: str = "2m",
    no_data_state: str = "OK",
) -> dict[str, Any]:
    return {
        "uid": uid,
        "title": title,
        "folderUID": folder_uid,
        "ruleGroup": group,
        "orgID": 1,
        "condition": "B",
        "data": [
            _alert_query_prometheus("A", ds_uid, expr),
            _alert_query_classic_condition("B", "A", evaluator=evaluator, threshold=threshold),
        ],
        "noDataState": no_data_state,
        "execErrState": "Alerting",
        "for": for_duration,
        "annotations": annotations,
        "labels": labels,
        "isPaused": False,
    }


def _slo_alert_rules(ds_uid: str, *, folder_uid: str) -> list[dict[str, Any]]:
    group = "tracegate-slo"
    base_labels = {"service": "tracegate", "kind": "slo"}

    return [
        _slo_alert_rule(
            uid="tg-slo-api-availability-low",
            title="SLO: API availability ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='min(tracegate_slo_component_up_ratio_5m{job="tracegate-api"})',
            evaluator="lt",
            threshold=0.99,
            annotations={
                "summary": "API scrape availability ratio is below 99% (5m)",
                "description": "tracegate_slo_component_up_ratio_5m for job=tracegate-api is below 0.99",
            },
            labels={**base_labels, "component": "api", "slo_type": "availability", "severity": "critical"},
            no_data_state="Alerting",
        ),
        _slo_alert_rule(
            uid="tg-slo-bot-availability-low",
            title="SLO: Bot availability ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='min(tracegate_slo_component_up_ratio_5m{job="tracegate-bot"})',
            evaluator="lt",
            threshold=0.99,
            annotations={
                "summary": "Bot scrape availability ratio is below 99% (5m)",
                "description": "tracegate_slo_component_up_ratio_5m for job=tracegate-bot is below 0.99",
            },
            labels={**base_labels, "component": "bot", "slo_type": "availability", "severity": "critical"},
            no_data_state="Alerting",
        ),
        _slo_alert_rule(
            uid="tg-slo-agent-availability-low",
            title="SLO: Agent availability ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='min(tracegate_slo_component_up_ratio_5m{job="tracegate-agent"})',
            evaluator="lt",
            threshold=0.95,
            annotations={
                "summary": "At least one agent scrape availability ratio is below 95% (5m)",
                "description": "min(tracegate_slo_component_up_ratio_5m{job=tracegate-agent}) is below 0.95",
            },
            labels={**base_labels, "component": "agent", "slo_type": "availability", "severity": "critical"},
            no_data_state="Alerting",
        ),
        _slo_alert_rule(
            uid="tg-slo-api-http-success-low",
            title="SLO: API HTTP success ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='tracegate_slo_http_request_success_ratio_5m{component="api"}',
            evaluator="lt",
            threshold=0.99,
            annotations={
                "summary": "API HTTP success ratio is below 99% (5m)",
                "description": "tracegate_slo_http_request_success_ratio_5m{component=api} is below 0.99",
            },
            labels={**base_labels, "component": "api", "slo_type": "success_ratio", "severity": "warning"},
        ),
        _slo_alert_rule(
            uid="tg-slo-agent-http-success-low",
            title="SLO: Agent HTTP success ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='tracegate_slo_http_request_success_ratio_5m{component="agent"}',
            evaluator="lt",
            threshold=0.98,
            annotations={
                "summary": "Agent HTTP success ratio is below 98% (5m)",
                "description": "tracegate_slo_http_request_success_ratio_5m{component=agent} is below 0.98",
            },
            labels={**base_labels, "component": "agent", "slo_type": "success_ratio", "severity": "warning"},
        ),
        _slo_alert_rule(
            uid="tg-slo-api-http-latency-high",
            title="SLO: API HTTP latency p95 high (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='tracegate_slo_http_request_latency_p95_seconds_5m{component="api"}',
            evaluator="gt",
            threshold=0.5,
            annotations={
                "summary": "API HTTP latency p95 is above 500ms (5m)",
                "description": "tracegate_slo_http_request_latency_p95_seconds_5m{component=api} is above 0.5s",
            },
            labels={**base_labels, "component": "api", "slo_type": "latency_p95", "severity": "warning"},
        ),
        _slo_alert_rule(
            uid="tg-slo-agent-http-latency-high",
            title="SLO: Agent HTTP latency p95 high (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='tracegate_slo_http_request_latency_p95_seconds_5m{component="agent"}',
            evaluator="gt",
            threshold=1.0,
            annotations={
                "summary": "Agent HTTP latency p95 is above 1s (5m)",
                "description": "tracegate_slo_http_request_latency_p95_seconds_5m{component=agent} is above 1s",
            },
            labels={**base_labels, "component": "agent", "slo_type": "latency_p95", "severity": "warning"},
        ),
        _slo_alert_rule(
            uid="tg-slo-bot-update-success-low",
            title="SLO: Bot update success ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr="tracegate_slo_bot_update_success_ratio_5m",
            evaluator="lt",
            threshold=0.99,
            annotations={
                "summary": "Bot update success ratio is below 99% (5m)",
                "description": "tracegate_slo_bot_update_success_ratio_5m is below 0.99",
            },
            labels={**base_labels, "component": "bot", "slo_type": "success_ratio", "severity": "warning"},
            no_data_state="OK",
        ),
        _slo_alert_rule(
            uid="tg-slo-bot-update-latency-high",
            title="SLO: Bot update latency p95 high (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr="tracegate_slo_bot_update_latency_p95_seconds_5m",
            evaluator="gt",
            threshold=3.0,
            annotations={
                "summary": "Bot update latency p95 is above 3s (5m)",
                "description": "tracegate_slo_bot_update_latency_p95_seconds_5m is above 3s",
            },
            labels={**base_labels, "component": "bot", "slo_type": "latency_p95", "severity": "warning"},
            no_data_state="OK",
        ),
    ]


async def _upsert_slo_alert_rule_group(
    client: httpx.AsyncClient,
    *,
    ds_uid: str,
    folder_uid: str,
    interval_seconds: int = 60,
) -> None:
    del interval_seconds  # Group interval is inherited on create/update via per-rule provisioning.

    desired_rules = _slo_alert_rules(ds_uid, folder_uid=folder_uid)
    desired_uids = {str(rule["uid"]) for rule in desired_rules}

    # Upsert each rule because Grafana's group PUT API only updates existing rule UIDs.
    for rule in desired_rules:
        uid = str(rule["uid"])
        get_r = await client.get(f"/api/v1/provisioning/alert-rules/{quote(uid, safe='')}")
        if get_r.status_code == 404:
            r = await client.post(
                "/api/v1/provisioning/alert-rules",
                json=rule,
                headers={"X-Disable-Provenance": "true"},
            )
            r.raise_for_status()
            continue
        get_r.raise_for_status()
        r = await client.put(
            f"/api/v1/provisioning/alert-rules/{quote(uid, safe='')}",
            json=rule,
            headers={"X-Disable-Provenance": "true"},
        )
        r.raise_for_status()

    # Remove stale rules in our managed group to keep provisioning idempotent.
    list_r = await client.get("/api/v1/provisioning/alert-rules")
    list_r.raise_for_status()
    for row in list_r.json():
        if row.get("folderUID") != folder_uid:
            continue
        if row.get("ruleGroup") != "tracegate-slo":
            continue
        uid = str(row.get("uid") or "")
        if not uid or uid in desired_uids:
            continue
        del_r = await client.delete(
            f"/api/v1/provisioning/alert-rules/{quote(uid, safe='')}",
            headers={"X-Disable-Provenance": "true"},
        )
        if del_r.status_code not in {200, 202, 204}:
            del_r.raise_for_status()


async def _upsert_contact_point(
    client: httpx.AsyncClient,
    *,
    uid: str,
    name: str,
    kind: str,
    settings: dict[str, Any],
    disable_resolve_message: bool = False,
) -> None:
    payload = {
        "uid": uid,
        "name": name,
        "type": kind,
        "settings": settings,
        "disableResolveMessage": disable_resolve_message,
    }
    get_r = await client.get("/api/v1/provisioning/contact-points")
    get_r.raise_for_status()
    existing = next((row for row in get_r.json() if str(row.get("uid") or "") == uid), None)
    headers = {"X-Disable-Provenance": "true"}
    if existing is None:
        r = await client.post("/api/v1/provisioning/contact-points", json=payload, headers=headers)
    else:
        r = await client.put(f"/api/v1/provisioning/contact-points/{quote(uid, safe='')}", json=payload, headers=headers)
    r.raise_for_status()


async def _upsert_notification_policies_for_slo(
    client: httpx.AsyncClient,
    *,
    receiver_name: str,
) -> None:
    get_r = await client.get("/api/v1/provisioning/policies")
    get_r.raise_for_status()
    root = get_r.json()
    routes = list(root.get("routes") or [])
    managed_matchers = [["service", "=", "tracegate"], ["kind", "=", "slo"]]
    managed_route = {
        "receiver": receiver_name,
        "group_by": ["alertname", "grafana_folder"],
        "group_wait": "30s",
        "group_interval": "5m",
        "repeat_interval": "30m",
        "object_matchers": managed_matchers,
        "continue": False,
    }

    replaced = False
    new_routes: list[dict[str, Any]] = []
    for route in routes:
        if route.get("object_matchers") == managed_matchers:
            if not replaced:
                new_routes.append(managed_route)
                replaced = True
            continue
        new_routes.append(route)
    if not replaced:
        new_routes.append(managed_route)
    root["routes"] = new_routes

    put_r = await client.put(
        "/api/v1/provisioning/policies",
        json=root,
        headers={"X-Disable-Provenance": "true"},
    )
    put_r.raise_for_status()


async def _get_dashboard(client: httpx.AsyncClient, uid: str) -> dict[str, Any] | None:
    r = await client.get(f"/api/dashboards/uid/{quote(uid, safe='')}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    body = r.json()
    db = body.get("dashboard")
    if isinstance(db, dict):
        return db
    return None


async def _count_slo_provisioned_rules(client: httpx.AsyncClient) -> int:
    r = await client.get("/api/v1/provisioning/alert-rules")
    r.raise_for_status()
    rows = r.json()
    return sum(1 for row in rows if row.get("ruleGroup") == "tracegate-slo")


_TG_ID_FROM_MARKER_RE = "^[^-]+ - ([0-9]+) - .+$"
_CONNECTION_ID_FROM_MARKER_RE = "^[^-]+ - [0-9]+ - (.+)$"


def _with_tg_id(expr: str) -> str:
    return f'label_replace({expr}, "tg_id", "$1", "connection_marker", "{_TG_ID_FROM_MARKER_RE}")'


def _with_tg_and_connection_id(expr: str) -> str:
    with_tg = _with_tg_id(expr)
    return (
        f'label_replace({with_tg}, "connection_id", "$1", '
        f'"connection_marker", "{_CONNECTION_ID_FROM_MARKER_RE}")'
    )


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
                        "expr": 'max by (tg_id, connection_label, protocol, mode, variant) (label_replace(tracegate_connection_active{user_pid="${__user.login}"}, "tg_id", "$1", "connection_marker", "^[^-]+ - ([0-9]+) - .+$"))',
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True, "Value": True},
                            "indexByName": {
                                "connection_label": 0,
                                "protocol": 1,
                                "mode": 2,
                                "variant": 3,
                                "tg_id": 4,
                            },
                            "renameByName": {"connection_label": "connection"},
                        },
                    }
                ],
                "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
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
                        "expr": 'sum by (connection_label) (rate(tracegate_wg_peer_rx_bytes[5m]) * on(peer_pid) group_left(connection_label) max by (peer_pid, connection_label) (tracegate_wg_peer_info{user_pid="${__user.login}"}))',
                        "legendFormat": "{{connection_label}}",
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
                        "expr": 'sum by (connection_label) (rate(tracegate_wg_peer_tx_bytes[5m]) * on(peer_pid) group_left(connection_label) max by (peer_pid, connection_label) (tracegate_wg_peer_info{user_pid="${__user.login}"}))',
                        "legendFormat": "{{connection_label}}",
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
                        "expr": 'time() - max by (connection_label) (tracegate_wg_peer_latest_handshake_seconds * on(peer_pid) group_left(connection_label) max by (peer_pid, connection_label) (tracegate_wg_peer_info{user_pid="${__user.login}"}))',
                        "legendFormat": "{{connection_label}}",
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
                        "expr": 'sum by (connection_label) (rate(tracegate_xray_connection_rx_bytes[5m]) * on(connection_marker) group_left(connection_label) max by (connection_marker, connection_label) (tracegate_connection_active{user_pid="${__user.login}", protocol=~"vless_.*"}))',
                        "legendFormat": "{{connection_label}}",
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
                        "expr": 'sum by (connection_label) (rate(tracegate_xray_connection_tx_bytes[5m]) * on(connection_marker) group_left(connection_label) max by (connection_marker, connection_label) (tracegate_connection_active{user_pid="${__user.login}", protocol=~"vless_.*"}))',
                        "legendFormat": "{{connection_label}}",
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
                        "expr": 'sum by (connection_label) (label_replace(rate(tracegate_hysteria_connection_rx_bytes[5m]), "cm_norm", "B$1 - $2 - $3", "connection_marker", "^[Bb]([0-9]+) - ([0-9]+) - (.+)$") * on(cm_norm) group_left(connection_label) max by (cm_norm, connection_label) (label_replace(tracegate_connection_active{user_pid="${__user.login}", protocol="hysteria2"}, "cm_norm", "B$1 - $2 - $3", "connection_marker", "^[Bb]([0-9]+) - ([0-9]+) - (.+)$")))',
                        "legendFormat": "{{connection_label}}",
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
                        "expr": 'sum by (connection_label) (label_replace(rate(tracegate_hysteria_connection_tx_bytes[5m]), "cm_norm", "B$1 - $2 - $3", "connection_marker", "^[Bb]([0-9]+) - ([0-9]+) - (.+)$") * on(cm_norm) group_left(connection_label) max by (cm_norm, connection_label) (label_replace(tracegate_connection_active{user_pid="${__user.login}", protocol="hysteria2"}, "cm_norm", "B$1 - $2 - $3", "connection_marker", "^[Bb]([0-9]+) - ([0-9]+) - (.+)$")))',
                        "legendFormat": "{{connection_label}}",
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
                        "expr": '(1 - (tracegate_host_memory_bytes{kind="available"} / ignoring(kind) tracegate_host_memory_bytes{kind="total"})) * 100',
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
                "title": "WireGuard RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum by (connection_label) (rate(tracegate_wg_peer_rx_bytes[5m]) * on(peer_pid) group_left(connection_label) max by (peer_pid, connection_label) (tracegate_wg_peer_info))",
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
            },
            {
                "id": 2,
                "type": "timeseries",
                "title": "WireGuard TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum by (connection_label) (rate(tracegate_wg_peer_tx_bytes[5m]) * on(peer_pid) group_left(connection_label) max by (peer_pid, connection_label) (tracegate_wg_peer_info))",
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
            },
            {
                "id": 11,
                "type": "timeseries",
                "title": "VLESS RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_label) (rate(tracegate_xray_connection_rx_bytes[5m]) * on(connection_marker) group_left(connection_label) max by (connection_marker, connection_label) (tracegate_connection_active{protocol=~"vless_.*"}))',
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            },
            {
                "id": 12,
                "type": "timeseries",
                "title": "VLESS TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_label) (rate(tracegate_xray_connection_tx_bytes[5m]) * on(connection_marker) group_left(connection_label) max by (connection_marker, connection_label) (tracegate_connection_active{protocol=~"vless_.*"}))',
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
            },
            {
                "id": 13,
                "type": "timeseries",
                "title": "Hysteria2 RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_label) (label_replace(rate(tracegate_hysteria_connection_rx_bytes[5m]), "cm_norm", "B$1 - $2 - $3", "connection_marker", "^[Bb]([0-9]+) - ([0-9]+) - (.+)$") * on(cm_norm) group_left(connection_label) max by (cm_norm, connection_label) (label_replace(tracegate_connection_active{protocol="hysteria2"}, "cm_norm", "B$1 - $2 - $3", "connection_marker", "^[Bb]([0-9]+) - ([0-9]+) - (.+)$")))',
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
            },
            {
                "id": 14,
                "type": "timeseries",
                "title": "Hysteria2 TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (connection_label) (label_replace(rate(tracegate_hysteria_connection_tx_bytes[5m]), "cm_norm", "B$1 - $2 - $3", "connection_marker", "^[Bb]([0-9]+) - ([0-9]+) - (.+)$") * on(cm_norm) group_left(connection_label) max by (cm_norm, connection_label) (label_replace(tracegate_connection_active{protocol="hysteria2"}, "cm_norm", "B$1 - $2 - $3", "connection_marker", "^[Bb]([0-9]+) - ([0-9]+) - (.+)$")))',
                        "legendFormat": "{{connection_label}}",
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
                        "expr": "sum by (connection_label) (rate(tracegate_wg_peer_rx_bytes[5m]) * on(peer_pid) group_left(connection_label) max by (peer_pid, connection_label) (tracegate_wg_peer_info))",
                        "legendFormat": "rx",
                    },
                    {
                        "refId": "B",
                        "expr": "sum by (connection_label) (rate(tracegate_wg_peer_tx_bytes[5m]) * on(peer_pid) group_left(connection_label) max by (peer_pid, connection_label) (tracegate_wg_peer_info))",
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
                        "expr": 'max by (connection_pid, tg_id, connection_label, protocol, mode, variant) (label_replace(tracegate_connection_active, "tg_id", "$1", "connection_marker", "^[^-]+ - ([0-9]+) - .+$"))',
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {
                                "Time": True,
                                "Value": True,
                                "connection_pid": True,
                            },
                            "indexByName": {
                                "tg_id": 0,
                                "connection_label": 1,
                                "protocol": 2,
                                "mode": 3,
                                "variant": 4,
                            },
                            "renameByName": {
                                "connection_label": "connection",
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
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
                        "expr": 'avg by (instance) ((1 - (tracegate_host_memory_bytes{kind="available"} / ignoring(kind) tracegate_host_memory_bytes{kind="total"})) * 100)',
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 40},
            },
        ],
    }


def _dashboard_admin_metadata(ds_uid: str) -> dict[str, Any]:
    return {
        "uid": "tracegate-admin-metadata",
        "title": "Tracegate (Admin Metadata)",
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "panels": [
            {
                "id": 1,
                "type": "table",
                "title": "Connection metadata (active)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            "max by (connection_label, tg_id, user_handle, device_name, protocol, mode, variant, connection_id, "
                            "connection_pid, user_pid, connection_marker, profile_name) "
                            f"({_with_tg_and_connection_id('tracegate_connection_active')})"
                        ),
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {
                                "Time": True,
                                "Value": True,
                            },
                            "indexByName": {
                                "connection_label": 0,
                                "tg_id": 1,
                                "user_handle": 2,
                                "device_name": 3,
                                "protocol": 4,
                                "mode": 5,
                                "variant": 6,
                                "connection_id": 7,
                                "connection_pid": 8,
                                "user_pid": 9,
                                "connection_marker": 10,
                                "profile_name": 11,
                            },
                            "renameByName": {
                                "connection_label": "connection",
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 12, "w": 24, "x": 0, "y": 0},
            },
            {
                "id": 2,
                "type": "table",
                "title": "WireGuard peer metadata",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            "max by (connection_label, tg_id, user_handle, device_name, profile_name, connection_id, "
                            "connection_pid, user_pid, peer_pid, connection_marker) "
                            f"({_with_tg_and_connection_id('tracegate_wg_peer_info')})"
                        ),
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {
                                "Time": True,
                                "Value": True,
                            },
                            "indexByName": {
                                "connection_label": 0,
                                "tg_id": 1,
                                "user_handle": 2,
                                "device_name": 3,
                                "peer_pid": 4,
                                "connection_id": 5,
                                "connection_pid": 6,
                                "user_pid": 7,
                                "connection_marker": 8,
                                "profile_name": 9,
                            },
                            "renameByName": {
                                "connection_label": "connection",
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 10, "w": 24, "x": 0, "y": 12},
            },
            {
                "id": 3,
                "type": "table",
                "title": "User identity map",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (user_handle, user_pid, role) (tracegate_user_info)",
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True, "Value": True},
                            "indexByName": {"user_handle": 0, "user_pid": 1, "role": 2},
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 22},
            },
        ],
    }


def _dashboard_operator(ds_uid: str) -> dict[str, Any]:
    return {
        "uid": "tracegate-admin-ops",
        "title": "Tracegate (Operator)",
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "panels": [
            {
                "id": 1,
                "type": "table",
                "title": "Component uptime ratio (5m)",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": "tracegate_slo_component_up_ratio_5m", "instant": True, "format": "table"}],
                "transformations": [{"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": {"Value": "up_ratio_5m"}}}],
                "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
                "gridPos": {"h": 8, "w": 8, "x": 0, "y": 0},
            },
            {
                "id": 2,
                "type": "table",
                "title": "HTTP success ratio (5m): API/Agent",
                "datasource": _ds(ds_uid),
                "targets": [
                    {"refId": "A", "expr": "tracegate_slo_http_request_success_ratio_5m", "instant": True, "format": "table"}
                ],
                "transformations": [{"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": {"Value": "success_ratio_5m"}}}],
                "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
                "gridPos": {"h": 8, "w": 8, "x": 8, "y": 0},
            },
            {
                "id": 3,
                "type": "stat",
                "title": "Bot update success ratio (5m)",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": "tracegate_slo_bot_update_success_ratio_5m"}],
                "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "orientation": "auto"},
                "fieldConfig": {"defaults": {"unit": "percentunit", "min": 0, "max": 1}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 16, "y": 0},
            },
            {
                "id": 4,
                "type": "timeseries",
                "title": "HTTP request latency p95 (5m): API/Agent",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": "tracegate_slo_http_request_latency_p95_seconds_5m", "legendFormat": "{{component}}"}],
                "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            },
            {
                "id": 5,
                "type": "timeseries",
                "title": "Bot update latency p95 (5m)",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": "tracegate_slo_bot_update_latency_p95_seconds_5m"}],
                "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
            },
            {
                "id": 6,
                "type": "table",
                "title": "Observed images (deploy revision)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (component, image) (tracegate_ops_component_image_info)",
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [{"id": "organize", "options": {"excludeByName": {"Time": True, "Value": True}}}],
                "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
            },
            {
                "id": 7,
                "type": "table",
                "title": "Component pod health (observed/ready)",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": "tracegate_ops_component_pods", "instant": True, "format": "table"}],
                "transformations": [{"id": "organize", "options": {"excludeByName": {"Time": True}}}],
                "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
            },
            {
                "id": 8,
                "type": "timeseries",
                "title": "Gateway container restart counts",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (component, container) (tracegate_ops_gateway_container_restart_count)",
                        "legendFormat": "{{component}} / {{container}}",
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
            },
            {
                "id": 9,
                "type": "timeseries",
                "title": "Outbox deliveries by status",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": "tracegate_ops_outbox_deliveries", "legendFormat": "{{status}}"}],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
            },
            {
                "id": 10,
                "type": "stat",
                "title": "Outbox pending/failed older than 5m",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": "tracegate_ops_outbox_pending_older_than_5m_deliveries"}],
                "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "orientation": "auto"},
                "gridPos": {"h": 8, "w": 8, "x": 0, "y": 32},
            },
            {
                "id": 11,
                "type": "timeseries",
                "title": "Disk used % (root)",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": "tracegate_ops_disk_used_percent", "legendFormat": "{{instance}}"}],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 8, "y": 32},
            },
            {
                "id": 12,
                "type": "timeseries",
                "title": "Node readiness",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": "tracegate_ops_node_ready", "legendFormat": "{{node}}"}],
                "fieldConfig": {"defaults": {"min": 0, "max": 1}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 16, "y": 32},
            },
            {
                "id": 13,
                "type": "timeseries",
                "title": "Metrics-server node sample age (s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "tracegate_ops_metrics_server_node_metric_age_seconds",
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 40},
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


async def bootstrap_with_config(
    *,
    base_url: str,
    admin_user: str,
    admin_password: str,
    prometheus_url: str,
    slo_webhook_url: str | None = None,
    slo_webhook_token: str | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {}

    async with httpx.AsyncClient(base_url=base_url.rstrip("/"), auth=(admin_user, admin_password), timeout=10) as client:
        await _wait_grafana(client)

        ds_uid = await _ensure_prometheus_datasource(client, prometheus_url)
        user_folder_uid = await _ensure_folder(client, uid="tracegate", title="Tracegate")
        admin_folder_uid = await _ensure_folder(client, uid="tracegate-admin", title="Tracegate Admin")

        await _upsert_dashboard(client, _dashboard_user(ds_uid), folder_uid=user_folder_uid)
        await _upsert_dashboard(client, _dashboard_admin(ds_uid), folder_uid=admin_folder_uid)
        await _upsert_dashboard(client, _dashboard_admin_metadata(ds_uid), folder_uid=admin_folder_uid)
        await _upsert_dashboard(client, _dashboard_operator(ds_uid), folder_uid=admin_folder_uid)
        await _upsert_slo_alert_rule_group(client, ds_uid=ds_uid, folder_uid=admin_folder_uid)
        if slo_webhook_url and slo_webhook_token:
            webhook_url = _append_query_param(slo_webhook_url, "token", slo_webhook_token)
            cp_uid = "tracegate-slo-ops-webhook"
            cp_name = "tracegate-slo-ops-webhook"
            await _upsert_contact_point(
                client,
                uid=cp_uid,
                name=cp_name,
                kind="webhook",
                settings={"url": webhook_url},
                disable_resolve_message=False,
            )
            await _upsert_notification_policies_for_slo(client, receiver_name=cp_name)
            report["contact_point_uid"] = cp_uid
            report["notification_policy_route"] = "tracegate-slo"
        await _restrict_folder_to_admins(client, folder_uid=admin_folder_uid)

        # Postconditions: fail bootstrap visibly instead of "successful no-op".
        if await _get_dashboard(client, "tracegate-admin-ops") is None:
            raise RuntimeError("operator dashboard was not persisted in Grafana")
        report["operator_dashboard_uid"] = "tracegate-admin-ops"
        report["slo_rule_count"] = await _count_slo_provisioned_rules(client)
        if int(report["slo_rule_count"]) < 9:
            raise RuntimeError(f"expected at least 9 SLO rules, got {report['slo_rule_count']}")
        report["datasource_uid"] = ds_uid
        report["admin_folder_uid"] = admin_folder_uid
    return report


async def bootstrap() -> dict[str, Any]:
    base_url = _env("GRAFANA_BASE_URL")
    admin_user = _env("GRAFANA_ADMIN_USER", "admin")
    admin_password = _env("GRAFANA_ADMIN_PASSWORD")
    prometheus_url = _env("PROMETHEUS_URL")
    slo_webhook_url = _env_optional("TRACEGATE_SLO_WEBHOOK_URL")
    slo_webhook_token = _env_optional("TRACEGATE_SLO_WEBHOOK_TOKEN")
    return await bootstrap_with_config(
        base_url=base_url,
        admin_user=admin_user,
        admin_password=admin_password,
        prometheus_url=prometheus_url,
        slo_webhook_url=slo_webhook_url,
        slo_webhook_token=slo_webhook_token,
    )


def main() -> None:
    report = asyncio.run(bootstrap())
    print(
        "grafana_bootstrap_ok",
        {
            "operator_dashboard_uid": report.get("operator_dashboard_uid"),
            "slo_rule_count": report.get("slo_rule_count"),
            "contact_point_uid": report.get("contact_point_uid"),
        },
    )
