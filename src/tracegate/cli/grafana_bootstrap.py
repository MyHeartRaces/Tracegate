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


async def _ensure_prometheus_datasource(
    client: httpx.AsyncClient, prometheus_url: str
) -> str:
    r = await client.get("/api/datasources/name/Prometheus")
    if r.status_code == 200:
        body = r.json()
        uid = body.get("uid")
        if uid:
            if str(body.get("url") or "").rstrip("/") != prometheus_url.rstrip("/"):
                datasource_id = body.get("id")
                if datasource_id:
                    update = await client.put(
                        f"/api/datasources/{datasource_id}",
                        json={
                            "id": datasource_id,
                            "uid": uid,
                            "name": "Prometheus",
                            "type": "prometheus",
                            "access": "proxy",
                            "url": prometheus_url,
                            "isDefault": True,
                        },
                    )
                    update.raise_for_status()
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
    return urlunsplit(
        (split.scheme, split.netloc, split.path, urlencode(query), split.fragment)
    )


def _hysteria_shared_inbound_rate_expr(direction: str) -> str:
    normalized = str(direction or "").strip().lower()
    if normalized not in {"rx", "tx"}:
        raise ValueError(f"unsupported Hysteria direction: {direction!r}")
    metric = f"tracegate_hysteria_inbound_{normalized}_bytes"
    return f"sum by (instance) (rate({metric}[5m]))"


def _hysteria_total_expr(direction: str, *, operator: str, window: str) -> str:
    normalized = str(direction or "").strip().lower()
    if normalized not in {"rx", "tx"}:
        raise ValueError(f"unsupported Hysteria direction: {direction!r}")
    conn_metric = f"tracegate_hysteria_connection_{normalized}_bytes"
    inbound_metric = f"tracegate_hysteria_inbound_{normalized}_bytes"
    return f"((sum({operator}({conn_metric}[{window}])) or sum({operator}({inbound_metric}[{window}]))) or vector(0))"


def _active_connection_selector(
    *, user_scoped: bool = False, protocol_regex: str | None = None
) -> str:
    labels: list[str] = []
    if user_scoped:
        labels.append('user_pid="${__user.login}"')
    if protocol_regex:
        labels.append(f'protocol=~"{protocol_regex}"')
    if not labels:
        return "tracegate_connection_active"
    return f"tracegate_connection_active{{{','.join(labels)}}}"


def _connection_rate_expr(
    metric: str,
    *,
    user_scoped: bool = False,
    protocol_regex: str | None = None,
    group_by: tuple[str, ...] = ("connection_label", "protocol"),
) -> str:
    active = _active_connection_selector(
        user_scoped=user_scoped, protocol_regex=protocol_regex
    )
    labels = ", ".join(group_by)
    measured = (
        f"sum by ({labels}) (rate({metric}[5m]) * on(connection_marker) "
        f"group_left({labels}) max by (connection_marker, {labels}) ({active}))"
    )
    active_zero = f"0 * max by ({labels}) ({active})"
    return f"({measured}) or ({active_zero})"


def _connection_total_expr(
    metric: str,
    *,
    operator: str,
    window: str,
    user_scoped: bool = False,
    protocol_regex: str | None = None,
) -> str:
    active = _active_connection_selector(
        user_scoped=user_scoped, protocol_regex=protocol_regex
    )
    return f"(sum({operator}({metric}[{window}]) * on(connection_marker) group_left max by (connection_marker) ({active})) or vector(0))"


def _connection_protocol_rate_expr(metric: str, *, direction: str) -> str:
    normalized = str(direction or "").strip().lower()
    if normalized not in {"rx", "tx"}:
        raise ValueError(f"unsupported connection direction: {direction!r}")
    measured = (
        f"sum by (protocol, mode, variant) (rate({metric}[5m]) * on(connection_marker) "
        "group_left(protocol, mode, variant) "
        "max by (connection_marker, protocol, mode, variant) (tracegate_connection_active))"
    )
    active_zero = "0 * max by (protocol, mode, variant) (tracegate_connection_active)"
    return f"({measured}) or ({active_zero})"


_NODE_EXPORTER_SELECTOR = 'job="tracegate-node-exporter"'
_NODE_NETWORK_DEVICE_FILTER = 'device!~"lo|veth.*|cni.*|flannel.*|docker.*|br-.*"'
_NODE_DISK_DEVICE_FILTER = 'device!~"loop.*|ram.*|fd.*"'
_NODE_ROOT_FS_SELECTOR = (
    f'{_NODE_EXPORTER_SELECTOR},mountpoint="/",fstype!~"tmpfs|overlay"'
)


def _node_cpu_used_percent_expr() -> str:
    return f'100 - (avg by (node) (rate(node_cpu_seconds_total{{{_NODE_EXPORTER_SELECTOR},mode="idle"}}[5m])) * 100)'


def _node_memory_used_percent_expr() -> str:
    return (
        f"100 * (1 - (node_memory_MemAvailable_bytes{{{_NODE_EXPORTER_SELECTOR}}} "
        f"/ node_memory_MemTotal_bytes{{{_NODE_EXPORTER_SELECTOR}}}))"
    )


def _node_root_disk_used_percent_expr() -> str:
    return (
        f"100 - (max by (node) (node_filesystem_avail_bytes{{{_NODE_ROOT_FS_SELECTOR}}}) "
        f"/ max by (node) (node_filesystem_size_bytes{{{_NODE_ROOT_FS_SELECTOR}}}) * 100)"
    )


def _node_root_disk_available_expr() -> str:
    return f"max by (node) (node_filesystem_avail_bytes{{{_NODE_ROOT_FS_SELECTOR}}})"


def _node_network_rate_expr(direction: str) -> str:
    normalized = str(direction or "").strip().lower()
    if normalized not in {"rx", "tx"}:
        raise ValueError(f"unsupported node network direction: {direction!r}")
    metric = (
        "node_network_receive_bytes_total"
        if normalized == "rx"
        else "node_network_transmit_bytes_total"
    )
    return f"sum by (node) (rate({metric}{{{_NODE_EXPORTER_SELECTOR},{_NODE_NETWORK_DEVICE_FILTER}}}[5m]))"


def _node_disk_io_rate_expr(direction: str) -> str:
    normalized = str(direction or "").strip().lower()
    if normalized not in {"read", "write"}:
        raise ValueError(f"unsupported node disk direction: {direction!r}")
    metric = (
        "node_disk_read_bytes_total"
        if normalized == "read"
        else "node_disk_written_bytes_total"
    )
    return f"sum by (node) (rate({metric}{{{_NODE_EXPORTER_SELECTOR},{_NODE_DISK_DEVICE_FILTER}}}[5m]))"


def _component_up_ratio_expr(
    job_selector: str = 'job=~"tracegate-api|tracegate-bot|tracegate-agent|tracegate-dispatcher"',
) -> str:
    return f'avg by (job, component, node, pod) (avg_over_time(up{{namespace="tracegate",{job_selector}}}[5m]))'


def _http_success_ratio_expr(
    job_selector: str = 'job=~"tracegate-api|tracegate-agent"',
) -> str:
    selector = f'namespace="tracegate",{job_selector}'
    return (
        f'(sum by (job, component) (rate(tracegate_http_requests_total{{{selector},status!~"5.."}}[5m])) '
        f"/ sum by (job, component) (rate(tracegate_http_requests_total{{{selector}}}[5m])))"
    )


def _http_latency_p95_expr(
    job_selector: str = 'job=~"tracegate-api|tracegate-agent"',
) -> str:
    selector = f'namespace="tracegate",{job_selector}'
    return (
        "histogram_quantile(0.95, "
        f"sum by (le, job, component) (rate(tracegate_http_request_duration_seconds_bucket{{{selector}}}[5m])))"
    )


def _bot_update_success_ratio_expr() -> str:
    return (
        '((sum(rate(tracegate_bot_updates_total{namespace="tracegate",result="ok"}[5m])) '
        '/ sum(rate(tracegate_bot_updates_total{namespace="tracegate"}[5m]))) or vector(1))'
    )


def _bot_update_latency_p95_expr() -> str:
    return (
        "histogram_quantile(0.95, "
        'sum by (le) (rate(tracegate_bot_update_duration_seconds_bucket{namespace="tracegate"}[5m])))'
    )


def _alert_query_prometheus(
    ref_id: str, ds_uid: str, expr: str, *, from_seconds: int = 600
) -> dict[str, Any]:
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
            _alert_query_classic_condition(
                "B", "A", evaluator=evaluator, threshold=threshold
            ),
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

    rules = [
        _slo_alert_rule(
            uid="tg-slo-api-availability-low",
            title="SLO: API availability ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='min(avg_over_time(up{namespace="tracegate",job="tracegate-api"}[5m]))',
            evaluator="lt",
            threshold=0.99,
            annotations={
                "summary": "API scrape availability ratio is below 99% (5m)",
                "description": "avg_over_time(up{job=tracegate-api}[5m]) is below 0.99",
            },
            labels={
                **base_labels,
                "component": "api",
                "slo_type": "availability",
                "severity": "critical",
            },
            no_data_state="Alerting",
        ),
        _slo_alert_rule(
            uid="tg-slo-bot-availability-low",
            title="SLO: Bot availability ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='min(avg_over_time(up{namespace="tracegate",job="tracegate-bot"}[5m]))',
            evaluator="lt",
            threshold=0.99,
            annotations={
                "summary": "Bot scrape availability ratio is below 99% (5m)",
                "description": "avg_over_time(up{job=tracegate-bot}[5m]) is below 0.99",
            },
            labels={
                **base_labels,
                "component": "bot",
                "slo_type": "availability",
                "severity": "warning",
            },
            no_data_state="OK",
        ),
        _slo_alert_rule(
            uid="tg-slo-agent-availability-low",
            title="SLO: Agent availability ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='min(avg_over_time(up{namespace="tracegate",job="tracegate-agent"}[5m]))',
            evaluator="lt",
            threshold=0.95,
            annotations={
                "summary": "At least one agent scrape availability ratio is below 95% (5m)",
                "description": "min(avg_over_time(up{job=tracegate-agent}[5m])) is below 0.95",
            },
            labels={
                **base_labels,
                "component": "agent",
                "slo_type": "availability",
                "severity": "critical",
            },
            for_duration="5m",
            no_data_state="Alerting",
        ),
        _slo_alert_rule(
            uid="tg-slo-api-http-success-low",
            title="SLO: API HTTP success ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=(
                '(sum(rate(tracegate_http_requests_total{namespace="tracegate",job="tracegate-api",status!~"5.."}[5m])) '
                '/ sum(rate(tracegate_http_requests_total{namespace="tracegate",job="tracegate-api"}[5m])))'
            ),
            evaluator="lt",
            threshold=0.99,
            annotations={
                "summary": "API HTTP success ratio is below 99% (5m)",
                "description": "API non-5xx HTTP request ratio is below 0.99",
            },
            labels={
                **base_labels,
                "component": "api",
                "slo_type": "success_ratio",
                "severity": "warning",
            },
        ),
        _slo_alert_rule(
            uid="tg-slo-agent-http-success-low",
            title="SLO: Agent HTTP success ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=(
                '(sum(rate(tracegate_http_requests_total{namespace="tracegate",job="tracegate-agent",status!~"5.."}[5m])) '
                '/ sum(rate(tracegate_http_requests_total{namespace="tracegate",job="tracegate-agent"}[5m])))'
            ),
            evaluator="lt",
            threshold=0.98,
            annotations={
                "summary": "Agent HTTP success ratio is below 98% (5m)",
                "description": "Agent non-5xx HTTP request ratio is below 0.98",
            },
            labels={
                **base_labels,
                "component": "agent",
                "slo_type": "success_ratio",
                "severity": "warning",
            },
        ),
        _slo_alert_rule(
            uid="tg-slo-api-http-latency-high",
            title="SLO: API HTTP latency p95 high (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=(
                'histogram_quantile(0.95, sum by (le) (rate(tracegate_http_request_duration_seconds_bucket{namespace="tracegate",job="tracegate-api"}[5m])))'
            ),
            evaluator="gt",
            threshold=0.5,
            annotations={
                "summary": "API HTTP latency p95 is above 500ms (5m)",
                "description": "API HTTP request duration p95 is above 0.5s",
            },
            labels={
                **base_labels,
                "component": "api",
                "slo_type": "latency_p95",
                "severity": "warning",
            },
        ),
        _slo_alert_rule(
            uid="tg-slo-agent-http-latency-high",
            title="SLO: Agent HTTP latency p95 high (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=(
                'max(histogram_quantile(0.95, sum by (le, component) (rate(tracegate_http_request_duration_seconds_bucket{namespace="tracegate",job="tracegate-agent"}[5m]))))'
            ),
            evaluator="gt",
            threshold=1.0,
            annotations={
                "summary": "Agent HTTP latency p95 is above 1s (5m)",
                "description": "Max agent HTTP request duration p95 is above 1s",
            },
            labels={
                **base_labels,
                "component": "agent",
                "slo_type": "latency_p95",
                "severity": "warning",
            },
        ),
        _slo_alert_rule(
            uid="tg-slo-bot-update-success-low",
            title="SLO: Bot update success ratio low (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=_bot_update_success_ratio_expr(),
            evaluator="lt",
            threshold=0.99,
            annotations={
                "summary": "Bot update success ratio is below 99% (5m)",
                "description": "Bot update ok/total ratio is below 0.99",
            },
            labels={
                **base_labels,
                "component": "bot",
                "slo_type": "success_ratio",
                "severity": "warning",
            },
            no_data_state="OK",
        ),
        _slo_alert_rule(
            uid="tg-slo-bot-update-latency-high",
            title="SLO: Bot update latency p95 high (5m)",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=_bot_update_latency_p95_expr(),
            evaluator="gt",
            threshold=3.0,
            annotations={
                "summary": "Bot update latency p95 is above 3s (5m)",
                "description": "Bot update duration p95 is above 3s",
            },
            labels={
                **base_labels,
                "component": "bot",
                "slo_type": "latency_p95",
                "severity": "warning",
            },
            no_data_state="OK",
        ),
    ]
    rules.extend(
        _ops_alert_rules(
            ds_uid, folder_uid=folder_uid, group=group, base_labels=base_labels
        )
    )
    return rules


def _ops_alert_rules(
    ds_uid: str,
    *,
    folder_uid: str,
    group: str,
    base_labels: dict[str, str],
) -> list[dict[str, Any]]:
    node_up = 'min by (node, instance) (up{namespace="tracegate",job="tracegate-node-exporter"})'
    target_up = (
        "min by (job, component, node, pod, instance) "
        '(up{namespace="tracegate",job=~"tracegate-api|tracegate-bot|tracegate-agent|tracegate-dispatcher"})'
    )
    node_load_per_cpu = (
        f"node_load1{{{_NODE_EXPORTER_SELECTOR}}} / on(node) "
        f'count by (node) (node_cpu_seconds_total{{{_NODE_EXPORTER_SELECTOR},mode="idle"}})'
    )
    node_network_errors = (
        f"(sum by (node) (rate(node_network_receive_errs_total{{{_NODE_EXPORTER_SELECTOR},{_NODE_NETWORK_DEVICE_FILTER}}}[5m])) "
        f"+ sum by (node) (rate(node_network_transmit_errs_total{{{_NODE_EXPORTER_SELECTOR},{_NODE_NETWORK_DEVICE_FILTER}}}[5m])))"
    )
    pod_last_seen_age = (
        "time() - max by (node, pod) "
        '(container_last_seen{namespace="tracegate",pod!="",container!="POD"})'
    )
    container_restarts = 'changes(container_start_time_seconds{namespace="tracegate",container!="POD",container!="",container!="migrate-db"}[15m])'
    root_disk_free_bytes = f"max by (node, instance) (node_filesystem_avail_bytes{{{_NODE_ROOT_FS_SELECTOR}}})"
    xray_scrape_ok = (
        "min by (component, node, pod, instance) (tracegate_xray_stats_scrape_ok)"
    )
    hysteria_scrape_ok = (
        "min by (component, node, pod, instance) (tracegate_hysteria_stats_scrape_ok)"
    )

    return [
        _slo_alert_rule(
            uid="tg-ops-node-down",
            title="OPS: node exporter target down",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=node_up,
            evaluator="lt",
            threshold=1.0,
            annotations={
                "summary": "Node is unreachable from Prometheus",
                "description": "node-exporter scrape target is down or missing for at least 2 minutes",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "node_availability",
                "severity": "critical",
            },
            for_duration="2m",
            no_data_state="Alerting",
        ),
        _slo_alert_rule(
            uid="tg-ops-node-count-low",
            title="OPS: expected node count low",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr='count(up{namespace="tracegate",job="tracegate-node-exporter"} == 1)',
            evaluator="lt",
            threshold=3.0,
            annotations={
                "summary": "Tracegate sees fewer than 3 infrastructure nodes",
                "description": "Expected entry, transit and endpoint node exporters to be up",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "node_count",
                "severity": "critical",
            },
            for_duration="2m",
            no_data_state="Alerting",
        ),
        _slo_alert_rule(
            uid="tg-ops-target-down",
            title="OPS: Tracegate scrape target down",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=target_up,
            evaluator="lt",
            threshold=1.0,
            annotations={
                "summary": "Tracegate pod target is unreachable from Prometheus",
                "description": "API, bot, dispatcher or gateway-agent scrape target is down",
            },
            labels={
                **base_labels,
                "component": "pod",
                "slo_type": "pod_availability",
                "severity": "critical",
            },
            for_duration="2m",
            no_data_state="Alerting",
        ),
        _slo_alert_rule(
            uid="tg-ops-pod-not-seen",
            title="OPS: Tracegate pod not seen by cAdvisor",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=pod_last_seen_age,
            evaluator="gt",
            threshold=180.0,
            annotations={
                "summary": "Tracegate pod disappeared from cAdvisor",
                "description": "A pod has not been observed by cAdvisor for more than 3 minutes",
            },
            labels={
                **base_labels,
                "component": "pod",
                "slo_type": "pod_last_seen",
                "severity": "critical",
            },
            for_duration="2m",
            no_data_state="OK",
        ),
        _slo_alert_rule(
            uid="tg-ops-container-restarted",
            title="OPS: unexpected container restart",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=container_restarts,
            evaluator="gt",
            threshold=0.0,
            annotations={
                "summary": "Tracegate container restarted unexpectedly",
                "description": "container_start_time_seconds changed within the last 15 minutes",
            },
            labels={
                **base_labels,
                "component": "pod",
                "slo_type": "container_restart",
                "severity": "warning",
            },
            for_duration="1m",
            no_data_state="OK",
        ),
        _slo_alert_rule(
            uid="tg-ops-node-rebooted",
            title="OPS: node reboot detected",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=f"changes(node_boot_time_seconds{{{_NODE_EXPORTER_SELECTOR}}}[30m])",
            evaluator="gt",
            threshold=0.0,
            annotations={
                "summary": "Node reboot detected",
                "description": "node_boot_time_seconds changed within the last 30 minutes",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "node_reboot",
                "severity": "warning",
            },
            for_duration="1m",
            no_data_state="OK",
        ),
        _slo_alert_rule(
            uid="tg-ops-root-ssd-used-high",
            title="OPS: root SSD usage high",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=_node_root_disk_used_percent_expr(),
            evaluator="gt",
            threshold=80.0,
            annotations={
                "summary": "Root SSD usage is above 80%",
                "description": "Root filesystem has crossed the warning disk usage threshold",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "ssd_used_percent",
                "severity": "warning",
            },
            for_duration="5m",
        ),
        _slo_alert_rule(
            uid="tg-ops-root-ssd-used-critical",
            title="OPS: root SSD usage critical",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=_node_root_disk_used_percent_expr(),
            evaluator="gt",
            threshold=90.0,
            annotations={
                "summary": "Root SSD usage is above 90%",
                "description": "Root filesystem is close to full",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "ssd_used_percent",
                "severity": "critical",
            },
            for_duration="5m",
        ),
        _slo_alert_rule(
            uid="tg-ops-root-ssd-free-critical",
            title="OPS: root SSD free space critical",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=root_disk_free_bytes,
            evaluator="lt",
            threshold=2_147_483_648.0,
            annotations={
                "summary": "Root SSD free space is below 2 GiB",
                "description": "Absolute free space is critically low even if percentage still looks acceptable",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "ssd_free_bytes",
                "severity": "critical",
            },
            for_duration="5m",
        ),
        _slo_alert_rule(
            uid="tg-ops-memory-used-high",
            title="OPS: node memory usage high",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=_node_memory_used_percent_expr(),
            evaluator="gt",
            threshold=80.0,
            annotations={
                "summary": "Node memory usage is above 80%",
                "description": "Available memory dropped below the warning threshold",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "memory_used_percent",
                "severity": "warning",
            },
            for_duration="10m",
        ),
        _slo_alert_rule(
            uid="tg-ops-memory-used-critical",
            title="OPS: node memory usage critical",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=_node_memory_used_percent_expr(),
            evaluator="gt",
            threshold=90.0,
            annotations={
                "summary": "Node memory usage is above 90%",
                "description": "Available memory is critically low",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "memory_used_percent",
                "severity": "critical",
            },
            for_duration="5m",
        ),
        _slo_alert_rule(
            uid="tg-ops-cpu-used-high",
            title="OPS: node CPU usage high",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=_node_cpu_used_percent_expr(),
            evaluator="gt",
            threshold=95.0,
            annotations={
                "summary": "Node CPU usage is above 95%",
                "description": "CPU usage has stayed very high for 15 minutes",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "cpu_used_percent",
                "severity": "warning",
            },
            for_duration="15m",
        ),
        _slo_alert_rule(
            uid="tg-ops-load-high",
            title="OPS: node load average high",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=node_load_per_cpu,
            evaluator="gt",
            threshold=2.0,
            annotations={
                "summary": "Node load average is high relative to CPU count",
                "description": "1 minute load average is more than 2x the CPU count",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "load_per_cpu",
                "severity": "warning",
            },
            for_duration="10m",
        ),
        _slo_alert_rule(
            uid="tg-ops-network-errors",
            title="OPS: node network errors detected",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=node_network_errors,
            evaluator="gt",
            threshold=0.0,
            annotations={
                "summary": "Node network interface errors detected",
                "description": "Receive or transmit error counters are increasing",
            },
            labels={
                **base_labels,
                "component": "node",
                "slo_type": "network_errors",
                "severity": "warning",
            },
            for_duration="5m",
            no_data_state="OK",
        ),
        _slo_alert_rule(
            uid="tg-ops-outbox-stale-deliveries",
            title="OPS: bot/API outbox delivery backlog",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr="tracegate_ops_outbox_pending_older_than_5m_deliveries",
            evaluator="gt",
            threshold=0.0,
            annotations={
                "summary": "Tracegate has stale pending/failed message deliveries",
                "description": "At least one outbox delivery is pending or failed for more than 5 minutes",
            },
            labels={
                **base_labels,
                "component": "dispatcher",
                "slo_type": "message_delivery",
                "severity": "critical",
            },
            for_duration="5m",
        ),
        _slo_alert_rule(
            uid="tg-ops-dispatcher-active-alerts",
            title="OPS: dispatcher active alerts",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr="tracegate_dispatcher_ops_active_alerts",
            evaluator="gt",
            threshold=0.0,
            annotations={
                "summary": "Dispatcher reports active operational alerts",
                "description": "tracegate_dispatcher_ops_active_alerts is non-zero",
            },
            labels={
                **base_labels,
                "component": "dispatcher",
                "slo_type": "dispatcher_ops_alerts",
                "severity": "warning",
            },
            for_duration="2m",
        ),
        _slo_alert_rule(
            uid="tg-ops-xray-stats-scrape-failed",
            title="OPS: Xray stats scrape failed",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=xray_scrape_ok,
            evaluator="lt",
            threshold=1.0,
            annotations={
                "summary": "Xray stats scrape failed",
                "description": "Gateway agent cannot read Xray runtime stats",
            },
            labels={
                **base_labels,
                "component": "agent",
                "slo_type": "xray_stats_scrape",
                "severity": "warning",
            },
            for_duration="5m",
            no_data_state="OK",
        ),
        _slo_alert_rule(
            uid="tg-ops-hysteria-stats-scrape-failed",
            title="OPS: Hysteria stats scrape failed",
            folder_uid=folder_uid,
            group=group,
            ds_uid=ds_uid,
            expr=hysteria_scrape_ok,
            evaluator="lt",
            threshold=1.0,
            annotations={
                "summary": "Hysteria stats scrape failed",
                "description": "Gateway agent cannot read Hysteria runtime stats",
            },
            labels={
                **base_labels,
                "component": "agent",
                "slo_type": "hysteria_stats_scrape",
                "severity": "warning",
            },
            for_duration="5m",
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
    del (
        interval_seconds
    )  # Group interval is inherited on create/update via per-rule provisioning.

    desired_rules = _slo_alert_rules(ds_uid, folder_uid=folder_uid)
    desired_uids = {str(rule["uid"]) for rule in desired_rules}

    # Upsert each rule because Grafana's group PUT API only updates existing rule UIDs.
    for rule in desired_rules:
        uid = str(rule["uid"])
        get_r = await client.get(
            f"/api/v1/provisioning/alert-rules/{quote(uid, safe='')}"
        )
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
    existing = next(
        (row for row in get_r.json() if str(row.get("uid") or "") == uid), None
    )
    headers = {"X-Disable-Provenance": "true"}
    if existing is None:
        r = await client.post(
            "/api/v1/provisioning/contact-points", json=payload, headers=headers
        )
    else:
        r = await client.put(
            f"/api/v1/provisioning/contact-points/{quote(uid, safe='')}",
            json=payload,
            headers=headers,
        )
    r.raise_for_status()


def _same_object_matchers(left: Any, right: Any) -> bool:
    def normalize(value: Any) -> set[tuple[str, str, str]]:
        if not isinstance(value, list):
            return set()
        out: set[tuple[str, str, str]] = set()
        for row in value:
            if not isinstance(row, list | tuple) or len(row) != 3:
                continue
            out.add((str(row[0]), str(row[1]), str(row[2])))
        return out

    return normalize(left) == normalize(right)


async def _upsert_notification_policies_for_slo(
    client: httpx.AsyncClient,
    *,
    receiver_name: str,
) -> None:
    get_r = await client.get("/api/v1/provisioning/policies")
    get_r.raise_for_status()
    root = get_r.json()
    routes = list(root.get("routes") or [])
    legacy_matchers = [["service", "=", "tracegate"], ["kind", "=", "slo"]]
    managed_matchers = [
        ["service", "=", "tracegate"],
        ["kind", "=", "slo"],
        ["severity", "=", "critical"],
    ]
    managed_route = {
        "receiver": receiver_name,
        "group_by": ["alertname", "grafana_folder", "node", "pod"],
        "group_wait": "1m",
        "group_interval": "10m",
        "repeat_interval": "4h",
        "object_matchers": managed_matchers,
        "continue": False,
    }

    replaced = False
    new_routes: list[dict[str, Any]] = []
    for route in routes:
        if _same_object_matchers(
            route.get("object_matchers"), managed_matchers
        ) or _same_object_matchers(route.get("object_matchers"), legacy_matchers):
            if not replaced:
                new_routes.append(managed_route)
                replaced = True
            continue
        new_routes.append(route)
    if not replaced:
        new_routes.append(managed_route)
    # Grafana's built-in default receiver is email. Production does not
    # configure SMTP, so unmatched warnings must not fall through to it.
    # The Tracegate API webhook accepts non-critical alerts as a no-op and
    # forwards only critical alerts to Telegram admins.
    root["receiver"] = receiver_name
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
                        "expr": 'max by (telegram_id, connection_label, protocol, mode, variant, connection_id) (tracegate_connection_active{user_pid="${__user.login}"})',
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
                                "telegram_id": 4,
                                "connection_id": 5,
                            },
                            "renameByName": {"connection_label": "connection"},
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 0},
            },
            {
                "id": 11,
                "type": "timeseries",
                "title": "Xray RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_xray_connection_rx_bytes",
                            user_scoped=True,
                            protocol_regex="vless_.*|shadowsocks2022_shadowtls|wireguard_wstunnel",
                        ),
                        "legendFormat": "{{connection_label}}",
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            },
            {
                "id": 12,
                "type": "timeseries",
                "title": "Xray TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_xray_connection_tx_bytes",
                            user_scoped=True,
                            protocol_regex="vless_.*|shadowsocks2022_shadowtls|wireguard_wstunnel",
                        ),
                        "legendFormat": "{{connection_label}}",
                    }
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
                        "expr": _connection_rate_expr(
                            "tracegate_hysteria_connection_rx_bytes",
                            user_scoped=True,
                            protocol_regex="hysteria2",
                        ),
                        "legendFormat": "{{connection_label}}",
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
            },
            {
                "id": 14,
                "type": "timeseries",
                "title": "Hysteria2 TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_hysteria_connection_tx_bytes",
                            user_scoped=True,
                            protocol_regex="hysteria2",
                        ),
                        "legendFormat": "{{connection_label}}",
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
            },
            {
                "id": 18,
                "type": "timeseries",
                "title": "Shadowsocks RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_xray_connection_rx_bytes",
                            user_scoped=True,
                            protocol_regex="shadowsocks2022_shadowtls",
                        ),
                        "legendFormat": "{{connection_label}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
            },
            {
                "id": 19,
                "type": "timeseries",
                "title": "Shadowsocks TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_xray_connection_tx_bytes",
                            user_scoped=True,
                            protocol_regex="shadowsocks2022_shadowtls",
                        ),
                        "legendFormat": "{{connection_label}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
            },
            {
                "id": 5,
                "type": "timeseries",
                "title": "Node CPU usage (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_cpu_used_percent_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 32},
            },
            {
                "id": 6,
                "type": "timeseries",
                "title": "Node memory used (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_memory_used_percent_expr(),
                        "legendFormat": "{{node}}",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 32},
            },
            {
                "id": 7,
                "type": "timeseries",
                "title": "Root disk used (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_root_disk_used_percent_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 40},
            },
            {
                "id": 8,
                "type": "timeseries",
                "title": "Total node network RX/TX (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_network_rate_expr("rx"),
                        "legendFormat": "{{node}} RX",
                    },
                    {
                        "refId": "B",
                        "expr": _node_network_rate_expr("tx"),
                        "legendFormat": "{{node}} TX",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 40},
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
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 48},
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
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 48},
            },
            {
                "id": 15,
                "type": "timeseries",
                "title": "Own total RX/TX rate (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            _connection_total_expr(
                                "tracegate_xray_connection_rx_bytes",
                                operator="rate",
                                window="5m",
                                user_scoped=True,
                            )
                            + " + "
                            + _connection_total_expr(
                                "tracegate_hysteria_connection_rx_bytes",
                                operator="rate",
                                window="5m",
                                user_scoped=True,
                                protocol_regex="hysteria2",
                            )
                        ),
                        "legendFormat": "RX",
                    },
                    {
                        "refId": "B",
                        "expr": (
                            _connection_total_expr(
                                "tracegate_xray_connection_tx_bytes",
                                operator="rate",
                                window="5m",
                                user_scoped=True,
                            )
                            + " + "
                            + _connection_total_expr(
                                "tracegate_hysteria_connection_tx_bytes",
                                operator="rate",
                                window="5m",
                                user_scoped=True,
                                protocol_regex="hysteria2",
                            )
                        ),
                        "legendFormat": "TX",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 56},
            },
            {
                "id": 16,
                "type": "stat",
                "title": "Own total traffic (selected range)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            _connection_total_expr(
                                "tracegate_xray_connection_rx_bytes",
                                operator="increase",
                                window="$__range",
                                user_scoped=True,
                            )
                            + " + "
                            + _connection_total_expr(
                                "tracegate_xray_connection_tx_bytes",
                                operator="increase",
                                window="$__range",
                                user_scoped=True,
                            )
                            + " + "
                            + _connection_total_expr(
                                "tracegate_hysteria_connection_rx_bytes",
                                operator="increase",
                                window="$__range",
                                user_scoped=True,
                                protocol_regex="hysteria2",
                            )
                            + " + "
                            + _connection_total_expr(
                                "tracegate_hysteria_connection_tx_bytes",
                                operator="increase",
                                window="$__range",
                                user_scoped=True,
                                protocol_regex="hysteria2",
                            )
                        ),
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "bytes"}, "overrides": []},
                "gridPos": {"h": 8, "w": 6, "x": 12, "y": 56},
            },
            {
                "id": 17,
                "type": "stat",
                "title": "Node uptime",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": f"time() - node_boot_time_seconds{{{_NODE_EXPORTER_SELECTOR}}}",
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
                "gridPos": {"h": 8, "w": 6, "x": 18, "y": 56},
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
                "id": 11,
                "type": "timeseries",
                "title": "Xray RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_xray_connection_rx_bytes",
                            protocol_regex="vless_.*|shadowsocks2022_shadowtls|wireguard_wstunnel",
                        ),
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
            },
            {
                "id": 12,
                "type": "timeseries",
                "title": "Xray TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_xray_connection_tx_bytes",
                            protocol_regex="vless_.*|shadowsocks2022_shadowtls|wireguard_wstunnel",
                        ),
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
            },
            {
                "id": 13,
                "type": "timeseries",
                "title": "Hysteria2 RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_hysteria_connection_rx_bytes",
                            protocol_regex="hysteria2",
                        ),
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            },
            {
                "id": 14,
                "type": "timeseries",
                "title": "Hysteria2 TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_hysteria_connection_tx_bytes",
                            protocol_regex="hysteria2",
                        ),
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
            },
            {
                "id": 29,
                "type": "timeseries",
                "title": "Shadowsocks RX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_xray_connection_rx_bytes",
                            protocol_regex="shadowsocks2022_shadowtls",
                        ),
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
            },
            {
                "id": 30,
                "type": "timeseries",
                "title": "Shadowsocks TX rate (bytes/s) by connection",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_rate_expr(
                            "tracegate_xray_connection_tx_bytes",
                            protocol_regex="shadowsocks2022_shadowtls",
                        ),
                        "legendFormat": "{{connection_label}}",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
            },
            {
                "id": 3,
                "type": "timeseries",
                "title": "Node network RX/TX (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_network_rate_expr("rx"),
                        "legendFormat": "{{node}} RX",
                    },
                    {
                        "refId": "B",
                        "expr": _node_network_rate_expr("tx"),
                        "legendFormat": "{{node}} TX",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
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
                        "expr": _node_cpu_used_percent_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
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
                        "expr": _node_root_disk_used_percent_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 32},
            },
            {
                "id": 9,
                "type": "table",
                "title": "Active connections (all protocols)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (telegram_id, connection_id, connection_pid, connection_label, user_handle, protocol, mode, variant) (tracegate_connection_active)",
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
                                "telegram_id": 0,
                                "user_handle": 1,
                                "connection_label": 2,
                                "protocol": 3,
                                "mode": 4,
                                "variant": 5,
                                "connection_id": 6,
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
                "gridPos": {"h": 10, "w": 24, "x": 0, "y": 48},
            },
            {
                "id": 7,
                "type": "timeseries",
                "title": "Host load average (agent)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'avg by (instance) (tracegate_host_load_average{window="1m"})',
                    },
                    {
                        "refId": "B",
                        "expr": 'avg by (instance) (tracegate_host_load_average{window="5m"})',
                    },
                    {
                        "refId": "C",
                        "expr": 'avg by (instance) (tracegate_host_load_average{window="15m"})',
                    },
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
            {
                "id": 15,
                "type": "timeseries",
                "title": "Traffic rate by protocol RX (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_protocol_rate_expr(
                            "tracegate_xray_connection_rx_bytes", direction="rx"
                        ),
                        "legendFormat": "{{protocol}} / {{mode}} / {{variant}}",
                    },
                    {
                        "refId": "B",
                        "expr": _connection_protocol_rate_expr(
                            "tracegate_hysteria_connection_rx_bytes", direction="rx"
                        ),
                        "legendFormat": "{{protocol}} / {{mode}} / {{variant}}",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 58},
            },
            {
                "id": 16,
                "type": "timeseries",
                "title": "Traffic rate by protocol TX (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _connection_protocol_rate_expr(
                            "tracegate_xray_connection_tx_bytes", direction="tx"
                        ),
                        "legendFormat": "{{protocol}} / {{mode}} / {{variant}}",
                    },
                    {
                        "refId": "B",
                        "expr": _connection_protocol_rate_expr(
                            "tracegate_hysteria_connection_tx_bytes", direction="tx"
                        ),
                        "legendFormat": "{{protocol}} / {{mode}} / {{variant}}",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 58},
            },
            {
                "id": 17,
                "type": "timeseries",
                "title": "Gateway pod CPU usage",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (pod, container) (rate(container_cpu_usage_seconds_total{namespace="tracegate",pod=~"tracegate-.*gateway.*",container!="POD",container!=""}[5m]))',
                        "legendFormat": "{{pod}} / {{container}}",
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 66},
            },
            {
                "id": 18,
                "type": "timeseries",
                "title": "Gateway pod memory working set",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (pod, container) (container_memory_working_set_bytes{namespace="tracegate",pod=~"tracegate-.*gateway.*",container!="POD",container!=""})',
                        "legendFormat": "{{pod}} / {{container}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "bytes"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 66},
            },
            {
                "id": 19,
                "type": "timeseries",
                "title": "Gateway pod network RX/TX (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (pod) (rate(container_network_receive_bytes_total{namespace="tracegate",pod=~"tracegate-.*gateway.*"}[5m]))',
                        "legendFormat": "{{pod}} RX",
                    },
                    {
                        "refId": "B",
                        "expr": 'sum by (pod) (rate(container_network_transmit_bytes_total{namespace="tracegate",pod=~"tracegate-.*gateway.*"}[5m]))',
                        "legendFormat": "{{pod}} TX",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 74},
            },
            {
                "id": 20,
                "type": "timeseries",
                "title": "Transit node network RX/TX (MTProto context)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (instance) (rate(tracegate_host_network_bytes_total{job="tracegate-agent",component="gateway-transit",direction="rx",interface!="lo"}[5m]))',
                        "legendFormat": "{{instance}} RX",
                    },
                    {
                        "refId": "B",
                        "expr": 'sum by (instance) (rate(tracegate_host_network_bytes_total{job="tracegate-agent",component="gateway-transit",direction="tx",interface!="lo"}[5m]))',
                        "legendFormat": "{{instance}} TX",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 74},
            },
            {
                "id": 21,
                "type": "timeseries",
                "title": "Node uptime",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": f"time() - node_boot_time_seconds{{{_NODE_EXPORTER_SELECTOR}}}",
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 0, "y": 82},
            },
            {
                "id": 22,
                "type": "timeseries",
                "title": "Root SSD available",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_root_disk_available_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "bytes"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 8, "y": 82},
            },
            {
                "id": 23,
                "type": "timeseries",
                "title": "Scrape health",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'up{namespace="tracegate"}',
                        "legendFormat": "{{job}} / {{pod}}",
                    },
                    {
                        "refId": "B",
                        "expr": "tracegate_xray_stats_scrape_ok",
                        "legendFormat": "xray",
                    },
                    {
                        "refId": "C",
                        "expr": "tracegate_hysteria_stats_scrape_ok",
                        "legendFormat": "hysteria2",
                    },
                ],
                "gridPos": {"h": 8, "w": 8, "x": 16, "y": 82},
            },
            {
                "id": 24,
                "type": "table",
                "title": "Infra nodes (node-exporter)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": f'up{{namespace="tracegate",{_NODE_EXPORTER_SELECTOR}}}',
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True},
                            "renameByName": {"Value": "scrape_up"},
                            "indexByName": {
                                "node": 0,
                                "instance": 1,
                                "pod": 2,
                                "scrape_up": 3,
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 90},
            },
            {
                "id": 25,
                "type": "timeseries",
                "title": "Infra node load average",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": f"node_load1{{{_NODE_EXPORTER_SELECTOR}}}",
                        "legendFormat": "{{node}} 1m",
                    },
                    {
                        "refId": "B",
                        "expr": f"node_load5{{{_NODE_EXPORTER_SELECTOR}}}",
                        "legendFormat": "{{node}} 5m",
                    },
                    {
                        "refId": "C",
                        "expr": f"node_load15{{{_NODE_EXPORTER_SELECTOR}}}",
                        "legendFormat": "{{node}} 15m",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 98},
            },
            {
                "id": 26,
                "type": "timeseries",
                "title": "Infra node disk IO (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_disk_io_rate_expr("read"),
                        "legendFormat": "{{node}} read",
                    },
                    {
                        "refId": "B",
                        "expr": _node_disk_io_rate_expr("write"),
                        "legendFormat": "{{node}} write",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 98},
            },
            {
                "id": 27,
                "type": "timeseries",
                "title": "Tracegate pod CPU by node",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (node, pod, container) (rate(container_cpu_usage_seconds_total{namespace="tracegate",container!="POD",container!=""}[5m]))',
                        "legendFormat": "{{node}} / {{pod}} / {{container}}",
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 106},
            },
            {
                "id": 28,
                "type": "timeseries",
                "title": "Tracegate pod network by node (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (node, pod) (rate(container_network_receive_bytes_total{namespace="tracegate"}[5m]))',
                        "legendFormat": "{{node}} / {{pod}} RX",
                    },
                    {
                        "refId": "B",
                        "expr": 'sum by (node, pod) (rate(container_network_transmit_bytes_total{namespace="tracegate"}[5m]))',
                        "legendFormat": "{{node}} / {{pod}} TX",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 106},
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
                            "max by (connection_label, telegram_id, user_handle, device_name, protocol, mode, variant, connection_id, "
                            "connection_pid, user_pid, connection_marker, profile_name) (tracegate_connection_active)"
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
                                "telegram_id": 1,
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
                "id": 3,
                "type": "table",
                "title": "User identity map",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            "max by (telegram_id, user_handle, user_pid, role, entitlement_status, "
                            "bot_blocked, has_active_connection) (tracegate_user_info)"
                        ),
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
                                "telegram_id": 0,
                                "user_handle": 1,
                                "user_pid": 2,
                                "role": 3,
                                "entitlement_status": 4,
                                "bot_blocked": 5,
                                "has_active_connection": 6,
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12},
            },
            {
                "id": 2,
                "type": "table",
                "title": "Persistent MTProto access map",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (telegram_id, user_handle, user_pid, label, issued_by) (tracegate_mtproto_access_active)",
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
                                "telegram_id": 0,
                                "user_handle": 1,
                                "user_pid": 2,
                                "label": 3,
                                "issued_by": 4,
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12},
            },
            {
                "id": 4,
                "type": "timeseries",
                "title": "Total traffic rate RX/TX (bytes/s, all users/connections)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            "(sum(rate(tracegate_xray_connection_rx_bytes[5m])) or vector(0)) + "
                            + _hysteria_total_expr("rx", operator="rate", window="5m")
                        ),
                        "legendFormat": "RX total",
                    },
                    {
                        "refId": "B",
                        "expr": (
                            "(sum(rate(tracegate_xray_connection_tx_bytes[5m])) or vector(0)) + "
                            + _hysteria_total_expr("tx", operator="rate", window="5m")
                        ),
                        "legendFormat": "TX total",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 20},
            },
            {
                "id": 5,
                "type": "stat",
                "title": "Total RX traffic (selected range, bytes)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            "(sum(increase(tracegate_xray_connection_rx_bytes[$__range])) or vector(0)) + "
                            + _hysteria_total_expr(
                                "rx", operator="increase", window="$__range"
                            )
                        ),
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "bytes"}, "overrides": []},
                "options": {
                    "colorMode": "value",
                    "graphMode": "none",
                    "justifyMode": "auto",
                    "orientation": "auto",
                    "reduceOptions": {
                        "calcs": ["lastNotNull"],
                        "fields": "",
                        "values": False,
                    },
                    "showPercentChange": False,
                    "textMode": "auto",
                    "wideLayout": True,
                },
                "gridPos": {"h": 7, "w": 12, "x": 0, "y": 28},
            },
            {
                "id": 6,
                "type": "stat",
                "title": "Total TX traffic (selected range, bytes)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            "(sum(increase(tracegate_xray_connection_tx_bytes[$__range])) or vector(0)) + "
                            + _hysteria_total_expr(
                                "tx", operator="increase", window="$__range"
                            )
                        ),
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "bytes"}, "overrides": []},
                "options": {
                    "colorMode": "value",
                    "graphMode": "none",
                    "justifyMode": "auto",
                    "orientation": "auto",
                    "reduceOptions": {
                        "calcs": ["lastNotNull"],
                        "fields": "",
                        "values": False,
                    },
                    "showPercentChange": False,
                    "textMode": "auto",
                    "wideLayout": True,
                },
                "gridPos": {"h": 7, "w": 12, "x": 12, "y": 28},
            },
            {
                "id": 7,
                "type": "stat",
                "title": "Total traffic RX+TX (selected range, bytes)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            "(sum(increase(tracegate_xray_connection_rx_bytes[$__range])) or vector(0)) + "
                            + _hysteria_total_expr(
                                "rx", operator="increase", window="$__range"
                            )
                            + " + "
                            "(sum(increase(tracegate_xray_connection_tx_bytes[$__range])) or vector(0)) + "
                            + _hysteria_total_expr(
                                "tx", operator="increase", window="$__range"
                            )
                        ),
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "bytes"}, "overrides": []},
                "options": {
                    "colorMode": "value",
                    "graphMode": "none",
                    "justifyMode": "center",
                    "orientation": "auto",
                    "reduceOptions": {
                        "calcs": ["lastNotNull"],
                        "fields": "",
                        "values": False,
                    },
                    "showPercentChange": False,
                    "textMode": "value_and_name",
                    "wideLayout": True,
                },
                "gridPos": {"h": 7, "w": 24, "x": 0, "y": 35},
            },
            {
                "id": 8,
                "type": "timeseries",
                "title": "MTProto grant age (days) by user",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "(time() - tracegate_mtproto_access_updated_at_seconds) / 86400",
                        "legendFormat": "{{user_handle}} / {{label}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "d"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 42},
            },
            {
                "id": 9,
                "type": "stat",
                "title": "MTProto grants refreshed in the last 24h",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum((time() - tracegate_mtproto_access_updated_at_seconds) < bool 86400)",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
                "options": {
                    "colorMode": "value",
                    "graphMode": "none",
                    "justifyMode": "auto",
                    "orientation": "auto",
                    "reduceOptions": {
                        "calcs": ["lastNotNull"],
                        "fields": "",
                        "values": False,
                    },
                    "showPercentChange": False,
                    "textMode": "auto",
                    "wideLayout": True,
                },
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 42},
            },
            {
                "id": 10,
                "type": "stat",
                "title": "Oldest MTProto grant age (days)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max((time() - tracegate_mtproto_access_updated_at_seconds) / 86400)",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "d"}, "overrides": []},
                "options": {
                    "colorMode": "value",
                    "graphMode": "none",
                    "justifyMode": "auto",
                    "orientation": "auto",
                    "reduceOptions": {
                        "calcs": ["lastNotNull"],
                        "fields": "",
                        "values": False,
                    },
                    "showPercentChange": False,
                    "textMode": "auto",
                    "wideLayout": True,
                },
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 50},
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
                "title": "Component scrape availability (5m)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _component_up_ratio_expr(),
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True},
                            "renameByName": {"Value": "up_ratio_5m"},
                            "indexByName": {
                                "job": 0,
                                "component": 1,
                                "node": 2,
                                "pod": 3,
                                "up_ratio_5m": 4,
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 8, "x": 0, "y": 0},
            },
            {
                "id": 2,
                "type": "table",
                "title": "HTTP success ratio (5m): API/Agent",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _http_success_ratio_expr(),
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True},
                            "renameByName": {"Value": "success_ratio_5m"},
                            "indexByName": {
                                "job": 0,
                                "component": 1,
                                "success_ratio_5m": 2,
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 8, "x": 8, "y": 0},
            },
            {
                "id": 3,
                "type": "stat",
                "title": "Bot update success ratio (5m)",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": _bot_update_success_ratio_expr()}],
                "options": {
                    "reduceOptions": {
                        "calcs": ["lastNotNull"],
                        "fields": "",
                        "values": False,
                    },
                    "orientation": "auto",
                },
                "fieldConfig": {
                    "defaults": {"unit": "percentunit", "min": 0, "max": 1},
                    "overrides": [],
                },
                "gridPos": {"h": 8, "w": 8, "x": 16, "y": 0},
            },
            {
                "id": 4,
                "type": "timeseries",
                "title": "HTTP request latency p95 (5m): API/Agent",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _http_latency_p95_expr(),
                        "legendFormat": "{{job}} / {{component}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            },
            {
                "id": 5,
                "type": "timeseries",
                "title": "Bot update latency p95 (5m)",
                "datasource": _ds(ds_uid),
                "targets": [{"refId": "A", "expr": _bot_update_latency_p95_expr()}],
                "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
            },
            {
                "id": 6,
                "type": "timeseries",
                "title": "Dispatcher OPS checks (1h)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum by (check, result) (increase(tracegate_dispatcher_ops_checks_total[1h])) or vector(0)",
                        "legendFormat": "{{check}} / {{result}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
            },
            {
                "id": 7,
                "type": "timeseries",
                "title": "OPS alert messages (1h)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum by (kind, result) (increase(tracegate_dispatcher_ops_alert_messages_total[1h])) or vector(0)",
                        "legendFormat": "{{kind}} / {{result}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
            },
            {
                "id": 8,
                "type": "stat",
                "title": "Active OPS alerts",
                "datasource": _ds(ds_uid),
                "targets": [
                    {"refId": "A", "expr": "tracegate_dispatcher_ops_active_alerts"}
                ],
                "options": {
                    "reduceOptions": {
                        "calcs": ["lastNotNull"],
                        "fields": "",
                        "values": False,
                    },
                    "orientation": "auto",
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
            },
            {
                "id": 9,
                "type": "timeseries",
                "title": "Outbox deliveries by status",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "tracegate_ops_outbox_deliveries or vector(0)",
                        "legendFormat": "{{status}}",
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
            },
            {
                "id": 10,
                "type": "stat",
                "title": "Outbox pending/failed older than 5m",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "tracegate_ops_outbox_pending_older_than_5m_deliveries",
                    }
                ],
                "options": {
                    "reduceOptions": {
                        "calcs": ["lastNotNull"],
                        "fields": "",
                        "values": False,
                    },
                    "orientation": "auto",
                },
                "gridPos": {"h": 8, "w": 8, "x": 0, "y": 32},
            },
            {
                "id": 11,
                "type": "timeseries",
                "title": "Disk used % (root)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_root_disk_used_percent_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 8, "y": 32},
            },
            {
                "id": 12,
                "type": "timeseries",
                "title": "Outbox purge runs (24h)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum by (result) (increase(tracegate_dispatcher_outbox_purge_runs_total[24h])) or vector(0)",
                        "legendFormat": "{{result}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 16, "y": 32},
            },
            {
                "id": 13,
                "type": "timeseries",
                "title": "Outbox purged events (24h)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "sum by (status_bucket) (increase(tracegate_dispatcher_outbox_purged_events_total[24h])) or vector(0)",
                        "legendFormat": "{{status_bucket}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 40},
            },
            {
                "id": 14,
                "type": "table",
                "title": "Runtime features by role",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (role, feature) (tracegate_runtime_feature_enabled)",
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True},
                            "renameByName": {"Value": "enabled"},
                            "indexByName": {"role": 0, "feature": 1, "enabled": 2},
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 48},
            },
            {
                "id": 15,
                "type": "table",
                "title": "Runtime contract and obfuscation handoff",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (role) (tracegate_runtime_contract_present)",
                        "instant": True,
                        "format": "table",
                    },
                    {
                        "refId": "B",
                        "expr": "max by (role) (tracegate_obfuscation_runtime_state_present)",
                        "instant": True,
                        "format": "table",
                    },
                ],
                "transformations": [
                    {
                        "id": "joinByField",
                        "options": {"byField": "role", "mode": "outer"},
                    },
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time A": True, "Time B": True},
                            "renameByName": {
                                "Value A": "runtime_contract_present",
                                "Value B": "obfuscation_handoff_present",
                            },
                            "indexByName": {
                                "role": 0,
                                "runtime_contract_present": 1,
                                "obfuscation_handoff_present": 2,
                            },
                        },
                    },
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 48},
            },
            {
                "id": 16,
                "type": "table",
                "title": "Runtime profile / backend / 443 owner",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (role, profile) (tracegate_runtime_profile_info)",
                        "instant": True,
                        "format": "table",
                    },
                    {
                        "refId": "B",
                        "expr": "max by (role, backend) (tracegate_obfuscation_backend_info)",
                        "instant": True,
                        "format": "table",
                    },
                    {
                        "refId": "C",
                        "expr": 'max by (role, protocol, owner) (tracegate_fronting_owner_info{protocol="tcp"})',
                        "instant": True,
                        "format": "table",
                    },
                    {
                        "refId": "D",
                        "expr": 'max by (role, protocol, owner) (tracegate_fronting_owner_info{protocol="udp"})',
                        "instant": True,
                        "format": "table",
                    },
                ],
                "transformations": [
                    {
                        "id": "joinByField",
                        "options": {"byField": "role", "mode": "outer"},
                    },
                    {
                        "id": "joinByField",
                        "options": {"byField": "role", "mode": "outer"},
                    },
                    {
                        "id": "joinByField",
                        "options": {"byField": "role", "mode": "outer"},
                    },
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {
                                "Time A": True,
                                "Time B": True,
                                "Time C": True,
                                "Time D": True,
                                "Value A": True,
                                "Value B": True,
                                "Value C": True,
                                "Value D": True,
                                "protocol C": True,
                                "protocol D": True,
                            },
                            "renameByName": {
                                "profile": "runtime_profile",
                                "backend": "obfuscation_backend",
                                "owner C": "tcp_443_owner",
                                "owner D": "udp_443_owner",
                            },
                            "indexByName": {
                                "role": 0,
                                "runtime_profile": 1,
                                "obfuscation_backend": 2,
                                "tcp_443_owner": 3,
                                "udp_443_owner": 4,
                            },
                        },
                    },
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 56},
            },
            {
                "id": 17,
                "type": "table",
                "title": "Persistent MTProto access by issuer",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "count by (issued_by) (tracegate_mtproto_access_active)",
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True},
                            "renameByName": {"Value": "active_grants"},
                            "indexByName": {"issued_by": 0, "active_grants": 1},
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 64},
            },
            {
                "id": 18,
                "type": "table",
                "title": "Runtime endpoints (tracegate-agent)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": "max by (node, role, component, pod, instance) (tracegate_agent_info)",
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True},
                            "renameByName": {"Value": "present"},
                            "indexByName": {
                                "node": 0,
                                "role": 1,
                                "component": 2,
                                "pod": 3,
                                "instance": 4,
                                "present": 5,
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 72},
            },
            {
                "id": 19,
                "type": "table",
                "title": "Infra nodes (node-exporter)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": f'up{{namespace="tracegate",{_NODE_EXPORTER_SELECTOR}}}',
                        "instant": True,
                        "format": "table",
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True},
                            "renameByName": {"Value": "scrape_up"},
                            "indexByName": {
                                "node": 0,
                                "instance": 1,
                                "pod": 2,
                                "scrape_up": 3,
                            },
                        },
                    }
                ],
                "options": {
                    "showHeader": True,
                    "cellHeight": "sm",
                    "footer": {"show": False},
                },
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 72},
            },
            {
                "id": 20,
                "type": "timeseries",
                "title": "Infra node CPU usage (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_cpu_used_percent_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 0, "y": 80},
            },
            {
                "id": 21,
                "type": "timeseries",
                "title": "Infra node memory used (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_memory_used_percent_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 8, "y": 80},
            },
            {
                "id": 22,
                "type": "timeseries",
                "title": "Infra node root disk used (%)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_root_disk_used_percent_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "percent"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 16, "y": 80},
            },
            {
                "id": 23,
                "type": "timeseries",
                "title": "Infra node network RX/TX (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_network_rate_expr("rx"),
                        "legendFormat": "{{node}} RX",
                    },
                    {
                        "refId": "B",
                        "expr": _node_network_rate_expr("tx"),
                        "legendFormat": "{{node}} TX",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 88},
            },
            {
                "id": 24,
                "type": "timeseries",
                "title": "Infra node load average",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": f"node_load1{{{_NODE_EXPORTER_SELECTOR}}}",
                        "legendFormat": "{{node}} 1m",
                    },
                    {
                        "refId": "B",
                        "expr": f"node_load5{{{_NODE_EXPORTER_SELECTOR}}}",
                        "legendFormat": "{{node}} 5m",
                    },
                    {
                        "refId": "C",
                        "expr": f"node_load15{{{_NODE_EXPORTER_SELECTOR}}}",
                        "legendFormat": "{{node}} 15m",
                    },
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 88},
            },
            {
                "id": 25,
                "type": "timeseries",
                "title": "Infra node uptime",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": f"time() - node_boot_time_seconds{{{_NODE_EXPORTER_SELECTOR}}}",
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 0, "y": 96},
            },
            {
                "id": 26,
                "type": "timeseries",
                "title": "Infra node root SSD available",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_root_disk_available_expr(),
                        "legendFormat": "{{node}}",
                    }
                ],
                "fieldConfig": {"defaults": {"unit": "bytes"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 8, "y": 96},
            },
            {
                "id": 27,
                "type": "timeseries",
                "title": "Infra node disk IO (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": _node_disk_io_rate_expr("read"),
                        "legendFormat": "{{node}} read",
                    },
                    {
                        "refId": "B",
                        "expr": _node_disk_io_rate_expr("write"),
                        "legendFormat": "{{node}} write",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 8, "x": 16, "y": 96},
            },
            {
                "id": 28,
                "type": "timeseries",
                "title": "Tracegate pod CPU by node",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (node, pod, container) (rate(container_cpu_usage_seconds_total{namespace="tracegate",container!="POD",container!=""}[5m]))',
                        "legendFormat": "{{node}} / {{pod}} / {{container}}",
                    }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 104},
            },
            {
                "id": 29,
                "type": "timeseries",
                "title": "Tracegate pod network by node (bytes/s)",
                "datasource": _ds(ds_uid),
                "targets": [
                    {
                        "refId": "A",
                        "expr": 'sum by (node, pod) (rate(container_network_receive_bytes_total{namespace="tracegate"}[5m]))',
                        "legendFormat": "{{node}} / {{pod}} RX",
                    },
                    {
                        "refId": "B",
                        "expr": 'sum by (node, pod) (rate(container_network_transmit_bytes_total{namespace="tracegate"}[5m]))',
                        "legendFormat": "{{node}} / {{pod}} TX",
                    },
                ],
                "fieldConfig": {"defaults": {"unit": "Bps"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 104},
            },
        ],
    }


async def _upsert_dashboard(
    client: httpx.AsyncClient, dashboard: dict[str, Any], *, folder_uid: str
) -> None:
    r = await client.post(
        "/api/dashboards/db",
        json={"dashboard": dashboard, "folderUid": folder_uid, "overwrite": True},
    )
    r.raise_for_status()


async def _restrict_folder_to_admins(
    client: httpx.AsyncClient, *, folder_uid: str
) -> None:
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

    async with httpx.AsyncClient(
        base_url=base_url.rstrip("/"), auth=(admin_user, admin_password), timeout=10
    ) as client:
        await _wait_grafana(client)

        ds_uid = await _ensure_prometheus_datasource(client, prometheus_url)
        user_folder_uid = await _ensure_folder(
            client, uid="tracegate", title="Tracegate"
        )
        admin_folder_uid = await _ensure_folder(
            client, uid="tracegate-admin", title="Tracegate Admin"
        )

        await _upsert_dashboard(
            client, _dashboard_user(ds_uid), folder_uid=user_folder_uid
        )
        await _upsert_dashboard(
            client, _dashboard_admin(ds_uid), folder_uid=admin_folder_uid
        )
        await _upsert_dashboard(
            client, _dashboard_admin_metadata(ds_uid), folder_uid=admin_folder_uid
        )
        await _upsert_dashboard(
            client, _dashboard_operator(ds_uid), folder_uid=admin_folder_uid
        )
        await _upsert_slo_alert_rule_group(
            client, ds_uid=ds_uid, folder_uid=admin_folder_uid
        )
        if slo_webhook_url and slo_webhook_token:
            webhook_url = _append_query_param(
                slo_webhook_url, "token", slo_webhook_token
            )
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
            raise RuntimeError(
                f"expected at least 9 SLO rules, got {report['slo_rule_count']}"
            )
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
