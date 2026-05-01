import pytest

from tracegate.cli.grafana_bootstrap import (
    _dashboard_admin,
    _dashboard_admin_metadata,
    _dashboard_operator,
    _dashboard_user,
    _same_object_matchers,
    _slo_alert_rules,
    _upsert_notification_policies_for_slo,
)


def _panel_by_id(dashboard: dict, panel_id: int) -> dict:
    for panel in dashboard.get("panels", []):
        if int(panel.get("id") or 0) == panel_id:
            return panel
    raise AssertionError(f"panel id={panel_id} not found")


def test_admin_active_connections_panel_is_compact_table() -> None:
    dashboard = _dashboard_admin("prom")
    panel = _panel_by_id(dashboard, 9)

    assert panel["type"] == "table"
    assert panel["title"] == "Active connections (all protocols)"
    assert panel["targets"][0]["instant"] is True
    assert panel["targets"][0]["format"] == "table"
    assert "tracegate_connection_active" in panel["targets"][0]["expr"]
    assert "telegram_id" in panel["targets"][0]["expr"]
    assert "connection_id" in panel["targets"][0]["expr"]

    organize = next(
        (tr for tr in panel.get("transformations", []) if tr.get("id") == "organize"),
        None,
    )
    assert organize is not None
    options = organize["options"]
    assert options["excludeByName"]["connection_pid"] is True
    assert options["renameByName"]["connection_label"] == "connection"
    assert options["indexByName"]["telegram_id"] == 0


def test_user_connection_panels_use_human_readable_labels() -> None:
    dashboard = _dashboard_user("prom")
    for panel_id in [11, 12]:
        panel = _panel_by_id(dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "connection_label" in expr
        assert "sum by (connection_marker)" not in expr


def test_admin_connection_panels_use_human_readable_labels() -> None:
    dashboard = _dashboard_admin("prom")
    for panel_id in [11, 12]:
        panel = _panel_by_id(dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "connection_label" in expr
        assert "sum by (user_handle, connection_marker)" not in expr


def test_hysteria_panels_use_per_connection_rate_metrics() -> None:
    user_dashboard = _dashboard_user("prom")
    for panel_id in [13, 14]:
        panel = _panel_by_id(user_dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "tracegate_hysteria_connection_" in expr
        assert 'user_pid="${__user.login}"' in expr
        assert "0 * max by (connection_label, protocol)" in expr
        assert panel["targets"][0]["legendFormat"] == "{{connection_label}}"

    admin_dashboard = _dashboard_admin("prom")
    for panel_id in [13, 14]:
        panel = _panel_by_id(admin_dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "tracegate_hysteria_connection_" in expr
        assert "connection_label" in expr
        assert "0 * max by (connection_label, protocol)" in expr
        assert panel["targets"][0]["legendFormat"] == "{{connection_label}}"


def test_shadowsocks_panels_use_per_connection_rate_metrics() -> None:
    user_dashboard = _dashboard_user("prom")
    for panel_id in [18, 19]:
        panel = _panel_by_id(user_dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "tracegate_xray_connection_" in expr
        assert 'protocol=~"shadowsocks2022_shadowtls"' in expr
        assert 'user_pid="${__user.login}"' in expr
        assert "0 * max by (connection_label, protocol)" in expr
        assert panel["targets"][0]["legendFormat"] == "{{connection_label}}"

    admin_dashboard = _dashboard_admin("prom")
    for panel_id in [29, 30]:
        panel = _panel_by_id(admin_dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "tracegate_xray_connection_" in expr
        assert 'protocol=~"shadowsocks2022_shadowtls"' in expr
        assert "connection_label" in expr
        assert "0 * max by (connection_label, protocol)" in expr
        assert panel["targets"][0]["legendFormat"] == "{{connection_label}}"


def test_user_panels_scope_queries_by_logged_in_user_pid() -> None:
    dashboard = _dashboard_user("prom")
    for panel_id in [1, 11, 12, 18, 19]:
        panel = _panel_by_id(dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert 'user_pid="${__user.login}"' in expr


def test_host_memory_used_panels_ignore_kind_label_in_ratio() -> None:
    user_dashboard = _dashboard_user("prom")
    user_panel = _panel_by_id(user_dashboard, 10)
    assert (
        '/ ignoring(kind) tracegate_host_memory_bytes{kind="total"}'
        in user_panel["targets"][0]["expr"]
    )

    admin_dashboard = _dashboard_admin("prom")
    admin_panel = _panel_by_id(admin_dashboard, 8)
    assert (
        '/ ignoring(kind) tracegate_host_memory_bytes{kind="total"}'
        in admin_panel["targets"][0]["expr"]
    )


def test_admin_metadata_dashboard_exposes_ids() -> None:
    dashboard = _dashboard_admin_metadata("prom")
    assert dashboard["uid"] == "tracegate-admin-metadata"

    conn_panel = _panel_by_id(dashboard, 1)
    expr = conn_panel["targets"][0]["expr"]
    assert conn_panel["type"] == "table"
    assert conn_panel["targets"][0]["format"] == "table"
    assert "connection_pid" in expr
    assert "user_pid" in expr
    assert "connection_marker" in expr
    assert "connection_id" in expr
    assert "telegram_id" in expr

    mtproto_panel = _panel_by_id(dashboard, 2)
    mtproto_expr = mtproto_panel["targets"][0]["expr"]
    assert mtproto_panel["type"] == "table"
    assert mtproto_panel["targets"][0]["format"] == "table"
    assert "tracegate_mtproto_access_active" in mtproto_expr
    assert "telegram_id" in mtproto_expr
    assert "user_handle" in mtproto_expr
    assert "issued_by" in mtproto_expr


def test_admin_metadata_dashboard_has_total_traffic_panels() -> None:
    dashboard = _dashboard_admin_metadata("prom")

    rate_panel = _panel_by_id(dashboard, 4)
    assert rate_panel["type"] == "timeseries"
    rx_rate_expr = rate_panel["targets"][0]["expr"]
    tx_rate_expr = rate_panel["targets"][1]["expr"]
    for expr in (rx_rate_expr, tx_rate_expr):
        assert "tracegate_xray_connection_" in expr
        assert "tracegate_hysteria_" in expr
        assert "or vector(0)" in expr
    assert rate_panel["fieldConfig"]["defaults"]["unit"] == "Bps"

    rx_panel = _panel_by_id(dashboard, 5)
    assert rx_panel["type"] == "stat"
    assert "increase(" in rx_panel["targets"][0]["expr"]
    assert rx_panel["fieldConfig"]["defaults"]["unit"] == "bytes"

    tx_panel = _panel_by_id(dashboard, 6)
    assert tx_panel["type"] == "stat"
    assert "increase(" in tx_panel["targets"][0]["expr"]
    assert tx_panel["fieldConfig"]["defaults"]["unit"] == "bytes"

    total_panel = _panel_by_id(dashboard, 7)
    assert total_panel["type"] == "stat"
    total_expr = total_panel["targets"][0]["expr"]
    assert "tracegate_xray_connection_rx_bytes" in total_expr
    assert "tracegate_xray_connection_tx_bytes" in total_expr
    assert "tracegate_hysteria_connection_rx_bytes" in total_expr
    assert "tracegate_hysteria_inbound_rx_bytes" in total_expr
    assert "tracegate_hysteria_connection_tx_bytes" in total_expr
    assert "tracegate_hysteria_inbound_tx_bytes" in total_expr
    assert total_panel["fieldConfig"]["defaults"]["unit"] == "bytes"

    mtproto_age = _panel_by_id(dashboard, 8)
    assert (
        "time() - tracegate_mtproto_access_updated_at_seconds"
        in mtproto_age["targets"][0]["expr"]
    )
    assert mtproto_age["fieldConfig"]["defaults"]["unit"] == "d"

    mtproto_recent = _panel_by_id(dashboard, 9)
    assert (
        "tracegate_mtproto_access_updated_at_seconds"
        in mtproto_recent["targets"][0]["expr"]
    )
    assert "< bool 86400" in mtproto_recent["targets"][0]["expr"]

    mtproto_oldest = _panel_by_id(dashboard, 10)
    assert (
        "max((time() - tracegate_mtproto_access_updated_at_seconds) / 86400)"
        == mtproto_oldest["targets"][0]["expr"]
    )
    assert mtproto_oldest["fieldConfig"]["defaults"]["unit"] == "d"


def test_operator_dashboard_includes_slo_and_ops_panels() -> None:
    dashboard = _dashboard_operator("prom")
    assert dashboard["uid"] == "tracegate-admin-ops"
    assert dashboard["title"] == "Tracegate (Operator)"

    slo_up = _panel_by_id(dashboard, 1)
    assert "avg_over_time(up" in slo_up["targets"][0]["expr"]
    assert "tracegate-agent" in slo_up["targets"][0]["expr"]

    http_success = _panel_by_id(dashboard, 2)
    assert "tracegate_http_requests_total" in http_success["targets"][0]["expr"]
    assert 'status!~"5.."' in http_success["targets"][0]["expr"]

    bot_success = _panel_by_id(dashboard, 3)
    assert "tracegate_bot_updates_total" in bot_success["targets"][0]["expr"]

    checks = _panel_by_id(dashboard, 6)
    assert "tracegate_dispatcher_ops_checks_total" in checks["targets"][0]["expr"]

    active_alerts = _panel_by_id(dashboard, 8)
    assert (
        "tracegate_dispatcher_ops_active_alerts" in active_alerts["targets"][0]["expr"]
    )

    outbox = _panel_by_id(dashboard, 9)
    assert "tracegate_ops_outbox_deliveries" in outbox["targets"][0]["expr"]

    disk_used = _panel_by_id(dashboard, 11)
    assert "node_filesystem_avail_bytes" in disk_used["targets"][0]["expr"]
    assert 'job="tracegate-node-exporter"' in disk_used["targets"][0]["expr"]

    purge_runs = _panel_by_id(dashboard, 12)
    assert (
        "tracegate_dispatcher_outbox_purge_runs_total"
        in purge_runs["targets"][0]["expr"]
    )

    purged_events = _panel_by_id(dashboard, 13)
    assert (
        "tracegate_dispatcher_outbox_purged_events_total"
        in purged_events["targets"][0]["expr"]
    )

    runtime_features = _panel_by_id(dashboard, 14)
    assert "tracegate_runtime_feature_enabled" in runtime_features["targets"][0]["expr"]

    runtime_contract = _panel_by_id(dashboard, 15)
    assert (
        "tracegate_runtime_contract_present" in runtime_contract["targets"][0]["expr"]
    )
    assert (
        "tracegate_obfuscation_runtime_state_present"
        in runtime_contract["targets"][1]["expr"]
    )

    runtime_backend = _panel_by_id(dashboard, 16)
    assert "tracegate_runtime_profile_info" in runtime_backend["targets"][0]["expr"]
    assert "tracegate_obfuscation_backend_info" in runtime_backend["targets"][1]["expr"]
    assert (
        'tracegate_fronting_owner_info{protocol="tcp"}'
        in runtime_backend["targets"][2]["expr"]
    )
    assert (
        'tracegate_fronting_owner_info{protocol="udp"}'
        in runtime_backend["targets"][3]["expr"]
    )

    mtproto_issuer = _panel_by_id(dashboard, 17)
    assert (
        "count by (issued_by) (tracegate_mtproto_access_active)"
        in mtproto_issuer["targets"][0]["expr"]
    )

    runtime_endpoints = _panel_by_id(dashboard, 18)
    assert "tracegate_agent_info" in runtime_endpoints["targets"][0]["expr"]

    infra_nodes = _panel_by_id(dashboard, 19)
    assert 'job="tracegate-node-exporter"' in infra_nodes["targets"][0]["expr"]

    infra_cpu = _panel_by_id(dashboard, 20)
    assert "node_cpu_seconds_total" in infra_cpu["targets"][0]["expr"]

    pod_network = _panel_by_id(dashboard, 29)
    assert "container_network_receive_bytes_total" in pod_network["targets"][0]["expr"]


def test_slo_alert_rules_cover_api_bot_and_agent() -> None:
    rules = _slo_alert_rules("prom", folder_uid="tracegate-admin")
    assert len(rules) >= 27

    by_uid = {rule["uid"]: rule for rule in rules}
    assert {
        "tg-slo-api-availability-low",
        "tg-slo-bot-availability-low",
        "tg-slo-agent-availability-low",
        "tg-slo-api-http-success-low",
        "tg-slo-agent-http-success-low",
        "tg-slo-api-http-latency-high",
        "tg-slo-agent-http-latency-high",
        "tg-slo-bot-update-success-low",
        "tg-slo-bot-update-latency-high",
    } <= set(by_uid)

    api_avail = by_uid["tg-slo-api-availability-low"]
    assert api_avail["folderUID"] == "tracegate-admin"
    assert api_avail["ruleGroup"] == "tracegate-slo"
    assert api_avail["condition"] == "B"
    assert api_avail["labels"]["component"] == "api"
    assert api_avail["labels"]["slo_type"] == "availability"
    assert api_avail["noDataState"] == "Alerting"
    assert (
        'avg_over_time(up{namespace="tracegate",job="tracegate-api"}[5m])'
        in api_avail["data"][0]["model"]["expr"]
    )
    assert api_avail["data"][1]["model"]["conditions"][0]["evaluator"]["type"] == "lt"
    assert api_avail["data"][1]["model"]["conditions"][0]["evaluator"]["params"] == [
        0.99
    ]

    agent_avail = by_uid["tg-slo-agent-availability-low"]
    assert agent_avail["for"] == "5m"
    assert agent_avail["data"][1]["model"]["conditions"][0]["evaluator"]["params"] == [
        0.95
    ]

    bot_avail = by_uid["tg-slo-bot-availability-low"]
    assert bot_avail["labels"]["severity"] == "warning"
    assert bot_avail["noDataState"] == "OK"

    agent_latency = by_uid["tg-slo-agent-http-latency-high"]
    assert (
        "tracegate_http_request_duration_seconds_bucket"
        in agent_latency["data"][0]["model"]["expr"]
    )
    assert 'job="tracegate-agent"' in agent_latency["data"][0]["model"]["expr"]
    assert (
        agent_latency["data"][1]["model"]["conditions"][0]["evaluator"]["type"] == "gt"
    )
    assert agent_latency["data"][1]["model"]["conditions"][0]["evaluator"][
        "params"
    ] == [1.0]

    bot_success = by_uid["tg-slo-bot-update-success-low"]
    assert bot_success["noDataState"] == "OK"
    assert bot_success["labels"]["component"] == "bot"
    assert bot_success["labels"]["severity"] == "warning"
    assert "tracegate_bot_updates_total" in bot_success["data"][0]["model"]["expr"]
    assert "or vector(1)" in bot_success["data"][0]["model"]["expr"]


def test_ops_alert_rules_cover_nodes_pods_delivery_and_runtime_health() -> None:
    rules = _slo_alert_rules("prom", folder_uid="tracegate-admin")
    by_uid = {rule["uid"]: rule for rule in rules}

    expected = {
        "tg-ops-node-down",
        "tg-ops-node-count-low",
        "tg-ops-target-down",
        "tg-ops-pod-not-seen",
        "tg-ops-container-restarted",
        "tg-ops-node-rebooted",
        "tg-ops-root-ssd-used-high",
        "tg-ops-root-ssd-used-critical",
        "tg-ops-root-ssd-free-critical",
        "tg-ops-memory-used-high",
        "tg-ops-memory-used-critical",
        "tg-ops-cpu-used-high",
        "tg-ops-load-high",
        "tg-ops-network-errors",
        "tg-ops-outbox-stale-deliveries",
        "tg-ops-dispatcher-active-alerts",
        "tg-ops-xray-stats-scrape-failed",
        "tg-ops-hysteria-stats-scrape-failed",
    }
    assert expected <= set(by_uid)

    node_down = by_uid["tg-ops-node-down"]
    assert node_down["labels"]["component"] == "node"
    assert node_down["labels"]["slo_type"] == "node_availability"
    assert node_down["labels"]["severity"] == "critical"
    assert node_down["labels"]["kind"] == "slo"
    assert 'job="tracegate-node-exporter"' in node_down["data"][0]["model"]["expr"]
    assert node_down["noDataState"] == "Alerting"

    pod_down = by_uid["tg-ops-target-down"]
    assert (
        'job=~"tracegate-api|tracegate-bot|tracegate-agent|tracegate-dispatcher"'
        in pod_down["data"][0]["model"]["expr"]
    )
    assert pod_down["labels"]["slo_type"] == "pod_availability"

    ssd = by_uid["tg-ops-root-ssd-used-high"]
    assert "node_filesystem_avail_bytes" in ssd["data"][0]["model"]["expr"]
    assert ssd["data"][1]["model"]["conditions"][0]["evaluator"]["params"] == [80.0]

    free_critical = by_uid["tg-ops-root-ssd-free-critical"]
    assert free_critical["data"][1]["model"]["conditions"][0]["evaluator"][
        "params"
    ] == [2_147_483_648.0]
    assert "below 2 GiB" in free_critical["annotations"]["summary"]

    outbox = by_uid["tg-ops-outbox-stale-deliveries"]
    assert (
        "tracegate_ops_outbox_pending_older_than_5m_deliveries"
        in outbox["data"][0]["model"]["expr"]
    )
    assert outbox["labels"]["severity"] == "critical"

    restart = by_uid["tg-ops-container-restarted"]
    assert "container_start_time_seconds" in restart["data"][0]["model"]["expr"]


def test_notification_policy_matchers_are_compared_order_insensitively() -> None:
    left = [["kind", "=", "slo"], ["service", "=", "tracegate"]]
    right = [["service", "=", "tracegate"], ["kind", "=", "slo"]]

    assert _same_object_matchers(left, right)

    critical = [
        ["kind", "=", "slo"],
        ["service", "=", "tracegate"],
        ["severity", "=", "critical"],
    ]
    warning = [
        ["kind", "=", "slo"],
        ["service", "=", "tracegate"],
        ["severity", "=", "warning"],
    ]
    assert not _same_object_matchers(critical, warning)


class _FakeGrafanaPolicyClient:
    def __init__(self) -> None:
        self.put_payload: dict | None = None

    async def get(self, _path: str):
        return _FakeGrafanaResponse(
            {
                "receiver": "grafana-default-email",
                "group_by": ["grafana_folder", "alertname"],
                "routes": [],
            }
        )

    async def put(self, _path: str, *, json: dict, headers: dict):
        del headers
        self.put_payload = json
        return _FakeGrafanaResponse({})


class _FakeGrafanaResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        return None


@pytest.mark.asyncio
async def test_notification_policy_root_uses_webhook_receiver() -> None:
    client = _FakeGrafanaPolicyClient()

    await _upsert_notification_policies_for_slo(
        client, receiver_name="tracegate-slo-ops-webhook"
    )

    assert client.put_payload is not None
    assert client.put_payload["receiver"] == "tracegate-slo-ops-webhook"
    assert client.put_payload["routes"][0]["object_matchers"] == [
        ["service", "=", "tracegate"],
        ["kind", "=", "slo"],
        ["severity", "=", "critical"],
    ]
