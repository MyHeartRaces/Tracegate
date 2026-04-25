from tracegate.cli.grafana_bootstrap import (
    _dashboard_admin,
    _dashboard_admin_metadata,
    _dashboard_operator,
    _dashboard_user,
    _slo_alert_rules,
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
    assert "label_replace(tracegate_connection_active" in panel["targets"][0]["expr"]
    assert 'max by (connection_pid, tg_id, connection_label, protocol, mode, variant)' in panel["targets"][0]["expr"]

    organize = next((tr for tr in panel.get("transformations", []) if tr.get("id") == "organize"), None)
    assert organize is not None
    options = organize["options"]
    assert options["excludeByName"]["connection_pid"] is True
    assert options["renameByName"]["connection_label"] == "connection"
    assert options["indexByName"]["tg_id"] == 0


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


def test_hysteria_panels_use_shared_inbound_rate_metrics() -> None:
    user_dashboard = _dashboard_user("prom")
    for panel_id in [13, 14]:
        panel = _panel_by_id(user_dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "tracegate_hysteria_inbound_" in expr
        assert "sum by (instance)" in expr
        assert panel["targets"][0]["legendFormat"] == "{{instance}}"

    admin_dashboard = _dashboard_admin("prom")
    for panel_id in [13, 14]:
        panel = _panel_by_id(admin_dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "tracegate_hysteria_inbound_" in expr
        assert "sum by (instance)" in expr
        assert panel["targets"][0]["legendFormat"] == "{{instance}}"


def test_user_panels_scope_queries_by_logged_in_user_pid() -> None:
    dashboard = _dashboard_user("prom")
    for panel_id in [1, 11, 12]:
        panel = _panel_by_id(dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert 'user_pid="${__user.login}"' in expr


def test_host_memory_used_panels_ignore_kind_label_in_ratio() -> None:
    user_dashboard = _dashboard_user("prom")
    user_panel = _panel_by_id(user_dashboard, 10)
    assert "/ ignoring(kind) tracegate_host_memory_bytes{kind=\"total\"}" in user_panel["targets"][0]["expr"]

    admin_dashboard = _dashboard_admin("prom")
    admin_panel = _panel_by_id(admin_dashboard, 8)
    assert "/ ignoring(kind) tracegate_host_memory_bytes{kind=\"total\"}" in admin_panel["targets"][0]["expr"]


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
    assert "label_replace(" in expr

    mtproto_panel = _panel_by_id(dashboard, 2)
    mtproto_expr = mtproto_panel["targets"][0]["expr"]
    assert mtproto_panel["type"] == "table"
    assert mtproto_panel["targets"][0]["format"] == "table"
    assert "tracegate_mtproto_access_active" in mtproto_expr
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
    assert "time() - tracegate_mtproto_access_updated_at_seconds" in mtproto_age["targets"][0]["expr"]
    assert mtproto_age["fieldConfig"]["defaults"]["unit"] == "d"

    mtproto_recent = _panel_by_id(dashboard, 9)
    assert "tracegate_mtproto_access_updated_at_seconds" in mtproto_recent["targets"][0]["expr"]
    assert "< bool 86400" in mtproto_recent["targets"][0]["expr"]

    mtproto_oldest = _panel_by_id(dashboard, 10)
    assert "max((time() - tracegate_mtproto_access_updated_at_seconds) / 86400)" == mtproto_oldest["targets"][0]["expr"]
    assert mtproto_oldest["fieldConfig"]["defaults"]["unit"] == "d"


def test_operator_dashboard_includes_slo_and_ops_panels() -> None:
    dashboard = _dashboard_operator("prom")
    assert dashboard["uid"] == "tracegate-admin-ops"
    assert dashboard["title"] == "Tracegate (Operator)"

    slo_up = _panel_by_id(dashboard, 1)
    assert "tracegate_slo_component_up_ratio_5m" in slo_up["targets"][0]["expr"]

    checks = _panel_by_id(dashboard, 6)
    assert "tracegate_dispatcher_ops_checks_total" in checks["targets"][0]["expr"]

    active_alerts = _panel_by_id(dashboard, 8)
    assert "tracegate_dispatcher_ops_active_alerts" in active_alerts["targets"][0]["expr"]

    outbox = _panel_by_id(dashboard, 9)
    assert "tracegate_ops_outbox_deliveries" in outbox["targets"][0]["expr"]

    purge_runs = _panel_by_id(dashboard, 12)
    assert "tracegate_dispatcher_outbox_purge_runs_total" in purge_runs["targets"][0]["expr"]

    purged_events = _panel_by_id(dashboard, 13)
    assert "tracegate_dispatcher_outbox_purged_events_total" in purged_events["targets"][0]["expr"]

    runtime_features = _panel_by_id(dashboard, 14)
    assert "tracegate_runtime_feature_enabled" in runtime_features["targets"][0]["expr"]

    runtime_contract = _panel_by_id(dashboard, 15)
    assert "tracegate_runtime_contract_present" in runtime_contract["targets"][0]["expr"]
    assert "tracegate_obfuscation_runtime_state_present" in runtime_contract["targets"][1]["expr"]

    runtime_backend = _panel_by_id(dashboard, 16)
    assert "tracegate_runtime_profile_info" in runtime_backend["targets"][0]["expr"]
    assert "tracegate_obfuscation_backend_info" in runtime_backend["targets"][1]["expr"]
    assert 'tracegate_fronting_owner_info{protocol="tcp"}' in runtime_backend["targets"][2]["expr"]
    assert 'tracegate_fronting_owner_info{protocol="udp"}' in runtime_backend["targets"][3]["expr"]

    mtproto_issuer = _panel_by_id(dashboard, 17)
    assert "count by (issued_by) (tracegate_mtproto_access_active)" in mtproto_issuer["targets"][0]["expr"]


def test_slo_alert_rules_cover_api_bot_and_agent() -> None:
    rules = _slo_alert_rules("prom", folder_uid="tracegate-admin")
    assert len(rules) == 9

    by_uid = {rule["uid"]: rule for rule in rules}
    assert set(by_uid) == {
        "tg-slo-api-availability-low",
        "tg-slo-bot-availability-low",
        "tg-slo-agent-availability-low",
        "tg-slo-api-http-success-low",
        "tg-slo-agent-http-success-low",
        "tg-slo-api-http-latency-high",
        "tg-slo-agent-http-latency-high",
        "tg-slo-bot-update-success-low",
        "tg-slo-bot-update-latency-high",
    }

    api_avail = by_uid["tg-slo-api-availability-low"]
    assert api_avail["folderUID"] == "tracegate-admin"
    assert api_avail["ruleGroup"] == "tracegate-slo"
    assert api_avail["condition"] == "B"
    assert api_avail["labels"]["component"] == "api"
    assert api_avail["labels"]["slo_type"] == "availability"
    assert api_avail["noDataState"] == "Alerting"
    assert 'tracegate_slo_component_up_ratio_5m{job="tracegate-api"}' in api_avail["data"][0]["model"]["expr"]
    assert api_avail["data"][1]["model"]["conditions"][0]["evaluator"]["type"] == "lt"
    assert api_avail["data"][1]["model"]["conditions"][0]["evaluator"]["params"] == [0.99]

    agent_avail = by_uid["tg-slo-agent-availability-low"]
    assert agent_avail["for"] == "5m"
    assert agent_avail["data"][1]["model"]["conditions"][0]["evaluator"]["params"] == [0.95]

    agent_latency = by_uid["tg-slo-agent-http-latency-high"]
    assert 'tracegate_slo_http_request_latency_p95_seconds_5m{component="agent"}' in agent_latency["data"][0]["model"]["expr"]
    assert agent_latency["data"][1]["model"]["conditions"][0]["evaluator"]["type"] == "gt"
    assert agent_latency["data"][1]["model"]["conditions"][0]["evaluator"]["params"] == [1.0]

    bot_success = by_uid["tg-slo-bot-update-success-low"]
    assert bot_success["noDataState"] == "OK"
    assert bot_success["labels"]["component"] == "bot"
    assert bot_success["labels"]["severity"] == "warning"
    assert bot_success["data"][0]["model"]["expr"] == "tracegate_slo_bot_update_success_ratio_5m"
