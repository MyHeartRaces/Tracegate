from tracegate.cli.grafana_bootstrap import _dashboard_admin, _dashboard_admin_metadata, _dashboard_user


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
    for panel_id in [2, 3, 4, 11, 12, 13, 14]:
        panel = _panel_by_id(dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "connection_label" in expr
        assert "sum by (connection_marker)" not in expr


def test_admin_connection_panels_use_human_readable_labels() -> None:
    dashboard = _dashboard_admin("prom")
    for panel_id in [1, 2, 11, 12, 13, 14]:
        panel = _panel_by_id(dashboard, panel_id)
        expr = panel["targets"][0]["expr"]
        assert "connection_label" in expr
        assert "sum by (user_handle, connection_marker)" not in expr


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

    wg_panel = _panel_by_id(dashboard, 2)
    wg_expr = wg_panel["targets"][0]["expr"]
    assert "peer_pid" in wg_expr
    assert "connection_pid" in wg_expr
