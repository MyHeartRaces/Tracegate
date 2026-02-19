from tracegate.cli.grafana_bootstrap import _dashboard_admin


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
