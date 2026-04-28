from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


_GRAFANA_ROUTER_PATH = Path(__file__).resolve().parents[1] / "src" / "tracegate" / "api" / "routers" / "grafana.py"
_SPEC = spec_from_file_location("tracegate_api_router_grafana_for_tests", _GRAFANA_ROUTER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
_format_grafana_alert_webhook_message = _MODULE._format_grafana_alert_webhook_message


def _sample_payload(*, status: str) -> dict:
    return {
        "status": status,
        "commonLabels": {
            "alertname": "AgentAvailabilityLow",
        },
        "commonAnnotations": {
            "summary": "At least one agent scrape availability ratio is below 95% (5m)",
        },
        "alerts": [
            {
                "labels": {
                    "component": "agent",
                    "slo_type": "availability",
                    "severity": "critical",
                    "alertname": "AgentAvailabilityLow",
                },
                "annotations": {
                    "summary": "At least one agent scrape availability ratio is below 95% (5m)",
                },
            }
        ],
    }


def test_grafana_webhook_message_is_readable_for_firing_alerts() -> None:
    text, alert_count, status_raw = _format_grafana_alert_webhook_message(_sample_payload(status="firing"))

    assert status_raw == "firing"
    assert alert_count == 1
    assert text.startswith("🚨 Grafana Alert")
    assert "Status: firing" in text
    assert "Alerts: 1" in text
    assert "• agent / availability (critical)" in text
    assert "[GRAFANA][ALERT]" not in text
    assert "alerts=1 status=firing" not in text


def test_grafana_webhook_message_is_readable_for_resolved_alerts() -> None:
    text, alert_count, status_raw = _format_grafana_alert_webhook_message(_sample_payload(status="resolved"))

    assert status_raw == "resolved"
    assert alert_count == 1
    assert text.startswith("✅ Grafana Resolved")
    assert "Status: resolved" in text
