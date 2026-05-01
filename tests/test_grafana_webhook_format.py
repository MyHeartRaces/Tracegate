from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest
from starlette.requests import Request

from tracegate.settings import Settings


_GRAFANA_ROUTER_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tracegate"
    / "api"
    / "routers"
    / "grafana.py"
)
_SPEC = spec_from_file_location(
    "tracegate_api_router_grafana_for_tests", _GRAFANA_ROUTER_PATH
)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
_format_grafana_alert_webhook_message = _MODULE._format_grafana_alert_webhook_message
_grafana_alert_webhook_has_critical = _MODULE._grafana_alert_webhook_has_critical


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
                    "node": "tracegate-transit",
                    "instance": "198.51.100.20:8070",
                    "pod": "tracegate-gateway-transit-abc",
                },
                "annotations": {
                    "summary": "At least one agent scrape availability ratio is below 95% (5m)",
                },
            }
        ],
    }


def test_grafana_webhook_message_is_readable_for_firing_alerts() -> None:
    text, alert_count, status_raw = _format_grafana_alert_webhook_message(
        _sample_payload(status="firing")
    )

    assert status_raw == "firing"
    assert alert_count == 1
    assert text.startswith("🚨 Grafana Alert")
    assert "Status: firing" in text
    assert "Alerts: 1" in text
    assert "• agent / availability (critical)" in text
    assert (
        "Target: endpoint / tracegate-transit / 198.51.100.20:8070 / tracegate-gateway-transit-abc"
        in text
    )
    assert "[GRAFANA][ALERT]" not in text
    assert "alerts=1 status=firing" not in text


def test_grafana_webhook_message_is_readable_for_resolved_alerts() -> None:
    text, alert_count, status_raw = _format_grafana_alert_webhook_message(
        _sample_payload(status="resolved")
    )

    assert status_raw == "resolved"
    assert alert_count == 1
    assert text.startswith("✅ Grafana Recovered")
    assert "Status: resolved" in text


def test_grafana_alert_webhook_detects_only_critical_payloads() -> None:
    assert _grafana_alert_webhook_has_critical(_sample_payload(status="firing")) is True

    warning = _sample_payload(status="firing")
    warning["alerts"][0]["labels"]["severity"] = "warning"
    warning["commonLabels"]["severity"] = "warning"
    assert _grafana_alert_webhook_has_critical(warning) is False

    common_only = {"commonLabels": {"severity": "critical"}, "alerts": []}
    assert _grafana_alert_webhook_has_critical(common_only) is True


def test_grafana_login_handles_get_and_head() -> None:
    methods = {
        method
        for route in _MODULE.router.routes
        if getattr(route, "path", "") == "/grafana/login"
        for method in getattr(route, "methods", set())
    }

    assert {"GET", "HEAD"} <= methods


def test_grafana_path_otp_handles_get_and_head() -> None:
    methods = {
        method
        for route in _MODULE.router.routes
        if getattr(route, "path", "") == "/grafana/otp/{code}/{scope}"
        for method in getattr(route, "methods", set())
    }

    assert {"GET", "HEAD"} <= methods


def test_grafana_public_base_url_prefers_grafana_domain() -> None:
    settings = Settings(
        public_base_url="https://tracegate.test",
        grafana_public_base_url="https://grafana.tracegate.test",
    )

    assert _MODULE._grafana_public_base_url(settings) == "https://grafana.tracegate.test"


def test_grafana_otp_login_url_keeps_code_in_path() -> None:
    url = _MODULE._grafana_otp_login_url(
        public_base_url="https://grafana.tracegate.test/",
        code="otp-code_123",
        scope=_MODULE.GrafanaSessionScope.ADMIN,
    )

    assert url == "https://grafana.tracegate.test/grafana/otp/otp-code_123/admin"
    assert "?" not in url


@pytest.mark.asyncio
async def test_grafana_login_without_code_returns_help_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _MODULE,
        "get_settings",
        lambda: Settings(
            grafana_enabled=True, grafana_otp_handoff_url="https://t.me/tracegate_bot"
        ),
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "server": ("tracegate.test", 443),
            "path": "/grafana/login",
            "headers": [],
            "query_string": b"",
        }
    )

    response = await _MODULE.grafana_login(request=request, code=None, session=object())

    assert response.status_code == 401
    assert "location" not in response.headers
    assert b"Grafana OTP required" in response.body
    assert b"https://t.me/tracegate_bot" in response.body
