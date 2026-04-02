from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

 
class _MetricStub:
    def labels(self, *args, **kwargs):
        return self

    def inc(self, *args, **kwargs) -> None:
        return None

    def set(self, *args, **kwargs) -> None:
        return None

    def remove(self, *args, **kwargs) -> None:
        return None


_prom_stub = types.ModuleType("prometheus_client")
_prom_stub.Counter = lambda *args, **kwargs: _MetricStub()
_prom_stub.Gauge = lambda *args, **kwargs: _MetricStub()
_orig_prometheus_client = sys.modules.get("prometheus_client")
sys.modules["prometheus_client"] = _prom_stub
try:
    from tracegate.dispatcher import ops  # noqa: E402
    from tracegate.settings import Settings  # noqa: E402
finally:
    if _orig_prometheus_client is None:
        sys.modules.pop("prometheus_client", None)
    else:
        sys.modules["prometheus_client"] = _orig_prometheus_client


@pytest.mark.asyncio
async def test_process_alerts_waits_for_metrics_server_grace_period(monkeypatch) -> None:
    sent: list[str] = []
    started = datetime(2026, 4, 2, 12, 0, 0, tzinfo=timezone.utc)
    now_values = iter(
        [
            started,
            started + timedelta(seconds=120),
            started + timedelta(seconds=180),
            started + timedelta(seconds=181),
        ]
    )

    monkeypatch.setattr(ops, "_utcnow", lambda: next(now_values))

    async def _load_admin_chat_ids(settings: Settings) -> list[int]:
        return [1]

    async def _send_to_recipients(**kwargs) -> bool:
        sent.append(str(kwargs["text"]))
        return True

    monkeypatch.setattr(ops, "_load_admin_chat_ids", _load_admin_chat_ids)
    monkeypatch.setattr(ops, "_send_to_recipients", _send_to_recipients)

    settings = Settings(
        bot_token="test-token",
        dispatcher_ops_alerts_metrics_server_min_active_seconds=180,
    )
    state = ops._OpsState(initialized=True)
    active = {"metrics_server_missing_nodes": "metrics-server scrape gap: missing node metrics for p526963-kvmvps"}

    await ops._process_alerts(settings=settings, state=state, active_alerts=active, instant_events=[], http_client=SimpleNamespace())
    await ops._process_alerts(settings=settings, state=state, active_alerts=active, instant_events=[], http_client=SimpleNamespace())
    assert sent == []

    await ops._process_alerts(settings=settings, state=state, active_alerts=active, instant_events=[], http_client=SimpleNamespace())
    assert len(sent) == 1
    assert sent[0].startswith("❗ OPS Alert")

    await ops._process_alerts(settings=settings, state=state, active_alerts={}, instant_events=[], http_client=SimpleNamespace())
    assert len(sent) == 2
    assert sent[1].startswith("✅ OPS Resolved")


@pytest.mark.asyncio
async def test_process_alerts_does_not_send_resolved_for_unsent_alert(monkeypatch) -> None:
    sent: list[str] = []
    started = datetime(2026, 4, 2, 12, 0, 0, tzinfo=timezone.utc)
    now_values = iter([started, started + timedelta(seconds=60)])

    monkeypatch.setattr(ops, "_utcnow", lambda: next(now_values))

    async def _load_admin_chat_ids(settings: Settings) -> list[int]:
        return [1]

    async def _send_to_recipients(**kwargs) -> bool:
        sent.append(str(kwargs["text"]))
        return True

    monkeypatch.setattr(ops, "_load_admin_chat_ids", _load_admin_chat_ids)
    monkeypatch.setattr(ops, "_send_to_recipients", _send_to_recipients)

    settings = Settings(
        bot_token="test-token",
        dispatcher_ops_alerts_metrics_server_min_active_seconds=180,
    )
    state = ops._OpsState(initialized=True)
    active = {"metrics_server_missing_nodes": "metrics-server scrape gap: missing node metrics for p526963-kvmvps"}

    await ops._process_alerts(settings=settings, state=state, active_alerts=active, instant_events=[], http_client=SimpleNamespace())
    await ops._process_alerts(settings=settings, state=state, active_alerts={}, instant_events=[], http_client=SimpleNamespace())

    assert sent == []


def test_collect_node_down_alerts_returns_only_ready_nodes() -> None:
    settings = Settings(dispatcher_ops_alerts_node_down_enabled=True)
    state = ops._OpsState()
    active: dict[str, str] = {}
    nodes_payload = {
        "items": [
            {
                "metadata": {"name": "ready-node"},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            },
            {
                "metadata": {"name": "flapping-node"},
                "status": {
                    "conditions": [
                        {
                            "type": "Ready",
                            "status": "Unknown",
                            "reason": "NodeStatusUnknown",
                            "message": "Kubelet stopped posting node status.",
                        }
                    ]
                },
            },
        ]
    }

    ready_nodes = ops._collect_node_down_alerts(
        settings=settings,
        state=state,
        nodes_payload=nodes_payload,
        active=active,
    )

    assert ready_nodes == {"ready-node"}
    assert active == {
        "node_not_ready:flapping-node": (
            "Node not Ready: flapping-node (NodeStatusUnknown - Kubelet stopped posting node status.)"
        )
    }
