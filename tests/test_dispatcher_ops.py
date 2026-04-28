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
async def test_process_alerts_sends_immediately_and_resolves(monkeypatch) -> None:
    sent: list[str] = []
    started = datetime(2026, 4, 2, 12, 0, 0, tzinfo=timezone.utc)
    now_values = iter([started, started + timedelta(seconds=30)])

    monkeypatch.setattr(ops, "_utcnow", lambda: next(now_values))

    async def _load_admin_chat_ids(settings: Settings) -> list[int]:
        return [1]

    async def _send_to_recipients(**kwargs) -> bool:
        sent.append(str(kwargs["text"]))
        return True

    monkeypatch.setattr(ops, "_load_admin_chat_ids", _load_admin_chat_ids)
    monkeypatch.setattr(ops, "_send_to_recipients", _send_to_recipients)

    settings = Settings(bot_token="test-token")
    state = ops._OpsState(initialized=True)
    active = {"disk_high:transit-1": "Disk usage high on transit-1: 92.0% (threshold=80.0%)"}

    await ops._process_alerts(settings=settings, state=state, active_alerts=active, instant_events=[], http_client=SimpleNamespace())
    assert len(sent) == 1
    assert sent[0].startswith("❗ OPS Alert")

    await ops._process_alerts(settings=settings, state=state, active_alerts={}, instant_events=[], http_client=SimpleNamespace())
    assert len(sent) == 2
    assert sent[1].startswith("✅ OPS Resolved")


@pytest.mark.asyncio
async def test_collect_alerts_merges_outbox_and_disk_checks(monkeypatch) -> None:
    async def _outbox_snapshot() -> tuple[dict[str, int], int]:
        return {"DEAD": 2}, 0

    async def _disk_alerts(*, settings: Settings, state: ops._OpsState, http_client) -> dict[str, str]:
        assert settings.dispatcher_ops_alerts_disk_enabled is True
        return {"disk_high:transit-1": "Disk usage high on transit-1: 92.0% (threshold=80.0%)"}

    monkeypatch.setattr(ops, "_outbox_delivery_health_snapshot", _outbox_snapshot)
    monkeypatch.setattr(ops, "_collect_disk_alerts", _disk_alerts)

    active, instant_events = await ops._collect_alerts(
        settings=Settings(
            dispatcher_ops_alerts_outbox_dead_enabled=True,
            dispatcher_ops_alerts_outbox_dead_threshold=0,
            dispatcher_ops_alerts_disk_enabled=True,
        ),
        state=ops._OpsState(),
        http_client=SimpleNamespace(),
    )

    assert instant_events == []
    assert active == {
        "outbox_dead": "Outbox DEAD deliveries > threshold: 2 (threshold=0)",
        "disk_high:transit-1": "Disk usage high on transit-1: 92.0% (threshold=80.0%)",
    }
