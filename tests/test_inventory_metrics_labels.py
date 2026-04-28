from datetime import datetime, timezone
import sys
import types


class _FakeGaugeMetricFamily:
    def __init__(self, name: str, documentation: str, labels=None):  # noqa: ANN001
        self.name = name
        self.documentation = documentation
        self.labels = list(labels or [])
        self.samples: list[tuple[list[str], float]] = []

    def add_metric(self, label_values, value):  # noqa: ANN001, ANN201
        self.samples.append((list(label_values or []), float(value)))


def _inventory_metrics_module():
    fake_prometheus = types.ModuleType("prometheus_client")
    fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
    fake_prometheus_core = types.ModuleType("prometheus_client.core")
    fake_prometheus_core.GaugeMetricFamily = _FakeGaugeMetricFamily
    sys.modules.setdefault("prometheus_client", fake_prometheus)
    sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)

    from tracegate.api import inventory_metrics as m

    return m


def test_connection_label_uses_human_format() -> None:
    label = _inventory_metrics_module()._connection_label(  # noqa: SLF001
        protocol="vless_reality_vision",
        mode="chain",
        variant="V2",
        user_handle="@alice",
        tg_id="123456789",
        device_name="iPhone",
    )
    assert label == "V2(VLESS REALITY/CHAIN) - @alice(123456789) - iPhone"


def test_inventory_collector_exports_mtproto_access_metric() -> None:
    m = _inventory_metrics_module()
    store = m.InventoryStore()
    store.set(
        m.InventorySnapshot(
            refreshed_at=datetime(2026, 4, 18, 12, 0, 0, tzinfo=timezone.utc),
            users=[
                m.UserRow(user_pid="user-1", user_handle="@alice", role="user"),
            ],
            connections=[],
            mtproto_access=[
                m.MTProtoAccessRow(
                    user_pid="user-1",
                    user_handle="@alice",
                    label="@alice",
                    issued_by="bot",
                    created_at_seconds=1_713_441_600.0,
                    updated_at_seconds=1_713_528_000.0,
                    last_sync_at_seconds=1_713_531_600.0,
                )
            ],
        )
    )

    collector = m.InventoryCollector(store)
    out = list(collector.collect())
    mtproto_metric = next(row for row in out if getattr(row, "name", "") == "tracegate_mtproto_access_active")
    mtproto_created = next(row for row in out if getattr(row, "name", "") == "tracegate_mtproto_access_created_at_seconds")
    mtproto_updated = next(row for row in out if getattr(row, "name", "") == "tracegate_mtproto_access_updated_at_seconds")
    mtproto_synced = next(row for row in out if getattr(row, "name", "") == "tracegate_mtproto_access_last_sync_at_seconds")

    assert mtproto_metric.samples == [
        (["user-1", "@alice", "@alice", "bot"], 1.0),
    ]
    assert mtproto_created.samples == [
        (["user-1", "@alice", "@alice", "bot"], 1_713_441_600.0),
    ]
    assert mtproto_updated.samples == [
        (["user-1", "@alice", "@alice", "bot"], 1_713_528_000.0),
    ]
    assert mtproto_synced.samples == [
        (["user-1", "@alice", "@alice", "bot"], 1_713_531_600.0),
    ]
