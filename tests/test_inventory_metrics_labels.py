import sys
import types


fake_prometheus = types.ModuleType("prometheus_client")
fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
fake_prometheus_core = types.ModuleType("prometheus_client.core")
fake_prometheus_core.GaugeMetricFamily = object
sys.modules.setdefault("prometheus_client", fake_prometheus)
sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)

from tracegate.api.inventory_metrics import _connection_label


def test_connection_label_uses_human_format() -> None:
    label = _connection_label(
        protocol="vless_reality_vision",
        mode="chain",
        variant="B2",
        user_handle="@alice",
        tg_id="123456789",
        device_name="iPhone",
    )
    assert label == "B2(VLESS REALITY/CHAIN) - @alice(123456789) - iPhone"
