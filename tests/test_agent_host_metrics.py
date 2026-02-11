import sys
import types

fake_prometheus = types.ModuleType("prometheus_client")
fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
fake_prometheus_core = types.ModuleType("prometheus_client.core")
fake_prometheus_core.GaugeMetricFamily = object
sys.modules.setdefault("prometheus_client", fake_prometheus)
sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)


def _metrics_helpers():
    from tracegate.agent.metrics import _parse_meminfo, _parse_netdev

    return _parse_meminfo, _parse_netdev


def test_parse_meminfo() -> None:
    _parse_meminfo, _ = _metrics_helpers()
    parsed = _parse_meminfo(
        """
MemTotal:       16386048 kB
MemFree:         1024000 kB
MemAvailable:    8192000 kB
""".strip()
    )

    assert parsed == (16386048 * 1024, 8192000 * 1024)


def test_parse_netdev() -> None:
    _, _parse_netdev = _metrics_helpers()
    parsed = _parse_netdev(
        """
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0
  eth0: 12345 11 0 0 0 0 0 0 67890 22 0 0 0 0 0 0
""".strip()
    )

    assert parsed == [("lo", 100, 200), ("eth0", 12345, 67890)]
