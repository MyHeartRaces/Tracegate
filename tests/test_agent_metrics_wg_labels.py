import sys
import types

import pytest


class _FakeGaugeMetricFamily:
    def __init__(self, name: str, documentation: str, labels=None):  # noqa: ANN001
        self.name = name
        self.documentation = documentation
        self.labels = list(labels or [])
        self.samples: list[tuple[list[str], float]] = []

    def add_metric(self, label_values, value):  # noqa: ANN001, ANN201
        self.samples.append((list(label_values or []), float(value)))


def test_wg_metrics_export_peer_public_key_only(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # Keep this unit test independent from prometheus_client availability.
    fake_prometheus = types.ModuleType("prometheus_client")
    fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
    fake_prometheus_core = types.ModuleType("prometheus_client.core")
    fake_prometheus_core.GaugeMetricFamily = _FakeGaugeMetricFamily
    sys.modules.setdefault("prometheus_client", fake_prometheus)
    sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)

    from tracegate.agent import metrics as m
    from tracegate.settings import Settings

    # Avoid calling real `wg`.
    monkeypatch.setattr(
        m,
        "_wg_dump",
        lambda _iface: [
            ["wg0", "priv", "pub", "51820"],  # interface header row (ignored by collector)
            ["peer-pub-1", "", "", "10.70.0.2/32", "1700000000", "10", "20", "25"],
        ],
    )
    # Avoid calling real Xray/Hysteria APIs.
    monkeypatch.setattr(m, "_query_xray_user_traffic_bytes", lambda _settings: {})
    monkeypatch.setattr(m, "_fetch_hysteria_traffic_bytes", lambda _url, _secret: {})

    collector = m.AgentMetricsCollector(Settings(agent_role="VPS_T", agent_data_root=str(tmp_path)))
    out = list(collector.collect())

    rx = next(row for row in out if getattr(row, "name", "") == "tracegate_wg_peer_rx_bytes")
    tx = next(row for row in out if getattr(row, "name", "") == "tracegate_wg_peer_tx_bytes")
    hs = next(row for row in out if getattr(row, "name", "") == "tracegate_wg_peer_latest_handshake_seconds")

    assert rx.labels == ["peer_public_key"]
    assert tx.labels == ["peer_public_key"]
    assert hs.labels == ["peer_public_key"]

    assert rx.samples == [(["peer-pub-1"], 10.0)]
    assert tx.samples == [(["peer-pub-1"], 20.0)]
    assert hs.samples == [(["peer-pub-1"], 1700000000.0)]
