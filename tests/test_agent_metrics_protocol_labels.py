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


def test_agent_metrics_omit_legacy_wireguard_series(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    fake_prometheus = types.ModuleType("prometheus_client")
    fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
    fake_prometheus_core = types.ModuleType("prometheus_client.core")
    fake_prometheus_core.GaugeMetricFamily = _FakeGaugeMetricFamily
    sys.modules.setdefault("prometheus_client", fake_prometheus)
    sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)

    from tracegate.agent import metrics as m
    from tracegate.settings import Settings

    monkeypatch.setattr(m, "_query_xray_user_traffic_bytes", lambda _settings: {})
    monkeypatch.setattr(m, "_query_xray_inbound_traffic_bytes", lambda _settings: {})
    monkeypatch.setattr(m, "_fetch_hysteria_traffic_bytes", lambda _url, _secret: {})

    settings = Settings(
        agent_role="TRANSIT",
        agent_data_root=str(tmp_path),
        pseudonym_secret="test-secret",
    )
    collector = m.AgentMetricsCollector(settings)
    out = list(collector.collect())

    metric_names = {getattr(row, "name", "") for row in out}
    assert "tracegate_wg_peer_rx_bytes" not in metric_names
    assert "tracegate_wg_peer_tx_bytes" not in metric_names
    assert "tracegate_wg_peer_latest_handshake_seconds" not in metric_names


def test_hysteria_metrics_normalize_connection_marker(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    fake_prometheus = types.ModuleType("prometheus_client")
    fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
    fake_prometheus_core = types.ModuleType("prometheus_client.core")
    fake_prometheus_core.GaugeMetricFamily = _FakeGaugeMetricFamily
    sys.modules.setdefault("prometheus_client", fake_prometheus)
    sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)

    from tracegate.agent import metrics as m
    from tracegate.settings import Settings

    monkeypatch.setattr(
        m,
        "_query_xray_user_traffic_bytes",
        lambda _settings: {
            "v3 - 123456 - conn-lower": {"uplink": 11, "downlink": 22},
            "v4_123456789_aaaaaaaabbbb4ccc8dddeeeeeeeeeeee": {"uplink": 55, "downlink": 66},
            "V4 - 654321 - conn-upper": {"uplink": 33, "downlink": 44},
        },
    )
    monkeypatch.setattr(
        m,
        "_query_xray_inbound_traffic_bytes",
        lambda _settings: {
            "hy2-in": {"uplink": 77, "downlink": 88},
        },
    )
    monkeypatch.setattr(
        m,
        "_fetch_hysteria_traffic_bytes",
        lambda _url, _secret: (_ for _ in ()).throw(AssertionError("must not call Hysteria API in xray-centric")),
    )

    settings = Settings(
        agent_role="TRANSIT",
        agent_data_root=str(tmp_path),
        agent_runtime_profile="xray-centric",
        pseudonym_secret="test-secret",
    )
    collector = m.AgentMetricsCollector(settings)
    out = list(collector.collect())

    hyst_rx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_connection_rx_bytes")
    hyst_tx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_connection_tx_bytes")
    hyst_inbound_rx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_inbound_rx_bytes")
    hyst_inbound_tx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_inbound_tx_bytes")

    assert hyst_rx.samples == [
        (["V3 - 123456 - conn-lower"], 11.0),
        (["V4 - 123456789 - aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"], 55.0),
        (["V4 - 654321 - conn-upper"], 33.0),
    ]
    assert hyst_tx.samples == [
        (["V3 - 123456 - conn-lower"], 22.0),
        (["V4 - 123456789 - aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"], 66.0),
        (["V4 - 654321 - conn-upper"], 44.0),
    ]
    assert hyst_inbound_rx.samples == [(["hy2-in"], 77.0)]
    assert hyst_inbound_tx.samples == [(["hy2-in"], 88.0)]


def test_xray_centric_metrics_split_vless_and_hysteria_from_xray_stats(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    fake_prometheus = types.ModuleType("prometheus_client")
    fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
    fake_prometheus_core = types.ModuleType("prometheus_client.core")
    fake_prometheus_core.GaugeMetricFamily = _FakeGaugeMetricFamily
    sys.modules.setdefault("prometheus_client", fake_prometheus)
    sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)

    from tracegate.agent import metrics as m
    from tracegate.settings import Settings

    monkeypatch.setattr(
        m,
        "_query_xray_user_traffic_bytes",
        lambda _settings: {
            "V1 - 1 - c-vless": {"uplink": 10, "downlink": 20},
            "V3 - 1 - c-hy": {"uplink": 30, "downlink": 40},
            "V4 - 1 - c-hy2": {"uplink": 50, "downlink": 60},
        },
    )
    monkeypatch.setattr(
        m,
        "_query_xray_inbound_traffic_bytes",
        lambda _settings: {
            "hy2-in": {"uplink": 300, "downlink": 400},
        },
    )
    monkeypatch.setattr(
        m,
        "_fetch_hysteria_traffic_bytes",
        lambda _url, _secret: (_ for _ in ()).throw(AssertionError("must not call Hysteria API in xray-centric")),
    )

    settings = Settings(
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        agent_data_root=str(tmp_path),
        pseudonym_secret="test-secret",
    )
    collector = m.AgentMetricsCollector(settings)
    out = list(collector.collect())

    xray_rx = next(row for row in out if getattr(row, "name", "") == "tracegate_xray_connection_rx_bytes")
    xray_tx = next(row for row in out if getattr(row, "name", "") == "tracegate_xray_connection_tx_bytes")
    hyst_ok = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_stats_scrape_ok")
    hyst_rx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_connection_rx_bytes")
    hyst_tx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_connection_tx_bytes")
    hyst_inbound_rx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_inbound_rx_bytes")
    hyst_inbound_tx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_inbound_tx_bytes")

    assert xray_rx.samples == [(["V1 - 1 - c-vless"], 10.0)]
    assert xray_tx.samples == [(["V1 - 1 - c-vless"], 20.0)]
    assert hyst_ok.samples == [([], 1.0)]
    assert hyst_rx.samples == [
        (["V3 - 1 - c-hy"], 30.0),
        (["V4 - 1 - c-hy2"], 50.0),
    ]
    assert hyst_tx.samples == [
        (["V3 - 1 - c-hy"], 40.0),
        (["V4 - 1 - c-hy2"], 60.0),
    ]
    assert hyst_inbound_rx.samples == [(["hy2-in"], 300.0)]
    assert hyst_inbound_tx.samples == [(["hy2-in"], 400.0)]


def test_entry_xray_centric_metrics_export_hysteria_inbound_totals(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    fake_prometheus = types.ModuleType("prometheus_client")
    fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
    fake_prometheus_core = types.ModuleType("prometheus_client.core")
    fake_prometheus_core.GaugeMetricFamily = _FakeGaugeMetricFamily
    sys.modules.setdefault("prometheus_client", fake_prometheus)
    sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)

    from tracegate.agent import metrics as m
    from tracegate.settings import Settings

    monkeypatch.setattr(m, "_query_xray_user_traffic_bytes", lambda _settings: {})
    monkeypatch.setattr(
        m,
        "_query_xray_inbound_traffic_bytes",
        lambda _settings: {
            "hy2-in": {"uplink": 123, "downlink": 456},
        },
    )
    monkeypatch.setattr(
        m,
        "_fetch_hysteria_traffic_bytes",
        lambda _url, _secret: (_ for _ in ()).throw(AssertionError("must not call Hysteria API in xray-centric")),
    )

    settings = Settings(
        agent_role="ENTRY",
        agent_runtime_profile="xray-centric",
        agent_data_root=str(tmp_path),
        pseudonym_secret="test-secret",
    )
    collector = m.AgentMetricsCollector(settings)
    out = list(collector.collect())

    hyst_ok = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_stats_scrape_ok")
    hyst_inbound_rx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_inbound_rx_bytes")
    hyst_inbound_tx = next(row for row in out if getattr(row, "name", "") == "tracegate_hysteria_inbound_tx_bytes")

    assert hyst_ok.samples == [([], 1.0)]
    assert hyst_inbound_rx.samples == [(["hy2-in"], 123.0)]
    assert hyst_inbound_tx.samples == [(["hy2-in"], 456.0)]


def test_agent_metrics_export_runtime_and_obfuscation_flags(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    fake_prometheus = types.ModuleType("prometheus_client")
    fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
    fake_prometheus_core = types.ModuleType("prometheus_client.core")
    fake_prometheus_core.GaugeMetricFamily = _FakeGaugeMetricFamily
    sys.modules.setdefault("prometheus_client", fake_prometheus)
    sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)

    from tracegate.agent import metrics as m
    from tracegate.settings import Settings

    monkeypatch.setattr(m, "_query_xray_user_traffic_bytes", lambda _settings: {})
    monkeypatch.setattr(m, "_query_xray_inbound_traffic_bytes", lambda _settings: {})
    monkeypatch.setattr(m, "_fetch_hysteria_traffic_bytes", lambda _url, _secret: {})
    monkeypatch.setattr(
        m,
        "_runtime_contract_payload",
        lambda _root: {
            "runtimeProfile": "xray-centric",
            "xray": {
                "finalMaskEnabled": True,
                "echEnabled": False,
            },
                "fronting": {
                    "mtprotoDomain": "proto.tracegate.test",
                    "tcp443Owner": "haproxy",
                    "publicUdpOwner": "xray",
                    "udp443Owner": "xray",
                    "touchUdp443": False,
                },
        },
    )
    monkeypatch.setattr(m, "_obfuscation_runtime_state", lambda _settings: {"backend": "zapret2"})

    settings = Settings(
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        agent_data_root=str(tmp_path),
        pseudonym_secret="test-secret",
    )
    collector = m.AgentMetricsCollector(settings)
    out = list(collector.collect())
    runtime_contract_present = next(row for row in out if getattr(row, "name", "") == "tracegate_runtime_contract_present")
    runtime_profile = next(row for row in out if getattr(row, "name", "") == "tracegate_runtime_profile_info")
    runtime_features = next(row for row in out if getattr(row, "name", "") == "tracegate_runtime_feature_enabled")
    fronting_owner = next(row for row in out if getattr(row, "name", "") == "tracegate_fronting_owner_info")
    obfuscation_backend = next(row for row in out if getattr(row, "name", "") == "tracegate_obfuscation_backend_info")

    assert runtime_contract_present.samples == [(["TRANSIT"], 1.0)]
    assert runtime_profile.samples == [(["TRANSIT", "xray-centric"], 1.0)]
    assert runtime_features.samples == [
        (["TRANSIT", "finalmask"], 1.0),
        (["TRANSIT", "ech"], 0.0),
        (["TRANSIT", "mtproto_domain"], 1.0),
        (["TRANSIT", "touch_udp_443"], 0.0),
    ]
    assert fronting_owner.samples == [
        (["TRANSIT", "tcp", "haproxy"], 1.0),
        (["TRANSIT", "udp", "xray"], 1.0),
        (["TRANSIT", "udp443", "xray"], 1.0),
    ]
    assert obfuscation_backend.samples == [(["TRANSIT", "zapret2"], 1.0)]


def test_naiveproxy_agent_metrics_skip_xray_and_export_runtime_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    fake_prometheus = types.ModuleType("prometheus_client")
    fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
    fake_prometheus_core = types.ModuleType("prometheus_client.core")
    fake_prometheus_core.GaugeMetricFamily = _FakeGaugeMetricFamily
    sys.modules.setdefault("prometheus_client", fake_prometheus)
    sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)

    from tracegate.agent import metrics as m
    from tracegate.settings import Settings

    called = {"xray": False}

    def _unexpected_xray(_settings):
        called["xray"] = True
        return {}

    monkeypatch.setattr(m, "_query_xray_user_traffic_bytes", _unexpected_xray)
    monkeypatch.setattr(m, "_query_xray_inbound_traffic_bytes", _unexpected_xray)
    monkeypatch.setattr(
        m,
        "_fetch_hysteria_traffic_bytes",
        lambda _url, _secret: (_ for _ in ()).throw(AssertionError("must not call Hysteria API")),
    )
    monkeypatch.setattr(
        m,
        "_runtime_contract_payload",
        lambda _root: {"runtimeProfile": "tracegate-naiveproxy-v4"},
    )

    runtime_dir = tmp_path / "runtime" / "naiveproxy"
    runtime_dir.mkdir(parents=True)
    (runtime_dir / "Caddyfile").write_text(":11443 {}", encoding="utf-8")
    (runtime_dir / "users.json").write_text(
        '{"users":[{"disabled":false},{"disabled":true}]}',
        encoding="utf-8",
    )

    settings = Settings(
        agent_role="NAIVEPROXY",
        agent_runtime_profile="tracegate-naiveproxy-v4",
        agent_data_root=str(tmp_path),
        naiveproxy_tcp_exposure="demux",
        naiveproxy_public_tcp_port=443,
        naiveproxy_public_udp_port=443,
        naiveproxy_decoy_mode="auth-portal",
        pseudonym_secret="test-secret",
    )
    out = list(m.AgentMetricsCollector(settings).collect())
    by_name = {getattr(row, "name", ""): row for row in out}

    assert called == {"xray": False}
    assert "tracegate_xray_stats_scrape_ok" not in by_name
    assert "tracegate_hysteria_stats_scrape_ok" not in by_name
    assert by_name["tracegate_naiveproxy_runtime_info"].samples == [
        (["NAIVEPROXY", "demux", "auth-portal"], 1.0)
    ]
    assert by_name["tracegate_naiveproxy_config_present"].samples == [
        (["NAIVEPROXY", "caddyfile"], 1.0),
        (["NAIVEPROXY", "users"], 1.0),
    ]
    assert by_name["tracegate_naiveproxy_users"].samples == [
        (["NAIVEPROXY", "active"], 1.0),
        (["NAIVEPROXY", "total"], 2.0),
    ]
