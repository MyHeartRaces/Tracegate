from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import grpc

pytest.importorskip("prometheus_client")

from tracegate.agent import metrics, xray_api
from tracegate.settings import Settings


class _Channel:
    def __init__(self, rpc=None) -> None:  # noqa: ANN001
        self.rpc = rpc

    def unary_unary(self, path, **kwargs):  # noqa: ANN001
        assert path == "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus"
        assert kwargs["request_serializer"] is not None
        assert kwargs["response_deserializer"] is not None
        return self.rpc

    def close(self) -> None:
        return None


def test_query_outbound_observations_maps_xray_response(monkeypatch) -> None:  # noqa: ANN001
    response = SimpleNamespace(
        status=SimpleNamespace(
            status=[
                SimpleNamespace(
                    outbound_tag="to-transit-ss",
                    alive=True,
                    delay=37,
                    last_seen_time=100,
                    last_try_time=101,
                    health_ping=SimpleNamespace(all=20, fail=1),
                )
            ]
        )
    )

    def _rpc(request, timeout=None):  # noqa: ANN001
        assert request is not None
        assert timeout == 3.0
        return response

    monkeypatch.setattr(xray_api.grpc, "insecure_channel", lambda _target: _Channel(_rpc))

    assert xray_api.query_outbound_observations(Settings()) == {
        "to-transit-ss": {
            "alive": True,
            "delay_ms": 37,
            "last_seen_time": 100,
            "last_try_time": 101,
            "checks": 20,
            "failures": 1,
        }
    }


def test_query_outbound_observations_falls_back_to_legacy_rpc(monkeypatch) -> None:  # noqa: ANN001
    response = SimpleNamespace(status=SimpleNamespace(status=[]))

    class _Unimplemented(grpc.RpcError):
        def code(self):  # noqa: ANN201
            return grpc.StatusCode.UNIMPLEMENTED

    def _current_rpc(_request, timeout=None):  # noqa: ANN001
        assert timeout == 3.0
        raise _Unimplemented()

    class _LegacyStub:
        def __init__(self, channel) -> None:  # noqa: ANN001
            assert isinstance(channel, _Channel)

        def GetOutboundStatus(self, _request, timeout=None):  # noqa: ANN001, N802
            assert timeout == 3.0
            return response

    monkeypatch.setattr(xray_api.grpc, "insecure_channel", lambda _target: _Channel(_current_rpc))
    monkeypatch.setattr(xray_api.observatory_command_pb2_grpc, "ObservatoryServiceStub", _LegacyStub)

    assert xray_api.query_outbound_observations(Settings()) == {}


def test_entry_metrics_export_each_backhaul_channel(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    monkeypatch.setattr(metrics, "_read_loadavg", lambda: None)
    monkeypatch.setattr(metrics, "_read_meminfo", lambda: None)
    monkeypatch.setattr(metrics, "_read_network_totals", lambda: [])
    monkeypatch.setattr(metrics, "_query_xray_user_traffic_bytes", lambda _settings: {})
    monkeypatch.setattr(metrics, "_wireguard_connection_traffic_bytes", lambda _path: {})
    monkeypatch.setattr(
        metrics,
        "_query_xray_outbound_observations",
        lambda _settings: {
            "to-transit-ss": {"alive": True, "delay_ms": 25, "last_try_time": 100, "checks": 10, "failures": 0},
            "to-transit-ss2": {"alive": False, "delay_ms": 99_999_999, "last_try_time": 101, "checks": 10, "failures": 2},
            "to-transit": {"alive": True, "delay_ms": 40, "last_try_time": 102, "checks": 10, "failures": 0},
        },
    )
    monkeypatch.setattr(metrics, "_probe_http_proxy_egress", lambda: (True, 0.04))
    settings = Settings(
        agent_role="ENTRY",
        agent_data_root=str(tmp_path),
        agent_runtime_profile="tracegate3",
    )
    families = {family.name: family for family in metrics.AgentMetricsCollector(settings).collect()}
    success = families["tracegate_backhaul_egress_probe_success"]
    samples: set[tuple[str, float]] = set()
    for sample in success.samples:
        if hasattr(sample, "labels"):
            labels = sample.labels
            value = sample.value
        elif isinstance(sample[0], list):
            labels = dict(zip(success.labels, sample[0], strict=True))
            value = sample[1]
        else:
            labels = next(item for item in sample if isinstance(item, dict))
            value = next(item for item in sample if isinstance(item, (int, float)))
        samples.add((labels["channel"], value))
    assert samples == {
        ("shadowtls-primary-a", 1),
        ("shadowtls-primary-b", 0),
        ("reality-fallback", 1),
    }


def test_reality_probe_uses_full_https_egress_through_local_proxy(monkeypatch) -> None:  # noqa: ANN001
    calls = []

    class _Response:
        def raise_for_status(self) -> None:
            return None

    def _get(url, **kwargs):  # noqa: ANN001, ANN202
        calls.append((url, kwargs))
        return _Response()

    monotonic = iter((10.0, 10.25))
    monkeypatch.setattr(metrics.httpx, "get", _get)
    monkeypatch.setattr(metrics.time, "monotonic", lambda: next(monotonic))

    assert metrics._probe_http_proxy_egress() == (True, 0.25)
    assert calls == [
        (
            "https://www.google.com/generate_204",
            {
                "proxy": "http://127.0.0.1:18083",
                "timeout": 8.0,
                "follow_redirects": True,
            },
        )
    ]


def test_entry_bundle_binds_reality_probe_to_dedicated_outbound() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config = json.loads((repo_root / "bundles/base-entry/xray.json").read_text(encoding="utf-8"))
    inbound = next(row for row in config["inbounds"] if row.get("tag") == "backhaul-probe-reality-in")
    assert inbound["listen"] == "127.0.0.1"
    assert inbound["port"] == 18083
    assert inbound["protocol"] == "http"
    rule = next(
        row
        for row in config["routing"]["rules"]
        if row.get("inboundTag") == ["backhaul-probe-reality-in"]
    )
    assert rule["outboundTag"] == "to-transit"
