import sys
import types
import json
from types import SimpleNamespace

import pytest


class _FakeGaugeMetricFamily:
    def __init__(self, name: str, documentation: str, labels=None):  # noqa: ANN001
        self.name = name
        self.documentation = documentation
        self.labels = list(labels or [])
        self.samples = []

    def add_metric(self, label_values, value):  # noqa: ANN001, ANN201
        self.samples.append((list(label_values or []), float(value)))


fake_prometheus = types.ModuleType("prometheus_client")
fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
fake_prometheus_core = types.ModuleType("prometheus_client.core")
fake_prometheus_core.GaugeMetricFamily = _FakeGaugeMetricFamily
sys.modules.setdefault("prometheus_client", fake_prometheus)
sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)


def _metrics_helpers():
    from tracegate.agent.metrics import _parse_meminfo, _parse_netdev

    return _parse_meminfo, _parse_netdev


def test_probe_peer_parses_linux_ping(monkeypatch) -> None:  # noqa: ANN001
    from tracegate.agent import metrics as m

    monkeypatch.setattr(
        m.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                "3 packets transmitted, 2 received, 33.3333% packet loss\n"
                "rtt min/avg/max/mdev = 45.000/47.500/50.000/2.500 ms\n"
            ),
            stderr="",
        ),
    )
    success_ratio, average_rtt = m._probe_peer("192.0.2.1")
    assert success_ratio == pytest.approx(2 / 3, abs=0.001)
    assert average_rtt == pytest.approx(0.0475)


def test_haproxy_stats_parser_filters_frontends(monkeypatch) -> None:  # noqa: ANN001
    from tracegate.agent import metrics as m

    payload = (
        b"# pxname,svname,status,scur,qcur,type,\n"
        b"fe,FRONTEND,OPEN,1,0,0,\n"
        b"be_mtproto,mtproto,UP,2,0,2,\n"
        b"be_mtproto,BACKEND,UP,2,0,1,\n"
    )

    class _Socket:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            self.chunks = [payload, b""]

        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN002
            return None

        def settimeout(self, _timeout) -> None:  # noqa: ANN001
            return None

        def connect(self, _path) -> None:  # noqa: ANN001
            return None

        def sendall(self, _payload) -> None:  # noqa: ANN001
            return None

        def recv(self, _size):  # noqa: ANN001, ANN201
            return self.chunks.pop(0)

    monkeypatch.setattr(m.socket, "socket", _Socket)
    assert m._read_haproxy_stats("/run/haproxy.sock") == [
        {
            "pxname": "be_mtproto",
            "svname": "mtproto",
            "status": "UP",
            "scur": "2",
            "qcur": "0",
            "type": "2",
        },
        {
            "pxname": "be_mtproto",
            "svname": "BACKEND",
            "status": "UP",
            "scur": "2",
            "qcur": "0",
            "type": "1",
        },
    ]


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


def test_wireguard_dump_is_mapped_to_connection_marker(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    from tracegate.agent import metrics as m

    state_path = tmp_path / "desired-state.json"
    state_path.write_text(
        json.dumps(
            {
                "wireguardWSTunnel": [
                    {
                        "variant": "V0",
                        "userId": "123",
                        "connectionId": "conn-1",
                        "wireguard": {"clientPublicKey": "peer-key"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        m.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="wg\tpeer-key\t(none)\t192.0.2.1:1234\t10.0.0.2/32\t1\t12000000\t34000000\t25\n",
            stderr="",
        ),
    )

    assert m._wireguard_connection_traffic_bytes(state_path) == {
        "V0 - 123 - conn-1": (12000000, 34000000)
    }


def test_mtproto_traffic_parser_accepts_current_telemt_data_list(monkeypatch) -> None:  # noqa: ANN001
    from tracegate.agent import metrics as m

    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {
            "ok": True,
            "data": [
                {"username": "tg_123456", "total_octets": 42},
                {"username": "bootstrap", "total_octets": 100},
            ],
        },
    )
    monkeypatch.setattr("httpx.get", lambda *args, **kwargs: response)

    assert m._fetch_mtproto_user_traffic_bytes("http://127.0.0.1/stats") == {
        "123456": 42
    }


def test_mtproto_stats_are_only_exported_by_runtime_owner() -> None:
    from tracegate.agent import metrics as m

    assert m._mtproto_stats_enabled(
        SimpleNamespace(agent_role="ENTRY", mtproto_route_mode="entry-local-endpoint-egress")
    ) is True
    assert m._mtproto_stats_enabled(
        SimpleNamespace(agent_role="TRANSIT", mtproto_route_mode="entry-local-endpoint-egress")
    ) is False
    assert m._mtproto_stats_enabled(
        SimpleNamespace(agent_role="TRANSIT", mtproto_route_mode="entry-endpoint-tunnel")
    ) is True
    assert m._mtproto_stats_enabled(
        SimpleNamespace(agent_role="ENTRY", mtproto_route_mode="entry-endpoint-tunnel")
    ) is False
