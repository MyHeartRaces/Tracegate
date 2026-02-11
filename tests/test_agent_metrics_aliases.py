import json
import sys
import types
from pathlib import Path

fake_prometheus = types.ModuleType("prometheus_client")
fake_prometheus.REGISTRY = types.SimpleNamespace(register=lambda _: None)
fake_prometheus_core = types.ModuleType("prometheus_client.core")
fake_prometheus_core.GaugeMetricFamily = object
sys.modules.setdefault("prometheus_client", fake_prometheus)
sys.modules.setdefault("prometheus_client.core", fake_prometheus_core)


def test_load_wg_peer_map_reads_alias_labels(tmp_path: Path) -> None:
    from tracegate.agent.metrics import _load_wg_peer_map

    peers_dir = tmp_path / "wg-peers"
    peers_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "peer_public_key": "pub-key-1",
        "user_id": "100",
        "user_display": "@alice (100)",
        "device_id": "dev-1",
        "device_name": "Alice iPhone",
        "connection_alias": "@alice (100) - Alice iPhone - conn-1",
    }
    (peers_dir / "peer-dev-1.json").write_text(json.dumps(payload), encoding="utf-8")

    mapping = _load_wg_peer_map(tmp_path)
    assert mapping["pub-key-1"]["user_id"] == "100"
    assert mapping["pub-key-1"]["user_display"] == "@alice (100)"
    assert mapping["pub-key-1"]["device_id"] == "dev-1"
    assert mapping["pub-key-1"]["device_name"] == "Alice iPhone"
    assert mapping["pub-key-1"]["connection_alias"] == "@alice (100) - Alice iPhone - conn-1"
