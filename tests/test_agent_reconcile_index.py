import json
from pathlib import Path

from tracegate.agent.reconcile import (
    AgentPaths,
    load_all_user_artifacts,
    load_all_wg_peer_artifacts,
    remove_connection_artifact_index,
    remove_user_artifact_index,
    remove_wg_peer_artifact_index,
    upsert_user_artifact_index,
    upsert_wg_peer_artifact_index,
)
from tracegate.settings import Settings


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_index_rebuild_from_disk(tmp_path: Path) -> None:
    settings = Settings(agent_data_root=str(tmp_path))
    paths = AgentPaths.from_settings(settings)

    _write(
        tmp_path / "users/u1/connection-c1.json",
        {"user_id": "u1", "connection_id": "c1", "protocol": "vless_reality", "config": {"uuid": "u1"}},
    )

    rows = load_all_user_artifacts(paths)

    assert len(rows) == 1
    assert rows[0]["connection_id"] == "c1"
    assert (paths.runtime / "artifact-index.json").exists()


def test_index_update_and_remove_user_connections(tmp_path: Path) -> None:
    settings = Settings(agent_data_root=str(tmp_path))
    paths = AgentPaths.from_settings(settings)

    upsert_user_artifact_index(
        settings,
        {
            "user_id": "u1",
            "connection_id": "c1",
            "protocol": "vless_reality",
            "config": {"uuid": "r1"},
        },
    )
    upsert_user_artifact_index(
        settings,
        {
            "user_id": "u1",
            "connection_id": "c2",
            "protocol": "hysteria2",
            "config": {"auth": {"type": "userpass", "username": "u1", "password": "p"}},
        },
    )

    rows = load_all_user_artifacts(paths)
    assert [row["connection_id"] for row in rows] == ["c1", "c2"]

    remove_connection_artifact_index(settings, "c1")
    rows = load_all_user_artifacts(paths)
    assert [row["connection_id"] for row in rows] == ["c2"]

    remove_user_artifact_index(settings, "u1")
    assert load_all_user_artifacts(paths) == []


def test_index_update_and_remove_wg_peers(tmp_path: Path) -> None:
    settings = Settings(agent_data_root=str(tmp_path))
    paths = AgentPaths.from_settings(settings)

    upsert_wg_peer_artifact_index(
        settings,
        peer_key="dev-1",
        payload={"peer_public_key": "pub-1", "peer_ip": "10.70.0.2", "connection_id": "c1"},
    )
    upsert_wg_peer_artifact_index(
        settings,
        peer_key="dev-2",
        payload={"peer_public_key": "pub-2", "peer_ip": "10.70.0.3", "connection_id": "c2"},
    )

    rows = load_all_wg_peer_artifacts(paths)
    assert [row["peer_public_key"] for row in rows] == ["pub-1", "pub-2"]

    remove_wg_peer_artifact_index(settings, peer_key="dev-1")
    rows = load_all_wg_peer_artifacts(paths)
    assert [row["peer_public_key"] for row in rows] == ["pub-2"]
