import json
from pathlib import Path

from tracegate.agent.reconcile import (
    AgentPaths,
    load_all_user_artifacts,
    remove_connection_artifact_index,
    remove_user_artifact_index,
    upsert_user_artifact_index,
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
