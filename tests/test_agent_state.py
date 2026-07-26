from pathlib import Path

from tracegate.agent.state import AgentStateStore


def test_agent_state_database_is_private(tmp_path: Path) -> None:
    store = AgentStateStore(tmp_path)

    assert store.db_path.stat().st_mode & 0o777 == 0o600
