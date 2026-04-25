from pathlib import Path


def test_env_example_uses_tracegate2_entry_transit_naming() -> None:
    env_example = (Path(__file__).resolve().parents[1] / ".env.example").read_text(encoding="utf-8")

    assert "AGENT_ROLE=TRANSIT" in env_example
    assert "AGENT_RUNTIME_MODE=systemd" in env_example
    assert "AGENT_RUNTIME_PROFILE=xray-centric" in env_example
    assert "DEFAULT_ENTRY_HOST=" in env_example
    assert "DEFAULT_TRANSIT_HOST=" in env_example
    assert "DEFAULT_VPS_E_HOST=" not in env_example
    assert "DEFAULT_VPS_T_HOST=" not in env_example
    assert "WIREGUARD_SERVER_PUBLIC_KEY=" not in env_example
    assert "AGENT_RELOAD_WG_CMD=" not in env_example
    assert "AGENT_WG_INTERFACE=" not in env_example


def test_docker_compose_uses_tracegate2_defaults() -> None:
    compose = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text(encoding="utf-8")

    assert "DEFAULT_TRANSIT_HOST" in compose
    assert "DEFAULT_ENTRY_HOST" in compose
    assert "AGENT_ROLE: ${AGENT_ROLE:-TRANSIT}" in compose
    assert "AGENT_RUNTIME_MODE: ${AGENT_RUNTIME_MODE:-systemd}" in compose
    assert "DEFAULT_VPS_T_HOST" not in compose
    assert "DEFAULT_VPS_E_HOST" not in compose
