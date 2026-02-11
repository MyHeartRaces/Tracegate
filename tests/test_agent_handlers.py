import pytest

from tracegate.agent import handlers
from tracegate.settings import Settings


def test_run_reload_commands_success(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def _run(cmd: str, dry_run: bool) -> tuple[bool, str]:
        calls.append(cmd)
        assert dry_run is False
        return True, "ok"

    monkeypatch.setattr(handlers, "run_command", _run)
    settings = Settings(agent_dry_run=False)

    handlers._run_reload_commands(settings, ["cmd-one", "", "cmd-two"])

    assert calls == ["cmd-one", "cmd-two"]


def test_run_reload_commands_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _run(cmd: str, dry_run: bool) -> tuple[bool, str]:
        assert dry_run is False
        if cmd == "bad-cmd":
            return False, "boom"
        return True, "ok"

    monkeypatch.setattr(handlers, "run_command", _run)
    settings = Settings(agent_dry_run=False)

    with pytest.raises(handlers.HandlerError, match="bad-cmd"):
        handlers._run_reload_commands(settings, ["good-cmd", "bad-cmd"])
