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


def test_out_of_order_revoke_then_upsert_is_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # Avoid touching real reconcilers / reload hooks in this unit test.
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: [])
    monkeypatch.setattr(handlers, "_run_reload_commands", lambda _settings, _cmds: None)

    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=True)

    revoke = {
        "user_id": "1",
        "connection_id": "c1",
        "op_ts": "2026-02-12T00:00:02+00:00",
    }
    handlers.handle_revoke_connection(settings, revoke)

    upsert_old = {
        "user_id": "1",
        "connection_id": "c1",
        "revision_id": "r1",
        "op_ts": "2026-02-12T00:00:01+00:00",
        "config": {"protocol": "vless"},
    }
    msg = handlers.handle_upsert_user(settings, upsert_old)
    assert "ignored upsert" in msg

    assert not (tmp_path / "users" / "1" / "connection-c1.json").exists()

    upsert_new = {
        "user_id": "1",
        "connection_id": "c1",
        "revision_id": "r2",
        "op_ts": "2026-02-12T00:00:03+00:00",
        "config": {"protocol": "vless"},
    }
    handlers.handle_upsert_user(settings, upsert_new)

    p = tmp_path / "users" / "1" / "connection-c1.json"
    assert p.exists()
    assert "r2" in p.read_text(encoding="utf-8")


def test_out_of_order_upsert_does_not_roll_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: [])
    monkeypatch.setattr(handlers, "_run_reload_commands", lambda _settings, _cmds: None)

    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=True)

    newer = {
        "user_id": "1",
        "connection_id": "c1",
        "revision_id": "r2",
        "op_ts": "2026-02-12T00:00:03+00:00",
        "config": {"protocol": "vless"},
    }
    older = {
        "user_id": "1",
        "connection_id": "c1",
        "revision_id": "r1",
        "op_ts": "2026-02-12T00:00:01+00:00",
        "config": {"protocol": "vless"},
    }

    handlers.handle_upsert_user(settings, newer)
    msg = handlers.handle_upsert_user(settings, older)
    assert "ignored older upsert" in msg

    p = tmp_path / "users" / "1" / "connection-c1.json"
    assert p.exists()
    assert "r2" in p.read_text(encoding="utf-8")


def test_out_of_order_wg_peer_remove_then_upsert_is_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: [])
    monkeypatch.setattr(handlers, "_run_reload_commands", lambda _settings, _cmds: None)

    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=True)

    # Remove first (newer)
    handlers.handle_wg_peer_remove(
        settings,
        {"device_id": "d1", "op_ts": "2026-02-12T00:00:02+00:00"},
    )

    # Then an older upsert arrives
    msg = handlers.handle_wg_peer_upsert(
        settings,
        {
            "device_id": "d1",
            "peer_public_key": "pub",
            "peer_ip": "10.0.0.2",
            "op_ts": "2026-02-12T00:00:01+00:00",
        },
    )
    assert "ignored wg peer upsert" in msg

    # Newer upsert should reactivate
    msg2 = handlers.handle_wg_peer_upsert(
        settings,
        {
            "device_id": "d1",
            "peer_public_key": "pub",
            "peer_ip": "10.0.0.2",
            "op_ts": "2026-02-12T00:00:03+00:00",
        },
    )
    assert "wg peer upserted" in msg2
    assert (tmp_path / "wg-peers" / "peer-d1.json").exists()
