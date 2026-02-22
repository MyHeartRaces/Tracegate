import json
import shlex

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


def test_handle_apply_bundle_applies_firewall_when_nftables_conf_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls: list[str] = []

    def _run(cmd: str, dry_run: bool) -> tuple[bool, str]:
        calls.append(cmd)
        assert dry_run is False
        return True, "ok"

    monkeypatch.setattr(handlers, "run_command", _run)
    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=False)

    handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-vps-t",
            "files": {
                "nftables.conf": "flush ruleset\n",
            },
            "commands": [],
        },
    )

    bundle_conf = tmp_path / "bundles" / "base-vps-t" / "nftables.conf"
    conf_arg = shlex.quote(str(bundle_conf))
    assert calls == [f"nft -c -f {conf_arg}", f"nft -f {conf_arg}"]


def test_handle_apply_bundle_skips_firewall_when_nftables_conf_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls: list[str] = []

    def _run(cmd: str, dry_run: bool) -> tuple[bool, str]:
        calls.append(cmd)
        return True, "ok"

    monkeypatch.setattr(handlers, "run_command", _run)
    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=False)

    handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-vps-t",
            "files": {"xray/config.json": "{}"},
            "commands": ["echo done"],
        },
    )

    assert calls == ["echo done"]


def test_handle_apply_bundle_raises_on_firewall_validation_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    def _run(cmd: str, dry_run: bool) -> tuple[bool, str]:
        if cmd.startswith("nft -c -f "):
            return False, "syntax error"
        return True, "ok"

    monkeypatch.setattr(handlers, "run_command", _run)
    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=False)

    with pytest.raises(handlers.HandlerError, match="firewall validation failed"):
        handlers.handle_apply_bundle(
            settings,
            {
                "bundle_name": "base-vps-e",
                "files": {"nftables.conf": "broken"},
                "commands": [],
            },
        )


def test_handle_apply_bundle_syncs_base_configs_and_reconciles(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)

    reconciler_calls: list[str] = []

    def _reconcile(_settings: Settings) -> list[str]:
        reconciler_calls.append("called")
        return ["xray", "hysteria", "wireguard"]

    monkeypatch.setattr(handlers, "reconcile_all", _reconcile)

    reload_calls: list[list[str]] = []
    monkeypatch.setattr(
        handlers,
        "_run_reload_commands",
        lambda _settings, cmds: reload_calls.append(list(cmds)),
    )

    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_dry_run=False,
        agent_xray_api_enabled=True,
        agent_reload_xray_cmd="reload-xray",
        agent_reload_hysteria_cmd="reload-hysteria",
        agent_reload_wg_cmd="reload-wg",
    )

    msg = handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-vps-t",
            "files": {
                "xray.json": "{\"inbounds\":[]}",
                "hysteria.yaml": "listen: :443\n",
                "wg0.conf": "[Interface]\nListenPort = 51820\n",
            },
            "commands": [],
        },
    )

    assert reconciler_calls == ["called"]
    assert reload_calls == [["reload-xray", "reload-hysteria", "reload-wg"]]
    assert (tmp_path / "base/xray/config.json").read_text(encoding="utf-8") == "{\"inbounds\":[]}"
    assert (tmp_path / "base/hysteria/config.yaml").read_text(encoding="utf-8") == "listen: :443\n"
    assert (tmp_path / "base/wireguard/wg0.conf").read_text(encoding="utf-8") == "[Interface]\nListenPort = 51820\n"
    assert "base_sync=hysteria,wireguard,xray" in msg
    assert "reconciled=hysteria,wireguard,xray" in msg


def test_handle_apply_bundle_ignores_non_base_bundle_for_reconcile(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: pytest.fail("reconcile_all should not run"))
    monkeypatch.setattr(handlers, "_run_reload_commands", lambda _settings, _cmds: pytest.fail("reloads should not run"))

    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=False)

    handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "custom-operator-bundle",
            "files": {"xray.json": "{}"},
            "commands": [],
        },
    )

    assert not (tmp_path / "base/xray/config.json").exists()


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


def test_wg_peer_upsert_does_not_persist_config_private_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: [])
    monkeypatch.setattr(handlers, "_run_reload_commands", lambda _settings, _cmds: None)

    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=True)

    handlers.handle_wg_peer_upsert(
        settings,
        {
            "device_id": "d1",
            "user_id": "1",
            "user_display": "@alice (1)",
            "device_name": "Alice iPhone",
            "connection_alias": "@alice (1) - Alice iPhone - c1",
            "peer_public_key": "pub",
            "peer_ip": "10.0.0.2",
            "op_ts": "2026-02-12T00:00:01+00:00",
            "config": {"interface": {"private_key": "VERY-SECRET"}},
        },
    )

    persisted = json.loads((tmp_path / "wg-peers" / "peer-d1.json").read_text(encoding="utf-8"))
    assert "config" not in persisted
    assert "VERY-SECRET" not in json.dumps(persisted)
