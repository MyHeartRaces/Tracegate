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


def test_reload_commands_do_not_emit_legacy_hysteria_reload_even_for_old_profile_names() -> None:
    settings = Settings(
        agent_runtime_mode="kubernetes",
        agent_runtime_profile="xray-hysteria",
        agent_reload_xray_cmd="reload-xray",
    )

    cmds = handlers._reload_commands_for_changed(settings, {"hysteria", "xray"})

    assert cmds == ["reload-xray"]


def test_reload_commands_keep_hysteria_empty_outside_legacy_container_mode() -> None:
    settings = Settings(
        agent_runtime_mode="systemd",
        agent_runtime_profile="xray-hysteria",
        agent_reload_xray_cmd="reload-xray",
    )

    cmds = handlers._reload_commands_for_changed(settings, {"hysteria"})

    assert cmds == []


def test_reload_commands_include_standalone_hysteria_for_tracegate22() -> None:
    settings = Settings(
        agent_runtime_mode="systemd",
        agent_runtime_profile="tracegate-2.2",
        agent_reload_hysteria_cmd="reload-hysteria",
    )

    cmds = handlers._reload_commands_for_changed(settings, {"hysteria"})

    assert cmds == ["reload-hysteria"]


def test_reload_commands_include_proxy_stack_when_changed() -> None:
    settings = Settings(
        agent_runtime_mode="systemd",
        agent_reload_haproxy_cmd="reload-haproxy",
        agent_reload_nginx_cmd="reload-nginx",
    )

    cmds = handlers._reload_commands_for_changed(settings, {"haproxy", "nginx"})

    assert cmds == ["reload-haproxy", "reload-nginx"]


def test_reload_commands_include_obfuscation_hook_when_changed() -> None:
    settings = Settings(
        agent_runtime_mode="systemd",
        agent_reload_obfuscation_cmd="reload-obfuscation",
    )

    cmds = handlers._reload_commands_for_changed(settings, {"obfuscation"})

    assert cmds == ["reload-obfuscation"]


def test_reload_commands_include_private_fronting_and_mtproto_hooks_when_changed() -> None:
    settings = Settings(
        agent_runtime_mode="systemd",
        agent_reload_mtproto_cmd="reload-mtproto",
        agent_reload_fronting_cmd="reload-fronting",
    )

    cmds = handlers._reload_commands_for_changed(settings, {"fronting", "mtproto"})

    assert cmds == ["reload-mtproto", "reload-fronting"]


def test_reload_commands_include_private_profiles_hook_when_changed() -> None:
    settings = Settings(
        agent_runtime_mode="systemd",
        agent_reload_profiles_cmd="reload-profiles",
    )

    cmds = handlers._reload_commands_for_changed(settings, {"profiles"})

    assert cmds == ["reload-profiles"]


def test_reload_commands_include_private_link_crypto_hook_when_changed() -> None:
    settings = Settings(
        agent_runtime_mode="systemd",
        agent_reload_link_crypto_cmd="reload-link-crypto",
    )

    cmds = handlers._reload_commands_for_changed(settings, {"link-crypto"})

    assert cmds == ["reload-link-crypto"]


def test_reload_commands_force_xray_reload_even_when_api_mode_is_enabled() -> None:
    settings = Settings(
        agent_runtime_mode="systemd",
        agent_xray_api_enabled=True,
        agent_reload_xray_cmd="reload-xray",
    )

    cmds = handlers._reload_commands_for_changed(settings, {"xray"}, force_xray_reload=True)

    assert cmds == ["reload-xray"]


def test_handle_upsert_user_reconciles_without_reload_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(
        handlers,
        "_reconcile_user_lifecycle_without_reload",
        lambda _settings: handlers.ReconcileAllResult(
            changed=["xray", "profiles", "hysteria"],
            force_xray_reload=True,
        ),
    )
    monkeypatch.setattr(
        handlers,
        "_run_reload_commands",
        lambda _settings, _cmds: pytest.fail("user lifecycle must not run reload commands"),
    )
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_reload_xray_cmd="reload-xray",
        agent_reload_hysteria_cmd="reload-hysteria",
        agent_reload_profiles_cmd="reload-profiles",
    )

    msg = handlers.handle_upsert_user(
        settings,
        {
            "user_id": "1",
            "connection_id": "c1",
            "revision_id": "r1",
            "op_ts": "2026-02-12T00:00:01+00:00",
            "config": {"protocol": "vless"},
        },
    )

    assert "live_reconciled=hysteria,profiles,xray" in msg
    assert "reloads=0" in msg


def test_handle_revoke_user_reconciles_without_reload_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(
        handlers,
        "_reconcile_user_lifecycle_without_reload",
        lambda _settings: handlers.ReconcileAllResult(
            changed=["profiles"],
            force_xray_reload=False,
        ),
    )
    monkeypatch.setattr(
        handlers,
        "_run_reload_commands",
        lambda _settings, _cmds: pytest.fail("user lifecycle must not run reload commands"),
    )
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_reload_profiles_cmd="reload-profiles",
    )

    msg = handlers.handle_revoke_user(settings, {"user_id": "1"})

    assert "live_reconciled=profiles" in msg
    assert "reloads=0" in msg


def test_handle_revoke_connection_reconciles_without_reload_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(
        handlers,
        "_reconcile_user_lifecycle_without_reload",
        lambda _settings: handlers.ReconcileAllResult(
            changed=["xray"],
            force_xray_reload=True,
        ),
    )
    monkeypatch.setattr(
        handlers,
        "_run_reload_commands",
        lambda _settings, _cmds: pytest.fail("user lifecycle must not run reload commands"),
    )
    settings = Settings(agent_data_root=str(tmp_path), agent_reload_xray_cmd="reload-xray")

    msg = handlers.handle_revoke_connection(
        settings,
        {"user_id": "1", "connection_id": "c1"},
    )

    assert "live_reconciled=xray" in msg
    assert "reloads=0" in msg


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
            "bundle_name": "base-transit",
            "files": {
                "nftables.conf": "flush ruleset\n",
            },
            "commands": [],
        },
    )

    bundle_conf = tmp_path / "bundles" / "base-transit" / "nftables.conf"
    conf_arg = shlex.quote(str(bundle_conf))
    assert calls == [f"nft -c -f {conf_arg}", f"nft -f {conf_arg}"]


def test_handle_apply_bundle_reloads_obfuscation_after_firewall_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls: list[str] = []

    def _run(cmd: str, dry_run: bool) -> tuple[bool, str]:
        calls.append(cmd)
        assert dry_run is False
        return True, "ok"

    monkeypatch.setattr(handlers, "run_command", _run)
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_dry_run=False,
        agent_reload_obfuscation_cmd="reload-obfuscation",
    )

    handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-entry",
            "files": {
                "nftables.conf": "flush ruleset\n",
            },
            "commands": [],
        },
    )

    bundle_conf = tmp_path / "bundles" / "base-entry" / "nftables.conf"
    conf_arg = shlex.quote(str(bundle_conf))
    assert calls == [f"nft -c -f {conf_arg}", f"nft -f {conf_arg}", "reload-obfuscation"]


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
            "bundle_name": "base-transit",
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
                "bundle_name": "base-entry",
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
        assert _settings.agent_xray_api_enabled is False
        reconciler_calls.append("called")
        return ["xray"]

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
        agent_runtime_profile="xray-hysteria",
        agent_xray_api_enabled=True,
        agent_reload_xray_cmd="reload-xray",
    )

    msg = handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-transit",
            "files": {
                "xray.json": "{\"inbounds\":[]}",
            },
            "commands": [],
        },
    )

    assert reconciler_calls == ["called"]
    assert reload_calls == [["reload-xray"]]
    assert settings.agent_xray_api_enabled is True
    assert (tmp_path / "base/xray/config.json").read_text(encoding="utf-8") == "{\"inbounds\":[]}"
    assert "base_sync=xray" in msg
    assert "reconciled=xray" in msg


def test_handle_apply_bundle_syncs_proxy_base_configs(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: ["haproxy", "nginx"])

    reload_calls: list[list[str]] = []
    monkeypatch.setattr(
        handlers,
        "_run_reload_commands",
        lambda _settings, cmds: reload_calls.append(list(cmds)),
    )

    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_dry_run=False,
        agent_reload_haproxy_cmd="reload-haproxy",
        agent_reload_nginx_cmd="reload-nginx",
    )

    msg = handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-entry",
            "files": {
                "haproxy.cfg": "frontend fe\n  bind :443\n",
                "nginx.conf": "events {}\nhttp {}\n",
            },
            "commands": [],
        },
    )

    assert (tmp_path / "base/haproxy/haproxy.cfg").read_text(encoding="utf-8") == "frontend fe\n  bind :443\n"
    assert (tmp_path / "base/nginx/nginx.conf").read_text(encoding="utf-8") == "events {}\nhttp {}\n"
    assert reload_calls == [["reload-haproxy", "reload-nginx"]]
    assert "base_sync=haproxy,nginx" in msg
    assert "reconciled=haproxy,nginx" in msg


def test_handle_apply_bundle_syncs_base_decoy_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: [])
    monkeypatch.setattr(handlers, "_run_reload_commands", lambda _settings, _cmds: pytest.fail("reloads should not run"))

    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_dry_run=False,
    )

    msg = handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-transit",
            "files": {
                "decoy/index.html": "<html>Tracegate</html>\n",
                "decoy/auth/index.html": "<html>Auth</html>\n",
            },
            "commands": [],
        },
    )

    assert (tmp_path / "base/decoy/index.html").read_text(encoding="utf-8") == "<html>Tracegate</html>\n"
    assert (tmp_path / "base/decoy/auth/index.html").read_text(encoding="utf-8") == "<html>Auth</html>\n"
    assert "base_sync=decoy" in msg


def test_handle_apply_bundle_syncs_binary_decoy_assets(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: [])
    monkeypatch.setattr(handlers, "_run_reload_commands", lambda _settings, _cmds: pytest.fail("reloads should not run"))

    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_dry_run=False,
    )

    msg = handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-transit",
            "files": {
                "decoy/assets/great-wave.jpg": {
                    "encoding": "base64",
                    "content": "/9j/dHJhY2VnYXRlLWpwZWc=",
                },
            },
            "commands": [],
        },
    )

    assert (tmp_path / "bundles/base-transit/decoy/assets/great-wave.jpg").read_bytes() == b"\xff\xd8\xfftracegate-jpeg"
    assert (tmp_path / "base/decoy/assets/great-wave.jpg").read_bytes() == b"\xff\xd8\xfftracegate-jpeg"
    assert "base_sync=decoy" in msg


def test_handle_apply_bundle_rejects_invalid_binary_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)

    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=False)

    with pytest.raises(handlers.HandlerError, match="invalid bundle files payload"):
        handlers.handle_apply_bundle(
            settings,
            {
                "bundle_name": "base-transit",
                "files": {
                    "decoy/assets/great-wave.jpg": {
                        "encoding": "base64",
                        "content": "%%%not-base64%%%",
                    },
                },
                "commands": [],
            },
        )


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


def test_handle_apply_bundle_skips_placeholder_service_configs(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: pytest.fail("reconcile_all should not run"))
    monkeypatch.setattr(handlers, "_run_reload_commands", lambda _settings, _cmds: pytest.fail("reloads should not run"))

    settings = Settings(agent_data_root=str(tmp_path), agent_dry_run=False)

    msg = handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-transit",
            "files": {
                "xray.json": '{"privateKey":"REPLACE_PRIVATE_KEY"}',
            },
            "commands": [],
        },
    )

    assert "base_sync=" not in msg
    assert not (tmp_path / "base/xray/config.json").exists()


def test_handle_apply_bundle_xray_centric_skips_hysteria_base_sync(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)

    reload_calls: list[list[str]] = []
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: ["xray"])
    monkeypatch.setattr(
        handlers,
        "_run_reload_commands",
        lambda _settings, cmds: reload_calls.append(list(cmds)),
    )

    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_dry_run=False,
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        agent_reload_xray_cmd="reload-xray",
    )

    msg = handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-transit",
            "files": {
                "xray.json": '{"inbounds":[],"outbounds":[]}',
            },
            "commands": [],
        },
    )

    assert (tmp_path / "base/xray/config.json").read_text(encoding="utf-8") == '{"inbounds":[],"outbounds":[]}'
    assert reload_calls == [["reload-xray"]]
    assert "base_sync=xray" in msg
    assert "reconciled=xray" in msg


def test_handle_apply_bundle_tracegate22_syncs_standalone_hysteria_base(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)

    reload_calls: list[list[str]] = []
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: ["hysteria"])
    monkeypatch.setattr(
        handlers,
        "_run_reload_commands",
        lambda _settings, cmds: reload_calls.append(list(cmds)),
    )

    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_dry_run=False,
        agent_role="TRANSIT",
        agent_runtime_profile="tracegate-2.2",
        agent_reload_hysteria_cmd="reload-hysteria",
    )

    msg = handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-transit",
            "files": {
                "hysteria/server.yaml": "listen: :4443\nobfs:\n  type: salamander\n",
            },
            "commands": [],
        },
    )

    assert (tmp_path / "base/hysteria/server.yaml").read_text(encoding="utf-8") == (
        "listen: :4443\nobfs:\n  type: salamander\n"
    )
    assert reload_calls == [["reload-hysteria"]]
    assert "base_sync=hysteria" in msg
    assert "reconciled=hysteria" in msg


def test_handle_apply_bundle_reload_includes_obfuscation_hook(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(handlers, "_apply_firewall_bundle", lambda *_args, **_kwargs: None)

    reload_calls: list[list[str]] = []
    monkeypatch.setattr(handlers, "reconcile_all", lambda _settings: ["xray", "obfuscation", "mtproto", "fronting"])
    monkeypatch.setattr(
        handlers,
        "_run_reload_commands",
        lambda _settings, cmds: reload_calls.append(list(cmds)),
    )

    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_dry_run=False,
        agent_role="TRANSIT",
        agent_runtime_profile="xray-centric",
        agent_reload_xray_cmd="reload-xray",
        agent_reload_obfuscation_cmd="reload-obfuscation",
        agent_reload_mtproto_cmd="reload-mtproto",
        agent_reload_fronting_cmd="reload-fronting",
    )

    msg = handlers.handle_apply_bundle(
        settings,
        {
            "bundle_name": "base-transit",
            "files": {
                "xray.json": '{"inbounds":[],"outbounds":[]}',
            },
            "commands": [],
        },
    )

    assert reload_calls == [["reload-xray", "reload-obfuscation", "reload-mtproto", "reload-fronting"]]
    assert "reconciled=fronting,mtproto,obfuscation,xray" in msg


def test_out_of_order_revoke_then_upsert_is_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # Avoid touching real reconcilers / reload hooks in this unit test.
    monkeypatch.setattr(
        handlers,
        "_reconcile_user_lifecycle_without_reload",
        lambda _settings: handlers.ReconcileAllResult(changed=[], force_xray_reload=False),
    )
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
    monkeypatch.setattr(
        handlers,
        "_reconcile_user_lifecycle_without_reload",
        lambda _settings: handlers.ReconcileAllResult(changed=[], force_xray_reload=False),
    )
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
