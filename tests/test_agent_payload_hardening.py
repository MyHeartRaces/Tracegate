"""Agent payload hardening (CodeQL py/path-injection and py/command-line-injection).

Dispatcher payloads are trusted only as data: identifiers that become file or
directory names must be plain names, and the agent never executes shell
commands carried in a payload.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from tracegate.agent import handlers
from tracegate.agent.system import atomic_write
from tracegate.services.decoy_auth import sanitize_github_repo_html
from tracegate.services.private_handoffs import _write_secret_text_if_changed
from tracegate.settings import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(agent_data_root=str(tmp_path / "agent"), agent_dry_run=True)


@pytest.mark.parametrize("bad", ["../escape", "..", "a/b", "/etc", "", " ", "x" * 200, "a\\b", ".hidden"])
def test_safe_component_rejects_path_like_values(bad: str) -> None:
    with pytest.raises(handlers.HandlerError):
        handlers._safe_component(bad, "user_id")


@pytest.mark.parametrize("good", ["123456789", "base-entry", "3f2c1e9a-0b6d-4c1e-9f7a-2d8b6c5e4a10", "a_b.c"])
def test_safe_component_accepts_dispatcher_identifiers(good: str) -> None:
    assert handlers._safe_component(good, "id") == good


def test_apply_bundle_refuses_payload_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[str] = []
    monkeypatch.setattr(handlers, "run_command", lambda cmd, dry_run: executed.append(cmd) or (True, ""))

    with pytest.raises(handlers.HandlerError, match="commands are not accepted"):
        handlers.handle_apply_bundle(
            _settings(tmp_path),
            {"bundle_name": "custom", "files": {}, "commands": ["touch /tmp/pwned"]},
        )
    assert executed == []


def test_apply_bundle_refuses_a_traversing_bundle_name(tmp_path: Path) -> None:
    with pytest.raises(handlers.HandlerError, match="invalid bundle_name"):
        handlers.handle_apply_bundle(_settings(tmp_path), {"bundle_name": "../../outside", "files": {"x": "y"}})
    assert not (tmp_path / "outside").exists()


def test_revoke_user_never_removes_outside_the_users_directory(tmp_path: Path) -> None:
    victim = tmp_path / "agent" / "keep"
    victim.mkdir(parents=True)

    with pytest.raises(handlers.HandlerError, match="invalid user_id"):
        handlers.handle_revoke_user(_settings(tmp_path), {"user_id": "../keep"})
    assert victim.is_dir()


def test_revoke_connection_rejects_traversing_ids(tmp_path: Path) -> None:
    with pytest.raises(handlers.HandlerError, match="invalid connection_id"):
        handlers.handle_revoke_connection(_settings(tmp_path), {"user_id": "42", "connection_id": "../../x"})


def test_upsert_user_rejects_traversing_ids(tmp_path: Path) -> None:
    payload = {"user_id": "../../x", "connection_id": "c1", "revision_id": "r1", "config": {}}
    with pytest.raises(handlers.HandlerError, match="invalid user_id"):
        handlers.handle_upsert_user(_settings(tmp_path), payload)


@pytest.mark.parametrize("relative", ["../outside.txt", "/etc/passwd", ".", "a/../../outside.txt"])
def test_atomic_write_stays_inside_root(tmp_path: Path, relative: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ValueError):
        atomic_write(root, relative, "data")
    assert not (tmp_path / "outside.txt").exists()


def test_atomic_write_writes_nested_files(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    atomic_write(root, "a/b.txt", "data")
    assert (root / "a" / "b.txt").read_text() == "data"


def test_secret_text_is_never_world_readable(tmp_path: Path) -> None:
    old = os.umask(0o022)
    try:
        target = tmp_path / "secret.txt"
        assert _write_secret_text_if_changed(target, "s3cret")
    finally:
        os.umask(old)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text() == "s3cret"


@pytest.mark.parametrize(
    "script",
    ["<script>alert(1)</script >", "<script>alert(1)</SCRIPT foo>", "<script type=x>alert(1)", "<ScRiPt>alert(1)</script>"],
)
def test_github_mirror_sanitizer_drops_script_variants(script: str) -> None:
    html = sanitize_github_repo_html(
        f"<html><head>{script}</head><body>ok</body></html>",
        repo_url="https://github.com/example/repo",
    )
    assert "alert(1)" not in html


def test_run_args_never_goes_through_a_shell() -> None:
    from tracegate.agent.system import run_args

    ok, out = run_args(["echo", "$(id); `id` | id"], False)
    assert ok
    assert out == "$(id); `id` | id"


def test_firewall_bundle_passes_the_config_path_as_one_argument(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(handlers, "run_args", lambda args, dry_run: calls.append(list(args)) or (True, ""))
    monkeypatch.setattr(handlers, "run_command", lambda cmd, dry_run: (True, ""))

    handlers.handle_apply_bundle(
        Settings(agent_data_root=str(tmp_path / "agent"), agent_dry_run=False),
        {"bundle_name": "base-entry", "files": {"nftables.conf": "flush ruleset\n"}},
    )

    # nft reads a fixed agent-owned copy, never a path built from the request.
    conf = str(tmp_path / "agent" / "runtime" / "firewall" / "bundle-nftables.conf")
    assert calls == [["nft", "-c", "-f", conf], ["nft", "-f", conf]]


@pytest.mark.parametrize("parts", [("..", "x"), ("/etc", "passwd"), ("a", "..", "..", "x"), (".",)])
def test_contained_path_refuses_escapes_and_the_root_itself(tmp_path: Path, parts: tuple[str, ...]) -> None:
    from tracegate.agent.system import contained_path

    with pytest.raises(ValueError):
        contained_path(tmp_path, *parts)


def test_contained_path_refuses_symlink_escape(tmp_path: Path) -> None:
    from tracegate.agent.system import contained_path

    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(tmp_path)
    with pytest.raises(ValueError):
        contained_path(root, "link", "outside.txt")
