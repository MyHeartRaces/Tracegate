import pytest

from tracegate.agent import xray_api
from tracegate.settings import Settings
from xray.proxy.hysteria.account import config_pb2 as hysteria_account_pb2
from xray.proxy.vless import account_pb2 as vless_account_pb2


def test_build_vless_user_packs_vless_account() -> None:
    user = xray_api._build_vless_user(email="V1 - 1 - c1", uuid="11111111-1111-4111-8111-111111111111")

    account = vless_account_pb2.Account()
    account.ParseFromString(user.account.value)

    assert user.email == "V1 - 1 - c1"
    assert user.account.type == "xray.proxy.vless.Account"
    assert account.id == "11111111-1111-4111-8111-111111111111"
    assert account.encryption == "none"


def test_build_hysteria_user_packs_hysteria_account() -> None:
    user = xray_api._build_hysteria_user(email="V3 - 1 - c2", auth="hy2-token-value")

    account = hysteria_account_pb2.Account()
    account.ParseFromString(user.account.value)

    assert user.email == "V3 - 1 - c2"
    assert user.account.type == "xray.proxy.hysteria.account.Account"
    assert account.auth == "hy2-token-value"


def test_xray_api_target_accepts_loopback_addresses() -> None:
    assert xray_api._require_loopback_xray_api_target(Settings(agent_xray_api_server="127.0.0.1:8080")) == "127.0.0.1:8080"
    assert xray_api._require_loopback_xray_api_target(Settings(agent_xray_api_server="[::1]:8080")) == "[::1]:8080"
    assert xray_api._require_loopback_xray_api_target(Settings(agent_xray_api_server="unix:///run/xray/api.sock")) == "unix:///run/xray/api.sock"


def test_xray_api_target_rejects_remote_addresses() -> None:
    with pytest.raises(xray_api.XrayApiError, match="loopback-bound"):
        xray_api._require_loopback_xray_api_target(Settings(agent_xray_api_server="10.0.0.10:8080"))


def test_sync_inbound_users_dispatches_vless_add_and_remove(monkeypatch) -> None:
    calls: list[tuple[str, str, str]] = []
    removals: list[tuple[str, str]] = []

    monkeypatch.setattr(xray_api, "list_inbound_user_emails", lambda _settings, *, inbound_tag: {"old@example"})
    monkeypatch.setattr(
        xray_api,
        "add_vless_user",
        lambda _settings, *, inbound_tag, email, uuid: calls.append((inbound_tag, email, uuid)),
    )
    monkeypatch.setattr(
        xray_api,
        "add_hysteria_user",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected hysteria add")),
    )
    monkeypatch.setattr(
        xray_api,
        "remove_user",
        lambda _settings, *, inbound_tag, email: removals.append((inbound_tag, email)),
    )

    changed = xray_api.sync_inbound_users(
        Settings(),
        inbound_tag="vless-reality-in",
        desired_email_to_user={"new@example": {"protocol": "vless", "uuid": "vless-uuid"}},
    )

    assert changed is True
    assert calls == [("vless-reality-in", "new@example", "vless-uuid")]
    assert removals == [("vless-reality-in", "old@example")]


def test_sync_inbound_users_dispatches_hysteria_add(monkeypatch) -> None:
    calls: list[tuple[str, str, str]] = []
    removals: list[tuple[str, str]] = []

    monkeypatch.setattr(xray_api, "list_inbound_user_emails", lambda _settings, *, inbound_tag: set())
    monkeypatch.setattr(
        xray_api,
        "add_vless_user",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected vless add")),
    )
    monkeypatch.setattr(
        xray_api,
        "add_hysteria_user",
        lambda _settings, *, inbound_tag, email, auth: calls.append((inbound_tag, email, auth)),
    )
    monkeypatch.setattr(
        xray_api,
        "remove_user",
        lambda _settings, *, inbound_tag, email: removals.append((inbound_tag, email)),
    )

    changed = xray_api.sync_inbound_users(
        Settings(),
        inbound_tag="hy2-in",
        desired_email_to_user={"V3 - 1 - c2": {"protocol": "hysteria", "auth": "hy2-token-value"}},
    )

    assert changed is True
    assert calls == [("hy2-in", "V3 - 1 - c2", "hy2-token-value")]
    assert removals == []
