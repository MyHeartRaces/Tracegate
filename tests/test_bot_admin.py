from __future__ import annotations

import pytest

import test_bot_support  # noqa: F401
from test_bot_support import DummyBot, DummyCallback, DummyMessage, DummyState, FakeApi, callback_datas
from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import nav, texts
from tracegate.bot.admin_tools import parse_telegram_id, parse_user_block_request
from tracegate.bot.handlers import admin, feedback
from tracegate.bot.states import AdminFlow


async def _no_sleep(_seconds: float) -> None:
    return None


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> FakeApi:
    fake = FakeApi()
    fake.users[1]["role"] = "admin"
    fake.users[2] = {"telegram_id": 2, "role": "user", "telegram_username": "bob"}
    fake.users[3] = {"telegram_id": 3, "role": "superadmin"}
    monkeypatch.setattr(ctx, "api", fake)
    monkeypatch.setattr(ctx.settings, "superadmin_telegram_ids", [3])
    monkeypatch.setattr(ctx.settings, "admin_users_report_hidden_ids", [])
    monkeypatch.setattr(admin.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(feedback.asyncio, "sleep", _no_sleep)
    return fake


def _side_effects(api: FakeApi) -> list[str]:
    readonly = {"get_or_create_user", "get_user", "list_users", "list_mtproto_access"}
    return [name for name, _args, _kwargs in api.calls if name not in readonly]


# --------------------------------------------------------- permissions ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "handler",
    [
        admin.admin_menu,
        admin.admin_users,
        admin.admin_tgp,
        admin.admin_reset_ask,
        admin.admin_reset,
        admin.admin_revoke_access,
        admin.admin_block,
        admin.admin_unblock,
        admin.admin_tgp_revoke,
    ],
)
async def test_admin_callbacks_refuse_regular_users(api: FakeApi, handler) -> None:  # noqa: ANN001
    callback = DummyCallback("x", user_id=2)
    state = DummyState()
    await handler(callback, state)
    assert callback.message.screens == [texts.NO_RIGHTS]
    assert state.state is None
    assert not _side_effects(api)


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", [admin.admin_grant, admin.admin_ungrant, admin.admin_list])
async def test_superadmin_callbacks_refuse_admins(api: FakeApi, handler) -> None:  # noqa: ANN001
    callback = DummyCallback("x", user_id=1)
    await handler(callback, DummyState())
    assert callback.message.screens == [texts.SUPERADMIN_ONLY]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "flow_state", "text"),
    [
        (admin.receive_user_access_revoke_id, AdminFlow.waiting_for_user_access_revoke_id, "2"),
        (admin.receive_mtproto_revoke_id, AdminFlow.waiting_for_mtproto_revoke_id, "2"),
        (admin.receive_user_block, AdminFlow.waiting_for_user_block, "2 72 spam"),
        (admin.receive_user_unblock, AdminFlow.waiting_for_user_unblock, "2"),
        (admin.announce_text, AdminFlow.waiting_for_announce_text, "hello"),
        (admin.receive_admin_grant_id, AdminFlow.waiting_for_grant_id, "2"),
        (admin.receive_admin_revoke_id, AdminFlow.waiting_for_revoke_id, "2"),
    ],
)
async def test_fsm_handlers_recheck_role_on_every_message(api: FakeApi, handler, flow_state, text: str) -> None:  # noqa: ANN001
    # The actor was demoted after the prompt was shown.
    api.users[1]["role"] = "user"
    message = DummyMessage(text, user_id=1)
    state = DummyState(state=flow_state)
    await handler(message, state)
    assert message.sent_texts == [texts.NO_RIGHTS]
    assert state.state is None
    assert not _side_effects(api)


@pytest.mark.asyncio
async def test_grant_message_requires_superadmin(api: FakeApi) -> None:
    message = DummyMessage("2", user_id=1)
    state = DummyState(state=AdminFlow.waiting_for_grant_id)
    await admin.receive_admin_grant_id(message, state)
    assert message.sent_texts == [texts.SUPERADMIN_ONLY]
    assert not api.called("set_user_role")

    super_message = DummyMessage("2", user_id=3)
    await admin.receive_admin_grant_id(super_message, DummyState(state=AdminFlow.waiting_for_grant_id))
    assert api.called("set_user_role") == [((2, "admin"), {})]
    assert super_message.sent_texts == [texts.admin_role_granted(2)]


@pytest.mark.asyncio
async def test_ungrant_refuses_configured_superadmin(api: FakeApi) -> None:
    message = DummyMessage("3", user_id=3)
    await admin.receive_admin_revoke_id(message, DummyState(state=AdminFlow.waiting_for_revoke_id))
    assert message.sent_texts == [texts.ADMIN_CANT_REVOKE_SUPERADMIN]
    assert not api.called("set_user_role")


# ------------------------------------------------------ input validation ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "flow_state"),
    [
        (admin.receive_user_access_revoke_id, AdminFlow.waiting_for_user_access_revoke_id),
        (admin.receive_mtproto_revoke_id, AdminFlow.waiting_for_mtproto_revoke_id),
        (admin.receive_user_unblock, AdminFlow.waiting_for_user_unblock),
    ],
)
@pytest.mark.parametrize("text", ["abc", "12a", "-5", "0", "", "1 2"])
async def test_numeric_id_validation_is_russian_and_keeps_state(api: FakeApi, handler, flow_state, text: str) -> None:  # noqa: ANN001
    message = DummyMessage(text, user_id=1)
    state = DummyState(state=flow_state)
    await handler(message, state)
    assert message.sent_texts == [texts.ADMIN_BAD_ID]
    assert "invalid literal" not in message.sent_texts[0]
    assert state.state == flow_state
    assert callback_datas(message.last_keyboard()) == [cb.ADMIN]


@pytest.mark.asyncio
async def test_unknown_user_id_is_reported(api: FakeApi) -> None:
    message = DummyMessage("999", user_id=1)
    state = DummyState(state=AdminFlow.waiting_for_user_unblock)
    await admin.receive_user_unblock(message, state)
    assert message.sent_texts == [texts.ADMIN_USER_NOT_FOUND]
    assert state.state is None


@pytest.mark.parametrize(
    ("text", "default", "message"),
    [
        ("", None, texts.BLOCK_ERR_EMPTY),
        ("123", None, texts.BLOCK_ERR_FORMAT),
        ("abc 72", None, texts.BLOCK_ERR_BAD_ID),
        ("123 x", None, texts.BLOCK_ERR_BAD_HOURS),
        ("123 0", None, texts.BLOCK_ERR_HOURS_RANGE),
        ("123 10000", None, texts.BLOCK_ERR_HOURS_RANGE),
        ("abc", 5, texts.BLOCK_ERR_BAD_HOURS),
        ("72 " + "x" * 300, 5, texts.BLOCK_ERR_REASON_TOO_LONG),
    ],
)
def test_block_request_errors_are_russian(text: str, default: int | None, message: str) -> None:
    with pytest.raises(ValueError) as exc_info:
        parse_user_block_request(text, default_target_id=default)
    assert str(exc_info.value) == message


def test_block_request_accepts_permanent_and_timed() -> None:
    assert parse_user_block_request("42 9999") == (42, 9999, None)
    assert parse_user_block_request("1 спам", default_target_id=7) == (7, 1, "спам")
    assert parse_telegram_id(" 123 ") == 123
    assert parse_telegram_id("0") is None


@pytest.mark.asyncio
async def test_block_flow_bad_input_keeps_state_then_blocks_and_notifies(api: FakeApi) -> None:
    state = DummyState(state=AdminFlow.waiting_for_user_block)
    bad = DummyMessage("2 abc", user_id=1)
    await admin.receive_user_block(bad, state)
    assert bad.sent_texts == [texts.BLOCK_ERR_BAD_HOURS]
    assert state.state == AdminFlow.waiting_for_user_block

    bot = DummyBot()
    good = DummyMessage("2 72 спам", user_id=1, bot=bot)
    await admin.receive_user_block(good, state)
    assert api.called("block_user_bot")[0][1] == {"hours": 72, "reason": "спам", "revoke_access": True}
    assert bot.sent[0]["chat_id"] == 2
    assert bot.sent[0]["text"].startswith("⚠️ Администратор ограничил тебе доступ")
    assert good.sent_texts[0].startswith("✅ Блокировка применена.")


@pytest.mark.asyncio
async def test_block_admin_target_requires_superadmin(api: FakeApi) -> None:
    api.users[4] = {"telegram_id": 4, "role": "admin"}
    message = DummyMessage("4 1", user_id=1)
    await admin.receive_user_block(message, DummyState(state=AdminFlow.waiting_for_user_block))
    assert message.sent_texts == [texts.ADMIN_CANT_MANAGE]
    assert not api.called("block_user_bot")


# ------------------------------------------------------------- reports ---


@pytest.mark.asyncio
async def test_users_report_is_chunked_under_telegram_limit(api: FakeApi) -> None:
    for telegram_id in range(10, 200):
        api.users[telegram_id] = {
            "telegram_id": telegram_id,
            "role": "user",
            "telegram_username": f"user_with_a_rather_long_name_{telegram_id}",
        }
    callback = DummyCallback(cb.ADMIN_USERS, user_id=1)
    await admin.admin_users(callback, DummyState())
    chunks = callback.message.screens + callback.message.sent_texts
    assert len(callback.message.screens) == 1
    assert len(chunks) > 1
    assert all(len(chunk) <= 4096 for chunk in chunks)
    assert callback.message.screens[0].startswith("👥 Пользователи Tracegate:")
    assert callback_datas(callback.message.answers[-1][1]["reply_markup"]) == [cb.ADMIN, cb.MENU]


@pytest.mark.asyncio
async def test_admin_tgp_report_and_targeted_revoke(api: FakeApi) -> None:
    api.mtproto[2] = {"label": "@bob", "issued_by": "bot"}
    callback = DummyCallback(cb.ADMIN_TGP, user_id=1)
    await admin.admin_tgp(callback, DummyState())
    assert "@bob (2)" in callback.message.screens[0]

    prompt = DummyCallback(cb.ADMIN_TGP_REVOKE, user_id=1)
    state = DummyState()
    await admin.admin_tgp_revoke(prompt, state)
    assert state.state == AdminFlow.waiting_for_mtproto_revoke_id
    assert callback_datas(prompt.message.last_keyboard()) == [cb.ADMIN]

    message = DummyMessage("2", user_id=1)
    await admin.receive_mtproto_revoke_id(message, state)
    assert message.sent_texts == [texts.admin_tgp_revoked("@bob (2)")]
    again = DummyMessage("2", user_id=1)
    await admin.receive_mtproto_revoke_id(again, DummyState(state=AdminFlow.waiting_for_mtproto_revoke_id))
    assert again.sent_texts == [texts.ADMIN_TGP_NOT_FOUND]


@pytest.mark.asyncio
async def test_admin_api_error_shows_reference_without_body(api: FakeApi) -> None:
    from tracegate.bot.client import ApiClientError

    api.fail["list_mtproto_access"] = ApiClientError(status_code=502, path="/mtproto/access", detail="upstream secret")
    callback = DummyCallback(cb.ADMIN_TGP, user_id=1)
    await admin.admin_tgp(callback, DummyState())
    screen = callback.message.screens[0]
    assert screen.startswith(texts.ERR_ADMIN)
    assert "502" in screen
    assert "secret" not in screen and "/mtproto" not in screen


# --------------------------------------------------------------- flows ---


@pytest.mark.asyncio
async def test_revoke_access_flow_with_notification(api: FakeApi) -> None:
    state = DummyState()
    await admin.admin_revoke_access(DummyCallback(cb.ADMIN_REVOKE_ACCESS, user_id=1), state)
    message = DummyMessage("2", user_id=1)
    await admin.receive_user_access_revoke_id(message, state)
    assert state.state == AdminFlow.waiting_for_user_access_revoke_notify
    assert callback_datas(message.last_keyboard()) == [cb.ADMIN_NOTIFY_YES, cb.ADMIN_NOTIFY_NO, cb.ADMIN]

    callback = DummyCallback(cb.ADMIN_NOTIFY_YES, user_id=1)
    await admin.admin_revoke_notify(callback, state)
    assert api.called("revoke_user_access")[0][1] == {"actor_telegram_id": 1, "target_telegram_id": 2}
    assert callback.message.screens[0].startswith("✅ Доступ отозван у @bob (2).")
    assert callback.bot.sent[0]["chat_id"] == 2
    assert state.state is None


@pytest.mark.asyncio
async def test_revoke_access_notification_failure_is_reported(api: FakeApi) -> None:
    state = DummyState(
        state=AdminFlow.waiting_for_user_access_revoke_notify,
        data={"revoke_access_target_id": 2, "revoke_access_target_label": "@bob (2)"},
    )
    callback = DummyCallback(cb.ADMIN_NOTIFY_YES, user_id=1)
    callback.bot.fail_for.add(2)
    await admin.admin_revoke_notify(callback, state)
    assert texts.ADMIN_NOTIFY_FAILED in callback.message.screens[0]


@pytest.mark.asyncio
async def test_revoke_access_notify_without_session_is_expired(api: FakeApi) -> None:
    callback = DummyCallback(cb.ADMIN_NOTIFY_NO, user_id=1)
    await admin.admin_revoke_notify(callback, DummyState())
    assert callback.message.screens == [texts.ADMIN_SESSION_EXPIRED]
    assert not api.called("revoke_user_access")


@pytest.mark.asyncio
async def test_admin_menu_cancel_clears_state(api: FakeApi) -> None:
    state = DummyState(state=AdminFlow.waiting_for_user_block, data={"block_target_id": 2})
    callback = DummyCallback(cb.ADMIN, user_id=1)
    await admin.admin_menu(callback, state)
    assert state.state is None and state.data == {}
    assert callback.message.screens == [texts.ADMIN_MENU]


@pytest.mark.asyncio
async def test_feedback_block_sends_new_prompt_and_keeps_notification(api: FakeApi) -> None:
    callback = DummyCallback("feedback_block:2", user_id=1)
    state = DummyState()
    await admin.feedback_block(callback, state)
    assert callback.message.edits == []
    assert callback.message.sent_texts[0].startswith("🚫 Заблокировать автора: @bob (2)")
    assert state.state == AdminFlow.waiting_for_user_block
    assert state.data["block_target_id"] == 2

    message = DummyMessage("72 спам", user_id=1)
    await admin.receive_user_block(message, state)
    assert api.called("block_user_bot")[0][0] == (2,)


@pytest.mark.asyncio
async def test_global_reset_requires_confirmation(api: FakeApi) -> None:
    ask = DummyCallback(cb.ADMIN_RESET_ASK, user_id=1)
    await admin.admin_reset_ask(ask, DummyState())
    assert ask.message.screens == [texts.ADMIN_RESET_CONFIRM]
    assert not api.called("reset_all_connections")
    confirm = DummyCallback(cb.ADMIN_RESET, user_id=1)
    await admin.admin_reset(confirm, DummyState())
    assert confirm.message.screens == [texts.admin_reset_done(connections=3, tgp=1)]


@pytest.mark.asyncio
async def test_announce_flow(api: FakeApi) -> None:
    command = DummyMessage("/announce", user_id=1)
    state = DummyState()
    await admin.announce(command, state)
    assert state.state == AdminFlow.waiting_for_announce_text
    bot = DummyBot()
    bot.fail_for.add(3)
    text = DummyMessage("Плановые работы", user_id=1, bot=bot)
    await admin.announce_text(text, state)
    assert sorted(row["chat_id"] for row in bot.sent) == [1, 2]
    assert text.sent_texts == [texts.admin_announce_done(sent=2, failed=1)]


@pytest.mark.asyncio
async def test_admin_list_for_superadmin(api: FakeApi) -> None:
    callback = DummyCallback(cb.ADMIN_LIST, user_id=3)
    await admin.admin_list(callback, DummyState())
    screen = callback.message.screens[0]
    assert screen.startswith("👑 Суперадмины")
    assert "@alice (1)" in screen


def test_split_text_respects_limit() -> None:
    text = "\n".join("строка " * 20 for _ in range(500))
    chunks = nav.split_text(text, limit=1000)
    assert all(len(chunk) <= 1000 for chunk in chunks)
    assert " ".join(chunks).split() == text.split()
