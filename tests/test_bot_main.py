from __future__ import annotations

from types import SimpleNamespace

import pytest

import test_bot_support  # noqa: F401
from tracegate.bot import main, nav, texts
from tracegate.bot.middleware import BotAccessMiddleware


def test_dispatcher_wiring_routers_middlewares_and_error_handler() -> None:
    dp = main.build_dispatcher()
    names = [router.name for router in dp.sub_routers]
    assert names == ["start", "guide", "admin", "devices", "connections", "mtproto", "feedback", "fallback"]
    callback_middlewares = [type(mw) for mw in dp.callback_query.middleware]
    assert callback_middlewares.index(BotAccessMiddleware) < callback_middlewares.index(
        nav.CallbackAnswerFirstMiddleware
    )
    assert nav.CallbackAnswerFirstMiddleware not in [type(mw) for mw in dp.message.middleware]
    assert any(handler.callback is nav.on_error for handler in dp.errors.handlers)


@pytest.mark.asyncio
async def test_set_bot_commands_publishes_russian_commands() -> None:
    published: list = []

    async def _set(commands):  # noqa: ANN001, ANN202
        published.extend(commands)

    await main.set_bot_commands(SimpleNamespace(set_my_commands=_set))
    assert [(c.command, c.description) for c in published] == [
        ("start", "Меню"),
        ("guide", "Инструкция"),
        ("cancel", "Отмена"),
    ]
    assert tuple((c.command, c.description) for c in published) == texts.COMMANDS


@pytest.mark.asyncio
async def test_polling_starts_even_when_set_my_commands_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    class _Session:
        async def close(self) -> None:
            events.append("session_closed")

    class _Bot:
        def __init__(self, token: str) -> None:
            self.session = _Session()

        async def set_my_commands(self, commands):  # noqa: ANN001, ANN202
            events.append("set_my_commands")
            raise RuntimeError("telegram unavailable")

    class _Dispatcher:
        async def start_polling(self, bot):  # noqa: ANN001, ANN202
            events.append("start_polling")

    async def _delete_webhook(bot, *, drop_pending_updates):  # noqa: ANN001, ANN202
        events.append("delete_webhook")

    async def _close() -> None:
        events.append("api_closed")

    monkeypatch.setattr(main, "Bot", _Bot)
    monkeypatch.setattr(main, "build_dispatcher", lambda: _Dispatcher())
    monkeypatch.setattr(main, "delete_webhook_with_retry", _delete_webhook)
    monkeypatch.setattr(main.api, "close", _close)
    await main._run_polling()
    assert events == ["delete_webhook", "set_my_commands", "start_polling", "api_closed", "session_closed"]


def test_compat_names_for_external_tests() -> None:
    assert main._profile_key("v1direct") == "reality"
    assert main._format_mtproto_link_message({"httpsUrl": "https://t.me/proxy?x"}).endswith(
        main.MTPROTO_UPDATE_TELEGRAM_HINT
    )
    from tracegate.bot import context as ctx

    assert main.settings is ctx.settings
    assert main.api is ctx.api


def test_main_module_is_wiring_only() -> None:
    from pathlib import Path

    source = Path(main.__file__).read_text(encoding="utf-8")
    assert "@router" not in source
    assert "callback_query(" not in source.replace("dp.callback_query", "")
    assert len(source.splitlines()) < 200
