"""Bot entry point (``tracegate-bot``): dispatcher wiring and the runners.

Handlers live in ``tracegate.bot.handlers``; strings in ``tracegate.bot.texts``.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.types import BotCommand, FSInputFile
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

from tracegate.bot import context as ctx
from tracegate.bot import nav, texts
from tracegate.bot.handlers import build_routers
from tracegate.bot.metrics import BotMetricsMiddleware, maybe_start_bot_metrics_server
from tracegate.bot.middleware import BotAccessMiddleware
from tracegate.bot.startup import delete_webhook_with_retry
from tracegate.observability import configure_logging

# Compatibility names used by tests outside the bot package.
from tracegate.bot.profiles import enabled_profile_specs as _enabled_profile_specs  # noqa: F401
from tracegate.bot.profiles import profile as _profile  # noqa: F401
from tracegate.bot.profiles import profile_key as _profile_key  # noqa: F401
from tracegate.bot.texts import MTPROTO_UPDATE_TELEGRAM_HINT  # noqa: F401
from tracegate.bot.texts import format_mtproto_link_message as _format_mtproto_link_message  # noqa: F401

logger = logging.getLogger("tracegate.bot")

settings = ctx.settings
api = ctx.api


def build_dispatcher() -> Dispatcher:
    dp = Dispatcher()
    metrics_mw = BotMetricsMiddleware()
    access_mw = BotAccessMiddleware()
    answer_mw = nav.CallbackAnswerFirstMiddleware()
    dp.message.middleware(metrics_mw)
    dp.callback_query.middleware(metrics_mw)
    dp.message.middleware(access_mw)
    dp.callback_query.middleware(access_mw)
    dp.callback_query.middleware(answer_mw)
    dp.errors.register(nav.on_error)
    for router in build_routers():
        dp.include_router(router)
    return dp


async def set_bot_commands(bot: Bot) -> None:
    """Publish the command menu. Best-effort: never blocks startup."""

    try:
        await bot.set_my_commands(
            [BotCommand(command=command, description=description) for command, description in texts.COMMANDS]
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("bot_set_my_commands_failed error=%s", type(exc).__name__)


def run() -> None:
    configure_logging(settings.log_level)
    if not settings.bot_token:
        raise RuntimeError("BOT_TOKEN is required")
    if not settings.bot_api_token:
        raise RuntimeError("BOT_API_TOKEN is required")
    if not settings.bot_api_base_url:
        raise RuntimeError("BOT_API_BASE_URL is required")
    maybe_start_bot_metrics_server(
        enabled=bool(settings.bot_metrics_enabled),
        host=str(settings.bot_metrics_host),
        port=int(settings.bot_metrics_port),
    )

    mode = (settings.bot_mode or "polling").strip().lower()
    if mode == "webhook":
        _run_webhook()
    elif mode == "polling":
        asyncio.run(_run_polling())
    else:
        raise RuntimeError(f"Unsupported BOT_MODE={settings.bot_mode!r} (expected 'polling' or 'webhook')")


async def _run_polling() -> None:
    bot = Bot(token=settings.bot_token)
    dp = build_dispatcher()

    # Ensure webhook is disabled; otherwise Telegram rejects getUpdates.
    await delete_webhook_with_retry(bot, drop_pending_updates=True)
    await set_bot_commands(bot)
    try:
        await dp.start_polling(bot)
    finally:
        await api.close()
        await bot.session.close()


def _run_webhook() -> None:
    bot = Bot(token=settings.bot_token)
    dp = build_dispatcher()

    path = settings.bot_webhook_path or "/"
    if not path.startswith("/"):
        path = "/" + path
    secret_token = settings.bot_webhook_secret_token or None

    public_url = settings.bot_webhook_public_url.strip()
    if not public_url:
        base = settings.bot_webhook_public_base_url.strip()
        if not base:
            raise RuntimeError("BOT_WEBHOOK_PUBLIC_URL or BOT_WEBHOOK_PUBLIC_BASE_URL is required for webhook mode")
        public_url = base.rstrip("/") + path

    tls_cert = Path(settings.bot_webhook_tls_cert)
    tls_key = Path(settings.bot_webhook_tls_key)
    if not tls_cert.exists() or not tls_key.exists():
        raise RuntimeError(
            "Webhook TLS files are missing. "
            f"Expected cert={tls_cert} key={tls_key} (configure BOT_WEBHOOK_TLS_CERT/BOT_WEBHOOK_TLS_KEY)"
        )

    app = web.Application()
    SimpleRequestHandler(dispatcher=dp, bot=bot, secret_token=secret_token).register(app, path=path)
    setup_application(app, dp, bot=bot)

    async def on_startup(_: web.Application) -> None:
        cert_file = FSInputFile(str(tls_cert)) if settings.bot_webhook_upload_cert else None
        await bot.set_webhook(
            url=public_url,
            secret_token=secret_token,
            certificate=cert_file,
            drop_pending_updates=True,
        )
        await set_bot_commands(bot)

    async def on_shutdown(_: web.Application) -> None:
        await bot.delete_webhook(drop_pending_updates=False)
        await api.close()
        await bot.session.close()

    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=str(tls_cert), keyfile=str(tls_key))

    web.run_app(
        app,
        host=settings.bot_webhook_listen_host,
        port=settings.bot_webhook_listen_port,
        ssl_context=ssl_context,
        access_log=None,
    )


if __name__ == "__main__":
    run()
