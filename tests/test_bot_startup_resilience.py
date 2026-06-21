import pytest
from aiogram.exceptions import TelegramNetworkError

from tracegate.bot import startup as bot_startup


class _DummyMethod:
    __api_method__ = "deleteWebhook"


@pytest.mark.asyncio
async def test_delete_webhook_with_retry_recovers(monkeypatch):
    class _Bot:
        def __init__(self):
            self.calls = 0

        async def delete_webhook(self, *, drop_pending_updates):
            self.calls += 1
            if self.calls == 1:
                raise TelegramNetworkError(method=_DummyMethod(), message="dns timeout")
            return True

    sleeps = []

    async def _fake_sleep(value):
        sleeps.append(value)

    monkeypatch.setattr(bot_startup.asyncio, "sleep", _fake_sleep)

    bot = _Bot()
    await bot_startup.delete_webhook_with_retry(
        bot,
        drop_pending_updates=True,
        attempts=3,
        base_delay_seconds=0.1,
    )
    assert bot.calls == 2
    assert sleeps == [0.1]


@pytest.mark.asyncio
async def test_delete_webhook_with_retry_raises_after_exhausted(monkeypatch):
    class _Bot:
        async def delete_webhook(self, *, drop_pending_updates):
            raise TelegramNetworkError(method=_DummyMethod(), message="dns timeout")

    sleeps = []

    async def _fake_sleep(value):
        sleeps.append(value)

    monkeypatch.setattr(bot_startup.asyncio, "sleep", _fake_sleep)

    with pytest.raises(TelegramNetworkError):
        await bot_startup.delete_webhook_with_retry(
            _Bot(),
            drop_pending_updates=True,
            attempts=3,
            base_delay_seconds=0.1,
        )
    assert sleeps == [0.1, 0.2]
