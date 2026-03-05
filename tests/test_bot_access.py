from tracegate.bot.access import blocked_message
from tracegate.services.bot_blocks import PERMANENT_BOT_BLOCK_UNTIL


def test_blocked_message_for_timed_block_includes_until_and_reason() -> None:
    text = blocked_message(
        {
            "bot_blocked_until": "2026-03-06T12:00:00+00:00",
            "bot_block_reason": "abuse",
        }
    )
    assert "временно ограничен до 2026-03-06T12:00:00+00:00" in text
    assert "Причина: abuse" in text


def test_blocked_message_for_permanent_block_mentions_permanent() -> None:
    text = blocked_message(
        {
            "bot_blocked_until": PERMANENT_BOT_BLOCK_UNTIL.isoformat(),
            "bot_block_reason": "fraud",
        }
    )
    assert "перманентно ограничен" in text
    assert "Причина: fraud" in text
