from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from tracegate.schemas import UserBotBlockUpdate
from tracegate.services.bot_blocks import (
    MAX_TIMED_BOT_BLOCK_HOURS,
    PERMANENT_BOT_BLOCK_HOURS,
    PERMANENT_BOT_BLOCK_UNTIL,
    compute_bot_block_until,
    is_permanent_bot_block_until,
)


def test_user_bot_block_update_accepts_max_timed_hours() -> None:
    payload = UserBotBlockUpdate(hours=MAX_TIMED_BOT_BLOCK_HOURS)
    assert payload.hours == MAX_TIMED_BOT_BLOCK_HOURS


def test_user_bot_block_update_accepts_permanent_hours() -> None:
    payload = UserBotBlockUpdate(hours=PERMANENT_BOT_BLOCK_HOURS)
    assert payload.hours == PERMANENT_BOT_BLOCK_HOURS


def test_user_bot_block_update_rejects_hours_over_permanent() -> None:
    with pytest.raises(ValidationError):
        UserBotBlockUpdate(hours=PERMANENT_BOT_BLOCK_HOURS + 1)


def test_compute_bot_block_until_for_timed_block() -> None:
    now = datetime(2026, 3, 5, 10, 0, tzinfo=timezone.utc)
    until = compute_bot_block_until(now, hours=72)
    assert until == now + timedelta(hours=72)
    assert not is_permanent_bot_block_until(until)


def test_compute_bot_block_until_for_permanent_block() -> None:
    now = datetime(2026, 3, 5, 10, 0, tzinfo=timezone.utc)
    until = compute_bot_block_until(now, hours=PERMANENT_BOT_BLOCK_HOURS)
    assert until == PERMANENT_BOT_BLOCK_UNTIL
    assert is_permanent_bot_block_until(until)
