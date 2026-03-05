from __future__ import annotations

from datetime import datetime, timedelta, timezone

MAX_TIMED_BOT_BLOCK_HOURS = 9998
PERMANENT_BOT_BLOCK_HOURS = 9999
PERMANENT_BOT_BLOCK_UNTIL = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


def is_permanent_bot_block_hours(hours: int) -> bool:
    return int(hours) == PERMANENT_BOT_BLOCK_HOURS


def compute_bot_block_until(now: datetime, *, hours: int) -> datetime:
    if is_permanent_bot_block_hours(hours):
        return PERMANENT_BOT_BLOCK_UNTIL
    return now + timedelta(hours=int(hours))


def is_permanent_bot_block_until(until: datetime | None) -> bool:
    return until is not None and until >= PERMANENT_BOT_BLOCK_UNTIL
