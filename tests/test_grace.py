from datetime import datetime, timedelta, timezone

import pytest

from tracegate.enums import EntitlementStatus
from tracegate.models import User
from tracegate.services.grace import GraceError, ensure_can_issue_new_config


def _user(status: EntitlementStatus, grace_ends_at):
    return User(
        telegram_id=123,
        devices_max=5,
        entitlement_status=status,
        grace_ends_at=grace_ends_at,
    )


def test_grace_blocks_new_revision() -> None:
    user = _user(EntitlementStatus.GRACE, datetime.now(timezone.utc) + timedelta(days=2))
    with pytest.raises(GraceError):
        ensure_can_issue_new_config(user, force=False)


def test_force_allows_in_grace() -> None:
    user = _user(EntitlementStatus.GRACE, datetime.now(timezone.utc) + timedelta(days=2))
    ensure_can_issue_new_config(user, force=True)
