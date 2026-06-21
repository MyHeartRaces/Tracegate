from __future__ import annotations

from datetime import datetime, timezone

from tracegate.enums import EntitlementStatus
from tracegate.models import User


class GraceError(PermissionError):
    pass


def ensure_can_issue_new_config(user: User, force: bool = False) -> None:
    if force:
        return

    if user.entitlement_status == EntitlementStatus.BLOCKED:
        raise GraceError("User entitlement is blocked")

    if user.entitlement_status == EntitlementStatus.GRACE:
        now = datetime.now(timezone.utc)
        if user.grace_ends_at is None or user.grace_ends_at >= now:
            raise GraceError("Grace period allows existing configs only; issuing new revisions is blocked")
