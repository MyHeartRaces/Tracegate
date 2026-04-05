from __future__ import annotations

from tracegate.enums import UserRole


def normalize_user_role(role: UserRole | str | None) -> str:
    if isinstance(role, UserRole):
        return role.value
    return str(role or "").strip().lower()


def can_manage_user(*, actor_role: UserRole | str | None, target_role: UserRole | str | None) -> bool:
    actor = normalize_user_role(actor_role)
    target = normalize_user_role(target_role)
    if target == UserRole.SUPERADMIN.value:
        return False
    if actor == UserRole.SUPERADMIN.value:
        return True
    if actor == UserRole.ADMIN.value:
        return target == UserRole.USER.value
    return False
