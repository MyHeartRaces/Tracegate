from tracegate.enums import UserRole
from tracegate.services.user_roles import can_manage_user, normalize_user_role


def test_normalize_user_role_supports_enum_and_string() -> None:
    assert normalize_user_role(UserRole.ADMIN) == "admin"
    assert normalize_user_role("SUPERADMIN") == "superadmin"


def test_can_manage_user_blocks_superadmin_target() -> None:
    assert not can_manage_user(actor_role="superadmin", target_role="superadmin")
    assert not can_manage_user(actor_role="admin", target_role="superadmin")


def test_can_manage_user_allows_superadmin_over_admin_and_user() -> None:
    assert can_manage_user(actor_role="superadmin", target_role="admin")
    assert can_manage_user(actor_role="superadmin", target_role="user")


def test_can_manage_user_restricts_admin_to_regular_user() -> None:
    assert can_manage_user(actor_role="admin", target_role="user")
    assert not can_manage_user(actor_role="admin", target_role="admin")
