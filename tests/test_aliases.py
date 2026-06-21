from tracegate.services.aliases import connection_alias, user_display


def test_user_display_prefers_username() -> None:
    assert user_display(telegram_id=123, telegram_username="alice") == "@alice (123)"


def test_user_display_falls_back_to_full_name() -> None:
    assert user_display(telegram_id=123, telegram_username=None, telegram_first_name="Alice", telegram_last_name="Doe") == "Alice Doe (123)"


def test_connection_alias_contains_user_device_connection() -> None:
    alias = connection_alias(
        telegram_id=123,
        telegram_username="alice",
        device_name="MacBook",
        connection_id="00000000-0000-0000-0000-000000000001",
    )
    assert alias == "@alice (123) - MacBook - 00000000-0000-0000-0000-000000000001"
