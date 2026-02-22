from tracegate.services.hysteria_markers import (
    hysteria_auth_username_aliases,
    hysteria_ios_safe_username,
    hysteria_legacy_username,
    normalize_hysteria_connection_marker,
    parse_hysteria_username,
)


def test_hysteria_ios_safe_username_is_compact_and_stable() -> None:
    out = hysteria_ios_safe_username(
        variant="B3",
        tg_id=123456789,
        connection_id="11111111-2222-4333-8444-555555555555",
    )

    assert out == "b3_123456789_11111111222243338444555555555555"


def test_parse_hysteria_username_accepts_legacy_and_ios_safe() -> None:
    legacy = "B4 - 123456789 - aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    ios = "b4_123456789_aaaaaaaabbbb4ccc8dddeeeeeeeeeeee"

    assert parse_hysteria_username(legacy) == (
        "B4",
        "123456789",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    )
    assert parse_hysteria_username(ios) == (
        "B4",
        "123456789",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    )


def test_normalize_hysteria_connection_marker_converts_ios_safe_to_legacy_format() -> None:
    marker = "b3_123456789_11111111222243338444555555555555"
    assert normalize_hysteria_connection_marker(marker) == (
        "B3 - 123456789 - 11111111-2222-4333-8444-555555555555"
    )


def test_hysteria_auth_username_aliases_include_legacy_and_ios_safe() -> None:
    aliases = hysteria_auth_username_aliases(
        variant="B3",
        tg_id="123456789",
        connection_id="11111111-2222-4333-8444-555555555555",
    )
    assert aliases == {
        hysteria_legacy_username(
            variant="B3",
            tg_id="123456789",
            connection_id="11111111-2222-4333-8444-555555555555",
        ),
        hysteria_ios_safe_username(
            variant="B3",
            tg_id="123456789",
            connection_id="11111111-2222-4333-8444-555555555555",
        ),
    }
