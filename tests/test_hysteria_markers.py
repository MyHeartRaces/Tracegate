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
        tg_id=255761416,
        connection_id="531ce66a-9265-477b-bfab-1dccf53bac6f",
    )

    assert out == "b3_255761416_531ce66a9265477bbfab1dccf53bac6f"


def test_parse_hysteria_username_accepts_legacy_and_ios_safe() -> None:
    legacy = "B4 - 255761416 - 3a709a5f-0efd-469d-a1e6-c74271451dba"
    ios = "b4_255761416_3a709a5f0efd469da1e6c74271451dba"

    assert parse_hysteria_username(legacy) == (
        "B4",
        "255761416",
        "3a709a5f-0efd-469d-a1e6-c74271451dba",
    )
    assert parse_hysteria_username(ios) == (
        "B4",
        "255761416",
        "3a709a5f-0efd-469d-a1e6-c74271451dba",
    )


def test_normalize_hysteria_connection_marker_converts_ios_safe_to_legacy_format() -> None:
    marker = "b3_255761416_531ce66a9265477bbfab1dccf53bac6f"
    assert normalize_hysteria_connection_marker(marker) == (
        "B3 - 255761416 - 531ce66a-9265-477b-bfab-1dccf53bac6f"
    )


def test_hysteria_auth_username_aliases_include_legacy_and_ios_safe() -> None:
    aliases = hysteria_auth_username_aliases(
        variant="B3",
        tg_id="255761416",
        connection_id="531ce66a-9265-477b-bfab-1dccf53bac6f",
    )
    assert aliases == {
        hysteria_legacy_username(
            variant="B3",
            tg_id="255761416",
            connection_id="531ce66a-9265-477b-bfab-1dccf53bac6f",
        ),
        hysteria_ios_safe_username(
            variant="B3",
            tg_id="255761416",
            connection_id="531ce66a-9265-477b-bfab-1dccf53bac6f",
        ),
    }
