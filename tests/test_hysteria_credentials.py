import pytest

from tracegate.services.hysteria_credentials import (
    HysteriaAuthModeError,
    build_hysteria_auth_payload,
    build_hysteria_opaque_token_value,
    build_hysteria_token_value,
    normalize_hysteria_auth_mode,
)


def test_hysteria_userpass_payload_keeps_username_password_and_token() -> None:
    payload = build_hysteria_auth_payload(
        auth_mode="userpass",
        variant="V4",
        tg_id=42,
        connection_id="11111111-2222-4333-8444-555555555555",
        device_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )

    assert payload["type"] == "userpass"
    assert payload["username"].startswith("v4_42_")
    assert payload["password"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert payload["token"] == payload["username"] + ":aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert payload["client_id"] == payload["username"]


def test_hysteria_token_payload_uses_single_token_field() -> None:
    payload = build_hysteria_auth_payload(
        auth_mode="token",
        variant="V3",
        tg_id=7,
        connection_id="11111111-2222-4333-8444-555555555555",
        device_id="device-1",
    )

    assert payload == {
        "type": "token",
        "token": payload["client_id"] + "-device1",
        "client_id": payload["client_id"],
    }
    assert payload["client_id"].startswith("v3_7_")


def test_hysteria_opaque_token_value_is_uri_safe() -> None:
    token = build_hysteria_opaque_token_value(
        username="v3_7_11111111222243338444555555555555",
        password="device-1",
    )
    assert token == "v3_7_11111111222243338444555555555555-device1"
    assert ":" not in token


def test_hysteria_auth_mode_validation() -> None:
    assert normalize_hysteria_auth_mode("") == "userpass"
    assert normalize_hysteria_auth_mode("token") == "token"

    with pytest.raises(HysteriaAuthModeError, match="unsupported hysteria auth mode"):
        normalize_hysteria_auth_mode("custom")

    with pytest.raises(HysteriaAuthModeError, match="username and password are required"):
        build_hysteria_token_value(username="", password="x")
