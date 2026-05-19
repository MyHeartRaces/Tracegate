import pytest

from tracegate.services.client_config_tokens import (
    ClientConfigTokenError,
    build_client_config_token,
    parse_client_config_token,
)


def test_client_config_token_round_trip_device_subject() -> None:
    token = build_client_config_token(
        subject_type="device",
        subject_id="dev-1",
        secret="secret-key",
    )

    assert parse_client_config_token(token, secret="secret-key") == {
        "subject_type": "device",
        "subject_id": "dev-1",
    }


def test_client_config_token_rejects_tampering() -> None:
    token = build_client_config_token(
        subject_type="revision",
        subject_id="rev-1",
        secret="secret-key",
    )
    data, sig = token.split(".", 1)
    tampered = f"{data}x.{sig}"

    with pytest.raises(ClientConfigTokenError, match="signature"):
        parse_client_config_token(tampered, secret="secret-key")


def test_client_config_token_requires_supported_subject() -> None:
    with pytest.raises(ClientConfigTokenError, match="subject_type"):
        build_client_config_token(subject_type="connection", subject_id="conn-1", secret="secret-key")


def test_client_config_token_requires_secret() -> None:
    with pytest.raises(ClientConfigTokenError, match="secret"):
        build_client_config_token(subject_type="device", subject_id="dev-1", secret="")
