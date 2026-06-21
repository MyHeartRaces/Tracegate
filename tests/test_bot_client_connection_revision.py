import asyncio
from uuid import uuid4

import pytest

from tracegate.bot.client import TracegateApiClient
from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant


def test_create_connection_and_revision_rolls_back_connection_on_revision_error() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str]] = []

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path))
        if method == "POST" and path == "/connections":
            return {"id": "conn-1"}
        if method == "POST" and path == "/revisions/by-connection/conn-1":
            raise RuntimeError("revision failed")
        if method == "DELETE" and path == "/connections/conn-1":
            return None
        raise AssertionError(f"unexpected request: {method} {path}")

    client._request = fake_request  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError, match="revision failed"):
            asyncio.run(
                client.create_connection_and_revision(
                    user_id=1,
                    device_id=uuid4(),
                    protocol=ConnectionProtocol.HYSTERIA2,
                    mode=ConnectionMode.DIRECT,
                    variant=ConnectionVariant.V3,
                    sni_id=None,
                    custom_overrides_json=None,
                )
            )
    finally:
        asyncio.run(client.close())

    assert ("DELETE", "/connections/conn-1") in calls


def test_create_connection_and_revision_forwards_local_socks_credential_overrides() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str, dict]] = []
    device_id = uuid4()
    overrides = {"local_socks_username": "incy-user", "local_socks_password": "incy-pass_01"}

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path, kwargs))
        if method == "POST" and path == "/connections":
            return {"id": "conn-1"}
        if method == "POST" and path == "/revisions/by-connection/conn-1":
            return {"id": "rev-1"}
        raise AssertionError(f"unexpected request: {method} {path}")

    client._request = fake_request  # type: ignore[method-assign]
    try:
        connection, revision = asyncio.run(
            client.create_connection_and_revision(
                user_id=1,
                device_id=device_id,
                protocol=ConnectionProtocol.VLESS_GRPC_TLS,
                mode=ConnectionMode.DIRECT,
                variant=ConnectionVariant.V1,
                sni_id=None,
                custom_overrides_json=overrides,
            )
        )
    finally:
        asyncio.run(client.close())

    assert connection == {"id": "conn-1"}
    assert revision == {"id": "rev-1"}
    connection_call = calls[0]
    assert connection_call[:2] == ("POST", "/connections")
    assert connection_call[2]["json"]["custom_overrides_json"] == overrides
