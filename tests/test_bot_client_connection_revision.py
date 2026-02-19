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
                    protocol=ConnectionProtocol.WIREGUARD,
                    mode=ConnectionMode.DIRECT,
                    variant=ConnectionVariant.B5,
                    sni_id=None,
                    custom_overrides_json=None,
                )
            )
    finally:
        asyncio.run(client.close())

    assert ("DELETE", "/connections/conn-1") in calls
