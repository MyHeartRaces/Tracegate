import asyncio

from tracegate.bot.client import TracegateApiClient


def test_issue_mtproto_access_uses_issue_endpoint() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str, dict]] = []

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path, kwargs))
        return {"ok": True}

    client._request = fake_request  # type: ignore[method-assign]
    try:
        asyncio.run(
            client.issue_mtproto_access(
                telegram_id=101,
                label="@user101",
                rotate=True,
                issued_by="bot",
            )
        )
    finally:
        asyncio.run(client.close())

    method, path, kwargs = calls[0]
    assert method == "POST"
    assert path == "/mtproto/access/issue"
    assert kwargs["json"] == {
        "telegram_id": 101,
        "label": "@user101",
        "rotate": True,
        "issued_by": "bot",
    }


def test_revoke_mtproto_access_uses_delete_endpoint() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str, dict]] = []

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path, kwargs))
        return {"removed": True}

    client._request = fake_request  # type: ignore[method-assign]
    try:
        asyncio.run(client.revoke_mtproto_access(101))
    finally:
        asyncio.run(client.close())

    method, path, _kwargs = calls[0]
    assert method == "DELETE"
    assert path == "/mtproto/access/101"


def test_get_mtproto_access_uses_user_endpoint() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str, dict]] = []

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path, kwargs))
        return {"telegram_id": 101}

    client._request = fake_request  # type: ignore[method-assign]
    try:
        asyncio.run(client.get_mtproto_access(101))
    finally:
        asyncio.run(client.close())

    method, path, _kwargs = calls[0]
    assert method == "GET"
    assert path == "/mtproto/access/by-user/101"
