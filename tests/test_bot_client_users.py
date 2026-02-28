import asyncio

from tracegate.bot.client import TracegateApiClient


def test_list_users_uses_default_filters() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str, dict]] = []

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path, kwargs))
        return []

    client._request = fake_request  # type: ignore[method-assign]
    try:
        asyncio.run(client.list_users(limit=300))
    finally:
        asyncio.run(client.close())

    method, path, kwargs = calls[0]
    assert method == "GET"
    assert path == "/users"
    assert kwargs["params"] == {"limit": "300"}


def test_list_users_can_include_and_prune_empty() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str, dict]] = []

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path, kwargs))
        return []

    client._request = fake_request  # type: ignore[method-assign]
    try:
        asyncio.run(
            client.list_users(
                role="user",
                limit=1000,
                blocked_only=True,
                include_empty=True,
                prune_empty=False,
            )
        )
    finally:
        asyncio.run(client.close())

    _method, _path, kwargs = calls[0]
    assert kwargs["params"] == {
        "limit": "1000",
        "role": "user",
        "blocked_only": "true",
        "include_empty": "true",
        "prune_empty": "false",
    }
