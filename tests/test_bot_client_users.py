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


def test_revoke_user_access_uses_admin_endpoint() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str, dict]] = []

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path, kwargs))
        return {}

    client._request = fake_request  # type: ignore[method-assign]
    try:
        asyncio.run(client.revoke_user_access(actor_telegram_id=11, target_telegram_id=22))
    finally:
        asyncio.run(client.close())

    method, path, kwargs = calls[0]
    assert method == "POST"
    assert path == "/admin/revoke-user-access"
    assert kwargs["json"] == {
        "actor_telegram_id": 11,
        "target_telegram_id": 22,
    }


def test_list_mtproto_access_uses_mtproto_endpoint() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str, dict]] = []

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path, kwargs))
        return []

    client._request = fake_request  # type: ignore[method-assign]
    try:
        asyncio.run(client.list_mtproto_access(include_revoked=True))
    finally:
        asyncio.run(client.close())

    method, path, kwargs = calls[0]
    assert method == "GET"
    assert path == "/mtproto/access"
    assert kwargs["params"] == {"include_revoked": "true"}


def test_accept_bot_welcome_uses_user_endpoint() -> None:
    client = TracegateApiClient("http://example.test", "token")
    calls: list[tuple[str, str, dict]] = []

    async def fake_request(method: str, path: str, **kwargs):  # noqa: ANN001
        calls.append((method, path, kwargs))
        return {}

    client._request = fake_request  # type: ignore[method-assign]
    try:
        asyncio.run(client.accept_bot_welcome(42, version="tracegate-2.1-client-safety-v1"))
    finally:
        asyncio.run(client.close())

    method, path, kwargs = calls[0]
    assert method == "POST"
    assert path == "/users/42/bot-welcome-accept"
    assert kwargs["json"] == {"version": "tracegate-2.1-client-safety-v1"}
