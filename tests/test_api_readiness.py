from contextlib import AbstractAsyncContextManager

import pytest
from fastapi import HTTPException

from tracegate.api.routers import health


class _Session(AbstractAsyncContextManager):
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def execute(self, _):
        if self.error:
            raise self.error
        return 1


@pytest.mark.asyncio
async def test_ready_checks_database(monkeypatch) -> None:
    monkeypatch.setattr(health, "get_sessionmaker", lambda: lambda: _Session())
    assert (await health.ready()).status == "ready"


@pytest.mark.asyncio
async def test_ready_fails_closed_when_database_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(health, "get_sessionmaker", lambda: lambda: _Session(RuntimeError("offline")))
    with pytest.raises(HTTPException) as exc:
        await health.ready()
    assert exc.value.status_code == 503
