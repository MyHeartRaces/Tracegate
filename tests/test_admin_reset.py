from __future__ import annotations

import sys
import types

import pytest

from tracegate.enums import UserRole
from tracegate.models import User
from tracegate.schemas import AdminResetConnectionsRequest

_prom_stub = types.ModuleType("prometheus_client")
_prom_stub.CONTENT_TYPE_LATEST = "text/plain"
_prom_stub.generate_latest = lambda: b""
_orig_prometheus_client = sys.modules.get("prometheus_client")
sys.modules["prometheus_client"] = _prom_stub
try:
    from tracegate.api.routers import admin as admin_router  # noqa: E402
finally:
    if _orig_prometheus_client is None:
        sys.modules.pop("prometheus_client", None)
    else:
        sys.modules["prometheus_client"] = _orig_prometheus_client


class _EmptyScalarResult:
    def scalars(self):
        return self

    def all(self) -> list:
        return []


class _FakeSession:
    def __init__(self, actor: User) -> None:
        self.actor = actor
        self.statements: list[str] = []
        self.commits = 0

    async def get(self, model, key):  # noqa: ANN001
        if model is User and int(key) == int(self.actor.telegram_id):
            return self.actor
        return None

    async def execute(self, stmt):  # noqa: ANN001
        self.statements.append(str(stmt))
        return _EmptyScalarResult()

    async def commit(self) -> None:
        self.commits += 1


def _actor(role: UserRole) -> User:
    return User(telegram_id=255761416, role=role)


@pytest.mark.asyncio
async def test_superadmin_reset_does_not_filter_out_superadmin_connections() -> None:
    session = _FakeSession(_actor(UserRole.SUPERADMIN))

    result = await admin_router.reset_connections(
        AdminResetConnectionsRequest(actor_telegram_id=255761416),
        session=session,  # type: ignore[arg-type]
    )

    assert result.revoked_connections == 0
    assert session.commits == 1
    assert len(session.statements) == 2
    assert "user.role !=" not in "\n".join(session.statements).lower()


@pytest.mark.asyncio
async def test_admin_reset_keeps_superadmin_protection() -> None:
    session = _FakeSession(_actor(UserRole.ADMIN))

    await admin_router.reset_connections(
        AdminResetConnectionsRequest(actor_telegram_id=255761416),
        session=session,  # type: ignore[arg-type]
    )

    assert "user.role !=" in "\n".join(session.statements).lower()
