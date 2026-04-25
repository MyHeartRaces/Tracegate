from datetime import datetime, timezone
from uuid import uuid4

import pytest

from tracegate.enums import EntitlementStatus, NodeRole, RecordStatus, UserRole
from tracegate.models import MTProtoAccessGrant, NodeEndpoint, User
from tracegate.services.mtproto_grants import MTProtoGrantError, issue_mtproto_grant, revoke_mtproto_grant
from tracegate.settings import Settings


class _DummyScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _DummySession:
    def __init__(self, *, user: User | None, grant: MTProtoAccessGrant | None, nodes: list[NodeEndpoint]) -> None:
        self.user = user
        self.grant = grant
        self.nodes = list(nodes)
        self.added: list[object] = []

    async def get(self, model, key):
        if model is User:
            if self.user is not None and int(self.user.telegram_id) == int(key):
                return self.user
            return None
        if model is MTProtoAccessGrant:
            if self.grant is not None and int(self.grant.telegram_id) == int(key):
                return self.grant
            return None
        raise AssertionError(f"unexpected model lookup: {model}")

    async def execute(self, _stmt):
        return _DummyScalarResult(self.nodes)

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, MTProtoAccessGrant):
            self.grant = obj


def _user(*, telegram_id: int = 100, entitlement_status: EntitlementStatus = EntitlementStatus.ACTIVE) -> User:
    return User(
        telegram_id=telegram_id,
        telegram_username="alice",
        telegram_first_name="Alice",
        telegram_last_name=None,
        role=UserRole.USER,
        devices_max=5,
        entitlement_status=entitlement_status,
    )


def _transit_node() -> NodeEndpoint:
    now = datetime.now(timezone.utc)
    return NodeEndpoint(
        id=uuid4(),
        role=NodeRole.TRANSIT,
        name="transit-a",
        base_url="http://transit-a:8070",
        public_ipv4="203.0.113.10",
        fqdn="transit.tracegate.test",
        proxy_fqdn=None,
        active=True,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_issue_mtproto_grant_upserts_local_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _DummySession(user=_user(), grant=None, nodes=[_transit_node()])

    async def _request(_settings, *, node, method, path, json_payload=None):  # noqa: ANN001
        assert node.name == "transit-a"
        assert method == "POST"
        assert path == "/v1/mtproto/access/issue"
        assert json_payload["telegram_id"] == 100
        return {
            "changed": True,
            "profile": {
                "protocol": "mtproto",
                "server": "proxied.tracegate.su",
                "httpsUrl": "https://t.me/proxy?server=proxied.tracegate.su",
            },
        }

    monkeypatch.setattr("tracegate.services.mtproto_grants._request_transit_agent", _request)

    grant, profile, changed, node_name = await issue_mtproto_grant(
        session,
        settings=Settings(agent_auth_token="agent-token"),
        telegram_id=100,
        label=None,
        rotate=False,
        issued_by="bot",
    )

    assert changed is True
    assert node_name == "transit-a"
    assert profile["protocol"] == "mtproto"
    assert grant.telegram_id == 100
    assert grant.status == RecordStatus.ACTIVE
    assert grant.label == "@alice"
    assert grant.issued_by == "bot"
    assert grant.last_sync_at is not None
    assert session.added == [grant]


@pytest.mark.asyncio
async def test_issue_mtproto_grant_rejects_blocked_user() -> None:
    session = _DummySession(
        user=_user(entitlement_status=EntitlementStatus.BLOCKED),
        grant=None,
        nodes=[_transit_node()],
    )

    with pytest.raises(MTProtoGrantError, match="entitlement is blocked") as exc:
        await issue_mtproto_grant(
            session,
            settings=Settings(agent_auth_token="agent-token"),
            telegram_id=100,
        )

    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_revoke_mtproto_grant_marks_local_grant_revoked(monkeypatch: pytest.MonkeyPatch) -> None:
    grant = MTProtoAccessGrant(
        telegram_id=100,
        status=RecordStatus.ACTIVE,
        label="@alice",
        issued_by="bot",
    )
    session = _DummySession(user=_user(), grant=grant, nodes=[_transit_node()])

    async def _request(_settings, *, node, method, path, json_payload=None):  # noqa: ANN001
        assert node.name == "transit-a"
        assert method == "DELETE"
        assert path == "/v1/mtproto/access/100"
        assert json_payload is None
        return {"removed": True}

    monkeypatch.setattr("tracegate.services.mtproto_grants._request_transit_agent", _request)

    out_grant, removed, node_name = await revoke_mtproto_grant(
        session,
        settings=Settings(agent_auth_token="agent-token"),
        telegram_id=100,
    )

    assert removed is True
    assert node_name == "transit-a"
    assert out_grant is grant
    assert grant.status == RecordStatus.REVOKED
    assert grant.last_sync_at is not None
