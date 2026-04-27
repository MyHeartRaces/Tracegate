from __future__ import annotations

import sys
import types
from uuid import uuid4

import pytest
from fastapi import HTTPException

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, RecordStatus
from tracegate.models import Connection, Device, User
from tracegate.schemas import ConnectionCreate, ConnectionUpdate

_prom_stub = types.ModuleType("prometheus_client")
_prom_stub.CONTENT_TYPE_LATEST = "text/plain"
_prom_stub.generate_latest = lambda: b""
_orig_prometheus_client = sys.modules.get("prometheus_client")
sys.modules["prometheus_client"] = _prom_stub
try:
    from tracegate.api.routers.connections import create_connection, update_connection  # noqa: E402
finally:
    if _orig_prometheus_client is None:
        sys.modules.pop("prometheus_client", None)
    else:
        sys.modules["prometheus_client"] = _orig_prometheus_client


class _FakeSession:
    def __init__(
        self,
        *,
        user: User,
        device: Device,
        connection: Connection | None = None,
        active_connection_count: int = 0,
    ) -> None:
        self.user = user
        self.device = device
        self.connection = connection
        self.active_connection_count = active_connection_count
        self.added: list[object] = []
        self.commits = 0

    async def get(self, model, key):  # noqa: ANN001
        if model is User and key == self.user.telegram_id:
            return self.user
        if model is Device and key == self.device.id:
            return self.device
        if model is Connection and self.connection is not None and str(key) == str(self.connection.id):
            return self.connection
        return None

    async def scalar(self, _query):  # noqa: ANN001
        return self.active_connection_count

    def add(self, row: object) -> None:
        if isinstance(row, Connection):
            if row.id is None:
                row.id = uuid4()
            if row.status is None:
                row.status = RecordStatus.ACTIVE
            self.connection = row
        self.added.append(row)

    async def commit(self) -> None:
        self.commits += 1
        if self.connection is not None:
            if self.connection.id is None:
                self.connection.id = uuid4()
            if self.connection.status is None:
                self.connection.status = RecordStatus.ACTIVE

    async def rollback(self) -> None:
        pass

    async def refresh(self, _row: object) -> None:
        pass


def _user() -> User:
    return User(telegram_id=1001, devices_max=5)


def _device(user: User) -> Device:
    return Device(id=uuid4(), user_id=user.telegram_id, name="phone", status=RecordStatus.ACTIVE)


@pytest.mark.asyncio
async def test_create_connection_accepts_required_local_socks_credential_pair() -> None:
    user = _user()
    device = _device(user)
    session = _FakeSession(user=user, device=device)

    result = await create_connection(
        ConnectionCreate(
            user_id=user.telegram_id,
            device_id=device.id,
            protocol=ConnectionProtocol.VLESS_GRPC_TLS,
            mode=ConnectionMode.DIRECT,
            variant=ConnectionVariant.V0,
            profile_name="v0-grpc-vless",
            custom_overrides_json={
                "local_socks_username": "incy-user",
                "local_socks_password": "incy-pass_01",
            },
        ),
        session=session,  # type: ignore[arg-type]
    )

    assert result.custom_overrides_json == {
        "local_socks_username": "incy-user",
        "local_socks_password": "REDACTED",
    }
    assert session.connection is not None
    assert session.connection.custom_overrides_json == {
        "local_socks_username": "incy-user",
        "local_socks_password": "incy-pass_01",
    }
    assert session.commits == 1


@pytest.mark.asyncio
async def test_create_connection_rejects_device_connection_limit() -> None:
    user = _user()
    device = _device(user)
    session = _FakeSession(user=user, device=device, active_connection_count=4)

    with pytest.raises(HTTPException) as exc_info:
        await create_connection(
            ConnectionCreate(
                user_id=user.telegram_id,
                device_id=device.id,
                protocol=ConnectionProtocol.VLESS_REALITY,
                mode=ConnectionMode.DIRECT,
                variant=ConnectionVariant.V1,
                profile_name="v1-direct-reality-vless",
                custom_overrides_json={},
            ),
            session=session,  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 400
    assert "Connection limit reached for device (4)" in str(exc_info.value.detail)
    assert session.commits == 0


@pytest.mark.asyncio
async def test_create_connection_rejects_incomplete_local_socks_credentials() -> None:
    user = _user()
    device = _device(user)
    session = _FakeSession(user=user, device=device)

    with pytest.raises(HTTPException) as exc_info:
        await create_connection(
            ConnectionCreate(
                user_id=user.telegram_id,
                device_id=device.id,
                protocol=ConnectionProtocol.VLESS_REALITY,
                mode=ConnectionMode.DIRECT,
                variant=ConnectionVariant.V1,
                profile_name="v1-direct-reality-vless",
                custom_overrides_json={"local_socks_username": "incy-user"},
            ),
            session=session,  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 400
    assert "provided together" in str(exc_info.value.detail)
    assert session.commits == 0


@pytest.mark.asyncio
async def test_create_connection_rejects_redacted_sensitive_override_values() -> None:
    user = _user()
    device = _device(user)
    session = _FakeSession(user=user, device=device)

    with pytest.raises(HTTPException) as exc_info:
        await create_connection(
            ConnectionCreate(
                user_id=user.telegram_id,
                device_id=device.id,
                protocol=ConnectionProtocol.VLESS_REALITY,
                mode=ConnectionMode.DIRECT,
                variant=ConnectionVariant.V1,
                profile_name="v1-direct-reality-vless",
                custom_overrides_json={
                    "local_socks_username": "incy-user",
                    "local_socks_password": "REDACTED",
                },
            ),
            session=session,  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 400
    assert "redacted" in str(exc_info.value.detail)
    assert session.commits == 0


@pytest.mark.asyncio
async def test_update_connection_rejects_incomplete_local_socks_credentials() -> None:
    user = _user()
    device = _device(user)
    connection = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        profile_name="v2-direct-quic-hysteria",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    session = _FakeSession(user=user, device=device, connection=connection)

    with pytest.raises(HTTPException) as exc_info:
        await update_connection(
            str(connection.id),
            ConnectionUpdate(custom_overrides_json={"local_socks_password": "incy-pass"}),
            session=session,  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 400
    assert "provided together" in str(exc_info.value.detail)
    assert session.commits == 0


@pytest.mark.asyncio
async def test_update_connection_redacts_sensitive_override_values_in_response() -> None:
    user = _user()
    device = _device(user)
    connection = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.WIREGUARD_WSTUNNEL,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V0,
        profile_name="v0-wgws-wireguard",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    session = _FakeSession(user=user, device=device, connection=connection)

    result = await update_connection(
        str(connection.id),
        ConnectionUpdate(
            custom_overrides_json={
                "wireguard_private_key": "client-private",
                "wireguard_preshared_key": "wg-psk",
                "local_socks_username": "incy-user",
                "local_socks_password": "incy-pass_01",
            }
        ),
        session=session,  # type: ignore[arg-type]
    )

    assert result.custom_overrides_json == {
        "wireguard_private_key": "REDACTED",
        "wireguard_preshared_key": "REDACTED",
        "local_socks_username": "incy-user",
        "local_socks_password": "REDACTED",
    }
    assert connection.custom_overrides_json["wireguard_private_key"] == "client-private"
    assert connection.custom_overrides_json["local_socks_password"] == "incy-pass_01"


@pytest.mark.asyncio
async def test_update_connection_preserves_existing_secret_when_patch_returns_redacted_value() -> None:
    user = _user()
    device = _device(user)
    connection = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.WIREGUARD_WSTUNNEL,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V0,
        profile_name="v0-wgws-wireguard",
        custom_overrides_json={
            "wireguard_private_key": "client-private",
            "wireguard_preshared_key": "wg-psk",
            "local_socks_username": "incy-user",
            "local_socks_password": "incy-pass_01",
        },
        status=RecordStatus.ACTIVE,
    )
    session = _FakeSession(user=user, device=device, connection=connection)

    result = await update_connection(
        str(connection.id),
        ConnectionUpdate(
            custom_overrides_json={
                "wireguard_private_key": "REDACTED",
                "wireguard_preshared_key": "REDACTED",
                "local_socks_username": "incy-user",
                "local_socks_password": "REDACTED",
            }
        ),
        session=session,  # type: ignore[arg-type]
    )

    assert result.custom_overrides_json == {
        "wireguard_private_key": "REDACTED",
        "wireguard_preshared_key": "REDACTED",
        "local_socks_username": "incy-user",
        "local_socks_password": "REDACTED",
    }
    assert connection.custom_overrides_json == {
        "wireguard_private_key": "client-private",
        "wireguard_preshared_key": "wg-psk",
        "local_socks_username": "incy-user",
        "local_socks_password": "incy-pass_01",
    }
    assert session.commits == 1


@pytest.mark.asyncio
async def test_update_connection_rejects_redacted_secret_without_existing_value() -> None:
    user = _user()
    device = _device(user)
    connection = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.WIREGUARD_WSTUNNEL,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V0,
        profile_name="v0-wgws-wireguard",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    session = _FakeSession(user=user, device=device, connection=connection)

    with pytest.raises(HTTPException) as exc_info:
        await update_connection(
            str(connection.id),
            ConnectionUpdate(custom_overrides_json={"wireguard_private_key": "REDACTED"}),
            session=session,  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 400
    assert "redacted" in str(exc_info.value.detail)
    assert connection.custom_overrides_json == {}
    assert session.commits == 0
