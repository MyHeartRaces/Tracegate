from __future__ import annotations

import asyncio
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from prometheus_client import REGISTRY
from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import select

from tracegate.db import get_sessionmaker
from tracegate.enums import RecordStatus
from tracegate.models import Connection, Device, MTProtoAccessGrant, User
from tracegate.services.pseudonym import connection_pid, user_pid
from tracegate.settings import Settings

logger = logging.getLogger("tracegate.api.inventory_metrics")

_REGISTERED = False


@dataclass(frozen=True)
class UserRow:
    telegram_id: str
    user_pid: str
    user_handle: str
    role: str
    entitlement_status: str
    bot_blocked: str
    has_active_connection: str
    devices_total: int
    active_connections_total: int


@dataclass(frozen=True)
class ConnectionRow:
    telegram_id: str
    connection_id: str
    connection_pid: str
    connection_marker: str
    user_pid: str
    user_handle: str
    protocol: str
    mode: str
    variant: str
    device_name: str
    profile_name: str
    connection_label: str
    created_at_seconds: float


@dataclass(frozen=True)
class MTProtoAccessRow:
    telegram_id: str
    user_pid: str
    user_handle: str
    label: str
    issued_by: str
    created_at_seconds: float
    updated_at_seconds: float
    last_sync_at_seconds: float | None


@dataclass(frozen=True)
class InventorySnapshot:
    refreshed_at: datetime
    users: list[UserRow]
    connections: list[ConnectionRow]
    mtproto_access: list[MTProtoAccessRow]


def _user_handle(user: User) -> str:
    username = (user.telegram_username or "").strip().lstrip("@")
    if username:
        return f"@{username}"
    full_name = " ".join(
        [part.strip() for part in [user.telegram_first_name or "", user.telegram_last_name or ""] if part and part.strip()]
    ).strip()
    return full_name or "unknown"


def _protocol_kind(protocol: str) -> str:
    normalized = protocol.strip().lower()
    mapping = {
        "hysteria2": "HY2",
        "vless_reality_vision": "VLESS REALITY",
        "vless_reality": "VLESS REALITY",
        "vless_grpc_tls": "VLESS gRPC",
        "vless_ws_tls": "VLESS WS",
    }
    return mapping.get(normalized, protocol.replace("_", " ").upper())


def _connection_label(
    *,
    protocol: str,
    mode: str,
    variant: str,
    user_handle: str,
    tg_id: str,
    device_name: str,
) -> str:
    kind = _protocol_kind(protocol)
    mode_suffix = mode.strip().upper()
    owner = user_handle.strip() or "unknown"
    owner_with_id = f"{owner}({tg_id})"
    device = device_name.strip() or "device-unknown"
    return f"{variant}({kind}/{mode_suffix}) - {owner_with_id} - {device}"


class InventoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot = InventorySnapshot(
            refreshed_at=datetime.fromtimestamp(0, tz=timezone.utc),
            users=[],
            connections=[],
            mtproto_access=[],
        )

    def get(self) -> InventorySnapshot:
        with self._lock:
            return self._snapshot

    def set(self, snapshot: InventorySnapshot) -> None:
        with self._lock:
            self._snapshot = snapshot


_STORE = InventoryStore()


class InventoryCollector:
    def __init__(self, store: InventoryStore) -> None:
        self._store = store

    def collect(self):  # noqa: ANN201
        snap = self._store.get()

        refreshed = GaugeMetricFamily(
            "tracegate_inventory_refreshed_at_seconds",
            "Unix timestamp of the last successful control-plane inventory refresh",
        )
        refreshed.add_metric([], int(snap.refreshed_at.timestamp()))
        yield refreshed

        users = GaugeMetricFamily(
            "tracegate_user_info",
            "Tracegate users exported by control-plane",
            labels=[
                "telegram_id",
                "user_pid",
                "user_handle",
                "role",
                "entitlement_status",
                "bot_blocked",
                "has_active_connection",
            ],
        )
        for row in snap.users:
            users.add_metric(
                [
                    row.telegram_id,
                    row.user_pid,
                    row.user_handle,
                    row.role,
                    row.entitlement_status,
                    row.bot_blocked,
                    row.has_active_connection,
                ],
                1,
            )
        yield users

        user_devices = GaugeMetricFamily(
            "tracegate_user_devices_total",
            "Number of devices known for a Tracegate user",
            labels=["telegram_id", "user_pid", "user_handle", "role"],
        )
        user_connections = GaugeMetricFamily(
            "tracegate_user_active_connections_total",
            "Number of active connections owned by a Tracegate user",
            labels=["telegram_id", "user_pid", "user_handle", "role"],
        )
        for row in snap.users:
            labels = [row.telegram_id, row.user_pid, row.user_handle, row.role]
            user_devices.add_metric(labels, row.devices_total)
            user_connections.add_metric(labels, row.active_connections_total)
        yield user_devices
        yield user_connections

        conns = GaugeMetricFamily(
            "tracegate_connection_active",
            "Active connections (pseudo-id keyed) exported by control-plane",
            labels=[
                "telegram_id",
                "connection_id",
                "connection_pid",
                "connection_marker",
                "user_pid",
                "user_handle",
                "protocol",
                "mode",
                "variant",
                "device_name",
                "profile_name",
                "connection_label",
            ],
        )
        for row in snap.connections:
            conns.add_metric(
                [
                    row.telegram_id,
                    row.connection_id,
                    row.connection_pid,
                    row.connection_marker,
                    row.user_pid,
                    row.user_handle,
                    row.protocol,
                    row.mode,
                    row.variant,
                    row.device_name,
                    row.profile_name,
                    row.connection_label,
                ],
                1,
            )
        yield conns

        conn_created = GaugeMetricFamily(
            "tracegate_connection_created_at_seconds",
            "Unix timestamp when an active Tracegate connection was created",
            labels=["telegram_id", "connection_id", "connection_pid", "user_pid", "user_handle", "protocol", "mode", "variant", "connection_label"],
        )
        for row in snap.connections:
            conn_created.add_metric(
                [
                    row.telegram_id,
                    row.connection_id,
                    row.connection_pid,
                    row.user_pid,
                    row.user_handle,
                    row.protocol,
                    row.mode,
                    row.variant,
                    row.connection_label,
                ],
                row.created_at_seconds,
            )
        yield conn_created

        mtproto = GaugeMetricFamily(
            "tracegate_mtproto_access_active",
            "Active persistent MTProto access grants exported by control-plane",
            labels=["telegram_id", "user_pid", "user_handle", "label", "issued_by"],
        )
        for row in snap.mtproto_access:
            mtproto.add_metric([row.telegram_id, row.user_pid, row.user_handle, row.label, row.issued_by], 1)
        yield mtproto

        mtproto_created = GaugeMetricFamily(
            "tracegate_mtproto_access_created_at_seconds",
            "Unix timestamp when the persistent MTProto access grant was created",
            labels=["telegram_id", "user_pid", "user_handle", "label", "issued_by"],
        )
        mtproto_updated = GaugeMetricFamily(
            "tracegate_mtproto_access_updated_at_seconds",
            "Unix timestamp when the persistent MTProto access grant was last updated",
            labels=["telegram_id", "user_pid", "user_handle", "label", "issued_by"],
        )
        mtproto_synced = GaugeMetricFamily(
            "tracegate_mtproto_access_last_sync_at_seconds",
            "Unix timestamp when the persistent MTProto access grant was last synced to runtime",
            labels=["telegram_id", "user_pid", "user_handle", "label", "issued_by"],
        )
        for row in snap.mtproto_access:
            labels = [row.telegram_id, row.user_pid, row.user_handle, row.label, row.issued_by]
            mtproto_created.add_metric(labels, row.created_at_seconds)
            mtproto_updated.add_metric(labels, row.updated_at_seconds)
            if row.last_sync_at_seconds is not None:
                mtproto_synced.add_metric(labels, row.last_sync_at_seconds)
        yield mtproto_created
        yield mtproto_updated
        yield mtproto_synced


def register_inventory_metrics() -> None:
    global _REGISTERED  # noqa: PLW0603
    if _REGISTERED:
        return
    REGISTRY.register(InventoryCollector(_STORE))
    _REGISTERED = True


async def _build_snapshot(settings: Settings) -> InventorySnapshot:
    async with get_sessionmaker()() as session:
        all_users = (await session.execute(select(User).order_by(User.created_at.asc()))).scalars().all()
        device_rows = (await session.execute(select(Device).where(Device.status == RecordStatus.ACTIVE))).scalars().all()
        connection_rows = (
            await session.execute(
                select(Connection, Device, User)
                .join(Device, Device.id == Connection.device_id)
                .join(User, User.telegram_id == Connection.user_id)
                .where(Connection.status == RecordStatus.ACTIVE)
                .order_by(Connection.created_at.asc())
            )
        ).all()
        mtproto_rows = (
            await session.execute(
                select(MTProtoAccessGrant, User)
                .join(User, User.telegram_id == MTProtoAccessGrant.telegram_id)
                .where(MTProtoAccessGrant.status == RecordStatus.ACTIVE)
                .order_by(MTProtoAccessGrant.updated_at.asc())
            )
        ).all()

        now = datetime.now(timezone.utc)
        devices_by_user: dict[int, int] = defaultdict(int)
        for device in device_rows:
            devices_by_user[int(device.user_id)] += 1

        active_connections_by_user: dict[int, int] = defaultdict(int)
        for conn, _device, _user in connection_rows:
            active_connections_by_user[int(conn.user_id)] += 1

        users: list[UserRow] = []
        connections: list[ConnectionRow] = []
        mtproto_access: list[MTProtoAccessRow] = []

        for user in all_users:
            telegram_id = int(user.telegram_id)
            blocked_until = user.bot_blocked_until
            blocked_until_aware = blocked_until
            if blocked_until_aware is not None and blocked_until_aware.tzinfo is None:
                blocked_until_aware = blocked_until_aware.replace(tzinfo=timezone.utc)
            active_connections_total = active_connections_by_user[telegram_id]
            users.append(
                UserRow(
                    telegram_id=str(telegram_id),
                    user_pid=user_pid(settings, telegram_id),
                    user_handle=_user_handle(user),
                    role=str(user.role.value),
                    entitlement_status=str(user.entitlement_status.value),
                    bot_blocked="true" if blocked_until_aware is not None and blocked_until_aware > now else "false",
                    has_active_connection="true" if active_connections_total > 0 else "false",
                    devices_total=devices_by_user[telegram_id],
                    active_connections_total=active_connections_total,
                )
            )

        for conn, device, user in connection_rows:
            upid = user_pid(settings, user.telegram_id)
            uhandle = _user_handle(user)

            cpid = connection_pid(settings, str(conn.id))
            protocol = str(conn.protocol.value)
            mode = str(conn.mode.value)
            variant = str(conn.variant.value)
            marker = f"{variant} - {user.telegram_id} - {conn.id}"
            device_name = str(device.name or "").strip()
            profile_name = str(conn.profile_name or "").strip()
            label = _connection_label(
                protocol=protocol,
                mode=mode,
                variant=variant,
                user_handle=uhandle,
                tg_id=str(user.telegram_id),
                device_name=device_name,
            )

            connections.append(
                ConnectionRow(
                    telegram_id=str(user.telegram_id),
                    connection_id=str(conn.id),
                    connection_pid=cpid,
                    connection_marker=marker,
                    user_pid=upid,
                    user_handle=uhandle,
                    protocol=protocol,
                    mode=mode,
                    variant=variant,
                    device_name=device_name,
                    profile_name=profile_name,
                    connection_label=label,
                    created_at_seconds=float(conn.created_at.timestamp()),
                )
            )

        for grant, user in mtproto_rows:
            upid = user_pid(settings, user.telegram_id)
            uhandle = _user_handle(user)
            label = str(grant.label or "").strip() or str(user.telegram_id)
            issued_by = str(grant.issued_by or "").strip() or "unknown"
            mtproto_access.append(
                MTProtoAccessRow(
                    telegram_id=str(user.telegram_id),
                    user_pid=upid,
                    user_handle=uhandle,
                    label=label,
                    issued_by=issued_by,
                    created_at_seconds=float(grant.created_at.timestamp()),
                    updated_at_seconds=float(grant.updated_at.timestamp()),
                    last_sync_at_seconds=float(grant.last_sync_at.timestamp()) if grant.last_sync_at is not None else None,
                )
            )

        return InventorySnapshot(
            refreshed_at=now,
            users=sorted(users, key=lambda row: (row.user_handle.lower(), row.telegram_id)),
            connections=connections,
            mtproto_access=mtproto_access,
        )


async def inventory_refresh_loop(settings: Settings, *, interval_seconds: int = 15) -> None:
    while True:
        try:
            snap = await _build_snapshot(settings)
            _STORE.set(snap)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("inventory_metrics_refresh_failed")

        await asyncio.sleep(max(1, int(interval_seconds)))
