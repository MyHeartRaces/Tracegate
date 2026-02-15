from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from prometheus_client import REGISTRY
from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import select

from tracegate.db import get_sessionmaker
from tracegate.enums import ConnectionProtocol, RecordStatus
from tracegate.models import Connection, Device, User, WireguardPeer
from tracegate.services.pseudonym import connection_pid, user_pid, wg_peer_pid
from tracegate.settings import Settings

logger = logging.getLogger("tracegate.api.inventory_metrics")

_REGISTERED = False


@dataclass(frozen=True)
class UserRow:
    user_pid: str
    user_handle: str
    role: str


@dataclass(frozen=True)
class ConnectionRow:
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


@dataclass(frozen=True)
class WgPeerRow:
    peer_pid: str
    connection_pid: str
    connection_marker: str
    user_pid: str
    user_handle: str
    device_name: str
    profile_name: str
    connection_label: str


@dataclass(frozen=True)
class InventorySnapshot:
    refreshed_at: datetime
    users: list[UserRow]
    connections: list[ConnectionRow]
    wg_peers: list[WgPeerRow]


def _user_handle(user: User) -> str:
    username = (user.telegram_username or "").strip().lstrip("@")
    if username:
        return f"@{username}"
    full_name = " ".join(
        [part.strip() for part in [user.telegram_first_name or "", user.telegram_last_name or ""] if part and part.strip()]
    ).strip()
    return full_name or "unknown"


def _connection_label(*, protocol: str, mode: str, variant: str, profile_name: str, device_name: str) -> str:
    # Keep it readable in tables/legends (avoid raw UUIDs).
    parts = []
    if profile_name:
        parts.append(profile_name)
    if device_name:
        parts.append(device_name)
    proto = protocol.replace("_", " ").upper()
    parts.append(f"{proto}/{mode.upper()}/{variant}")
    return " | ".join(parts)


class InventoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot = InventorySnapshot(refreshed_at=datetime.fromtimestamp(0, tz=timezone.utc), users=[], connections=[], wg_peers=[])

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
            "Tracegate users (pseudo-id keyed) exported by control-plane",
            labels=["user_pid", "user_handle", "role"],
        )
        for row in snap.users:
            users.add_metric([row.user_pid, row.user_handle, row.role], 1)
        yield users

        conns = GaugeMetricFamily(
            "tracegate_connection_active",
            "Active connections (pseudo-id keyed) exported by control-plane",
            labels=[
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

        wg_peers = GaugeMetricFamily(
            "tracegate_wg_peer_info",
            "WireGuard peer identity mapping (for joining node counters with control-plane labels)",
            labels=[
                "peer_pid",
                "connection_pid",
                "connection_marker",
                "user_pid",
                "user_handle",
                "device_name",
                "profile_name",
                "connection_label",
            ],
        )
        for row in snap.wg_peers:
            wg_peers.add_metric(
                [
                    row.peer_pid,
                    row.connection_pid,
                    row.connection_marker,
                    row.user_pid,
                    row.user_handle,
                    row.device_name,
                    row.profile_name,
                    row.connection_label,
                ],
                1,
            )
        yield wg_peers


def register_inventory_metrics() -> None:
    global _REGISTERED  # noqa: PLW0603
    if _REGISTERED:
        return
    REGISTRY.register(InventoryCollector(_STORE))
    _REGISTERED = True


async def _build_snapshot(settings: Settings) -> InventorySnapshot:
    async with get_sessionmaker()() as session:
        # Active connections + users/devices (for dashboards and joins).
        rows = (
            await session.execute(
                select(Connection, Device, User)
                .join(Device, Device.id == Connection.device_id)
                .join(User, User.telegram_id == Connection.user_id)
                .where(Connection.status == RecordStatus.ACTIVE)
                .order_by(Connection.created_at.asc())
            )
        ).all()

        users_by_pid: dict[str, UserRow] = {}
        connections: list[ConnectionRow] = []
        wg_conn_by_device: dict[str, ConnectionRow] = {}

        for conn, device, user in rows:
            upid = user_pid(settings, user.telegram_id)
            uhandle = _user_handle(user)
            users_by_pid.setdefault(upid, UserRow(user_pid=upid, user_handle=uhandle, role=str(user.role.value)))

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
                profile_name=profile_name,
                device_name=device_name,
            )

            crow = ConnectionRow(
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
            )
            connections.append(crow)

            if conn.protocol == ConnectionProtocol.WIREGUARD:
                # Best-effort mapping for WG peers by device.
                wg_conn_by_device[str(conn.device_id)] = crow

        # Active WireGuard peers -> map to connection by device.
        wg_rows = (
            await session.execute(
                select(WireguardPeer, Device, User)
                .join(Device, Device.id == WireguardPeer.device_id)
                .join(User, User.telegram_id == WireguardPeer.user_id)
                .where(WireguardPeer.status == RecordStatus.ACTIVE)
            )
        ).all()

        wg_peers: list[WgPeerRow] = []
        for peer, device, user in wg_rows:
            pub = str(peer.peer_public_key or "").strip()
            if not pub:
                continue
            peer_id = wg_peer_pid(settings, pub)
            conn_row = wg_conn_by_device.get(str(peer.device_id))
            if conn_row is None:
                continue
            wg_peers.append(
                WgPeerRow(
                    peer_pid=peer_id,
                    connection_pid=conn_row.connection_pid,
                    connection_marker=conn_row.connection_marker,
                    user_pid=conn_row.user_pid,
                    user_handle=conn_row.user_handle,
                    device_name=conn_row.device_name,
                    profile_name=conn_row.profile_name,
                    connection_label=conn_row.connection_label,
                )
            )

        return InventorySnapshot(
            refreshed_at=datetime.now(timezone.utc),
            users=sorted(users_by_pid.values(), key=lambda r: (r.user_handle.lower(), r.user_pid)),
            connections=connections,
            wg_peers=wg_peers,
        )


async def inventory_refresh_loop(settings: Settings, *, interval_seconds: int = 15) -> None:
    # Initial build eagerly (dashboards are less confusing if info metrics exist immediately).
    while True:
        try:
            snap = await _build_snapshot(settings)
            _STORE.set(snap)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("inventory_refresh_failed")
        await asyncio.sleep(max(5, int(interval_seconds)))
