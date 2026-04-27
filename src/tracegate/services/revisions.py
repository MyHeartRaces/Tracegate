from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from tracegate.enums import ConnectionProtocol, NodeRole, OutboxEventType, RecordStatus
from tracegate.models import Connection, ConnectionRevision, NodeEndpoint, User
from tracegate.services.aliases import connection_alias, user_display
from tracegate.services.config_builder import EndpointSet, build_effective_config
from tracegate.services.connection_profiles import MAX_ACTIVE_REVISIONS_PER_CONNECTION, RESERVE_REVISION_SLOT
from tracegate.services.grace import ensure_can_issue_new_config
from tracegate.services.outbox import create_outbox_event
from tracegate.services.overrides import validate_overrides
from tracegate.services.role_targeting import target_roles_for_connection
from tracegate.services.runtime_contract import resolve_runtime_contract
from tracegate.services.sni_catalog import SniCatalogEntry, get_by_id, load_catalog
from tracegate.settings import get_settings


class RevisionError(RuntimeError):
    pass


def _normalize_optional_host(value: str | None) -> str | None:
    host = str(value or "").strip()
    return host or None


def _is_placeholder_host(value: str | None) -> bool:
    host = (_normalize_optional_host(value) or "").lower().rstrip(".")
    if not host:
        return False
    return host == "example.com" or host.endswith(".example.com")


def _resolve_node_public_host(*, fqdn: str | None, public_ipv4: str | None, default_host: str | None) -> str:
    candidates = [
        _normalize_optional_host(fqdn),
        _normalize_optional_host(default_host),
        _normalize_optional_host(public_ipv4),
    ]
    for host in candidates:
        if host and not _is_placeholder_host(host):
            return host

    for host in candidates:
        if host:
            return host
    return ""


async def _load_connection(session: AsyncSession, connection_id: UUID) -> Connection:
    connection = await session.scalar(
        select(Connection)
        .where(Connection.id == connection_id)
        .options(selectinload(Connection.device), selectinload(Connection.revisions))
    )
    if connection is None:
        raise RevisionError("Connection not found")
    return connection


async def _load_user(session: AsyncSession, user_id: int) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise RevisionError("User not found")
    return user


async def _resolve_sni(
    session: AsyncSession,
    protocol: ConnectionProtocol,
    requested_sni_id: int | None,
    overrides: dict,
) -> SniCatalogEntry | None:
    if protocol != ConnectionProtocol.VLESS_REALITY:
        return None

    sni_id = requested_sni_id or overrides.get("camouflage_sni_id")
    if sni_id is None:
        for row in load_catalog():
            if row.enabled:
                return row
        raise RevisionError("No enabled SNI domains available")

    row = get_by_id(int(sni_id))
    if row is None or not row.enabled:
        raise RevisionError("Requested SNI is unavailable")
    return row


async def _resolve_endpoints(session: AsyncSession) -> EndpointSet:
    settings = get_settings()
    runtime_contract = resolve_runtime_contract(settings.agent_runtime_profile)
    transit = await session.scalar(
        select(NodeEndpoint)
        .where(NodeEndpoint.active.is_(True), NodeEndpoint.role == NodeRole.TRANSIT)
        .order_by(NodeEndpoint.created_at.asc())
    )
    entry = await session.scalar(
        select(NodeEndpoint)
        .where(NodeEndpoint.active.is_(True), NodeEndpoint.role == NodeRole.ENTRY)
        .order_by(NodeEndpoint.created_at.asc())
    )

    return EndpointSet(
        transit_host=(
            _resolve_node_public_host(
                fqdn=transit.fqdn,
                public_ipv4=transit.public_ipv4,
                default_host=settings.default_transit_host,
            )
            if transit
            else settings.default_transit_host
        ),
        entry_host=(
            _resolve_node_public_host(
                fqdn=entry.fqdn,
                public_ipv4=entry.public_ipv4,
                default_host=settings.default_entry_host,
            )
            if entry
            else settings.default_entry_host
        ),
        hysteria_auth_mode=runtime_contract.hysteria_auth_mode,
        hysteria_udp_port=settings.hysteria_udp_port,
        hysteria_salamander_password_entry=settings.hysteria_salamander_password_entry,
        hysteria_salamander_password_transit=settings.hysteria_salamander_password_transit,
        transit_proxy_host=(
            None if _is_placeholder_host(transit.proxy_fqdn) else _normalize_optional_host(transit.proxy_fqdn)
        )
        if transit
        else None,
        entry_proxy_host=(
            None if _is_placeholder_host(entry.proxy_fqdn) else _normalize_optional_host(entry.proxy_fqdn)
        )
        if entry
        else None,
        reality_public_key=settings.reality_public_key,
        reality_short_id=settings.reality_short_id,
        reality_public_key_transit=settings.reality_public_key_transit,
        reality_short_id_transit=settings.reality_short_id_transit,
        reality_public_key_entry=settings.reality_public_key_entry,
        reality_short_id_entry=settings.reality_short_id_entry,
        vless_ws_path=settings.vless_ws_path,
        vless_ws_tls_port=settings.vless_ws_tls_port,
        hysteria_ech_config_list_entry=settings.hysteria_ech_config_list_entry,
        hysteria_ech_config_list_transit=settings.hysteria_ech_config_list_transit,
        hysteria_ech_force_query_entry=settings.hysteria_ech_force_query_entry,
        hysteria_ech_force_query_transit=settings.hysteria_ech_force_query_transit,
    )


def _is_allowed_reality_sni(fqdn: str) -> bool:
    settings = get_settings()
    suffixes = [s.lower().strip() for s in settings.reality_sni_allow_suffixes if s and s.strip()]
    if not suffixes:
        return True
    name = fqdn.lower().strip()
    for suffix in suffixes:
        if suffix.startswith("."):
            if name.endswith(suffix):
                return True
        else:
            if name == suffix or name.endswith("." + suffix):
                return True
    return False


async def _emit_apply_for_revision(
    session: AsyncSession,
    *,
    connection: Connection,
    revision: ConnectionRevision,
    idempotency_prefix: str,
    op_ts: datetime | None = None,
) -> None:
    user = await _load_user(session, connection.user_id)
    device_name = (connection.device.name if connection.device else "").strip() or str(connection.device_id)
    user_label = user_display(
        telegram_id=user.telegram_id,
        telegram_username=user.telegram_username,
        telegram_first_name=user.telegram_first_name,
        telegram_last_name=user.telegram_last_name,
    )
    conn_alias = connection_alias(
        telegram_id=user.telegram_id,
        telegram_username=user.telegram_username,
        telegram_first_name=user.telegram_first_name,
        telegram_last_name=user.telegram_last_name,
        device_name=device_name,
        connection_id=str(connection.id),
    )
    cfg = revision.effective_config_json or {}
    event_ts = op_ts or revision.created_at

    payload = {
        "user_id": str(user.telegram_id),
        "user_display": user_label,
        "telegram_username": user.telegram_username,
        "device_id": str(connection.device_id),
        "device_name": device_name,
        "connection_id": str(connection.id),
        "connection_alias": conn_alias,
        "revision_id": str(revision.id),
        "op_ts": event_ts.isoformat(),
        "protocol": connection.protocol.value,
        "mode": connection.mode.value,
        "variant": connection.variant.value,
        "config": cfg,
    }
    if connection.protocol == ConnectionProtocol.VLESS_REALITY:
        payload["camouflage_sni"] = cfg.get("sni")

    for role in target_roles_for_connection(connection.protocol, connection.variant, connection.mode):
        await create_outbox_event(
            session,
            event_type=OutboxEventType.UPSERT_USER,
            aggregate_id=str(connection.id),
            payload=payload,
            role_target=role,
            idempotency_suffix=f"{idempotency_prefix}:{revision.id}:{role.value}",
        )


async def _compact_slots(connection: Connection) -> None:
    active = [rev for rev in connection.revisions if rev.status == RecordStatus.ACTIVE]
    active.sort(key=lambda r: (r.slot, r.created_at))
    for idx, rev in enumerate(active[:MAX_ACTIVE_REVISIONS_PER_CONNECTION]):
        rev.slot = idx
    for rev in active[MAX_ACTIVE_REVISIONS_PER_CONNECTION:]:
        rev.status = RecordStatus.REVOKED
        rev.slot = RESERVE_REVISION_SLOT


async def create_revision(
    session: AsyncSession,
    *,
    connection_id: UUID,
    camouflage_sni_id: int | None,
    force: bool,
) -> ConnectionRevision:
    connection = await _load_connection(session, connection_id)
    user = await _load_user(session, connection.user_id)

    ensure_can_issue_new_config(user, force=force)
    validate_overrides(connection.protocol, connection.custom_overrides_json)

    selected_sni = await _resolve_sni(session, connection.protocol, camouflage_sni_id, connection.custom_overrides_json)
    if selected_sni is not None and not _is_allowed_reality_sni(selected_sni.fqdn):
        raise RevisionError("Selected SNI is blocked by REALITY SNI policy (reality_sni_allow_suffixes).")
    endpoints = await _resolve_endpoints(session)

    active_revisions = sorted(
        [r for r in connection.revisions if r.status == RecordStatus.ACTIVE],
        key=lambda r: r.slot,
        reverse=True,
    )
    for rev in active_revisions:
        rev.slot = rev.slot + 10
    await session.flush()

    for rev in active_revisions:
        prev_slot = rev.slot - 10
        next_slot = prev_slot + 1
        if next_slot > RESERVE_REVISION_SLOT:
            rev.status = RecordStatus.REVOKED
            rev.slot = RESERVE_REVISION_SLOT
        else:
            rev.slot = next_slot
    await session.flush()

    effective_config = build_effective_config(
        user=user,
        device=connection.device,
        connection=connection,
        selected_sni=selected_sni,
        endpoints=endpoints,
    )
    revision = ConnectionRevision(
        connection_id=connection.id,
        slot=0,
        status=RecordStatus.ACTIVE,
        camouflage_sni_id=selected_sni.id if selected_sni else None,
        effective_config_json=effective_config,
        created_at=datetime.now(timezone.utc),
    )
    connection.revisions.append(revision)
    await session.flush()

    await _emit_apply_for_revision(
        session,
        connection=connection,
        revision=revision,
        idempotency_prefix="issue",
    )

    await _compact_slots(connection)
    await session.flush()
    return revision


async def activate_revision(session: AsyncSession, revision_id: UUID) -> ConnectionRevision:
    revision = await session.get(ConnectionRevision, revision_id)
    if revision is None:
        raise RevisionError("Revision not found")

    connection = await _load_connection(session, revision.connection_id)
    others = [r for r in connection.revisions if r.id != revision.id and r.status == RecordStatus.ACTIVE]
    others.sort(key=lambda r: (r.slot, r.created_at))

    if revision.status == RecordStatus.ACTIVE:
        revision.slot = revision.slot + 10
    for rev in others:
        rev.slot = rev.slot + 10
    await session.flush()

    revision.status = RecordStatus.ACTIVE
    revision.slot = 0

    others.sort(key=lambda r: (r.slot, r.created_at))
    for idx, rev in enumerate(others, start=1):
        if idx > RESERVE_REVISION_SLOT:
            rev.status = RecordStatus.REVOKED
            rev.slot = RESERVE_REVISION_SLOT
        else:
            rev.slot = idx

    await session.flush()
    await _emit_apply_for_revision(
        session,
        connection=connection,
        revision=revision,
        idempotency_prefix="activate",
        op_ts=datetime.now(timezone.utc),
    )
    return revision


async def revoke_revision(session: AsyncSession, revision_id: UUID) -> ConnectionRevision:
    revision = await session.get(ConnectionRevision, revision_id)
    if revision is None:
        raise RevisionError("Revision not found")

    revision.status = RecordStatus.REVOKED

    connection = await _load_connection(session, revision.connection_id)
    await _compact_slots(connection)
    await session.flush()

    active_now = [r for r in connection.revisions if r.status == RecordStatus.ACTIVE]
    active_slot0 = next((r for r in active_now if r.slot == 0), None)
    if active_slot0 is not None:
        await _emit_apply_for_revision(
            session,
            connection=connection,
            revision=active_slot0,
            idempotency_prefix=f"revoke-promote:{revision.id}",
            op_ts=datetime.now(timezone.utc),
        )
    else:
        op_ts = datetime.now(timezone.utc).isoformat()
        payload = {
            "connection_id": str(connection.id),
            "revision_id": str(revision.id),
            "user_id": str(connection.user_id),
            "device_id": str(connection.device_id),
            "op_ts": op_ts,
        }
        connection.status = RecordStatus.REVOKED
        for role in target_roles_for_connection(connection.protocol, connection.variant, connection.mode):
            await create_outbox_event(
                session,
                event_type=OutboxEventType.REVOKE_CONNECTION,
                aggregate_id=str(connection.id),
                payload=payload,
                role_target=role,
                idempotency_suffix=f"revoke-final:{revision.id}:{role.value}",
            )

    await session.flush()
    return revision
