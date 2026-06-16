from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from tracegate.enums import ConnectionMode, ConnectionProtocol, NodeRole, OutboxEventType, RecordStatus
from tracegate.models import Connection, ConnectionRevision, NodeEndpoint, User
from tracegate.services.aliases import connection_alias, user_display
from tracegate.services.config_builder import EndpointSet, build_effective_config
from tracegate.services.connection_profiles import MAX_ACTIVE_REVISIONS_PER_CONNECTION, RESERVE_REVISION_SLOT
from tracegate.services.grace import ensure_can_issue_new_config
from tracegate.services.outbox import create_outbox_event
from tracegate.services.overrides import validate_overrides
from tracegate.services.pseudonym import PseudonymError, pseudo_id
from tracegate.services.role_targeting import target_roles_for_connection
from tracegate.services.runtime_contract import resolve_runtime_contract
from tracegate.services.sni_catalog import SniCatalogEntry, get_by_id, load_catalog
from tracegate.settings import get_settings


DEFAULT_V1_REALITY_SNI = "partners.lemanapro.ru"
ENTRY_INGRESS_PAIR_LOCK_ID = 6822526267863597649


class RevisionError(RuntimeError):
    pass


@dataclass(frozen=True)
class EntryIngressPairAssignment:
    pair_key: str
    shard_id: str
    public_ip: str
    host: str
    sni: SniCatalogEntry


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


def _select_revision_sticky_host(
    *,
    hosts: list[str],
    fallback: str,
    connection_id: UUID | None,
    rotation_generation: int,
    role: str,
) -> str:
    candidates: list[str] = []
    for value in hosts:
        host = _normalize_optional_host(value)
        if host and not _is_placeholder_host(host) and host not in candidates:
            candidates.append(host)
    if not candidates or connection_id is None:
        return fallback

    key = f"{connection_id}:{role}".encode()
    base_index = int.from_bytes(hashlib.sha256(key).digest()[:8], "big") % len(candidates)
    index = (base_index + max(0, rotation_generation)) % len(candidates)
    return candidates[index]


def _select_revision_sticky_shard_host(
    *,
    shards: list[dict],
    fallback: str,
    connection_id: UUID | None,
    rotation_generation: int,
    settings,
    role: str = "entry",
) -> str:
    candidates: list[tuple[str, str]] = []
    for shard in shards:
        if not isinstance(shard, dict) or str(shard.get("state") or "active").strip().lower() != "active":
            continue
        shard_id = str(shard.get("id") or "").strip()
        template = str(shard.get("hostnameTemplate") or "").strip()
        if shard_id and template and "{token}" in template and (shard_id, template) not in candidates:
            candidates.append((shard_id, template))
    if not candidates or connection_id is None:
        return fallback

    key = f"{connection_id}:{role}".encode()
    base_index = int.from_bytes(hashlib.sha256(key).digest()[:8], "big") % len(candidates)
    shard_id, template = candidates[(base_index + max(0, rotation_generation)) % len(candidates)]
    try:
        token = pseudo_id(
            settings=settings,
            kind=f"{role}-ingress",
            raw=f"{connection_id}:{max(0, rotation_generation)}",
            length=max(8, int(getattr(settings, f"{role}_ingress_alias_token_length"))),
        )
    except PseudonymError as exc:
        raise RevisionError(f"Unable to derive a private {role.title()} ingress alias") from exc
    return template.replace("{token}", token).replace("{shard}", shard_id)


def _active_entry_ingress_shards(shards: list[dict]) -> list[tuple[str, str, str]]:
    active: list[tuple[str, str, str]] = []
    for shard in shards:
        if not isinstance(shard, dict) or str(shard.get("state") or "active").strip().lower() != "active":
            continue
        shard_id = str(shard.get("id") or "").strip()
        template = str(shard.get("hostnameTemplate") or "").strip()
        public_ip = str(shard.get("publicIp") or "").strip()
        candidate = (shard_id, template, public_ip)
        if shard_id and template and public_ip and "{token}" in template and candidate not in active:
            active.append(candidate)
    return active


def _render_entry_ingress_alias(
    *,
    shard_id: str,
    template: str,
    connection_id: UUID,
    rotation_generation: int,
    settings,
    role: str = "entry",
) -> str:
    try:
        token = pseudo_id(
            settings=settings,
            kind=f"{role}-ingress",
            raw=f"{connection_id}:{max(0, rotation_generation)}",
            length=max(8, int(getattr(settings, f"{role}_ingress_alias_token_length"))),
        )
    except PseudonymError as exc:
        raise RevisionError(f"Unable to derive a private {role.title()} ingress alias") from exc
    return template.replace("{token}", token).replace("{shard}", shard_id)


def _exclusive_sni_pool(settings, *, role: str = "entry") -> list[SniCatalogEntry]:
    requested = [str(value or "").strip().lower() for value in getattr(settings, f"{role}_ingress_sni_pool")]
    requested = list(dict.fromkeys(value for value in requested if value))
    if len(requested) < 10 or len(requested) > 15:
        raise RevisionError(f"Exclusive {role.title()} SNI pool must contain 10 to 15 unique domains")

    by_fqdn = {row.fqdn.lower(): row for row in load_catalog() if row.enabled}
    missing = [fqdn for fqdn in requested if fqdn not in by_fqdn]
    if missing:
        raise RevisionError(f"Exclusive {role.title()} SNI pool contains unavailable domains: {', '.join(missing)}")
    return [by_fqdn[fqdn] for fqdn in requested]


def _entry_ingress_pair_key(public_ip: str, sni_fqdn: str) -> str:
    return hashlib.sha256(f"{public_ip}|{sni_fqdn.lower()}".encode()).hexdigest()


def _infer_legacy_entry_pair(config: dict, shards: list[dict]) -> tuple[str, str] | None:
    if not isinstance(config, dict):
        return None
    host = str(config.get("server") or "").strip().lower()
    sni = str(config.get("sni") or "").strip().lower()
    assignment = config.get("entry_ingress_assignment")
    assigned_public_ip = (
        str(assignment.get("public_ip") or "").strip()
        if isinstance(assignment, dict)
        else ""
    )
    if not host or not sni:
        return None

    for shard in shards:
        if not isinstance(shard, dict):
            continue
        shard_id = str(shard.get("id") or "").strip()
        public_ip = str(shard.get("publicIp") or "").strip()
        template = str(shard.get("hostnameTemplate") or "").strip().lower()
        if not shard_id or not public_ip or "{token}" not in template:
            continue
        rendered = template.replace("{shard}", shard_id)
        prefix, suffix = rendered.split("{token}", 1)
        token_length = len(host) - len(prefix) - len(suffix)
        if token_length > 0 and host.startswith(prefix) and host.endswith(suffix):
            return _entry_ingress_pair_key(assigned_public_ip or public_ip, sni), shard_id
    return None


def _uses_exclusive_entry_pair(connection: Connection, settings) -> bool:
    return bool(
        settings.entry_ingress_exclusive_sni_pairs_enabled
        and connection.protocol == ConnectionProtocol.VLESS_REALITY
        and _is_chain_connection(connection)
    )


def _uses_exclusive_endpoint_pair(connection: Connection, settings) -> bool:
    return bool(
        settings.endpoint_ingress_exclusive_sni_pairs_enabled
        and connection.protocol == ConnectionProtocol.VLESS_REALITY
        and not _is_chain_connection(connection)
    )


async def _lock_entry_ingress_pair_allocator(session: AsyncSession) -> None:
    try:
        dialect_name = session.get_bind().dialect.name
    except (AttributeError, TypeError):
        return
    if dialect_name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": ENTRY_INGRESS_PAIR_LOCK_ID},
        )


async def _allocate_entry_ingress_pair(
    session: AsyncSession,
    *,
    connection_id: UUID,
    rotation_generation: int,
    settings,
    role: str = "entry",
) -> EntryIngressPairAssignment:
    shards = _active_entry_ingress_shards(getattr(settings, f"{role}_ingress_shards"))
    if not shards:
        raise RevisionError(f"Exclusive {role.title()} shard/SNI allocation requires at least one active shard")
    sni_pool = _exclusive_sni_pool(settings, role=role)

    candidates: list[EntryIngressPairAssignment] = []
    for shard_id, template, public_ip in shards:
        host = _render_entry_ingress_alias(
            shard_id=shard_id,
            template=template,
            connection_id=connection_id,
            rotation_generation=rotation_generation,
            settings=settings,
            role=role,
        )
        for sni in sni_pool:
            candidates.append(
                EntryIngressPairAssignment(
                    pair_key=_entry_ingress_pair_key(public_ip, sni.fqdn),
                    shard_id=shard_id,
                    public_ip=public_ip,
                    host=host,
                    sni=sni,
                )
            )

    seed = hashlib.sha256(f"{connection_id}:{rotation_generation}:{role}-sni-pair".encode()).digest()
    start = int.from_bytes(seed[:8], "big") % len(candidates)
    ordered = candidates[start:] + candidates[:start]

    await _lock_entry_ingress_pair_allocator(session)
    used_result = await session.execute(
        select(ConnectionRevision.ingress_pair_key, ConnectionRevision.effective_config_json).where(
            ConnectionRevision.status == RecordStatus.ACTIVE,
        )
    )
    used: set[str] = set()
    for pair_key, config in used_result.all():
        if pair_key:
            used.add(str(pair_key))
            continue
        inferred = _infer_legacy_entry_pair(config or {}, getattr(settings, f"{role}_ingress_shards"))
        if inferred is not None:
            used.add(inferred[0])
    for candidate in ordered:
        if candidate.pair_key not in used:
            return candidate
    raise RevisionError(
        f"Exclusive {role.title()} shard/SNI pool is exhausted ({len(candidates)} active-pair capacity)"
    )


async def _ensure_ingress_pair_available(session: AsyncSession, revision: ConnectionRevision) -> None:
    pair_key = str(getattr(revision, "ingress_pair_key", "") or "").strip()
    if not pair_key:
        settings = get_settings()
        config = getattr(revision, "effective_config_json", {}) or {}
        inferred = _infer_legacy_entry_pair(config, settings.entry_ingress_shards)
        if inferred is None:
            inferred = _infer_legacy_entry_pair(config, settings.endpoint_ingress_shards)
        if inferred is not None:
            pair_key, revision.ingress_shard_id = inferred
            revision.ingress_pair_key = pair_key
    if not pair_key:
        return
    await _lock_entry_ingress_pair_allocator(session)
    conflict = await session.scalar(
        select(ConnectionRevision.id).where(
            ConnectionRevision.status == RecordStatus.ACTIVE,
            ConnectionRevision.ingress_pair_key == pair_key,
            ConnectionRevision.id != revision.id,
        )
    )
    if conflict is not None:
        raise RevisionError("Revision Entry shard/SNI pair is already leased by another active revision")


def _is_chain_connection(connection: Connection) -> bool:
    mode = getattr(connection, "mode", None)
    if mode == ConnectionMode.CHAIN:
        return True
    return str(getattr(mode, "value", mode) or "").strip().lower() == ConnectionMode.CHAIN.value


def _ensure_chain_endpoint_ready(connection: Connection, endpoints: EndpointSet) -> None:
    if not _is_chain_connection(connection):
        return
    entry_host = _normalize_optional_host(endpoints.entry_host)
    if not entry_host or _is_placeholder_host(entry_host):
        raise RevisionError(
            "Chain connections require a configured non-placeholder Entry host "
            "(set an active Entry node endpoint or DEFAULT_ENTRY_HOST)."
        )


def _ensure_chain_config_ready(connection: Connection, cfg: dict) -> None:
    if not _is_chain_connection(connection):
        return
    if not isinstance(cfg, dict):
        raise RevisionError("Chain revision cannot be applied: config is missing.")
    server = _normalize_optional_host(str(cfg.get("server") or ""))
    chain = cfg.get("chain") if isinstance(cfg.get("chain"), dict) else {}
    chain_entry = _normalize_optional_host(str(chain.get("entry") or "")) if chain else None
    if not server or _is_placeholder_host(server):
        raise RevisionError("Chain revision cannot be applied: config.server is missing or still a placeholder Entry host.")
    if chain_entry is not None and _is_placeholder_host(chain_entry):
        raise RevisionError("Chain revision cannot be applied: config.chain.entry is still a placeholder Entry host.")


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
        default_row = next((row for row in load_catalog() if row.enabled and row.fqdn == DEFAULT_V1_REALITY_SNI), None)
        if default_row is not None:
            return default_row
        for row in load_catalog():
            if row.enabled:
                return row
        raise RevisionError("No enabled SNI domains available")

    row = get_by_id(int(sni_id))
    if row is None or not row.enabled:
        raise RevisionError("Requested SNI is unavailable")
    return row


async def _resolve_endpoints(
    session: AsyncSession,
    *,
    connection_id: UUID | None = None,
    rotation_generation: int = 0,
    entry_host_override: str | None = None,
    transit_host_override: str | None = None,
) -> EndpointSet:
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

    transit_host = (
        _resolve_node_public_host(
            fqdn=transit.fqdn,
            public_ipv4=transit.public_ipv4,
            default_host=settings.default_transit_host,
        )
        if transit
        else settings.default_transit_host
    )
    entry_host = (
        _resolve_node_public_host(
            fqdn=entry.fqdn,
            public_ipv4=entry.public_ipv4,
            default_host=settings.default_entry_host,
        )
        if entry
        else settings.default_entry_host
    )
    transit_server_name = transit_host
    entry_server_name = entry_host
    if settings.ingress_rotation_enabled and settings.ingress_rotation_strategy == "revision-sticky":
        transit_host = _select_revision_sticky_host(
            hosts=settings.endpoint_ingress_hosts,
            fallback=transit_host,
            connection_id=connection_id,
            rotation_generation=rotation_generation,
            role="endpoint",
        )
        entry_host = _select_revision_sticky_host(
            hosts=settings.entry_ingress_hosts,
            fallback=entry_host,
            connection_id=connection_id,
            rotation_generation=rotation_generation,
            role="entry",
        )
        if settings.entry_ingress_shards:
            entry_host = _select_revision_sticky_shard_host(
                shards=settings.entry_ingress_shards,
                fallback=entry_host,
                connection_id=connection_id,
                rotation_generation=rotation_generation,
                settings=settings,
            )
        if settings.endpoint_ingress_shards:
            transit_host = _select_revision_sticky_shard_host(
                shards=settings.endpoint_ingress_shards,
                fallback=transit_host,
                connection_id=connection_id,
                rotation_generation=rotation_generation,
                settings=settings,
                role="endpoint",
            )
    elif settings.endpoint_ingress_shards:
        # Endpoint-first always exposes clients through shard addresses. The
        # rotation flag controls planned hostname-pool rotation, not whether
        # clients should bypass the service/egress-only address.
        transit_host = _select_revision_sticky_shard_host(
            shards=settings.endpoint_ingress_shards,
            fallback=transit_host,
            connection_id=connection_id,
            rotation_generation=rotation_generation,
            settings=settings,
            role="endpoint",
        )
    if entry_host_override:
        entry_host = entry_host_override
    if transit_host_override:
        transit_host = transit_host_override
    return EndpointSet(
        transit_host=transit_host,
        entry_host=entry_host,
        transit_server_name=transit_server_name,
        entry_server_name=entry_server_name,
        hysteria_auth_mode=runtime_contract.hysteria_auth_mode,
        hysteria_udp_port=settings.hysteria_udp_port,
        hysteria_salamander_password_entry=settings.hysteria_salamander_password_entry,
        hysteria_salamander_password_transit=settings.hysteria_salamander_password_transit,
        naiveproxy_host=settings.naiveproxy_host,
        naiveproxy_public_tcp_port=settings.naiveproxy_public_tcp_port,
        naiveproxy_public_udp_port=settings.naiveproxy_public_udp_port,
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
        vless_encryption_enabled=settings.vless_encryption_enabled,
        vless_encryption=settings.vless_encryption,
        vless_encryption_reality_sni=settings.vless_encryption_reality_sni,
        vless_encryption_ws_path=settings.vless_encryption_ws_path,
        vless_encryption_grpc_service_name=settings.vless_encryption_grpc_service_name,
        hysteria_ech_config_list_entry=settings.hysteria_ech_config_list_entry,
        hysteria_ech_config_list_transit=settings.hysteria_ech_config_list_transit,
        hysteria_ech_force_query_entry=settings.hysteria_ech_force_query_entry,
        hysteria_ech_force_query_transit=settings.hysteria_ech_force_query_transit,
        shadowtls_server_name_entry=settings.shadowtls_server_name_entry,
        shadowtls_server_name_transit=settings.shadowtls_server_name_transit,
        shadowtls_password_entry=settings.shadowtls_password_entry,
        shadowtls_password_transit=settings.shadowtls_password_transit,
        shadowsocks2022_method=settings.shadowsocks2022_method,
        shadowsocks2022_password_entry=settings.shadowsocks2022_password_entry,
        shadowsocks2022_password_transit=settings.shadowsocks2022_password_transit,
        wireguard_server_public_key=settings.wireguard_server_public_key,
        wireguard_dns=settings.wireguard_dns,
        wireguard_allowed_ips=tuple(settings.wireguard_allowed_ips),
        wireguard_mtu=settings.wireguard_mtu,
        wstunnel_path=settings.wireguard_wstunnel_path,
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
    _ensure_chain_config_ready(connection, cfg)
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

    settings = get_settings()
    pair_assignment: EntryIngressPairAssignment | None = None
    pair_role: str | None = None
    if _uses_exclusive_entry_pair(connection, settings):
        pair_assignment = await _allocate_entry_ingress_pair(
            session,
            connection_id=connection.id,
            rotation_generation=len(connection.revisions),
            settings=settings,
        )
        pair_role = "entry"
        selected_sni = pair_assignment.sni
    elif _uses_exclusive_endpoint_pair(connection, settings):
        pair_assignment = await _allocate_entry_ingress_pair(
            session,
            connection_id=connection.id,
            rotation_generation=len(connection.revisions),
            settings=settings,
            role="endpoint",
        )
        pair_role = "endpoint"
        selected_sni = pair_assignment.sni
    else:
        selected_sni = await _resolve_sni(
            session,
            connection.protocol,
            camouflage_sni_id,
            connection.custom_overrides_json,
        )
    if selected_sni is not None and not _is_allowed_reality_sni(selected_sni.fqdn):
        raise RevisionError("Selected SNI is blocked by REALITY SNI policy (reality_sni_allow_suffixes).")
    if (
        connection.protocol == ConnectionProtocol.VLESS_REALITY
        and settings.vless_encryption_enabled
        and settings.vless_encryption_reality_sni
        and not _is_allowed_reality_sni(settings.vless_encryption_reality_sni)
    ):
        raise RevisionError("VLESS encryption REALITY SNI is blocked by REALITY SNI policy.")
    endpoints = await _resolve_endpoints(
        session,
        connection_id=connection.id,
        rotation_generation=len(connection.revisions),
        entry_host_override=pair_assignment.host if pair_assignment and pair_role == "entry" else None,
        transit_host_override=pair_assignment.host if pair_assignment and pair_role == "endpoint" else None,
    )
    _ensure_chain_endpoint_ready(connection, endpoints)

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
    if pair_assignment is not None:
        effective_config[f"{pair_role}_ingress_assignment"] = {
            "shard_id": pair_assignment.shard_id,
            "public_ip": pair_assignment.public_ip,
            "sni_id": pair_assignment.sni.id,
        }
    revision = ConnectionRevision(
        connection_id=connection.id,
        slot=0,
        status=RecordStatus.ACTIVE,
        camouflage_sni_id=selected_sni.id if selected_sni else None,
        ingress_pair_key=pair_assignment.pair_key if pair_assignment else None,
        ingress_shard_id=pair_assignment.shard_id if pair_assignment else None,
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
    await _ensure_ingress_pair_available(session, revision)
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
