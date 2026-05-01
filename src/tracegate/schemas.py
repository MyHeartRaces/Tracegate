from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from tracegate.enums import (
    ApiScope,
    ConnectionMode,
    ConnectionProtocol,
    ConnectionVariant,
    DeliveryStatus,
    EntitlementStatus,
    NodeRole,
    OutboxEventType,
    OutboxStatus,
    RecordStatus,
    UserRole,
)
from tracegate.services.bot_blocks import PERMANENT_BOT_BLOCK_HOURS
from tracegate.services.connection_profiles import MAX_DEVICES_PER_USER


class HealthResponse(BaseModel):
    status: str


class SniDomainCreate(BaseModel):
    fqdn: str
    enabled: bool = True
    is_test: bool = False
    note: str | None = None
    providers: list[str] = Field(default_factory=list)


class SniDomainRead(BaseModel):
    id: int
    fqdn: str
    enabled: bool
    is_test: bool
    note: str | None = None
    providers: list[str] = Field(default_factory=list)


class SniDomainUpdate(BaseModel):
    enabled: bool | None = None
    is_test: bool | None = None
    note: str | None = None
    providers: list[str] | None = None


class UserCreate(BaseModel):
    telegram_id: int
    devices_max: int = Field(default=MAX_DEVICES_PER_USER, ge=1, le=MAX_DEVICES_PER_USER)


class UserRead(BaseModel):
    telegram_id: int
    telegram_username: str | None = None
    telegram_first_name: str | None = None
    telegram_last_name: str | None = None
    role: UserRole
    devices_max: int
    entitlement_status: EntitlementStatus
    grace_ends_at: datetime | None
    bot_blocked_until: datetime | None = None
    bot_block_reason: str | None = None
    bot_welcome_accepted_at: datetime | None = None
    bot_welcome_version: str | None = None


class MTProtoAccessRead(BaseModel):
    telegram_id: int
    status: RecordStatus
    label: str | None = None
    issued_by: str | None = None
    last_sync_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class MTProtoAccessIssueRequest(BaseModel):
    telegram_id: int
    label: str | None = Field(default=None, max_length=128)
    rotate: bool = False
    issued_by: str | None = Field(default=None, max_length=64)


class MTProtoAccessIssueResult(BaseModel):
    grant: MTProtoAccessRead
    profile: dict[str, Any]
    changed: bool
    node: str


class MTProtoAccessRevokeResult(BaseModel):
    telegram_id: int
    removed: bool
    node: str


class UserEntitlementUpdate(BaseModel):
    entitlement_status: EntitlementStatus
    grace_ends_at: datetime | None = None


class UserRoleUpdate(BaseModel):
    role: UserRole


class UserProfileUpdate(BaseModel):
    telegram_username: str | None = Field(default=None, max_length=64)
    telegram_first_name: str | None = Field(default=None, max_length=128)
    telegram_last_name: str | None = Field(default=None, max_length=128)


class UserBotBlockUpdate(BaseModel):
    hours: int = Field(ge=1, le=PERMANENT_BOT_BLOCK_HOURS)
    reason: str | None = Field(default=None, max_length=255)
    revoke_access: bool = True


class UserBotWelcomeAccept(BaseModel):
    version: str = Field(min_length=1, max_length=64)


class DeviceCreate(BaseModel):
    user_id: int
    name: str = Field(min_length=1, max_length=128)


class DeviceRename(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class DeviceRead(BaseModel):
    id: UUID
    user_id: int
    name: str
    is_active: bool = False
    status: RecordStatus


class ConnectionCreate(BaseModel):
    user_id: int
    device_id: UUID
    protocol: ConnectionProtocol
    mode: ConnectionMode
    variant: ConnectionVariant
    profile_name: str = "default"
    custom_overrides_json: dict[str, Any] = Field(default_factory=dict)


class ConnectionUpdate(BaseModel):
    mode: ConnectionMode | None = None
    variant: ConnectionVariant | None = None
    profile_name: str | None = None
    custom_overrides_json: dict[str, Any] | None = None
    status: RecordStatus | None = None


class ConnectionRead(BaseModel):
    id: UUID
    user_id: int
    device_id: UUID
    device_name: str | None = None
    user_display: str | None = None
    alias: str | None = None
    protocol: ConnectionProtocol
    mode: ConnectionMode
    variant: ConnectionVariant
    profile_name: str
    custom_overrides_json: dict[str, Any]
    status: RecordStatus


class RevisionCreate(BaseModel):
    camouflage_sni_id: int | None = None
    force: bool = False


class RevisionRead(BaseModel):
    id: UUID
    connection_id: UUID
    slot: int
    status: RecordStatus
    camouflage_sni_id: int | None
    effective_config_json: dict[str, Any]
    created_at: datetime


class NodeEndpointCreate(BaseModel):
    role: NodeRole
    name: str
    base_url: str
    public_ipv4: str
    fqdn: str | None = None
    proxy_fqdn: str | None = None
    active: bool = True


class NodeEndpointUpdate(BaseModel):
    base_url: str | None = None
    public_ipv4: str | None = None
    fqdn: str | None = None
    proxy_fqdn: str | None = None
    active: bool | None = None


class NodeEndpointRead(BaseModel):
    id: UUID
    role: NodeRole
    name: str
    base_url: str
    public_ipv4: str
    fqdn: str | None
    proxy_fqdn: str | None
    active: bool


class BotMessageRefCreate(BaseModel):
    telegram_id: int
    chat_id: int
    message_id: int
    connection_id: UUID | None = None
    device_id: UUID | None = None
    revision_id: UUID | None = None


class BotMessageRefRead(BaseModel):
    id: UUID
    telegram_id: int
    chat_id: int
    message_id: int
    connection_id: UUID | None
    device_id: UUID | None
    revision_id: UUID | None
    removed_at: datetime | None
    created_at: datetime


class BotMessageCleanupRequest(BaseModel):
    connection_id: UUID | None = None
    device_id: UUID | None = None
    revision_id: UUID | None = None


class OutboxEventRead(BaseModel):
    id: UUID
    event_type: OutboxEventType
    role_target: NodeRole | None
    node_id: UUID | None
    aggregate_id: str
    payload_json: dict[str, Any]
    idempotency_key: str
    status: OutboxStatus
    attempts: int


class OutboxDeliveryRead(BaseModel):
    id: UUID
    outbox_event_id: UUID
    node_id: UUID
    status: DeliveryStatus
    attempts: int


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    scopes: list[ApiScope] = Field(default_factory=lambda: [ApiScope.ALL], min_length=1)


class ApiTokenRead(BaseModel):
    id: UUID
    name: str
    scopes: list[str]
    status: RecordStatus
    created_at: datetime
    last_used_at: datetime | None


class ApiTokenCreated(BaseModel):
    token: str
    token_meta: ApiTokenRead


class ReapplyBaseRequest(BaseModel):
    role: NodeRole | None = None


class ReissueRequest(BaseModel):
    user_id: int | None = None


class AdminResetConnectionsRequest(BaseModel):
    actor_telegram_id: int


class AdminResetConnectionsResult(BaseModel):
    revoked_connections: int
    revoked_mtproto_accesses: int = 0
    revoked_connection_ids: list[UUID] = Field(default_factory=list)


class AdminRevokeUserAccessRequest(BaseModel):
    actor_telegram_id: int
    target_telegram_id: int


class AdminRevokeUserAccessResult(BaseModel):
    target_telegram_id: int
    revoked_connections: int
    revoked_devices: int
    revoked_mtproto_access: bool = False
    revoked_connection_ids: list[UUID] = Field(default_factory=list)


class AgentEventEnvelope(BaseModel):
    event_id: UUID
    idempotency_key: str
    event_type: OutboxEventType
    payload: dict[str, Any]


class AgentEventResponse(BaseModel):
    accepted: bool
    duplicate: bool = False
    message: str


class AgentHealthCheckResult(BaseModel):
    name: str
    ok: bool
    details: str


class AgentHealthResponse(BaseModel):
    role: str
    checks: list[AgentHealthCheckResult]
    overall_ok: bool
