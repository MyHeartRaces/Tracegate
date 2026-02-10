from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from tracegate.enums import (
    ConnectionMode,
    ConnectionProtocol,
    ConnectionVariant,
    DeliveryStatus,
    EntitlementStatus,
    NodeRole,
    OutboxEventType,
    OutboxStatus,
    RecordStatus,
)


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
    devices_max: int = 5


class UserRead(BaseModel):
    telegram_id: int
    devices_max: int
    entitlement_status: EntitlementStatus
    grace_ends_at: datetime | None


class UserEntitlementUpdate(BaseModel):
    entitlement_status: EntitlementStatus
    grace_ends_at: datetime | None = None


class DeviceCreate(BaseModel):
    user_id: int
    name: str = Field(min_length=1, max_length=128)


class DeviceRename(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class DeviceRead(BaseModel):
    id: UUID
    user_id: int
    name: str
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
    active: bool = True


class NodeEndpointRead(BaseModel):
    id: UUID
    role: NodeRole
    name: str
    base_url: str
    public_ipv4: str
    fqdn: str | None
    active: bool


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


class ApiTokenRead(BaseModel):
    id: UUID
    name: str
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
