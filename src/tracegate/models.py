from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, BigInteger, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from tracegate.db import Base
from tracegate.enums import (
    ConnectionMode,
    ConnectionProtocol,
    ConnectionVariant,
    DeliveryStatus,
    EntitlementStatus,
    IpamLeaseStatus,
    NodeRole,
    OutboxEventType,
    OutboxStatus,
    OwnerType,
    RecordStatus,
    UserRole,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "tg_user"

    # Telegram user id is the primary key in v0.1 (Telegram is the only identity provider).
    telegram_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    telegram_username: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    telegram_first_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    telegram_last_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role"),
        default=UserRole.USER,
        nullable=False,
        index=True,
    )
    devices_max: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    entitlement_status: Mapped[EntitlementStatus] = mapped_column(
        Enum(EntitlementStatus, name="entitlement_status"), default=EntitlementStatus.ACTIVE, nullable=False
    )
    grace_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    bot_blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    bot_block_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    devices: Mapped[list[Device]] = relationship(back_populates="user", cascade="all,delete-orphan")

class Device(Base):
    __tablename__ = "device"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("tg_user.telegram_id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[RecordStatus] = mapped_column(
        Enum(RecordStatus, name="device_status"), default=RecordStatus.ACTIVE, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    user: Mapped[User] = relationship(back_populates="devices")
    connections: Mapped[list[Connection]] = relationship(back_populates="device", cascade="all,delete-orphan")


class Connection(Base):
    __tablename__ = "connection"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("tg_user.telegram_id", ondelete="CASCADE"), index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("device.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[ConnectionProtocol] = mapped_column(
        Enum(ConnectionProtocol, name="connection_protocol"), nullable=False
    )
    mode: Mapped[ConnectionMode] = mapped_column(Enum(ConnectionMode, name="connection_mode"), nullable=False)
    variant: Mapped[ConnectionVariant] = mapped_column(Enum(ConnectionVariant, name="connection_variant"), nullable=False)
    profile_name: Mapped[str] = mapped_column(String(64), nullable=False)
    custom_overrides_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[RecordStatus] = mapped_column(
        Enum(RecordStatus, name="connection_status"), default=RecordStatus.ACTIVE, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    device: Mapped[Device] = relationship(back_populates="connections")
    revisions: Mapped[list[ConnectionRevision]] = relationship(back_populates="connection", cascade="all,delete-orphan")


class ConnectionRevision(Base):
    __tablename__ = "connection_revision"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connection.id", ondelete="CASCADE"), index=True
    )
    slot: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[RecordStatus] = mapped_column(
        Enum(RecordStatus, name="connection_revision_status"), default=RecordStatus.ACTIVE, nullable=False
    )
    # Static SNI catalog lives in the repo (not in Postgres). We store only the selected catalog id.
    camouflage_sni_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    effective_config_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    connection: Mapped[Connection] = relationship(back_populates="revisions")

    __table_args__ = (
        Index("ix_connection_revision_active_slot", "connection_id", "status", "slot"),
        Index(
            "uq_connection_revision_active_slot",
            "connection_id",
            "slot",
            unique=True,
            postgresql_where=text("status = 'ACTIVE'"),
        ),
    )


class IpamPool(Base):
    __tablename__ = "ipam_pool"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cidr: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    gateway: Mapped[str] = mapped_column(String(64), nullable=False)
    quarantine_seconds: Mapped[int] = mapped_column(Integer, default=1800, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    leases: Mapped[list[IpamLease]] = relationship(back_populates="pool", cascade="all,delete-orphan")


class IpamLease(Base):
    __tablename__ = "ipam_lease"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pool_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("ipam_pool.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_type: Mapped[OwnerType] = mapped_column(Enum(OwnerType, name="owner_type"), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    status: Mapped[IpamLeaseStatus] = mapped_column(
        Enum(IpamLeaseStatus, name="ipam_lease_status"), default=IpamLeaseStatus.ACTIVE, nullable=False
    )
    quarantined_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    pool: Mapped[IpamPool] = relationship(back_populates="leases")

    __table_args__ = (
        UniqueConstraint("pool_id", "ip", name="uq_ipam_pool_ip"),
        Index(
            "uq_ipam_lease_active_owner",
            "pool_id",
            "owner_type",
            "owner_id",
            unique=True,
            postgresql_where=text("status = 'ACTIVE'"),
        ),
    )


class WireguardPeer(Base):
    __tablename__ = "wireguard_peer"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("tg_user.telegram_id", ondelete="CASCADE"), index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("device.id", ondelete="CASCADE"), unique=True, index=True
    )
    peer_public_key: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    lease_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("ipam_lease.id", ondelete="RESTRICT"), unique=True)
    preshared_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    allowed_ips: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[RecordStatus] = mapped_column(
        Enum(RecordStatus, name="wireguard_peer_status"), default=RecordStatus.ACTIVE, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class NodeEndpoint(Base):
    __tablename__ = "node_endpoint"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role: Mapped[NodeRole] = mapped_column(Enum(NodeRole, name="node_role"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    base_url: Mapped[str] = mapped_column(String(255), nullable=False)
    public_ipv4: Mapped[str] = mapped_column(String(64), nullable=False)
    fqdn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Optional hostname that is expected to be reachable via an L7 proxy (e.g. Cloudflare orange cloud).
    # Used for HTTPS/WebSocket transports where the client must connect by name.
    proxy_fqdn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class OutboxEvent(Base):
    __tablename__ = "outbox_event"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type: Mapped[OutboxEventType] = mapped_column(Enum(OutboxEventType, name="outbox_event_type"), nullable=False)
    role_target: Mapped[NodeRole | None] = mapped_column(Enum(NodeRole, name="outbox_role_target"), nullable=True)
    node_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("node_endpoint.id"), nullable=True)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    status: Mapped[OutboxStatus] = mapped_column(
        Enum(OutboxStatus, name="outbox_status"), default=OutboxStatus.PENDING, nullable=False, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    deliveries: Mapped[list[OutboxDelivery]] = relationship(back_populates="event", cascade="all,delete-orphan")


class OutboxDelivery(Base):
    __tablename__ = "outbox_delivery"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    outbox_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("outbox_event.id", ondelete="CASCADE"), index=True
    )
    node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("node_endpoint.id", ondelete="CASCADE"), index=True)
    status: Mapped[DeliveryStatus] = mapped_column(
        Enum(DeliveryStatus, name="delivery_status"), default=DeliveryStatus.PENDING, nullable=False, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    locked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    event: Mapped[OutboxEvent] = relationship(back_populates="deliveries")
    node: Mapped[NodeEndpoint] = relationship()

    __table_args__ = (UniqueConstraint("outbox_event_id", "node_id", name="uq_outbox_delivery_event_node"),)


class ApiToken(Base):
    __tablename__ = "api_token"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["*"], nullable=False)
    status: Mapped[RecordStatus] = mapped_column(
        Enum(RecordStatus, name="api_token_status"), default=RecordStatus.ACTIVE, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GrafanaOtp(Base):
    __tablename__ = "grafana_otp"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    telegram_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("tg_user.telegram_id", ondelete="CASCADE"), index=True, nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class BotMessageRef(Base):
    __tablename__ = "bot_message_ref"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    telegram_id: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)
    message_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    connection_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    device_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    revision_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("chat_id", "message_id", name="uq_bot_message_ref_chat_msg"),)
