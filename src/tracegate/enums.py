from enum import Enum


class EntitlementStatus(str, Enum):
    ACTIVE = "active"
    GRACE = "grace"
    BLOCKED = "blocked"


class ConnectionProtocol(str, Enum):
    VLESS_REALITY = "vless_reality"
    HYSTERIA2 = "hysteria2"
    WIREGUARD = "wireguard"


class ConnectionMode(str, Enum):
    DIRECT = "direct"
    CHAIN = "chain"


class ConnectionVariant(str, Enum):
    B1 = "B1"
    B2 = "B2"
    B3 = "B3"
    B5 = "B5"


class RecordStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class IpamLeaseStatus(str, Enum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    RELEASED = "released"


class OutboxEventType(str, Enum):
    APPLY_BUNDLE = "APPLY_BUNDLE"
    UPSERT_USER = "UPSERT_USER"
    REVOKE_USER = "REVOKE_USER"
    WG_PEER_UPSERT = "WG_PEER_UPSERT"
    WG_PEER_REMOVE = "WG_PEER_REMOVE"


class OutboxStatus(str, Enum):
    PENDING = "pending"
    INFLIGHT = "inflight"
    SENT = "sent"
    FAILED = "failed"


class NodeRole(str, Enum):
    VPS_T = "VPS_T"
    VPS_E = "VPS_E"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class OwnerType(str, Enum):
    USER = "user"
    DEVICE = "device"
    PEER = "peer"
