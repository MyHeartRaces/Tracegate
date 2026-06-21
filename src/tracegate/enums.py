from enum import Enum


class EntitlementStatus(str, Enum):
    ACTIVE = "active"
    GRACE = "grace"
    BLOCKED = "blocked"

class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"


class ConnectionProtocol(str, Enum):
    VLESS_REALITY = "vless_reality"
    VLESS_GRPC_TLS = "vless_grpc_tls"
    VLESS_WS_TLS = "vless_ws_tls"
    HYSTERIA2 = "hysteria2"
    SHADOWSOCKS2022_SHADOWTLS = "shadowsocks2022_shadowtls"
    WIREGUARD_WSTUNNEL = "wireguard_wstunnel"


class ConnectionMode(str, Enum):
    DIRECT = "direct"
    CHAIN = "chain"


class ConnectionVariant(str, Enum):
    V0 = "V0"
    V1 = "V1"
    V2 = "V2"
    V3 = "V3"
    V4 = "V4"
    V5 = "V5"
    V6 = "V6"
    V7 = "V7"


class RecordStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class ApiScope(str, Enum):
    ALL = "*"
    USERS_RW = "users:rw"
    USERS_ROLE = "users:role"
    DEVICES_RW = "devices:rw"
    CONNECTIONS_RW = "connections:rw"
    REVISIONS_RW = "revisions:rw"
    NODES_RW = "nodes:rw"
    SNI_READ = "sni:read"
    DISPATCH_RW = "dispatch:rw"
    BOT_MESSAGES_RW = "bot_messages:rw"
    GRAFANA_OTP = "grafana:otp"
    TOKENS_READ = "tokens:read"
    TOKENS_WRITE = "tokens:write"
    METRICS_READ = "metrics:read"


class IpamLeaseStatus(str, Enum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    RELEASED = "released"


class OutboxEventType(str, Enum):
    APPLY_BUNDLE = "APPLY_BUNDLE"
    UPSERT_USER = "UPSERT_USER"
    REVOKE_USER = "REVOKE_USER"
    REVOKE_CONNECTION = "REVOKE_CONNECTION"


class OutboxStatus(str, Enum):
    PENDING = "pending"
    INFLIGHT = "inflight"
    SENT = "sent"
    FAILED = "failed"


class NodeRole(str, Enum):
    TRANSIT = "TRANSIT"
    ENTRY = "ENTRY"
    # Backward-compatible aliases for legacy data and older code paths.
    VPS_T = "TRANSIT"
    VPS_E = "ENTRY"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    DEAD = "dead"


class OwnerType(str, Enum):
    USER = "user"
    DEVICE = "device"
    PEER = "peer"
