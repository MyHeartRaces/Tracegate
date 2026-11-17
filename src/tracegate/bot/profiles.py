"""Connection profile resolution and Russian labels for the bot."""

from __future__ import annotations

from tracegate.bot import context as ctx
from tracegate.bot import texts
from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant
from tracegate.services.connection_profiles import (
    RETIRED_CLIENT_PROTOCOL_MESSAGE,
    enabled_profile_keys,
    is_retired_client_profile,
    supported_profile_specs,
)

# Profile keys and aliases of the VLESS WS-TLS / gRPC-TLS families retired in
# 4.1.1. Buttons in old chat messages may still carry them; they never resolve.
RETIRED_PROFILE_SPECS = frozenset(
    {
        "backup-ws",
        "backup-grpc",
        "entry-ws-legacy",
        "v0ws",
        "v0grpc",
        "v0-ws-vless",
        "v0-grpc-vless",
        "v5-entry-ws",
        "v5-universal-entry",
    }
)

_SPEC_ALIASES = {
    "universal": "entry",
    "v1": "reality",
    "v1direct": "reality",
    "v2direct": "hysteria",
}

HYSTERIA_OBFS_TYPES = frozenset({"salamander", "gecko"})


class ProfileDisabledError(ValueError):
    """The profile exists but is switched off in this deployment."""


def _normalize_spec(spec: str) -> str:
    normalized = str(spec or "").strip().lower()
    if normalized in RETIRED_PROFILE_SPECS:
        raise ValueError(RETIRED_CLIENT_PROTOCOL_MESSAGE)
    return _SPEC_ALIASES.get(normalized, normalized)


def profile_key(spec: str) -> str:
    key = _normalize_spec(spec)
    if key not in supported_profile_specs():
        raise ValueError("unknown profile")
    return key


def profile(spec: str) -> tuple[ConnectionProtocol, ConnectionMode, ConnectionVariant]:
    return supported_profile_specs()[profile_key(spec)]


def enabled_profile_specs() -> set[str]:
    return enabled_profile_keys(ctx.settings.enabled_client_profiles)


def ensure_profile_enabled(spec: str) -> str:
    key = profile_key(spec)
    if key not in enabled_profile_specs():
        raise ProfileDisabledError(key)
    return key


def connection_kind(connection: dict) -> str:
    """One of entry, reality, hysteria, legacy, other."""

    protocol = str(connection.get("protocol") or "").strip().lower()
    mode = str(connection.get("mode") or "").strip().lower()
    if is_retired_client_profile(protocol, mode):
        return "legacy"
    if protocol == ConnectionProtocol.VLESS_REALITY.value:
        return "entry" if mode == ConnectionMode.CHAIN.value else "reality"
    if protocol == ConnectionProtocol.HYSTERIA2.value and mode == ConnectionMode.DIRECT.value:
        return "hysteria"
    return "other"


def is_legacy_connection(connection: dict) -> bool:
    return connection_kind(connection) == "legacy"


def hysteria_obfs(connection: dict) -> str | None:
    overrides = connection.get("custom_overrides_json")
    if not isinstance(overrides, dict) or "hysteria_obfs" not in overrides:
        return None
    value = str(overrides.get("hysteria_obfs") or "").strip().lower()
    return value if value in HYSTERIA_OBFS_TYPES else None


def _user_alias(connection: dict) -> str:
    # The API fills ``alias`` with an auto-generated "<user> - <device> - <id>"
    # string. Only a custom alias (one that does not embed the id) is shown.
    alias = str(connection.get("alias") or "").strip()
    connection_id = str(connection.get("id") or "").strip()
    if not alias or (connection_id and connection_id in alias):
        return ""
    return alias


def connection_label(connection: dict) -> str:
    kind = connection_kind(connection)
    if kind == "legacy":
        return texts.LABEL_LEGACY
    if kind == "entry":
        label = texts.LABEL_CHAIN
    elif kind == "reality":
        label = texts.LABEL_DIRECT_VLESS
    elif kind == "hysteria":
        obfs = hysteria_obfs(connection)
        label = texts.LABEL_DIRECT_HYSTERIA
        if obfs == "salamander":
            label = f"{label} · {texts.LABEL_SALAMANDER}"
        elif obfs == "gecko":
            label = f"{label} · {texts.LABEL_GECKO}"
    else:
        label = texts.LABEL_OTHER
    alias = _user_alias(connection)
    return f"{label} · {alias}" if alias else label
