from __future__ import annotations

from typing import Any

from tracegate.enums import ConnectionProtocol


class OverrideValidationError(ValueError):
    pass


def _ensure_keys(payload: dict[str, Any], allowed: set[str], forbidden: set[str]) -> None:
    keys = set(payload)
    rejected = sorted((keys - allowed) | (keys & forbidden))
    if rejected:
        raise OverrideValidationError(f"Unsupported override keys: {', '.join(rejected)}")


def validate_overrides(protocol: ConnectionProtocol, overrides: dict[str, Any]) -> dict[str, Any]:
    overrides = overrides or {}

    if protocol == ConnectionProtocol.VLESS_REALITY:
        allowed = {
            "mode",
            "camouflage_sni_id",
            "connect_timeout_ms",
            "dial_timeout_ms",
            "local_socks_port",
            "tcp_fast_open",
        }
        forbidden = {"port", "server_port", "reality_server_port", "chain_sni"}
        _ensure_keys(overrides, allowed, forbidden)

    elif protocol == ConnectionProtocol.HYSTERIA2:
        allowed = {
            "client_mode",
            "up_mbps",
            "down_mbps",
            "socks_listen",
            "http_listen",
        }
        forbidden = {
            "masquerade",
            "traffic_stats_secret",
            "disable_stats_auth",
            "server_port",
            "port",
        }
        _ensure_keys(overrides, allowed, forbidden)

    elif protocol == ConnectionProtocol.WIREGUARD:
        allowed = {"dns", "mtu", "persistent_keepalive", "allowed_ips"}
        forbidden = {"listen_port", "endpoint_port", "server_port"}
        _ensure_keys(overrides, allowed, forbidden)

    else:
        raise OverrideValidationError(f"Unsupported protocol: {protocol}")

    return overrides
