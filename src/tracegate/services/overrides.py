from __future__ import annotations

import re
from ipaddress import ip_address
from typing import Any

from tracegate.enums import ConnectionProtocol


class OverrideValidationError(ValueError):
    pass


_LOCAL_SOCKS_CREDENTIAL_RE = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@%-]{1,128}$")


def _ensure_keys(payload: dict[str, Any], allowed: set[str], forbidden: set[str]) -> None:
    keys = set(payload)
    rejected = sorted((keys - allowed) | (keys & forbidden))
    if rejected:
        raise OverrideValidationError(f"Unsupported override keys: {', '.join(rejected)}")


def _is_loopback_host(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _parse_port(raw: object, *, field_name: str) -> int:
    value = str(raw or "").strip()
    if not value:
        raise OverrideValidationError(f"{field_name} must not be empty")
    if ":" in value:
        raise OverrideValidationError(f"{field_name} must be a port number, not host:port")
    try:
        port = int(value)
    except ValueError as exc:
        raise OverrideValidationError(f"{field_name} must be an integer port") from exc
    if port < 1024 or port > 65535:
        raise OverrideValidationError(f"{field_name} must be in 1024..65535")
    return port


def _parse_int_range(raw: object, *, field_name: str, min_value: int, max_value: int) -> int:
    value = str(raw if raw is not None else "").strip()
    if not value:
        raise OverrideValidationError(f"{field_name} must not be empty")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise OverrideValidationError(f"{field_name} must be an integer") from exc
    if parsed < min_value or parsed > max_value:
        raise OverrideValidationError(f"{field_name} must be in {min_value}..{max_value}")
    return parsed


def _parse_loopback_endpoint(raw: object, *, field_name: str) -> tuple[str, int]:
    value = str(raw or "").strip()
    if not value:
        raise OverrideValidationError(f"{field_name} must not be empty")
    if value.startswith("["):
        host_end = value.find("]")
        if host_end < 0 or host_end + 1 >= len(value) or value[host_end + 1] != ":":
            raise OverrideValidationError(f"{field_name} must use loopback host:port")
        host = value[1:host_end].strip()
        port_raw = value[host_end + 2 :].strip()
    else:
        host, sep, port_raw = value.rpartition(":")
        if not sep:
            host = "127.0.0.1"
            port_raw = value
    host = host.strip() or "127.0.0.1"
    if not _is_loopback_host(host):
        raise OverrideValidationError(f"{field_name} must be bound to loopback")
    port = _parse_port(port_raw, field_name=f"{field_name} port")
    return host, port


def _validate_local_socks_port(overrides: dict[str, Any]) -> None:
    if "local_socks_port" in overrides and overrides.get("local_socks_port") is not None:
        _parse_port(overrides["local_socks_port"], field_name="local_socks_port")


def _validate_local_socks_credentials(overrides: dict[str, Any]) -> None:
    has_username = "local_socks_username" in overrides and overrides.get("local_socks_username") is not None
    has_password = "local_socks_password" in overrides and overrides.get("local_socks_password") is not None
    if not has_username and not has_password:
        return
    if not has_username or not has_password:
        raise OverrideValidationError("local SOCKS5 username and password overrides must be provided together")

    username = str(overrides.get("local_socks_username") or "").strip()
    password = str(overrides.get("local_socks_password") or "").strip()
    if not username or not password:
        raise OverrideValidationError("local SOCKS5 username and password overrides must not be empty")
    if _LOCAL_SOCKS_CREDENTIAL_RE.fullmatch(username) is None:
        raise OverrideValidationError("local_socks_username contains unsupported characters or is too long")
    if _LOCAL_SOCKS_CREDENTIAL_RE.fullmatch(password) is None:
        raise OverrideValidationError("local_socks_password contains unsupported characters or is too long")


def _validate_loopback_endpoint_override(overrides: dict[str, Any], key: str) -> None:
    if key in overrides and overrides.get(key) is not None:
        _parse_loopback_endpoint(overrides[key], field_name=key)


def _validate_absolute_http_path_override(overrides: dict[str, Any], key: str) -> None:
    if key not in overrides or overrides.get(key) is None:
        return
    value = str(overrides.get(key) or "").strip()
    if not value.startswith("/"):
        raise OverrideValidationError(f"{key} must be an absolute HTTP path")
    if "://" in value or any(ch.isspace() for ch in value):
        raise OverrideValidationError(f"{key} must be a clean HTTP path")


def _validate_host_override(overrides: dict[str, Any], key: str) -> None:
    if key not in overrides or overrides.get(key) is None:
        return
    value = str(overrides.get(key) or "").strip()
    if not value:
        raise OverrideValidationError(f"{key} must not be empty")
    if "://" in value or "/" in value or any(ch.isspace() for ch in value):
        raise OverrideValidationError(f"{key} must be a hostname or IP address")
    if value.startswith("[") and value.endswith("]"):
        return
    if ":" in value:
        raise OverrideValidationError(f"{key} must not include a port")


def _validate_int_range_override(overrides: dict[str, Any], key: str, *, min_value: int, max_value: int) -> None:
    if key in overrides and overrides.get(key) is not None:
        _parse_int_range(overrides[key], field_name=key, min_value=min_value, max_value=max_value)


def _validate_hysteria_client_mode(overrides: dict[str, Any]) -> None:
    if "client_mode" not in overrides or overrides.get("client_mode") is None:
        return
    mode = str(overrides.get("client_mode") or "").strip().lower()
    if mode != "socks":
        raise OverrideValidationError("Hysteria client_mode must stay socks because local SOCKS5 auth is required")


def validate_overrides(protocol: ConnectionProtocol, overrides: dict[str, Any]) -> dict[str, Any]:
    overrides = overrides or {}

    if protocol == ConnectionProtocol.VLESS_REALITY:
        allowed = {
            "mode",
            "camouflage_sni_id",
            "connect_timeout_ms",
            "dial_timeout_ms",
            "local_socks_port",
            "local_socks_username",
            "local_socks_password",
            "tcp_fast_open",
        }
        forbidden = {"port", "server_port", "reality_server_port", "chain_sni"}
        _ensure_keys(overrides, allowed, forbidden)
        _validate_local_socks_port(overrides)
        _validate_local_socks_credentials(overrides)

    elif protocol == ConnectionProtocol.VLESS_WS_TLS:
        allowed = {
            "connect_timeout_ms",
            "dial_timeout_ms",
            "local_socks_port",
            "local_socks_username",
            "local_socks_password",
            "tcp_fast_open",
            "connect_host",
            # WS+TLS specifics
            "ws_path",
            "ws_host",
            "tls_server_name",
            "tls_insecure",
        }
        forbidden = {"port", "server_port"}
        _ensure_keys(overrides, allowed, forbidden)
        _validate_host_override(overrides, "connect_host")
        _validate_local_socks_port(overrides)
        _validate_local_socks_credentials(overrides)

    elif protocol == ConnectionProtocol.VLESS_GRPC_TLS:
        allowed = {
            "connect_timeout_ms",
            "dial_timeout_ms",
            "local_socks_port",
            "local_socks_username",
            "local_socks_password",
            "tcp_fast_open",
            "connect_host",
            "grpc_service_name",
            "grpc_authority",
            "tls_server_name",
            "tls_insecure",
        }
        forbidden = {"port", "server_port", "grpc_port"}
        _ensure_keys(overrides, allowed, forbidden)
        _validate_host_override(overrides, "connect_host")
        _validate_local_socks_port(overrides)
        _validate_local_socks_credentials(overrides)

    elif protocol == ConnectionProtocol.HYSTERIA2:
        allowed = {
            "client_mode",
            "up_mbps",
            "down_mbps",
            "socks_listen",
            "local_socks_username",
            "local_socks_password",
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
        _validate_hysteria_client_mode(overrides)
        _validate_local_socks_credentials(overrides)
        _validate_loopback_endpoint_override(overrides, "socks_listen")
        _validate_loopback_endpoint_override(overrides, "http_listen")

    elif protocol == ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS:
        allowed = {
            "local_socks_port",
            "local_socks_username",
            "local_socks_password",
            "method",
            "password",
            "shadowtls_password",
            "shadowtls_server_name",
            "alpn",
        }
        forbidden = {"port", "server_port", "shadowtls_port"}
        _ensure_keys(overrides, allowed, forbidden)
        _validate_local_socks_port(overrides)
        _validate_local_socks_credentials(overrides)

    elif protocol == ConnectionProtocol.WIREGUARD_WSTUNNEL:
        allowed = {
            "local_socks_port",
            "local_socks_username",
            "local_socks_password",
            "server",
            "tls_server_name",
            "wstunnel_path",
            "local_udp_listen",
            "wireguard_private_key",
            "wireguard_public_key",
            "wireguard_preshared_key",
            "wireguard_address",
            "allowed_ips",
            "dns",
            "mtu",
            "persistent_keepalive",
        }
        forbidden = {"port", "server_port", "wireguard_port", "wstunnel_port"}
        _ensure_keys(overrides, allowed, forbidden)
        _validate_local_socks_port(overrides)
        _validate_local_socks_credentials(overrides)
        _validate_loopback_endpoint_override(overrides, "local_udp_listen")
        _validate_absolute_http_path_override(overrides, "wstunnel_path")
        _validate_int_range_override(overrides, "mtu", min_value=1200, max_value=1420)
        _validate_int_range_override(overrides, "persistent_keepalive", min_value=0, max_value=60)

    else:
        raise OverrideValidationError(f"Unsupported protocol: {protocol}")

    return overrides
