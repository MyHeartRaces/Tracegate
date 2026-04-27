from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
import json
import os
from pathlib import Path
import shlex
from typing import Any

from tracegate.constants import (
    TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT,
    TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT,
    TRACEGATE_PUBLIC_UDP_PORT,
)


class PairedUdpObfsRunnerError(RuntimeError):
    pass


_PLAN_SCHEMA = "tracegate.paired-udp-obfs-runner-plan.v1"
_ALLOWED_MODES = {"udp2raw-faketcp": "faketcp", "udp2raw-icmp": "icmp"}
_PLACEHOLDERS = {"CHANGE_ME", "CHANGEME", "TODO", "TBD"}


@dataclass(frozen=True, slots=True)
class PairedUdpObfsProfile:
    path: Path
    backend: str
    mode: str
    raw_mode: str
    side: str
    listen: str
    target: str
    key: str
    udp2raw_bin: str
    cipher_mode: str
    auth_mode: str
    auto_firewall: bool
    requires_both_sides: bool
    fail_closed: bool
    no_host_wide_interception: bool
    no_nfqueue: bool
    public_udp_port: int
    forbid_udp_443: bool
    forbid_tcp_8443: bool
    dpi_mode: str
    packet_shape: str
    mtu_mode: str
    max_packet_size: int


def _parse_env_value(raw: str) -> str:
    lexer = shlex.shlex(raw, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    parts = list(lexer)
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    raise PairedUdpObfsRunnerError(f"invalid env value with unquoted whitespace: {raw}")


def _load_env(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise PairedUdpObfsRunnerError(f"paired UDP obfs profile is missing: {path}") from exc

    payload: dict[str, str] = {}
    for line_no, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].strip()
        if "=" not in stripped:
            raise PairedUdpObfsRunnerError(f"invalid paired UDP obfs env line {line_no}: missing '='")
        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            raise PairedUdpObfsRunnerError(f"invalid paired UDP obfs env line {line_no}: empty key")
        payload[key] = _parse_env_value(raw_value.strip())
    return payload


def _env_bool(payload: dict[str, str], key: str, *, default: bool) -> bool:
    raw = str(payload.get(key, "")).strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    raise PairedUdpObfsRunnerError(f"{key} must be boolean")


def _env_string(payload: dict[str, str], key: str, *, default: str = "") -> str:
    return str(payload.get(key) or default).strip()


def _env_int(payload: dict[str, str], key: str, *, default: int) -> int:
    raw = str(payload.get(key, "")).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise PairedUdpObfsRunnerError(f"{key} must be an integer") from exc
    return value


def _parse_endpoint(value: str) -> tuple[str, int]:
    raw = str(value or "").strip()
    host, sep, port_raw = raw.rpartition(":")
    if not sep or not host or not port_raw:
        raise ValueError(f"invalid endpoint: {raw or 'missing'}")
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ValueError(f"invalid endpoint port: {raw}") from exc
    if not host or port < 1 or port > 65535:
        raise ValueError(f"invalid endpoint: {raw}")
    return host, port


def _is_loopback_host(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _looks_placeholder(value: object) -> bool:
    raw = str(value or "").strip().upper()
    return not raw or raw.startswith("REPLACE_") or raw in _PLACEHOLDERS


def load_paired_udp_obfs_profile(
    path: str | Path,
    *,
    udp2raw_bin_override: str = "",
) -> PairedUdpObfsProfile:
    profile_path = Path(path)
    payload = _load_env(profile_path)

    backend = _env_string(payload, "TRACEGATE_UDP_OBFS_BACKEND", default="udp2raw").lower()
    if backend != "udp2raw":
        raise PairedUdpObfsRunnerError(f"TRACEGATE_UDP_OBFS_BACKEND must be udp2raw, got {backend or 'missing'}")

    mode = _env_string(payload, "TRACEGATE_UDP_OBFS_MODE", default="udp2raw-faketcp").lower()
    raw_mode = _ALLOWED_MODES.get(mode)
    if raw_mode is None:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_MODE must be udp2raw-faketcp or udp2raw-icmp")

    side = _env_string(payload, "TRACEGATE_UDP_OBFS_SIDE").lower()
    if side not in {"client", "server"}:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_SIDE must be client or server")

    listen = _env_string(payload, "TRACEGATE_UDP_OBFS_LISTEN")
    target = _env_string(payload, "TRACEGATE_UDP_OBFS_TARGET")
    try:
        listen_host, _listen_port = _parse_endpoint(listen)
        target_host, _target_port = _parse_endpoint(target)
    except ValueError as exc:
        raise PairedUdpObfsRunnerError(str(exc)) from exc

    if side == "client" and not _is_loopback_host(listen_host):
        raise PairedUdpObfsRunnerError("client paired UDP obfs listen endpoint must stay loopback-bound")
    if side == "server" and not _is_loopback_host(target_host):
        raise PairedUdpObfsRunnerError("server paired UDP obfs target endpoint must stay loopback-bound")

    key = _env_string(payload, "TRACEGATE_UDP_OBFS_KEY")
    if _looks_placeholder(key) or len(key) < 16:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_KEY must be a non-placeholder secret with at least 16 characters")

    udp2raw_bin = str(udp2raw_bin_override or "").strip() or _env_string(
        payload,
        "TRACEGATE_UDP_OBFS_UDP2RAW_BIN",
        default="udp2raw",
    )
    if not udp2raw_bin:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_UDP2RAW_BIN is missing")

    cipher_mode = _env_string(payload, "TRACEGATE_UDP_OBFS_CIPHER_MODE", default="aes128cbc").lower()
    if cipher_mode != "aes128cbc":
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_CIPHER_MODE must stay aes128cbc")

    auth_mode = _env_string(payload, "TRACEGATE_UDP_OBFS_AUTH_MODE", default="md5").lower()
    if auth_mode != "md5":
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_AUTH_MODE must stay md5")

    requires_both_sides = _env_bool(payload, "TRACEGATE_UDP_OBFS_REQUIRES_BOTH_SIDES", default=True)
    if not requires_both_sides:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_REQUIRES_BOTH_SIDES must stay true")

    fail_closed = _env_bool(payload, "TRACEGATE_UDP_OBFS_FAIL_CLOSED", default=True)
    if not fail_closed:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_FAIL_CLOSED must stay true")

    no_host_wide = _env_bool(payload, "TRACEGATE_UDP_OBFS_NO_HOST_WIDE_INTERCEPTION", default=True)
    if not no_host_wide:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_NO_HOST_WIDE_INTERCEPTION must stay true")

    no_nfqueue = _env_bool(payload, "TRACEGATE_UDP_OBFS_NO_NFQUEUE", default=True)
    if not no_nfqueue:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_NO_NFQUEUE must stay true")

    public_udp_port = _env_int(payload, "TRACEGATE_UDP_OBFS_PUBLIC_UDP_PORT", default=TRACEGATE_PUBLIC_UDP_PORT)
    if public_udp_port != TRACEGATE_PUBLIC_UDP_PORT:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_PUBLIC_UDP_PORT must stay 8443")

    forbid_udp_443 = _env_bool(payload, "TRACEGATE_UDP_OBFS_FORBID_UDP_443", default=True)
    if not forbid_udp_443:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_FORBID_UDP_443 must stay true")

    forbid_tcp_8443 = _env_bool(payload, "TRACEGATE_UDP_OBFS_FORBID_TCP_8443", default=True)
    if not forbid_tcp_8443:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_FORBID_TCP_8443 must stay true")

    dpi_mode = _env_string(
        payload,
        "TRACEGATE_UDP_OBFS_DPI_MODE",
        default="salamander-plus-scoped-paired-obfs",
    ).lower()
    if dpi_mode != "salamander-plus-scoped-paired-obfs":
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_DPI_MODE must stay salamander-plus-scoped-paired-obfs")

    packet_shape = _env_string(payload, "TRACEGATE_UDP_OBFS_PACKET_SHAPE", default="bounded-profile").lower()
    if packet_shape != "bounded-profile":
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_PACKET_SHAPE must stay bounded-profile")

    mtu_mode = _env_string(payload, "TRACEGATE_UDP_OBFS_MTU_MODE", default="clamp").lower()
    if mtu_mode != "clamp":
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_MTU_MODE must stay clamp")

    max_packet_size = _env_int(payload, "TRACEGATE_UDP_OBFS_MAX_PACKET_SIZE", default=1252)
    if max_packet_size < 1000 or max_packet_size > 1350:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_MAX_PACKET_SIZE must stay between 1000 and 1350")

    auto_firewall = _env_bool(payload, "TRACEGATE_UDP_OBFS_AUTO_FIREWALL", default=False)
    if auto_firewall:
        raise PairedUdpObfsRunnerError("TRACEGATE_UDP_OBFS_AUTO_FIREWALL must stay false; use a private scoped firewall layer")

    return PairedUdpObfsProfile(
        path=profile_path,
        backend=backend,
        mode=mode,
        raw_mode=raw_mode,
        side=side,
        listen=listen,
        target=target,
        key=key,
        udp2raw_bin=udp2raw_bin,
        cipher_mode=cipher_mode,
        auth_mode=auth_mode,
        auto_firewall=auto_firewall,
        requires_both_sides=requires_both_sides,
        fail_closed=fail_closed,
        no_host_wide_interception=no_host_wide,
        no_nfqueue=no_nfqueue,
        public_udp_port=public_udp_port,
        forbid_udp_443=forbid_udp_443,
        forbid_tcp_8443=forbid_tcp_8443,
        dpi_mode=dpi_mode,
        packet_shape=packet_shape,
        mtu_mode=mtu_mode,
        max_packet_size=max_packet_size,
    )


def _udp2raw_command(profile: PairedUdpObfsProfile, *, redact_secret: bool) -> list[str]:
    command = [
        profile.udp2raw_bin,
        "-c" if profile.side == "client" else "-s",
        "-l",
        profile.listen,
        "-r",
        profile.target,
        "-k",
        "REDACTED" if redact_secret else profile.key,
        "--raw-mode",
        profile.raw_mode,
        "--cipher-mode",
        profile.cipher_mode,
        "--auth-mode",
        profile.auth_mode,
    ]
    if profile.auto_firewall:
        command.append("-a")
    return command


def build_paired_udp_obfs_runner_plan(
    *,
    action: str,
    profile_path: str | Path,
    udp2raw_bin: str = "",
) -> dict[str, Any]:
    action_normalized = str(action or "").strip().lower()
    if action_normalized == "reload":
        action_normalized = "start"
    if action_normalized not in {"plan", "validate", "start", "stop"}:
        raise PairedUdpObfsRunnerError(f"unsupported paired UDP obfs action: {action}")

    profile = load_paired_udp_obfs_profile(profile_path, udp2raw_bin_override=udp2raw_bin)
    return {
        "schema": _PLAN_SCHEMA,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "action": action_normalized,
        "profile": str(profile.path),
        "backend": profile.backend,
        "mode": profile.mode,
        "side": profile.side,
        "listen": profile.listen,
        "target": profile.target,
        "command": _udp2raw_command(profile, redact_secret=True) if action_normalized != "stop" else [],
        "foreground": action_normalized == "start",
        "security": {
            "secretMaterialInline": False,
            "requiresBothSides": profile.requires_both_sides,
            "failClosed": profile.fail_closed,
            "noHostWideInterception": profile.no_host_wide_interception,
            "noNfqueue": profile.no_nfqueue,
            "autoFirewall": profile.auto_firewall,
            "cipherMode": profile.cipher_mode,
            "authMode": profile.auth_mode,
            "forbiddenPublicPorts": [
                {"protocol": "udp", "port": TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, "action": "drop"},
                {"protocol": "tcp", "port": TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT, "action": "drop"},
            ],
        },
        "dpiResistance": {
            "enabled": True,
            "mode": profile.dpi_mode,
            "portSplit": {
                "publicUdpPort": profile.public_udp_port,
                "forbidUdp443": profile.forbid_udp_443,
                "forbidTcp8443": profile.forbid_tcp_8443,
            },
            "packetShape": {
                "strategy": profile.packet_shape,
                "mtuMode": profile.mtu_mode,
                "maxPacketSize": profile.max_packet_size,
            },
        },
    }


def exec_paired_udp_obfs(profile_path: str | Path, *, udp2raw_bin: str = "") -> None:
    profile = load_paired_udp_obfs_profile(profile_path, udp2raw_bin_override=udp2raw_bin)
    command = _udp2raw_command(profile, redact_secret=False)
    os.execvp(command[0], command)


def plan_to_json(plan: dict[str, Any]) -> str:
    if plan.get("schema") != _PLAN_SCHEMA:
        raise PairedUdpObfsRunnerError("unsupported paired UDP obfs runner plan")
    return json.dumps(plan, ensure_ascii=True, indent=2) + "\n"
