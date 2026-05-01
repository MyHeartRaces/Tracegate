from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tracegate.constants import TRACEGATE_PUBLIC_UDP_PORT
from tracegate.services.mtproto import (
    MTPROTO_FAKE_TLS_PROFILE_NAME,
    MTProtoConfigError,
    build_mtproto_share_links,
    normalize_mtproto_domain,
)
from tracegate.services.connection_profiles import (
    router_transit_tcp_selected_profiles,
    router_transit_udp_selected_profiles,
    tcp_chain_selected_profiles,
    udp_chain_selected_profiles,
)
from tracegate.settings import (
    Settings,
    effective_mtproto_issued_state_file,
    effective_mtproto_public_profile_file,
    effective_private_runtime_root,
    effective_zapret_state_dir,
)


def _shell_quote(value: object) -> str:
    raw = str(value)
    return "'" + raw.replace("'", "'\"'\"'") + "'"


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _write_text_if_changed(path: Path, content: str) -> bool:
    current = _read_text(path)
    if current == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    return True


def _write_secret_text_if_changed(path: Path, content: str) -> bool:
    changed = _write_text_if_changed(path, content)
    try:
        current_mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        return changed
    if current_mode != 0o600:
        path.chmod(0o600)
        changed = True
    return changed


def _remove_if_exists(path: Path) -> bool:
    if not path.exists():
        return False
    path.unlink()
    return True


def _json_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, indent=2) + "\n"


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _profile_path(settings: Settings, *, role_upper: str) -> str:
    profile_dir = Path(str(settings.private_zapret_profile_dir or "").strip() or "/etc/tracegate/private/zapret")
    if role_upper == "ENTRY":
        profile_name = str(settings.private_zapret_profile_entry or "").strip() or "entry-lite.env"
    else:
        profile_name = str(settings.private_zapret_profile_transit or "").strip() or "transit-lite.env"
    return str(profile_dir / profile_name)


def _mtproto_profile_path(settings: Settings) -> str:
    profile_dir = Path(str(settings.private_zapret_profile_dir or "").strip() or "/etc/tracegate/private/zapret")
    profile_name = str(settings.private_zapret_profile_mtproto or "").strip() or "mtproto-extra.env"
    return str(profile_dir / profile_name)


def _interconnect_profile_path(settings: Settings) -> str:
    profile_dir = Path(str(settings.private_zapret_profile_dir or "").strip() or "/etc/tracegate/private/zapret")
    profile_name = str(settings.private_zapret_profile_interconnect or "").strip() or "entry-transit-stealth.env"
    return str(profile_dir / profile_name)


def _obfuscation_interface(settings: Settings, *, role_upper: str) -> str:
    if role_upper == "ENTRY":
        return str(settings.private_entry_interface or "").strip() or "eth0"
    return str(settings.private_transit_interface or "").strip() or "eth0"


def _role_state_dir(settings: Settings, *, role_lower: str) -> Path:
    return Path(effective_private_runtime_root(settings)) / "obfuscation" / role_lower


def _profiles_state_dir(settings: Settings, *, role_lower: str) -> Path:
    return Path(effective_private_runtime_root(settings)) / "profiles" / role_lower


def _link_crypto_state_dir(settings: Settings, *, role_lower: str) -> Path:
    return Path(effective_private_runtime_root(settings)) / "link-crypto" / role_lower


def _router_state_dir(settings: Settings, *, role_lower: str) -> Path:
    return Path(effective_private_runtime_root(settings)) / "router" / role_lower


def _router_profile_path(settings: Settings, *, role_lower: str, link_class: str, profile_name: str) -> str:
    profile_dir = Path(str(settings.private_router_profile_dir or "").strip() or "/etc/tracegate/private/router")
    safe_role = str(role_lower or "").strip().lower() or "unknown"
    safe_class = str(link_class or "").strip() or "unknown"
    safe_profile = str(profile_name or "").strip() or "profile.json"
    return str(profile_dir / safe_role / safe_class / safe_profile)


def _mieru_profile_path(settings: Settings, *, side: str) -> str:
    profile_dir = Path(str(settings.private_mieru_profile_dir or "").strip() or "/etc/tracegate/private/mieru")
    if side.strip().lower() == "client":
        profile_name = str(settings.private_mieru_client_profile or "").strip() or "client.json"
    else:
        profile_name = str(settings.private_mieru_server_profile or "").strip() or "server.json"
    return str(profile_dir / profile_name)


def _udp_link_profile_path(settings: Settings, *, side: str) -> str:
    profile_dir = Path(str(settings.private_udp_link_profile_dir or "").strip() or "/etc/tracegate/private/udp-link")
    if side.strip().lower() == "client":
        profile_name = str(settings.private_udp_link_client_profile or "").strip() or "client.yaml"
    else:
        profile_name = str(settings.private_udp_link_server_profile or "").strip() or "server.yaml"
    return str(profile_dir / profile_name)


def _udp_link_obfs_profile_path(settings: Settings) -> str:
    profile_dir = Path(str(settings.private_udp_link_profile_dir or "").strip() or "/etc/tracegate/private/udp-link")
    profile_name = str(settings.private_udp_link_obfs_profile or "").strip() or "salamander.env"
    return str(profile_dir / profile_name)


def _udp_link_paired_obfs_profile_path(settings: Settings) -> str:
    profile_dir = Path(str(settings.private_udp_link_profile_dir or "").strip() or "/etc/tracegate/private/udp-link")
    profile_name = str(settings.private_udp_link_paired_obfs_profile or "").strip() or "paired-obfs.env"
    return str(profile_dir / profile_name)


def _link_crypto_private_profile_path(settings: Settings, profile_name: object, *, fallback: str) -> str:
    profile_dir = Path(str(settings.private_link_crypto_profile_dir or "").strip() or "/etc/tracegate/private/link-crypto")
    safe_name = str(profile_name or "").strip() or fallback
    return str(profile_dir / safe_name)


def _private_file_ref(path: str) -> dict[str, Any]:
    return {
        "kind": "file",
        "path": path,
        "secretMaterial": True,
    }


def _shadowtls_profile_path(settings: Settings, *, role_upper: str) -> str:
    profile_dir = Path(str(settings.private_shadowtls_profile_dir or "").strip() or "/etc/tracegate/private/shadowtls")
    if role_upper == "ENTRY":
        profile_name = str(settings.private_shadowtls_profile_entry or "").strip() or "entry-config.yaml"
    else:
        profile_name = str(settings.private_shadowtls_profile_transit or "").strip() or "transit-config.yaml"
    return str(profile_dir / profile_name)


def _obfuscation_state_payload(
    settings: Settings,
    *,
    runtime_contract_path: Path,
    runtime_contract_payload: dict[str, Any],
) -> dict[str, Any]:
    role_upper = str(runtime_contract_payload.get("role") or "").strip().upper() or "UNKNOWN"
    fronting = runtime_contract_payload.get("fronting")
    fronting_block = fronting if isinstance(fronting, dict) else {}
    xray = runtime_contract_payload.get("xray")
    xray_block = xray if isinstance(xray, dict) else {}
    decoy = runtime_contract_payload.get("decoy")
    decoy_block = decoy if isinstance(decoy, dict) else {}

    try:
        mtproto_public_port = int(fronting_block.get("mtprotoPublicPort") or 443)
    except (TypeError, ValueError):
        mtproto_public_port = 443
    try:
        public_udp_port = int(
            fronting_block.get("publicUdpPort")
            or fronting_block.get("udpPublicPort")
            or TRACEGATE_PUBLIC_UDP_PORT
        )
    except (TypeError, ValueError):
        public_udp_port = TRACEGATE_PUBLIC_UDP_PORT
    public_udp_owner = str(fronting_block.get("publicUdpOwner") or fronting_block.get("udp443Owner") or "").strip()

    return {
        "role": role_upper,
        "interface": _obfuscation_interface(settings, role_upper=role_upper),
        "runtimeProfile": str(runtime_contract_payload.get("runtimeProfile") or "").strip() or "tracegate-2.2",
        "runtimeContractPath": str(runtime_contract_path),
        "contractPresent": runtime_contract_path.exists(),
        "backend": str(settings.private_obfuscation_backend or "").strip().lower() or "zapret2",
        "decoyRoots": [str(value) for value in (decoy_block.get("nginxRoots") or []) if str(value).strip()],
        "splitHysteriaMasqueradeDirs": [
            str(value) for value in (decoy_block.get("splitHysteriaMasqueradeDirs") or []) if str(value).strip()
        ],
        "xrayHysteriaMasqueradeDirs": [
            str(value) for value in (decoy_block.get("xrayHysteriaMasqueradeDirs") or []) if str(value).strip()
        ],
        "xrayConfigPaths": [str(value) for value in (xray_block.get("configPaths") or []) if str(value).strip()],
        "xrayHysteriaInboundTags": [str(value) for value in (xray_block.get("hysteriaInboundTags") or []) if str(value).strip()],
        "finalMaskEnabled": bool(xray_block.get("finalMaskEnabled", False)),
        "echEnabled": bool(xray_block.get("echEnabled", False)),
        "public": {
            "zapretProfileFile": _profile_path(settings, role_upper=role_upper),
            "zapretInterconnectProfileFile": _interconnect_profile_path(settings),
            "zapretMtprotoProfileFile": _mtproto_profile_path(settings),
            "zapretPolicyDir": str(settings.private_zapret_policy_dir or "").strip() or "/etc/tracegate/private/zapret",
            "zapretStateDir": effective_zapret_state_dir(settings),
        },
        "fronting": {
            "tcp443Owner": str(fronting_block.get("tcp443Owner") or "").strip(),
            "publicUdpPort": public_udp_port,
            "publicUdpOwner": public_udp_owner,
            "udp443Owner": public_udp_owner,
            "touchUdp443": bool(fronting_block.get("touchUdp443", False)),
            "mtprotoDomain": str(fronting_block.get("mtprotoDomain") or "").strip(),
            "mtprotoPublicPort": mtproto_public_port,
            "mtprotoFrontingMode": str(fronting_block.get("mtprotoFrontingMode") or "dedicated-dns-only").strip().lower(),
        },
    }


def _write_obfuscation_state(
    settings: Settings,
    *,
    runtime_contract_path: Path,
    runtime_contract_payload: dict[str, Any],
) -> bool:
    payload = _obfuscation_state_payload(
        settings,
        runtime_contract_path=runtime_contract_path,
        runtime_contract_payload=runtime_contract_payload,
    )
    role_lower = str(payload["role"]).lower()
    state_dir = _role_state_dir(settings, role_lower=role_lower)
    json_path = state_dir / "runtime-state.json"
    env_path = state_dir / "runtime-state.env"

    env_lines = [
        f"TRACEGATE_RUNTIME_ROLE={_shell_quote(payload['role'])}",
        f"TRACEGATE_NETWORK_INTERFACE={_shell_quote(payload['interface'])}",
        f"TRACEGATE_RUNTIME_PROFILE={_shell_quote(payload['runtimeProfile'])}",
        f"TRACEGATE_RUNTIME_CONTRACT={_shell_quote(payload['runtimeContractPath'])}",
        f"TRACEGATE_RUNTIME_CONTRACT_PRESENT={_shell_quote(_bool_text(bool(payload['contractPresent'])))}",
        f"TRACEGATE_RUNTIME_STATE_JSON={_shell_quote(str(json_path))}",
        f"TRACEGATE_OBFUSCATION_BACKEND={_shell_quote(payload['backend'])}",
        f"TRACEGATE_DECOY_ROOTS={_shell_quote(':'.join(payload['decoyRoots']))}",
        f"TRACEGATE_SPLIT_HYSTERIA_DIRS={_shell_quote(':'.join(payload['splitHysteriaMasqueradeDirs']))}",
        f"TRACEGATE_XRAY_HYSTERIA_DIRS={_shell_quote(':'.join(payload['xrayHysteriaMasqueradeDirs']))}",
        f"TRACEGATE_XRAY_CONFIG_PATHS={_shell_quote(':'.join(payload['xrayConfigPaths']))}",
        f"TRACEGATE_XRAY_HYSTERIA_TAGS={_shell_quote(':'.join(payload['xrayHysteriaInboundTags']))}",
        f"TRACEGATE_FINALMASK_ENABLED={_shell_quote(_bool_text(bool(payload['finalMaskEnabled'])))}",
        f"TRACEGATE_ECH_ENABLED={_shell_quote(_bool_text(bool(payload['echEnabled'])))}",
        f"TRACEGATE_ZAPRET_PROFILE_FILE={_shell_quote(payload['public']['zapretProfileFile'])}",
        f"TRACEGATE_ZAPRET_INTERCONNECT_PROFILE_FILE={_shell_quote(payload['public']['zapretInterconnectProfileFile'])}",
        f"TRACEGATE_ZAPRET_MTPROTO_PROFILE_FILE={_shell_quote(payload['public']['zapretMtprotoProfileFile'])}",
        f"TRACEGATE_ZAPRET_POLICY_DIR={_shell_quote(payload['public']['zapretPolicyDir'])}",
        f"TRACEGATE_ZAPRET_STATE_DIR={_shell_quote(payload['public']['zapretStateDir'])}",
        f"TRACEGATE_TCP_443_OWNER={_shell_quote(payload['fronting']['tcp443Owner'])}",
        f"TRACEGATE_PUBLIC_UDP_PORT={_shell_quote(payload['fronting']['publicUdpPort'])}",
        f"TRACEGATE_PUBLIC_UDP_OWNER={_shell_quote(payload['fronting']['publicUdpOwner'])}",
        f"TRACEGATE_UDP_443_OWNER={_shell_quote(payload['fronting']['udp443Owner'])}",
        f"TRACEGATE_TOUCH_UDP_443={_shell_quote(_bool_text(bool(payload['fronting']['touchUdp443'])))}",
        f"TRACEGATE_MTPROTO_DOMAIN={_shell_quote(payload['fronting']['mtprotoDomain'])}",
        f"TRACEGATE_MTPROTO_PUBLIC_PORT={_shell_quote(payload['fronting']['mtprotoPublicPort'])}",
        f"TRACEGATE_MTPROTO_FRONTING_MODE={_shell_quote(payload['fronting']['mtprotoFrontingMode'])}",
    ]

    changed = False
    changed = _write_text_if_changed(json_path, _json_text(payload)) or changed
    changed = _write_text_if_changed(env_path, "\n".join(env_lines) + "\n") or changed
    return changed


def _link_crypto_local_listen(settings: Settings, *, port: int) -> str:
    bind_host = str(settings.private_link_crypto_bind_host or "").strip() or "127.0.0.1"
    return f"{bind_host}:{int(port)}"


def _udp_link_local_listen(settings: Settings, *, port: int) -> str:
    bind_host = str(settings.private_udp_link_bind_host or "").strip() or "127.0.0.1"
    return f"{bind_host}:{int(port)}"


def _udp_link_hardening(settings: Settings) -> dict[str, Any]:
    return {
        "enabled": bool(settings.private_udp_link_hardening_enabled),
        "failClosed": True,
        "requirePrivateAuth": True,
        "rejectAnonymous": True,
        "antiReplay": {
            "enabled": bool(settings.private_udp_link_anti_replay_enabled),
            "windowPackets": int(settings.private_udp_link_replay_window_packets or 4096),
        },
        "antiAmplification": {
            "enabled": bool(settings.private_udp_link_anti_amplification_enabled),
            "maxUnvalidatedBytes": int(settings.private_udp_link_max_unvalidated_bytes or 1200),
        },
        "rateLimit": {
            "enabled": bool(settings.private_udp_link_rate_limit_enabled),
            "handshakePerMinute": int(settings.private_udp_link_handshake_rate_per_minute or 120),
            "newSessionPerMinute": int(settings.private_udp_link_new_session_rate_per_minute or 60),
        },
        "mtu": {
            "mode": str(settings.private_udp_link_mtu_mode or "").strip() or "clamp",
            "maxPacketSize": int(settings.private_udp_link_mtu_max_packet_size or 1252),
        },
        "keyRotation": {
            "enabled": bool(settings.private_udp_link_key_rotation_enabled),
            "strategy": "generation-drain",
            "maxAgeSeconds": int(settings.private_udp_link_key_rotation_max_age_seconds or 3600),
            "overlapSeconds": int(settings.private_udp_link_key_rotation_overlap_seconds or 120),
        },
        "sourceValidation": {
            "enabled": bool(settings.private_udp_link_source_validation_enabled),
            "mode": str(settings.private_udp_link_source_validation_mode or "").strip() or "profile-bound-remote",
        },
    }


def _udp_link_dpi_resistance(settings: Settings) -> dict[str, Any]:
    return {
        "enabled": True,
        "mode": "salamander-plus-scoped-paired-obfs",
        "portSplit": {
            "publicUdpPort": TRACEGATE_PUBLIC_UDP_PORT,
            "forbidUdp443": False,
            "forbidTcp8443": True,
        },
        "requiredLayers": [
            "hysteria2-quic",
            "salamander",
            "private-auth",
            "anti-replay",
            "anti-amplification",
            "mtu-clamp",
            "source-validation",
        ],
        "pairedObfs": {
            "supported": True,
            "enabled": bool(settings.private_udp_link_paired_obfs_enabled),
            "backend": "udp2raw",
            "requiresBothSides": True,
            "failClosed": True,
        },
        "packetShape": {
            "strategy": "bounded-profile",
            "mtuMode": str(settings.private_udp_link_mtu_mode or "").strip() or "clamp",
            "maxPacketSize": int(settings.private_udp_link_mtu_max_packet_size or 1252),
        },
    }


def _link_crypto_remote_endpoint(host: object, *, fallback_host: str, remote_port: int) -> str:
    remote_host = str(host or "").strip() or fallback_host
    return f"{remote_host}:{int(remote_port)}"


def _normalize_link_wss_path(value: object) -> str:
    raw = str(value or "").strip() or "/cdn-cgi/tracegate-link"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    return raw


def _link_crypto_outer_wss_server_name(settings: Settings) -> str:
    return str(settings.private_link_crypto_outer_wss_server_name or "").strip() or "bridge.example.com"


def _link_crypto_outer_carrier(settings: Settings, *, link_class: str, side: str) -> dict[str, Any]:
    if link_class != "entry-transit" or not bool(settings.private_link_crypto_outer_carrier_enabled):
        return {
            "enabled": False,
            "mode": "direct",
            "secretMaterial": False,
            "tlsPinning": {"required": False, "mode": "none", "secretMaterial": False},
            "admission": {"required": False, "mode": "none", "secretMaterial": False},
        }

    server_name = _link_crypto_outer_wss_server_name(settings)
    public_port = int(settings.private_link_crypto_outer_wss_public_port or 443)
    public_path = _normalize_link_wss_path(settings.private_link_crypto_outer_wss_path)
    client_port = int(settings.private_link_crypto_outer_wss_client_port or 14081)
    server_port = int(settings.private_link_crypto_outer_wss_server_port or 14082)
    transit_port = int(settings.private_link_crypto_transit_port or 10882)
    spki_profile = _link_crypto_private_profile_path(
        settings,
        settings.private_link_crypto_outer_wss_spki_profile,
        fallback="outer-wss-spki.env",
    )
    admission_profile = _link_crypto_private_profile_path(
        settings,
        settings.private_link_crypto_outer_wss_admission_profile,
        fallback="outer-wss-admission.env",
    )
    return {
        "enabled": True,
        "mode": str(settings.private_link_crypto_outer_carrier_mode or "wss").strip() or "wss",
        "protocol": "websocket-tls",
        "serverName": server_name,
        "publicPort": public_port,
        "publicPath": public_path,
        "url": f"wss://{server_name}:{public_port}{public_path}",
        "verifyTls": bool(settings.private_link_crypto_outer_wss_verify_tls),
        "secretMaterial": False,
        "side": side,
        "localEndpoint": f"127.0.0.1:{client_port if side == 'client' else server_port}",
        "entryClientListen": f"127.0.0.1:{client_port}",
        "transitServerListen": f"127.0.0.1:{server_port}",
        "transitTarget": f"127.0.0.1:{transit_port}",
        "tlsPinning": {
            "required": True,
            "mode": "spki-sha256",
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref(spki_profile),
            "secretMaterial": False,
        },
        "admission": {
            "required": True,
            "mode": "hmac-sha256-generation-bound",
            "carrier": "websocket-subprotocol",
            "header": "Sec-WebSocket-Protocol",
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref(admission_profile),
            "rejectUnauthenticated": True,
            "secretMaterial": False,
        },
    }


def _link_crypto_zapret2_policy(settings: Settings, *, profile_file: str) -> dict[str, Any]:
    return {
        "enabled": bool(settings.private_link_crypto_zapret2_enabled),
        "required": True,
        "profileFile": profile_file,
        "profileSource": "private-file-reference",
        "profileRef": _private_file_ref(profile_file),
        "packetShaping": "zapret2-scoped",
        "applyMode": "marked-flow-only",
        "scope": "link-crypto-flow-only",
        "targetSurfaces": ["tcp/443", "entry-transit", "router-link-crypto"],
        "hostWideInterception": False,
        "nfqueue": False,
        "failOpen": True,
    }


def _link_crypto_tcp_dpi_resistance(settings: Settings, *, link_class: str, outer_carrier_enabled: bool) -> dict[str, Any]:
    zapret_profile = _interconnect_profile_path(settings)
    shaping_profile = _link_crypto_private_profile_path(
        settings,
        settings.private_link_crypto_tcp_shaping_profile,
        fallback="tcp-shaping.env",
    )
    promotion_profile = _link_crypto_private_profile_path(
        settings,
        settings.private_link_crypto_promotion_preflight_profile,
        fallback="promotion-preflight.env",
    )
    required_layers = [
        "mieru-private-auth",
        "scoped-zapret2",
        "private-zapret2-profile",
        "loopback-only",
        "generation-drain",
        "no-direct-backhaul",
    ]
    if outer_carrier_enabled:
        required_layers.extend(["outer-wss-tls", "spki-sha256-pin", "hmac-admission"])

    return {
        "enabled": True,
        "mode": "mieru-wss-spki-hmac-zapret2-scoped" if outer_carrier_enabled else "mieru-zapret2-scoped",
        "requiredLayers": required_layers,
        "outerCarrier": {
            "required": bool(outer_carrier_enabled),
            "spkiPinningRequired": bool(outer_carrier_enabled),
            "hmacAdmissionRequired": bool(outer_carrier_enabled),
        },
        "zapret2": {
            "required": True,
            "enabled": bool(settings.private_link_crypto_zapret2_enabled),
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref(zapret_profile),
            "packetShaping": "zapret2-scoped",
            "applyMode": "marked-flow-only",
            "scope": "link-crypto-flow-only",
            "hostWideInterception": False,
            "nfqueue": False,
        },
        "trafficShaping": {
            "required": True,
            "strategy": "private-zapret2-profile",
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref(shaping_profile),
            "scope": "marked-flow-only",
            "target": "tcp/443-outer-wss" if outer_carrier_enabled else "tcp/443-link-crypto",
            "secretMaterial": False,
        },
        "promotionPreflight": {
            "required": True,
            "failClosed": True,
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref(promotion_profile),
            "checks": [
                "mieru-private-auth",
                "zapret2-scoped-profile",
                "no-direct-backhaul",
            ]
            + (["spki-pin", "hmac-admission"] if outer_carrier_enabled else []),
            "secretMaterial": False,
        },
        "linkClass": link_class,
    }


def _link_crypto_profile_ref(settings: Settings, *, side: str) -> dict[str, Any]:
    return {
        "kind": "file",
        "path": _mieru_profile_path(settings, side=side),
        "secretMaterial": True,
    }


def _link_crypto_row(
    settings: Settings,
    *,
    link_class: str,
    role_upper: str,
    side: str,
    local_listen: str,
    remote_role: str,
    remote_endpoint: str,
    selected_profiles: list[str],
) -> dict[str, Any]:
    outer_carrier = _link_crypto_outer_carrier(settings, link_class=link_class, side=side)
    return {
        "class": link_class,
        "enabled": True,
        "role": role_upper,
        "side": side,
        "carrier": "mieru",
        "managedBy": "link-crypto",
        "xrayBackhaul": False,
        "generation": int(settings.private_link_crypto_generation or 1),
        "profileRef": _link_crypto_profile_ref(settings, side=side),
        "local": {
            "listen": local_listen,
            "auth": {
                "required": True,
                "mode": "private-profile",
            },
        },
        "remote": {
            "role": remote_role,
            "endpoint": remote_endpoint,
        },
        "outerCarrier": outer_carrier,
        "selectedProfiles": selected_profiles,
        "zapret2": _link_crypto_zapret2_policy(settings, profile_file=_interconnect_profile_path(settings)),
        "dpiResistance": _link_crypto_tcp_dpi_resistance(
            settings,
            link_class=link_class,
            outer_carrier_enabled=bool(outer_carrier.get("enabled", False)),
        ),
        "rotation": {
            "strategy": "generation-drain",
            "restartExisting": False,
        },
        "stability": {
            "failOpen": True,
            "bypassOnFailure": True,
            "dropUnrelatedTraffic": False,
        },
    }


def _udp_link_row(
    settings: Settings,
    *,
    link_class: str,
    role_upper: str,
    side: str,
    local_listen: str,
    remote_role: str,
    remote_endpoint: str,
    selected_profiles: list[str],
) -> dict[str, Any]:
    return {
        "class": link_class,
        "enabled": True,
        "role": role_upper,
        "side": side,
        "carrier": "hysteria2",
        "transport": "udp-quic",
        "managedBy": "link-crypto",
        "xrayBackhaul": False,
        "generation": int(settings.private_link_crypto_generation or 1),
        "profileRef": {
            "kind": "file",
            "path": _udp_link_profile_path(settings, side=side),
            "secretMaterial": True,
        },
        "local": {
            "listen": local_listen,
            "protocol": "udp",
            "auth": {
                "required": True,
                "mode": "private-profile",
            },
        },
        "remote": {
            "role": remote_role,
            "endpoint": remote_endpoint,
            "protocol": "udp-quic",
        },
        "datagram": {
            "udpCapable": True,
            "innerTransports": ["hysteria2-quic"],
            "preferredForProfiles": selected_profiles,
        },
        "obfs": {
            "type": "salamander",
            "required": True,
            "profileRef": {
                "kind": "file",
                "path": _udp_link_obfs_profile_path(settings),
                "secretMaterial": True,
            },
        },
        "pairedObfs": {
            "enabled": bool(settings.private_udp_link_paired_obfs_enabled),
            "backend": "udp2raw",
            "mode": str(settings.private_udp_link_paired_obfs_mode or "").strip() or "udp2raw-faketcp",
            "requiresBothSides": True,
            "failClosed": True,
            "noHostWideInterception": True,
            "noNfqueue": True,
            "profileRef": {
                "kind": "file",
                "path": _udp_link_paired_obfs_profile_path(settings),
                "secretMaterial": True,
            },
        },
        "hardening": _udp_link_hardening(settings),
        "dpiResistance": _udp_link_dpi_resistance(settings),
        "selectedProfiles": selected_profiles,
        "rotation": {
            "strategy": "generation-drain",
            "restartExisting": False,
        },
        "stability": {
            "failOpen": False,
            "bypassOnFailure": False,
            "dropUnrelatedTraffic": False,
        },
    }


def _link_crypto_payload(
    settings: Settings,
    *,
    runtime_contract_path: Path,
    runtime_contract_payload: dict[str, Any],
) -> dict[str, Any]:
    role_upper = str(runtime_contract_payload.get("role") or "").strip().upper() or "UNKNOWN"
    links: list[dict[str, Any]] = []
    remote_port = int(settings.private_link_crypto_remote_port or 443)
    udp_links: list[dict[str, Any]] = []
    udp_remote_port = int(settings.private_udp_link_remote_port or TRACEGATE_PUBLIC_UDP_PORT)
    entry_transit_udp_enabled = bool(settings.private_link_crypto_enabled and settings.private_udp_link_enabled)

    if role_upper == "ENTRY":
        if bool(settings.private_link_crypto_enabled):
            links.append(
                _link_crypto_row(
                    settings,
                    link_class="entry-transit",
                    role_upper=role_upper,
                    side="client",
                    local_listen=_link_crypto_local_listen(settings, port=int(settings.private_link_crypto_entry_port)),
                    remote_role="TRANSIT",
                    remote_endpoint=_link_crypto_remote_endpoint(
                        settings.default_transit_host,
                        fallback_host="transit.example.com",
                        remote_port=remote_port,
                    ),
                    selected_profiles=tcp_chain_selected_profiles(),
                )
            )
        if entry_transit_udp_enabled:
            udp_links.append(
                _udp_link_row(
                    settings,
                    link_class="entry-transit-udp",
                    role_upper=role_upper,
                    side="client",
                    local_listen=_udp_link_local_listen(settings, port=int(settings.private_udp_link_entry_port)),
                    remote_role="TRANSIT",
                    remote_endpoint=_link_crypto_remote_endpoint(
                        settings.default_transit_host,
                        fallback_host="transit.example.com",
                        remote_port=udp_remote_port,
                    ),
                    selected_profiles=udp_chain_selected_profiles(),
                )
            )
        if bool(settings.private_link_crypto_router_entry_enabled):
            links.append(
                _link_crypto_row(
                    settings,
                    link_class="router-entry",
                    role_upper=role_upper,
                    side="server",
                    local_listen=_link_crypto_local_listen(
                        settings,
                        port=int(settings.private_link_crypto_router_entry_port),
                    ),
                    remote_role="ROUTER",
                    remote_endpoint=_link_crypto_remote_endpoint(
                        settings.default_entry_host,
                        fallback_host="entry.example.com",
                        remote_port=remote_port,
                    ),
                    selected_profiles=tcp_chain_selected_profiles(),
                )
            )
        if bool(settings.private_udp_link_router_entry_enabled):
            udp_links.append(
                _udp_link_row(
                    settings,
                    link_class="router-entry-udp",
                    role_upper=role_upper,
                    side="server",
                    local_listen=_udp_link_local_listen(settings, port=int(settings.private_udp_link_router_entry_port)),
                    remote_role="ROUTER",
                    remote_endpoint=_link_crypto_remote_endpoint(
                        settings.default_entry_host,
                        fallback_host="entry.example.com",
                        remote_port=udp_remote_port,
                    ),
                    selected_profiles=udp_chain_selected_profiles(),
                )
            )
    elif role_upper == "TRANSIT":
        if bool(settings.private_link_crypto_enabled):
            links.append(
                _link_crypto_row(
                    settings,
                    link_class="entry-transit",
                    role_upper=role_upper,
                    side="server",
                    local_listen=_link_crypto_local_listen(settings, port=int(settings.private_link_crypto_transit_port)),
                    remote_role="ENTRY",
                    remote_endpoint=_link_crypto_remote_endpoint(
                        settings.default_entry_host,
                        fallback_host="entry.example.com",
                        remote_port=remote_port,
                    ),
                    selected_profiles=tcp_chain_selected_profiles(),
                )
            )
        if entry_transit_udp_enabled:
            udp_links.append(
                _udp_link_row(
                    settings,
                    link_class="entry-transit-udp",
                    role_upper=role_upper,
                    side="server",
                    local_listen=_udp_link_local_listen(settings, port=int(settings.private_udp_link_transit_port)),
                    remote_role="ENTRY",
                    remote_endpoint=_link_crypto_remote_endpoint(
                        settings.default_entry_host,
                        fallback_host="entry.example.com",
                        remote_port=udp_remote_port,
                    ),
                    selected_profiles=udp_chain_selected_profiles(),
                )
            )
        if bool(settings.private_link_crypto_router_transit_enabled):
            links.append(
                _link_crypto_row(
                    settings,
                    link_class="router-transit",
                    role_upper=role_upper,
                    side="server",
                    local_listen=_link_crypto_local_listen(
                        settings,
                        port=int(settings.private_link_crypto_router_transit_port),
                    ),
                    remote_role="ROUTER",
                    remote_endpoint=_link_crypto_remote_endpoint(
                        settings.default_transit_host,
                        fallback_host="transit.example.com",
                        remote_port=remote_port,
                    ),
                    selected_profiles=router_transit_tcp_selected_profiles(),
                )
            )
        if bool(settings.private_udp_link_router_transit_enabled):
            udp_links.append(
                _udp_link_row(
                    settings,
                    link_class="router-transit-udp",
                    role_upper=role_upper,
                    side="server",
                    local_listen=_udp_link_local_listen(settings, port=int(settings.private_udp_link_router_transit_port)),
                    remote_role="ROUTER",
                    remote_endpoint=_link_crypto_remote_endpoint(
                        settings.default_transit_host,
                        fallback_host="transit.example.com",
                        remote_port=udp_remote_port,
                    ),
                    selected_profiles=router_transit_udp_selected_profiles(),
                )
            )

    return {
        "schema": "tracegate.link-crypto.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": str(runtime_contract_payload.get("runtimeProfile") or "").strip() or "tracegate-2.2",
        "runtimeContractPath": str(runtime_contract_path),
        "transportProfiles": runtime_contract_payload.get("transportProfiles") or {},
        "secretMaterial": False,
        "counts": {
            "total": len(links),
            "entryTransit": len([row for row in links if row.get("class") == "entry-transit"]),
            "routerEntry": len([row for row in links if row.get("class") == "router-entry"]),
            "routerTransit": len([row for row in links if row.get("class") == "router-transit"]),
        },
        "links": links,
        "udpCounts": {
            "total": len(udp_links),
            "entryTransitUdp": len([row for row in udp_links if row.get("class") == "entry-transit-udp"]),
            "routerEntryUdp": len([row for row in udp_links if row.get("class") == "router-entry-udp"]),
            "routerTransitUdp": len([row for row in udp_links if row.get("class") == "router-transit-udp"]),
        },
        "udpLinks": udp_links,
    }


def _write_link_crypto_state(
    settings: Settings,
    *,
    runtime_contract_path: Path,
    runtime_contract_payload: dict[str, Any],
) -> bool:
    payload = _link_crypto_payload(
        settings,
        runtime_contract_path=runtime_contract_path,
        runtime_contract_payload=runtime_contract_payload,
    )
    role_lower = str(payload["role"]).lower()
    state_dir = _link_crypto_state_dir(settings, role_lower=role_lower)
    json_path = state_dir / "desired-state.json"
    env_path = state_dir / "desired-state.env"
    link_classes = [str(row.get("class") or "").strip() for row in payload["links"] if str(row.get("class") or "").strip()]
    udp_link_classes = [
        str(row.get("class") or "").strip()
        for row in payload.get("udpLinks", [])
        if str(row.get("class") or "").strip()
    ]
    outer_carrier_enabled = "entry-transit" in link_classes and bool(settings.private_link_crypto_outer_carrier_enabled)

    env_lines = [
        f"TRACEGATE_LINK_CRYPTO_ROLE={_shell_quote(payload['role'])}",
        f"TRACEGATE_LINK_CRYPTO_RUNTIME_PROFILE={_shell_quote(payload['runtimeProfile'])}",
        f"TRACEGATE_LINK_CRYPTO_STATE_JSON={_shell_quote(str(json_path))}",
        f"TRACEGATE_LINK_CRYPTO_SECRET_MATERIAL={_shell_quote(_bool_text(bool(payload['secretMaterial'])))}",
        f"TRACEGATE_LINK_CRYPTO_COUNT={_shell_quote(payload['counts']['total'])}",
        f"TRACEGATE_LINK_CRYPTO_CLASSES={_shell_quote(':'.join(link_classes))}",
        f"TRACEGATE_LINK_CRYPTO_CARRIER={_shell_quote('mieru')}",
        f"TRACEGATE_LINK_CRYPTO_UDP_COUNT={_shell_quote(payload.get('udpCounts', {}).get('total', 0))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_CLASSES={_shell_quote(':'.join(udp_link_classes))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_CARRIER={_shell_quote('hysteria2')}",
        f"TRACEGATE_LINK_CRYPTO_UDP_REMOTE_PORT={_shell_quote(int(settings.private_udp_link_remote_port or TRACEGATE_PUBLIC_UDP_PORT))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_SALAMANDER_REQUIRED={_shell_quote(_bool_text(True))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_PAIRED_OBFS_ENABLED={_shell_quote(_bool_text(bool(settings.private_udp_link_paired_obfs_enabled)))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_PAIRED_OBFS_MODE={_shell_quote(str(settings.private_udp_link_paired_obfs_mode or '').strip() or 'udp2raw-faketcp')}",
        f"TRACEGATE_LINK_CRYPTO_UDP_HARDENING_ENABLED={_shell_quote(_bool_text(bool(settings.private_udp_link_hardening_enabled)))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_ANTI_REPLAY_ENABLED={_shell_quote(_bool_text(bool(settings.private_udp_link_anti_replay_enabled)))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_REPLAY_WINDOW_PACKETS={_shell_quote(int(settings.private_udp_link_replay_window_packets or 4096))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_ANTI_AMPLIFICATION_ENABLED={_shell_quote(_bool_text(bool(settings.private_udp_link_anti_amplification_enabled)))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_MAX_UNVALIDATED_BYTES={_shell_quote(int(settings.private_udp_link_max_unvalidated_bytes or 1200))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_HANDSHAKE_RATE_PER_MINUTE={_shell_quote(int(settings.private_udp_link_handshake_rate_per_minute or 120))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_NEW_SESSION_RATE_PER_MINUTE={_shell_quote(int(settings.private_udp_link_new_session_rate_per_minute or 60))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_MTU_MODE={_shell_quote(str(settings.private_udp_link_mtu_mode or '').strip() or 'clamp')}",
        f"TRACEGATE_LINK_CRYPTO_UDP_MTU_MAX_PACKET_SIZE={_shell_quote(int(settings.private_udp_link_mtu_max_packet_size or 1252))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_KEY_ROTATION_MAX_AGE_SECONDS={_shell_quote(int(settings.private_udp_link_key_rotation_max_age_seconds or 3600))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_KEY_ROTATION_OVERLAP_SECONDS={_shell_quote(int(settings.private_udp_link_key_rotation_overlap_seconds or 120))}",
        f"TRACEGATE_LINK_CRYPTO_UDP_SOURCE_VALIDATION_MODE={_shell_quote(str(settings.private_udp_link_source_validation_mode or '').strip() or 'profile-bound-remote')}",
        f"TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_ENABLED={_shell_quote(_bool_text(outer_carrier_enabled))}",
        f"TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_MODE={_shell_quote(str(settings.private_link_crypto_outer_carrier_mode or 'wss').strip() or 'wss')}",
        f"TRACEGATE_LINK_CRYPTO_OUTER_WSS_SERVER_NAME={_shell_quote(_link_crypto_outer_wss_server_name(settings))}",
        f"TRACEGATE_LINK_CRYPTO_OUTER_WSS_PUBLIC_PORT={_shell_quote(int(settings.private_link_crypto_outer_wss_public_port or 443))}",
        f"TRACEGATE_LINK_CRYPTO_OUTER_WSS_PATH={_shell_quote(_normalize_link_wss_path(settings.private_link_crypto_outer_wss_path))}",
        f"TRACEGATE_LINK_CRYPTO_OUTER_WSS_VERIFY_TLS={_shell_quote(_bool_text(bool(settings.private_link_crypto_outer_wss_verify_tls)))}",
        f"TRACEGATE_LINK_CRYPTO_OUTER_WSS_SPKI_PINNING_REQUIRED={_shell_quote(_bool_text(outer_carrier_enabled))}",
        f"TRACEGATE_LINK_CRYPTO_OUTER_WSS_ADMISSION_REQUIRED={_shell_quote(_bool_text(outer_carrier_enabled))}",
        f"TRACEGATE_LINK_CRYPTO_TCP_DPI_RESISTANCE_REQUIRED={_shell_quote(_bool_text(bool(link_classes)))}",
        f"TRACEGATE_LINK_CRYPTO_TCP_TRAFFIC_SHAPING_REQUIRED={_shell_quote(_bool_text(bool(link_classes)))}",
        f"TRACEGATE_LINK_CRYPTO_PROMOTION_PREFLIGHT_REQUIRED={_shell_quote(_bool_text(bool(link_classes)))}",
        f"TRACEGATE_LINK_CRYPTO_GENERATION={_shell_quote(int(settings.private_link_crypto_generation or 1))}",
        f"TRACEGATE_LINK_CRYPTO_ZAPRET2_ENABLED={_shell_quote(_bool_text(bool(settings.private_link_crypto_zapret2_enabled)))}",
        f"TRACEGATE_LINK_CRYPTO_ZAPRET2_REQUIRED={_shell_quote(_bool_text(bool(link_classes)))}",
        f"TRACEGATE_LINK_CRYPTO_ZAPRET2_HOST_WIDE_INTERCEPTION={_shell_quote(_bool_text(False))}",
        f"TRACEGATE_LINK_CRYPTO_ZAPRET2_NFQUEUE={_shell_quote(_bool_text(False))}",
    ]

    changed = False
    changed = _write_text_if_changed(json_path, _json_text(payload)) or changed
    changed = _write_text_if_changed(env_path, "\n".join(env_lines) + "\n") or changed
    return changed


def _router_client_profile_refs(
    settings: Settings,
    *,
    role_lower: str,
    link_class: str,
    transport: str,
    paired_obfs_enabled: bool,
) -> dict[str, Any]:
    if transport == "udp-quic":
        refs: dict[str, Any] = {
            "hysteriaClient": {
                "kind": "file",
                "path": _router_profile_path(
                    settings,
                    role_lower=role_lower,
                    link_class=link_class,
                    profile_name=str(settings.private_router_udp_client_profile or "").strip() or "hysteria-client.yaml",
                ),
                "secretMaterial": True,
            },
            "salamander": {
                "kind": "file",
                "path": _router_profile_path(
                    settings,
                    role_lower=role_lower,
                    link_class=link_class,
                    profile_name=str(settings.private_router_udp_salamander_profile or "").strip() or "salamander.env",
                ),
                "secretMaterial": True,
            },
        }
        if paired_obfs_enabled:
            refs["pairedObfs"] = {
                "kind": "file",
                "path": _router_profile_path(
                    settings,
                    role_lower=role_lower,
                    link_class=link_class,
                    profile_name=str(settings.private_router_udp_paired_obfs_profile or "").strip() or "paired-obfs.env",
                ),
                "secretMaterial": True,
            }
        return refs

    return {
        "mieruClient": {
            "kind": "file",
            "path": _router_profile_path(
                settings,
                role_lower=role_lower,
                link_class=link_class,
                profile_name=str(settings.private_router_mieru_client_profile or "").strip() or "mieru-client.json",
            ),
            "secretMaterial": True,
        }
    }


def _router_link_route(settings: Settings, row: dict[str, Any], *, transport: str) -> dict[str, Any]:
    local = _mapping(row.get("local"))
    remote = _mapping(row.get("remote"))
    link_class = str(row.get("class") or "").strip()
    role_lower = str(row.get("role") or "").strip().lower() or "unknown"
    paired_obfs = _mapping(row.get("pairedObfs"))
    route = {
        "class": link_class,
        "enabled": bool(row.get("enabled", True)),
        "serverRole": str(row.get("role") or "").strip(),
        "serverSide": str(row.get("side") or "").strip(),
        "remoteRole": str(remote.get("role") or "").strip(),
        "carrier": str(row.get("carrier") or "").strip(),
        "transport": transport,
        "managedBy": str(row.get("managedBy") or "").strip(),
        "xrayBackhaul": bool(row.get("xrayBackhaul", True)),
        "generation": _int_value(row.get("generation"), 0),
        "serverListen": str(local.get("listen") or "").strip(),
        "publicEndpoint": str(remote.get("endpoint") or "").strip(),
        "selectedProfiles": _string_list(row.get("selectedProfiles")),
        "profileRef": _mapping(row.get("profileRef")),
        "auth": _mapping(local.get("auth")),
        "rotation": _mapping(row.get("rotation")),
        "stability": _mapping(row.get("stability")),
        "routerClient": {
            "requiresPrivateProfile": True,
            "secretMaterial": "external-private-file",
            "hostWideInterception": False,
            "nfqueue": False,
            "profileRefs": _router_client_profile_refs(
                settings,
                role_lower=role_lower,
                link_class=link_class,
                transport=transport,
                paired_obfs_enabled=bool(paired_obfs.get("enabled", False)),
            ),
        },
    }
    if transport == "udp-quic":
        route["datagram"] = _mapping(row.get("datagram"))
        route["obfs"] = _mapping(row.get("obfs"))
        route["pairedObfs"] = paired_obfs
        route["hardening"] = _mapping(row.get("hardening"))
        route["dpiResistance"] = _mapping(row.get("dpiResistance"))
    else:
        route["outerCarrier"] = _mapping(row.get("outerCarrier"))
        route["zapret2"] = _mapping(row.get("zapret2"))
    return route


def _router_handoff_payload(
    settings: Settings,
    *,
    runtime_contract_path: Path,
    runtime_contract_payload: dict[str, Any],
) -> dict[str, Any]:
    role_upper = str(runtime_contract_payload.get("role") or "").strip().upper() or "UNKNOWN"
    link_crypto = _link_crypto_payload(
        settings,
        runtime_contract_path=runtime_contract_path,
        runtime_contract_payload=runtime_contract_payload,
    )
    tcp_routes = [
        _router_link_route(settings, row, transport="tcp")
        for row in link_crypto.get("links", [])
        if str(row.get("class") or "").strip() in {"router-entry", "router-transit"}
    ]
    udp_routes = [
        _router_link_route(settings, row, transport="udp-quic")
        for row in link_crypto.get("udpLinks", [])
        if str(row.get("class") or "").strip() in {"router-entry-udp", "router-transit-udp"}
    ]
    tcp_classes = [str(row.get("class") or "").strip() for row in tcp_routes if str(row.get("class") or "").strip()]
    udp_classes = [str(row.get("class") or "").strip() for row in udp_routes if str(row.get("class") or "").strip()]
    return {
        "schema": "tracegate.router-handoff.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": str(runtime_contract_payload.get("runtimeProfile") or "").strip() or "tracegate-2.2",
        "runtimeContractPath": str(runtime_contract_path),
        "secretMaterial": False,
        "enabled": bool(tcp_routes or udp_routes),
        "placement": "personal-router-before-entry" if role_upper == "ENTRY" else "personal-router-before-transit",
        "contract": {
            "routerIsEntryReplacement": False,
            "requiresServerSideLinkCrypto": True,
            "requiresPrivateRouterProfile": bool(tcp_routes or udp_routes),
            "noHostWideInterception": True,
            "noNfqueue": True,
        },
        "counts": {
            "total": len(tcp_routes) + len(udp_routes),
            "tcp": len(tcp_routes),
            "udp": len(udp_routes),
        },
        "classes": {
            "tcp": tcp_classes,
            "udp": udp_classes,
        },
        "routes": {
            "tcp": tcp_routes,
            "udp": udp_routes,
        },
    }


def _router_client_route(row: dict[str, Any], *, transport: str) -> dict[str, Any]:
    router_client = _mapping(row.get("routerClient"))
    route = {
        "class": str(row.get("class") or "").strip(),
        "enabled": bool(row.get("enabled", False)),
        "transport": transport,
        "serverRole": str(row.get("serverRole") or "").strip().upper(),
        "routerRole": "ROUTER",
        "serverEndpoint": str(row.get("publicEndpoint") or "").strip(),
        "selectedProfiles": _string_list(row.get("selectedProfiles")),
        "routerSide": {
            "mode": "client",
            "requiresPrivateProfile": True,
            "profileRefs": _mapping(router_client.get("profileRefs")),
            "failClosed": True,
            "hostWideInterception": False,
            "nfqueue": False,
        },
        "serverSide": {
            "mode": "server",
            "listen": str(row.get("serverListen") or "").strip(),
            "auth": _mapping(row.get("auth")),
        },
    }
    if transport == "tcp":
        route["carrier"] = "mieru"
        route["outerCarrier"] = _mapping(row.get("outerCarrier"))
    else:
        route["carrier"] = "hysteria2"
        route["datagram"] = _mapping(row.get("datagram"))
        route["obfs"] = _mapping(row.get("obfs"))
        route["pairedObfs"] = _mapping(row.get("pairedObfs"))
        route["hardening"] = _mapping(row.get("hardening"))
        route["dpiResistance"] = _mapping(row.get("dpiResistance"))
    return route


def _router_client_bundle_payload(
    *,
    router_state_payload: dict[str, Any],
    router_state_json_path: Path,
) -> dict[str, Any]:
    routes = _mapping(router_state_payload.get("routes"))
    tcp_routes = [_router_client_route(_mapping(row), transport="tcp") for row in _dict_list(routes.get("tcp"))]
    udp_routes = [_router_client_route(_mapping(row), transport="udp-quic") for row in _dict_list(routes.get("udp"))]
    paired_obfs_enabled = any(bool(_mapping(row.get("pairedObfs")).get("enabled", False)) for row in udp_routes)
    components = [
        {
            "name": "mieru-client",
            "required": bool(tcp_routes),
            "transports": ["tcp"],
            "failClosed": True,
            "noHostWideInterception": True,
            "noNfqueue": True,
        },
        {
            "name": "hysteria2-client",
            "required": bool(udp_routes),
            "transports": ["udp-quic"],
            "obfs": "salamander",
            "failClosed": True,
            "noHostWideInterception": True,
            "noNfqueue": True,
        },
        {
            "name": "paired-udp-obfs",
            "required": paired_obfs_enabled,
            "backend": "udp2raw",
            "requiresBothSides": True,
            "failClosed": True,
            "noHostWideInterception": True,
            "noNfqueue": True,
        },
    ]
    return {
        "schema": "tracegate.router-client-bundle.v1",
        "version": 1,
        "role": str(router_state_payload.get("role") or "").strip().upper(),
        "runtimeProfile": str(router_state_payload.get("runtimeProfile") or "").strip() or "tracegate-2.2",
        "handoffStateJson": str(router_state_json_path),
        "secretMaterial": False,
        "enabled": bool(router_state_payload.get("enabled", False)),
        "placement": str(router_state_payload.get("placement") or "").strip(),
        "counts": _mapping(router_state_payload.get("counts")),
        "classes": _mapping(router_state_payload.get("classes")),
        "requirements": {
            "routerIsEntryReplacement": False,
            "requiresPrivateProfile": bool(router_state_payload.get("enabled", False)),
            "requiresServerSideLinkCrypto": True,
            "requiresBothSides": bool(tcp_routes or udp_routes),
            "failClosed": True,
            "noHostWideInterception": True,
            "noNfqueue": True,
            "profileDistribution": "external-private-files",
        },
        "components": components,
        "routes": {
            "tcp": tcp_routes,
            "udp": udp_routes,
        },
    }


def _write_router_state(
    settings: Settings,
    *,
    runtime_contract_path: Path,
    runtime_contract_payload: dict[str, Any],
) -> bool:
    payload = _router_handoff_payload(
        settings,
        runtime_contract_path=runtime_contract_path,
        runtime_contract_payload=runtime_contract_payload,
    )
    role_lower = str(payload["role"]).lower()
    state_dir = _router_state_dir(settings, role_lower=role_lower)
    json_path = state_dir / "desired-state.json"
    env_path = state_dir / "desired-state.env"
    client_bundle_path = state_dir / "client-bundle.json"
    client_env_path = state_dir / "client-bundle.env"
    client_bundle = _router_client_bundle_payload(router_state_payload=payload, router_state_json_path=json_path)
    tcp_classes = _string_list(_mapping(payload.get("classes")).get("tcp"))
    udp_classes = _string_list(_mapping(payload.get("classes")).get("udp"))
    udp_routes = _mapping(payload.get("routes")).get("udp")
    udp_route_list = udp_routes if isinstance(udp_routes, list) else []
    paired_obfs_enabled = any(
        bool(_mapping(_mapping(row).get("pairedObfs")).get("enabled", False)) for row in udp_route_list
    )
    env_lines = [
        f"TRACEGATE_ROUTER_HANDOFF_ROLE={_shell_quote(payload['role'])}",
        f"TRACEGATE_ROUTER_HANDOFF_RUNTIME_PROFILE={_shell_quote(payload['runtimeProfile'])}",
        f"TRACEGATE_ROUTER_HANDOFF_STATE_JSON={_shell_quote(str(json_path))}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_JSON={_shell_quote(str(client_bundle_path))}",
        f"TRACEGATE_ROUTER_HANDOFF_SECRET_MATERIAL={_shell_quote(_bool_text(False))}",
        f"TRACEGATE_ROUTER_HANDOFF_ENABLED={_shell_quote(_bool_text(bool(payload['enabled'])))}",
        f"TRACEGATE_ROUTER_HANDOFF_COUNT={_shell_quote(_mapping(payload.get('counts')).get('total', 0))}",
        f"TRACEGATE_ROUTER_HANDOFF_TCP_COUNT={_shell_quote(_mapping(payload.get('counts')).get('tcp', 0))}",
        f"TRACEGATE_ROUTER_HANDOFF_UDP_COUNT={_shell_quote(_mapping(payload.get('counts')).get('udp', 0))}",
        f"TRACEGATE_ROUTER_HANDOFF_TCP_CLASSES={_shell_quote(':'.join(tcp_classes))}",
        f"TRACEGATE_ROUTER_HANDOFF_UDP_CLASSES={_shell_quote(':'.join(udp_classes))}",
        f"TRACEGATE_ROUTER_HANDOFF_PAIRED_OBFS_ENABLED={_shell_quote(_bool_text(paired_obfs_enabled))}",
        f"TRACEGATE_ROUTER_HANDOFF_REQUIRES_PRIVATE_PROFILE={_shell_quote(_bool_text(bool(payload['enabled'])))}",
        "TRACEGATE_ROUTER_HANDOFF_ROUTER_IS_ENTRY_REPLACEMENT='false'",
        "TRACEGATE_ROUTER_HANDOFF_NO_HOST_WIDE_INTERCEPTION='true'",
        "TRACEGATE_ROUTER_HANDOFF_NO_NFQUEUE='true'",
    ]
    component_names = [
        str(row.get("name") or "").strip()
        for row in _dict_list(client_bundle.get("components"))
        if bool(row.get("required", False)) and str(row.get("name") or "").strip()
    ]
    client_env_lines = [
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_ROLE={_shell_quote(client_bundle['role'])}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_RUNTIME_PROFILE={_shell_quote(client_bundle['runtimeProfile'])}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_JSON={_shell_quote(str(client_bundle_path))}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_HANDOFF_JSON={_shell_quote(str(json_path))}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_SECRET_MATERIAL={_shell_quote(_bool_text(False))}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_ENABLED={_shell_quote(_bool_text(bool(client_bundle['enabled'])))}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_COMPONENTS={_shell_quote(':'.join(component_names))}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_TCP_COUNT={_shell_quote(_mapping(client_bundle.get('counts')).get('tcp', 0))}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_UDP_COUNT={_shell_quote(_mapping(client_bundle.get('counts')).get('udp', 0))}",
        f"TRACEGATE_ROUTER_CLIENT_BUNDLE_REQUIRES_BOTH_SIDES={_shell_quote(_bool_text(bool(_mapping(client_bundle.get('requirements')).get('requiresBothSides', False))))}",
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_FAIL_CLOSED='true'",
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_HOST_WIDE_INTERCEPTION='true'",
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_NFQUEUE='true'",
    ]

    changed = False
    changed = _write_text_if_changed(json_path, _json_text(payload)) or changed
    changed = _write_text_if_changed(env_path, "\n".join(env_lines) + "\n") or changed
    changed = _write_text_if_changed(client_bundle_path, _json_text(client_bundle)) or changed
    changed = _write_text_if_changed(client_env_path, "\n".join(client_env_lines) + "\n") or changed
    return changed


def _split_endpoint(value: str) -> tuple[str, int]:
    raw = str(value or "").strip()
    host, sep, port_raw = raw.rpartition(":")
    if not sep or not host or not port_raw:
        return raw, 0
    try:
        return host.strip(), int(port_raw)
    except ValueError:
        return host.strip(), 0


def _render_fronting_cfg(
    *,
    listen_addr: str,
    reality_upstream: str,
    ws_tls_upstream: str,
    mtproto_upstream: str,
    ws_sni: str,
    mtproto_domain: str,
) -> str:
    lines = [
        "global",
        "  log /dev/log local0",
        "  log /dev/log local1 notice",
        "  daemon",
        "  maxconn 20000",
        "",
        "defaults",
        "  log global",
        "  mode tcp",
        "  option tcplog",
        "  timeout connect 5s",
        "  timeout client 60s",
        "  timeout server 60s",
        "",
        "frontend fe_tracegate_private_fronting",
        f"  bind {listen_addr}",
        "  tcp-request inspect-delay 5s",
        "  tcp-request content accept if { req.ssl_sni -m found }",
        "  tcp-request content accept if WAIT_END",
    ]
    if mtproto_domain:
        lines.append(f"  acl mtproto_sni req.ssl_sni -i {mtproto_domain}")
    if ws_sni:
        lines.append(f"  acl ws_tls_sni req.ssl_sni -i {ws_sni}")
    if mtproto_domain:
        lines.append("  use_backend be_mtproto if mtproto_sni")
    if ws_sni:
        lines.append("  use_backend be_ws_tls if ws_tls_sni")
    lines.extend(
        [
            "  default_backend be_reality",
            "",
            "backend be_reality",
            f"  server reality {reality_upstream} check",
            "",
            "backend be_ws_tls",
            f"  server ws_tls {ws_tls_upstream} check",
            "",
            "backend be_mtproto",
            f"  server mtproto {mtproto_upstream} check",
            "",
        ]
    )
    return "\n".join(lines)


def _write_fronting_state(
    settings: Settings,
    *,
    runtime_contract_payload: dict[str, Any],
) -> bool:
    role_upper = str(runtime_contract_payload.get("role") or "").strip().upper()
    if role_upper != "TRANSIT":
        return False

    private_root = Path(effective_private_runtime_root(settings))
    state_dir = private_root / "fronting"
    runtime_dir = state_dir / "runtime"
    cfg_file = runtime_dir / "haproxy.cfg"
    pid_file = runtime_dir / "haproxy.pid"
    obfuscation_state_json = _role_state_dir(settings, role_lower="transit") / "runtime-state.json"
    fronting_block = runtime_contract_payload.get("fronting")
    fronting = fronting_block if isinstance(fronting_block, dict) else {}
    try:
        public_udp_port = int(
            fronting.get("publicUdpPort")
            or fronting.get("udpPublicPort")
            or TRACEGATE_PUBLIC_UDP_PORT
        )
    except (TypeError, ValueError):
        public_udp_port = TRACEGATE_PUBLIC_UDP_PORT
    public_udp_owner = str(fronting.get("publicUdpOwner") or fronting.get("udp443Owner") or "").strip()
    mtproto_domain = str(settings.private_fronting_mtproto_domain_override or "").strip() or str(fronting.get("mtprotoDomain") or "").strip()
    ws_sni = str(settings.private_fronting_ws_sni or "").strip() or str(settings.default_transit_host or "").strip()

    payload = {
        "action": "reconcile",
        "role": role_upper,
        "backend": "private",
        "runtimeStateJson": str(obfuscation_state_json),
        "listenAddr": str(settings.private_fronting_listen_addr or "").strip() or "127.0.0.1:10443",
        "protocol": str(settings.private_fronting_protocol or "").strip().lower() or "tcp",
        "realityUpstream": str(settings.private_fronting_reality_upstream or "").strip() or "127.0.0.1:2443",
        "wsTlsUpstream": str(settings.private_fronting_ws_tls_upstream or "").strip() or "127.0.0.1:10443",
        "mtprotoUpstream": str(settings.private_fronting_mtproto_upstream or "").strip() or "127.0.0.1:9443",
        "mtprotoProfileFile": _mtproto_profile_path(settings),
        "touchUdp443": bool(fronting.get("touchUdp443", settings.fronting_touch_udp_443)),
        "mtprotoDomain": mtproto_domain,
        "mtprotoFrontingMode": str(fronting.get("mtprotoFrontingMode") or settings.mtproto_fronting_mode or "dedicated-dns-only").strip().lower(),
        "tcp443Owner": str(fronting.get("tcp443Owner") or "").strip(),
        "publicUdpPort": public_udp_port,
        "publicUdpOwner": public_udp_owner,
        "udp443Owner": public_udp_owner,
        "cfgFile": str(cfg_file),
        "pidFile": str(pid_file),
        "wsSni": ws_sni,
    }
    cfg_text = _render_fronting_cfg(
        listen_addr=payload["listenAddr"],
        reality_upstream=payload["realityUpstream"],
        ws_tls_upstream=payload["wsTlsUpstream"],
        mtproto_upstream=payload["mtprotoUpstream"],
        ws_sni=payload["wsSni"],
        mtproto_domain=payload["mtprotoDomain"],
    )

    changed = False
    changed = _write_text_if_changed(cfg_file, cfg_text) or changed
    changed = _write_text_if_changed(state_dir / "last-action.json", _json_text(payload)) or changed
    return changed


def _read_secret_hex(path: Path) -> str:
    raw = path.read_text(encoding="utf-8")
    return "".join(ch for ch in raw if ch.lower() in "0123456789abcdef").lower()


def _write_mtproto_state(
    settings: Settings,
    *,
    runtime_contract_payload: dict[str, Any],
) -> bool:
    role_upper = str(runtime_contract_payload.get("role") or "").strip().upper()
    if role_upper != "TRANSIT":
        return False

    state_dir = Path(effective_mtproto_public_profile_file(settings)).parent
    runtime_dir = state_dir / "runtime"
    issued_state_file = Path(effective_mtproto_issued_state_file(settings))
    obfuscation_state_json = _role_state_dir(settings, role_lower="transit") / "runtime-state.json"

    payload = {
        "action": "reconcile",
        "role": role_upper,
        "backend": str(settings.private_mtproto_backend or "").strip().lower() or "private",
        "domain": str(settings.mtproto_domain or "").strip(),
        "publicPort": int(settings.mtproto_public_port or 443),
        "upstreamHost": str(settings.private_mtproto_upstream_host or "").strip() or "127.0.0.1",
        "upstreamPort": int(settings.private_mtproto_upstream_port or 9443),
        "profileFile": _mtproto_profile_path(settings),
        "runtimeStateJson": str(obfuscation_state_json),
        "publicProfileFile": str(state_dir / "public-profile.json"),
        "issuedStateFile": str(issued_state_file),
    }

    changed = False
    changed = _write_text_if_changed(state_dir / "last-action.json", _json_text(payload)) or changed
    if not issued_state_file.exists():
        changed = _write_text_if_changed(issued_state_file, _json_text({"version": 1, "entries": []})) or changed

    secret_file = Path(str(settings.private_mtproto_secret_file or "").strip() or "/etc/tracegate/private/mtproto/secret.txt")
    profile_path = Path(effective_mtproto_public_profile_file(settings))
    if secret_file.is_file() and payload["domain"] and payload["publicPort"] > 0:
        try:
            normalized_domain = normalize_mtproto_domain(payload["domain"])
            share = build_mtproto_share_links(
                server=normalized_domain,
                port=int(payload["publicPort"]),
                secret_hex=_read_secret_hex(secret_file),
                transport="tls",
                domain=normalized_domain,
            )
        except (MTProtoConfigError, OSError, ValueError):
            changed = _remove_if_exists(profile_path) or changed
        else:
            profile_payload = {
                "protocol": "mtproto",
                "profile": MTPROTO_FAKE_TLS_PROFILE_NAME,
                "server": normalized_domain,
                "port": int(payload["publicPort"]),
                "transport": "tls",
                "domain": normalized_domain,
                "secretPolicy": "shared",
                "clientSecretHex": share.client_secret_hex,
                "tgUri": share.tg_uri,
                "httpsUrl": share.https_url,
            }
            changed = _write_text_if_changed(profile_path, _json_text(profile_payload)) or changed
    else:
        changed = _remove_if_exists(profile_path) or changed

    # Ensure the state dir / runtime dir layout exists even if the helper is not active yet.
    runtime_dir.mkdir(parents=True, exist_ok=True)
    return changed


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dict_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def _string_list(value: object) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    raw = str(value or "").strip()
    return [raw] if raw else []


def _wireguard_peer_allowed_ips(wireguard: dict[str, Any]) -> list[str]:
    address = wireguard.get("address")
    if isinstance(address, (list, tuple, set)):
        return _string_list(address)
    raw = str(address or "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]


def _int_value(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _local_socks_state(config: dict[str, Any]) -> dict[str, Any]:
    local_socks = _mapping(config.get("local_socks"))
    auth = _mapping(local_socks.get("auth"))
    return {
        "enabled": bool(local_socks.get("enabled", True)),
        "listen": str(local_socks.get("listen") or "").strip(),
        "auth": {
            "required": bool(auth.get("required", True)),
            "mode": str(auth.get("mode") or "").strip(),
            "username": str(auth.get("username") or "").strip(),
            "password": str(auth.get("password") or "").strip(),
        },
    }


def _profile_metadata(row: dict[str, Any], config: dict[str, Any], *, role_upper: str) -> dict[str, Any]:
    return {
        "role": role_upper,
        "userId": str(row.get("user_id") or "").strip(),
        "userDisplay": str(row.get("user_display") or "").strip(),
        "deviceId": str(row.get("device_id") or "").strip(),
        "deviceName": str(row.get("device_name") or "").strip(),
        "connectionId": str(row.get("connection_id") or "").strip(),
        "connectionAlias": str(row.get("connection_alias") or "").strip(),
        "revisionId": str(row.get("revision_id") or "").strip(),
        "variant": str(row.get("variant") or "").strip(),
        "mode": str(row.get("mode") or "").strip(),
        "profile": str(config.get("profile") or "").strip(),
    }


def _profile_stage(*, protocol: str, mode: str, role_upper: str, chain: dict[str, Any] | None) -> str:
    is_chain = str(mode or "").strip().lower() == "chain" or chain is not None
    if protocol == "wireguard_wstunnel":
        return "direct-transit-public"
    if is_chain:
        return "entry-public-to-transit-relay" if role_upper == "ENTRY" else "transit-private-terminator"
    return "direct-transit-public"


def _chain_state(config: dict[str, Any]) -> dict[str, Any] | None:
    chain = config.get("chain")
    if not isinstance(chain, dict):
        return None
    return {
        "type": str(chain.get("type") or "").strip(),
        "entry": str(chain.get("entry") or "").strip(),
        "transit": str(chain.get("transit") or "").strip(),
        "linkClass": str(chain.get("link_class") or "").strip(),
        "carrier": str(chain.get("carrier") or "").strip(),
        "preferredOuter": str(chain.get("preferred_outer") or "").strip(),
        "outerCarrier": str(chain.get("outer_carrier") or "").strip(),
        "optionalPacketShaping": str(chain.get("optional_packet_shaping") or "").strip(),
        "managedBy": str(chain.get("managed_by") or "").strip(),
        "selectedProfiles": _string_list(chain.get("selected_profiles")),
        "innerTransport": str(chain.get("inner_transport") or "").strip(),
        "xrayBackhaul": bool(chain.get("xray_backhaul", True)),
    }


def _obfuscation_policy(*, protocol: str, mode: str, chain: dict[str, Any] | None) -> dict[str, Any]:
    if str(mode or "").strip().lower() == "chain" or chain is not None:
        managed_by = str((chain or {}).get("managedBy") or "").strip().lower()
        preferred_outer = str((chain or {}).get("preferredOuter") or "").strip().lower()
        if managed_by == "xray-chain" or preferred_outer == "reality-xhttp":
            return {
                "scope": "entry-transit-private-relay",
                "outer": "reality-xhttp",
                "packetShaping": "none",
                "hostWideInterception": False,
            }
        return {
            "scope": "entry-transit-private-relay",
            "outer": "wss-carrier",
            "packetShaping": "zapret2-scoped",
            "hostWideInterception": False,
        }
    if protocol == "wireguard_wstunnel":
        return {
            "scope": "public-wss-443",
            "outer": "wstunnel",
            "packetShaping": "none",
            "hostWideInterception": False,
        }
    return {
        "scope": "public-tcp-443",
        "outer": "shadowtls-v3",
        "packetShaping": "none",
        "hostWideInterception": False,
    }


def _shadowtls_profile_state(settings: Settings, row: dict[str, Any], *, role_upper: str) -> dict[str, Any] | None:
    config = _mapping(row.get("config"))
    connection_id = str(row.get("connection_id") or "").strip()
    if not connection_id:
        return None
    mode = str(row.get("mode") or "").strip()
    shadowtls = _mapping(config.get("shadowtls"))
    chain = _chain_state(config)
    return {
        **_profile_metadata(row, config, role_upper=role_upper),
        "protocol": "shadowsocks2022_shadowtls",
        "stage": _profile_stage(
            protocol="shadowsocks2022_shadowtls",
            mode=mode,
            role_upper=role_upper,
            chain=chain,
        ),
        "server": str(config.get("server") or "").strip(),
        "port": _int_value(config.get("port"), 443),
        "sni": str(config.get("sni") or "").strip(),
        "shadowsocks2022": {
            "method": str(config.get("method") or "").strip(),
            "password": str(config.get("password") or "").strip(),
        },
        "shadowtls": {
            "version": _int_value(shadowtls.get("version"), 3),
            "serverName": str(shadowtls.get("server_name") or "").strip(),
            "alpn": _string_list(shadowtls.get("alpn")),
            "credentialScope": "node-static",
            "profileRef": {
                "kind": "file",
                "path": _shadowtls_profile_path(settings, role_upper=role_upper),
                "secretMaterial": True,
            },
            "manageUsers": False,
            "restartOnUserChange": False,
        },
        "localSocks": _local_socks_state(config),
        "chain": chain,
        "obfuscation": _obfuscation_policy(protocol="shadowsocks2022_shadowtls", mode=mode, chain=chain),
    }


def _wireguard_profile_state(row: dict[str, Any], *, role_upper: str) -> dict[str, Any] | None:
    config = _mapping(row.get("config"))
    connection_id = str(row.get("connection_id") or "").strip()
    if not connection_id:
        return None
    mode = str(row.get("mode") or "").strip()
    wireguard = _mapping(config.get("wireguard"))
    wstunnel = _mapping(config.get("wstunnel"))
    return {
        **_profile_metadata(row, config, role_upper=role_upper),
        "protocol": "wireguard_wstunnel",
        "stage": _profile_stage(
            protocol="wireguard_wstunnel",
            mode=mode,
            role_upper=role_upper,
            chain=None,
        ),
        "server": str(config.get("server") or "").strip(),
        "port": _int_value(config.get("port"), 443),
        "sni": str(config.get("sni") or "").strip(),
        "wstunnel": {
            "mode": str(wstunnel.get("mode") or "wireguard-over-websocket").strip(),
            "url": str(wstunnel.get("url") or "").strip(),
            "path": str(wstunnel.get("path") or "").strip(),
            "tlsServerName": str(wstunnel.get("tls_server_name") or "").strip(),
            "localUdpListen": str(wstunnel.get("local_udp_listen") or "").strip(),
        },
        "wireguard": {
            "clientPublicKey": str(wireguard.get("public_key") or "").strip(),
            "clientPrivateKey": str(wireguard.get("private_key") or "").strip(),
            "serverPublicKey": str(wireguard.get("server_public_key") or "").strip(),
            "presharedKey": str(wireguard.get("preshared_key") or "").strip(),
            "address": str(wireguard.get("address") or "").strip(),
            "allowedIps": _wireguard_peer_allowed_ips(wireguard),
            "clientRouteAllowedIps": _string_list(wireguard.get("allowed_ips")),
            "dns": str(wireguard.get("dns") or "").strip(),
            "mtu": _int_value(wireguard.get("mtu"), 1280),
            "persistentKeepalive": _int_value(wireguard.get("persistent_keepalive"), 25),
        },
        "sync": {
            "strategy": "wg-set",
            "interface": str(wireguard.get("interface") or "wg").strip(),
            "applyMode": "live-peer-sync",
            "removeStalePeers": True,
            "restartWireGuard": False,
            "restartWSTunnel": False,
        },
        "localSocks": _local_socks_state(config),
        "chain": None,
        "obfuscation": _obfuscation_policy(protocol="wireguard_wstunnel", mode=mode, chain=None),
    }


def _write_profile_state(
    settings: Settings,
    *,
    runtime_contract_path: Path,
    runtime_contract_payload: dict[str, Any],
    user_artifacts: list[dict[str, Any]],
) -> bool:
    role_upper = str(runtime_contract_payload.get("role") or "").strip().upper() or "UNKNOWN"
    role_lower = role_upper.lower()

    shadowtls_profiles: list[dict[str, Any]] = []
    wireguard_profiles: list[dict[str, Any]] = []
    for row in user_artifacts:
        protocol = str(row.get("protocol") or "").strip().lower()
        if protocol == "shadowsocks2022_shadowtls":
            state = _shadowtls_profile_state(settings, row, role_upper=role_upper)
            if state is not None:
                shadowtls_profiles.append(state)
        elif protocol == "wireguard_wstunnel":
            state = _wireguard_profile_state(row, role_upper=role_upper)
            if state is not None:
                wireguard_profiles.append(state)

    shadowtls_profiles.sort(key=lambda row: str(row.get("connectionId") or ""))
    wireguard_profiles.sort(key=lambda row: str(row.get("connectionId") or ""))
    total = len(shadowtls_profiles) + len(wireguard_profiles)

    payload = {
        "schema": "tracegate.private-profiles.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": str(runtime_contract_payload.get("runtimeProfile") or "").strip() or "tracegate-2.2",
        "runtimeContractPath": str(runtime_contract_path),
        "secretMaterial": True,
        "transportProfiles": runtime_contract_payload.get("transportProfiles") or {},
        "counts": {
            "total": total,
            "shadowsocks2022ShadowTLS": len(shadowtls_profiles),
            "wireguardWSTunnel": len(wireguard_profiles),
        },
        "shadowsocks2022ShadowTLS": shadowtls_profiles,
        "wireguardWSTunnel": wireguard_profiles,
    }

    state_dir = _profiles_state_dir(settings, role_lower=role_lower)
    json_path = state_dir / "desired-state.json"
    env_path = state_dir / "desired-state.env"
    env_lines = [
        f"TRACEGATE_PROFILE_ROLE={_shell_quote(payload['role'])}",
        f"TRACEGATE_PROFILE_RUNTIME_PROFILE={_shell_quote(payload['runtimeProfile'])}",
        f"TRACEGATE_PROFILE_STATE_JSON={_shell_quote(str(json_path))}",
        f"TRACEGATE_PROFILE_SECRET_MATERIAL={_shell_quote(_bool_text(True))}",
        f"TRACEGATE_PROFILE_COUNT={_shell_quote(total)}",
        f"TRACEGATE_SHADOWSOCKS2022_SHADOWTLS_COUNT={_shell_quote(len(shadowtls_profiles))}",
        f"TRACEGATE_WIREGUARD_WSTUNNEL_COUNT={_shell_quote(len(wireguard_profiles))}",
    ]

    changed = False
    changed = _write_secret_text_if_changed(json_path, _json_text(payload)) or changed
    changed = _write_secret_text_if_changed(env_path, "\n".join(env_lines) + "\n") or changed
    return changed


def write_private_runtime_handoffs(
    settings: Settings,
    *,
    runtime_contract_path: Path,
    runtime_contract_payload: dict[str, Any],
    user_artifacts: list[dict[str, Any]] | None = None,
) -> set[str]:
    changed: set[str] = set()
    if _write_obfuscation_state(
        settings,
        runtime_contract_path=runtime_contract_path,
        runtime_contract_payload=runtime_contract_payload,
    ):
        changed.add("obfuscation")
    if _write_fronting_state(settings, runtime_contract_payload=runtime_contract_payload):
        changed.add("fronting")
    if _write_mtproto_state(settings, runtime_contract_payload=runtime_contract_payload):
        changed.add("mtproto")
    if _write_profile_state(
        settings,
        runtime_contract_path=runtime_contract_path,
        runtime_contract_payload=runtime_contract_payload,
        user_artifacts=user_artifacts or [],
    ):
        changed.add("profiles")
    if _write_link_crypto_state(
        settings,
        runtime_contract_path=runtime_contract_path,
        runtime_contract_payload=runtime_contract_payload,
    ):
        changed.add("link-crypto")
    if _write_router_state(
        settings,
        runtime_contract_path=runtime_contract_path,
        runtime_contract_payload=runtime_contract_payload,
    ):
        changed.add("link-crypto")
    return changed
