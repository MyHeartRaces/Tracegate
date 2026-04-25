from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tracegate.services.mtproto import (
    MTPROTO_FAKE_TLS_PROFILE_NAME,
    MTProtoConfigError,
    build_mtproto_share_links,
    normalize_mtproto_domain,
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


def _mieru_profile_path(settings: Settings, *, side: str) -> str:
    profile_dir = Path(str(settings.private_mieru_profile_dir or "").strip() or "/etc/tracegate/private/mieru")
    if side.strip().lower() == "client":
        profile_name = str(settings.private_mieru_client_profile or "").strip() or "client.json"
    else:
        profile_name = str(settings.private_mieru_server_profile or "").strip() or "server.json"
    return str(profile_dir / profile_name)


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

    return {
        "role": role_upper,
        "interface": _obfuscation_interface(settings, role_upper=role_upper),
        "runtimeProfile": str(runtime_contract_payload.get("runtimeProfile") or "").strip() or "xray-centric",
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
            "udp443Owner": str(fronting_block.get("udp443Owner") or "").strip(),
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


def _link_crypto_remote_endpoint(host: object, *, fallback_host: str, remote_port: int) -> str:
    remote_host = str(host or "").strip() or fallback_host
    return f"{remote_host}:{int(remote_port)}"


def _link_crypto_zapret2_policy(settings: Settings, *, profile_file: str) -> dict[str, Any]:
    return {
        "enabled": bool(settings.private_link_crypto_zapret2_enabled),
        "profileFile": profile_file,
        "packetShaping": "zapret2-scoped",
        "applyMode": "marked-flow-only",
        "hostWideInterception": False,
        "nfqueue": False,
        "failOpen": True,
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
        "selectedProfiles": selected_profiles,
        "zapret2": _link_crypto_zapret2_policy(settings, profile_file=_interconnect_profile_path(settings)),
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


def _link_crypto_payload(
    settings: Settings,
    *,
    runtime_contract_path: Path,
    runtime_contract_payload: dict[str, Any],
) -> dict[str, Any]:
    role_upper = str(runtime_contract_payload.get("role") or "").strip().upper() or "UNKNOWN"
    links: list[dict[str, Any]] = []
    remote_port = int(settings.private_link_crypto_remote_port or 443)

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
                    selected_profiles=["V2", "V4", "V6"],
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
                    selected_profiles=["V2", "V4", "V6"],
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
                    selected_profiles=["V2", "V4", "V6"],
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
                    selected_profiles=["V1", "V3", "V5", "V7"],
                )
            )

    return {
        "schema": "tracegate.link-crypto.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": str(runtime_contract_payload.get("runtimeProfile") or "").strip() or "xray-centric",
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

    env_lines = [
        f"TRACEGATE_LINK_CRYPTO_ROLE={_shell_quote(payload['role'])}",
        f"TRACEGATE_LINK_CRYPTO_RUNTIME_PROFILE={_shell_quote(payload['runtimeProfile'])}",
        f"TRACEGATE_LINK_CRYPTO_STATE_JSON={_shell_quote(str(json_path))}",
        f"TRACEGATE_LINK_CRYPTO_SECRET_MATERIAL={_shell_quote(_bool_text(bool(payload['secretMaterial'])))}",
        f"TRACEGATE_LINK_CRYPTO_COUNT={_shell_quote(payload['counts']['total'])}",
        f"TRACEGATE_LINK_CRYPTO_CLASSES={_shell_quote(':'.join(link_classes))}",
        f"TRACEGATE_LINK_CRYPTO_CARRIER={_shell_quote('mieru')}",
        f"TRACEGATE_LINK_CRYPTO_GENERATION={_shell_quote(int(settings.private_link_crypto_generation or 1))}",
        f"TRACEGATE_LINK_CRYPTO_ZAPRET2_ENABLED={_shell_quote(_bool_text(bool(settings.private_link_crypto_zapret2_enabled)))}",
        f"TRACEGATE_LINK_CRYPTO_ZAPRET2_HOST_WIDE_INTERCEPTION={_shell_quote(_bool_text(False))}",
        f"TRACEGATE_LINK_CRYPTO_ZAPRET2_NFQUEUE={_shell_quote(_bool_text(False))}",
    ]

    changed = False
    changed = _write_text_if_changed(json_path, _json_text(payload)) or changed
    changed = _write_text_if_changed(env_path, "\n".join(env_lines) + "\n") or changed
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
        "  tcp-request content accept if { req.ssl_hello_type 1 }",
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
        "wsTlsUpstream": str(settings.private_fronting_ws_tls_upstream or "").strip() or "127.0.0.1:4443",
        "mtprotoUpstream": str(settings.private_fronting_mtproto_upstream or "").strip() or "127.0.0.1:9443",
        "mtprotoProfileFile": _mtproto_profile_path(settings),
        "touchUdp443": bool(fronting.get("touchUdp443", settings.fronting_touch_udp_443)),
        "mtprotoDomain": mtproto_domain,
        "mtprotoFrontingMode": str(fronting.get("mtprotoFrontingMode") or settings.mtproto_fronting_mode or "dedicated-dns-only").strip().lower(),
        "tcp443Owner": str(fronting.get("tcp443Owner") or "").strip(),
        "udp443Owner": str(fronting.get("udp443Owner") or "").strip(),
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
        "profile": str(config.get("profile") or "").strip(),
    }


def _profile_stage(*, protocol: str, variant: str, role_upper: str) -> str:
    if protocol == "wireguard_wstunnel":
        return "direct-transit-public"
    if variant == "V6":
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
        "optionalPacketShaping": str(chain.get("optional_packet_shaping") or "").strip(),
        "managedBy": str(chain.get("managed_by") or "").strip(),
        "selectedProfiles": _string_list(chain.get("selected_profiles")),
        "innerTransport": str(chain.get("inner_transport") or "").strip(),
        "xrayBackhaul": bool(chain.get("xray_backhaul", True)),
    }


def _obfuscation_policy(*, protocol: str, variant: str) -> dict[str, Any]:
    if variant == "V6":
        return {
            "scope": "entry-transit-private-relay",
            "outer": "mieru",
            "packetShaping": "zapret2-scoped",
            "hostWideInterception": False,
        }
    if protocol == "wireguard_wstunnel":
        return {
            "scope": "public-wss-443",
            "outer": "wstunnel",
            "packetShaping": "zapret2-scoped",
            "hostWideInterception": False,
        }
    return {
        "scope": "public-tcp-443",
        "outer": "shadowtls-v3",
        "packetShaping": "zapret2-scoped",
        "hostWideInterception": False,
    }


def _shadowtls_profile_state(settings: Settings, row: dict[str, Any], *, role_upper: str) -> dict[str, Any] | None:
    config = _mapping(row.get("config"))
    connection_id = str(row.get("connection_id") or "").strip()
    if not connection_id:
        return None
    variant = str(row.get("variant") or "").strip()
    shadowtls = _mapping(config.get("shadowtls"))
    return {
        **_profile_metadata(row, config, role_upper=role_upper),
        "protocol": "shadowsocks2022_shadowtls",
        "stage": _profile_stage(protocol="shadowsocks2022_shadowtls", variant=variant, role_upper=role_upper),
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
        "chain": _chain_state(config),
        "obfuscation": _obfuscation_policy(protocol="shadowsocks2022_shadowtls", variant=variant),
    }


def _wireguard_profile_state(row: dict[str, Any], *, role_upper: str) -> dict[str, Any] | None:
    config = _mapping(row.get("config"))
    connection_id = str(row.get("connection_id") or "").strip()
    if not connection_id:
        return None
    variant = str(row.get("variant") or "").strip()
    wireguard = _mapping(config.get("wireguard"))
    wstunnel = _mapping(config.get("wstunnel"))
    return {
        **_profile_metadata(row, config, role_upper=role_upper),
        "protocol": "wireguard_wstunnel",
        "stage": _profile_stage(protocol="wireguard_wstunnel", variant=variant, role_upper=role_upper),
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
            "interface": str(wireguard.get("interface") or "wg0").strip(),
            "applyMode": "live-peer-sync",
            "removeStalePeers": True,
            "restartWireGuard": False,
            "restartWSTunnel": False,
        },
        "localSocks": _local_socks_state(config),
        "chain": None,
        "obfuscation": _obfuscation_policy(protocol="wireguard_wstunnel", variant=variant),
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
        "runtimeProfile": str(runtime_contract_payload.get("runtimeProfile") or "").strip() or "xray-centric",
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
    return changed
