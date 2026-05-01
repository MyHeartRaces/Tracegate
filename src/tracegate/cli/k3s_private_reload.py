from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

from tracegate.services.runtime_preflight import (
    LinkCryptoEnv,
    LinkCryptoState,
    PrivateProfileEnv,
    PrivateProfileState,
    RouterClientBundle,
    RouterClientBundleEnv,
    RouterHandoffEnv,
    RouterHandoffState,
    RuntimePreflightError,
    RuntimePreflightFinding,
    load_link_crypto_env,
    load_link_crypto_state,
    load_private_profile_env,
    load_private_profile_state,
    load_router_client_bundle,
    load_router_client_bundle_env,
    load_router_handoff_env,
    load_router_handoff_state,
    validate_link_crypto_env,
    validate_link_crypto_state,
    validate_private_profile_env,
    validate_private_profile_state,
    validate_router_client_bundle,
    validate_router_client_bundle_env,
    validate_router_handoff_env,
    validate_router_handoff_state,
)


class K3sPrivateReloadError(RuntimeError):
    pass


_MARKER_SCHEMA = "tracegate.k3s-private-reload.v1"
_SUMMARY_SCHEMA = "tracegate.k3s-private-reload-summary.v1"


def _role_lower(role: str) -> str:
    role_upper = str(role or "").strip().upper()
    if role_upper not in {"ENTRY", "TRANSIT"}:
        raise K3sPrivateReloadError(f"role must be ENTRY or TRANSIT, got: {role}")
    return role_upper.lower()


def _load_contract(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise K3sPrivateReloadError(f"runtime contract is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise K3sPrivateReloadError(f"runtime contract is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise K3sPrivateReloadError(f"runtime contract must be a JSON object: {path}")
    return payload


def _error_findings(findings: list[RuntimePreflightFinding]) -> list[RuntimePreflightFinding]:
    return [finding for finding in findings if finding.severity == "error"]


def _raise_for_errors(findings: list[RuntimePreflightFinding], *, component: str) -> None:
    errors = _error_findings(findings)
    if not errors:
        return
    details = "; ".join(f"{finding.code}: {finding.message}" for finding in errors[:5])
    if len(errors) > 5:
        details += f"; ... {len(errors) - 5} more"
    raise K3sPrivateReloadError(f"{component} handoff validation failed: {details}")


def _safe_write_marker(marker_path: Path, payload: dict[str, object]) -> None:
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = marker_path.with_suffix(marker_path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    tmp.replace(marker_path)


def _row_string(row: dict[str, Any], key: str) -> str:
    return str(row.get(key) or "").strip()


def _nested_dict(row: dict[str, Any], key: str) -> dict[str, Any]:
    value = row.get(key)
    return value if isinstance(value, dict) else {}


def _sorted_unique(values: list[object]) -> list[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()}, key=str)


def _count_true(rows: list[dict[str, Any]], key: str, *, default: bool = False) -> int:
    return len([row for row in rows if bool(row.get(key, default))])


def _safe_positive_ints(values: list[object]) -> list[int]:
    parsed: set[int] = set()
    for value in values:
        try:
            item = int(value)
        except (TypeError, ValueError):
            continue
        if item > 0:
            parsed.add(item)
    return sorted(parsed)


def _source_fingerprint(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {
        "sizeBytes": int(stat.st_size),
        "mtimeNs": int(stat.st_mtime_ns),
    }


def _profile_local_socks_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    auth_rows = [_nested_dict(_nested_dict(row, "localSocks"), "auth") for row in rows]
    return {
        "total": len(rows),
        "authRequired": len([auth for auth in auth_rows if bool(auth.get("required", False))]),
        "anonymous": len([auth for auth in auth_rows if not bool(auth.get("required", False))]),
        "usernamePassword": len([auth for auth in auth_rows if str(auth.get("mode") or "").strip() == "username_password"]),
    }


def _profile_obfuscation_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    obfuscation_rows = [_nested_dict(row, "obfuscation") for row in rows]
    return {
        "outers": _sorted_unique([row.get("outer") for row in obfuscation_rows]),
        "packetShaping": _sorted_unique([row.get("packetShaping") for row in obfuscation_rows]),
        "hostWideInterception": len([row for row in obfuscation_rows if bool(row.get("hostWideInterception", False))]),
    }


def _profile_shadowtls_outer_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    shadowtls_rows = [_nested_dict(row, "shadowtls") for row in rows if _row_string(row, "protocol") == "shadowsocks2022_shadowtls"]
    profile_refs = [_nested_dict(row, "profileRef") for row in shadowtls_rows]
    return {
        "total": len(shadowtls_rows),
        "credentialScopes": _sorted_unique([row.get("credentialScope") for row in shadowtls_rows]),
        "fileProfileRefs": len([row for row in profile_refs if _row_string(row, "kind") == "file"]),
        "secretProfileRefs": len([row for row in profile_refs if bool(row.get("secretMaterial", False))]),
        "perUserPasswords": len([row for row in shadowtls_rows if _row_string(row, "password")]),
        "manageUsers": len([row for row in shadowtls_rows if bool(row.get("manageUsers", False))]),
        "restartOnUserChange": len([row for row in shadowtls_rows if bool(row.get("restartOnUserChange", False))]),
    }


def _profile_wireguard_sync_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    wireguard_rows = [row for row in rows if _row_string(row, "protocol") == "wireguard_wstunnel"]
    sync_rows = [_nested_dict(row, "sync") for row in wireguard_rows]
    return {
        "total": len(wireguard_rows),
        "strategies": _sorted_unique([row.get("strategy") for row in sync_rows]),
        "interfaces": _sorted_unique([row.get("interface") for row in sync_rows]),
        "livePeerSync": len([row for row in sync_rows if _row_string(row, "applyMode") == "live-peer-sync"]),
        "removeStalePeers": len([row for row in sync_rows if bool(row.get("removeStalePeers", False))]),
        "restartWireGuard": len([row for row in sync_rows if bool(row.get("restartWireGuard", False))]),
        "restartWSTunnel": len([row for row in sync_rows if bool(row.get("restartWSTunnel", False))]),
    }


def _profile_chain_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    chain_rows = [_nested_dict(row, "chain") for row in rows if isinstance(row.get("chain"), dict)]
    return {
        "total": len(chain_rows),
        "managedBy": _sorted_unique([row.get("managedBy") for row in chain_rows]),
        "carriers": _sorted_unique([row.get("carrier") for row in chain_rows]),
        "xrayBackhaul": len([row for row in chain_rows if bool(row.get("xrayBackhaul", True))]),
    }


def _profile_stage_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    by_variant: dict[str, list[str]] = {}
    for row in rows:
        variant = _row_string(row, "variant")
        stage = _row_string(row, "stage")
        if not variant or not stage:
            continue
        by_variant.setdefault(variant, []).append(stage)
    return {variant: _sorted_unique(stages) for variant, stages in sorted(by_variant.items(), key=lambda item: item[0])}


def _transport_profiles_summary(transport_profiles: dict[str, Any]) -> dict[str, object]:
    client_names = transport_profiles.get("clientNames")
    local_socks = _nested_dict(transport_profiles, "localSocks")
    return {
        "clientNames": _sorted_unique(client_names if isinstance(client_names, list) else []),
        "clientCount": len(client_names) if isinstance(client_names, list) else 0,
        "localSocks": {
            "auth": _row_string(local_socks, "auth"),
            "allowAnonymousLocalhost": bool(local_socks.get("allowAnonymousLocalhost", False)),
        },
    }


def _profiles_summary(
    state: PrivateProfileState,
    env: PrivateProfileEnv,
    *,
    findings: list[RuntimePreflightFinding],
) -> dict[str, object]:
    shadowtls_rows = list(state.shadowsocks2022_shadowtls)
    wireguard_rows = list(state.wireguard_wstunnel)
    rows = [*shadowtls_rows, *wireguard_rows]
    return {
        "total": state.total_count,
        "protocols": {
            "shadowsocks2022ShadowTLS": state.shadowsocks2022_shadowtls_count,
            "wireguardWSTunnel": state.wireguard_wstunnel_count,
        },
        "variants": _sorted_unique([row.get("variant") for row in rows]),
        "profiles": _sorted_unique([row.get("profile") for row in rows]),
        "transportProfiles": _transport_profiles_summary(state.transport_profiles),
        "stages": _profile_stage_summary(rows),
        "localSocks": _profile_local_socks_summary(rows),
        "chain": _profile_chain_summary(rows),
        "obfuscation": _profile_obfuscation_summary(rows),
        "shadowtlsOuter": _profile_shadowtls_outer_summary(rows),
        "wireguardSync": _profile_wireguard_sync_summary(rows),
        "sources": {
            "state": _source_fingerprint(state.path),
            "env": _source_fingerprint(env.path),
        },
        "warnings": len([finding for finding in findings if finding.severity == "warning"]),
    }


def _split_shadowsocks2022_password(value: object) -> tuple[str, str]:
    raw = str(value or "").strip()
    server_key, sep, user_key = raw.rpartition(":")
    if not sep:
        raise K3sPrivateReloadError("Shadowsocks-2022 V3 password must use server-key:user-key format")
    server_key = server_key.strip()
    user_key = user_key.strip()
    if not server_key or not user_key:
        raise K3sPrivateReloadError("Shadowsocks-2022 V3 password contains an empty server or user key")
    return server_key, user_key


def _write_shadowsocks2022_runtime_config(*, state: PrivateProfileState, root: Path, role_lower: str) -> None:
    rows = list(state.shadowsocks2022_shadowtls)
    config_path = root / "runtime" / f"shadowsocks2022-{role_lower}-server.json"
    if not rows:
        try:
            config_path.unlink()
        except FileNotFoundError:
            pass
        return

    method = _row_string(_nested_dict(rows[0], "shadowsocks2022"), "method") or "2022-blake3-aes-128-gcm"
    server_password = ""
    users: list[dict[str, str]] = []
    for row in rows:
        ss2022 = _nested_dict(row, "shadowsocks2022")
        row_method = _row_string(ss2022, "method") or method
        if row_method != method:
            raise K3sPrivateReloadError("all V3 Shadowsocks-2022 rows for one role must use the same method")
        row_server_password, row_user_password = _split_shadowsocks2022_password(ss2022.get("password"))
        if not server_password:
            server_password = row_server_password
        elif row_server_password != server_password:
            raise K3sPrivateReloadError("all V3 Shadowsocks-2022 rows for one role must share the same server key")
        users.append(
            {
                "name": _row_string(row, "connectionId") or f"v3-{len(users) + 1}",
                "password": row_user_password,
            }
        )

    server = {
        "server": "127.0.0.1",
        "server_port": 18443,
        "method": method,
        "password": server_password,
        "users": users,
        "timeout": 300,
        "mode": "tcp_only",
    }
    if role_lower == "entry":
        payload = {
            "log": {"level": "info"},
            "inbounds": [
                {
                    "type": "shadowsocks",
                    "tag": "ss2022-in",
                    "listen": "127.0.0.1",
                    "listen_port": 18443,
                    "network": "tcp",
                    "method": method,
                    "password": server_password,
                    "users": users,
                }
            ],
            "outbounds": [
                {
                    "type": "socks",
                    "tag": "chain-to-transit",
                    "server": "127.0.0.1",
                    "server_port": 11082,
                    "version": "5",
                    "network": "tcp",
                }
            ],
            "route": {
                "rules": [{"inbound": ["ss2022-in"], "outbound": "chain-to-transit"}],
                "final": "chain-to-transit",
            },
        }
    else:
        payload = {"servers": [server]}
    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = config_path.with_suffix(config_path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    tmp.replace(config_path)
    config_path.chmod(0o600)


def _link_crypto_zapret2_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    zapret_rows = [_nested_dict(row, "zapret2") for row in rows]
    return {
        "enabled": len([row for row in zapret_rows if bool(row.get("enabled", False))]),
        "applyModes": _sorted_unique([row.get("applyMode") for row in zapret_rows]),
        "packetShaping": _sorted_unique([row.get("packetShaping") for row in zapret_rows]),
        "hostWideInterception": len([row for row in zapret_rows if bool(row.get("hostWideInterception", False))]),
        "nfqueue": len([row for row in zapret_rows if bool(row.get("nfqueue", False))]),
        "failOpen": len([row for row in zapret_rows if bool(row.get("failOpen", False))]),
    }


def _link_crypto_local_auth_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    auth_rows = [_nested_dict(_nested_dict(row, "local"), "auth") for row in rows]
    return {
        "total": len(rows),
        "authRequired": len([auth for auth in auth_rows if bool(auth.get("required", False))]),
        "anonymous": len([auth for auth in auth_rows if not bool(auth.get("required", False))]),
        "modes": _sorted_unique([auth.get("mode") for auth in auth_rows]),
    }


def _link_crypto_stability_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    rotation_rows = [_nested_dict(row, "rotation") for row in rows]
    stability_rows = [_nested_dict(row, "stability") for row in rows]
    return {
        "rotationStrategies": _sorted_unique([row.get("strategy") for row in rotation_rows]),
        "restartExisting": len([row for row in rotation_rows if bool(row.get("restartExisting", False))]),
        "failOpen": len([row for row in stability_rows if bool(row.get("failOpen", False))]),
        "dropUnrelatedTraffic": len([row for row in stability_rows if bool(row.get("dropUnrelatedTraffic", False))]),
    }


def _link_crypto_profile_ref_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    profile_refs = [_nested_dict(row, "profileRef") for row in rows]
    return {
        "fileRefs": len([row for row in profile_refs if _row_string(row, "kind") == "file"]),
        "inlineRefs": len([row for row in profile_refs if _row_string(row, "kind") == "inline"]),
        "secretMaterial": len([row for row in profile_refs if bool(row.get("secretMaterial", False))]),
        "missingPath": len([row for row in profile_refs if not _row_string(row, "path")]),
    }


def _link_crypto_remote_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    remote_rows = [_nested_dict(row, "remote") for row in rows]
    return {
        "roles": _sorted_unique([row.get("role") for row in remote_rows]),
        "endpointCount": len([row for row in remote_rows if _row_string(row, "endpoint")]),
    }


def _link_crypto_outer_carrier_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    outer_rows = [_nested_dict(row, "outerCarrier") for row in rows]
    enabled_rows = [row for row in outer_rows if bool(row.get("enabled", False))]
    return {
        "enabled": len(enabled_rows),
        "modes": _sorted_unique([row.get("mode") for row in enabled_rows]),
        "protocols": _sorted_unique([row.get("protocol") for row in enabled_rows]),
        "verifyTls": len([row for row in enabled_rows if bool(row.get("verifyTls", False))]),
        "secretMaterial": len([row for row in enabled_rows if bool(row.get("secretMaterial", False))]),
    }


def _link_crypto_udp_hardening_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    hardening_rows = [_nested_dict(row, "hardening") for row in rows]
    anti_replay_rows = [_nested_dict(row, "antiReplay") for row in hardening_rows]
    anti_amplification_rows = [_nested_dict(row, "antiAmplification") for row in hardening_rows]
    rate_limit_rows = [_nested_dict(row, "rateLimit") for row in hardening_rows]
    mtu_rows = [_nested_dict(row, "mtu") for row in hardening_rows]
    key_rotation_rows = [_nested_dict(row, "keyRotation") for row in hardening_rows]
    source_validation_rows = [_nested_dict(row, "sourceValidation") for row in hardening_rows]
    return {
        "enabled": len([row for row in hardening_rows if bool(row.get("enabled", False))]),
        "failClosed": len([row for row in hardening_rows if bool(row.get("failClosed", False))]),
        "rejectAnonymous": len([row for row in hardening_rows if bool(row.get("rejectAnonymous", False))]),
        "antiReplay": len([row for row in anti_replay_rows if bool(row.get("enabled", False))]),
        "antiAmplification": len([row for row in anti_amplification_rows if bool(row.get("enabled", False))]),
        "rateLimit": len([row for row in rate_limit_rows if bool(row.get("enabled", False))]),
        "mtuModes": _sorted_unique([row.get("mode") for row in mtu_rows]),
        "keyRotation": len([row for row in key_rotation_rows if bool(row.get("enabled", False))]),
        "keyRotationStrategies": _sorted_unique([row.get("strategy") for row in key_rotation_rows]),
        "sourceValidation": len([row for row in source_validation_rows if bool(row.get("enabled", False))]),
        "sourceValidationModes": _sorted_unique([row.get("mode") for row in source_validation_rows]),
    }


def _link_crypto_summary(
    state: LinkCryptoState,
    env: LinkCryptoEnv,
    *,
    findings: list[RuntimePreflightFinding],
) -> dict[str, object]:
    rows = list(state.links)
    udp_rows = list(state.udp_links)
    return {
        "total": state.total_count,
        "classes": {
            "entryTransit": state.entry_transit_count,
            "routerEntry": state.router_entry_count,
            "routerTransit": state.router_transit_count,
        },
        "udp": {
            "total": state.udp_total_count,
            "classes": {
                "entryTransitUdp": state.entry_transit_udp_count,
                "routerEntryUdp": state.router_entry_udp_count,
                "routerTransitUdp": state.router_transit_udp_count,
            },
            "carriers": _sorted_unique([row.get("carrier") for row in udp_rows]),
            "transports": _sorted_unique([row.get("transport") for row in udp_rows]),
            "selectedProfiles": _sorted_unique(
                [
                    profile
                    for row in udp_rows
                    for profile in row.get("selectedProfiles", [])
                    if isinstance(row.get("selectedProfiles"), list)
                ]
            ),
            "hardening": _link_crypto_udp_hardening_summary(udp_rows),
        },
        "carriers": _sorted_unique([row.get("carrier") for row in rows]),
        "sides": _sorted_unique([row.get("side") for row in rows]),
        "selectedProfiles": _sorted_unique(
            [profile for row in rows for profile in row.get("selectedProfiles", []) if isinstance(row.get("selectedProfiles"), list)]
        ),
        "transportProfiles": _transport_profiles_summary(state.transport_profiles),
        "generations": _safe_positive_ints([row.get("generation") for row in rows]),
        "xrayBackhaul": _count_true(rows, "xrayBackhaul", default=True),
        "remote": _link_crypto_remote_summary(rows),
        "outerCarrier": _link_crypto_outer_carrier_summary(rows),
        "profileRefs": _link_crypto_profile_ref_summary(rows),
        "localAuth": _link_crypto_local_auth_summary(rows),
        "zapret2": _link_crypto_zapret2_summary(rows),
        "stability": _link_crypto_stability_summary(rows),
        "sources": {
            "state": _source_fingerprint(state.path),
            "env": _source_fingerprint(env.path),
        },
        "warnings": len([finding for finding in findings if finding.severity == "warning"]),
    }


_ROUTER_LINK_CLASSES = {"router-entry", "router-transit", "router-entry-udp", "router-transit-udp"}


def _link_crypto_has_router_routes(state: LinkCryptoState) -> bool:
    return any(_row_string(row, "class") in _ROUTER_LINK_CLASSES for row in [*state.links, *state.udp_links])


def _router_handoff_paths(root: Path, role_lower: str) -> tuple[Path, Path, Path, Path]:
    router_root = root / "router" / role_lower
    return (
        router_root / "desired-state.json",
        router_root / "desired-state.env",
        router_root / "client-bundle.json",
        router_root / "client-bundle.env",
    )


def _router_handoff_present(root: Path, role_lower: str) -> bool:
    return any(path.exists() for path in _router_handoff_paths(root, role_lower))


def _router_profile_refs_summary(routes: list[dict[str, Any]]) -> dict[str, object]:
    refs: list[dict[str, Any]] = []
    for row in routes:
        router_client = _nested_dict(row, "routerClient")
        router_side = _nested_dict(row, "routerSide")
        profile_refs = _nested_dict(router_client, "profileRefs") or _nested_dict(router_side, "profileRefs")
        refs.extend(value for value in profile_refs.values() if isinstance(value, dict))
    return {
        "total": len(refs),
        "fileRefs": len([row for row in refs if _row_string(row, "kind") == "file"]),
        "secretMaterial": len([row for row in refs if bool(row.get("secretMaterial", False))]),
        "missingPath": len([row for row in refs if not _row_string(row, "path")]),
    }


def _router_components_summary(bundle: RouterClientBundle) -> dict[str, object]:
    components = list(bundle.components)
    return {
        "required": _sorted_unique([row.get("name") for row in components if bool(row.get("required", False))]),
        "failClosed": len([row for row in components if bool(row.get("failClosed", False))]),
        "noHostWideInterception": len([row for row in components if bool(row.get("noHostWideInterception", False))]),
        "noNfqueue": len([row for row in components if bool(row.get("noNfqueue", False))]),
    }


def _router_hardening_summary(routes: list[dict[str, Any]]) -> dict[str, object]:
    paired_obfs_rows = [_nested_dict(row, "pairedObfs") for row in routes]
    hardening_rows = [_nested_dict(row, "hardening") for row in routes]
    return {
        "pairedObfs": len([row for row in paired_obfs_rows if bool(row.get("enabled", False))]),
        "pairedObfsBothSides": len([row for row in paired_obfs_rows if bool(row.get("requiresBothSides", False))]),
        "pairedObfsFailClosed": len([row for row in paired_obfs_rows if bool(row.get("failClosed", False))]),
        "failClosed": len([row for row in hardening_rows if bool(row.get("failClosed", False))]),
        "sourceValidation": len([row for row in hardening_rows if bool(_nested_dict(row, "sourceValidation").get("enabled", False))]),
    }


def _router_summary(
    state: RouterHandoffState,
    env: RouterHandoffEnv,
    bundle: RouterClientBundle,
    bundle_env: RouterClientBundleEnv,
    *,
    findings: list[RuntimePreflightFinding],
) -> dict[str, object]:
    handoff_routes = [*state.tcp_routes, *state.udp_routes]
    bundle_routes = [*bundle.tcp_routes, *bundle.udp_routes]
    return {
        "enabled": state.enabled,
        "placement": state.placement,
        "counts": {
            "total": state.total_count,
            "tcp": state.tcp_count,
            "udp": state.udp_count,
        },
        "classes": {
            "tcp": list(state.tcp_classes),
            "udp": list(state.udp_classes),
        },
        "bundle": {
            "enabled": bundle.enabled,
            "components": _router_components_summary(bundle),
            "profileDistribution": _row_string(bundle.requirements, "profileDistribution"),
            "requiresBothSides": bool(bundle.requirements.get("requiresBothSides", False)),
            "failClosed": bool(bundle.requirements.get("failClosed", False)),
        },
        "profileRefs": _router_profile_refs_summary([*handoff_routes, *bundle_routes]),
        "hardening": _router_hardening_summary([*state.udp_routes, *bundle.udp_routes]),
        "env": {
            "pairedObfs": env.paired_obfs_enabled,
            "clientComponents": list(bundle_env.components),
            "clientFailClosed": bundle_env.fail_closed,
            "clientNoHostWideInterception": bundle_env.no_host_wide_interception,
            "clientNoNfqueue": bundle_env.no_nfqueue,
        },
        "sources": {
            "state": _source_fingerprint(state.path),
            "env": _source_fingerprint(env.path),
            "clientBundle": _source_fingerprint(bundle.path),
            "clientEnv": _source_fingerprint(bundle_env.path),
        },
        "warnings": len([finding for finding in findings if finding.severity == "warning"]),
    }


def _validate_router_handoff_bundle(
    *,
    role: str,
    root: Path,
    contract_path: Path,
    link_crypto_state: LinkCryptoState,
) -> dict[str, object]:
    role_lower = _role_lower(role)
    state_path, env_path, bundle_path, bundle_env_path = _router_handoff_paths(root, role_lower)
    state = load_router_handoff_state(state_path)
    env = load_router_handoff_env(env_path)
    bundle = load_router_client_bundle(bundle_path)
    bundle_env = load_router_client_bundle_env(bundle_env_path)
    contract = _load_contract(contract_path)
    findings = [
        *validate_router_handoff_state(
            state=state,
            contract=contract,
            expected_role=role,
            contract_path=contract_path,
            link_crypto_state=link_crypto_state,
        ),
        *validate_router_handoff_env(
            env=env,
            expected_role=role,
            contract=contract,
            state=state,
        ),
        *validate_router_client_bundle(
            bundle=bundle,
            expected_role=role,
            contract=contract,
            handoff_state=state,
        ),
        *validate_router_client_bundle_env(
            env=bundle_env,
            expected_role=role,
            contract=contract,
            bundle=bundle,
            handoff_state=state,
        ),
    ]
    _raise_for_errors(findings, component="router")
    return _router_summary(state, env, bundle, bundle_env, findings=findings)


def _validate_profiles(*, role: str, root: Path, contract_path: Path) -> dict[str, object]:
    role_lower = _role_lower(role)
    state = load_private_profile_state(root / "profiles" / role_lower / "desired-state.json")
    env = load_private_profile_env(root / "profiles" / role_lower / "desired-state.env")
    contract = _load_contract(contract_path)
    findings = [
        *validate_private_profile_state(
            state=state,
            contract=contract,
            expected_role=role,
            contract_path=contract_path,
        ),
        *validate_private_profile_env(
            env=env,
            expected_role=role,
            contract=contract,
            state=state,
        ),
    ]
    _raise_for_errors(findings, component="profiles")
    _write_shadowsocks2022_runtime_config(state=state, root=root, role_lower=role_lower)
    return _profiles_summary(state, env, findings=findings)


def _validate_link_crypto(*, role: str, root: Path, contract_path: Path) -> dict[str, object]:
    role_lower = _role_lower(role)
    state = load_link_crypto_state(root / "link-crypto" / role_lower / "desired-state.json")
    env = load_link_crypto_env(root / "link-crypto" / role_lower / "desired-state.env")
    contract = _load_contract(contract_path)
    findings = [
        *validate_link_crypto_state(
            state=state,
            contract=contract,
            expected_role=role,
            contract_path=contract_path,
        ),
        *validate_link_crypto_env(
            env=env,
            expected_role=role,
            contract=contract,
            state=state,
        ),
    ]
    _raise_for_errors(findings, component="link-crypto")
    summary = _link_crypto_summary(state, env, findings=findings)
    if _link_crypto_has_router_routes(state) or _router_handoff_present(root, role_lower):
        summary["router"] = _validate_router_handoff_bundle(
            role=role,
            root=root,
            contract_path=contract_path,
            link_crypto_state=state,
        )
    return summary


def run_private_reload(
    *,
    component: str,
    role: str,
    private_runtime_root: Path,
    runtime_contract: Path,
    marker_root: Path | None = None,
) -> dict[str, object]:
    role_lower = _role_lower(role)
    component_normalized = str(component or "").strip().lower()
    if component_normalized == "profiles":
        summary = _validate_profiles(role=role, root=private_runtime_root, contract_path=runtime_contract)
    elif component_normalized == "link-crypto":
        summary = _validate_link_crypto(role=role, root=private_runtime_root, contract_path=runtime_contract)
    else:
        raise K3sPrivateReloadError(f"unsupported k3s private reload component: {component}")

    marker_dir = marker_root or private_runtime_root / "runtime"
    marker_path = marker_dir / f"{component_normalized}-{role_lower}-last-reload.json"
    marker_payload: dict[str, object] = {
        "schema": _MARKER_SCHEMA,
        "summarySchema": _SUMMARY_SCHEMA,
        "component": component_normalized,
        "role": role_lower.upper(),
        "validatedAt": datetime.now(timezone.utc).isoformat(),
        "runtimeContract": str(runtime_contract),
        "summary": summary,
    }
    _safe_write_marker(marker_path, marker_payload)
    return {**marker_payload, "markerPath": str(marker_path)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracegate-k3s-private-reload",
        description="Validate Tracegate k3s private runtime handoffs and emit a redacted reload marker.",
    )
    parser.add_argument("--component", required=True, choices=["profiles", "link-crypto"], help="Private handoff component")
    parser.add_argument("--role", required=True, choices=["ENTRY", "TRANSIT", "entry", "transit"], help="Gateway role")
    parser.add_argument("--private-runtime-root", default="/var/lib/tracegate/private", help="Private runtime root")
    parser.add_argument(
        "--runtime-contract",
        default="/var/lib/tracegate/runtime/runtime-contract.json",
        help="Runtime contract JSON emitted by the agent",
    )
    parser.add_argument("--marker-root", default="", help="Override marker output directory")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run_private_reload(
            component=args.component,
            role=args.role,
            private_runtime_root=Path(args.private_runtime_root),
            runtime_contract=Path(args.runtime_contract),
            marker_root=Path(args.marker_root) if args.marker_root else None,
        )
    except (K3sPrivateReloadError, RuntimePreflightError) as exc:
        raise SystemExit(str(exc)) from exc

    sys.stdout.write(
        "OK k3s private reload "
        f"component={result['component']} "
        f"role={result['role']} "
        f"marker={result['markerPath']}\n"
    )


if __name__ == "__main__":
    main()
