from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
import threading

import yaml

from tracegate.services.private_handoffs import write_private_runtime_handoffs
from tracegate.agent.hysteria_clients import build_hysteria_xray_clients
from tracegate.enums import ConnectionProtocol, ConnectionVariant, NodeRole
from tracegate.services.role_targeting import target_roles_for_connection
from tracegate.services.runtime_contract import resolve_runtime_contract
from tracegate.services.sni_catalog import load_catalog
from tracegate.settings import Settings, effective_private_runtime_root

_INDEX_FILE_NAME = "artifact-index.json"
_RUNTIME_CONTRACT_FILE_NAME = "runtime-contract.json"
_K3S_PRIVATE_RELOAD_MARKER_SCHEMA = "tracegate.k3s-private-reload.v1"
_K3S_PRIVATE_RELOAD_SUMMARY_SCHEMA = "tracegate.k3s-private-reload-summary.v1"
_DECOY_MANIFEST_FILE_NAME = ".tracegate-sync-manifest.json"
_INDEX_LOCK = threading.Lock()


@dataclass(frozen=True)
class AgentPaths:
    root: Path
    base: Path
    runtime: Path
    users_dir: Path

    @staticmethod
    def from_settings(settings: Settings) -> "AgentPaths":
        root = Path(settings.agent_data_root)
        return AgentPaths(
            root=root,
            base=root / "base",
            runtime=root / "runtime",
            users_dir=root / "users",
        )


@dataclass(frozen=True)
class RealityInboundGroup:
    id: str
    port: int
    dest_host: str
    snis: tuple[str, ...]


@dataclass(frozen=True)
class ReconcileXrayResult:
    changed: bool
    force_reload: bool = False


@dataclass(frozen=True)
class ReconcileAllResult:
    changed: list[str]
    force_xray_reload: bool = False


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _safe_dump_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _safe_dump_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def _safe_dump_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(content)
    tmp.replace(path)


def _normalize_xray_runtime_for_live_user_compare(payload: dict | None) -> dict | None:
    if payload is None:
        return None

    normalized = copy.deepcopy(payload)
    for inbound in normalized.get("inbounds", []):
        if not isinstance(inbound, dict):
            continue
        protocol = str(inbound.get("protocol") or "").strip().lower()
        settings = inbound.get("settings")
        if not isinstance(settings, dict):
            continue
        if protocol in {"vless", "hysteria"} and isinstance(settings.get("clients"), list):
            settings["clients"] = []
    return normalized


def _xray_structural_reload_required(current: dict | None, desired: dict | None) -> bool:
    if current is None or desired is None:
        return current != desired
    return _normalize_xray_runtime_for_live_user_compare(current) != _normalize_xray_runtime_for_live_user_compare(
        desired
    )


def _ensure_public_decoy_mode(path: Path, *, is_dir: bool | None = None) -> bool:
    try:
        current = path.stat().st_mode & 0o777
    except FileNotFoundError:
        return False
    target = 0o755 if (path.is_dir() if is_dir is None else is_dir) else 0o644
    if current == target:
        return False
    path.chmod(target)
    return True


def _safe_remove_path(path: Path) -> bool:
    if not path.exists():
        return False
    if path.is_dir():
        for child in sorted(path.iterdir(), key=lambda row: row.name, reverse=True):
            _safe_remove_path(child)
        path.rmdir()
        return True
    path.unlink()
    return True


def _try_load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        payload = _load_json(path)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _try_load_yaml(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        payload = _load_yaml(path)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _try_read_bytes(path: Path) -> bytes | None:
    if not path.exists():
        return None
    try:
        return path.read_bytes()
    except Exception:
        return None


def _has_nonempty_value(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        return any(_has_nonempty_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_has_nonempty_value(item) for item in value)
    if isinstance(value, bool):
        return value
    return True


def _sorted_unique_strings(values: list[str]) -> list[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()}, key=str)


def _safe_int(value: object, *, default: int = 0) -> int:
    try:
        return int(value if value is not None else default)
    except (TypeError, ValueError):
        return default


def _extract_masquerade_dirs(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    dirs: list[str] = []
    direct_dir = str(value.get("dir") or "").strip()
    if direct_dir:
        dirs.append(direct_dir)
    file_block = value.get("file")
    if isinstance(file_block, dict):
        file_dir = str(file_block.get("dir") or "").strip()
        if file_dir:
            dirs.append(file_dir)
    return _sorted_unique_strings(dirs)


def _extract_nginx_roots(config_text: str) -> list[str]:
    roots: list[str] = []
    for line in config_text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped.startswith("root ") or not stripped.endswith(";"):
            continue
        root = stripped[len("root ") : -1].strip()
        if root:
            roots.append(root)
    return _sorted_unique_strings(roots)


def _runtime_contract_path(paths: AgentPaths) -> Path:
    return paths.runtime / _RUNTIME_CONTRACT_FILE_NAME


def _contract_port_owner(contract, role: str, *, protocol: str, port: int) -> str:
    for row_protocol, row_port, _name in contract.expected_ports(role):
        if row_protocol != protocol or row_port != port:
            continue
        if protocol == "udp":
            return "hysteria" if contract.manages_component("hysteria") else "xray"
        if contract.manages_component("haproxy"):
            return "haproxy"
        if contract.manages_component("xray"):
            return "xray"
    return ""


def _collect_xray_runtime_state(paths: AgentPaths) -> dict[str, object]:
    config_paths = [
        paths.runtime / "xray" / "config.json",
        paths.runtime / "xray-v2" / "config.json",
    ]
    inspected_paths: list[str] = []
    hysteria_inbound_tags: list[str] = []
    hysteria_masquerade_dirs: list[str] = []
    api_services: list[str] = []
    api_inbounds: list[dict[str, object]] = []
    finalmask_enabled = False
    ech_enabled = False

    for path in config_paths:
        payload = _try_load_json(path)
        if payload is None:
            continue
        inspected_paths.append(str(path))
        api = payload.get("api")
        if isinstance(api, dict):
            services = api.get("services")
            if isinstance(services, list):
                api_services.extend(str(service or "").strip() for service in services)

        inbounds = payload.get("inbounds")
        if isinstance(inbounds, list):
            for row in inbounds:
                if not isinstance(row, dict):
                    continue
                tag = str(row.get("tag") or "").strip()
                if tag != "api":
                    continue
                api_inbounds.append(
                    {
                        "tag": tag,
                        "listen": str(row.get("listen") or "").strip(),
                        "port": _safe_int(row.get("port")),
                        "protocol": str(row.get("protocol") or "").strip().lower(),
                    }
                )

        stream_rows = []
        for section_name in ("inbounds", "outbounds"):
            section = payload.get(section_name)
            if isinstance(section, list):
                stream_rows.extend([row for row in section if isinstance(row, dict)])

        for row in stream_rows:
            stream = row.get("streamSettings")
            if not isinstance(stream, dict):
                continue

            if _has_nonempty_value(stream.get("finalmask")):
                finalmask_enabled = True

            tls_settings = stream.get("tlsSettings")
            if isinstance(tls_settings, dict) and (
                _has_nonempty_value(tls_settings.get("echServerKeys"))
                or _has_nonempty_value(tls_settings.get("echConfigList"))
            ):
                ech_enabled = True

            if str(row.get("protocol") or "").strip().lower() != "hysteria":
                continue
            tag = str(row.get("tag") or "").strip()
            if tag:
                hysteria_inbound_tags.append(tag)
            hysteria_settings = stream.get("hysteriaSettings")
            if isinstance(hysteria_settings, dict):
                hysteria_masquerade_dirs.extend(_extract_masquerade_dirs(hysteria_settings.get("masquerade")))

    return {
        "configPaths": inspected_paths,
        "hasV2SplitBackend": config_paths[1].exists(),
        "hysteriaInboundTags": _sorted_unique_strings(hysteria_inbound_tags),
        "hysteriaMasqueradeDirs": _sorted_unique_strings(hysteria_masquerade_dirs),
        "apiServices": _sorted_unique_strings(api_services),
        "apiInbounds": api_inbounds,
        "finalMaskEnabled": finalmask_enabled,
        "echEnabled": ech_enabled,
    }


def _build_link_crypto_contract_payload(settings: Settings) -> dict[str, object]:
    role_upper = str(settings.agent_role or "").strip().upper()
    classes: list[str] = []
    local_ports: dict[str, int] = {}
    selected_profiles: dict[str, list[str]] = {}

    def add_link(link_class: str, *, port: int, profiles: list[str]) -> None:
        classes.append(link_class)
        local_ports[link_class] = int(port)
        selected_profiles[link_class] = profiles

    if role_upper == "ENTRY":
        if bool(settings.private_link_crypto_enabled):
            add_link("entry-transit", port=int(settings.private_link_crypto_entry_port), profiles=["V2", "V4", "V6"])
        if bool(settings.private_link_crypto_router_entry_enabled):
            add_link("router-entry", port=int(settings.private_link_crypto_router_entry_port), profiles=["V2", "V4", "V6"])
    elif role_upper == "TRANSIT":
        if bool(settings.private_link_crypto_enabled):
            add_link("entry-transit", port=int(settings.private_link_crypto_transit_port), profiles=["V2", "V4", "V6"])
        if bool(settings.private_link_crypto_router_transit_enabled):
            add_link("router-transit", port=int(settings.private_link_crypto_router_transit_port), profiles=["V1", "V3", "V5", "V7"])

    outer_wss_server_name = str(settings.private_link_crypto_outer_wss_server_name or "").strip() or "bridge.example.com"
    outer_wss_public_port = int(settings.private_link_crypto_outer_wss_public_port or 443)
    outer_wss_path = str(settings.private_link_crypto_outer_wss_path or "").strip() or "/cdn-cgi/tracegate-link"
    if not outer_wss_path.startswith("/"):
        outer_wss_path = f"/{outer_wss_path}"
    outer_carrier = {
        "enabled": bool("entry-transit" in classes and settings.private_link_crypto_outer_carrier_enabled),
        "mode": str(settings.private_link_crypto_outer_carrier_mode or "").strip() or "wss",
        "protocol": "websocket-tls",
        "serverName": outer_wss_server_name,
        "publicPort": outer_wss_public_port,
        "publicPath": outer_wss_path,
        "url": f"wss://{outer_wss_server_name}:{outer_wss_public_port}{outer_wss_path}",
        "verifyTls": bool(settings.private_link_crypto_outer_wss_verify_tls),
        "secretMaterial": False,
        "localPorts": {
            "entryClient": int(settings.private_link_crypto_outer_wss_client_port or 14081),
            "transitServer": int(settings.private_link_crypto_outer_wss_server_port or 14082),
        },
        "endpoints": {
            "entryClientListen": f"127.0.0.1:{int(settings.private_link_crypto_outer_wss_client_port or 14081)}",
            "transitServerListen": f"127.0.0.1:{int(settings.private_link_crypto_outer_wss_server_port or 14082)}",
            "transitTarget": f"127.0.0.1:{int(settings.private_link_crypto_transit_port or 10882)}",
        },
    }

    return {
        "enabled": bool(classes),
        "entryTransitEnabled": bool(settings.private_link_crypto_enabled),
        "routerEntryEnabled": bool(settings.private_link_crypto_router_entry_enabled),
        "routerTransitEnabled": bool(settings.private_link_crypto_router_transit_enabled),
        "carrier": "mieru",
        "manager": "link-crypto",
        "profileSource": "private-file-reference",
        "secretMaterial": False,
        "xrayBackhaul": False,
        "generation": int(settings.private_link_crypto_generation or 1),
        "bindHost": str(settings.private_link_crypto_bind_host or "").strip() or "127.0.0.1",
        "remotePort": int(settings.private_link_crypto_remote_port or 443),
        "outerCarrier": outer_carrier,
        "classes": classes,
        "counts": {
            "total": len(classes),
            "entryTransit": len([link_class for link_class in classes if link_class == "entry-transit"]),
            "routerEntry": len([link_class for link_class in classes if link_class == "router-entry"]),
            "routerTransit": len([link_class for link_class in classes if link_class == "router-transit"]),
        },
        "localPorts": local_ports,
        "selectedProfiles": selected_profiles,
        "zapret2": {
            "enabled": bool(settings.private_link_crypto_zapret2_enabled),
            "packetShaping": "zapret2-scoped",
            "applyMode": "marked-flow-only",
            "hostWideInterception": False,
            "nfqueue": False,
            "failOpen": True,
        },
    }


def _csv_values(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _build_runtime_contract_payload(settings: Settings) -> dict[str, object]:
    paths = AgentPaths.from_settings(settings)
    contract = resolve_runtime_contract(settings.agent_runtime_profile)

    runtime_xray = _collect_xray_runtime_state(paths)
    runtime_hysteria = _try_load_yaml(paths.runtime / "hysteria" / "config.yaml") or {}
    runtime_nginx_path = paths.runtime / "nginx" / "nginx.conf"
    runtime_nginx = runtime_nginx_path.read_text(encoding="utf-8") if runtime_nginx_path.exists() else ""

    link_crypto = _build_link_crypto_contract_payload(settings)
    payload = {
        "role": str(settings.agent_role or "").strip().upper() or "UNKNOWN",
        "runtimeProfile": contract.name,
        "localSocksAuth": "required" if contract.local_socks_auth_required else "disabled",
        "contract": {
            "aliases": list(contract.aliases),
            "managedComponents": list(contract.managed_components),
            "runtimeDirs": list(contract.runtime_dirs),
            "hysteriaAuthMode": contract.hysteria_auth_mode,
            "hysteriaMetricsSource": contract.hysteria_metrics_source,
            "transitStatsProvider": contract.transit_stats_provider,
            "xrayBackhaulAllowed": contract.xray_backhaul_allowed,
            "expectedPorts": [
                {"protocol": protocol, "port": port, "name": name}
                for protocol, port, name in contract.expected_ports(settings.agent_role)
            ],
        },
        "transportProfiles": {
            "clientNames": list(contract.client_profiles),
            "localSocks": {
                "auth": "required" if contract.local_socks_auth_required else "disabled",
                "allowAnonymousLocalhost": bool(contract.allow_anonymous_local_socks),
            },
            "clientExposure": {
                "defaultMode": "vpn-tun",
                "localProxyExports": "advanced-only",
                "lanSharing": "forbidden",
                "unauthenticatedLocalProxy": "forbidden",
            },
        },
        "network": {
            "egressIsolation": {
                "required": bool(settings.agent_egress_isolation_required),
                "mode": str(settings.agent_egress_isolation_mode or "").strip() or "dedicated-egress-ip",
                "ingressPublicIPs": _csv_values(settings.agent_egress_ingress_public_ips),
                "egressPublicIPs": _csv_values(settings.agent_egress_public_ips),
                "forbidIngressIpAsEgress": bool(settings.agent_egress_forbid_ingress_ip_as_egress),
                "requireTransitEgressPublicIP": bool(settings.agent_egress_require_transit_public_ip),
                "clientLeakMitigation": str(settings.agent_egress_client_leak_mitigation or "").strip() or "egress-ip-only",
                "enforcement": {
                    "mode": str(settings.agent_egress_enforcement_mode or "").strip() or "operator-managed",
                    "managedBy": str(settings.agent_egress_enforcement_managed_by or "").strip()
                    or "/etc/tracegate/private/egress-isolation",
                    "snat": str(settings.agent_egress_enforcement_snat or "").strip() or "required",
                    "ingressPublicIpOutbound": str(
                        settings.agent_egress_enforcement_ingress_public_ip_outbound or ""
                    ).strip()
                    or "forbidden",
                },
            },
        },
        "linkCrypto": link_crypto,
        "rollout": {
            "gatewayStrategy": str(settings.agent_gateway_strategy or "").strip() or "RollingUpdate",
            "allowRecreateStrategy": bool(settings.agent_gateway_allow_recreate_strategy),
            "maxUnavailable": str(settings.agent_gateway_max_unavailable or "0").strip() or "0",
            "maxSurge": str(settings.agent_gateway_max_surge or "1").strip() or "1",
            "progressDeadlineSeconds": int(settings.agent_gateway_progress_deadline_seconds),
            "pdbMinAvailable": str(settings.agent_gateway_pdb_min_available or "1").strip() or "1",
            "probesEnabled": bool(settings.agent_gateway_probes_enabled),
            "privatePreflightEnabled": bool(settings.agent_gateway_private_preflight_enabled),
            "privatePreflightForbidPlaceholders": bool(settings.agent_gateway_private_preflight_forbid_placeholders),
        },
        "fronting": {
            "tcp443Owner": _contract_port_owner(contract, settings.agent_role, protocol="tcp", port=443),
            "udp443Owner": _contract_port_owner(contract, settings.agent_role, protocol="udp", port=443),
            "touchUdp443": bool(settings.fronting_touch_udp_443),
            "mtprotoDomain": str(settings.mtproto_domain or "").strip(),
            "mtprotoPublicPort": int(settings.mtproto_public_port),
            "mtprotoFrontingMode": str(settings.mtproto_fronting_mode or "").strip().lower() or "dedicated-dns-only",
        },
        "paths": {
            "root": str(paths.root),
            "baseRoot": str(paths.base),
            "runtimeRoot": str(paths.runtime),
            "usersRoot": str(paths.users_dir),
            "xrayConfig": str(paths.runtime / "xray" / "config.json"),
            "xrayV2Config": str(paths.runtime / "xray-v2" / "config.json"),
            "haproxyConfig": str(paths.runtime / "haproxy" / "haproxy.cfg"),
            "nginxConfig": str(runtime_nginx_path),
        },
        "decoy": {
            "nginxRoots": _extract_nginx_roots(runtime_nginx),
            "splitHysteriaMasqueradeDirs": _extract_masquerade_dirs(runtime_hysteria.get("masquerade")),
            "xrayHysteriaMasqueradeDirs": runtime_xray["hysteriaMasqueradeDirs"],
        },
        "xray": runtime_xray,
    }
    return payload


def _write_runtime_contract_state(settings: Settings) -> tuple[bool, dict[str, object]]:
    paths = AgentPaths.from_settings(settings)
    payload = _build_runtime_contract_payload(settings)

    current = _try_load_json(_runtime_contract_path(paths))
    if current != payload:
        _safe_dump_json(_runtime_contract_path(paths), payload)
        return True, payload
    return False, payload


def _cleanup_unmanaged_runtime_state(settings: Settings) -> None:
    contract = resolve_runtime_contract(settings.agent_runtime_profile)
    paths = AgentPaths.from_settings(settings)

    if not contract.manages_component("hysteria"):
        runtime_hysteria_dir = paths.runtime / "hysteria"
        _safe_remove_path(runtime_hysteria_dir)


def _safe_decoy_target_root(path_raw: str) -> Path | None:
    raw = str(path_raw or "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute() or path == Path("/"):
        return None
    return path


def _decoy_manifest_path(root: Path) -> Path:
    return root / _DECOY_MANIFEST_FILE_NAME


def _load_decoy_manifest(root: Path) -> set[str]:
    path = _decoy_manifest_path(root)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    payload = raw.get("files") if isinstance(raw, dict) else raw
    if not isinstance(payload, list):
        return set()
    return {str(value).strip().strip("/") for value in payload if str(value).strip()}


def _write_decoy_manifest(root: Path, files: set[str]) -> bool:
    normalized = sorted({str(value).strip().strip("/") for value in files if str(value).strip()}, key=str)
    payload = {"version": 1, "files": normalized}
    path = _decoy_manifest_path(root)
    current = _try_load_json(path)
    if current == payload:
        return False
    _safe_dump_json(path, payload)
    return True


def _prune_empty_parent_dirs(path: Path, *, stop_at: Path) -> None:
    current = path.parent
    stop = stop_at.resolve()
    while current.exists() and current.resolve() != stop:
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def _runtime_decoy_roots(paths: AgentPaths) -> list[str]:
    runtime_nginx_path = paths.runtime / "nginx" / "nginx.conf"
    runtime_nginx = runtime_nginx_path.read_text(encoding="utf-8") if runtime_nginx_path.exists() else ""
    roots: list[str] = []
    roots.extend(_extract_nginx_roots(runtime_nginx))
    roots.extend(_collect_xray_runtime_state(paths).get("xrayHysteriaMasqueradeDirs") or [])
    return _sorted_unique_strings(roots)


def reconcile_decoy(settings: Settings) -> bool:
    paths = AgentPaths.from_settings(settings)
    source_dir = paths.base / "decoy"
    if not source_dir.exists():
        return False

    roots = _runtime_decoy_roots(paths)
    changed = False
    desired_files = {
        str(source.relative_to(source_dir)).strip("/")
        for source in source_dir.rglob("*")
        if source.is_file()
    }
    for root_raw in roots:
        target_root = _safe_decoy_target_root(root_raw)
        if target_root is None:
            continue
        target_root.mkdir(parents=True, exist_ok=True)
        changed = _ensure_public_decoy_mode(target_root, is_dir=True) or changed
        previous_files = _load_decoy_manifest(target_root)
        for relative_name in sorted(previous_files - desired_files, key=str):
            stale_path = target_root / relative_name
            if not stale_path.exists():
                continue
            if stale_path.is_file():
                stale_path.unlink()
                _prune_empty_parent_dirs(stale_path, stop_at=target_root)
                changed = True
        for source in sorted(source_dir.rglob("*"), key=lambda row: str(row.relative_to(source_dir))):
            target = target_root / source.relative_to(source_dir)
            if source.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                changed = _ensure_public_decoy_mode(target, is_dir=True) or changed
                continue
            payload = source.read_bytes()
            if _try_read_bytes(target) == payload:
                changed = _ensure_public_decoy_mode(target, is_dir=False) or changed
                continue
            _safe_dump_bytes(target, payload)
            target.chmod(0o644)
            changed = True
        manifest_changed = _write_decoy_manifest(target_root, desired_files)
        changed = _ensure_public_decoy_mode(_decoy_manifest_path(target_root), is_dir=False) or manifest_changed or changed
    return changed


def _merge_clients(existing: list[dict] | None, dynamic: list[dict]) -> list[dict]:
    """
    Merge base and dynamic client lists by UUID.

    Base clients are kept (for operator-defined static users, e.g. inter-node transit),
    while dynamic users override by the same id.
    """
    out: dict[str, dict] = {}
    for row in existing or []:
        if not isinstance(row, dict):
            continue
        client_id = str(row.get("id") or "").strip()
        if not client_id:
            continue
        out[client_id] = row
    for row in dynamic:
        client_id = str(row.get("id") or "").strip()
        if not client_id:
            continue
        out[client_id] = row
    return [out[key] for key in sorted(out, key=str)]


def _merge_hysteria_clients(existing: list[dict] | None, dynamic: list[dict]) -> list[dict]:
    """
    Merge Xray-native Hysteria client rows by canonical email.

    Dynamic rows should replace older rows for the same logical connection marker while
    keeping any unrelated static/bootstrap rows intact.
    """
    out: dict[str, dict] = {}
    for row in existing or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("email") or row.get("auth") or "").strip()
        if not key:
            continue
        out[key] = row
    for row in dynamic:
        if not isinstance(row, dict):
            continue
        key = str(row.get("email") or row.get("auth") or "").strip()
        if not key:
            continue
        out[key] = row
    return [out[key] for key in sorted(out, key=str)]


def _split_host_port(value: str) -> tuple[str, str]:
    raw = str(value or "").strip()
    if not raw:
        return "", ""
    if raw.startswith("["):
        end = raw.find("]")
        if end != -1:
            host = raw[1:end].strip()
            rest = raw[end + 1 :]
            if rest.startswith(":"):
                return host, rest[1:].strip()
            return host, ""
    if ":" in raw and raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        return host.strip(), port.strip()
    return raw, ""


def _reality_dest_host_for_inbound(
    *,
    selected_sni: str | None,
    inbound_reality_settings: dict | None,
    fallback_dest: str,
) -> str:
    if selected_sni:
        return selected_sni.strip()
    inbound_dest = ""
    if isinstance(inbound_reality_settings, dict):
        inbound_dest = str(inbound_reality_settings.get("dest") or "").strip()
    host, _ = _split_host_port(inbound_dest)
    if host:
        return host
    fallback_host, _ = _split_host_port(fallback_dest)
    return fallback_host


def _grouped_reality_tag(base_tag: str, group_id: str) -> str:
    base = str(base_tag or "").strip() or "reality-in"
    raw = str(group_id or "").strip().lower()
    suffix_chars: list[str] = []
    for ch in raw:
        if ch.isalnum() or ch in {"-", "_"}:
            suffix_chars.append(ch)
        else:
            suffix_chars.append("-")
    suffix = "".join(suffix_chars).strip("-")
    if not suffix:
        suffix = "group"
    return f"{base}-{suffix}"


def _safe_xray_tag_suffix(value: str) -> str:
    raw = str(value or "").strip().lower()
    chars: list[str] = []
    for ch in raw:
        chars.append(ch if ch.isalnum() or ch in {"-", "_"} else "-")
    suffix = "".join(chars).strip("-")
    return suffix or "path"


def _default_transit_target(settings: Settings) -> tuple[str, int]:
    return str(settings.default_transit_host or "").strip(), 443


def _selected_transit_path(row: dict) -> dict | None:
    cfg = row.get("config") if isinstance(row, dict) else None
    if not isinstance(cfg, dict):
        return None
    transit = cfg.get("transit")
    if not isinstance(transit, dict):
        return None
    selected = transit.get("selected_path")
    if not isinstance(selected, dict):
        return None
    name = str(selected.get("name") or "").strip()
    host = str(selected.get("host") or "").strip()
    try:
        port = int(selected.get("port") or 0)
    except Exception:
        port = 0
    if not name or not host or port <= 0:
        return None
    return {"name": name, "host": host, "port": port}


def _set_vless_outbound_target(outbound: dict, *, host: str, port: int) -> None:
    settings_block = outbound.get("settings")
    if not isinstance(settings_block, dict):
        return
    vnext = settings_block.get("vnext")
    if not isinstance(vnext, list):
        return
    for hop in vnext:
        if not isinstance(hop, dict):
            continue
        if host:
            hop["address"] = host
        hop["port"] = int(port)


def _strip_xray_entry_transit_backhaul(base: dict) -> None:
    outbounds = base.get("outbounds")
    if isinstance(outbounds, list):
        base["outbounds"] = [
            outbound
            for outbound in outbounds
            if not (
                isinstance(outbound, dict)
                and str(outbound.get("tag") or "").strip().startswith("to-transit")
            )
        ]

    routing = base.get("routing")
    if not isinstance(routing, dict):
        return
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return
    routing["rules"] = [
        rule
        for rule in rules
        if not (
            isinstance(rule, dict)
            and str(rule.get("outboundTag") or "").strip().startswith("to-transit")
        )
    ]


def _is_default_transit_rule(rule: dict, managed_reality_tags: set[str]) -> bool:
    if str(rule.get("outboundTag") or "").strip() != "to-transit":
        return False
    inbound_tags = rule.get("inboundTag")
    if not isinstance(inbound_tags, list):
        return False
    tags = {str(tag).strip() for tag in inbound_tags if str(tag).strip()}
    if not tags.intersection(managed_reality_tags):
        return False
    return not any(key in rule for key in ("domain", "ip", "port", "network", "protocol"))


def _apply_sticky_transit_routing(
    *,
    base: dict,
    assignments: list[tuple[str, dict]],
    managed_reality_tags: set[str],
) -> None:
    if not assignments or not managed_reality_tags:
        return

    outbounds = base.get("outbounds")
    if not isinstance(outbounds, list):
        return

    base_outbound = next(
        (
            outbound
            for outbound in outbounds
            if isinstance(outbound, dict) and str(outbound.get("tag") or "").strip() == "to-transit"
        ),
        None,
    )
    if not isinstance(base_outbound, dict):
        return

    path_by_tag: dict[str, dict] = {}
    users_by_tag: dict[str, set[str]] = {}
    for email, selected_path in assignments:
        user_email = str(email or "").strip()
        path_name = str(selected_path.get("name") or "").strip()
        host = str(selected_path.get("host") or "").strip()
        port = int(selected_path.get("port") or 0)
        if not user_email or not path_name or not host or port <= 0:
            continue
        tag = f"to-transit-{_safe_xray_tag_suffix(path_name)}"
        path_by_tag.setdefault(tag, {"host": host, "port": port})
        users_by_tag.setdefault(tag, set()).add(user_email)

    if not path_by_tag:
        return

    existing_tags = {str(outbound.get("tag") or "").strip() for outbound in outbounds if isinstance(outbound, dict)}
    for tag in sorted(path_by_tag, key=str):
        if tag in existing_tags:
            continue
        outbound = copy.deepcopy(base_outbound)
        outbound["tag"] = tag
        _set_vless_outbound_target(outbound, host=str(path_by_tag[tag]["host"]), port=int(path_by_tag[tag]["port"]))
        outbounds.append(outbound)

    routing = base.setdefault("routing", {})
    if not isinstance(routing, dict):
        return
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        return

    inbound_tags = sorted(managed_reality_tags, key=str)
    sticky_rules: list[dict] = []
    for tag in sorted(users_by_tag, key=str):
        users = sorted(users_by_tag[tag], key=str)
        if not users:
            continue
        sticky_rules.append(
            {
                "type": "field",
                "inboundTag": inbound_tags,
                "user": users,
                "outboundTag": tag,
            }
        )

    if not sticky_rules:
        return

    insert_at = len(rules)
    for idx, rule in enumerate(rules):
        if isinstance(rule, dict) and _is_default_transit_rule(rule, managed_reality_tags):
            insert_at = idx
            break
    rules[insert_at:insert_at] = sticky_rules


def _entry_v2_split_backend_enabled(settings: Settings) -> bool:
    return str(settings.agent_role or "").strip() == "ENTRY" and bool(
        settings.agent_entry_v2_split_backend_enabled
    )


def _load_reality_multi_inbound_groups(settings: Settings) -> list[RealityInboundGroup]:
    rows = settings.reality_multi_inbound_groups or []
    out: list[RealityInboundGroup] = []
    seen_ids: set[str] = set()
    seen_ports: set[int] = set()
    seen_snis: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        group_id = str(row.get("id") or "").strip().lower()
        if not group_id or group_id in seen_ids:
            continue
        try:
            port = int(row.get("port"))
        except Exception:
            continue
        if port <= 0 or port > 65535 or port in seen_ports:
            continue
        dest_host, _ = _split_host_port(str(row.get("dest") or "").strip().lower())
        if not dest_host:
            continue
        snis_raw = row.get("snis")
        if not isinstance(snis_raw, list):
            continue
        group_snis: list[str] = []
        local_seen: set[str] = set()
        for sni_raw in snis_raw:
            sni = str(sni_raw or "").strip().lower()
            if not sni or sni in local_seen:
                continue
            # First group that claims an SNI wins.
            if sni in seen_snis:
                continue
            local_seen.add(sni)
            seen_snis.add(sni)
            group_snis.append(sni)
        if not group_snis:
            continue
        seen_ids.add(group_id)
        seen_ports.add(port)
        out.append(
            RealityInboundGroup(
                id=group_id,
                port=port,
                dest_host=dest_host,
                snis=tuple(sorted(group_snis, key=str.lower)),
            )
        )
    out.sort(key=lambda g: (g.port, g.id))
    return out


def _is_managed_reality_inbound(*, inbound: dict, managed_reality_tags: set[str]) -> bool:
    tag = str(inbound.get("tag") or "").strip()
    stream = inbound.get("streamSettings") or {}
    is_reality = inbound.get("protocol") == "vless" and stream.get("security") == "reality"
    if not is_reality:
        return False
    if managed_reality_tags:
        return tag in managed_reality_tags
    return True


def _split_entry_v2_runtime_configs(
    *,
    settings: Settings,
    rendered: dict,
    managed_reality_tags: set[str],
) -> tuple[dict, dict | None]:
    if not _entry_v2_split_backend_enabled(settings):
        return rendered, None

    main = copy.deepcopy(rendered)
    v2 = copy.deepcopy(rendered)

    main_inbounds: list = []
    v2_inbounds: list = []
    for inbound in rendered.get("inbounds", []):
        if not isinstance(inbound, dict):
            main_inbounds.append(copy.deepcopy(inbound))
            continue
        if _is_managed_reality_inbound(inbound=inbound, managed_reality_tags=managed_reality_tags):
            v2_inbounds.append(copy.deepcopy(inbound))
        else:
            main_inbounds.append(copy.deepcopy(inbound))

    if not v2_inbounds:
        return rendered, None

    main["inbounds"] = main_inbounds
    v2["inbounds"] = v2_inbounds
    return main, v2


def _extend_reality_routing_tags(
    *,
    base: dict,
    extra_tags_by_source_tag: dict[str, list[str]],
) -> None:
    if not extra_tags_by_source_tag:
        return
    routing = base.get("routing")
    if not isinstance(routing, dict):
        return
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return

    normalized_extras: dict[str, list[str]] = {}
    for source_tag, extra_tags in extra_tags_by_source_tag.items():
        source = str(source_tag or "").strip()
        if not source:
            continue
        extras = sorted(
            set([str(tag).strip() for tag in (extra_tags or []) if str(tag).strip()]),
            key=str,
        )
        if extras:
            normalized_extras[source] = extras
    if not normalized_extras:
        return

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        inbound_tag = rule.get("inboundTag")
        if not isinstance(inbound_tag, list):
            continue
        tags = [str(tag).strip() for tag in inbound_tag if str(tag).strip()]
        if not tags:
            continue
        extras: set[str] = set()
        for source_tag, add_tags in normalized_extras.items():
            if source_tag in tags:
                extras.update(add_tags)
        if not extras:
            continue
        rule["inboundTag"] = sorted(set([*tags, *extras]), key=str)


def _empty_index() -> dict[str, dict[str, dict]]:
    return {"users": {}}


def _scan_user_artifacts(paths: AgentPaths) -> dict[str, dict]:
    if not paths.users_dir.exists():
        return {}
    artifacts: dict[str, dict] = {}
    for json_path in paths.users_dir.rglob("connection-*.json"):
        try:
            row = _load_json(json_path)
        except Exception:
            continue
        connection_id = str(row.get("connection_id") or "").strip()
        if not connection_id:
            continue
        artifacts[connection_id] = row
    return artifacts


def _index_path(paths: AgentPaths) -> Path:
    return paths.runtime / _INDEX_FILE_NAME


def _load_index(paths: AgentPaths) -> dict[str, dict[str, dict]] | None:
    path = _index_path(paths)
    if not path.exists():
        return None
    try:
        raw = _load_json(path)
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None

    users_raw = raw.get("users")
    users = users_raw if isinstance(users_raw, dict) else {}

    out = _empty_index()
    for key, value in users.items():
        key_s = str(key).strip()
        if not key_s or not isinstance(value, dict):
            continue
        out["users"][key_s] = value
    return out


def _save_index(paths: AgentPaths, index: dict[str, dict[str, dict]]) -> None:
    payload = {"users": dict(index.get("users") or {})}
    _safe_dump_json(_index_path(paths), payload)


def _rebuild_index(paths: AgentPaths) -> dict[str, dict[str, dict]]:
    rebuilt = _empty_index()
    rebuilt["users"] = _scan_user_artifacts(paths)
    _save_index(paths, rebuilt)
    return rebuilt


def _ensure_index(paths: AgentPaths) -> dict[str, dict[str, dict]]:
    loaded = _load_index(paths)
    if loaded is not None:
        return loaded
    return _rebuild_index(paths)


def load_all_user_artifacts(paths: AgentPaths) -> list[dict]:
    with _INDEX_LOCK:
        index = _ensure_index(paths)
        return [index["users"][key] for key in sorted(index["users"], key=str)]


def _artifact_applies_to_role(settings: Settings, row: dict) -> bool:
    role_raw = str(settings.agent_role or "").strip()
    if not role_raw:
        return True

    try:
        role = NodeRole(role_raw)
    except Exception:
        return True

    proto_raw = str(row.get("protocol") or "").strip().lower()
    variant_raw = str(row.get("variant") or "").strip()
    try:
        protocol = ConnectionProtocol(proto_raw)
        variant = ConnectionVariant(variant_raw)
    except Exception:
        role_target_raw = str(row.get("role_target") or "").strip()
        if role_target_raw:
            return role_target_raw == role.value
        return True

    return role in target_roles_for_connection(protocol, variant)


def _artifact_applies_to_xray_public_runtime(settings: Settings, row: dict) -> bool:
    role_raw = str(settings.agent_role or "").strip()
    try:
        role = NodeRole(role_raw)
    except Exception:
        return _artifact_applies_to_role(settings, row)

    proto_raw = str(row.get("protocol") or "").strip().lower()
    variant_raw = str(row.get("variant") or "").strip()
    try:
        protocol = ConnectionProtocol(proto_raw)
        variant = ConnectionVariant(variant_raw)
    except Exception:
        return _artifact_applies_to_role(settings, row)

    if protocol == ConnectionProtocol.VLESS_REALITY and variant == ConnectionVariant.V2:
        return role == NodeRole.ENTRY
    if protocol == ConnectionProtocol.HYSTERIA2 and variant == ConnectionVariant.V4:
        return role == NodeRole.ENTRY
    return _artifact_applies_to_role(settings, row)


def upsert_user_artifact_index(settings: Settings, payload: dict) -> None:
    connection_id = str(payload.get("connection_id") or "").strip()
    if not connection_id:
        return
    paths = AgentPaths.from_settings(settings)
    with _INDEX_LOCK:
        index = _ensure_index(paths)
        index["users"][connection_id] = payload
        _save_index(paths, index)


def remove_user_artifact_index(settings: Settings, user_id: str) -> None:
    user_id_str = str(user_id).strip()
    if not user_id_str:
        return
    paths = AgentPaths.from_settings(settings)
    with _INDEX_LOCK:
        index = _ensure_index(paths)
        keep: dict[str, dict] = {}
        for key, value in index["users"].items():
            if str(value.get("user_id") or "").strip() == user_id_str:
                continue
            keep[key] = value
        index["users"] = keep
        _save_index(paths, index)


def remove_connection_artifact_index(settings: Settings, connection_id: str) -> None:
    connection_id_str = str(connection_id).strip()
    if not connection_id_str:
        return
    paths = AgentPaths.from_settings(settings)
    with _INDEX_LOCK:
        index = _ensure_index(paths)
        index["users"].pop(connection_id_str, None)
        _save_index(paths, index)


def reconcile_xray(settings: Settings) -> ReconcileXrayResult:
    # Optional fast-path: if API mode is enabled, we still write the runtime config
    # for persistence across Xray restarts, but we apply user changes live via gRPC.
    sync_inbound_users = None
    if settings.agent_xray_api_enabled:
        from .xray_api import sync_inbound_users as _sync_inbound_users  # local import to keep agent startup lean

        sync_inbound_users = _sync_inbound_users

    contract = resolve_runtime_contract(settings.agent_runtime_profile)
    paths = AgentPaths.from_settings(settings)
    base_path = paths.base / "xray" / "config.json"
    runtime_path = paths.runtime / "xray" / "config.json"
    runtime_v2_path = paths.runtime / "xray-v2" / "config.json"
    if not base_path.exists():
        return ReconcileXrayResult(changed=False, force_reload=False)

    base = _load_json(base_path)
    artifacts = load_all_user_artifacts(paths)
    groups = _load_reality_multi_inbound_groups(settings)
    group_by_id = {g.id: g for g in groups}
    sni_to_group_id: dict[str, str] = {}
    for group in groups:
        for sni in group.snis:
            sni_to_group_id.setdefault(sni, group.id)

    clients_reality: list[dict] = []
    clients_reality_fallback: list[dict] = []
    clients_reality_by_group: dict[str, list[dict]] = {group.id: [] for group in groups}
    clients_ws: list[dict] = []
    clients_grpc: list[dict] = []
    xray_public_artifacts = [row for row in artifacts if _artifact_applies_to_xray_public_runtime(settings, row)]
    clients_hysteria_xray = build_hysteria_xray_clients(xray_public_artifacts)
    selected_reality_sni: str | None = None
    selected_reality_sni_ts = ""

    def _connection_marker(row: dict) -> str:
        # Keep marker stable across bot, node configs, and metrics.
        # Format: "V* - TG_ID - CONNECTION_ID"
        variant = str(row.get("variant") or "").strip() or "V?"
        user_id = str(row.get("user_id") or "").strip() or "?"
        connection_id = str(row.get("connection_id") or "").strip() or "?"
        return f"{variant} - {user_id} - {connection_id}"

    # Prefer a stable, pre-seeded REALITY SNI allow-list.
    # In grouped mode each inbound owns its own SNI list.
    server_names_legacy: set[str] = set([str(s).strip().lower() for s in (settings.sni_seed or []) if str(s).strip()])
    fallback_server_names: set[str] = set([str(s).strip().lower() for s in (settings.sni_seed or []) if str(s).strip()])
    group_server_names: dict[str, set[str]] = {
        group.id: set([str(s).strip().lower() for s in group.snis if str(s).strip()])
        for group in groups
    }
    if not groups:
        for row in load_catalog():
            if row.enabled and row.fqdn:
                server_names_legacy.add(row.fqdn.strip().lower())

    for row in artifacts:
        if not _artifact_applies_to_xray_public_runtime(settings, row):
            continue
        proto = (row.get("protocol") or "").strip().lower()
        if proto not in {"vless_reality", "vless_ws_tls", "vless_grpc_tls"}:
            continue
        cfg = row.get("config") or {}
        uuid = cfg.get("uuid")
        if not uuid:
            continue
        if proto == "vless_reality":
            sni = (cfg.get("sni") or "").strip().lower()
            if sni:
                if groups:
                    group_id = sni_to_group_id.get(sni)
                    if group_id:
                        group_server_names.setdefault(group_id, set()).add(sni)
                    else:
                        fallback_server_names.add(sni)
                else:
                    server_names_legacy.add(sni)
                    op_ts = str(row.get("op_ts") or "").strip()
                    if selected_reality_sni is None:
                        selected_reality_sni = sni
                        selected_reality_sni_ts = op_ts
                    elif op_ts and (not selected_reality_sni_ts or op_ts > selected_reality_sni_ts):
                        selected_reality_sni = sni
                        selected_reality_sni_ts = op_ts

            client_row = {
                "id": uuid,
                "email": _connection_marker(row),
            }
            if groups and sni:
                group_id = sni_to_group_id.get(sni)
                if group_id:
                    clients_reality_by_group.setdefault(group_id, []).append(client_row)
                else:
                    clients_reality_fallback.append(client_row)
            elif groups:
                clients_reality_fallback.append(client_row)
            else:
                clients_reality.append(client_row)
        elif proto == "vless_ws_tls":
            clients_ws.append(
                {
                    "id": uuid,
                    "email": _connection_marker(row),
                }
            )
        else:
            clients_grpc.append(
                {
                    "id": uuid,
                    "email": _connection_marker(row),
                }
            )

    # Stable ordering for deterministic diffs.
    clients_reality.sort(key=lambda c: str(c.get("id") or ""))
    clients_reality_fallback.sort(key=lambda c: str(c.get("id") or ""))
    for bucket in clients_reality_by_group.values():
        bucket.sort(key=lambda c: str(c.get("id") or ""))
    clients_ws.sort(key=lambda c: str(c.get("id") or ""))
    clients_grpc.sort(key=lambda c: str(c.get("id") or ""))

    inbounds = base.get("inbounds", [])
    if not isinstance(inbounds, list):
        inbounds = []
        base["inbounds"] = inbounds
    managed_reality_tags = {"vless-reality-in", "entry-in"}
    managed_ws_tags = {"vless-ws-in"}
    managed_grpc_tags = {"vless-grpc-in"}
    has_tagged_reality = any(str((row or {}).get("tag") or "").strip() in managed_reality_tags for row in inbounds)
    has_tagged_ws = any(str((row or {}).get("tag") or "").strip() in managed_ws_tags for row in inbounds)
    has_tagged_grpc = any(str((row or {}).get("tag") or "").strip() in managed_grpc_tags for row in inbounds)

    managed_reality_base_tags: set[str] = set()
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        tag = str(inbound.get("tag") or "").strip()
        stream = inbound.get("streamSettings") or {}
        is_reality = inbound.get("protocol") == "vless" and stream.get("security") == "reality"
        should_manage_reality = (tag in managed_reality_tags) if has_tagged_reality else is_reality
        if is_reality and should_manage_reality:
            managed_reality_base_tags.add(tag)

    group_tag_to_group_id: dict[str, str] = {}
    group_tags_by_base_tag: dict[str, list[str]] = {}
    if groups:
        expanded_inbounds: list[dict] = []
        expected_group_tags = {
            _grouped_reality_tag(base_tag, group.id)
            for base_tag in managed_reality_base_tags
            for group in groups
        }
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                expanded_inbounds.append(inbound)
                continue
            tag = str(inbound.get("tag") or "").strip()
            if tag in expected_group_tags:
                continue
            expanded_inbounds.append(inbound)
            stream = inbound.get("streamSettings") or {}
            is_reality = inbound.get("protocol") == "vless" and stream.get("security") == "reality"
            should_manage_reality = (tag in managed_reality_tags) if has_tagged_reality else is_reality
            if not (is_reality and should_manage_reality):
                continue
            for group in groups:
                clone = copy.deepcopy(inbound)
                clone_tag = _grouped_reality_tag(tag, group.id)
                clone["tag"] = clone_tag
                clone["port"] = int(group.port)
                expanded_inbounds.append(clone)
                group_tag_to_group_id[clone_tag] = group.id
                group_tags_by_base_tag.setdefault(tag, []).append(clone_tag)
        inbounds = expanded_inbounds
        base["inbounds"] = inbounds
        _extend_reality_routing_tags(base=base, extra_tags_by_source_tag=group_tags_by_base_tag)

    managed_reality_runtime_tags = set(managed_reality_base_tags)
    managed_reality_runtime_tags.update(group_tag_to_group_id.keys())

    desired_by_tag: dict[str, dict[str, dict[str, str]]] = {}

    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        tag = str(inbound.get("tag") or "").strip()
        stream = inbound.get("streamSettings") or {}
        is_reality = inbound.get("protocol") == "vless" and stream.get("security") == "reality"
        should_manage_reality = (tag in managed_reality_runtime_tags) if managed_reality_runtime_tags else is_reality
        if is_reality:
            if not should_manage_reality:
                continue
            group_id = group_tag_to_group_id.get(tag)
            if groups:
                if group_id:
                    dynamic_clients = clients_reality_by_group.get(group_id, [])
                    target_server_names = set(group_server_names.get(group_id) or [])
                elif tag in managed_reality_base_tags:
                    dynamic_clients = clients_reality_fallback
                    target_server_names = set(fallback_server_names)
                else:
                    dynamic_clients = []
                    target_server_names = set()
            else:
                dynamic_clients = clients_reality
                target_server_names = set(server_names_legacy)

            inbound_settings = inbound.setdefault("settings", {})
            merged_clients = _merge_clients(
                inbound_settings.get("clients") if isinstance(inbound_settings.get("clients"), list) else [],
                dynamic_clients,
            )
            inbound.setdefault("settings", {})["clients"] = merged_clients

            stream = inbound.setdefault("streamSettings", {})
            reality = stream.setdefault("realitySettings", {})
            existing = reality.get("serverNames") or []
            if not isinstance(existing, list):
                existing = []
            if groups and group_id:
                merged_server_names = sorted(set(target_server_names), key=str.lower)
            else:
                merged_server_names = sorted(
                    set([*existing, *target_server_names]),
                    key=lambda s: str(s).lower(),
                )
            if merged_server_names:
                reality["serverNames"] = merged_server_names

            if groups and group_id:
                group = group_by_id.get(group_id)
                if group is not None:
                    reality["dest"] = f"{group.dest_host}:443"
            else:
                dest_host = _reality_dest_host_for_inbound(
                    selected_sni=None if groups else selected_reality_sni,
                    inbound_reality_settings=reality,
                    fallback_dest=settings.reality_dest,
                )
                if dest_host:
                    reality["dest"] = f"{dest_host}:443"

            if tag:
                desired: dict[str, dict[str, str]] = {}
                for row in merged_clients:
                    if not isinstance(row, dict):
                        continue
                    email = str(row.get("email") or "").strip()
                    client_id = str(row.get("id") or "").strip()
                    if email and client_id:
                        desired[email] = {"protocol": "vless", "uuid": client_id}
                desired_by_tag[tag] = desired
            continue

        # VLESS over WebSocket (with or without TLS termination upstream).
        is_ws = inbound.get("protocol") == "vless" and str((stream.get("network") or "")).lower() == "ws"
        if is_ws:
            should_manage_ws = (tag in managed_ws_tags) if has_tagged_ws else True
            if not should_manage_ws:
                continue
            inbound_settings = inbound.setdefault("settings", {})
            merged_clients = _merge_clients(
                inbound_settings.get("clients") if isinstance(inbound_settings.get("clients"), list) else [],
                clients_ws,
            )
            inbound.setdefault("settings", {})["clients"] = merged_clients

            if tag:
                desired: dict[str, dict[str, str]] = {}
                for row in merged_clients:
                    if not isinstance(row, dict):
                        continue
                    email = str(row.get("email") or "").strip()
                    client_id = str(row.get("id") or "").strip()
                    if email and client_id:
                        desired[email] = {"protocol": "vless", "uuid": client_id}
                desired_by_tag[tag] = desired
            continue

        # VLESS over gRPC (with TLS termination upstream).
        is_grpc = inbound.get("protocol") == "vless" and str((stream.get("network") or "")).lower() == "grpc"
        if is_grpc:
            should_manage_grpc = (tag in managed_grpc_tags) if has_tagged_grpc else True
            if not should_manage_grpc:
                continue
            inbound_settings = inbound.setdefault("settings", {})
            merged_clients = _merge_clients(
                inbound_settings.get("clients") if isinstance(inbound_settings.get("clients"), list) else [],
                clients_grpc,
            )
            inbound.setdefault("settings", {})["clients"] = merged_clients

            if tag:
                desired: dict[str, dict[str, str]] = {}
                for row in merged_clients:
                    if not isinstance(row, dict):
                        continue
                    email = str(row.get("email") or "").strip()
                    client_id = str(row.get("id") or "").strip()
                    if email and client_id:
                        desired[email] = {"protocol": "vless", "uuid": client_id}
                desired_by_tag[tag] = desired
            continue

        is_hysteria = str(inbound.get("protocol") or "").strip().lower() == "hysteria"
        if is_hysteria:
            inbound_settings = inbound.setdefault("settings", {})
            merged_clients = _merge_hysteria_clients(
                inbound_settings.get("clients") if isinstance(inbound_settings.get("clients"), list) else [],
                clients_hysteria_xray,
            )
            inbound_settings["clients"] = merged_clients
            if tag:
                desired: dict[str, dict[str, str]] = {}
                for row in merged_clients:
                    if not isinstance(row, dict):
                        continue
                    email = str(row.get("email") or "").strip()
                    auth = str(row.get("auth") or "").strip()
                    if email and auth:
                        desired[email] = {"protocol": "hysteria", "auth": auth}
                desired_by_tag[tag] = desired

    if contract.xray_backhaul_allowed:
        outbounds = base.get("outbounds", [])
        transit_host, transit_port = _default_transit_target(settings)
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            if str(outbound.get("tag") or "").strip() != "to-transit":
                continue
            if str(outbound.get("protocol") or "").strip().lower() != "vless":
                continue
            _set_vless_outbound_target(outbound, host=transit_host, port=transit_port)
    else:
        _strip_xray_entry_transit_backhaul(base)

    main_runtime, v2_runtime = _split_entry_v2_runtime_configs(
        settings=settings,
        rendered=base,
        managed_reality_tags=managed_reality_runtime_tags,
    )

    # Only write when there is a real change; otherwise we trigger unnecessary reloads.
    current = _load_json(runtime_path) if runtime_path.exists() else None
    should_write = current != main_runtime
    force_reload = _xray_structural_reload_required(current, main_runtime) if should_write else False

    if should_write:
        _safe_dump_json(runtime_path, main_runtime)

    should_write_v2 = False
    if v2_runtime is not None:
        current_v2 = _load_json(runtime_v2_path) if runtime_v2_path.exists() else None
        should_write_v2 = current_v2 != v2_runtime
        if should_write_v2:
            force_reload = force_reload or _xray_structural_reload_required(current_v2, v2_runtime)
        if should_write_v2:
            _safe_dump_json(runtime_v2_path, v2_runtime)
    elif runtime_v2_path.exists():
        runtime_v2_path.unlink()
        should_write_v2 = True
        force_reload = True

    if settings.agent_xray_api_enabled and sync_inbound_users is not None:
        # Apply user changes live without restarting Xray.
        main_inbound_tags = {
            str(row.get("tag") or "").strip()
            for row in (main_runtime.get("inbounds") or [])
            if isinstance(row, dict)
        }
        for tag, desired in desired_by_tag.items():
            if tag not in main_inbound_tags:
                continue
            sync_inbound_users(settings, inbound_tag=tag, desired_email_to_user=desired)

    return ReconcileXrayResult(changed=should_write or should_write_v2, force_reload=force_reload)


def _reconcile_passthrough_component(
    *,
    settings: Settings,
    component: str,
    source_name: str,
) -> bool:
    paths = AgentPaths.from_settings(settings)
    base_path = paths.base / component / source_name
    runtime_path = paths.runtime / component / source_name
    if not base_path.exists():
        return False

    desired = base_path.read_text(encoding="utf-8")
    current = runtime_path.read_text(encoding="utf-8") if runtime_path.exists() else None
    if current == desired:
        return False

    _safe_dump_text(runtime_path, desired)
    return True


def _file_fingerprint(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {
        "sizeBytes": int(stat.st_size),
        "mtimeNs": int(stat.st_mtime_ns),
    }


def _k3s_private_marker_matches_source(marker: dict, *, component: str, role_upper: str, state_path: Path, env_path: Path) -> bool:
    if marker.get("schema") != _K3S_PRIVATE_RELOAD_MARKER_SCHEMA:
        return False
    if marker.get("summarySchema") != _K3S_PRIVATE_RELOAD_SUMMARY_SCHEMA:
        return False
    if marker.get("component") != component:
        return False
    if marker.get("role") != role_upper:
        return False
    summary = marker.get("summary")
    if not isinstance(summary, dict):
        return False
    sources = summary.get("sources")
    if not isinstance(sources, dict):
        return False
    state_source = sources.get("state")
    env_source = sources.get("env")
    if not isinstance(state_source, dict) or not isinstance(env_source, dict):
        return False
    return state_source == _file_fingerprint(state_path) and env_source == _file_fingerprint(env_path)


def _k3s_private_reload_marker_stale(settings: Settings, *, component: str) -> bool:
    if str(settings.agent_runtime_mode or "").strip().lower() != "kubernetes":
        return False
    role_lower = str(settings.agent_role or "").strip().lower()
    if role_lower not in {"entry", "transit"}:
        return False
    role_upper = role_lower.upper()
    component_dir = {"profiles": "profiles", "link-crypto": "link-crypto"}.get(component)
    if not component_dir:
        return False
    private_root = Path(effective_private_runtime_root(settings))
    state_path = private_root / component_dir / role_lower / "desired-state.json"
    env_path = private_root / component_dir / role_lower / "desired-state.env"
    marker_path = private_root / "runtime" / f"{component}-{role_lower}-last-reload.json"
    if not state_path.exists():
        return False
    if not marker_path.exists() or not env_path.exists():
        return True
    try:
        marker_mtime_ns = marker_path.stat().st_mtime_ns
        state_mtime_ns = state_path.stat().st_mtime_ns
        env_mtime_ns = env_path.stat().st_mtime_ns
        marker_payload = _load_json(marker_path)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return True
    if state_mtime_ns > marker_mtime_ns or env_mtime_ns > marker_mtime_ns:
        return True
    return not _k3s_private_marker_matches_source(
        marker_payload,
        component=component,
        role_upper=role_upper,
        state_path=state_path,
        env_path=env_path,
    )


def _reconcile_all_result(settings: Settings) -> ReconcileAllResult:
    contract = resolve_runtime_contract(settings.agent_runtime_profile)
    paths = AgentPaths.from_settings(settings)
    changed: list[str] = []
    force_xray_reload = False
    if contract.manages_component("xray"):
        xray_result = reconcile_xray(settings)
        if xray_result.changed:
            changed.append("xray")
        force_xray_reload = xray_result.force_reload
    if settings.agent_role in {"TRANSIT", "ENTRY"}:
        if contract.manages_component("haproxy") and _reconcile_passthrough_component(
            settings=settings, component="haproxy", source_name="haproxy.cfg"
        ):
            changed.append("haproxy")
        if contract.manages_component("nginx") and _reconcile_passthrough_component(
            settings=settings, component="nginx", source_name="nginx.conf"
        ):
            changed.append("nginx")
        if reconcile_decoy(settings):
            changed.append("decoy")

    _cleanup_unmanaged_runtime_state(settings)
    runtime_contract_changed, runtime_contract_payload = _write_runtime_contract_state(settings)
    private_user_artifacts = [row for row in load_all_user_artifacts(paths) if _artifact_applies_to_role(settings, row)]
    private_handoffs_changed = write_private_runtime_handoffs(
        settings,
        runtime_contract_path=_runtime_contract_path(paths),
        runtime_contract_payload=runtime_contract_payload,
        user_artifacts=private_user_artifacts,
    )
    if runtime_contract_changed:
        if str(settings.agent_reload_obfuscation_cmd or "").strip():
            changed.append("obfuscation")
        if str(settings.agent_reload_mtproto_cmd or "").strip():
            changed.append("mtproto")
        if str(settings.agent_reload_fronting_cmd or "").strip():
            changed.append("fronting")
        if str(settings.agent_reload_link_crypto_cmd or "").strip():
            changed.append("link-crypto")
    for component, command in (
        ("obfuscation", str(settings.agent_reload_obfuscation_cmd or "").strip()),
        ("mtproto", str(settings.agent_reload_mtproto_cmd or "").strip()),
        ("fronting", str(settings.agent_reload_fronting_cmd or "").strip()),
        ("profiles", str(settings.agent_reload_profiles_cmd or "").strip()),
        ("link-crypto", str(settings.agent_reload_link_crypto_cmd or "").strip()),
    ):
        marker_stale = _k3s_private_reload_marker_stale(settings, component=component)
        if (component in private_handoffs_changed or marker_stale) and command and component not in changed:
            changed.append(component)
    return ReconcileAllResult(changed=changed, force_xray_reload=force_xray_reload)


def reconcile_all(settings: Settings) -> list[str]:
    return _reconcile_all_result(settings).changed
