from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
import threading

import yaml

from tracegate.enums import ConnectionProtocol, ConnectionVariant, NodeRole
from tracegate.services.role_targeting import target_roles_for_connection
from tracegate.settings import Settings
from tracegate.services.sni_catalog import load_catalog

_INDEX_FILE_NAME = "artifact-index.json"
_INDEX_LOCK = threading.Lock()


@dataclass(frozen=True)
class AgentPaths:
    root: Path
    base: Path
    runtime: Path
    users_dir: Path
    wg_peers_dir: Path

    @staticmethod
    def from_settings(settings: Settings) -> "AgentPaths":
        root = Path(settings.agent_data_root)
        return AgentPaths(
            root=root,
            base=root / "base",
            runtime=root / "runtime",
            users_dir=root / "users",
            wg_peers_dir=root / "wg-peers",
        )


@dataclass(frozen=True)
class RealityInboundGroup:
    id: str
    port: int
    dest_host: str
    snis: tuple[str, ...]


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
    return {"users": {}, "wg_peers": {}}


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


def _scan_wg_peer_artifacts(paths: AgentPaths) -> dict[str, dict]:
    if not paths.wg_peers_dir.exists():
        return {}
    artifacts: dict[str, dict] = {}
    for json_path in paths.wg_peers_dir.glob("peer-*.json"):
        key = json_path.stem.replace("peer-", "", 1).strip()
        if not key:
            continue
        try:
            row = _load_json(json_path)
        except Exception:
            continue
        artifacts[key] = row
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
    wg_raw = raw.get("wg_peers")
    users = users_raw if isinstance(users_raw, dict) else {}
    wg_peers = wg_raw if isinstance(wg_raw, dict) else {}

    out = _empty_index()
    for key, value in users.items():
        key_s = str(key).strip()
        if not key_s or not isinstance(value, dict):
            continue
        out["users"][key_s] = value
    for key, value in wg_peers.items():
        key_s = str(key).strip()
        if not key_s or not isinstance(value, dict):
            continue
        out["wg_peers"][key_s] = value
    return out


def _save_index(paths: AgentPaths, index: dict[str, dict[str, dict]]) -> None:
    payload = {
        "users": dict(index.get("users") or {}),
        "wg_peers": dict(index.get("wg_peers") or {}),
    }
    _safe_dump_json(_index_path(paths), payload)


def _rebuild_index(paths: AgentPaths) -> dict[str, dict[str, dict]]:
    rebuilt = _empty_index()
    rebuilt["users"] = _scan_user_artifacts(paths)
    rebuilt["wg_peers"] = _scan_wg_peer_artifacts(paths)
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


def load_all_wg_peer_artifacts(paths: AgentPaths) -> list[dict]:
    with _INDEX_LOCK:
        index = _ensure_index(paths)
        return [index["wg_peers"][key] for key in sorted(index["wg_peers"], key=str)]


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


def upsert_wg_peer_artifact_index(settings: Settings, *, peer_key: str, payload: dict) -> None:
    key = str(peer_key).strip()
    if not key:
        return
    paths = AgentPaths.from_settings(settings)
    with _INDEX_LOCK:
        index = _ensure_index(paths)
        index["wg_peers"][key] = payload
        _save_index(paths, index)


def remove_wg_peer_artifact_index(settings: Settings, *, peer_key: str) -> None:
    key = str(peer_key).strip()
    if not key:
        return
    paths = AgentPaths.from_settings(settings)
    with _INDEX_LOCK:
        index = _ensure_index(paths)
        index["wg_peers"].pop(key, None)
        _save_index(paths, index)


def reconcile_xray(settings: Settings) -> bool:
    # Optional fast-path: if API mode is enabled, we still write the runtime config
    # for persistence across Xray restarts, but we apply user changes live via gRPC.
    from .xray_api import sync_inbound_users  # local import to keep agent startup lean

    paths = AgentPaths.from_settings(settings)
    base_path = paths.base / "xray" / "config.json"
    runtime_path = paths.runtime / "xray" / "config.json"
    if not base_path.exists():
        return False

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
    selected_reality_sni: str | None = None
    selected_reality_sni_ts = ""

    def _connection_marker(row: dict) -> str:
        # Keep marker stable across bot, node configs, and metrics.
        # Format: "B* - TG_ID - CONNECTION_ID"
        variant = str(row.get("variant") or "").strip() or "B?"
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
        if not _artifact_applies_to_role(settings, row):
            continue
        proto = (row.get("protocol") or "").strip().lower()
        if proto not in {"vless_reality", "vless_ws_tls"}:
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
        else:
            clients_ws.append(
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

    inbounds = base.get("inbounds", [])
    if not isinstance(inbounds, list):
        inbounds = []
        base["inbounds"] = inbounds
    managed_reality_tags = {"vless-reality-in", "entry-in"}
    managed_ws_tags = {"vless-ws-in"}
    has_tagged_reality = any(str((row or {}).get("tag") or "").strip() in managed_reality_tags for row in inbounds)
    has_tagged_ws = any(str((row or {}).get("tag") or "").strip() in managed_ws_tags for row in inbounds)

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
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                expanded_inbounds.append(inbound)
                continue
            expanded_inbounds.append(inbound)
            tag = str(inbound.get("tag") or "").strip()
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

    desired_by_tag: dict[str, dict[str, str]] = {}

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
                desired: dict[str, str] = {}
                for row in merged_clients:
                    if not isinstance(row, dict):
                        continue
                    email = str(row.get("email") or "").strip()
                    client_id = str(row.get("id") or "").strip()
                    if email and client_id:
                        desired[email] = client_id
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
                desired: dict[str, str] = {}
                for row in merged_clients:
                    if not isinstance(row, dict):
                        continue
                    email = str(row.get("email") or "").strip()
                    client_id = str(row.get("id") or "").strip()
                    if email and client_id:
                        desired[email] = client_id
                desired_by_tag[tag] = desired

    # Transport invariant: VPS-E -> VPS-T chain leg must always use tcp/443.
    outbounds = base.get("outbounds", [])
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        if str(outbound.get("tag") or "").strip() != "to-transit":
            continue
        if str(outbound.get("protocol") or "").strip().lower() != "vless":
            continue
        settings_block = outbound.get("settings")
        if not isinstance(settings_block, dict):
            continue
        vnext = settings_block.get("vnext")
        if not isinstance(vnext, list):
            continue
        for hop in vnext:
            if isinstance(hop, dict):
                hop["port"] = 443

    # Only write when there is a real change; otherwise we trigger unnecessary reloads.
    current = _load_json(runtime_path) if runtime_path.exists() else None
    should_write = current != base

    if should_write:
        _safe_dump_json(runtime_path, base)

    if settings.agent_xray_api_enabled:
        # Apply user changes live without restarting Xray.
        for tag, desired in desired_by_tag.items():
            sync_inbound_users(settings, inbound_tag=tag, desired_email_to_uuid=desired)

    return should_write


def reconcile_hysteria(settings: Settings) -> bool:
    paths = AgentPaths.from_settings(settings)
    base_path = paths.base / "hysteria" / "config.yaml"
    runtime_path = paths.runtime / "hysteria" / "config.yaml"
    if not base_path.exists():
        return False

    base = _load_yaml(base_path)
    artifacts = load_all_user_artifacts(paths)

    userpass: dict[str, str] = {}
    auth = base.get("auth") or {}
    if auth.get("type") == "userpass":
        userpass = (auth.get("userpass") or {}) if isinstance(auth.get("userpass"), dict) else {}

    for row in artifacts:
        if row.get("protocol") != "hysteria2":
            continue
        cfg = row.get("config") or {}
        auth_cfg = cfg.get("auth") or {}
        if auth_cfg.get("type") != "userpass":
            continue
        username = (auth_cfg.get("username") or "").strip()
        password = (auth_cfg.get("password") or "").strip()
        if not username or not password:
            continue
        userpass[username] = password

    base["auth"] = {"type": "userpass", "userpass": userpass}
    current = _load_yaml(runtime_path) if runtime_path.exists() else None
    if current == base:
        return False

    _safe_dump_text(runtime_path, yaml.safe_dump(base, sort_keys=False))
    return True


def reconcile_wireguard(settings: Settings) -> bool:
    if settings.agent_role != "VPS_T":
        return False

    paths = AgentPaths.from_settings(settings)
    base_path = paths.base / "wireguard" / "wg0.conf"
    runtime_path = paths.runtime / "wireguard" / "wg0.conf"
    if not base_path.exists():
        return False

    base_text = base_path.read_text(encoding="utf-8").strip() + "\n"
    interface_lines: list[str] = []
    for line in base_text.splitlines():
        if line.strip().startswith("[Peer]"):
            break
        interface_lines.append(line)
    out = "\n".join(interface_lines).rstrip() + "\n\n"

    artifacts = load_all_wg_peer_artifacts(paths)
    peers: list[tuple[str, str | None, str]] = []
    for row in artifacts:
        peer_public_key = (row.get("peer_public_key") or "").strip()
        peer_ip = (row.get("peer_ip") or "").strip()
        if not peer_public_key or not peer_ip:
            continue
        psk = (row.get("preshared_key") or "").strip() or None
        peers.append((peer_public_key, psk, peer_ip))

    peers.sort(key=lambda t: (t[2], t[0]))
    for pub, psk, ip in peers:
        out += "[Peer]\n"
        out += f"PublicKey = {pub}\n"
        if psk:
            out += f"PresharedKey = {psk}\n"
        out += f"AllowedIPs = {ip}/32\n\n"

    current_text = runtime_path.read_text(encoding="utf-8") if runtime_path.exists() else None
    if current_text == out:
        return False

    _safe_dump_text(runtime_path, out)
    return True


def reconcile_all(settings: Settings) -> list[str]:
    changed: list[str] = []
    if reconcile_xray(settings):
        changed.append("xray")
    if settings.agent_role in {"VPS_T", "VPS_E"}:
        if reconcile_hysteria(settings):
            changed.append("hysteria")
    if settings.agent_role == "VPS_T":
        if reconcile_wireguard(settings):
            changed.append("wireguard")

    return changed
