from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
import threading

import yaml

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
    clients_reality: list[dict] = []
    clients_ws: list[dict] = []
    # Prefer a stable, pre-seeded REALITY SNI allow-list to avoid server restarts
    # when users issue a new revision with a different camouflage SNI.
    server_names: set[str] = set([str(s).strip() for s in (settings.sni_seed or []) if str(s).strip()])
    for row in load_catalog():
        if row.enabled and row.fqdn:
            server_names.add(row.fqdn)
    for row in artifacts:
        proto = (row.get("protocol") or "").strip().lower()
        if proto not in {"vless_reality", "vless_ws_tls"}:
            continue
        cfg = row.get("config") or {}
        uuid = cfg.get("uuid")
        if not uuid:
            continue
        if proto == "vless_reality":
            sni = (cfg.get("sni") or "").strip()
            if sni:
                server_names.add(sni)
            clients_reality.append(
                {
                    "id": uuid,
                    "email": f"{row.get('user_id')}:{row.get('connection_id')}",
                }
            )
        else:
            clients_ws.append(
                {
                    "id": uuid,
                    "email": f"{row.get('user_id')}:{row.get('connection_id')}",
                }
            )

    # Stable ordering for deterministic diffs.
    clients_reality.sort(key=lambda c: str(c.get("id") or ""))
    clients_ws.sort(key=lambda c: str(c.get("id") or ""))

    inbounds = base.get("inbounds", [])
    managed_reality_tags = {"vless-reality-in", "entry-in"}
    managed_ws_tags = {"vless-ws-in"}
    has_tagged_reality = any(str((row or {}).get("tag") or "").strip() in managed_reality_tags for row in inbounds)
    has_tagged_ws = any(str((row or {}).get("tag") or "").strip() in managed_ws_tags for row in inbounds)

    desired_by_tag: dict[str, dict[str, str]] = {}

    for inbound in inbounds:
        tag = str(inbound.get("tag") or "").strip()
        stream = inbound.get("streamSettings") or {}
        is_reality = inbound.get("protocol") == "vless" and stream.get("security") == "reality"
        should_manage_reality = (tag in managed_reality_tags) if has_tagged_reality else is_reality
        if is_reality:
            if not should_manage_reality:
                continue
            inbound_settings = inbound.setdefault("settings", {})
            merged_clients = _merge_clients(
                inbound_settings.get("clients") if isinstance(inbound_settings.get("clients"), list) else [],
                clients_reality,
            )
            inbound.setdefault("settings", {})["clients"] = merged_clients
            if server_names:
                stream = inbound.setdefault("streamSettings", {})
                reality = stream.setdefault("realitySettings", {})
                existing = reality.get("serverNames") or []
                if not isinstance(existing, list):
                    existing = []
                merged = sorted(set([*existing, *server_names]), key=lambda s: str(s).lower())
                reality["serverNames"] = merged

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
    if settings.agent_role == "VPS_T":
        if reconcile_hysteria(settings):
            changed.append("hysteria")
        if reconcile_wireguard(settings):
            changed.append("wireguard")

    return changed
