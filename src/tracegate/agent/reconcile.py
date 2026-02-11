from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from tracegate.settings import Settings


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


def load_all_user_artifacts(paths: AgentPaths) -> list[dict]:
    if not paths.users_dir.exists():
        return []
    artifacts: list[dict] = []
    for json_path in paths.users_dir.rglob("connection-*.json"):
        try:
            artifacts.append(_load_json(json_path))
        except Exception:
            continue
    return artifacts


def load_all_wg_peer_artifacts(paths: AgentPaths) -> list[dict]:
    if not paths.wg_peers_dir.exists():
        return []
    artifacts: list[dict] = []
    for json_path in paths.wg_peers_dir.glob("peer-*.json"):
        try:
            artifacts.append(_load_json(json_path))
        except Exception:
            continue
    return artifacts


def reconcile_xray(settings: Settings) -> bool:
    paths = AgentPaths.from_settings(settings)
    base_path = paths.base / "xray" / "config.json"
    runtime_path = paths.runtime / "xray" / "config.json"
    if not base_path.exists():
        return False

    base = _load_json(base_path)
    artifacts = load_all_user_artifacts(paths)
    clients_reality: list[dict] = []
    clients_ws: list[dict] = []
    server_names: set[str] = set()
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

    for inbound in base.get("inbounds", []):
        stream = inbound.get("streamSettings") or {}
        is_reality = inbound.get("tag") == "vless-reality-in" or (
            inbound.get("protocol") == "vless" and stream.get("security") == "reality"
        )
        if is_reality:
            inbound.setdefault("settings", {})["clients"] = clients_reality
            if server_names:
                stream = inbound.setdefault("streamSettings", {})
                reality = stream.setdefault("realitySettings", {})
                existing = reality.get("serverNames") or []
                if not isinstance(existing, list):
                    existing = []
                merged = sorted(set([*existing, *server_names]), key=lambda s: str(s).lower())
                reality["serverNames"] = merged
            continue

        # VLESS over WebSocket (with or without TLS termination upstream).
        is_ws = inbound.get("protocol") == "vless" and str((stream.get("network") or "")).lower() == "ws"
        if is_ws:
            inbound.setdefault("settings", {})["clients"] = clients_ws

    # Only write when there is a real change; otherwise we trigger unnecessary reloads.
    current = _load_json(runtime_path) if runtime_path.exists() else None
    if current == base:
        return False

    _safe_dump_json(runtime_path, base)
    return True


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
    if settings.agent_role == "VPS_T":
        if reconcile_xray(settings):
            changed.append("xray")
        if reconcile_hysteria(settings):
            changed.append("hysteria")
        if reconcile_wireguard(settings):
            changed.append("wireguard")
    else:
        # VPS-E in v0.1 can be an L4 forwarder; no runtime proxy configs required.
        pass

    return changed
