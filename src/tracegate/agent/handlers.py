from __future__ import annotations

import json
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tracegate.enums import OutboxEventType
from tracegate.settings import Settings

from .system import apply_files, run_command
from .reconcile import (
    reconcile_all,
    remove_connection_artifact_index,
    remove_user_artifact_index,
    remove_wg_peer_artifact_index,
    upsert_user_artifact_index,
    upsert_wg_peer_artifact_index,
)


class HandlerError(RuntimeError):
    pass


_RELOAD_LOCK = threading.Lock()


def _parse_ts(value: Any) -> datetime | None:
    """
    Parse an ISO8601 timestamp (best-effort).

    Used to make state application robust against out-of-order delivery.
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _payload_ts(payload: dict[str, Any]) -> datetime | None:
    # Prefer explicit op_ts, fall back to older field names for compatibility.
    return _parse_ts(payload.get("op_ts") or payload.get("revision_created_at") or payload.get("revoked_at"))


def _tombstones_dir(settings: Settings) -> Path:
    root = Path(settings.agent_data_root)
    return root / "runtime" / "tombstones"


def _tombstone_path(settings: Settings, *, kind: str, key: str) -> Path:
    safe_kind = str(kind).strip() or "unknown"
    safe_key = str(key).strip() or "missing"
    return _tombstones_dir(settings) / f"{safe_kind}-{safe_key}.json"


def _read_tombstone_ts(path: Path) -> datetime | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return _parse_ts(data.get("op_ts") or data.get("revoked_at") or data.get("created_at"))


def _write_tombstone(path: Path, *, ts: datetime, extra: dict[str, Any] | None = None) -> None:
    payload: dict[str, Any] = {"op_ts": ts.isoformat()}
    if extra:
        payload.update({k: v for (k, v) in extra.items() if v is not None})
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _user_dir(root: Path, user_id: str) -> Path:
    return root / "users" / user_id


def _run_reload_commands(settings: Settings, commands: list[str]) -> None:
    failures: list[str] = []
    # Serialize reload hooks so concurrent event handlers never drop a pending Xray apply.
    with _RELOAD_LOCK:
        for cmd in commands:
            if not cmd:
                continue
            ok, out = run_command(cmd, settings.agent_dry_run)
            if ok:
                continue
            details = (out or "").strip() or "no output"
            if len(details) > 400:
                details = details[:400].rstrip() + "..."
            failures.append(f"{cmd}: {details}")
    if failures:
        raise HandlerError("reload command failed: " + " | ".join(failures))


def _proxy_reload_commands(settings: Settings) -> list[str]:
    return [settings.agent_reload_xray_cmd, settings.agent_reload_hysteria_cmd]


def handle_apply_bundle(settings: Settings, payload: dict[str, Any]) -> str:
    bundle_name = payload.get("bundle_name")
    if not bundle_name:
        raise HandlerError("bundle_name is required")

    files = payload.get("files") or {}
    if not isinstance(files, dict):
        raise HandlerError("files must be a dictionary")

    root = Path(settings.agent_data_root) / "bundles" / bundle_name
    root.mkdir(parents=True, exist_ok=True)
    apply_files(root, files)

    command_results: list[str] = []
    for cmd in payload.get("commands", []):
        ok, out = run_command(cmd, settings.agent_dry_run)
        command_results.append(f"{cmd}: {'ok' if ok else 'failed'}: {out}")

    return f"bundle applied: {bundle_name}; files={len(files)}; commands={len(command_results)}"


def handle_upsert_user(settings: Settings, payload: dict[str, Any]) -> str:
    required = ["user_id", "connection_id", "revision_id", "config"]
    missing = [key for key in required if key not in payload]
    if missing:
        raise HandlerError(f"missing fields: {', '.join(missing)}")

    user_id = str(payload["user_id"]).strip()
    connection_id = str(payload["connection_id"]).strip()
    incoming_ts = _payload_ts(payload)

    tombstone = _tombstone_path(settings, kind="connection", key=connection_id)
    tomb_ts = _read_tombstone_ts(tombstone)
    if tomb_ts is not None:
        # If we cannot compare timestamps, keep the connection revoked.
        if incoming_ts is None or incoming_ts <= tomb_ts:
            return f"ignored upsert for revoked connection={connection_id}"
        # Reactivation: newer upsert overrides revoke tombstone.
        try:
            tombstone.unlink()
        except OSError:
            pass

    user_root = _user_dir(Path(settings.agent_data_root), user_id)
    user_root.mkdir(parents=True, exist_ok=True)

    target = user_root / f"connection-{connection_id}.json"
    if target.exists() and incoming_ts is not None:
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            existing = None
        if isinstance(existing, dict):
            existing_ts = _payload_ts(existing)
            if existing_ts is not None and incoming_ts < existing_ts:
                return f"ignored older upsert for connection={connection_id}"

    target.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    upsert_user_artifact_index(settings, payload)

    changed = set(reconcile_all(settings))
    if changed:
        cmds: list[str] = []
        if "xray" in changed:
            cmds.append(settings.agent_reload_xray_cmd)
        if "hysteria" in changed:
            cmds.append(settings.agent_reload_hysteria_cmd)
        _run_reload_commands(settings, cmds)

    return f"upserted user payload for user={user_id} connection={connection_id}"


def handle_revoke_user(settings: Settings, payload: dict[str, Any]) -> str:
    user_id = payload.get("user_id")
    if not user_id:
        raise HandlerError("missing user_id")

    path = _user_dir(Path(settings.agent_data_root), user_id)
    if path.exists():
        shutil.rmtree(path)
    remove_user_artifact_index(settings, user_id)

    changed = set(reconcile_all(settings))
    if changed:
        cmds: list[str] = []
        if "xray" in changed:
            cmds.append(settings.agent_reload_xray_cmd)
        if "hysteria" in changed:
            cmds.append(settings.agent_reload_hysteria_cmd)
        _run_reload_commands(settings, cmds)

    return f"revoked user artifacts for {user_id}"


def handle_revoke_connection(settings: Settings, payload: dict[str, Any]) -> str:
    user_id = payload.get("user_id")
    connection_id = payload.get("connection_id")
    if not user_id or not connection_id:
        raise HandlerError("missing user_id/connection_id")

    user_id_s = str(user_id).strip()
    connection_id_s = str(connection_id).strip()
    incoming_ts = _payload_ts(payload) or datetime.now(timezone.utc)

    tombstone = _tombstone_path(settings, kind="connection", key=connection_id_s)
    tomb_ts = _read_tombstone_ts(tombstone)
    if tomb_ts is not None and tomb_ts >= incoming_ts:
        return f"ignored stale revoke for connection={connection_id_s}"

    user_root = _user_dir(Path(settings.agent_data_root), user_id_s)
    target = user_root / f"connection-{connection_id_s}.json"
    if target.exists():
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            existing = None
        if isinstance(existing, dict):
            existing_ts = _payload_ts(existing)
            if existing_ts is not None and existing_ts > incoming_ts:
                return f"ignored stale revoke for connection={connection_id_s}"
        target.unlink()
    remove_connection_artifact_index(settings, connection_id_s)
    # Remove empty user dir to keep filesystem tidy.
    try:
        if user_root.exists() and not any(user_root.iterdir()):
            user_root.rmdir()
    except OSError:
        pass

    _write_tombstone(
        tombstone,
        ts=incoming_ts,
        extra={"user_id": user_id_s, "connection_id": connection_id_s},
    )

    changed = set(reconcile_all(settings))
    if changed:
        cmds: list[str] = []
        if "xray" in changed:
            cmds.append(settings.agent_reload_xray_cmd)
        if "hysteria" in changed:
            cmds.append(settings.agent_reload_hysteria_cmd)
        _run_reload_commands(settings, cmds)

    return f"revoked connection artifacts for user={user_id_s} connection={connection_id_s}"


def handle_wg_peer_upsert(settings: Settings, payload: dict[str, Any]) -> str:
    if "peer_public_key" not in payload or "peer_ip" not in payload:
        raise HandlerError("missing wireguard peer fields")

    peer_key = payload.get("device_id") or payload.get("connection_id") or payload.get("revision_id")
    if not peer_key:
        raise HandlerError("missing peer key")

    peer_key_s = str(peer_key).strip()
    incoming_ts = _payload_ts(payload)
    tombstone = _tombstone_path(settings, kind="wg-peer", key=peer_key_s)
    tomb_ts = _read_tombstone_ts(tombstone)
    if tomb_ts is not None:
        if incoming_ts is None or incoming_ts <= tomb_ts:
            return f"ignored wg peer upsert for revoked key={peer_key_s}"
        try:
            tombstone.unlink()
        except OSError:
            pass

    root = Path(settings.agent_data_root) / "wg-peers"
    root.mkdir(parents=True, exist_ok=True)
    target = root / f"peer-{peer_key_s}.json"
    if target.exists() and incoming_ts is not None:
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            existing = None
        if isinstance(existing, dict):
            existing_ts = _payload_ts(existing)
            if existing_ts is not None and incoming_ts < existing_ts:
                return f"ignored older wg peer upsert for key={peer_key_s}"
    target.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    upsert_wg_peer_artifact_index(settings, peer_key=peer_key_s, payload=payload)

    changed = set(reconcile_all(settings))
    if "wireguard" in changed:
        _run_reload_commands(settings, [settings.agent_reload_wg_cmd])
    return f"wg peer upserted: {peer_key_s}"


def handle_wg_peer_remove(settings: Settings, payload: dict[str, Any]) -> str:
    peer_key = payload.get("device_id") or payload.get("connection_id") or payload.get("revision_id")
    if not peer_key:
        raise HandlerError("missing peer key")

    peer_key_s = str(peer_key).strip()
    incoming_ts = _payload_ts(payload) or datetime.now(timezone.utc)
    tombstone = _tombstone_path(settings, kind="wg-peer", key=peer_key_s)
    tomb_ts = _read_tombstone_ts(tombstone)
    if tomb_ts is not None and tomb_ts >= incoming_ts:
        return f"ignored stale wg peer remove for key={peer_key_s}"

    target = Path(settings.agent_data_root) / "wg-peers" / f"peer-{peer_key_s}.json"
    if target.exists():
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            existing = None
        if isinstance(existing, dict):
            existing_ts = _payload_ts(existing)
            if existing_ts is not None and existing_ts > incoming_ts:
                return f"ignored stale wg peer remove for key={peer_key_s}"
        target.unlink()
    remove_wg_peer_artifact_index(settings, peer_key=peer_key_s)
    _write_tombstone(tombstone, ts=incoming_ts, extra={"peer_key": peer_key_s})

    changed = set(reconcile_all(settings))
    if "wireguard" in changed:
        _run_reload_commands(settings, [settings.agent_reload_wg_cmd])
    return f"wg peer removed: {peer_key_s}"


def dispatch_event(settings: Settings, event_type: OutboxEventType, payload: dict[str, Any]) -> str:
    if event_type == OutboxEventType.APPLY_BUNDLE:
        return handle_apply_bundle(settings, payload)
    if event_type == OutboxEventType.UPSERT_USER:
        return handle_upsert_user(settings, payload)
    if event_type == OutboxEventType.REVOKE_USER:
        return handle_revoke_user(settings, payload)
    if event_type == OutboxEventType.REVOKE_CONNECTION:
        return handle_revoke_connection(settings, payload)
    if event_type == OutboxEventType.WG_PEER_UPSERT:
        return handle_wg_peer_upsert(settings, payload)
    if event_type == OutboxEventType.WG_PEER_REMOVE:
        return handle_wg_peer_remove(settings, payload)

    raise HandlerError(f"Unsupported event type: {event_type}")
