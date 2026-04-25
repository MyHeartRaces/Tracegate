from __future__ import annotations

import copy
from typing import Any

from tracegate.settings import Settings

_STICKY_TRANSIT_PROTOCOLS = {"vless_reality"}
_STICKY_TRANSIT_VARIANTS = {"V2"}


def _payload_selected_path(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    cfg = payload.get("config")
    if not isinstance(cfg, dict):
        return None
    transit = cfg.get("transit")
    if not isinstance(transit, dict):
        return None
    selected = transit.get("selected_path")
    if not isinstance(selected, dict):
        return None
    return copy.deepcopy(selected)


def _is_sticky_transit_payload(settings: Settings, payload: dict[str, Any]) -> bool:
    if str(settings.agent_role or "").strip() != "ENTRY":
        return False
    protocol = str(payload.get("protocol") or "").strip().lower()
    variant = str(payload.get("variant") or "").strip().upper()
    return protocol in _STICKY_TRANSIT_PROTOCOLS and variant in _STICKY_TRANSIT_VARIANTS and isinstance(payload.get("config"), dict)


def _default_selected_path(settings: Settings) -> dict[str, Any]:
    host = str(settings.default_transit_host or "").strip()
    return {
        "name": "transit",
        "host": host,
        "port": 443,
        "priority": 0,
        "healthy": True,
        "latency_ms": None,
        "error": None,
        "selected_at": None,
    }


def assign_sticky_transit_if_needed(
    settings: Settings,
    payload: dict[str, Any],
    *,
    existing_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Keep a stable Entry -> Transit target in the user artifact.

    Tracegate 2 keeps the Entry -> Transit hop deterministic. The selected path
    is a fixed marker that points at the default Transit endpoint.
    """
    if not _is_sticky_transit_payload(settings, payload):
        return payload

    out = copy.deepcopy(payload)
    cfg = out.get("config")
    if not isinstance(cfg, dict):
        return payload

    selected = _payload_selected_path(out) or _payload_selected_path(existing_payload) or _default_selected_path(settings)
    transit = cfg.get("transit")
    if not isinstance(transit, dict):
        transit = {}
    cfg["transit"] = {
        **transit,
        "mode": "fixed",
        "scope": "connection",
        "listener": "transit_443",
        "selected_path": selected,
    }
    return out
