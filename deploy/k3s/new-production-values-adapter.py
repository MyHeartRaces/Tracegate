#!/usr/bin/env python3
from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml


FORBIDDEN_NEW_PRODUCTION_KEYS = {
    "naiveproxy",
    "transit",
    "transitRouter",
    "vlessEncryption",
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _load(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError("new production values must be a YAML mapping")
    return payload


def _forbidden_paths(value: Any, *, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            if key_text in FORBIDDEN_NEW_PRODUCTION_KEYS or "transit" in key_text.lower():
                errors.append(child_path)
            errors.extend(_forbidden_paths(child, path=child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_forbidden_paths(child, path=f"{path}[{index}]"))
    elif isinstance(value, str):
        lowered = value.lower()
        if "transit" in lowered or "naiveproxy" in lowered or "encrypted-vless" in lowered:
            errors.append(path)
    return errors


def adapt(values: dict[str, Any]) -> dict[str, Any]:
    forbidden = sorted(set(_forbidden_paths(values)))
    if forbidden:
        raise ValueError(f"new production values contain removed surfaces: {', '.join(forbidden)}")

    adapted = deepcopy(values)
    architecture = _mapping(adapted.get("architecture"))
    if architecture.get("mode") != "entry-endpoint":
        raise ValueError("new production values require architecture.mode=entry-endpoint")

    topology = _mapping(adapted.setdefault("topology", {}))
    servers = _mapping(topology.setdefault("servers", {}))
    endpoint_topology = _mapping(servers.get("endpoint"))
    if not endpoint_topology:
        raise ValueError("new production values require topology.servers.endpoint")

    control_plane = _mapping(adapted.setdefault("controlPlane", {}))
    env = _mapping(control_plane.setdefault("env", {}))
    aliases = {
        "defaultEndpointHost": "defaultTransitHost",
        "realityPublicKeyEndpoint": "realityPublicKeyTransit",
        "realityShortIdEndpoint": "realityShortIdTransit",
    }
    for endpoint_key, chart_key in aliases.items():
        if endpoint_key in env:
            env[chart_key] = env.pop(endpoint_key)
    env["naiveproxyHost"] = env.get("defaultTransitHost", "")

    gateway = _mapping(adapted.setdefault("gateway", {}))
    roles = _mapping(gateway.setdefault("roles", {}))
    endpoint_role = _mapping(roles.pop("endpoint", None))
    if not endpoint_role:
        raise ValueError("new production values require gateway.roles.endpoint")
    roles["transit"] = endpoint_role

    state_storage = _mapping(gateway.setdefault("stateStorage", {}))
    claims = _mapping(state_storage.setdefault("existingClaims", {}))
    if "endpoint" in claims:
        claims["transit"] = claims.pop("endpoint")

    adapted["naiveproxy"] = {"enabled": False}
    adapted["vlessEncryption"] = {"enabled": False}
    adapted["transitRouter"] = {"enabled": False}
    interconnect = _mapping(adapted.setdefault("interconnect", {}))
    interconnect["entryTransit"] = {
        "enabled": False,
        "routerEntry": {"enabled": False},
        "routerTransit": {"enabled": False},
    }
    interconnect["mieru"] = {"enabled": False}
    interconnect["zapret2"] = {"enabled": False}
    return adapted


def main() -> int:
    parser = argparse.ArgumentParser(description="Adapt clean Entry/Endpoint production values for the current chart.")
    parser.add_argument("--values", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        adapted = adapt(_load(args.values))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.safe_dump(adapted, sort_keys=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
