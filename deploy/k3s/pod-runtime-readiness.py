#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


ENDPOINT_REQUIRED_CONTAINERS = {
    "agent",
    "haproxy",
    "nginx",
    "xray",
    "hysteria",
    "mtproto",
    "shadowtls-v3",
    "wireguard",
    "wireguard-sync",
    "wstunnel-wireguard",
}


def _documents(path: Path) -> list[dict[str, Any]]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(doc, dict)]


def validate(path: Path, phase: str) -> list[str]:
    errors: list[str] = []
    rendered = path.read_text(encoding="utf-8")
    for removed_surface in ("NAIVEPROXY", "naiveproxy:", "VLESS_ENCRYPTION"):
        if removed_surface in rendered:
            errors.append(f"removed production surface rendered: {removed_surface}")
    deployments: dict[str, dict[str, Any]] = {}
    forbidden_components: list[str] = []
    for doc in _documents(path):
        labels = doc.get("metadata", {}).get("labels", {})
        component = str(labels.get("app.kubernetes.io/component") or "")
        if component in {"naiveproxy", "transit-router"}:
            forbidden_components.append(component)
        if doc.get("kind") == "Deployment" and component.startswith("gateway-"):
            deployments[component] = doc

    expected = {"gateway-transit"} if phase == "endpoint-first" else {"gateway-entry", "gateway-transit"}
    if set(deployments) != expected:
        errors.append(f"gateway deployments must be {sorted(expected)}, got {sorted(deployments)}")
    if forbidden_components:
        errors.append(f"legacy workload components rendered: {sorted(set(forbidden_components))}")

    for component, deployment in deployments.items():
        pod_spec = deployment.get("spec", {}).get("template", {}).get("spec", {})
        volumes = {row.get("name"): row for row in pod_spec.get("volumes", []) if isinstance(row, dict)}
        for name, volume in volumes.items():
            if "hostPath" in volume:
                errors.append(f"{component} volume {name!r} uses forbidden hostPath")
        state = volumes.get("gateway-state", {})
        if "persistentVolumeClaim" not in state:
            errors.append(f"{component} gateway-state must use a persistentVolumeClaim")

    endpoint = deployments.get("gateway-transit")
    if endpoint:
        pod_spec = endpoint.get("spec", {}).get("template", {}).get("spec", {})
        containers = {row.get("name") for row in pod_spec.get("containers", []) if isinstance(row, dict)}
        missing = sorted(ENDPOINT_REQUIRED_CONTAINERS - containers)
        if missing:
            errors.append(f"Endpoint gateway pod is missing required containers: {missing}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Tracegate 3 pod-only rendered runtime.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("endpoint-first", "full"))
    args = parser.parse_args()
    errors = validate(args.manifest, args.phase)
    if errors:
        for error in errors:
            print(f"pod-runtime-readiness: {error}")
        return 1
    print("pod-runtime-readiness: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
