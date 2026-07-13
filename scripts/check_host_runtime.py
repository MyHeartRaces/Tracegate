#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import re
import tomllib

import yaml


class HostRuntimeCheckError(RuntimeError):
    pass


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise HostRuntimeCheckError(f"required host runtime file is missing: {path}") from exc


def _require(text: str, needle: str, *, label: str) -> None:
    if needle not in text:
        raise HostRuntimeCheckError(f"{label} is missing required contract: {needle}")


def check_host_runtime(root: Path) -> None:
    root = root.resolve()
    if (root / "deploy/k3s").exists():
        raise HostRuntimeCheckError("deploy/k3s is retired and must not be present")

    manifest = yaml.safe_load(_read(root / "bundles/manifest.yaml"))
    project_path = root / "pyproject.toml"
    if project_path.exists():
        project = tomllib.loads(_read(project_path))
        version = str(project["project"]["version"])
        scripts = project["project"]["scripts"]
        if any("k3s" in str(name).lower() or "k3s" in str(target).lower() for name, target in scripts.items()):
            raise HostRuntimeCheckError("project scripts still expose a k3s command")
        for command in ("tracegate-host-private-preflight", "tracegate-host-private-reload"):
            if command not in scripts:
                raise HostRuntimeCheckError(f"missing host runtime command: {command}")
        if str(manifest.get("metadata", {}).get("version")) != version:
            raise HostRuntimeCheckError("bundle manifest version does not match package version")
    roles = {row.get("canonicalRole") for row in manifest.get("spec", {}).get("bundles", [])}
    if roles != {"Entry", "Endpoint"}:
        raise HostRuntimeCheckError(f"host bundles must cover Entry and Endpoint, got {sorted(roles)}")

    nginx = _read(root / "bundles/base-transit/nginx.conf")
    wgws_match = re.search(r"location\s+/wgws\s*\{(?P<body>.*?)\n\s*\}", nginx, re.DOTALL)
    if wgws_match is None:
        raise HostRuntimeCheckError("Endpoint nginx bundle is missing /wgws")
    wgws = wgws_match.group("body")
    _require(wgws, "proxy_http_version 1.1;", label="WGWS nginx route")
    _require(wgws, "proxy_set_header Upgrade $http_upgrade;", label="WGWS nginx route")
    _require(wgws, "proxy_pass http://127.0.0.1:51821;", label="WGWS nginx route")

    haproxy = _read(root / "bundles/base-transit/haproxy.cfg")
    for placeholder in ("REPLACE_SHADOWTLS_ACL", "REPLACE_SHADOWTLS_ROUTE", "REPLACE_SHADOWTLS_BACKEND"):
        _require(haproxy, placeholder, label="Endpoint HAProxy bundle")

    sync_unit = _read(root / "deploy/systemd/tracegate-wireguard-sync.service")
    _require(sync_unit, "tracegate-wireguard-sync-runner", label="WireGuard peer synchronizer unit")
    _require(sync_unit, "desired-state.json", label="WireGuard peer synchronizer unit")
    _require(sync_unit, "WIREGUARD_SYNC_KEEP_STALE_PEERS=false", label="WireGuard peer synchronizer unit")

    mtproto_path = root / "src/tracegate/services/mtproto.py"
    if mtproto_path.exists():
        mtproto = _read(mtproto_path)
        _require(mtproto, 'listen = "127.0.0.1:9091"', label="Telemt read-only API")
        _require(mtproto, 'whitelist = ["127.0.0.1/32", "::1/128"]', label="Telemt read-only API")
        _require(mtproto, '"read_only = true"', label="Telemt read-only API")

    release_script_path = root / "scripts/build_release_artifacts.sh"
    if release_script_path.exists():
        release_script = _read(release_script_path)
        _require(release_script, "tracegate-host-runtime-${VERSION}.tar.gz", label="release artifact builder")
        if "helm" in release_script.lower() or "deploy/k3s" in release_script:
            raise HostRuntimeCheckError("release artifact builder still depends on Helm/k3s")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the public host-based Tracegate runtime contract")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        check_host_runtime(args.root)
    except HostRuntimeCheckError as exc:
        print(f"host runtime check failed: {exc}")
        return 1
    print(f"host runtime check passed ({args.root.resolve()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
