#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import tomllib


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

    manifest_text = _read(root / "bundles/manifest.yaml")
    manifest_version_match = re.search(r"(?m)^\s{2}version:\s*([^\s#]+)\s*$", manifest_text)
    if manifest_version_match is None:
        raise HostRuntimeCheckError("bundle manifest version is missing")
    manifest_version = manifest_version_match.group(1)
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
        if manifest_version != version:
            raise HostRuntimeCheckError("bundle manifest version does not match package version")
    roles = set(re.findall(r"(?m)^\s+canonicalRole:\s*([^\s#]+)\s*$", manifest_text))
    if roles != {"Entry", "Endpoint"}:
        raise HostRuntimeCheckError(f"host bundles must cover Entry and Endpoint, got {sorted(roles)}")

    quic_sysctl = _read(root / "deploy/host/90-tracegate-quic.conf")
    for key in (
        "net.core.rmem_default",
        "net.core.rmem_max",
        "net.core.wmem_default",
        "net.core.wmem_max",
    ):
        _require(quic_sysctl, f"{key} = 16777216", label="host QUIC sysctl profile")

    host_install = _read(root / "deploy/host/tracegate-host-install")
    _require(host_install, "90-tracegate-quic.conf", label="host installer")
    _require(host_install, '"${SYSCTL}" -p', label="host installer")

    entry_firewall = _read(root / "bundles/base-entry/nftables.conf")
    transit_firewall = _read(root / "bundles/base-transit/nftables.conf")
    _require(entry_firewall, "tracegate-managed-mtproto-mask-firewall", label="Entry firewall bundle")
    _require(entry_firewall, "tcp dport 10444 drop", label="Entry firewall bundle")
    _require(transit_firewall, "tracegate-managed-entry-link-firewall", label="Endpoint firewall bundle")
    _require(
        transit_firewall,
        "tcp dport { 9443, 9444, 9445, 9446 } drop",
        label="Endpoint firewall bundle",
    )

    mtproto_unit = _read(root / "deploy/systemd/tracegate-mtproto@.service")
    _require(mtproto_unit, ":/app/config.toml:ro", label="Telemt systemd unit")
    if "--health-cmd" in mtproto_unit:
        raise HostRuntimeCheckError("Telemt unit must use its exec-form image healthcheck")

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

    for role in ("entry", "transit"):
        xray_path = root / f"bundles/base-{role}/xray.json"
        xray_text = _read(xray_path)
        if re.search(r"(?i)xhttp|splithttp", xray_text):
            raise HostRuntimeCheckError(f"{role} Xray bundle contains forbidden XHTTP transport")
        xray_payload = json.loads(xray_text)
        for section in ("inbounds", "outbounds"):
            for row in xray_payload.get(section, []):
                stream = row.get("streamSettings") if isinstance(row, dict) else None
                if (
                    isinstance(stream, dict)
                    and str(row.get("protocol") or "").strip().lower() == "vless"
                    and str(stream.get("security") or "").strip().lower() == "reality"
                    and str(stream.get("network") or "").strip().lower() != "raw"
                ):
                    raise HostRuntimeCheckError(
                        f"{role} VLESS/REALITY {section[:-1]} must use RAW/TCP"
                    )
        if role == "entry":
            outbounds = {
                str(row.get("tag") or ""): row
                for row in xray_payload.get("outbounds", [])
                if isinstance(row, dict)
            }
            backhaul = outbounds.get("to-transit")
            backhaul_stream = backhaul.get("streamSettings") if isinstance(backhaul, dict) else None
            if (
                not isinstance(backhaul, dict)
                or str(backhaul.get("protocol") or "").strip().lower() != "vless"
                or not isinstance(backhaul_stream, dict)
                or str(backhaul_stream.get("security") or "").strip().lower() != "reality"
                or str(backhaul_stream.get("network") or "").strip().lower() != "raw"
            ):
                raise HostRuntimeCheckError("Entry bundle is missing the VLESS/REALITY RAW Endpoint backhaul")
            has_default_backhaul = False
            for rule in xray_payload.get("routing", {}).get("rules", []):
                if not isinstance(rule, dict):
                    continue
                inbound_tags = {str(tag) for tag in rule.get("inboundTag", [])}
                if "entry-in" not in inbound_tags:
                    continue
                if str(rule.get("outboundTag") or "") == "direct":
                    raise HostRuntimeCheckError("Entry Chain routing must not bypass Endpoint egress")
                # The default Chain route must reach the Endpoint either directly via
                # the sole `to-transit` outbound (single-transport) or via the backhaul
                # balancer (SS2022 primary + REALITY fallback pool).
                targets_backhaul = (
                    str(rule.get("outboundTag") or "") == "to-transit"
                    or str(rule.get("balancerTag") or "") == "backhaul-balancer"
                )
                if targets_backhaul and not any(
                    key in rule for key in ("domain", "ip", "port", "network", "protocol")
                ):
                    has_default_backhaul = True
            if not has_default_backhaul:
                raise HostRuntimeCheckError("Entry Chain routing is missing the default Endpoint backhaul rule")
            ss_backhaul = outbounds.get("to-transit-ss")
            ss_backhaul_servers = (
                (ss_backhaul.get("settings") or {}).get("servers") if isinstance(ss_backhaul, dict) else None
            )
            if (
                not isinstance(ss_backhaul, dict)
                or str(ss_backhaul.get("protocol") or "").strip().lower() != "shadowsocks"
                or not isinstance(ss_backhaul_servers, list)
                or not ss_backhaul_servers
                or str((ss_backhaul_servers[0] or {}).get("method") or "").strip().lower()
                != "2022-blake3-aes-256-gcm"
            ):
                raise HostRuntimeCheckError(
                    "Entry bundle is missing the SS2022 (aes-256) Endpoint backhaul outbound to-transit-ss"
                )
            balancers = {
                str(row.get("tag") or ""): row
                for row in xray_payload.get("routing", {}).get("balancers", [])
                if isinstance(row, dict)
            }
            backhaul_balancer = balancers.get("backhaul-balancer")
            if (
                not isinstance(backhaul_balancer, dict)
                or backhaul_balancer.get("selector") != ["to-transit-ss"]
                or str(backhaul_balancer.get("fallbackTag") or "") != "to-transit"
                or str((backhaul_balancer.get("strategy") or {}).get("type") or "") != "leastPing"
            ):
                raise HostRuntimeCheckError(
                    "Entry backhaul balancer must prefer SS2022/ShadowTLS and use REALITY only as fallback"
                )

    xray = _read(root / "bundles/base-transit/xray.json")
    if '"tag": "ss2022-in"' in xray:
        raise HostRuntimeCheckError("primary Endpoint Xray bundle must not own SS2022")
    ss2022_xray = _read(root / "bundles/base-transit/xray-ss2022.json")
    _require(ss2022_xray, '"tag": "ss2022-in"', label="isolated Endpoint SS2022 Xray bundle")
    _require(ss2022_xray, '"method": "2022-blake3-aes-128-gcm"', label="isolated Endpoint SS2022 Xray bundle")
    _require(
        ss2022_xray,
        '"password": "REPLACE_SHADOWSOCKS2022_SERVER_KEY"',
        label="isolated Endpoint SS2022 Xray bundle",
    )
    _require(ss2022_xray, '"tag": "ss2022-backhaul-in"', label="isolated Endpoint SS2022 backhaul inbound")
    _require(
        ss2022_xray,
        '"method": "2022-blake3-aes-256-gcm"',
        label="isolated Endpoint SS2022 backhaul inbound",
    )
    _require(
        ss2022_xray,
        '"password": "REPLACE_SHADOWSOCKS2022_BACKHAUL_KEY"',
        label="isolated Endpoint SS2022 backhaul inbound",
    )

    sync_unit = _read(root / "deploy/systemd/tracegate-wireguard-sync.service")
    _require(sync_unit, "tracegate-wireguard-sync-runner", label="WireGuard peer synchronizer unit")
    _require(sync_unit, "desired-state.json", label="WireGuard peer synchronizer unit")
    _require(sync_unit, "WIREGUARD_SYNC_KEEP_STALE_PEERS=false", label="WireGuard peer synchronizer unit")

    latest_units = (
        "tracegate-api.service",
        "tracegate-bot.service",
        "tracegate-dispatcher.service",
        "tracegate-agent.service",
        "tracegate-agent-entry.service",
        "tracegate-entry-firewall.service",
        "tracegate-db-backup.service",
        "tracegate-xray@.service",
        "tracegate-xray-ss2022.service",
        "tracegate-hysteria@.service",
        "tracegate-hysteria-salamander.service",
        "tracegate-shadowtls.service",
        "tracegate-shadowtls-entry2.service",
        "tracegate-shadowtls-entry.service",
        "tracegate-shadowtls-backhaul2.service",
        "tracegate-shadowtls-backhaul.service",
        "tracegate-backhaul-fragment@.service",
        "tracegate-wstunnel-wireguard.service",
        "tracegate-mtproto@.service",
        "tracegate-prometheus.service",
        "tracegate-grafana.service",
    )
    for unit_name in latest_units:
        unit = _read(root / "deploy/systemd" / unit_name)
        if unit_name in {
            "tracegate-api.service",
            "tracegate-bot.service",
            "tracegate-dispatcher.service",
            "tracegate-agent.service",
            "tracegate-agent-entry.service",
            "tracegate-entry-firewall.service",
            "tracegate-db-backup.service",
        }:
            if "k3s" in unit.lower() or "kubectl" in unit.lower():
                raise HostRuntimeCheckError(f"{unit_name} still references retired cluster runtime")
            continue
        _require(unit, ":latest", label=unit_name)
        _require(unit, "docker pull", label=unit_name)
        _require(unit, "SuccessExitStatus=143", label=unit_name)
        if "@sha256:" in unit:
            raise HostRuntimeCheckError(f"{unit_name} must not lock an image digest")
        if unit_name.startswith("tracegate-xray"):
            _require(unit, "--user 0:0", label=unit_name)
        if unit_name.startswith("tracegate-backhaul-fragment"):
            _require(unit, "--user 0:0", label=unit_name)
            _require(unit, "tracegate-backhaul-fragment-config %i", label=unit_name)
        if unit_name.startswith("tracegate-hysteria"):
            _require(unit, "--user 0:0", label=unit_name)
            _require(unit, "--cap-drop ALL --cap-add NET_BIND_SERVICE", label=unit_name)

    mtproto_path = root / "src/tracegate/services/mtproto.py"
    if mtproto_path.exists():
        mtproto = _read(mtproto_path)
        # The Telemt stats API defaults to loopback:9091; the entry-endpoint-tunnel
        # deployment only moves the port (never off loopback) to dodge the Endpoint
        # dispatcher, and the metrics scraper follows the same URL.
        _require(mtproto, 'api_listen: str = "127.0.0.1:9091"', label="Telemt read-only API")
        _require(mtproto, 'whitelist = ["127.0.0.1/32", "::1/128"]', label="Telemt read-only API")
        _require(mtproto, '"read_only = true"', label="Telemt read-only API")
        # Loopback is always trusted for the PROXY header, and a non-loopback bind
        # is refused unless a source-gated ingress is explicitly configured.
        _require(mtproto, 'loopback_cidrs = ["127.0.0.1/32", "::1/128"]', label="Telemt PROXY trust")
        _require(
            mtproto,
            "may bind to a non-loopback address only when a source-gated PROXY-protocol",
            label="Telemt bind safety",
        )
    mtproto_unit = _read(root / "deploy/systemd/tracegate-mtproto@.service")
    _require(
        mtproto_unit,
        "/var/lib/tracegate/private/mtproto/runtime/config.toml:/app/config.toml:ro",
        label="Telemt container healthcheck",
    )
    fragment_config = _read(root / "deploy/systemd/tracegate-backhaul-fragment-config")
    _require(fragment_config, '"packets": packets', label="ShadowTLS fragment renderer")
    _require(fragment_config, '"length": length', label="ShadowTLS fragment renderer")
    _require(fragment_config, "byte-preserving TCP stream slicing", label="ShadowTLS fragment renderer")

    release_script_path = root / "scripts/build_release_artifacts.sh"
    if release_script_path.exists():
        release_script = _read(release_script_path)
        _require(release_script, "tracegate-host-runtime-${VERSION}.tar.gz", label="release artifact builder")
        if "helm" in release_script.lower() or "deploy/k3s" in release_script:
            raise HostRuntimeCheckError("release artifact builder still depends on Helm/k3s")

    if (root / "deploy/host/compose.yaml").exists() or (root / "deploy/host/tracegate-host.service").exists():
        raise HostRuntimeCheckError("retired Compose host runtime is still packaged")


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
