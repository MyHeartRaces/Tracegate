#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections.abc import Mapping
import ipaddress
from pathlib import Path
import re
import sys
from typing import Any

import yaml


MUTABLE_IMAGE_TAGS = {
    "",
    "latest",
    "main",
    "master",
    "dev",
    "edge",
    "nightly",
    "snapshot",
}
EXAMPLE_HOST_MARKERS = ("example.com", ".example.com")
OCI_DIGEST_RE = re.compile(r"^[A-Za-z0-9_+.-]+:[A-Fa-f0-9]{32,}$")


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise SystemExit(f"values file is missing: {path}") from exc
    if not isinstance(raw, dict):
        raise SystemExit(f"values file must be a YAML mapping: {path}")
    return raw


def _merge_values(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _merge_values(merged[key], value)
        else:
            merged[key] = value
    return merged


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _is_example_host(value: Any) -> bool:
    raw = _text(value).lower().rstrip(".")
    return any(marker in raw for marker in EXAMPLE_HOST_MARKERS)


def _has_value(value: Any) -> bool:
    return bool(_text(value))


def _as_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _memory_mi(value: Any) -> int | None:
    raw = _text(value)
    if raw.endswith("Mi"):
        return _as_int(raw[:-2], default=-1)
    if raw.endswith("Gi"):
        return _as_int(raw[:-2], default=-1) * 1024
    return None


def _cpu_millis(value: Any) -> int | None:
    raw = _text(value)
    if raw.endswith("m"):
        return _as_int(raw[:-1], default=-1)
    if "." in raw:
        return None
    parsed = _as_int(raw, default=-1)
    return parsed * 1000 if parsed >= 0 else None


def _entry_small_containers(values: Mapping[str, Any]) -> list[str]:
    interconnect = _as_dict(values.get("interconnect"))
    entry_transit = _as_dict(interconnect.get("entryTransit"))
    outer_carrier = _as_dict(entry_transit.get("outerCarrier"))
    mieru = _as_dict(interconnect.get("mieru"))
    zapret2 = _as_dict(interconnect.get("zapret2"))
    containers = ["agent", "haproxy", "nginx", "xray", "hysteria"]
    if bool(mieru.get("enabled", False)) and (
        bool(entry_transit.get("enabled", False)) or bool(_as_dict(entry_transit.get("routerEntry")).get("enabled", False))
    ):
        containers.append("mieru")
    if (
        bool(mieru.get("enabled", False))
        and bool(entry_transit.get("enabled", False))
        and bool(outer_carrier.get("enabled", False))
        and _text(outer_carrier.get("mode")) == "wss"
    ):
        containers.append("wstunnel")
    if bool(zapret2.get("enabled", False)):
        containers.append("zapret2")
    if bool(_as_dict(values.get("shadowsocks2022")).get("enabled", False)):
        containers.extend(["shadowsocks", "shadowtls"])
    return containers


def _experimental_requested(values: Mapping[str, Any]) -> bool:
    experimental = _as_dict(values.get("experimentalProfiles"))
    direct = _as_dict(experimental.get("directTransitObfuscation"))
    tuic = _as_dict(experimental.get("tuicV5"))
    return any(
        bool(value)
        for value in (
            experimental.get("enabled", False),
            direct.get("enabled", False),
            _as_dict(direct.get("mieru")).get("enabled", False),
            _as_dict(direct.get("restls")).get("enabled", False),
            tuic.get("enabled", False),
            tuic.get("directEnabled", False),
            tuic.get("chainEnabled", False),
        )
    )


def _is_mutable_tag(value: Any) -> bool:
    tag = _text(value).lower()
    return tag in MUTABLE_IMAGE_TAGS or tag.endswith("-latest")


def _has_digest(image: Mapping[str, Any]) -> bool:
    return _has_value(image.get("digest"))


def _has_valid_digest(image: Mapping[str, Any]) -> bool:
    return OCI_DIGEST_RE.fullmatch(_text(image.get("digest"))) is not None


def _image_label(path: str, image: Mapping[str, Any]) -> str:
    repo = _text(image.get("repository"))
    tag = _text(image.get("tag"))
    digest = _text(image.get("digest"))
    if digest:
        return f"{path} ({repo}@{digest})"
    return f"{path} ({repo}:{tag})"


def _is_clean_http_path(value: Any) -> bool:
    raw = _text(value)
    return bool(raw) and raw.startswith("/") and not raw.startswith("//") and "://" not in raw and "?" not in raw and "#" not in raw and not any(
        char.isspace() for char in raw
    )


def _ip_set(values: Any) -> set[str]:
    result: set[str] = set()
    for value in _as_list(values):
        raw = _text(value)
        if raw:
            result.add(raw)
    return result


def _valid_public_ip_set(values: set[str]) -> tuple[set[str], list[str]]:
    normalized: set[str] = set()
    invalid: list[str] = []
    for value in sorted(values):
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            invalid.append(value)
            continue
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified:
            invalid.append(value)
            continue
        normalized.add(str(parsed))
    return normalized, invalid


def validate_prod_overlay(chart_values: Path, prod_values: Path, *, strict: bool) -> list[str]:
    merged = _merge_values(_read_yaml(chart_values), _read_yaml(prod_values))
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    if strict and prod_values.name == "values-prod.example.yaml":
        errors.append("strict production validation must use an ignored private values file, not values-prod.example.yaml")

    global_values = _as_dict(merged.get("global"))
    global_image = _as_dict(global_values.get("image"))
    require("your-org" not in _text(global_image.get("repository")), "global.image.repository must not be the example repository")
    if _has_digest(global_image):
        require(_has_valid_digest(global_image), f"{_image_label('global.image', global_image)} must use a valid OCI digest")
    else:
        require(not _is_mutable_tag(global_image.get("tag")), f"{_image_label('global.image', global_image)} must use a pinned tag or digest")

    gateway = _as_dict(merged.get("gateway"))
    for name, image in sorted(_as_dict(gateway.get("images")).items()):
        image_map = _as_dict(image)
        if _has_digest(image_map):
            require(_has_valid_digest(image_map), f"{_image_label(f'gateway.images.{name}', image_map)} must use a valid OCI digest")
        else:
            require(not _is_mutable_tag(image_map.get("tag")), f"{_image_label(f'gateway.images.{name}', image_map)} must use a pinned tag or digest")

    control_plane = _as_dict(merged.get("controlPlane"))
    auth = _as_dict(control_plane.get("auth"))
    require(_has_value(auth.get("existingSecretName")), "controlPlane.auth.existingSecretName must reference an external Secret")

    database = _as_dict(control_plane.get("database"))
    embedded = _as_dict(database.get("embedded"))
    external_url_secret = _as_dict(database.get("externalUrlSecret"))
    if bool(embedded.get("enabled", False)):
        require(_has_value(embedded.get("password")), "embedded PostgreSQL requires a non-empty password")
    else:
        require(
            _has_value(database.get("externalUrl")) or _has_value(external_url_secret.get("name")),
            "production database must use externalUrl, externalUrlSecret.name, or embedded.enabled=true",
        )

    env = _as_dict(control_plane.get("env"))
    for label, value in (
        ("global.publicBaseUrl", global_values.get("publicBaseUrl")),
        ("controlPlane.env.defaultEntryHost", env.get("defaultEntryHost")),
        ("controlPlane.env.defaultTransitHost", env.get("defaultTransitHost")),
        ("controlPlane.env.mtprotoDomain", env.get("mtprotoDomain")),
    ):
        require(_has_value(value), f"{label} must be set for production")
        require(not _is_example_host(value), f"{label} must not use example.com")

    roles = _as_dict(gateway.get("roles"))
    entry = _as_dict(roles.get("entry"))
    transit = _as_dict(roles.get("transit"))
    entry_enabled = bool(entry.get("enabled", False))
    transit_enabled = bool(transit.get("enabled", False))
    if bool(gateway.get("hostNetwork", False)) and entry_enabled and transit_enabled:
        entry_selector = _as_dict(entry.get("nodeSelector"))
        transit_selector = _as_dict(transit.get("nodeSelector"))
        require(bool(entry_selector), "Entry gateway nodeSelector must be non-empty with hostNetwork")
        require(bool(transit_selector), "Transit gateway nodeSelector must be non-empty with hostNetwork")
        require(entry_selector != transit_selector, "Entry and Transit nodeSelector values must be distinct")

    for role_name, role in (("entry", entry), ("transit", transit)):
        if not bool(role.get("enabled", False)):
            continue
        tls = _as_dict(role.get("tls"))
        reality = _as_dict(role.get("reality"))
        require(not _is_example_host(tls.get("serverName")), f"gateway.roles.{role_name}.tls.serverName must not use example.com")
        require(_has_value(tls.get("existingSecretName")), f"gateway.roles.{role_name}.tls.existingSecretName must reference a TLS Secret")
        require(bool(_as_list(reality.get("serverNames"))), f"gateway.roles.{role_name}.reality.serverNames must not be empty")

    private_profiles = _as_dict(merged.get("privateProfiles"))
    require(bool(private_profiles.get("required", False)), "privateProfiles.required must stay true")
    require(not bool(private_profiles.get("inlineProfiles", False)), "privateProfiles.inlineProfiles must stay false")
    require(_has_value(private_profiles.get("existingSecretName")), "privateProfiles.existingSecretName must reference an external Secret")
    require(int(private_profiles.get("defaultMode", 0) or 0) in {256, 288, 384, 416}, "privateProfiles.defaultMode must be 0400, 0440, 0600 or 0640")

    transport_profiles = _as_dict(merged.get("transportProfiles"))
    socks5 = _as_dict(transport_profiles.get("socks5"))
    client_exposure = _as_dict(transport_profiles.get("clientExposure"))
    require(bool(socks5.get("required", False)), "transportProfiles.socks5.required must stay true")
    require(not bool(socks5.get("allowAnonymousLocalhost", False)), "transportProfiles.socks5.allowAnonymousLocalhost must stay false")
    require(_text(client_exposure.get("defaultMode")) == "vpn-tun", "transportProfiles.clientExposure.defaultMode must stay vpn-tun")
    require(
        _text(client_exposure.get("localProxyExports")) == "advanced-only",
        "transportProfiles.clientExposure.localProxyExports must stay advanced-only",
    )
    require(_text(client_exposure.get("lanSharing")) == "forbidden", "transportProfiles.clientExposure.lanSharing must stay forbidden")
    require(
        _text(client_exposure.get("unauthenticatedLocalProxy")) == "forbidden",
        "transportProfiles.clientExposure.unauthenticatedLocalProxy must stay forbidden",
    )

    network = _as_dict(merged.get("network"))
    egress_isolation = _as_dict(network.get("egressIsolation"))
    enforcement = _as_dict(egress_isolation.get("enforcement"))
    node_annotations = _as_dict(egress_isolation.get("nodeAnnotations"))
    require(bool(egress_isolation.get("required", False)), "network.egressIsolation.required must stay true")
    require(_text(egress_isolation.get("mode")) == "dedicated-egress-ip", "network.egressIsolation.mode must stay dedicated-egress-ip")
    require(
        bool(egress_isolation.get("forbidIngressIpAsEgress", False)),
        "network.egressIsolation.forbidIngressIpAsEgress must stay true",
    )
    require(
        bool(egress_isolation.get("requireTransitEgressPublicIP", False)),
        "network.egressIsolation.requireTransitEgressPublicIP must stay true",
    )
    require(_text(enforcement.get("mode")) == "operator-managed", "network.egressIsolation.enforcement.mode must stay operator-managed")
    require(_has_value(enforcement.get("managedBy")), "network.egressIsolation.enforcement.managedBy must be set")
    require(_text(enforcement.get("snat")) == "required", "network.egressIsolation.enforcement.snat must stay required")
    require(
        _text(enforcement.get("ingressPublicIpOutbound")) == "forbidden",
        "network.egressIsolation.enforcement.ingressPublicIpOutbound must stay forbidden",
    )
    require(bool(node_annotations.get("enabled", False)), "network.egressIsolation.nodeAnnotations.enabled must stay true in production")
    require(_has_value(node_annotations.get("ingressPublicIP")), "network.egressIsolation.nodeAnnotations.ingressPublicIP must be set")
    require(_has_value(node_annotations.get("egressPublicIP")), "network.egressIsolation.nodeAnnotations.egressPublicIP must be set")
    ingress_public_ips, invalid_ingress_ips = _valid_public_ip_set(_ip_set(egress_isolation.get("ingressPublicIPs")))
    egress_public_ips, invalid_egress_ips = _valid_public_ip_set(_ip_set(egress_isolation.get("egressPublicIPs")))
    require(bool(ingress_public_ips), "network.egressIsolation.ingressPublicIPs must contain at least one public IP")
    require(bool(egress_public_ips), "network.egressIsolation.egressPublicIPs must contain at least one public IP")
    require(not invalid_ingress_ips, f"network.egressIsolation.ingressPublicIPs contains invalid/non-public IPs: {', '.join(invalid_ingress_ips)}")
    require(not invalid_egress_ips, f"network.egressIsolation.egressPublicIPs contains invalid/non-public IPs: {', '.join(invalid_egress_ips)}")
    overlap = sorted(ingress_public_ips.intersection(egress_public_ips))
    require(not overlap, f"network.egressIsolation ingressPublicIPs and egressPublicIPs must be disjoint: {', '.join(overlap)}")

    rollout = _as_dict(gateway.get("rollingUpdate"))
    private_preflight = _as_dict(gateway.get("privatePreflight"))
    reload_commands = _as_dict(_as_dict(gateway.get("agent")).get("reloadCommands"))
    require(_text(gateway.get("strategy")) == "RollingUpdate", "gateway.strategy must stay RollingUpdate for production")
    require(not bool(gateway.get("allowRecreateStrategy", False)), "gateway.allowRecreateStrategy must stay false for production")
    require(_text(rollout.get("maxUnavailable")) == "0", "gateway.rollingUpdate.maxUnavailable must stay 0")
    require(bool(_as_dict(gateway.get("pdb")).get("enabled", False)), "gateway.pdb.enabled must stay true")
    require(bool(_as_dict(gateway.get("probes")).get("enabled", False)), "gateway.probes.enabled must stay true")
    require(bool(private_preflight.get("enabled", False)), "gateway.privatePreflight.enabled must stay true")
    require(bool(private_preflight.get("forbidPlaceholders", False)), "gateway.privatePreflight.forbidPlaceholders must stay true")
    entry_small = _as_dict(gateway.get("entrySmall"))
    if bool(entry_small.get("enabled", False)):
        entry_small_rollout = _as_dict(entry_small.get("rollout"))
        resources = _as_dict(entry_small.get("containerResources"))
        memory_budget_mi = _as_int(entry_small.get("memoryBudgetMi"))
        cpu_budget_millis = _as_int(entry_small.get("cpuLimitBudgetMillis"))
        require(entry_enabled, "gateway.entrySmall.enabled=true requires the Entry role")
        require(bool(entry_small.get("forbidWireGuard", False)), "gateway.entrySmall.forbidWireGuard must stay true")
        require(bool(entry_small.get("forbidExperimental", False)), "gateway.entrySmall.forbidExperimental must stay true")
        require(not bool(_as_dict(merged.get("wireguard")).get("enabled", False)), "wireguard.enabled must stay false when gateway.entrySmall.enabled=true")
        require(bool(_as_dict(merged.get("shadowsocks2022")).get("enabled", False)), "shadowsocks2022.enabled must stay true when gateway.entrySmall.enabled=true")
        require(not _experimental_requested(merged), "experimentalProfiles must stay disabled when gateway.entrySmall.enabled=true")
        require(_text(entry_small_rollout.get("strategy")) == "Recreate", "gateway.entrySmall.rollout.strategy must stay Recreate")
        require(
            bool(entry_small_rollout.get("allowRecreateStrategy", False)),
            "gateway.entrySmall.rollout.allowRecreateStrategy must stay true",
        )
        require(_text(entry_small_rollout.get("maxSurge")) == "0", "gateway.entrySmall.rollout.maxSurge must stay 0")

        memory_total_mi = 0
        cpu_total_millis = 0
        for container_name in _entry_small_containers(merged):
            container_resources = _as_dict(resources.get(container_name))
            limits = _as_dict(container_resources.get("limits"))
            memory_mi = _memory_mi(limits.get("memory"))
            cpu_millis = _cpu_millis(limits.get("cpu"))
            require(memory_mi is not None and memory_mi > 0, f"gateway.entrySmall.containerResources.{container_name}.limits.memory must use Mi or Gi")
            require(cpu_millis is not None and cpu_millis > 0, f"gateway.entrySmall.containerResources.{container_name}.limits.cpu must use millicores or whole cores")
            memory_total_mi += memory_mi or 0
            cpu_total_millis += cpu_millis or 0
        require(memory_total_mi <= memory_budget_mi, f"gateway.entrySmall memory limit total {memory_total_mi}Mi exceeds memoryBudgetMi={memory_budget_mi}")
        require(cpu_total_millis <= cpu_budget_millis, f"gateway.entrySmall CPU limit total {cpu_total_millis}m exceeds cpuLimitBudgetMillis={cpu_budget_millis}")
    roles = _as_dict(gateway.get("roles"))
    for role_name, role_payload in roles.items():
        role = _as_dict(role_payload)
        if not bool(role.get("enabled", False)):
            continue
        ports = _as_dict(role.get("ports"))
        require(_as_int(ports.get("publicTcp")) == 443, f"gateway.roles.{role_name}.ports.publicTcp must stay 443")
        require(_as_int(ports.get("publicUdp")) == 8443, f"gateway.roles.{role_name}.ports.publicUdp must stay 8443")
    profiles_reload = _text(reload_commands.get("profiles"))
    link_crypto_reload = _text(reload_commands.get("linkCrypto"))
    require(
        "tracegate-k3s-private-reload" in profiles_reload and "--component profiles" in profiles_reload,
        "gateway.agent.reloadCommands.profiles must run tracegate-k3s-private-reload --component profiles",
    )
    require(
        "tracegate-k3s-private-reload" in link_crypto_reload and "--component link-crypto" in link_crypto_reload,
        "gateway.agent.reloadCommands.linkCrypto must run tracegate-k3s-private-reload --component link-crypto",
    )

    decoy = _as_dict(merged.get("decoy"))
    has_decoy_source = any(_has_value(decoy.get(key)) for key in ("hostPath", "existingClaim", "existingConfigMap"))
    require(has_decoy_source, "production decoy must use hostPath, existingClaim, or existingConfigMap, not built-in lab files")

    interconnect = _as_dict(merged.get("interconnect"))
    entry_transit = _as_dict(interconnect.get("entryTransit"))
    outer_carrier = _as_dict(entry_transit.get("outerCarrier"))
    zapret2 = _as_dict(interconnect.get("zapret2"))
    require(not bool(entry_transit.get("xrayBackhaul", False)), "interconnect.entryTransit.xrayBackhaul must stay false")
    require(_text(entry_transit.get("chainBridgeOwner")) == "link-crypto", "interconnect.entryTransit.chainBridgeOwner must stay link-crypto")
    require(_text(entry_transit.get("fallback")) == "none", "interconnect.entryTransit.fallback must stay none")
    require(bool(outer_carrier.get("enabled", False)), "interconnect.entryTransit.outerCarrier.enabled must stay true")
    require(_text(outer_carrier.get("mode")) == "wss", "interconnect.entryTransit.outerCarrier.mode must stay wss")
    require(_text(outer_carrier.get("protocol") or "websocket-tls") == "websocket-tls", "interconnect.entryTransit.outerCarrier.protocol must stay websocket-tls")
    require(_has_value(outer_carrier.get("serverName")), "interconnect.entryTransit.outerCarrier.serverName must be set")
    require(not _is_example_host(outer_carrier.get("serverName")), "interconnect.entryTransit.outerCarrier.serverName must not use example.com")
    require(_as_int(outer_carrier.get("publicPort")) == 443, "interconnect.entryTransit.outerCarrier.publicPort must stay 443")
    require(_is_clean_http_path(outer_carrier.get("publicPath")), "interconnect.entryTransit.outerCarrier.publicPath must be a clean absolute HTTP path")
    require(bool(outer_carrier.get("verifyTls", False)), "interconnect.entryTransit.outerCarrier.verifyTls must stay true")
    spki_pinning = _as_dict(outer_carrier.get("spkiPinning"))
    admission = _as_dict(outer_carrier.get("admission"))
    require(bool(spki_pinning.get("required", False)), "interconnect.entryTransit.outerCarrier.spkiPinning.required must stay true")
    require(_has_value(spki_pinning.get("profileFile")), "interconnect.entryTransit.outerCarrier.spkiPinning.profileFile must be set")
    require(bool(admission.get("required", False)), "interconnect.entryTransit.outerCarrier.admission.required must stay true")
    require(
        _text(admission.get("mode")) == "hmac-sha256-generation-bound",
        "interconnect.entryTransit.outerCarrier.admission.mode must stay hmac-sha256-generation-bound",
    )
    require(_text(admission.get("header")) == "Sec-WebSocket-Protocol", "interconnect.entryTransit.outerCarrier.admission.header must stay Sec-WebSocket-Protocol")
    require(_has_value(admission.get("profileFile")), "interconnect.entryTransit.outerCarrier.admission.profileFile must be set")
    require(_has_value(outer_carrier.get("tcpShapingProfileFile")), "interconnect.entryTransit.outerCarrier.tcpShapingProfileFile must be set")
    require(_has_value(outer_carrier.get("promotionPreflightProfileFile")), "interconnect.entryTransit.outerCarrier.promotionPreflightProfileFile must be set")
    wireguard = _as_dict(merged.get("wireguard"))
    wireguard_wstunnel = _as_dict(wireguard.get("wstunnel"))
    bridge_path = _text(outer_carrier.get("publicPath"))
    require(bridge_path != _text(wireguard_wstunnel.get("publicPath")), "bridge WSS publicPath must be separate from wireguard.wstunnel.publicPath")
    require(
        bridge_path not in {_text(env.get("vlessWsPath")), _text(env.get("vlessGrpcPath"))},
        "bridge WSS publicPath must be separate from VLESS public paths",
    )
    require(not bool(zapret2.get("hostWideInterception", False)), "interconnect.zapret2.hostWideInterception must stay false")
    require(not bool(zapret2.get("nfqueue", False)), "interconnect.zapret2.nfqueue must stay false")
    require(bool(zapret2.get("enabled", False)), "interconnect.zapret2.enabled must stay true for TCP link-crypto DPI resistance")

    mtproto = _as_dict(merged.get("mtproto"))
    require(bool(mtproto.get("enabled", False)), "mtproto.enabled must stay true in core Tracegate 2.2")
    require(not _is_example_host(mtproto.get("domain")), "mtproto.domain must not use example.com")
    bridge_server_name = _text(outer_carrier.get("serverName")).lower().rstrip(".")
    transit_tls_server_name = _text(_as_dict(transit.get("tls")).get("serverName")).lower().rstrip(".")
    mtproto_domain = _text(mtproto.get("domain") or env.get("mtprotoDomain")).lower().rstrip(".")
    require(bridge_server_name != transit_tls_server_name, "bridge WSS serverName must be separate from gateway.roles.transit.tls.serverName")
    require(bridge_server_name != mtproto_domain, "bridge WSS serverName must be separate from the MTProto domain")

    return errors


def validate_namespace(chart_values: Path, prod_values: Path, expected_namespace: str) -> list[str]:
    expected = _text(expected_namespace)
    if not expected:
        return []
    merged = _merge_values(_read_yaml(chart_values), _read_yaml(prod_values))
    namespace = _text(_as_dict(merged.get("namespace")).get("name")) or "tracegate"
    if namespace != expected:
        return [
            f"namespace.name ({namespace}) must match TRACEGATE_NAMESPACE/Helm namespace ({expected})",
        ]
    return []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate a Tracegate k3s production values overlay.")
    parser.add_argument("--chart-values", required=True, type=Path, help="Base chart values.yaml")
    parser.add_argument("--values", required=True, type=Path, help="Production values overlay")
    parser.add_argument("--strict", action="store_true", help="Reject example placeholders and require production-ready values")
    parser.add_argument("--expected-namespace", default="", help="Require values namespace.name to match this namespace")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    errors = validate_prod_overlay(args.chart_values, args.values, strict=args.strict)
    errors.extend(validate_namespace(args.chart_values, args.values, args.expected_namespace))
    if errors:
        for error in errors:
            print(f"prod-overlay-check: {error}", file=sys.stderr)
        return 1
    print("prod-overlay-check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
