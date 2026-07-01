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
EXAMPLE_HOST_MARKERS = ("example.com", ".example.com", "example.net", ".example.net", "example.org", ".example.org")
OCI_DIGEST_RE = re.compile(r"^[A-Za-z0-9_+.-]+:[A-Fa-f0-9]{32,}$")
TRACEGATE3_CLIENT_PROFILE_KEYS = {
    "reality",
    "hysteria",
    "entry",
    "backup-grpc",
    "backup-ws",
    "backup-shadowtls",
    "backup-wgws",
}
ENDPOINT_FIRST_CLIENT_PROFILE_KEYS = {
    "reality",
    "hysteria",
    "backup-grpc",
    "backup-ws",
    "backup-shadowtls",
    "backup-wgws",
}


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


def _endpoint_role_key(roles: Mapping[str, Any]) -> str:
    return "endpoint" if isinstance(roles.get("endpoint"), Mapping) else "transit"


def _endpoint_role(roles: Mapping[str, Any]) -> dict[str, Any]:
    legacy = _as_dict(roles.get("transit"))
    endpoint = _as_dict(roles.get("endpoint"))
    return _merge_values(legacy, endpoint) if endpoint else legacy


def _endpoint_shadowtls_server_name(values: Mapping[str, Any]) -> str:
    shadowtls = _as_dict(_as_dict(values.get("shadowsocks2022")).get("shadowtls"))
    return _text(shadowtls.get("serverNameEndpoint") or shadowtls.get("serverNameTransit"))


def _entry_endpoint_clean_naming_errors(values: Mapping[str, Any]) -> list[str]:
    architecture = _as_dict(values.get("architecture"))
    if _text(architecture.get("mode")) != "entry-endpoint":
        return []

    errors: list[str] = []

    def visit(value: Any, path: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                child_path = f"{path}.{key_text}" if path else key_text
                if "transit" in key_text.lower():
                    errors.append(child_path)
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")
        elif isinstance(value, str) and "transit" in value.lower():
            errors.append(path)

    visit(values)
    return sorted(set(errors))


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


def _is_placeholder_repo(value: Any) -> bool:
    raw = _text(value).lower()
    return "your-org" in raw or raw.startswith("example/")


def _effective_public_host(configured: Any, fallback: Any) -> str:
    configured_text = _text(configured)
    fallback_text = _text(fallback)
    if fallback_text and (not configured_text or _is_example_host(configured_text)):
        return fallback_text
    return configured_text


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
    shadowsocks2022 = _as_dict(interconnect.get("shadowsocks2022"))
    zapret2 = _as_dict(interconnect.get("zapret2"))
    containers = ["agent", "haproxy", "nginx", "xray", "hysteria"]
    endpoint_backhaul = _as_dict(interconnect.get("endpointBackhaul"))
    if bool(endpoint_backhaul.get("enabled", False)) and bool(_as_dict(endpoint_backhaul.get("hysteria2")).get("enabled", False)):
        # The shared Endpoint fallback adds one Hysteria2 client sidecar on Entry.
        containers.append("hysteria")
    if bool(shadowsocks2022.get("enabled", False)) and (
        bool(entry_transit.get("enabled", False)) or bool(_as_dict(entry_transit.get("routerEntry")).get("enabled", False))
    ):
        containers.append("singbox")
    if (
        bool(shadowsocks2022.get("enabled", False))
        and bool(entry_transit.get("enabled", False))
        and bool(outer_carrier.get("enabled", False))
        and _text(outer_carrier.get("mode")) == "wss"
    ):
        containers.append("wstunnel")
    if bool(zapret2.get("enabled", False)):
        containers.append("zapret2")
    if bool(_as_dict(values.get("shadowsocks2022")).get("enabled", False)):
        containers.append("shadowtls")
    traffic_shaping = _as_dict(_as_dict(_as_dict(values.get("gateway")).get("trafficShaping")).get("entry"))
    if bool(traffic_shaping.get("enabled", False)):
        containers.append("entryTrafficShaper")
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


def _valid_public_ipv4_networks(values: Any) -> tuple[set[str], list[str]]:
    normalized: set[str] = set()
    invalid: list[str] = []
    for value in _as_list(values):
        raw = _text(value)
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            invalid.append(raw)
            continue
        if network.version != 4 or not network.is_global:
            invalid.append(raw)
            continue
        normalized.add(str(network))
    return normalized, invalid


def validate_prod_overlay(chart_values: Path, prod_values: Path, *, strict: bool) -> list[str]:
    raw_prod_values = _read_yaml(prod_values)
    merged = _merge_values(_read_yaml(chart_values), raw_prod_values)
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    if strict and prod_values.name == "values-prod.example.yaml":
        errors.append("strict production validation must use an ignored private values file, not values-prod.example.yaml")
    if strict:
        forbidden_clean_paths = _entry_endpoint_clean_naming_errors(raw_prod_values)
        if forbidden_clean_paths:
            errors.append(
                "entry-endpoint production values must use Entry/Endpoint naming only; forbidden legacy paths: "
                + ", ".join(forbidden_clean_paths)
            )

    global_values = _as_dict(merged.get("global"))
    global_image = _as_dict(global_values.get("image"))
    require("your-org" not in _text(global_image.get("repository")), "global.image.repository must not be the example repository")
    if _has_digest(global_image):
        require(_has_valid_digest(global_image), f"{_image_label('global.image', global_image)} must use a valid OCI digest")
    else:
        require(not _is_mutable_tag(global_image.get("tag")), f"{_image_label('global.image', global_image)} must use a pinned tag or digest")

    gateway = _as_dict(merged.get("gateway"))
    naiveproxy = _as_dict(merged.get("naiveproxy"))
    architecture = _as_dict(merged.get("architecture"))
    architecture_mode = _text(architecture.get("mode")) or "legacy-three-node"
    deployment_phase = _text(architecture.get("deploymentPhase")) or "full"
    pod_runtime_only = bool(architecture.get("podRuntimeOnly", False))
    require(
        architecture_mode in {"legacy-three-node", "entry-endpoint"},
        "architecture.mode must be legacy-three-node or entry-endpoint",
    )
    require(
        deployment_phase in {"endpoint-first", "entry-staged", "full"},
        "architecture.deploymentPhase must be endpoint-first, entry-staged or full",
    )
    if deployment_phase in {"endpoint-first", "entry-staged"}:
        require(architecture_mode == "entry-endpoint", "endpoint-first/entry-staged requires architecture.mode=entry-endpoint")
    interconnect_for_images = _as_dict(merged.get("interconnect"))
    entry_transit_for_images = _as_dict(interconnect_for_images.get("entryTransit"))
    link_crypto_for_images = _as_dict(interconnect_for_images.get("shadowsocks2022"))
    zapret2_for_images = _as_dict(interconnect_for_images.get("zapret2"))
    shadowsocks2022_for_images = _as_dict(merged.get("shadowsocks2022"))
    wireguard_for_images = _as_dict(merged.get("wireguard"))
    mtproto_for_images = _as_dict(merged.get("mtproto"))
    link_crypto_image_enabled = bool(link_crypto_for_images.get("enabled", False)) and (
        bool(entry_transit_for_images.get("enabled", False))
        or bool(_as_dict(entry_transit_for_images.get("routerEntry")).get("enabled", False))
        or bool(_as_dict(entry_transit_for_images.get("routerTransit")).get("enabled", False))
    )
    enabled_gateway_images = {"haproxy", "nginx", "xray", "hysteria", "singbox"}
    if bool(mtproto_for_images.get("enabled", False)):
        mtproto_runtime = _text(mtproto_for_images.get("runtime")).lower() or "mtg"
        mtproto_fallback_enabled = bool(_as_dict(mtproto_for_images.get("fallback")).get("enabled", False))
        if mtproto_runtime == "official":
            enabled_gateway_images.add("mtprotoOfficial")
        else:
            enabled_gateway_images.add("mtproto")
        if mtproto_fallback_enabled:
            enabled_gateway_images.update({"mtproto", "mtprotoOfficial"})
    if link_crypto_image_enabled and bool(_as_dict(entry_transit_for_images.get("outerCarrier")).get("enabled", False)):
        enabled_gateway_images.add("wstunnel")
    if bool(zapret2_for_images.get("enabled", False)):
        enabled_gateway_images.add("zapret2")
    if bool(shadowsocks2022_for_images.get("enabled", False)):
        enabled_gateway_images.add("shadowtls")
    if bool(wireguard_for_images.get("enabled", False)):
        enabled_gateway_images.update({"wireguard", "wstunnel"})
    if bool(naiveproxy.get("enabled", False)):
        enabled_gateway_images.add("naiveproxy")
    for name, image in sorted(_as_dict(gateway.get("images")).items()):
        if name not in enabled_gateway_images:
            continue
        image_map = _as_dict(image)
        require(not _is_placeholder_repo(image_map.get("repository")), f"{_image_label(f'gateway.images.{name}', image_map)} must not use the example repository")
        if _has_digest(image_map):
            require(_has_valid_digest(image_map), f"{_image_label(f'gateway.images.{name}', image_map)} must use a valid OCI digest")
        else:
            require(not _is_mutable_tag(image_map.get("tag")), f"{_image_label(f'gateway.images.{name}', image_map)} must use a pinned tag or digest")
    hysteria_image = _as_dict(_as_dict(gateway.get("images")).get("hysteria"))
    hysteria_version_match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", _text(hysteria_image.get("tag")))
    require(
        bool(hysteria_version_match)
        and tuple(int(part) for part in hysteria_version_match.groups()) >= (2, 9, 2),
        "gateway.images.hysteria.tag must be Hysteria 2.9.2 or newer for Gecko obfs",
    )

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
    database_backup = _as_dict(database.get("backup"))
    if bool(database_backup.get("enabled", False)):
        require(
            _has_value(database_backup.get("repositorySecretName")),
            "controlPlane.database.backup.repositorySecretName must reference an external Secret",
        )
        require(
            bool(_as_dict(database_backup.get("restoreCheck")).get("enabled", False)),
            "production PostgreSQL backups require restoreCheck.enabled=true",
        )
        for name in ("postgresImage", "resticImage"):
            image = _as_dict(database_backup.get(name))
            require(
                not _is_placeholder_repo(image.get("repository")),
                f"{_image_label(f'controlPlane.database.backup.{name}', image)} must not use the example repository",
            )
            if _has_digest(image):
                require(
                    _has_valid_digest(image),
                    f"{_image_label(f'controlPlane.database.backup.{name}', image)} must use a valid OCI digest",
                )
            else:
                require(
                    not _is_mutable_tag(image.get("tag")),
                    f"{_image_label(f'controlPlane.database.backup.{name}', image)} must use a pinned tag or digest",
                )

    env = _as_dict(control_plane.get("env"))
    roles = _as_dict(gateway.get("roles"))
    entry = _as_dict(roles.get("entry"))
    endpoint_role_key = _endpoint_role_key(roles)
    transit = _endpoint_role(roles)
    entry_default_host = _effective_public_host(env.get("defaultEntryHost"), _as_dict(entry.get("tls")).get("serverName"))
    transit_default_host = _effective_public_host(
        env.get("defaultEndpointHost") or env.get("defaultTransitHost"),
        _as_dict(transit.get("tls")).get("serverName"),
    )
    required_public_hosts = [
        ("global.publicBaseUrl", global_values.get("publicBaseUrl")),
        ("effective Entry host", entry_default_host),
        ("effective Endpoint host", transit_default_host),
        ("controlPlane.env.mtprotoDomain", env.get("mtprotoDomain")),
    ]
    if architecture_mode == "legacy-three-node":
        required_public_hosts.append(("controlPlane.env.naiveproxyHost", env.get("naiveproxyHost")))
    for label, value in required_public_hosts:
        require(_has_value(value), f"{label} must be set for production")
        require(not _is_example_host(value), f"{label} must not use example.com")

    entry_enabled = bool(entry.get("enabled", False))
    transit_enabled = bool(transit.get("enabled", False))
    if architecture_mode == "entry-endpoint":
        require(transit_enabled, "entry-endpoint requires the Endpoint gateway role")
        require(
            entry_enabled == (deployment_phase in {"entry-staged", "full"}),
            "Entry gateway role must be enabled only in the entry-staged and full deployment phases",
        )
    if bool(gateway.get("hostNetwork", False)) and entry_enabled and transit_enabled:
        entry_selector = _as_dict(entry.get("nodeSelector"))
        transit_selector = _as_dict(transit.get("nodeSelector"))
        require(bool(entry_selector), "Entry gateway nodeSelector must be non-empty with hostNetwork")
        require(bool(transit_selector), "Endpoint gateway nodeSelector must be non-empty with hostNetwork")
        require(entry_selector != transit_selector, "Entry and Endpoint nodeSelector values must be distinct")

    for role_name, role in (("entry", entry), (endpoint_role_key, transit)):
        if not bool(role.get("enabled", False)):
            continue
        tls = _as_dict(role.get("tls"))
        reality = _as_dict(role.get("reality"))
        role_default_host = entry_default_host if role_name == "entry" else transit_default_host
        effective_tls_server_name = _effective_public_host(tls.get("serverName"), role_default_host)
        require(not _is_example_host(effective_tls_server_name), f"gateway.roles.{role_name}.tls.serverName must not use example.com")
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

    topology = _as_dict(merged.get("topology"))
    topology_servers = _as_dict(topology.get("servers"))
    canonical_servers = {"endpoint": "Endpoint"}
    if deployment_phase in {"entry-staged", "full"}:
        canonical_servers["entry"] = "Entry"
    if architecture_mode == "legacy-three-node":
        canonical_servers["transit"] = "Transit"
    for server_key, display_name in canonical_servers.items():
        server = _as_dict(topology_servers.get(server_key))
        public_ip = _text(server.get("publicIp"))
        public_ips, invalid_public_ips = _valid_public_ip_set({public_ip} if public_ip else set())
        require(_text(server.get("displayName")) == display_name, f"topology.servers.{server_key}.displayName must be {display_name}")
        require(bool(public_ips), f"topology.servers.{server_key}.publicIp must be a public IP")
        require(not invalid_public_ips, f"topology.servers.{server_key}.publicIp is invalid/non-public: {public_ip}")
        require(bool(_as_dict(server.get("nodeSelector"))), f"topology.servers.{server_key}.nodeSelector must be non-empty")
    endpoint_topology = _as_dict(topology_servers.get("endpoint"))
    transit_topology = _as_dict(topology_servers.get("transit"))
    entry_topology = _as_dict(topology_servers.get("entry"))
    if architecture_mode == "legacy-three-node":
        require(_text(endpoint_topology.get("publicIp")) in egress_public_ips, "Endpoint publicIp must be listed as an egress public IP")
        require(_text(transit_topology.get("publicIp")) in ingress_public_ips, "Transit publicIp must be listed as an ingress public IP")
    else:
        require(not _has_value(transit_topology.get("publicIp")), "entry-endpoint forbids topology.servers.transit.publicIp")
        require(
            not _has_value(transit_topology.get("kubernetesNodeName")),
            "entry-endpoint forbids topology.servers.transit.kubernetesNodeName",
        )
    if deployment_phase in {"entry-staged", "full"}:
        require(_text(entry_topology.get("publicIp")) in ingress_public_ips, "Entry publicIp must be listed as an ingress public IP")
        require(
            _as_dict(entry_topology.get("nodeSelector")) == _as_dict(entry.get("nodeSelector")),
            "topology.servers.entry.nodeSelector must match gateway.roles.entry.nodeSelector",
        )
    require(
        _as_dict(endpoint_topology.get("nodeSelector")) == _as_dict(transit.get("nodeSelector")),
        "topology.servers.endpoint.nodeSelector must match the endpoint gateway selector",
    )
    require(_text(entry.get("canonicalServer")) == "entry", "gateway.roles.entry.canonicalServer must be entry")
    require(_text(transit.get("canonicalServer") or "endpoint") == "endpoint", f"gateway.roles.{endpoint_role_key}.canonicalServer must be endpoint")

    rollout = _as_dict(gateway.get("rollingUpdate"))
    private_preflight = _as_dict(gateway.get("privatePreflight"))
    reload_commands = _as_dict(_as_dict(gateway.get("agent")).get("reloadCommands"))
    traffic_shaping = _as_dict(gateway.get("trafficShaping"))
    entry_traffic_shaping = _as_dict(traffic_shaping.get("entry"))
    chain_client_traffic_shaping = _as_dict(traffic_shaping.get("chainClient"))
    hysteria_traffic_shaping = _as_dict(traffic_shaping.get("hysteria"))
    node_encryption = _as_dict(gateway.get("nodeEncryption"))
    node_encryption_annotations = _as_dict(node_encryption.get("nodeAnnotations"))
    require(_text(gateway.get("strategy")) == "RollingUpdate", "gateway.strategy must stay RollingUpdate for production")
    require(not bool(gateway.get("allowRecreateStrategy", False)), "gateway.allowRecreateStrategy must stay false for production")
    require(
        _text(rollout.get("maxUnavailable")) == "1",
        "gateway.rollingUpdate.maxUnavailable must stay 1 for single-replica hostNetwork production gateways",
    )
    require(
        _text(rollout.get("maxSurge")) in {"0", "0%"},
        "gateway.rollingUpdate.maxSurge must stay 0 for single-replica hostNetwork production gateways",
    )
    require(bool(_as_dict(gateway.get("pdb")).get("enabled", False)), "gateway.pdb.enabled must stay true")
    require(bool(_as_dict(gateway.get("probes")).get("enabled", False)), "gateway.probes.enabled must stay true")
    require(bool(private_preflight.get("enabled", False)), "gateway.privatePreflight.enabled must stay true")
    require(bool(private_preflight.get("forbidPlaceholders", False)), "gateway.privatePreflight.forbidPlaceholders must stay true")
    if entry_enabled:
        require(bool(entry_traffic_shaping.get("enabled", False)), "gateway.trafficShaping.entry.enabled must stay true")
        require(_has_value(entry_traffic_shaping.get("interface")), "gateway.trafficShaping.entry.interface must be set")
        require(_as_int(entry_traffic_shaping.get("maxMbit")) == 65, "gateway.trafficShaping.entry.maxMbit must stay at 65")
        require(bool(entry_traffic_shaping.get("applyEgress", False)), "gateway.trafficShaping.entry.applyEgress must stay true")
        require(bool(entry_traffic_shaping.get("applyIngressPolicing", False)), "gateway.trafficShaping.entry.applyIngressPolicing must stay true")
        require(bool(entry_traffic_shaping.get("failClosed", False)), "gateway.trafficShaping.entry.failClosed must stay true")
    require(bool(chain_client_traffic_shaping.get("enabled", False)), "gateway.trafficShaping.chainClient.enabled must stay true")
    require(
        1 <= _as_int(chain_client_traffic_shaping.get("maxMbit")) <= 10,
        "gateway.trafficShaping.chainClient.maxMbit must be in 1..10",
    )
    require(
        bool(chain_client_traffic_shaping.get("requireDeclaredHysteriaTx", False)),
        "gateway.trafficShaping.chainClient.requireDeclaredHysteriaTx must stay true",
    )
    require(
        bool(hysteria_traffic_shaping.get("ignoreClientBandwidth", False)),
        "gateway.trafficShaping.hysteria.ignoreClientBandwidth must stay true",
    )
    require(
        not bool(hysteria_traffic_shaping.get("entryChainIgnoreClientBandwidth", True)),
        "gateway.trafficShaping.hysteria.entryChainIgnoreClientBandwidth must stay false",
    )
    if architecture_mode == "legacy-three-node":
        require(bool(node_encryption.get("enabled", False)), "gateway.nodeEncryption.enabled must stay true")
        require(bool(node_encryption.get("required", False)), "gateway.nodeEncryption.required must stay true")
        require(_has_value(node_encryption.get("markerFile")), "gateway.nodeEncryption.markerFile must be set")
        require(_has_value(node_encryption.get("markerValue")), "gateway.nodeEncryption.markerValue must be set")
        require(bool(node_encryption_annotations.get("enabled", False)), "gateway.nodeEncryption.nodeAnnotations.enabled must stay true")
        require(
            _has_value(node_encryption_annotations.get("encryptedRuntime")),
            "gateway.nodeEncryption.nodeAnnotations.encryptedRuntime must be set",
        )
        require(
            _has_value(node_encryption_annotations.get("expectedValue")),
            "gateway.nodeEncryption.nodeAnnotations.expectedValue must be set",
        )
    else:
        require(not bool(node_encryption.get("enabled", False)), "entry-endpoint requires gateway.nodeEncryption.enabled=false")
        require(not bool(node_encryption.get("required", False)), "entry-endpoint requires gateway.nodeEncryption.required=false")
        require(
            not bool(node_encryption.get("runtimeInitValidation", False)),
            "entry-endpoint requires gateway.nodeEncryption.runtimeInitValidation=false",
        )
        require(
            not bool(node_encryption.get("requireDeviceMapperSource", False)),
            "entry-endpoint requires gateway.nodeEncryption.requireDeviceMapperSource=false",
        )
        require(
            not bool(node_encryption_annotations.get("enabled", False)),
            "entry-endpoint requires gateway.nodeEncryption.nodeAnnotations.enabled=false",
        )
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
    for role_name, role in (("entry", entry), (endpoint_role_key, transit)):
        if not bool(role.get("enabled", False)):
            continue
        ports = _as_dict(role.get("ports"))
        require(_as_int(ports.get("publicTcp")) == 443, f"gateway.roles.{role_name}.ports.publicTcp must stay 443")
        require(
            _as_int(ports.get("publicUdp")) == 443,
            f"gateway.roles.{role_name}.ports.publicUdp must stay 443 for Tracegate 3 Hysteria2",
        )
    require(
        [_text(value) for value in _as_list(env.get("wireguardAllowedIps")) if _text(value)] == ["0.0.0.0/0"],
        "production WireGuard client routes must stay IPv4-only",
    )
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
    has_global_decoy_source = any(
        _has_value(decoy.get(key)) for key in ("hostPath", "existingClaim", "existingConfigMap")
    )
    decoy_role_sources = _as_dict(decoy.get("roleSources"))
    for role_name, role_enabled in (("entry", entry_enabled), ("endpoint", transit_enabled)):
        if role_enabled:
            role_source = _as_dict(decoy_role_sources.get(role_name))
            require(
                has_global_decoy_source or _has_value(role_source.get("existingConfigMap")),
                f"production decoy for {role_name} must use a global source or decoy.roleSources.{role_name}.existingConfigMap",
            )
    if pod_runtime_only:
        state_storage = _as_dict(gateway.get("stateStorage"))
        existing_claims = _as_dict(state_storage.get("existingClaims"))
        require(_text(state_storage.get("mode")) == "pvc", "podRuntimeOnly requires gateway.stateStorage.mode=pvc")
        require(not _has_value(decoy.get("hostPath")), "podRuntimeOnly forbids decoy.hostPath")
        for role_name, role_enabled in (("entry", entry_enabled), (endpoint_role_key, transit_enabled)):
            if role_enabled:
                require(_has_value(existing_claims.get(role_name)), f"podRuntimeOnly requires gateway.stateStorage.existingClaims.{role_name}")

    require(not bool(naiveproxy.get("enabled", False)), "naiveproxy.enabled must stay false in Tracegate 3")

    transit_router = _as_dict(merged.get("transitRouter"))
    transit_router_enabled = bool(transit_router.get("enabled", False))
    mtproto_route = _as_dict(_as_dict(merged.get("mtproto")).get("route"))
    mtproto_route_mode = _text(mtproto_route.get("mode")) or "endpoint-direct"
    if mtproto_route_mode == "entry-transit-endpoint":
        require(transit_router_enabled, "transitRouter.enabled must stay true when mtproto.route.mode=entry-transit-endpoint")
    if transit_router_enabled:
        transit_router_entry = _as_dict(transit_router.get("entry"))
        transit_router_endpoint = _as_dict(transit_router.get("endpoint"))
        transit_router_tls = _as_dict(transit_router.get("tls"))
        transit_router_xray = _as_dict(transit_router.get("xray"))
        transit_router_sni = _as_dict(transit_router.get("sni"))
        transit_router_ports = _as_dict(transit_router.get("ports"))
        require(
            _as_dict(transit_router.get("nodeSelector")) == _as_dict(transit_topology.get("nodeSelector")),
            "transitRouter.nodeSelector must match the legacy Transit topology selector",
        )
        require(
            _text(transit_router_endpoint.get("host")) == transit_default_host,
            "transitRouter.endpoint.host must match the canonical Endpoint host",
        )
        require(
            _text(entry_topology.get("publicIp")) in _ip_set(transit_router_entry.get("allowedSources")),
            "transitRouter.entry.allowedSources must include the Entry publicIp",
        )
        require(_has_value(transit_router_tls.get("existingSecretName")), "transitRouter.tls.existingSecretName must reference a TLS Secret")
        require(_has_value(transit_router_xray.get("existingSecretName")), "transitRouter.xray.existingSecretName must reference an Xray Secret")
        require(_has_value(transit_router_sni.get("decoy")), "transitRouter.sni.decoy must be set")
        require(_as_int(transit_router_ports.get("publicTcp")) == 443, "transitRouter.ports.publicTcp must stay 443")
        require(_as_int(transit_router_ports.get("mtproto")) == 8443, "transitRouter.ports.mtproto must stay 8443")

    interconnect = _as_dict(merged.get("interconnect"))
    entry_transit = _as_dict(interconnect.get("entryTransit"))
    outer_carrier = _as_dict(entry_transit.get("outerCarrier"))
    zapret2 = _as_dict(interconnect.get("zapret2"))
    tcp_carrier = _as_dict(interconnect.get("shadowsocks2022"))
    link_crypto_enabled = architecture_mode != "entry-endpoint" and (
        bool(entry_transit.get("enabled", False))
        or bool(_as_dict(entry_transit.get("routerEntry")).get("enabled", False))
        or bool(_as_dict(entry_transit.get("routerTransit")).get("enabled", False))
    )
    require(not bool(entry_transit.get("xrayBackhaul", False)), "interconnect.entryTransit.xrayBackhaul must stay false")
    require(_text(entry_transit.get("chainBridgeOwner")) == "link-crypto", "interconnect.entryTransit.chainBridgeOwner must stay link-crypto")
    require(_text(entry_transit.get("fallback")) == "none", "interconnect.entryTransit.fallback must stay none")
    if link_crypto_enabled:
        require(_text(entry_transit.get("innerCarrier")) == "shadowsocks2022", "interconnect.entryTransit.innerCarrier must stay shadowsocks2022")
        require(bool(tcp_carrier.get("enabled", False)), "interconnect.shadowsocks2022.enabled must stay true for TCP link-crypto")
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
    if link_crypto_enabled:
        zapret_apply_to = {_text(value).lower() for value in _as_list(zapret2.get("applyTo")) if _text(value)}
        require(
            not zapret_apply_to.intersection({"entry-transit", "router-entry", "router-transit", "link-crypto", "link_crypto"}),
            "interconnect.zapret2.applyTo must not target TCP link-crypto surfaces",
        )

    ingress_rotation = _as_dict(architecture.get("ingressRotation"))
    entry_ingress = _as_dict(architecture.get("entryIngress"))
    endpoint_ingress = _as_dict(architecture.get("endpointIngress"))
    universal_entry = _as_dict(architecture.get("universalEntry"))
    entry_ingress_enabled = bool(entry_ingress.get("enabled", False))
    endpoint_ingress_enabled = bool(endpoint_ingress.get("enabled", False))
    universal_entry_enabled = bool(universal_entry.get("enabled", False))
    ingress_rotation_enabled = bool(ingress_rotation.get("enabled", False))
    removed_xhttp = _as_dict(interconnect.get("emergencyXrayChain"))
    require(not bool(removed_xhttp.get("enabled", False)), "interconnect.emergencyXrayChain must stay disabled; XHTTP was removed")
    require(not _as_list(removed_xhttp.get("shards")), "interconnect.emergencyXrayChain.shards must stay empty; XHTTP was removed")
    require(not _as_dict(removed_xhttp.get("xhttp")), "interconnect.emergencyXrayChain.xhttp must stay empty; XHTTP was removed")
    gateway_hysteria = _as_dict(_as_dict(merged.get("gateway")).get("hysteria"))
    gateway_hysteria_obfs = _as_dict(gateway_hysteria.get("obfs"))
    gateway_hysteria_gecko = _as_dict(gateway_hysteria_obfs.get("gecko"))
    direct_gecko_min = _as_int(gateway_hysteria_gecko.get("minPacketSize"))
    direct_gecko_max = _as_int(gateway_hysteria_gecko.get("maxPacketSize"))
    require(_text(gateway_hysteria_obfs.get("type")) == "gecko", "gateway.hysteria.obfs.type must stay gecko")
    require(
        512 <= direct_gecko_min <= direct_gecko_max <= 2048,
        "gateway.hysteria Gecko packet sizes must satisfy 512 <= minPacketSize <= maxPacketSize <= 2048",
    )
    entry_rotation_hosts = [_text(host) for host in _as_list(ingress_rotation.get("entryHosts")) if _text(host)]
    endpoint_rotation_hosts = [_text(host) for host in _as_list(ingress_rotation.get("endpointHosts")) if _text(host)]
    minimum_pool_size = _as_int(ingress_rotation.get("minimumPoolSize"), default=2)
    require(
        _text(ingress_rotation.get("strategy")) == "revision-sticky",
        "architecture.ingressRotation.strategy must stay revision-sticky",
    )
    require(
        not bool(ingress_rotation.get("rotateEndpointEgress", False)),
        "architecture.ingressRotation.rotateEndpointEgress must stay false",
    )
    if ingress_rotation_enabled:
        require(architecture_mode == "entry-endpoint", "ingress rotation requires architecture.mode=entry-endpoint")
        require(minimum_pool_size >= 2, "architecture.ingressRotation.minimumPoolSize must be at least 2")
        require(
            _as_int(ingress_rotation.get("overlapSeconds")) >= 300,
            "architecture.ingressRotation.overlapSeconds must be at least 300",
        )
        require(
            bool(ingress_rotation.get("requireDistinctPublicIPs", False)),
            "architecture.ingressRotation.requireDistinctPublicIPs must stay true",
        )
        require(
            bool(ingress_rotation.get("requireDistinctAsns", False)),
            "architecture.ingressRotation.requireDistinctAsns must stay true",
        )
        require(
            entry_ingress_enabled
            or endpoint_ingress_enabled
            or max(len(set(entry_rotation_hosts)), len(set(endpoint_rotation_hosts))) >= minimum_pool_size,
            "ingress rotation requires ingress shards or at least one hostname pool meeting minimumPoolSize",
        )
        require(
            len(ingress_public_ips) >= minimum_pool_size,
            "ingress rotation requires network.egressIsolation.ingressPublicIPs to meet minimumPoolSize",
        )
        for host in entry_rotation_hosts + endpoint_rotation_hosts:
            require(not _is_example_host(host), "architecture.ingressRotation hostnames must not use example.com")

    if entry_ingress_enabled:
        service_facing = _as_dict(entry_ingress.get("serviceFacing"))
        service_ip = _text(service_facing.get("publicIp"))
        shards = [_as_dict(shard) for shard in _as_list(entry_ingress.get("shards"))]
        shard_ids = [_text(shard.get("id")) for shard in shards]
        shard_ips = [_text(shard.get("publicIp")) for shard in shards]
        hostname_templates = [_text(shard.get("hostnameTemplate")) for shard in shards]
        mtproto_hosts = [_text(shard.get("mtprotoHost")) for shard in shards]
        active_shards = [shard for shard in shards if _text(shard.get("state") or "active") == "active"]
        alias = _as_dict(entry_ingress.get("alias"))
        firewall = _as_dict(entry_ingress.get("firewall"))
        channel = _as_dict(entry_ingress.get("channel"))
        tcp_channel = _as_dict(channel.get("tcp"))
        udp_channel = _as_dict(channel.get("udp"))
        four_ip_contract = {service_ip, *shard_ips}
        normalized_four_ips, invalid_four_ips = _valid_public_ip_set({value for value in four_ip_contract if value})

        require(architecture_mode == "entry-endpoint", "entry ingress sharding requires architecture.mode=entry-endpoint")
        require(ingress_rotation_enabled, "entry ingress sharding requires architecture.ingressRotation.enabled=true")
        require(len(shards) == 3, "architecture.entryIngress.shards must contain exactly three shards")
        require(len(active_shards) >= 2, "entry ingress sharding requires at least two active Entry shards")
        require(len(set(shard_ids)) == 3 and all(shard_ids), "Entry shard ids must be non-empty and unique")
        require(len(set(shard_ips)) == 3 and all(shard_ips), "Entry shard public IPs must be non-empty and unique")
        require(service_ip not in set(shard_ips), "service-facing public IP must be distinct from every Entry shard IP")
        require(len(normalized_four_ips) == 4 and not invalid_four_ips, "entry ingress sharding requires four distinct public IPs")
        require(all(ipaddress.ip_address(value).version == 4 for value in normalized_four_ips), "entry ingress sharding currently requires IPv4 addresses")
        require(four_ip_contract == ingress_public_ips, "network.egressIsolation.ingressPublicIPs must exactly match service-facing IP plus three shard IPs")
        require(_text(entry_topology.get("publicIp")) in set(shard_ips), "topology.servers.entry.publicIp must be one of the Entry shard IPs")
        require(all("{token}" in template for template in hostname_templates), "every Entry shard hostnameTemplate must contain {token}")
        require(len(set(hostname_templates)) == 3, "Entry shard hostnameTemplate values must be unique")
        require(len(set(mtproto_hosts)) == 3 and all(mtproto_hosts), "Entry shard mtprotoHost values must be non-empty and unique")
        require(all(not _is_example_host(host) for host in mtproto_hosts), "Entry shard mtprotoHost values must not use example.com")
        require(8 <= _as_int(alias.get("tokenLength"), default=0) <= 48, "architecture.entryIngress.alias.tokenLength must be in 8..48")
        require(bool(firewall.get("required", False)), "architecture.entryIngress.firewall.required must stay true")
        require(bool(tcp_channel.get("bindShardIpsOnly", False)), "Entry TCP listeners must bind shard IPs only")
        require(_as_int(tcp_channel.get("maxConnections")) >= 100, "Entry TCP maxConnections must be at least 100")
        require(_as_int(tcp_channel.get("maxConnectionsPerSource")) >= 1, "Entry TCP maxConnectionsPerSource must be at least 1")
        require(_as_int(tcp_channel.get("newConnectionsPer10Seconds")) >= 1, "Entry TCP newConnectionsPer10Seconds must be at least 1")
        require(bool(udp_channel.get("serviceIpRejectRequired", False)), "Entry UDP service-facing IP rejection must stay required")

    if endpoint_ingress_enabled:
        service_facing = _as_dict(endpoint_ingress.get("serviceFacing"))
        service_ip = _text(service_facing.get("publicIp"))
        shards = [_as_dict(shard) for shard in _as_list(endpoint_ingress.get("shards"))]
        shard_ids = [_text(shard.get("id")) for shard in shards]
        shard_ips = [_text(shard.get("publicIp")) for shard in shards]
        hostname_templates = [_text(shard.get("hostnameTemplate")) for shard in shards]
        active_shards = [shard for shard in shards if _text(shard.get("state") or "active") == "active"]
        alias = _as_dict(endpoint_ingress.get("alias"))
        firewall = _as_dict(endpoint_ingress.get("firewall"))
        channel = _as_dict(endpoint_ingress.get("channel"))
        tcp_channel = _as_dict(channel.get("tcp"))
        udp_channel = _as_dict(channel.get("udp"))
        endpoint_exclusive_pairs = _as_dict(endpoint_ingress.get("exclusiveSniPairs"))
        endpoint_sni_pool = {
            _text(value).lower().rstrip(".") for value in _as_list(endpoint_exclusive_pairs.get("pool")) if _text(value)
        }
        cdn_fallback = _as_dict(endpoint_ingress.get("cdnFallback"))
        cdn_fallback_enabled = bool(cdn_fallback.get("enabled", False))
        shadowtls_sni = _endpoint_shadowtls_server_name(merged).lower().rstrip(".")
        endpoint_ips = {service_ip, *shard_ips}
        normalized_endpoint_ips, invalid_endpoint_ips = _valid_public_ip_set({value for value in endpoint_ips if value})
        expected_ingress_ips = set(shard_ips)
        if deployment_phase in {"entry-staged", "full"}:
            expected_ingress_ips.add(_text(entry_topology.get("publicIp")))

        require(architecture_mode == "entry-endpoint", "Endpoint ingress sharding requires architecture.mode=entry-endpoint")
        require(len(shards) == 3, "architecture.endpointIngress.shards must contain exactly three shards")
        require(len(active_shards) >= 2, "Endpoint ingress sharding requires at least two active shards")
        require(len(set(shard_ids)) == 3 and all(shard_ids), "Endpoint shard ids must be non-empty and unique")
        require(len(set(shard_ips)) == 3 and all(shard_ips), "Endpoint shard public IPs must be non-empty and unique")
        require(service_ip not in set(shard_ips), "Endpoint service/egress IP must be distinct from every shard IP")
        require(len(normalized_endpoint_ips) == 4 and not invalid_endpoint_ips, "Endpoint ingress requires four distinct public IPv4 addresses")
        require(egress_public_ips == {service_ip}, "Endpoint service-facing IP must be the only egress public IP")
        require(
            ingress_public_ips == expected_ingress_ips,
            "ingressPublicIPs must exactly match Endpoint shards plus Entry IP when Entry is deployed",
        )
        require(_text(endpoint_topology.get("publicIp")) in set(shard_ips), "topology.servers.endpoint.publicIp must be one Endpoint shard IP")
        require(all("{token}" in template for template in hostname_templates), "every Endpoint shard hostnameTemplate must contain {token}")
        require(len(set(hostname_templates)) == 3, "Endpoint shard hostnameTemplate values must be unique")
        require(8 <= _as_int(alias.get("tokenLength"), default=0) <= 48, "architecture.endpointIngress.alias.tokenLength must be in 8..48")
        require(bool(firewall.get("required", False)), "architecture.endpointIngress.firewall.required must stay true")
        require(bool(tcp_channel.get("bindShardIpsOnly", False)), "Endpoint TCP listeners must bind shard IPs only")
        require(bool(udp_channel.get("serviceIpRejectRequired", False)), "Endpoint UDP service-facing IP rejection must stay required")
        require(
            not (shadowtls_sni and shadowtls_sni in endpoint_sni_pool),
            "shadowsocks2022.shadowtls.serverNameEndpoint must not reuse an Endpoint direct SNI",
        )
        if cdn_fallback_enabled:
            cdn_host = _text(cdn_fallback.get("publicHost")).lower().rstrip(".")
            origin_shard_id = _text(cdn_fallback.get("originShardId"))
            origin_firewall = _as_dict(cdn_fallback.get("originFirewall"))
            client_policy = _as_dict(cdn_fallback.get("clientPolicy"))
            allowed_networks, invalid_allowed_networks = _valid_public_ipv4_networks(
                origin_firewall.get("allowedSourceCidrs")
            )
            active_shard_ids = {_text(shard.get("id")) for shard in active_shards}
            endpoint_tls_server_name = _text(_as_dict(transit.get("tls")).get("serverName")).lower().rstrip(".")
            service_hostname = _text(service_facing.get("hostname")).lower().rstrip(".")
            enabled_client_profiles = {
                _text(value).lower() for value in _as_list(env.get("enabledClientProfiles")) if _text(value)
            }

            require(_text(cdn_fallback.get("provider")) == "cloudflare", "Endpoint CDN fallback provider must stay cloudflare")
            require(_text(cdn_fallback.get("transport")) == "grpc-tls-h2", "Endpoint CDN fallback transport must stay grpc-tls-h2")
            require(bool(cdn_host), "architecture.endpointIngress.cdnFallback.publicHost must be set")
            require(not _is_example_host(cdn_host), "Endpoint CDN fallback publicHost must not use example.com")
            require(cdn_host == transit_default_host.lower().rstrip("."), "Endpoint CDN fallback publicHost must match the effective Endpoint host")
            require(cdn_host == endpoint_tls_server_name, "Endpoint CDN fallback publicHost must match Endpoint TLS serverName")
            require(cdn_host == service_hostname, "Endpoint CDN fallback publicHost must match serviceFacing.hostname")
            require(cdn_host not in endpoint_sni_pool, "Endpoint CDN fallback publicHost must not reuse an Endpoint direct SNI")
            require(origin_shard_id in active_shard_ids, "Endpoint CDN fallback originShardId must identify an active shard")
            require(bool(origin_firewall.get("required", False)), "Endpoint CDN fallback origin firewall must stay required")
            require(bool(origin_firewall.get("denyDirectAccess", False)), "Endpoint CDN fallback direct origin access must stay denied")
            require(bool(allowed_networks), "Endpoint CDN fallback allowedSourceCidrs must contain public IPv4 networks")
            require(not invalid_allowed_networks, "Endpoint CDN fallback allowedSourceCidrs must contain only public IPv4 networks")
            require(_as_int(client_policy.get("maxParallelHandshakes")) == 1, "Endpoint CDN fallback maxParallelHandshakes must stay 1")
            require(bool(client_policy.get("jitter", False)), "Endpoint CDN fallback reconnect jitter must stay enabled")
            require("backup-grpc" in enabled_client_profiles, "Endpoint CDN fallback requires the backup-grpc client profile")

    if deployment_phase == "entry-staged":
        endpoint_backhaul = _as_dict(interconnect.get("endpointBackhaul"))
        endpoint_backhaul_selection = _as_dict(endpoint_backhaul.get("selection"))
        endpoint_backhaul_health = _as_dict(endpoint_backhaul.get("health"))
        endpoint_backhaul_shadowtls = _as_dict(endpoint_backhaul.get("shadowtls"))
        endpoint_backhaul_hysteria = _as_dict(endpoint_backhaul.get("hysteria2"))
        endpoint_backhaul_gecko = _as_dict(endpoint_backhaul_hysteria.get("gecko"))
        hysteria_allowed_sources = {
            _text(value) for value in _as_list(endpoint_backhaul_hysteria.get("allowedSources")) if _text(value)
        }
        enabled_client_profiles = {_text(value).lower() for value in _as_list(env.get("enabledClientProfiles")) if _text(value)}
        entry_public_ip = _text(entry_topology.get("publicIp"))
        staged_entry_host = _text(env.get("defaultEntryHost")).lower().rstrip(".")
        entry_tls_server_name = _text(_as_dict(entry.get("tls")).get("serverName")).lower().rstrip(".")

        require(entry_enabled, "entry-staged requires the Entry gateway role")
        require(not universal_entry_enabled, "entry-staged forbids Universal Entry client transport")
        require(not _has_value(universal_entry.get("publicHost")), "entry-staged forbids architecture.universalEntry.publicHost")
        require(_has_value(staged_entry_host), "entry-staged defaultEntryHost must be configured")
        require(
            entry_tls_server_name == staged_entry_host,
            "entry-staged gateway.roles.entry.tls.serverName must match defaultEntryHost",
        )
        require(
            enabled_client_profiles == ENDPOINT_FIRST_CLIENT_PROFILE_KEYS,
            "entry-staged must keep bot/API issuance limited to Endpoint-direct and Backup profiles",
        )
        require(bool(endpoint_backhaul.get("enabled", False)), "entry-staged requires interconnect.endpointBackhaul.enabled=true")
        require(_text(endpoint_backhaul.get("primary")) == "shadowsocks2022-shadowtls-v3", "entry-staged primary backhaul must stay shadowsocks2022-shadowtls-v3")
        require(_text(endpoint_backhaul.get("secondary")) == "hysteria2-gecko", "entry-staged secondary backhaul must stay hysteria2-gecko")
        require(bool(_as_dict(merged.get("shadowsocks2022")).get("enabled", False)), "entry-staged ShadowTLS primary requires shadowsocks2022.enabled=true")
        require(bool(endpoint_backhaul_shadowtls.get("enabled", False)), "entry-staged ShadowTLS primary must stay enabled")
        require(_has_value(endpoint_backhaul_shadowtls.get("endpointHost")), "entry-staged ShadowTLS endpointHost is required")
        require(_as_int(endpoint_backhaul_shadowtls.get("endpointPort")) == 443, "entry-staged ShadowTLS endpointPort must stay 443")
        require(1024 <= _as_int(endpoint_backhaul_shadowtls.get("entryLocalPort")) <= 65535, "entry-staged ShadowTLS entryLocalPort must be unprivileged")
        require(
            _text(endpoint_backhaul_shadowtls.get("serverName")).lower().rstrip(".") == _endpoint_shadowtls_server_name(merged).lower().rstrip("."),
            "entry-staged ShadowTLS serverName must match the Endpoint ShadowTLS SNI",
        )
        require(_text(endpoint_backhaul_selection.get("strategy")) == "roundRobin", "entry-staged connect sharding must stay roundRobin")
        require(_text(endpoint_backhaul_selection.get("stickyScope")) == "connection", "entry-staged connect sharding must stay connection-sticky")
        require(_as_int(endpoint_backhaul_selection.get("maxParallelDials")) == 1, "entry-staged maxParallelDials must stay 1")
        require(bool(endpoint_backhaul_health.get("payloadProbeRequired", False)), "entry-staged backhaul payload probes must stay required")
        require(bool(endpoint_backhaul_hysteria.get("enabled", False)), "entry-staged Hysteria2 fallback must stay enabled")
        require(
            _as_int(endpoint_backhaul_hysteria.get("endpointPort")) == _as_int(_as_dict(transit.get("ports")).get("publicUdp")),
            "entry-staged Hysteria2 endpointPort must match Endpoint publicUdp",
        )
        require(entry_public_ip in hysteria_allowed_sources, "entry-staged Hysteria2 allowedSources must include Entry publicIp")
        require(not bool(endpoint_backhaul_hysteria.get("fastOpen", True)), "entry-staged Hysteria2 fastOpen must stay false")
        require(not bool(endpoint_backhaul_hysteria.get("lazy", True)), "entry-staged Hysteria2 lazy must stay false")
        gecko_min = _as_int(endpoint_backhaul_gecko.get("minPacketSize"))
        gecko_max = _as_int(endpoint_backhaul_gecko.get("maxPacketSize"))
        require(512 <= gecko_min <= gecko_max <= 2048, "entry-staged Hysteria2 Gecko packet sizes are invalid")

    if universal_entry_enabled:
        universal_host = _text(universal_entry.get("publicHost"))
        origin_firewall = _as_dict(universal_entry.get("originFirewall"))
        client_policy = _as_dict(universal_entry.get("clientPolicy"))
        backhaul = _as_dict(universal_entry.get("backhaul"))
        endpoint_backhaul = _as_dict(interconnect.get("endpointBackhaul"))
        endpoint_backhaul_selection = _as_dict(endpoint_backhaul.get("selection"))
        endpoint_backhaul_health = _as_dict(endpoint_backhaul.get("health"))
        endpoint_backhaul_shadowtls = _as_dict(endpoint_backhaul.get("shadowtls"))
        endpoint_backhaul_hysteria = _as_dict(endpoint_backhaul.get("hysteria2"))
        endpoint_backhaul_gecko = _as_dict(endpoint_backhaul_hysteria.get("gecko"))
        allowed_source_cidrs, invalid_source_cidrs = _valid_public_ipv4_networks(origin_firewall.get("allowedSourceCidrs"))
        enabled_client_profiles = {_text(value).lower() for value in _as_list(env.get("enabledClientProfiles")) if _text(value)}
        hysteria_allowed_sources = {
            _text(value) for value in _as_list(endpoint_backhaul_hysteria.get("allowedSources")) if _text(value)
        }
        entry_public_ip = _text(entry_topology.get("publicIp"))

        require(architecture_mode == "entry-endpoint", "Universal Entry requires architecture.mode=entry-endpoint")
        require(not entry_ingress_enabled, "Universal Entry forbids architecture.entryIngress.enabled=true")
        require(not ingress_rotation_enabled, "Universal Entry forbids architecture.ingressRotation.enabled=true")
        require(_text(universal_entry.get("provider")) == "cloudflare", "Universal Entry provider must stay cloudflare")
        require(_text(universal_entry.get("transport")) == "grpc-tls-h2", "Universal Entry transport must stay grpc-tls-h2")
        require(_has_value(universal_host), "architecture.universalEntry.publicHost must be set")
        require(not _is_example_host(universal_host), "architecture.universalEntry.publicHost must not use example.com")
        require(universal_host == entry_default_host, "Universal Entry publicHost must match the effective Entry host")
        require(
            universal_host == _text(_as_dict(entry.get("tls")).get("serverName")),
            "Universal Entry publicHost must match gateway.roles.entry.tls.serverName",
        )
        require(bool(origin_firewall.get("required", False)), "Universal Entry origin firewall must stay required")
        require(bool(origin_firewall.get("denyDirectAccess", False)), "Universal Entry origin direct access must stay denied")
        require(bool(allowed_source_cidrs), "Universal Entry origin firewall must allow current Cloudflare IPv4 source CIDRs")
        require(not invalid_source_cidrs, f"Universal Entry origin firewall contains invalid/non-public IPv4 CIDRs: {', '.join(invalid_source_cidrs)}")
        require(bool(client_policy.get("multiplexSingleTls", False)), "Universal Entry must multiplex over one TLS connection")
        require(_as_int(client_policy.get("maxParallelHandshakes")) == 1, "Universal Entry maxParallelHandshakes must stay 1")
        require(bool(client_policy.get("jitter", False)), "Universal Entry reconnect jitter must stay enabled")
        require(bool(backhaul.get("requireMultiTransportPool", False)), "Universal Entry requires a multi-transport backhaul pool")
        require(bool(backhaul.get("failClosed", False)), "Universal Entry backhaul must fail closed")
        require(bool(backhaul.get("endpointEgressOnly", False)), "Universal Entry traffic must egress through Endpoint")
        require(
            enabled_client_profiles == TRACEGATE3_CLIENT_PROFILE_KEYS,
            "Universal Entry deployment must expose the complete Tracegate 3 client profile set",
        )
        require(bool(endpoint_backhaul.get("enabled", False)), "Universal Entry requires interconnect.endpointBackhaul.enabled=true")
        require(_text(endpoint_backhaul.get("primary")) == "shadowsocks2022-shadowtls-v3", "Universal Entry primary backhaul must stay shadowsocks2022-shadowtls-v3")
        require(_text(endpoint_backhaul.get("secondary")) == "hysteria2-gecko", "Universal Entry secondary backhaul must stay hysteria2-gecko")
        require(bool(_as_dict(merged.get("shadowsocks2022")).get("enabled", False)), "Universal Entry ShadowTLS primary requires shadowsocks2022.enabled=true")
        require(bool(endpoint_backhaul_shadowtls.get("enabled", False)), "Universal Entry ShadowTLS primary must stay enabled")
        require(_has_value(endpoint_backhaul_shadowtls.get("endpointHost")), "Universal Entry ShadowTLS endpointHost is required")
        require(_as_int(endpoint_backhaul_shadowtls.get("endpointPort")) == 443, "Universal Entry ShadowTLS endpointPort must stay 443")
        require(1024 <= _as_int(endpoint_backhaul_shadowtls.get("entryLocalPort")) <= 65535, "Universal Entry ShadowTLS entryLocalPort must be unprivileged")
        require(
            _text(endpoint_backhaul_shadowtls.get("serverName")).lower().rstrip(".") == _endpoint_shadowtls_server_name(merged).lower().rstrip("."),
            "Universal Entry ShadowTLS serverName must match the Endpoint ShadowTLS SNI",
        )
        require(_text(endpoint_backhaul_selection.get("strategy")) == "roundRobin", "Universal Entry connect sharding must stay roundRobin")
        require(_text(endpoint_backhaul_selection.get("stickyScope")) == "connection", "Universal Entry connect sharding must stay connection-sticky")
        require(_as_int(endpoint_backhaul_selection.get("maxParallelDials")) == 1, "Universal Entry maxParallelDials must stay 1")
        require(bool(endpoint_backhaul_health.get("payloadProbeRequired", False)), "Universal Entry backhaul payload probes must stay required")
        require(bool(endpoint_backhaul_hysteria.get("enabled", False)), "Universal Entry Hysteria2 fallback must stay enabled")
        require(
            _as_int(endpoint_backhaul_hysteria.get("endpointPort")) == _as_int(_as_dict(transit.get("ports")).get("publicUdp")),
            "Universal Entry Hysteria2 endpointPort must match Endpoint publicUdp",
        )
        require(entry_public_ip in hysteria_allowed_sources, "Universal Entry Hysteria2 allowedSources must include Entry publicIp")
        require(not bool(endpoint_backhaul_hysteria.get("fastOpen", True)), "Universal Entry Hysteria2 fastOpen must stay false")
        require(not bool(endpoint_backhaul_hysteria.get("lazy", True)), "Universal Entry Hysteria2 lazy must stay false")
        gecko_min = _as_int(endpoint_backhaul_gecko.get("minPacketSize"))
        gecko_max = _as_int(endpoint_backhaul_gecko.get("maxPacketSize"))
        require(512 <= gecko_min <= gecko_max <= 2048, "Universal Entry Hysteria2 Gecko packet sizes are invalid")
        if endpoint_ingress_enabled:
            endpoint_shard_ips = {
                _text(_as_dict(row).get("publicIp"))
                for row in _as_list(endpoint_ingress.get("shards"))
                if _text(_as_dict(row).get("publicIp"))
            }
            require(
                ingress_public_ips == endpoint_shard_ips | {entry_public_ip},
                "full ingressPublicIPs must contain the Entry IP and three Endpoint shard IPs",
            )
        else:
            require(ingress_public_ips == {entry_public_ip}, "Universal Entry ingressPublicIPs must contain only the Entry publicIp")

    if architecture_mode == "entry-endpoint":
        require(not transit_router_enabled, "entry-endpoint forbids transitRouter.enabled=true")
        require(not link_crypto_enabled, "entry-endpoint forbids the legacy interconnect.entryTransit path")
        require(mtproto_route_mode == "entry-endpoint-tunnel", "entry-endpoint requires mtproto.route.mode=entry-endpoint-tunnel")
        if pod_runtime_only:
            require(endpoint_ingress_enabled, "entry-endpoint pod-only production requires architecture.endpointIngress.enabled=true")
            enabled_profiles = {_text(value).lower() for value in _as_list(env.get("enabledClientProfiles")) if _text(value)}
            if deployment_phase == "endpoint-first":
                require(not universal_entry_enabled, "endpoint-first forbids Universal Entry")
                require(enabled_profiles == ENDPOINT_FIRST_CLIENT_PROFILE_KEYS, "endpoint-first must expose only Endpoint-direct and Backup profiles")
            elif deployment_phase == "entry-staged":
                require(not universal_entry_enabled, "entry-staged forbids Universal Entry")
                require(
                    enabled_profiles == ENDPOINT_FIRST_CLIENT_PROFILE_KEYS,
                    "entry-staged must expose only Endpoint-direct and Backup profiles",
                )
            else:
                require(universal_entry_enabled, "full entry-endpoint deployment requires Universal Entry")
                require(enabled_profiles == TRACEGATE3_CLIENT_PROFILE_KEYS, "full deployment must expose the complete Tracegate 3 client profile set")
            require(not bool(naiveproxy.get("enabled", False)), "podRuntimeOnly forbids NaiveProxy")
            require(not bool(zapret2.get("enabled", False)), "podRuntimeOnly forbids Zapret2")
            require(not _experimental_requested(merged), "podRuntimeOnly forbids experimental profiles")
            wireguard_runtime = _as_dict(merged.get("wireguard"))
            require(bool(wireguard_runtime.get("enabled", False)), "podRuntimeOnly new production requires WireGuard-over-WebSocket")
            require(bool(_as_dict(wireguard_runtime.get("wstunnel")).get("enabled", False)), "WireGuard-over-WebSocket requires the wstunnel pod container")

    mtproto = _as_dict(merged.get("mtproto"))
    require(bool(mtproto.get("enabled", False)), "mtproto.enabled must stay true in core Tracegate 3")
    require(not _is_example_host(mtproto.get("domain")), "mtproto.domain must not use example.com")
    mtproto_egress = _as_dict(mtproto.get("egress"))
    if mtproto_route_mode == "entry-endpoint-tunnel":
        mtproto_endpoint_route = _as_dict(mtproto_route.get("endpoint"))
        mtproto_allowed_proxy_sources = _ip_set(mtproto_endpoint_route.get("allowedProxySources"))
        mtproto_stealth = _as_dict(mtproto.get("stealth"))
        mtproto_runtime = _text(mtproto.get("runtime")).lower()
        mtproto_transport = _text(mtproto.get("transport")).lower()
        if mtproto_transport == "dd":
            mtproto_transport = "random_padding"
        tls_domain = _text(mtproto.get("tlsDomain")).lower().rstrip(".")
        require(mtproto_runtime in {"mtg", "official"}, "entry-endpoint-tunnel requires mtproto.runtime=mtg or official")
        require(_as_int(mtproto.get("publicPort")) == 443, "entry-endpoint-tunnel requires mtproto.publicPort=443")
        require(not bool(_as_dict(mtproto.get("fallback")).get("enabled", False)), "entry-endpoint-tunnel forbids fallback runtimes")
        require(
            _text(entry_topology.get("publicIp")) in mtproto_allowed_proxy_sources,
            "entry-endpoint-tunnel endpoint.allowedProxySources must include the Entry publicIp",
        )
        if mtproto_runtime == "official":
            mtproto_fallback = _as_dict(mtproto.get("fallback"))
            official_bind_address = _text(mtproto_fallback.get("officialBindAddress"))
            official_external_ip = _text(mtproto_fallback.get("officialExternalIp"))
            require(
                mtproto_transport in {"raw", "random_padding"},
                "entry-endpoint-tunnel official MTProto requires mtproto.transport=raw or random_padding",
            )
            require(not tls_domain, "entry-endpoint-tunnel official no-SNI MTProto requires empty mtproto.tlsDomain")
            require(not official_bind_address, "entry-endpoint-tunnel official MTProxy must not set officialBindAddress")
            require(
                official_external_ip in egress_public_ips,
                "entry-endpoint-tunnel officialExternalIp must be an Endpoint egress public IP",
            )
        else:
            require(tls_domain not in {"front-g.example.net", "splitter.front-m.example.net"}, "entry-endpoint-tunnel forbids common MTProto TLS domains")
            require(
                tls_domain in {_text(value).lower().rstrip(".") for value in _as_list(mtproto_stealth.get("validatedTlsDomains"))},
                "entry-endpoint-tunnel tlsDomain must be prevalidated",
            )
    if mtproto_route_mode == "entry-local-endpoint-egress":
        mtproto_egress_shadowtls = _as_dict(mtproto_egress.get("shadowtls"))
        require(_text(mtproto.get("runtime")) == "mtg", "entry-local-endpoint-egress requires mtproto.runtime=mtg")
        require(
            bool(_as_dict(interconnect.get("endpointBackhaul")).get("enabled", False)),
            "entry-local-endpoint-egress requires interconnect.endpointBackhaul.enabled=true",
        )
        require(_text(mtproto_egress.get("mode")) == "socks5-only", "entry-local-endpoint-egress requires mtproto.egress.mode=socks5-only")
        require(_as_int(mtproto_egress.get("socksPort")) > 0, "entry-local-endpoint-egress requires mtproto.egress.socksPort")
        require(_has_value(mtproto_egress.get("domainFrontingHost")), "entry-local-endpoint-egress requires mtproto.egress.domainFrontingHost")
        require(not bool(_as_dict(mtproto.get("fallback")).get("enabled", False)), "entry-local-endpoint-egress forbids MTProto fallback runtimes")
        require(bool(mtproto_egress_shadowtls.get("enabled", False)), "entry-local-endpoint-egress requires mtproto.egress.shadowtls.enabled=true")
        require(
            _has_value(mtproto_egress_shadowtls.get("serverName"))
            and _text(mtproto_egress_shadowtls.get("serverName")).lower().rstrip(".") not in {"front-g.example.net", "splitter.front-m.example.net"},
            "mtproto.egress.shadowtls.serverName must use a non-empty, non-common camouflage domain",
        )
        require(_has_value(mtproto_egress_shadowtls.get("endpointHost")), "mtproto.egress.shadowtls.endpointHost must be set")
        require(_as_int(mtproto_egress_shadowtls.get("endpointPort")) == 443, "mtproto.egress.shadowtls.endpointPort must stay 443")
        require(bool(mtproto_egress_shadowtls.get("allowedSources")), "mtproto.egress.shadowtls.allowedSources must include Entry source addresses")
    if link_crypto_enabled:
        bridge_server_name = _text(outer_carrier.get("serverName")).lower().rstrip(".")
        transit_tls_server_name = _text(_as_dict(transit.get("tls")).get("serverName")).lower().rstrip(".")
        mtproto_domain = _text(mtproto.get("domain") or env.get("mtprotoDomain")).lower().rstrip(".")
        require(bridge_server_name != transit_tls_server_name, f"bridge WSS serverName must be separate from gateway.roles.{endpoint_role_key}.tls.serverName")
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
