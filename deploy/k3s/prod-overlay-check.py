#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections.abc import Mapping
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
    require(bool(socks5.get("required", False)), "transportProfiles.socks5.required must stay true")
    require(not bool(socks5.get("allowAnonymousLocalhost", False)), "transportProfiles.socks5.allowAnonymousLocalhost must stay false")

    rollout = _as_dict(gateway.get("rollingUpdate"))
    private_preflight = _as_dict(gateway.get("privatePreflight"))
    require(_text(gateway.get("strategy")) == "RollingUpdate", "gateway.strategy must stay RollingUpdate for production")
    require(not bool(gateway.get("allowRecreateStrategy", False)), "gateway.allowRecreateStrategy must stay false for production")
    require(_text(rollout.get("maxUnavailable")) == "0", "gateway.rollingUpdate.maxUnavailable must stay 0")
    require(bool(_as_dict(gateway.get("pdb")).get("enabled", False)), "gateway.pdb.enabled must stay true")
    require(bool(_as_dict(gateway.get("probes")).get("enabled", False)), "gateway.probes.enabled must stay true")
    require(bool(private_preflight.get("enabled", False)), "gateway.privatePreflight.enabled must stay true")
    require(bool(private_preflight.get("forbidPlaceholders", False)), "gateway.privatePreflight.forbidPlaceholders must stay true")

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

    mtproto = _as_dict(merged.get("mtproto"))
    require(bool(mtproto.get("enabled", False)), "mtproto.enabled must stay true in core Tracegate 2.1")
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
