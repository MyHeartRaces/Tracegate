#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml


class ClusterPreflightError(RuntimeError):
    pass


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


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _enabled(value: Any) -> bool:
    return bool(value)


def _kubectl_json(kubectl: str, context: str, args: list[str]) -> dict[str, Any]:
    cmd = [kubectl]
    if context:
        cmd.extend(["--context", context])
    cmd.extend(args)
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise ClusterPreflightError((result.stderr or result.stdout or "kubectl command failed").strip())
    try:
        parsed = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ClusterPreflightError(f"kubectl returned invalid JSON for {' '.join(args)}") from exc
    if not isinstance(parsed, dict):
        raise ClusterPreflightError(f"kubectl returned non-object JSON for {' '.join(args)}")
    return parsed


def _label_selector(selector: Mapping[str, Any]) -> str:
    parts: list[str] = []
    for key, value in sorted(selector.items()):
        key_text = _text(key)
        value_text = _text(value)
        if not key_text:
            continue
        parts.append(f"{key_text}={value_text}" if value_text else key_text)
    return ",".join(parts)


def _csv_set(value: Any) -> set[str]:
    raw = _text(value)
    if not raw:
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


def _values_set(value: Any) -> set[str]:
    if isinstance(value, list):
        return {item for item in (_text(item) for item in value) if item}
    text = _text(value)
    return {text} if text else set()


def _private_profile_secret_keys(values: dict[str, Any]) -> set[str]:
    private_profiles = _as_dict(values.get("privateProfiles"))
    secret_keys = _as_dict(private_profiles.get("secretKeys"))
    gateway = _as_dict(values.get("gateway"))
    roles = _as_dict(gateway.get("roles"))
    interconnect = _as_dict(values.get("interconnect"))
    entry_transit = _as_dict(interconnect.get("entryTransit"))
    mieru = _as_dict(interconnect.get("mieru"))
    zapret2 = _as_dict(interconnect.get("zapret2"))
    shadowsocks2022 = _as_dict(values.get("shadowsocks2022"))
    wireguard = _as_dict(values.get("wireguard"))
    mtproto = _as_dict(values.get("mtproto"))
    experimental = _as_dict(values.get("experimentalProfiles"))
    direct_obfuscation = _as_dict(experimental.get("directTransitObfuscation"))
    tuic = _as_dict(experimental.get("tuicV5"))

    required: set[str] = set()
    for role_name in ("entry", "transit"):
        role = _as_dict(roles.get(role_name))
        if not _enabled(role.get("enabled")):
            continue
        suffix = "Entry" if role_name == "entry" else "Transit"
        required.add(_text(secret_keys.get(f"realityPrivateKey{suffix}")))
        required.add(_text(secret_keys.get(f"hysteriaSalamander{suffix}")))
        required.add(_text(secret_keys.get(f"hysteriaStats{suffix}")))

        link_client_enabled = (
            _enabled(mieru.get("enabled")) and _enabled(entry_transit.get("enabled")) and role_name == "entry"
        )
        link_server_enabled = _enabled(mieru.get("enabled")) and (
            (role_name == "transit" and _enabled(entry_transit.get("enabled")))
            or (role_name == "entry" and _enabled(_as_dict(entry_transit.get("routerEntry")).get("enabled")))
            or (role_name == "transit" and _enabled(_as_dict(entry_transit.get("routerTransit")).get("enabled")))
        )
        link_crypto_enabled = link_client_enabled or link_server_enabled
        if link_client_enabled:
            required.add(_text(secret_keys.get("mieruClient")))
        if link_server_enabled:
            required.add(_text(secret_keys.get("mieruServer")))

        if _enabled(zapret2.get("enabled")):
            required.add(_text(secret_keys.get(f"zapret{suffix}")))
            if link_crypto_enabled:
                required.add(_text(secret_keys.get("zapretInterconnect")))
            if role_name == "transit" and _enabled(mtproto.get("enabled")):
                required.add(_text(secret_keys.get("zapretMtproto")))

        if _enabled(shadowsocks2022.get("enabled")):
            required.add(_text(secret_keys.get(f"shadowsocks2022{suffix}")))
            required.add(_text(secret_keys.get(f"shadowtls{suffix}")))

        if role_name == "transit" and _enabled(wireguard.get("enabled")):
            required.add(_text(secret_keys.get("wireguard")))
        if role_name == "transit" and _enabled(mtproto.get("enabled")):
            required.add(_text(secret_keys.get("mtproto")))

        lab_direct_enabled = (
            role_name == "transit"
            and _enabled(experimental.get("enabled"))
            and _enabled(direct_obfuscation.get("enabled"))
        )
        if lab_direct_enabled and _enabled(_as_dict(direct_obfuscation.get("mieru")).get("enabled")):
            required.add(_text(secret_keys.get("labMieruDirect")))
        if lab_direct_enabled and _enabled(_as_dict(direct_obfuscation.get("restls")).get("enabled")):
            required.add(_text(secret_keys.get("labRestlsDirect")))

        lab_tuic_enabled = _enabled(experimental.get("enabled")) and _enabled(tuic.get("enabled")) and (
            (role_name == "transit" and _enabled(tuic.get("directEnabled"))) or _enabled(tuic.get("chainEnabled"))
        )
        if lab_tuic_enabled:
            required.add(_text(secret_keys.get(f"labTuic{suffix}")))

    return {key for key in required if key}


def _check_secret(
    *,
    kubectl: str,
    context: str,
    namespace: str,
    name: str,
    keys: set[str],
    errors: list[str],
) -> int:
    try:
        secret = _kubectl_json(kubectl, context, ["get", "secret", name, "-n", namespace, "-o", "json"])
    except ClusterPreflightError as exc:
        errors.append(f"missing Secret {namespace}/{name}: {exc}")
        return 0
    data = _as_dict(secret.get("data"))
    missing = sorted(key for key in keys if not _text(data.get(key)))
    if missing:
        errors.append(f"Secret {namespace}/{name} is missing data keys: {', '.join(missing)}")
    return 1


def _check_resource(
    *,
    kubectl: str,
    context: str,
    namespace: str,
    kind: str,
    name: str,
    errors: list[str],
) -> int:
    try:
        _kubectl_json(kubectl, context, ["get", kind, name, "-n", namespace, "-o", "json"])
    except ClusterPreflightError as exc:
        errors.append(f"missing {kind} {namespace}/{name}: {exc}")
        return 0
    return 1


def validate_cluster(
    *,
    chart_values: Path,
    values_path: Path,
    namespace_override: str,
    kubectl: str,
    context: str,
) -> tuple[list[str], dict[str, int | str]]:
    values = _merge_values(_read_yaml(chart_values), _read_yaml(values_path))
    namespace = namespace_override or _text(_as_dict(values.get("namespace")).get("name")) or "tracegate"
    errors: list[str] = []
    checked_secrets = 0
    checked_nodes = 0
    checked_egress_nodes = 0
    checked_decoy_resources = 0

    try:
        _kubectl_json(kubectl, context, ["get", "namespace", namespace, "-o", "json"])
    except ClusterPreflightError as exc:
        errors.append(f"missing namespace {namespace}: {exc}")

    control_plane = _as_dict(values.get("controlPlane"))
    if _enabled(control_plane.get("enabled")):
        auth = _as_dict(control_plane.get("auth"))
        auth_secret = _text(auth.get("existingSecretName"))
        if auth_secret:
            required_auth_keys = {"api-internal-token", "agent-auth-token"}
            if int(_as_dict(control_plane.get("replicas")).get("bot") or 0) > 0:
                required_auth_keys.add("bot-token")
            checked_secrets += _check_secret(
                kubectl=kubectl,
                context=context,
                namespace=namespace,
                name=auth_secret,
                keys=required_auth_keys,
                errors=errors,
            )

        database = _as_dict(control_plane.get("database"))
        external_url_secret = _as_dict(database.get("externalUrlSecret"))
        database_secret = _text(external_url_secret.get("name"))
        if database_secret and not _text(database.get("externalUrl")):
            checked_secrets += _check_secret(
                kubectl=kubectl,
                context=context,
                namespace=namespace,
                name=database_secret,
                keys={_text(external_url_secret.get("key")) or "url"},
                errors=errors,
            )

    private_profiles = _as_dict(values.get("privateProfiles"))
    private_secret = _text(private_profiles.get("existingSecretName"))
    if _enabled(private_profiles.get("required")) and private_secret:
        checked_secrets += _check_secret(
            kubectl=kubectl,
            context=context,
            namespace=namespace,
            name=private_secret,
            keys=_private_profile_secret_keys(values),
            errors=errors,
        )

    gateway = _as_dict(values.get("gateway"))
    roles = _as_dict(gateway.get("roles"))
    egress_isolation = _as_dict(_as_dict(values.get("network")).get("egressIsolation"))
    node_annotations = _as_dict(egress_isolation.get("nodeAnnotations"))
    check_egress_annotations = _enabled(node_annotations.get("enabled"))
    ingress_annotation_key = _text(node_annotations.get("ingressPublicIP")) or "tracegate.io/ingress-public-ip"
    egress_annotation_key = _text(node_annotations.get("egressPublicIP")) or "tracegate.io/egress-public-ip"
    expected_ingress_ips = _values_set(egress_isolation.get("ingressPublicIPs"))
    expected_egress_ips = _values_set(egress_isolation.get("egressPublicIPs"))
    for role_name in ("entry", "transit"):
        role = _as_dict(roles.get(role_name))
        if not _enabled(role.get("enabled")):
            continue
        tls_secret = _text(_as_dict(role.get("tls")).get("existingSecretName"))
        if tls_secret:
            checked_secrets += _check_secret(
                kubectl=kubectl,
                context=context,
                namespace=namespace,
                name=tls_secret,
                keys={"tls.crt", "tls.key"},
                errors=errors,
            )

        selector = _as_dict(role.get("nodeSelector"))
        if selector:
            label_selector = _label_selector(selector)
            try:
                nodes = _kubectl_json(kubectl, context, ["get", "nodes", "-l", label_selector, "-o", "json"])
            except ClusterPreflightError as exc:
                errors.append(f"nodeSelector for {role_name} failed ({label_selector}): {exc}")
                continue
            items = nodes.get("items") if isinstance(nodes.get("items"), list) else []
            if not items:
                errors.append(f"nodeSelector for {role_name} matched 0 nodes: {label_selector}")
            else:
                checked_nodes += len(items)
                if check_egress_annotations:
                    for item in items:
                        metadata = _as_dict(item.get("metadata"))
                        node_name = _text(metadata.get("name")) or "<unknown>"
                        annotations = _as_dict(metadata.get("annotations"))
                        ingress_ips = _csv_set(annotations.get(ingress_annotation_key))
                        if not ingress_ips:
                            errors.append(f"node {node_name} is missing {ingress_annotation_key} annotation")
                        elif expected_ingress_ips and not ingress_ips.intersection(expected_ingress_ips):
                            errors.append(
                                f"node {node_name} {ingress_annotation_key}={','.join(sorted(ingress_ips))} "
                                "does not match network.egressIsolation.ingressPublicIPs"
                            )
                        if role_name == "transit":
                            egress_ips = _csv_set(annotations.get(egress_annotation_key))
                            if not egress_ips:
                                errors.append(f"node {node_name} is missing {egress_annotation_key} annotation")
                            elif expected_egress_ips and not egress_ips.intersection(expected_egress_ips):
                                errors.append(
                                    f"node {node_name} {egress_annotation_key}={','.join(sorted(egress_ips))} "
                                    "does not match network.egressIsolation.egressPublicIPs"
                                )
                            if ingress_ips and egress_ips and ingress_ips.intersection(egress_ips):
                                errors.append(f"node {node_name} ingress and egress public IP annotations must be disjoint")
                            checked_egress_nodes += 1

    decoy = _as_dict(values.get("decoy"))
    if _text(decoy.get("existingConfigMap")):
        checked_decoy_resources += _check_resource(
            kubectl=kubectl,
            context=context,
            namespace=namespace,
            kind="configmap",
            name=_text(decoy.get("existingConfigMap")),
            errors=errors,
        )
    if _text(decoy.get("existingClaim")):
        checked_decoy_resources += _check_resource(
            kubectl=kubectl,
            context=context,
            namespace=namespace,
            kind="pvc",
            name=_text(decoy.get("existingClaim")),
            errors=errors,
        )

    return errors, {
        "namespace": namespace,
        "secrets": checked_secrets,
        "nodes": checked_nodes,
        "egressNodes": checked_egress_nodes,
        "decoyResources": checked_decoy_resources,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate existing k3s cluster prerequisites for Tracegate.")
    parser.add_argument("--chart-values", required=True, type=Path, help="Base chart values.yaml")
    parser.add_argument("--values", required=True, type=Path, help="Production values overlay")
    parser.add_argument("--namespace", default="", help="Override namespace from values")
    parser.add_argument("--kubectl", default="kubectl", help="kubectl binary/path")
    parser.add_argument("--context", default="", help="kubectl context")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    errors, summary = validate_cluster(
        chart_values=args.chart_values,
        values_path=args.values,
        namespace_override=args.namespace,
        kubectl=args.kubectl,
        context=args.context,
    )
    if errors:
        for error in errors:
            print(f"cluster-preflight: {error}", file=sys.stderr)
        return 1
    print(
        "cluster-preflight: OK "
        f"namespace={summary['namespace']} "
        f"secrets={summary['secrets']} "
        f"nodes={summary['nodes']} "
        f"egress_nodes={summary['egressNodes']} "
        f"decoy_resources={summary['decoyResources']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
