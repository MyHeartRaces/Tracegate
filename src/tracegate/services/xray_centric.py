from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class XrayCentricRenderError(RuntimeError):
    pass


_XRAY_CENTRIC_OVERLAY_MANIFEST_FILE_NAME = ".tracegate-overlay-manifest.json"


def _env(environ: dict[str, str], name: str, default: str = "") -> str:
    return str(environ.get(name, default) or "").strip()


def _require(environ: dict[str, str], name: str) -> str:
    value = _env(environ, name)
    if not value:
        raise XrayCentricRenderError(f"missing required env: {name}")
    return value


def _load_optional_json_file(path_raw: str, *, label: str) -> dict[str, Any] | None:
    path_value = str(path_raw or "").strip()
    if not path_value:
        return None
    path = Path(path_value)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise XrayCentricRenderError(f"{label} file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise XrayCentricRenderError(f"{label} must contain a JSON object: {path}") from exc
    if not isinstance(payload, dict):
        raise XrayCentricRenderError(f"{label} must contain a JSON object: {path}")
    return payload


def _load_optional_text_file(path_raw: str, *, label: str) -> str:
    path_value = str(path_raw or "").strip()
    if not path_value:
        return ""
    path = Path(path_value)
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise XrayCentricRenderError(f"{label} file not found: {path}") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _detect_hysteria_flags(payload: dict[str, Any]) -> tuple[bool, bool]:
    finalmask_enabled = False
    ech_enabled = False
    for inbound in payload.get("inbounds", []):
        if not isinstance(inbound, dict):
            continue
        stream = inbound.get("streamSettings")
        if not isinstance(stream, dict):
            continue
        if stream.get("network") != "hysteria":
            continue
        if stream.get("finalmask"):
            finalmask_enabled = True
        tls_settings = stream.get("tlsSettings")
        if isinstance(tls_settings, dict) and (tls_settings.get("echServerKeys") or tls_settings.get("echConfigList")):
            ech_enabled = True
    return finalmask_enabled, ech_enabled


@dataclass(frozen=True)
class XrayCentricOverlayRenderContext:
    source_root: Path
    materialized_root: Path | None
    overlay_root: Path
    bootstrap_auth: str
    decoy_dir: str
    tls_cert_file: str = "/etc/tracegate/tls/ws.crt"
    tls_key_file: str = "/etc/tracegate/tls/ws.key"
    entry_finalmask: dict[str, Any] | None = None
    transit_finalmask: dict[str, Any] | None = None
    entry_ech_server_keys: str = ""
    transit_ech_server_keys: str = ""

    @classmethod
    def from_environ(cls, environ: dict[str, str] | None = None) -> "XrayCentricOverlayRenderContext":
        env = dict(os.environ if environ is None else environ)
        source_root = Path(_require(env, "BUNDLE_SOURCE_ROOT"))
        materialized_root_raw = _env(env, "BUNDLE_MATERIALIZED_ROOT")
        materialized_root = Path(materialized_root_raw) if materialized_root_raw else None
        overlay_root = Path(_require(env, "BUNDLE_PRIVATE_OVERLAY_ROOT"))
        bootstrap_auth = _require(env, "HYSTERIA_BOOTSTRAP_PASSWORD")
        decoy_dir = _env(env, "XRAY_CENTRIC_DECOY_DIR", "/var/www/decoy") or "/var/www/decoy"
        tls_cert_file = _env(env, "XRAY_CENTRIC_TLS_CERT_FILE", "/etc/tracegate/tls/ws.crt") or "/etc/tracegate/tls/ws.crt"
        tls_key_file = _env(env, "XRAY_CENTRIC_TLS_KEY_FILE", "/etc/tracegate/tls/ws.key") or "/etc/tracegate/tls/ws.key"
        entry_finalmask = _load_optional_json_file(
            _env(env, "XRAY_HYSTERIA_FINALMASK_ENTRY_FILE") or _env(env, "XRAY_HYSTERIA_FINALMASK_FILE"),
            label="entry FinalMask",
        )
        transit_finalmask = _load_optional_json_file(
            _env(env, "XRAY_HYSTERIA_FINALMASK_TRANSIT_FILE") or _env(env, "XRAY_HYSTERIA_FINALMASK_FILE"),
            label="transit FinalMask",
        )
        entry_ech_server_keys = _load_optional_text_file(
            _env(env, "XRAY_HYSTERIA_ECH_SERVER_KEYS_ENTRY_FILE")
            or _env(env, "XRAY_HYSTERIA_ECH_SERVER_KEYS_FILE"),
            label="entry ECH server keys",
        )
        transit_ech_server_keys = _load_optional_text_file(
            _env(env, "XRAY_HYSTERIA_ECH_SERVER_KEYS_TRANSIT_FILE")
            or _env(env, "XRAY_HYSTERIA_ECH_SERVER_KEYS_FILE"),
            label="transit ECH server keys",
        )
        return cls(
            source_root=source_root,
            materialized_root=materialized_root,
            overlay_root=overlay_root,
            bootstrap_auth=bootstrap_auth,
            decoy_dir=decoy_dir,
            tls_cert_file=tls_cert_file,
            tls_key_file=tls_key_file,
            entry_finalmask=entry_finalmask,
            transit_finalmask=transit_finalmask,
            entry_ech_server_keys=entry_ech_server_keys,
            transit_ech_server_keys=transit_ech_server_keys,
        )


def build_xray_hysteria_inbound(
    *,
    tag: str = "hy2-in",
    listen: str = "0.0.0.0",
    port: int = 443,
    bootstrap_auth: str = "bootstrap-password",
    decoy_dir: str = "/var/www/decoy",
    tls_cert_file: str = "/etc/tracegate/tls/ws.crt",
    tls_key_file: str = "/etc/tracegate/tls/ws.key",
    finalmask: dict[str, Any] | None = None,
    ech_server_keys: str = "",
) -> dict[str, Any]:
    tls_settings: dict[str, Any] = {
        "alpn": ["h3"],
        "certificates": [
            {
                "certificateFile": tls_cert_file,
                "keyFile": tls_key_file,
            }
        ]
    }
    if ech_server_keys:
        tls_settings["echServerKeys"] = ech_server_keys

    stream_settings: dict[str, Any] = {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": tls_settings,
        "hysteriaSettings": {
            "version": 2,
            "auth": bootstrap_auth,
            "udpIdleTimeout": 60,
            "masquerade": {
                "type": "file",
                "dir": decoy_dir,
            },
        },
    }
    if finalmask:
        stream_settings["finalmask"] = copy.deepcopy(finalmask)

    return {
        "tag": tag,
        "listen": listen,
        "port": port,
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "clients": [],
        },
        "streamSettings": stream_settings,
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
        },
    }


def render_xray_centric_xray_config(
    base_config: dict[str, Any],
    *,
    role: str,
    bootstrap_auth: str = "bootstrap-password",
    decoy_dir: str = "/var/www/decoy",
    tls_cert_file: str = "/etc/tracegate/tls/ws.crt",
    tls_key_file: str = "/etc/tracegate/tls/ws.key",
    finalmask: dict[str, Any] | None = None,
    ech_server_keys: str = "",
) -> dict[str, Any]:
    rendered = copy.deepcopy(base_config)
    role_upper = str(role or "").strip().upper()
    if role_upper not in {"ENTRY", "TRANSIT"}:
        raise ValueError(f"unsupported role for xray-centric scaffold: {role}")

    inbounds = rendered.get("inbounds")
    if not isinstance(inbounds, list):
        inbounds = []
        rendered["inbounds"] = inbounds

    filtered_inbounds: list[dict[str, Any]] = []
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            filtered_inbounds.append(inbound)
            continue
        if inbound.get("protocol") == "hysteria":
            continue
        filtered_inbounds.append(inbound)
    filtered_inbounds.append(
        build_xray_hysteria_inbound(
            bootstrap_auth=bootstrap_auth,
            decoy_dir=decoy_dir,
            tls_cert_file=tls_cert_file,
            tls_key_file=tls_key_file,
            finalmask=finalmask,
            ech_server_keys=ech_server_keys,
        )
    )
    rendered["inbounds"] = filtered_inbounds

    routing = rendered.setdefault("routing", {})
    if not isinstance(routing, dict):
        routing = {}
        rendered["routing"] = routing
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        rules = []
        routing["rules"] = rules

    has_hy2_rule = False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        inbound_tags = rule.get("inboundTag")
        if not isinstance(inbound_tags, list):
            continue
        normalized_tags = [str(tag or "").strip() for tag in inbound_tags]
        if "hy2-in" in normalized_tags:
            has_hy2_rule = True

    if not has_hy2_rule:
        hy2_rule = {
            "type": "field",
            "inboundTag": ["hy2-in"],
            "outboundTag": "to-transit" if role_upper == "ENTRY" else "direct",
        }
        if role_upper == "ENTRY":
            insert_at = len(rules)
            for idx, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    continue
                outbound_tag = str(rule.get("outboundTag") or "").strip()
                inbound_tags = rule.get("inboundTag")
                if outbound_tag == "to-transit" and isinstance(inbound_tags, list):
                    insert_at = idx
                    break
            rules.insert(insert_at, hy2_rule)
        else:
            insert_at = len(rules)
            for idx, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    continue
                outbound_tag = str(rule.get("outboundTag") or "").strip()
                if outbound_tag == "block":
                    insert_at = idx
                    break
            rules.insert(insert_at, hy2_rule)

    return rendered


def _load_xray_bundle(ctx: XrayCentricOverlayRenderContext, bundle_name: str) -> tuple[dict[str, Any], Path]:
    candidate_paths: list[Path] = []
    if ctx.materialized_root is not None:
        candidate_paths.append(ctx.materialized_root / bundle_name / "xray.json")
    candidate_paths.append(ctx.source_root / bundle_name / "xray.json")
    for path in candidate_paths:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8")), path
    raise XrayCentricRenderError(f"xray bundle not found for {bundle_name}")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def _write_overlay_manifest(
    ctx: XrayCentricOverlayRenderContext,
    *,
    entry_source_path: Path,
    transit_source_path: Path,
) -> None:
    overlays: list[dict[str, Any]] = []
    for role_upper, relative_path, source_path in (
        ("ENTRY", Path("entry") / "xray.json", entry_source_path),
        ("TRANSIT", Path("transit") / "xray.json", transit_source_path),
    ):
        target_path = ctx.overlay_root / relative_path
        payload = json.loads(target_path.read_text(encoding="utf-8"))
        finalmask_enabled, ech_enabled = _detect_hysteria_flags(payload)
        overlays.append(
            {
                "role": role_upper,
                "path": relative_path.as_posix(),
                "sourcePath": str(source_path),
                "sha256": _sha256_file(target_path),
                "sizeBytes": int(target_path.stat().st_size),
                "targetUnit": f"tracegate-xray@{role_upper.lower()}",
                "features": {
                    "runtimeProfile": "xray-centric",
                    "finalMaskEnabled": finalmask_enabled,
                    "echEnabled": ech_enabled,
                },
            }
        )
    _write_json(
        ctx.overlay_root / _XRAY_CENTRIC_OVERLAY_MANIFEST_FILE_NAME,
        {
            "version": 1,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "runtimeProfile": "xray-centric",
            "overlayRoot": str(ctx.overlay_root),
            "materializedRoot": str(ctx.materialized_root) if ctx.materialized_root is not None else "",
            "sourceRoot": str(ctx.source_root),
            "overlays": overlays,
        },
    )


def render_xray_centric_private_overlays(ctx: XrayCentricOverlayRenderContext) -> None:
    entry_base, entry_source_path = _load_xray_bundle(ctx, "base-entry")
    transit_base, transit_source_path = _load_xray_bundle(ctx, "base-transit")

    entry_rendered = render_xray_centric_xray_config(
        entry_base,
        role="ENTRY",
        bootstrap_auth=ctx.bootstrap_auth,
        decoy_dir=ctx.decoy_dir,
        tls_cert_file=ctx.tls_cert_file,
        tls_key_file=ctx.tls_key_file,
        finalmask=ctx.entry_finalmask,
        ech_server_keys=ctx.entry_ech_server_keys,
    )
    transit_rendered = render_xray_centric_xray_config(
        transit_base,
        role="TRANSIT",
        bootstrap_auth=ctx.bootstrap_auth,
        decoy_dir=ctx.decoy_dir,
        tls_cert_file=ctx.tls_cert_file,
        tls_key_file=ctx.tls_key_file,
        finalmask=ctx.transit_finalmask,
        ech_server_keys=ctx.transit_ech_server_keys,
    )

    _write_json(ctx.overlay_root / "entry" / "xray.json", entry_rendered)
    _write_json(ctx.overlay_root / "transit" / "xray.json", transit_rendered)
    _write_overlay_manifest(
        ctx,
        entry_source_path=entry_source_path,
        transit_source_path=transit_source_path,
    )
