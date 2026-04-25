from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tracegate.services.xray_centric import render_xray_centric_xray_config


class MaterializedBundleRenderError(RuntimeError):
    pass


_MATERIALIZED_MANIFEST_FILE_NAME = ".tracegate-deploy-manifest.json"


def _env(environ: dict[str, str], name: str, default: str = "") -> str:
    return str(environ.get(name, default) or "").strip()


def _require(environ: dict[str, str], name: str) -> str:
    value = _env(environ, name)
    if not value:
        raise MaterializedBundleRenderError(f"missing required env: {name}")
    return value


def _first(environ: dict[str, str], *names: str, default: str = "") -> str:
    for name in names:
        value = _env(environ, name)
        if value:
            return value
    return default


def _require_first(environ: dict[str, str], *names: str) -> str:
    value = _first(environ, *names)
    if not value:
        raise MaterializedBundleRenderError(f"missing required env: {' or '.join(names)}")
    return value


def _load_optional_json_file(path_raw: str, *, label: str) -> dict[str, Any] | None:
    path_value = str(path_raw or "").strip()
    if not path_value:
        return None
    path = Path(path_value)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MaterializedBundleRenderError(f"{label} file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise MaterializedBundleRenderError(f"{label} must contain a JSON object: {path}") from exc
    if not isinstance(payload, dict):
        raise MaterializedBundleRenderError(f"{label} must contain a JSON object: {path}")
    return payload


def _load_optional_text_file(path_raw: str, *, label: str) -> str:
    path_value = str(path_raw or "").strip()
    if not path_value:
        return ""
    path = Path(path_value)
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise MaterializedBundleRenderError(f"{label} file not found: {path}") from exc


def _normalize_decoy_secret_path(path_raw: str, *, default: str = "/vault/mtproto/") -> str:
    raw = str(path_raw or "").strip()
    if not raw:
        return default
    raw = raw.split("?", 1)[0].split("#", 1)[0].strip()
    if not raw:
        return default
    if not raw.startswith("/"):
        raw = "/" + raw
    parts = [part.strip() for part in raw.split("/") if part.strip() not in {"", ".", ".."}]
    if not parts:
        return default
    return "/" + "/".join(parts) + "/"


def host_from_dest(dest: str) -> str:
    raw = str(dest or "").strip()
    if not raw:
        return ""
    if raw.startswith("[") and "]" in raw:
        return raw[1 : raw.index("]")]
    if raw.count(":") == 1:
        return raw.split(":", 1)[0].strip()
    return raw


def _haproxy_server_address(value: str, *, label: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise MaterializedBundleRenderError(f"{label} is required")
    if raw.startswith("["):
        if "]:" not in raw:
            raise MaterializedBundleRenderError(f"{label} must use host:port")
        host, port_raw = raw.rsplit(":", 1)
    else:
        if raw.count(":") != 1:
            raise MaterializedBundleRenderError(f"{label} must use host:port")
        host, port_raw = raw.split(":", 1)
    host = host.strip()
    port_raw = port_raw.strip()
    if not host or not re.fullmatch(r"\[?[A-Za-z0-9_.:-]+\]?", host):
        raise MaterializedBundleRenderError(f"{label} has invalid host")
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise MaterializedBundleRenderError(f"{label} has invalid port") from exc
    if port < 1 or port > 65535:
        raise MaterializedBundleRenderError(f"{label} has invalid port")
    return f"{host}:{port}"


@dataclass(frozen=True)
class MaterializedRealityInboundGroup:
    id: str
    port: int
    dest_host: str
    snis: tuple[str, ...]


def _load_reality_multi_inbound_groups(environ: dict[str, str]) -> tuple[MaterializedRealityInboundGroup, ...]:
    raw = _env(environ, "REALITY_MULTI_INBOUND_GROUPS")
    if not raw:
        return ()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MaterializedBundleRenderError("REALITY_MULTI_INBOUND_GROUPS must be valid JSON") from exc
    if not isinstance(payload, list):
        raise MaterializedBundleRenderError("REALITY_MULTI_INBOUND_GROUPS must be a JSON array")

    groups: list[MaterializedRealityInboundGroup] = []
    seen_ids: set[str] = set()
    seen_ports: set[int] = set()
    seen_snis: set[str] = set()
    for idx, row in enumerate(payload):
        if not isinstance(row, dict):
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] must be an object")
        group_id = str(row.get("id") or "").strip().lower()
        if not group_id:
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] is missing id")
        if group_id in seen_ids:
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] duplicates id {group_id}")
        try:
            port = int(row.get("port"))
        except Exception as exc:
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] has invalid port") from exc
        if port < 1 or port > 65535:
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] has invalid port {port}")
        if port in seen_ports:
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] duplicates port {port}")
        dest_host = host_from_dest(str(row.get("dest") or "").strip()).strip().lower()
        if not dest_host:
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] is missing dest")
        snis_raw = row.get("snis")
        if not isinstance(snis_raw, list):
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] must include snis[]")
        group_snis: list[str] = []
        local_seen: set[str] = set()
        for sni_raw in snis_raw:
            sni = str(sni_raw or "").strip().lower()
            if not sni or sni in local_seen:
                continue
            if sni in seen_snis:
                raise MaterializedBundleRenderError(
                    f"REALITY_MULTI_INBOUND_GROUPS[{idx}] reuses SNI already claimed elsewhere: {sni}"
                )
            local_seen.add(sni)
            seen_snis.add(sni)
            group_snis.append(sni)
        if not group_snis:
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] must contain at least one SNI")
        seen_ids.add(group_id)
        seen_ports.add(port)
        groups.append(
            MaterializedRealityInboundGroup(
                id=group_id,
                port=port,
                dest_host=dest_host,
                snis=tuple(sorted(group_snis, key=str.lower)),
            )
        )
    return tuple(sorted(groups, key=lambda row: (row.port, row.id)))


def _grouped_reality_tag(source_tag: str, group_id: str) -> str:
    return f"{source_tag}-{group_id}"


def _extend_routing_inbound_tags(base: dict[str, Any], *, source_tag: str, extra_tags: list[str]) -> None:
    if not source_tag or not extra_tags:
        return
    routing = base.get("routing")
    if not isinstance(routing, dict):
        return
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return
    normalized_tags = sorted(set([str(tag).strip() for tag in extra_tags if str(tag).strip()]), key=str)
    if not normalized_tags:
        return
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        inbound_tag = rule.get("inboundTag")
        if not isinstance(inbound_tag, list):
            continue
        tags = [str(tag).strip() for tag in inbound_tag if str(tag).strip()]
        if source_tag not in tags:
            continue
        rule["inboundTag"] = sorted(set([*tags, *normalized_tags]), key=str)


def _materialize_reality_groups(
    payload: dict[str, Any],
    *,
    source_tag: str,
    groups: tuple[MaterializedRealityInboundGroup, ...],
) -> None:
    if not groups:
        return
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return

    source_inbound: dict[str, Any] | None = None
    expanded: list[Any] = []
    expected_group_tags = {_grouped_reality_tag(source_tag, group.id) for group in groups}
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            expanded.append(inbound)
            continue
        tag = str(inbound.get("tag") or "").strip()
        if tag == source_tag:
            source_inbound = inbound
            expanded.append(inbound)
            continue
        if tag in expected_group_tags:
            continue
        expanded.append(inbound)

    if source_inbound is None:
        return

    clone_tags: list[str] = []
    for group in groups:
        clone = copy.deepcopy(source_inbound)
        clone_tag = _grouped_reality_tag(source_tag, group.id)
        clone["tag"] = clone_tag
        clone["port"] = int(group.port)
        settings = clone.setdefault("settings", {})
        if isinstance(settings, dict):
            settings["clients"] = []
        reality = clone.setdefault("streamSettings", {}).setdefault("realitySettings", {})
        reality["dest"] = f"{group.dest_host}:443"
        reality["serverNames"] = list(group.snis)
        expanded.append(clone)
        clone_tags.append(clone_tag)

    payload["inbounds"] = expanded
    _extend_routing_inbound_tags(payload, source_tag=source_tag, extra_tags=clone_tags)


def _haproxy_group_name(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower()).strip("_")


def _render_reality_demux(
    *,
    role_lower: str,
    groups: tuple[MaterializedRealityInboundGroup, ...],
) -> tuple[str, str, str]:
    if not groups:
        return "", "", ""
    acl_lines: list[str] = []
    route_lines: list[str] = []
    backend_blocks: list[str] = []
    for group in groups:
        group_name = _haproxy_group_name(group.id) or "group"
        acl_name = f"reality_{group_name}_sni"
        backend_name = f"be_{role_lower}_reality_{group_name}"
        server_name = f"{role_lower}_reality_{group_name}"
        snis = " ".join(group.snis)
        acl_lines.append(f"  acl {acl_name} req.ssl_sni -i {snis}")
        route_lines.append(f"  use_backend {backend_name} if {acl_name}")
        backend_blocks.extend(
            [
                f"backend {backend_name}",
                f"  server {server_name} 127.0.0.1:{group.port} check",
                "",
            ]
        )
    return "\n".join(acl_lines), "\n".join(route_lines), "\n".join(backend_blocks).rstrip()


@dataclass(frozen=True)
class MaterializedBundleRenderContext:
    source_root: Path
    materialized_root: Path
    private_overlay_root: Path | None
    entry_host: str
    transit_host: str
    ws_path: str
    bootstrap_password: str
    reality_public_key_entry: str
    reality_short_id_entry: str
    reality_public_key_transit: str
    reality_short_id_transit: str
    reality_private_key_entry: str
    reality_private_key_transit: str
    reality_dest_entry: str
    reality_dest_transit: str
    reality_server_name_entry: str
    reality_server_name_transit: str
    reality_multi_inbound_groups: tuple[MaterializedRealityInboundGroup, ...]
    entry_tls_server_name: str
    transit_tls_server_name: str
    mtproto_domain: str
    mtproto_upstream: str
    decoy_dir: str
    transit_decoy_agent_upstream: str
    transit_decoy_secret_path: str
    tls_cert_file: str
    tls_key_file: str
    entry_finalmask: dict[str, Any] | None
    transit_finalmask: dict[str, Any] | None
    entry_ech_server_keys: str
    transit_ech_server_keys: str

    @classmethod
    def from_environ(cls, environ: dict[str, str] | None = None) -> "MaterializedBundleRenderContext":
        env = dict(os.environ if environ is None else environ)

        source_root = Path(_require(env, "BUNDLE_SOURCE_ROOT"))
        materialized_root = Path(_require(env, "BUNDLE_MATERIALIZED_ROOT"))
        private_overlay_root_raw = _first(env, "BUNDLE_PRIVATE_OVERLAY_ROOT")
        private_overlay_root = Path(private_overlay_root_raw) if private_overlay_root_raw else None
        entry_host = _require(env, "DEFAULT_ENTRY_HOST")
        transit_host = _require(env, "DEFAULT_TRANSIT_HOST")
        ws_path = _first(env, "VLESS_WS_PATH", default="/ws") or "/ws"
        bootstrap_password = _require(env, "HYSTERIA_BOOTSTRAP_PASSWORD")

        reality_public_key_entry = _first(env, "REALITY_PUBLIC_KEY_ENTRY", "REALITY_PUBLIC_KEY")
        reality_short_id_entry = _require_first(env, "REALITY_SHORT_ID_ENTRY", "REALITY_SHORT_ID")
        reality_public_key_transit = _require_first(env, "REALITY_PUBLIC_KEY_TRANSIT", "REALITY_PUBLIC_KEY")
        reality_short_id_transit = _require_first(env, "REALITY_SHORT_ID_TRANSIT", "REALITY_SHORT_ID")
        reality_private_key_entry = _require(env, "REALITY_PRIVATE_KEY_ENTRY")
        reality_private_key_transit = _require(env, "REALITY_PRIVATE_KEY_TRANSIT")

        reality_dest_default = _first(env, "REALITY_DEST", default="splitter.wb.ru:443")
        reality_dest_entry = _first(env, "REALITY_DEST_ENTRY", default=reality_dest_default)
        reality_dest_transit = _first(env, "REALITY_DEST_TRANSIT", default=reality_dest_default)
        reality_server_name_entry = _first(env, "REALITY_SERVER_NAME_ENTRY", default=host_from_dest(reality_dest_entry))
        reality_server_name_transit = _first(
            env,
            "REALITY_SERVER_NAME_TRANSIT",
            default=host_from_dest(reality_dest_transit),
        )
        reality_multi_inbound_groups = _load_reality_multi_inbound_groups(env)

        entry_tls_server_name = _first(env, "ENTRY_TLS_SERVER_NAME", default=entry_host)
        transit_tls_server_name = _first(env, "TRANSIT_TLS_SERVER_NAME", default=transit_host)
        mtproto_domain = _first(env, "MTPROTO_DOMAIN")
        mtproto_upstream = _haproxy_server_address(
            _first(
                env,
                "MTPROTO_HAPROXY_UPSTREAM",
                "PRIVATE_FRONTING_MTPROTO_UPSTREAM",
                default="127.0.0.1:9443",
            )
            or "127.0.0.1:9443",
            label="MTPROTO_HAPROXY_UPSTREAM",
        )
        decoy_dir = _first(env, "XRAY_CENTRIC_DECOY_DIR", default="/var/www/decoy") or "/var/www/decoy"
        agent_port_raw = _first(env, "AGENT_PORT", default="8070") or "8070"
        try:
            agent_port = int(agent_port_raw)
        except ValueError:
            agent_port = 8070
        transit_decoy_agent_upstream = _first(
            env,
            "TRANSIT_DECOY_AGENT_UPSTREAM",
            default=f"http://127.0.0.1:{agent_port}",
        ) or f"http://127.0.0.1:{agent_port}"
        transit_decoy_secret_path = _normalize_decoy_secret_path(
            _first(env, "TRANSIT_DECOY_SECRET_PATH", default="/vault/mtproto/"),
        )
        tls_cert_file = _first(env, "XRAY_CENTRIC_TLS_CERT_FILE", default="/etc/tracegate/tls/ws.crt") or "/etc/tracegate/tls/ws.crt"
        tls_key_file = _first(env, "XRAY_CENTRIC_TLS_KEY_FILE", default="/etc/tracegate/tls/ws.key") or "/etc/tracegate/tls/ws.key"
        entry_finalmask = _load_optional_json_file(
            _first(env, "XRAY_HYSTERIA_FINALMASK_ENTRY_FILE", "XRAY_HYSTERIA_FINALMASK_FILE"),
            label="entry FinalMask",
        )
        transit_finalmask = _load_optional_json_file(
            _first(env, "XRAY_HYSTERIA_FINALMASK_TRANSIT_FILE", "XRAY_HYSTERIA_FINALMASK_FILE"),
            label="transit FinalMask",
        )
        entry_ech_server_keys = _load_optional_text_file(
            _first(env, "XRAY_HYSTERIA_ECH_SERVER_KEYS_ENTRY_FILE", "XRAY_HYSTERIA_ECH_SERVER_KEYS_FILE"),
            label="entry ECH server keys",
        )
        transit_ech_server_keys = _load_optional_text_file(
            _first(env, "XRAY_HYSTERIA_ECH_SERVER_KEYS_TRANSIT_FILE", "XRAY_HYSTERIA_ECH_SERVER_KEYS_FILE"),
            label="transit ECH server keys",
        )

        return cls(
            source_root=source_root,
            materialized_root=materialized_root,
            private_overlay_root=private_overlay_root,
            entry_host=entry_host,
            transit_host=transit_host,
            ws_path=ws_path,
            bootstrap_password=bootstrap_password,
            reality_public_key_entry=reality_public_key_entry,
            reality_short_id_entry=reality_short_id_entry,
            reality_public_key_transit=reality_public_key_transit,
            reality_short_id_transit=reality_short_id_transit,
            reality_private_key_entry=reality_private_key_entry,
            reality_private_key_transit=reality_private_key_transit,
            reality_dest_entry=reality_dest_entry,
            reality_dest_transit=reality_dest_transit,
            reality_server_name_entry=reality_server_name_entry,
            reality_server_name_transit=reality_server_name_transit,
            reality_multi_inbound_groups=reality_multi_inbound_groups,
            entry_tls_server_name=entry_tls_server_name,
            transit_tls_server_name=transit_tls_server_name,
            mtproto_domain=mtproto_domain,
            mtproto_upstream=mtproto_upstream,
            decoy_dir=decoy_dir,
            transit_decoy_agent_upstream=transit_decoy_agent_upstream,
            transit_decoy_secret_path=transit_decoy_secret_path,
            tls_cert_file=tls_cert_file,
            tls_key_file=tls_key_file,
            entry_finalmask=entry_finalmask,
            transit_finalmask=transit_finalmask,
            entry_ech_server_keys=entry_ech_server_keys,
            transit_ech_server_keys=transit_ech_server_keys,
        )


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bundle_files_manifest(bundle_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(row for row in bundle_dir.rglob("*") if row.is_file()):
        rows.append(
            {
                "path": path.relative_to(bundle_dir).as_posix(),
                "sizeBytes": int(path.stat().st_size),
                "sha256": _sha256_file(path),
            }
        )
    return rows


def _role_public_units(role_lower: str) -> list[str]:
    return [
        f"tracegate-xray@{role_lower}",
        f"tracegate-haproxy@{role_lower}",
        f"tracegate-nginx@{role_lower}",
    ]


def _role_private_companions(ctx: "MaterializedBundleRenderContext", role_lower: str) -> list[str]:
    units = [f"tracegate-obfuscation@{role_lower}"]
    if role_lower == "transit" and str(ctx.mtproto_domain or "").strip():
        units.extend(["tracegate-fronting@transit", "tracegate-mtproto@transit"])
    return units


def _detect_xray_hysteria_flags(payload: dict[str, Any]) -> tuple[bool, bool]:
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


def _materialized_manifest_payload(ctx: "MaterializedBundleRenderContext") -> dict[str, Any]:
    bundles: list[dict[str, Any]] = []
    for role_upper, bundle_name in (("ENTRY", "base-entry"), ("TRANSIT", "base-transit")):
        role_lower = role_upper.lower()
        bundle_dir = ctx.materialized_root / bundle_name
        xray_payload = json.loads((bundle_dir / "xray.json").read_text(encoding="utf-8"))
        finalmask_enabled, ech_enabled = _detect_xray_hysteria_flags(xray_payload)
        bundles.append(
            {
                "role": role_upper,
                "bundleName": bundle_name,
                "bundleDir": str(bundle_dir),
                "publicUnits": _role_public_units(role_lower),
                "privateCompanions": _role_private_companions(ctx, role_lower),
                "features": {
                    "runtimeProfile": "xray-centric",
                    "finalMaskEnabled": finalmask_enabled,
                    "echEnabled": ech_enabled,
                    "mtprotoFrontingEnabled": role_upper == "TRANSIT" and bool(str(ctx.mtproto_domain or "").strip()),
                    "mtprotoDomain": str(ctx.mtproto_domain or "").strip() if role_upper == "TRANSIT" else "",
                    "decoyDir": str(ctx.decoy_dir or "").strip(),
                    "transitDecoySecretPath": ctx.transit_decoy_secret_path if role_upper == "TRANSIT" else "",
                },
                "files": _bundle_files_manifest(bundle_dir),
            }
        )
    return {
        "version": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "runtimeProfile": "xray-centric",
        "materializedRoot": str(ctx.materialized_root),
        "sourceRoot": str(ctx.source_root),
        "privateOverlayRoot": str(ctx.private_overlay_root) if ctx.private_overlay_root is not None else "",
        "bundles": bundles,
    }


def _write_materialized_manifest(ctx: "MaterializedBundleRenderContext") -> None:
    _write_json(ctx.materialized_root / _MATERIALIZED_MANIFEST_FILE_NAME, _materialized_manifest_payload(ctx))


def _copy_source_bundles(ctx: MaterializedBundleRenderContext) -> None:
    ctx.materialized_root.mkdir(parents=True, exist_ok=True)
    for bundle_name in ("base-entry", "base-transit"):
        src_dir = ctx.source_root / bundle_name
        if not src_dir.exists():
            raise MaterializedBundleRenderError(f"bundle source does not exist: {src_dir}")
        dst_dir = ctx.materialized_root / bundle_name
        if dst_dir.exists():
            shutil.rmtree(dst_dir)
        shutil.copytree(src_dir, dst_dir)


def _deep_merge(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        merged = dict(base)
        for key, value in overlay.items():
            merged[key] = _deep_merge(base[key], value) if key in base else value
        return merged
    return overlay


def _copy_tree_overlay(source_dir: Path, target_dir: Path) -> None:
    for source in source_dir.rglob("*"):
        relative = source.relative_to(source_dir)
        target = target_dir / relative
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _apply_json_overlay(config_path: Path, overlay_dir: Path) -> None:
    replacement_path = overlay_dir / config_path.name
    merge_path = overlay_dir / f"{config_path.stem}.merge.json"
    if replacement_path.exists():
        shutil.copy2(replacement_path, config_path)
        return
    if not merge_path.exists():
        return
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    overlay = json.loads(merge_path.read_text(encoding="utf-8"))
    _write_json(config_path, _deep_merge(payload, overlay))


def _apply_text_overlay(config_path: Path, overlay_dir: Path) -> None:
    replacement_path = overlay_dir / config_path.name
    if replacement_path.exists():
        shutil.copy2(replacement_path, config_path)


def _apply_private_overlays(ctx: MaterializedBundleRenderContext) -> None:
    if ctx.private_overlay_root is None or not ctx.private_overlay_root.exists():
        return

    for role, bundle_name in (("entry", "base-entry"), ("transit", "base-transit")):
        overlay_dir = ctx.private_overlay_root / role
        if not overlay_dir.exists():
            continue
        bundle_dir = ctx.materialized_root / bundle_name
        _apply_json_overlay(bundle_dir / "xray.json", overlay_dir)
        for file_name in ("haproxy.cfg", "nginx.conf", "nftables.conf"):
            _apply_text_overlay(bundle_dir / file_name, overlay_dir)
        decoy_overlay_dir = overlay_dir / "decoy"
        if decoy_overlay_dir.exists():
            _copy_tree_overlay(decoy_overlay_dir, bundle_dir / "decoy")


def _materialize_transit_secret_surface(ctx: MaterializedBundleRenderContext) -> None:
    source_dir = ctx.materialized_root / "base-transit" / "decoy" / "vault" / "mtproto"
    if not source_dir.exists():
        return

    normalized = _normalize_decoy_secret_path(ctx.transit_decoy_secret_path)
    if normalized == "/vault/mtproto/":
        return

    relative_target = Path(normalized.strip("/"))
    target_dir = ctx.materialized_root / "base-transit" / "decoy" / relative_target
    if target_dir == source_dir:
        return

    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_dir, target_dir)


def render_materialized_bundles(ctx: MaterializedBundleRenderContext) -> None:
    _copy_source_bundles(ctx)

    entry_xray_path = ctx.materialized_root / "base-entry" / "xray.json"
    entry_xray = render_xray_centric_xray_config(
        json.loads(entry_xray_path.read_text(encoding="utf-8")),
        role="ENTRY",
        bootstrap_auth=ctx.bootstrap_password,
        decoy_dir=ctx.decoy_dir,
        tls_cert_file=ctx.tls_cert_file,
        tls_key_file=ctx.tls_key_file,
        finalmask=ctx.entry_finalmask,
        ech_server_keys=ctx.entry_ech_server_keys,
    )
    for inbound in entry_xray.get("inbounds", []):
        tag = str(inbound.get("tag") or "")
        if tag == "entry-in":
            reality = inbound.setdefault("streamSettings", {}).setdefault("realitySettings", {})
            reality["dest"] = ctx.reality_dest_entry
            reality["serverNames"] = [ctx.reality_server_name_entry]
            reality["privateKey"] = ctx.reality_private_key_entry
            reality["shortIds"] = [ctx.reality_short_id_entry]
        if tag == "vless-ws-in":
            ws_settings = inbound.setdefault("streamSettings", {}).setdefault("wsSettings", {})
            ws_settings["path"] = ctx.ws_path
    for outbound in entry_xray.get("outbounds", []):
        if str(outbound.get("tag") or "") != "to-transit":
            continue
        vnext = (((outbound.get("settings") or {}).get("vnext")) or [])
        if vnext:
            vnext[0]["address"] = ctx.transit_host
        reality = outbound.setdefault("streamSettings", {}).setdefault("realitySettings", {})
        reality["serverName"] = ctx.reality_server_name_transit
        reality["publicKey"] = ctx.reality_public_key_transit
        reality["shortId"] = ctx.reality_short_id_transit
    _materialize_reality_groups(
        entry_xray,
        source_tag="entry-in",
        groups=ctx.reality_multi_inbound_groups,
    )
    _write_json(entry_xray_path, entry_xray)

    entry_haproxy_path = ctx.materialized_root / "base-entry" / "haproxy.cfg"
    entry_reality_acls, entry_reality_routes, entry_reality_backends = _render_reality_demux(
        role_lower="entry",
        groups=ctx.reality_multi_inbound_groups,
    )
    entry_haproxy = entry_haproxy_path.read_text(encoding="utf-8").replace(
        "REPLACE_TLS_SERVER_NAME",
        ctx.entry_tls_server_name,
    )
    entry_haproxy = entry_haproxy.replace("REPLACE_REALITY_ACLS", entry_reality_acls)
    entry_haproxy = entry_haproxy.replace("REPLACE_REALITY_ROUTES", entry_reality_routes)
    entry_haproxy = entry_haproxy.replace("REPLACE_REALITY_BACKENDS", entry_reality_backends)
    entry_haproxy_path.write_text(entry_haproxy, encoding="utf-8")

    entry_nginx_path = ctx.materialized_root / "base-entry" / "nginx.conf"
    entry_nginx = entry_nginx_path.read_text(encoding="utf-8").replace(
        "REPLACE_TLS_SERVER_NAME",
        ctx.entry_tls_server_name,
    )
    entry_nginx = entry_nginx.replace("/var/www/decoy", ctx.decoy_dir)
    entry_nginx_path.write_text(entry_nginx, encoding="utf-8")

    transit_xray_path = ctx.materialized_root / "base-transit" / "xray.json"
    transit_xray = render_xray_centric_xray_config(
        json.loads(transit_xray_path.read_text(encoding="utf-8")),
        role="TRANSIT",
        bootstrap_auth=ctx.bootstrap_password,
        decoy_dir=ctx.decoy_dir,
        tls_cert_file=ctx.tls_cert_file,
        tls_key_file=ctx.tls_key_file,
        finalmask=ctx.transit_finalmask,
        ech_server_keys=ctx.transit_ech_server_keys,
    )
    for inbound in transit_xray.get("inbounds", []):
        tag = str(inbound.get("tag") or "")
        if tag == "vless-reality-in":
            reality = inbound.setdefault("streamSettings", {}).setdefault("realitySettings", {})
            reality["dest"] = ctx.reality_dest_transit
            reality["serverNames"] = [ctx.reality_server_name_transit]
            reality["privateKey"] = ctx.reality_private_key_transit
            reality["shortIds"] = [ctx.reality_short_id_transit]
        if tag == "vless-ws-in":
            ws_settings = inbound.setdefault("streamSettings", {}).setdefault("wsSettings", {})
            ws_settings["path"] = ctx.ws_path
    _materialize_reality_groups(
        transit_xray,
        source_tag="vless-reality-in",
        groups=ctx.reality_multi_inbound_groups,
    )
    _write_json(transit_xray_path, transit_xray)

    transit_haproxy_path = ctx.materialized_root / "base-transit" / "haproxy.cfg"
    transit_reality_acls, transit_reality_routes, transit_reality_backends = _render_reality_demux(
        role_lower="transit",
        groups=ctx.reality_multi_inbound_groups,
    )
    transit_haproxy = transit_haproxy_path.read_text(encoding="utf-8").replace(
        "REPLACE_TLS_SERVER_NAME",
        ctx.transit_tls_server_name,
    )
    mtproto_acl = ""
    mtproto_route = ""
    mtproto_backend = ""
    if ctx.mtproto_domain:
        mtproto_acl = f"  acl mtproto_sni req.ssl_sni -i {ctx.mtproto_domain}"
        mtproto_route = "  use_backend be_transit_mtproto if mtproto_sni"
        mtproto_backend = f"\nbackend be_transit_mtproto\n  server transit_mtproto {ctx.mtproto_upstream} check\n"
    transit_haproxy = transit_haproxy.replace("REPLACE_MTPROTO_ACL", mtproto_acl)
    transit_haproxy = transit_haproxy.replace("REPLACE_MTPROTO_ROUTE", mtproto_route)
    transit_haproxy = transit_haproxy.replace("REPLACE_MTPROTO_BACKEND", mtproto_backend)
    transit_haproxy = transit_haproxy.replace("REPLACE_REALITY_ACLS", transit_reality_acls)
    transit_haproxy = transit_haproxy.replace("REPLACE_REALITY_ROUTES", transit_reality_routes)
    transit_haproxy = transit_haproxy.replace("REPLACE_REALITY_BACKENDS", transit_reality_backends)
    transit_haproxy_path.write_text(transit_haproxy, encoding="utf-8")

    transit_nginx_path = ctx.materialized_root / "base-transit" / "nginx.conf"
    transit_nginx = transit_nginx_path.read_text(encoding="utf-8").replace(
        "REPLACE_TLS_SERVER_NAME",
        ctx.transit_tls_server_name,
    )
    transit_nginx = transit_nginx.replace("/var/www/decoy", ctx.decoy_dir)
    transit_nginx = transit_nginx.replace("REPLACE_TRANSIT_DECOY_UPSTREAM", ctx.transit_decoy_agent_upstream)
    transit_nginx = transit_nginx.replace("REPLACE_TRANSIT_SECRET_PATH", ctx.transit_decoy_secret_path)
    transit_nginx_path.write_text(transit_nginx, encoding="utf-8")

    _apply_private_overlays(ctx)
    _materialize_transit_secret_surface(ctx)
    _write_materialized_manifest(ctx)
