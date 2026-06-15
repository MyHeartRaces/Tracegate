from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from tracegate.client_export.config import ClientConfigExportError, ExportResult, client_profile_name, export_client_config

_SCHEMA = "tracegate.client-config-bundle.v1"


@dataclass(frozen=True)
class ClientConfigBundleItem:
    revision_id: str
    connection_id: str
    effective_config: dict[str, Any]
    device_id: str = ""
    protocol: str = ""
    mode: str = ""
    variant: str = ""
    profile_name: str = ""
    label: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def _safe_tag(value: str, fallback: str) -> str:
    raw = str(value or "").strip().lower()
    normalized = "".join(ch if ch.isalnum() else "-" for ch in raw)
    compact = "-".join(part for part in normalized.split("-") if part)
    return compact[:80] or fallback


def _json_attachment(exported: ExportResult) -> dict[str, Any] | None:
    if not exported.attachment_content:
        return None
    try:
        parsed = json.loads(exported.attachment_content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _artifact(exported: ExportResult) -> dict[str, Any] | None:
    if not exported.attachment_content or not exported.attachment_filename:
        return None
    content = exported.attachment_content
    artifact: dict[str, Any] = {
        "filename": exported.attachment_filename,
        "mime": exported.attachment_mime or "application/octet-stream",
        "contentBase64": base64.b64encode(content).decode("ascii"),
    }
    parsed = _json_attachment(exported)
    if parsed is not None:
        artifact["json"] = parsed
    if exported.attachment_filename.endswith(".wgws.json"):
        artifact["kind"] = "wgws-config"
    elif exported.attachment_filename.endswith(".singbox.json"):
        artifact["kind"] = "sing-box-config"
    elif exported.attachment_filename.endswith(".xray.json"):
        artifact["kind"] = "xray-config"
    else:
        artifact["kind"] = "file"
    return artifact


def _export_links(exported: ExportResult) -> list[dict[str, str]]:
    links: list[dict[str, str]] = []
    if exported.kind == "uri" and exported.content:
        links.append({"title": exported.title, "url": exported.content})
    if exported.alternate_content and exported.alternate_title:
        links.append({"title": exported.alternate_title, "url": exported.alternate_content})
    return links


def _retag_singbox_outbounds(outbounds: list[dict[str, Any]], *, tag_prefix: str) -> tuple[list[dict[str, Any]], str | None]:
    tags = [str(row.get("tag") or f"out-{idx}").strip() for idx, row in enumerate(outbounds)]
    mapping = {tag: f"{tag_prefix}-{_safe_tag(tag, 'out')}" for tag in tags}
    retagged: list[dict[str, Any]] = []
    for idx, row in enumerate(outbounds):
        copied = dict(row)
        original_tag = tags[idx]
        copied["tag"] = mapping[original_tag]
        detour = str(copied.get("detour") or "").strip()
        if detour in mapping:
            copied["detour"] = mapping[detour]
        retagged.append(copied)
    primary = mapping.get("proxy") or (retagged[0].get("tag") if retagged else None)
    return retagged, str(primary) if primary else None


def _singbox_outbounds_from_attachment(exported: ExportResult, *, tag_prefix: str) -> tuple[list[dict[str, Any]], str | None]:
    if not str(exported.attachment_filename or "").endswith(".singbox.json"):
        return [], None
    parsed = _json_attachment(exported)
    if not isinstance(parsed, dict):
        return [], None
    raw_outbounds = parsed.get("outbounds")
    if not isinstance(raw_outbounds, list):
        return [], None
    outbounds = [row for row in raw_outbounds if isinstance(row, dict)]
    return _retag_singbox_outbounds(outbounds, tag_prefix=tag_prefix)


def _singbox_vless_outbound(effective: dict[str, Any], *, tag: str) -> dict[str, Any] | None:
    vless_encryption = effective.get("vless_encryption")
    if isinstance(vless_encryption, dict) and bool(vless_encryption.get("enabled", False)):
        return None
    transport = str(effective.get("transport") or "").strip().lower()
    if transport not in {"ws_tls", "ws+tls", "ws-tls", "grpc_tls", "grpc+tls", "grpc-tls"}:
        return None
    server = str(effective.get("connect_host") or effective.get("server") or "").strip()
    uuid = str(effective.get("uuid") or "").strip()
    if not server or not uuid:
        return None
    logical_server = str(effective.get("server") or server).strip()
    sni = str(effective.get("sni") or logical_server or server).strip()
    tls = effective.get("tls") if isinstance(effective.get("tls"), dict) else {}
    outbound: dict[str, Any] = {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": int(effective.get("port") or 443),
        "uuid": uuid,
        "tls": {
            "enabled": True,
            "server_name": sni,
        },
    }
    if bool(tls.get("insecure", False)):
        outbound["tls"]["insecure"] = True
    if transport.startswith("ws") or transport in {"ws+tls", "ws-tls"}:
        ws = effective.get("ws") if isinstance(effective.get("ws"), dict) else {}
        headers: dict[str, str] = {}
        host = str(ws.get("host") or sni or "").strip()
        if host:
            headers["Host"] = host
        outbound["transport"] = {
            "type": "ws",
            "path": str(ws.get("path") or "/ws").strip() or "/ws",
            "headers": headers,
        }
    else:
        grpc = effective.get("grpc") if isinstance(effective.get("grpc"), dict) else {}
        outbound["transport"] = {
            "type": "grpc",
            "service_name": str(grpc.get("service_name") or "tracegate.v1.Edge").strip() or "tracegate.v1.Edge",
        }
    return outbound


def _singbox_outbounds_for_profile(
    effective: dict[str, Any],
    exported: ExportResult,
    *,
    tag_prefix: str,
) -> tuple[list[dict[str, Any]], str | None, list[str]]:
    warnings: list[str] = []
    from_attachment, primary = _singbox_outbounds_from_attachment(exported, tag_prefix=tag_prefix)
    if from_attachment:
        return from_attachment, primary, warnings

    proto = str(effective.get("protocol") or "").strip().lower()
    tag = f"{tag_prefix}-proxy"
    if proto == "vless":
        vless_encryption = effective.get("vless_encryption")
        if isinstance(vless_encryption, dict) and bool(vless_encryption.get("enabled", False)):
            warnings.append("vless_encryption_requires_xray_client")
            return [], None, warnings
        outbound = _singbox_vless_outbound(effective, tag=tag)
        if outbound:
            return [outbound], tag, warnings
        warnings.append("vless_transport_not_representable_as_official_singbox_outbound")
    elif proto == "wireguard":
        warnings.append("wireguard_wstunnel_requires_wgws_transport")
    elif proto == "mtproto":
        warnings.append("mtproto_not_representable_as_singbox_outbound")
    return [], None, warnings


def _profile_record(item: ClientConfigBundleItem, *, index: int) -> tuple[dict[str, Any], list[dict[str, Any]], str | None]:
    exported = export_client_config(item.effective_config)
    profile = client_profile_name(item.effective_config)
    tag_prefix = f"tg-{index}-{_safe_tag(profile, 'profile')}"
    singbox_outbounds, singbox_tag, warnings = _singbox_outbounds_for_profile(
        item.effective_config,
        exported,
        tag_prefix=tag_prefix,
    )
    artifact = _artifact(exported)
    record: dict[str, Any] = {
        "revisionId": item.revision_id,
        "connectionId": item.connection_id,
        "deviceId": item.device_id,
        "profile": profile,
        "protocol": str(item.effective_config.get("protocol") or item.protocol or "").strip(),
        "transport": str(item.effective_config.get("transport") or "").strip(),
        "mode": item.mode,
        "variant": item.variant,
        "links": _export_links(exported),
        "artifacts": [artifact] if artifact else [],
        "singbox": {
            "supported": bool(singbox_outbounds and singbox_tag),
            "outboundTag": singbox_tag or "",
        },
        "warnings": warnings,
    }
    if item.extra:
        record["tracegate"] = dict(item.extra)
    return record, singbox_outbounds, singbox_tag


def build_client_config_bundle(
    items: list[ClientConfigBundleItem],
    *,
    subject_type: str,
    subject_id: str,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc)
    profiles: list[dict[str, Any]] = []
    subscription_links: list[str] = []
    singbox_outbounds: list[dict[str, Any]] = []
    singbox_selector_tags: list[str] = []
    errors: list[dict[str, str]] = []

    for index, item in enumerate(items):
        try:
            profile, outbounds, singbox_tag = _profile_record(item, index=index)
        except ClientConfigExportError as exc:
            errors.append(
                {
                    "revisionId": item.revision_id,
                    "connectionId": item.connection_id,
                    "error": str(exc),
                }
            )
            continue
        profiles.append(profile)
        subscription_links.extend(link["url"] for link in profile["links"])
        singbox_outbounds.extend(outbounds)
        if singbox_tag:
            singbox_selector_tags.append(singbox_tag)

    selector = {
        "type": "selector",
        "tag": "proxy",
        "outbounds": singbox_selector_tags or ["direct"],
        "default": singbox_selector_tags[0] if singbox_selector_tags else "direct",
    }
    singbox_config = {
        "log": {"level": "warn"},
        "outbounds": [
            selector,
            *singbox_outbounds,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {"auto_detect_interface": True, "final": "proxy"},
    }
    subscription_text = "\n".join(subscription_links)
    return {
        "schema": _SCHEMA,
        "version": 1,
        "subject": {"type": subject_type, "id": subject_id},
        "generatedAt": generated.isoformat().replace("+00:00", "Z"),
        "counts": {
            "profiles": len(profiles),
            "links": len(subscription_links),
            "singboxOutbounds": len(singbox_selector_tags),
            "errors": len(errors),
        },
        "subscription": {
            "format": "plain-uri-list",
            "links": subscription_links,
            "base64": base64.b64encode(subscription_text.encode("utf-8")).decode("ascii") if subscription_text else "",
        },
        "singbox": singbox_config,
        "profiles": profiles,
        "errors": errors,
    }


def render_subscription_text(bundle: dict[str, Any]) -> str:
    subscription = bundle.get("subscription") if isinstance(bundle, dict) else {}
    links = subscription.get("links") if isinstance(subscription, dict) else []
    return "\n".join(str(link) for link in links if str(link).strip())


def render_subscription_base64(bundle: dict[str, Any]) -> str:
    text = render_subscription_text(bundle)
    return base64.b64encode(text.encode("utf-8")).decode("ascii") if text else ""
