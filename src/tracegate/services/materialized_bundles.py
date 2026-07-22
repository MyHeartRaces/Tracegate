from __future__ import annotations

import copy
import hashlib
from ipaddress import ip_address
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from tracegate.constants import TRACEGATE_PUBLIC_UDP_PORT
from tracegate.services.runtime_contract import normalize_runtime_profile_name
from tracegate.services.xray_centric import render_xray_centric_xray_config


class MaterializedBundleRenderError(RuntimeError):
    pass


_MATERIALIZED_MANIFEST_FILE_NAME = ".tracegate-deploy-manifest.json"
_RETIRED_REALITY_FRONTS = frozenset({"yandex.ru", "www.yandex.ru"})


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


def _bool_env(environ: dict[str, str], name: str, *, default: bool) -> bool:
    raw = _env(environ, name, "true" if default else "false").lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise MaterializedBundleRenderError(f"{name} must be a boolean")


def _int_env(environ: dict[str, str], name: str, *, default: int, min_value: int, max_value: int) -> int:
    raw = _env(environ, name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise MaterializedBundleRenderError(f"{name} must be an integer") from exc
    if value < min_value or value > max_value:
        raise MaterializedBundleRenderError(f"{name} must be in {min_value}..{max_value}")
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


def _reject_retired_reality_front(value: str, *, label: str) -> None:
    hostname = host_from_dest(value).strip().rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return
    if hostname in _RETIRED_REALITY_FRONTS:
        raise MaterializedBundleRenderError(f"{label} uses a retired Reality front")


def _hostname_from_public_url(value: str, *, label: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw)
    hostname = str(parsed.hostname or "").strip().lower()
    if not hostname or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname):
        raise MaterializedBundleRenderError(f"{label} must contain a valid hostname")
    return hostname


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


def _normalize_reality_sni(value: object, *, label: str) -> str:
    raw = str(value or "").strip().lower()
    try:
        ascii_name = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise MaterializedBundleRenderError(f"{label} contains an invalid SNI") from exc
    labels = ascii_name.rstrip(".").split(".")
    if (
        len(ascii_name) > 253
        or len(labels) < 2
        or any(
            not part
            or len(part) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part) is None
            for part in labels
        )
    ):
        raise MaterializedBundleRenderError(f"{label} contains an invalid SNI")
    return ascii_name.rstrip(".")


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
        _reject_retired_reality_front(
            dest_host,
            label=f"REALITY_MULTI_INBOUND_GROUPS[{idx}].dest",
        )
        snis_raw = row.get("snis")
        if not isinstance(snis_raw, list):
            raise MaterializedBundleRenderError(f"REALITY_MULTI_INBOUND_GROUPS[{idx}] must include snis[]")
        group_snis: list[str] = []
        local_seen: set[str] = set()
        for sni_idx, sni_raw in enumerate(snis_raw):
            sni = _normalize_reality_sni(
                sni_raw,
                label=f"REALITY_MULTI_INBOUND_GROUPS[{idx}].snis[{sni_idx}]",
            )
            _reject_retired_reality_front(
                sni,
                label=f"REALITY_MULTI_INBOUND_GROUPS[{idx}].snis[{sni_idx}]",
            )
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
    runtime_profile: str
    entry_host: str
    transit_host: str
    ws_path: str
    bootstrap_password: str
    hysteria_udp_port: int
    entry_hysteria_salamander_password: str
    transit_hysteria_salamander_password: str
    entry_hysteria_stats_secret: str
    transit_hysteria_stats_secret: str
    entry_hysteria_auth_url: str
    transit_hysteria_auth_url: str
    entry_hysteria_listen_host: str
    transit_hysteria_listen_host: str
    entry_hysteria_tls_cert_file: str
    entry_hysteria_tls_key_file: str
    transit_hysteria_tls_cert_file: str
    transit_hysteria_tls_key_file: str
    hysteria_chain_client_rate_limit_enabled: bool
    hysteria_chain_client_max_mbit: int
    hysteria_chain_client_require_declared_tx: bool
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
    grafana_tls_server_name: str
    shadowtls_server_name_transit: str
    shadowtls_backhaul2_sni: str
    shadowsocks2022_password_transit: str
    shadowsocks2022_backhaul_key: str
    reality_backhaul_port: int
    reality_backhaul_sni: str
    mtproto_domain: str
    mtproto_tls_domain: str
    mtproto_upstream: str
    # Dedicated Telemt-only Entry->Endpoint link target (entry-endpoint-tunnel
    # mode only). Entry relays the client's FakeTLS to this Endpoint address;
    # it is deliberately separate from mtproto_upstream, which stays the
    # role-local Telemt listener.
    mtproto_entry_link_upstream: str
    mtproto_route_mode: str
    mtproto_egress_socks_port: int
    mtproto_entry_backhaul_uuid: str
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
        runtime_profile = normalize_runtime_profile_name(_first(env, "AGENT_RUNTIME_PROFILE"))
        entry_host = _require(env, "DEFAULT_ENTRY_HOST")
        transit_host = _require(env, "DEFAULT_TRANSIT_HOST")
        ws_path = _first(env, "VLESS_WS_PATH", default="/ws") or "/ws"
        if runtime_profile == "tracegate-3":
            bootstrap_password = _first(env, "HYSTERIA_BOOTSTRAP_PASSWORD", default="unused-tracegate22-bootstrap")
        else:
            bootstrap_password = _require(env, "HYSTERIA_BOOTSTRAP_PASSWORD")

        hysteria_udp_port_raw = _first(env, "HYSTERIA_UDP_PORT", default=str(TRACEGATE_PUBLIC_UDP_PORT))
        try:
            hysteria_udp_port = int(hysteria_udp_port_raw)
        except ValueError as exc:
            raise MaterializedBundleRenderError("HYSTERIA_UDP_PORT must be an integer") from exc
        if hysteria_udp_port != TRACEGATE_PUBLIC_UDP_PORT:
            raise MaterializedBundleRenderError(f"HYSTERIA_UDP_PORT must stay {TRACEGATE_PUBLIC_UDP_PORT}")

        agent_port_raw = _first(env, "AGENT_PORT", default="8070") or "8070"
        try:
            agent_port = int(agent_port_raw)
        except ValueError:
            agent_port = 8070
        default_hysteria_auth_url = f"http://127.0.0.1:{agent_port}/v1/hysteria/auth"
        if runtime_profile == "tracegate-3":
            entry_hysteria_salamander_password = _require_first(
                env,
                "HYSTERIA_GECKO_PASSWORD_ENTRY",
                "HYSTERIA_GECKO_PASSWORD",
                "HYSTERIA_SALAMANDER_PASSWORD_ENTRY",
                "HYSTERIA_SALAMANDER_PASSWORD",
            )
            transit_hysteria_salamander_password = _require_first(
                env,
                "HYSTERIA_GECKO_PASSWORD_TRANSIT",
                "HYSTERIA_GECKO_PASSWORD",
                "HYSTERIA_SALAMANDER_PASSWORD_TRANSIT",
                "HYSTERIA_SALAMANDER_PASSWORD",
            )
            entry_hysteria_stats_secret = _require_first(
                env,
                "HYSTERIA_STATS_SECRET_ENTRY",
                "AGENT_STATS_SECRET_ENTRY",
                "AGENT_STATS_SECRET",
            )
            transit_hysteria_stats_secret = _require_first(
                env,
                "HYSTERIA_STATS_SECRET_TRANSIT",
                "AGENT_STATS_SECRET_TRANSIT",
                "AGENT_STATS_SECRET",
            )
        else:
            entry_hysteria_salamander_password = _first(
                env,
                "HYSTERIA_GECKO_PASSWORD_ENTRY",
                "HYSTERIA_GECKO_PASSWORD",
                "HYSTERIA_SALAMANDER_PASSWORD_ENTRY",
                "HYSTERIA_SALAMANDER_PASSWORD",
            )
            transit_hysteria_salamander_password = _first(
                env,
                "HYSTERIA_GECKO_PASSWORD_TRANSIT",
                "HYSTERIA_GECKO_PASSWORD",
                "HYSTERIA_SALAMANDER_PASSWORD_TRANSIT",
                "HYSTERIA_SALAMANDER_PASSWORD",
            )
            entry_hysteria_stats_secret = _first(
                env,
                "HYSTERIA_STATS_SECRET_ENTRY",
                "AGENT_STATS_SECRET_ENTRY",
                "AGENT_STATS_SECRET",
            )
            transit_hysteria_stats_secret = _first(
                env,
                "HYSTERIA_STATS_SECRET_TRANSIT",
                "AGENT_STATS_SECRET_TRANSIT",
                "AGENT_STATS_SECRET",
            )
        entry_hysteria_auth_url = _first(
            env,
            "HYSTERIA_AUTH_URL_ENTRY",
            "HYSTERIA_AUTH_URL",
            default=default_hysteria_auth_url,
        ) or default_hysteria_auth_url
        transit_hysteria_auth_url = _first(
            env,
            "HYSTERIA_AUTH_URL_TRANSIT",
            "HYSTERIA_AUTH_URL",
            default=default_hysteria_auth_url,
        ) or default_hysteria_auth_url
        hysteria_chain_client_rate_limit_enabled = _bool_env(
            env,
            "HYSTERIA_CHAIN_CLIENT_RATE_LIMIT_ENABLED",
            default=True,
        )
        hysteria_chain_client_max_mbit = _int_env(
            env,
            "HYSTERIA_CHAIN_CLIENT_MAX_MBIT",
            default=10,
            min_value=1,
            max_value=10,
        )
        hysteria_chain_client_require_declared_tx = _bool_env(
            env,
            "HYSTERIA_CHAIN_CLIENT_REQUIRE_DECLARED_TX",
            default=True,
        )

        reality_public_key_entry = _first(env, "REALITY_PUBLIC_KEY_ENTRY", "REALITY_PUBLIC_KEY")
        reality_short_id_entry = _require_first(env, "REALITY_SHORT_ID_ENTRY", "REALITY_SHORT_ID")
        reality_public_key_transit = _require_first(env, "REALITY_PUBLIC_KEY_TRANSIT", "REALITY_PUBLIC_KEY")
        reality_short_id_transit = _require_first(env, "REALITY_SHORT_ID_TRANSIT", "REALITY_SHORT_ID")
        reality_private_key_entry = _require(env, "REALITY_PRIVATE_KEY_ENTRY")
        reality_private_key_transit = _require(env, "REALITY_PRIVATE_KEY_TRANSIT")

        reality_dest_default = _first(env, "REALITY_DEST", default="ibtcom.ru:443")
        reality_dest_entry = _first(env, "REALITY_DEST_ENTRY", default=reality_dest_default)
        reality_dest_transit = _first(env, "REALITY_DEST_TRANSIT", default=reality_dest_default)
        reality_server_name_entry = _first(env, "REALITY_SERVER_NAME_ENTRY", default=host_from_dest(reality_dest_entry))
        reality_server_name_transit = _first(
            env,
            "REALITY_SERVER_NAME_TRANSIT",
            default=host_from_dest(reality_dest_transit),
        )
        for label, value in (
            ("REALITY_DEST_ENTRY", reality_dest_entry),
            ("REALITY_DEST_TRANSIT", reality_dest_transit),
            ("REALITY_SERVER_NAME_ENTRY", reality_server_name_entry),
            ("REALITY_SERVER_NAME_TRANSIT", reality_server_name_transit),
        ):
            _reject_retired_reality_front(value, label=label)
        reality_multi_inbound_groups = _load_reality_multi_inbound_groups(env)

        entry_tls_server_name = _first(env, "ENTRY_TLS_SERVER_NAME", default=entry_host)
        transit_tls_server_name = _first(env, "TRANSIT_TLS_SERVER_NAME", default=transit_host)
        grafana_tls_server_name = _first(
            env,
            "GRAFANA_TLS_SERVER_NAME",
            default=_hostname_from_public_url(
                _first(env, "GRAFANA_PUBLIC_BASE_URL"),
                label="GRAFANA_PUBLIC_BASE_URL",
            ),
        )
        shadowtls_server_name_transit = _first(env, "SHADOWTLS_SERVER_NAME_TRANSIT", "SHADOWTLS_SERVER_NAME")
        # Second ShadowTLS front for the pool's leg 2. When unset, leg 2 is omitted
        # and the pool runs with the single ShadowTLS leg + the REALITY-RAW leg.
        shadowtls_backhaul2_sni = _first(env, "SHADOWTLS_BACKHAUL2_SNI")
        shadowsocks2022_password_transit = _first(
            env,
            "SHADOWSOCKS2022_PASSWORD_TRANSIT",
            "SHADOWSOCKS2022_PASSWORD",
        )
        # Independent Entry->Endpoint SS2022+ShadowTLS backhaul key (aes-256).
        # When unset the SS2022 backhaul legs are omitted and the pool degrades to
        # the REALITY-RAW transport only, so staging never breaks the live link.
        shadowsocks2022_backhaul_key = _first(
            env,
            "SHADOWSOCKS2022_BACKHAUL_KEY",
            "SHADOWSOCKS2022_BACKHAUL_KEY_TRANSIT",
        )
        # REALITY-RAW backhaul leg lands on the dedicated source-gated port (default
        # 9446; 9443/9444 host the two ShadowTLS legs) with its own decoupled
        # camouflage SNI, distinct from the client-facing REALITY identity.
        reality_backhaul_port = _int_env(
            env, "REALITY_BACKHAUL_PORT", default=9446, min_value=1, max_value=65535
        )
        reality_backhaul_sni = _first(env, "REALITY_BACKHAUL_SNI", default=reality_server_name_transit)
        _reject_retired_reality_front(reality_backhaul_sni, label="REALITY_BACKHAUL_SNI")
        mtproto_domain = _first(env, "MTPROTO_DOMAIN")
        mtproto_tls_domain = _first(env, "MTPROTO_TLS_DOMAIN", default=mtproto_domain)
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
        # Dedicated Telemt-only link: Entry -> Endpoint public TLS port. Defaults to
        # the Endpoint host so the relay works without extra configuration; operators
        # can pin it to a specific Endpoint address.
        # Dedicated source-gated link port on the Endpoint where Telemt terminates
        # the relayed FakeTLS (default 9445). Not the public :443 catch-all.
        mtproto_link_port = _int_env(env, "MTPROTO_LINK_PORT", default=9445, min_value=1, max_value=65535)
        mtproto_entry_link_upstream = _haproxy_server_address(
            _first(env, "MTPROTO_ENTRY_LINK_UPSTREAM", default=f"{transit_host}:{mtproto_link_port}")
            or f"{transit_host}:{mtproto_link_port}",
            label="MTPROTO_ENTRY_LINK_UPSTREAM",
        )
        mtproto_route_mode = _first(env, "MTPROTO_ROUTE_MODE", default="entry-endpoint-tunnel")
        mtproto_egress_socks_port = _int_env(
            env,
            "MTPROTO_EGRESS_SOCKS_PORT",
            default=11084,
            min_value=1,
            max_value=65535,
        )
        mtproto_entry_backhaul_uuid = _first(env, "MTPROTO_ENTRY_BACKHAUL_UUID", "MTPROTO_BACKHAUL_UUID")
        if mtproto_route_mode == "entry-local-endpoint-egress" and mtproto_domain and not mtproto_entry_backhaul_uuid:
            raise MaterializedBundleRenderError(
                "MTPROTO_ENTRY_BACKHAUL_UUID or MTPROTO_BACKHAUL_UUID is required for entry-local-endpoint-egress"
            )
        decoy_dir = _first(env, "XRAY_CENTRIC_DECOY_DIR", default="/var/www/decoy") or "/var/www/decoy"
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
        entry_hysteria_listen_host = _first(env, "HYSTERIA_LISTEN_HOST_ENTRY", "HYSTERIA_LISTEN_HOST")
        transit_hysteria_listen_host = _first(env, "HYSTERIA_LISTEN_HOST_TRANSIT", "HYSTERIA_LISTEN_HOST")
        entry_hysteria_tls_cert_file = _first(
            env,
            "HYSTERIA_TLS_CERT_FILE_ENTRY",
            "HYSTERIA_TLS_CERT_FILE",
            default=tls_cert_file,
        ) or tls_cert_file
        entry_hysteria_tls_key_file = _first(
            env,
            "HYSTERIA_TLS_KEY_FILE_ENTRY",
            "HYSTERIA_TLS_KEY_FILE",
            default=tls_key_file,
        ) or tls_key_file
        transit_hysteria_tls_cert_file = _first(
            env,
            "HYSTERIA_TLS_CERT_FILE_TRANSIT",
            "HYSTERIA_TLS_CERT_FILE",
            default=tls_cert_file,
        ) or tls_cert_file
        transit_hysteria_tls_key_file = _first(
            env,
            "HYSTERIA_TLS_KEY_FILE_TRANSIT",
            "HYSTERIA_TLS_KEY_FILE",
            default=tls_key_file,
        ) or tls_key_file
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
            runtime_profile=runtime_profile,
            entry_host=entry_host,
            transit_host=transit_host,
            ws_path=ws_path,
            bootstrap_password=bootstrap_password,
            hysteria_udp_port=hysteria_udp_port,
            entry_hysteria_salamander_password=entry_hysteria_salamander_password,
            transit_hysteria_salamander_password=transit_hysteria_salamander_password,
            entry_hysteria_stats_secret=entry_hysteria_stats_secret,
            transit_hysteria_stats_secret=transit_hysteria_stats_secret,
            entry_hysteria_auth_url=entry_hysteria_auth_url,
            transit_hysteria_auth_url=transit_hysteria_auth_url,
            entry_hysteria_listen_host=entry_hysteria_listen_host,
            transit_hysteria_listen_host=transit_hysteria_listen_host,
            entry_hysteria_tls_cert_file=entry_hysteria_tls_cert_file,
            entry_hysteria_tls_key_file=entry_hysteria_tls_key_file,
            transit_hysteria_tls_cert_file=transit_hysteria_tls_cert_file,
            transit_hysteria_tls_key_file=transit_hysteria_tls_key_file,
            hysteria_chain_client_rate_limit_enabled=hysteria_chain_client_rate_limit_enabled,
            hysteria_chain_client_max_mbit=hysteria_chain_client_max_mbit,
            hysteria_chain_client_require_declared_tx=hysteria_chain_client_require_declared_tx,
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
            grafana_tls_server_name=grafana_tls_server_name,
            shadowtls_server_name_transit=shadowtls_server_name_transit,
            shadowtls_backhaul2_sni=shadowtls_backhaul2_sni,
            shadowsocks2022_password_transit=shadowsocks2022_password_transit,
            shadowsocks2022_backhaul_key=shadowsocks2022_backhaul_key,
            reality_backhaul_port=reality_backhaul_port,
            reality_backhaul_sni=reality_backhaul_sni,
            mtproto_domain=mtproto_domain,
            mtproto_tls_domain=mtproto_tls_domain,
            mtproto_upstream=mtproto_upstream,
            mtproto_entry_link_upstream=mtproto_entry_link_upstream,
            mtproto_route_mode=mtproto_route_mode,
            mtproto_egress_socks_port=mtproto_egress_socks_port,
            mtproto_entry_backhaul_uuid=mtproto_entry_backhaul_uuid,
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
        f"tracegate-hysteria@{role_lower}",
        f"tracegate-haproxy@{role_lower}",
        f"tracegate-nginx@{role_lower}",
    ]


def _role_public_units_for_profile(role_lower: str, runtime_profile: str) -> list[str]:
    if runtime_profile == "tracegate-3":
        return _role_public_units(role_lower)
    return [
        f"tracegate-xray@{role_lower}",
        f"tracegate-haproxy@{role_lower}",
        f"tracegate-nginx@{role_lower}",
    ]


def _role_private_companions(ctx: "MaterializedBundleRenderContext", role_lower: str) -> list[str]:
    units = [f"tracegate-obfuscation@{role_lower}"]
    mtproto_enabled = bool(str(ctx.mtproto_domain or "").strip())
    entry_local_mtproto = ctx.mtproto_route_mode == "entry-local-endpoint-egress"
    if role_lower == "entry" and mtproto_enabled and entry_local_mtproto:
        units.append("tracegate-mtproto@entry")
    if role_lower == "transit" and mtproto_enabled and not entry_local_mtproto:
        # entry-endpoint-tunnel: Telemt terminates on the Endpoint. The prober cover
        # ("fronting") is Telemt's own mask pointed back at the Entry cover site, so
        # no separate fronting unit is deployed here.
        units.append("tracegate-mtproto@transit")
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
                "publicUnits": _role_public_units_for_profile(role_lower, ctx.runtime_profile),
                "privateCompanions": _role_private_companions(ctx, role_lower),
                "features": {
                    "runtimeProfile": ctx.runtime_profile,
                    "standaloneHysteriaEnabled": ctx.runtime_profile == "tracegate-3",
                    "hysteriaGeckoEnabled": ctx.runtime_profile == "tracegate-3",
                    "finalMaskEnabled": finalmask_enabled,
                    "echEnabled": ech_enabled,
                    "mtprotoFrontingEnabled": bool(str(ctx.mtproto_domain or "").strip())
                    and (
                        (role_upper == "ENTRY" and ctx.mtproto_route_mode == "entry-local-endpoint-egress")
                        or (role_upper == "TRANSIT" and ctx.mtproto_route_mode != "entry-local-endpoint-egress")
                    ),
                    "mtprotoDomain": str(ctx.mtproto_domain or "").strip()
                    if (
                        (role_upper == "ENTRY" and ctx.mtproto_route_mode == "entry-local-endpoint-egress")
                        or (role_upper == "TRANSIT" and ctx.mtproto_route_mode != "entry-local-endpoint-egress")
                    )
                    else "",
                    "mtprotoTlsDomain": str(ctx.mtproto_tls_domain or ctx.mtproto_domain or "").strip()
                    if (
                        (role_upper == "ENTRY" and ctx.mtproto_route_mode == "entry-local-endpoint-egress")
                        or (role_upper == "TRANSIT" and ctx.mtproto_route_mode != "entry-local-endpoint-egress")
                    )
                    else "",
                    "decoyDir": str(ctx.decoy_dir or "").strip(),
                    "transitDecoySecretPath": ctx.transit_decoy_secret_path if role_upper == "TRANSIT" else "",
                },
                "files": _bundle_files_manifest(bundle_dir),
            }
        )
    return {
        "version": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "runtimeProfile": ctx.runtime_profile,
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
        config_path.parent.mkdir(parents=True, exist_ok=True)
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
        if ctx.runtime_profile == "tracegate-3":
            _apply_text_overlay(bundle_dir / "hysteria" / "server.yaml", overlay_dir / "hysteria")
        decoy_overlay_dir = overlay_dir / "decoy"
        if decoy_overlay_dir.exists():
            _copy_tree_overlay(decoy_overlay_dir, bundle_dir / "decoy")


def _materialize_source_gated_tcp_block(
    path: Path,
    *,
    marker: str,
    source_host: str,
    ports: tuple[int, ...],
) -> None:
    """Converge a source-gated nftables block after private replacements.

    Private text overlays replace the public nftables template wholesale.  The
    inter-server link gates are runtime invariants, so they must be restored
    after that replacement instead of relying on an overlay being updated in
    lockstep with the application release.
    """

    try:
        source = ip_address(str(source_host).strip())
    except ValueError as exc:
        raise MaterializedBundleRenderError(
            f"{marker} source host must be an IP address: {source_host!r}"
        ) from exc
    family = "ip" if source.version == 4 else "ip6"
    port_expr = str(ports[0]) if len(ports) == 1 else "{ " + ", ".join(str(port) for port in ports) + " }"
    begin = f"    # BEGIN {marker}"
    end = f"    # END {marker}"
    block = "\n".join(
        (
            begin,
            "    # Generated after private overlays; only the peer host may reach this link.",
            f"    {family} saddr {source} tcp dport {port_expr} accept",
            f"    tcp dport {port_expr} drop",
            end,
        )
    )
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(rf"(?ms)^\s*# BEGIN {re.escape(marker)}$.*?^\s*# END {re.escape(marker)}$")
    if pattern.search(text):
        text = pattern.sub(block, text, count=1)
    else:
        anchor = "    ip protocol icmp accept"
        if anchor not in text:
            raise MaterializedBundleRenderError(f"{path} has no input-chain ICMP anchor for {marker}")
        text = text.replace(anchor, f"{block}\n\n{anchor}", 1)
    path.write_text(text, encoding="utf-8")


def _materialize_interserver_firewalls(ctx: MaterializedBundleRenderContext) -> None:
    # The Endpoint can bind public Hysteria on a secondary address while its
    # outbound route to Entry uses the dedicated MTProto-link address. Prefer
    # that explicit link target, then the primary Endpoint host, and only then
    # the Hysteria bind address.
    transit_source_host = host_from_dest(ctx.mtproto_entry_link_upstream)
    for candidate in (transit_source_host, ctx.transit_host, ctx.transit_hysteria_listen_host):
        try:
            ip_address(candidate)
        except ValueError:
            continue
        transit_source_host = candidate
        break
    _materialize_source_gated_tcp_block(
        ctx.materialized_root / "base-entry" / "nftables.conf",
        marker="tracegate-managed-mtproto-mask-firewall",
        source_host=transit_source_host,
        ports=(10444,),
    )
    _materialize_source_gated_tcp_block(
        ctx.materialized_root / "base-transit" / "nftables.conf",
        marker="tracegate-managed-entry-link-firewall",
        source_host=ctx.entry_hysteria_listen_host,
        ports=(9443, 9444, 9445, 9446),
    )


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


def _strip_xray_hysteria_runtime(payload: dict[str, Any]) -> None:
    hysteria_tags: set[str] = set()
    retained_inbounds: list[Any] = []
    for inbound in payload.get("inbounds", []):
        if not isinstance(inbound, dict):
            retained_inbounds.append(inbound)
            continue
        tag = str(inbound.get("tag") or "").strip()
        stream = inbound.get("streamSettings")
        network = str((stream or {}).get("network") or "").strip().lower() if isinstance(stream, dict) else ""
        if str(inbound.get("protocol") or "").strip().lower() == "hysteria" or network == "hysteria" or tag == "hy2-in":
            if tag:
                hysteria_tags.add(tag)
            continue
        retained_inbounds.append(inbound)
    payload["inbounds"] = retained_inbounds

    if not hysteria_tags:
        return
    routing = payload.get("routing")
    rules = routing.get("rules") if isinstance(routing, dict) else None
    if not isinstance(rules, list):
        return
    retained_rules: list[Any] = []
    for rule in rules:
        if not isinstance(rule, dict):
            retained_rules.append(rule)
            continue
        inbound_tags = rule.get("inboundTag")
        if not isinstance(inbound_tags, list):
            retained_rules.append(rule)
            continue
        updated_tags = [tag for tag in inbound_tags if str(tag) not in hysteria_tags]
        if not updated_tags:
            continue
        if len(updated_tags) != len(inbound_tags):
            rule = dict(rule)
            rule["inboundTag"] = updated_tags
        retained_rules.append(rule)
    routing["rules"] = retained_rules


def _yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return json.dumps(str(value), ensure_ascii=True)


def _render_hysteria_server_yaml(
    *,
    listen_host: str,
    listen_port: int,
    tls_cert_file: str,
    tls_key_file: str,
    auth_url: str,
    salamander_password: str,
    stats_secret: str,
    decoy_dir: str,
    chain_client_rate_limit_enabled: bool = False,
    chain_client_max_mbit: int = 10,
) -> str:
    listen_address = f"{listen_host}:{listen_port}" if listen_host else f":{listen_port}"
    lines = [
        f"listen: {_yaml_scalar(listen_address)}",
        "tls:",
        f"  cert: {_yaml_scalar(tls_cert_file)}",
        f"  key: {_yaml_scalar(tls_key_file)}",
        "  sniGuard: dns-san",
        "auth:",
        "  type: http",
        "  http:",
        f"    url: {_yaml_scalar(auth_url)}",
        "    insecure: false",
        "obfs:",
        "  type: gecko",
        "  gecko:",
        f"    password: {_yaml_scalar(salamander_password)}",
        "    minPacketSize: 512",
        "    maxPacketSize: 1200",
        "quic:",
        "  maxIdleTimeout: 2m",
        "  disablePathMTUDiscovery: false",
        "congestion:",
        "  type: bbr",
    ]
    if chain_client_rate_limit_enabled:
        lines.extend(
            [
                "bandwidth:",
                f"  up: {chain_client_max_mbit} mbps",
                f"  down: {chain_client_max_mbit} mbps",
                "ignoreClientBandwidth: false",
            ]
        )
    else:
        lines.append("ignoreClientBandwidth: true")
    lines.extend(
        [
            "disableUDP: false",
            "udpIdleTimeout: 5m",
            "sniff:",
            "  enable: true",
            "  timeout: 2s",
            "trafficStats:",
            "  listen: 127.0.0.1:9999",
            f"  secret: {_yaml_scalar(stats_secret)}",
            "masquerade:",
            "  type: file",
            "  file:",
            f"    dir: {_yaml_scalar(decoy_dir)}",
            "",
        ]
    )
    return "\n".join(lines)


def _write_hysteria_server_configs(ctx: MaterializedBundleRenderContext) -> None:
    if ctx.runtime_profile != "tracegate-3":
        return
    for (
        bundle_name,
        auth_url,
        salamander_password,
        stats_secret,
        chain_client_rate_limit_enabled,
        listen_host,
        tls_cert_file,
        tls_key_file,
    ) in (
        (
            "base-entry",
            ctx.entry_hysteria_auth_url,
            ctx.entry_hysteria_salamander_password,
            ctx.entry_hysteria_stats_secret,
            ctx.hysteria_chain_client_rate_limit_enabled,
            ctx.entry_hysteria_listen_host,
            ctx.entry_hysteria_tls_cert_file,
            ctx.entry_hysteria_tls_key_file,
        ),
        (
            "base-transit",
            ctx.transit_hysteria_auth_url,
            ctx.transit_hysteria_salamander_password,
            ctx.transit_hysteria_stats_secret,
            False,
            ctx.transit_hysteria_listen_host,
            ctx.transit_hysteria_tls_cert_file,
            ctx.transit_hysteria_tls_key_file,
        ),
    ):
        target = ctx.materialized_root / bundle_name / "hysteria" / "server.yaml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            _render_hysteria_server_yaml(
                listen_host=listen_host,
                listen_port=ctx.hysteria_udp_port,
                tls_cert_file=tls_cert_file,
                tls_key_file=tls_key_file,
                auth_url=auth_url,
                salamander_password=salamander_password,
                stats_secret=stats_secret,
                decoy_dir=ctx.decoy_dir,
                chain_client_rate_limit_enabled=chain_client_rate_limit_enabled,
                chain_client_max_mbit=ctx.hysteria_chain_client_max_mbit,
            ),
            encoding="utf-8",
        )


def _materialize_ss2022_backhaul_inbound(payload: dict[str, Any], *, key: str) -> None:
    """Provision or remove the isolated Entry->Endpoint SS2022 backhaul inbound.

    The backhaul leg is optional. When no aes-256 key is provisioned the inbound
    is dropped entirely (never rendered with a placeholder password, which would
    be an invalid SS2022 key and crash the runtime), and any routing reference to
    it is pruned so the isolated Xray config stays valid.
    """
    tag = "ss2022-backhaul-in"
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return
    inbound = next(
        (row for row in inbounds if isinstance(row, dict) and str(row.get("tag") or "") == tag),
        None,
    )
    if key:
        if inbound is not None:
            inbound.setdefault("settings", {})["password"] = key
        return
    payload["inbounds"] = [
        row for row in inbounds if not (isinstance(row, dict) and str(row.get("tag") or "") == tag)
    ]
    routing = payload.get("routing")
    rules = routing.get("rules") if isinstance(routing, dict) else None
    if not isinstance(rules, list):
        return
    pruned_rules: list[Any] = []
    for rule in rules:
        if not isinstance(rule, dict):
            pruned_rules.append(rule)
            continue
        inbound_tags = rule.get("inboundTag")
        if isinstance(inbound_tags, list) and tag in inbound_tags:
            remaining = [item for item in inbound_tags if str(item) != tag]
            if not remaining:
                continue
            rule = dict(rule)
            rule["inboundTag"] = remaining
        pruned_rules.append(rule)
    routing["rules"] = pruned_rules


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
        tag = str(outbound.get("tag") or "")
        if tag == "to-transit":
            # REALITY-RAW leg (heterogeneous fallback in the pool). Dials the
            # dedicated source-gated backhaul port with its own decoupled camouflage
            # SNI, distinct from the client-facing REALITY identity.
            vnext = (((outbound.get("settings") or {}).get("vnext")) or [])
            if vnext:
                vnext[0]["address"] = ctx.transit_host
                vnext[0]["port"] = ctx.reality_backhaul_port
            reality = outbound.setdefault("streamSettings", {}).setdefault("realitySettings", {})
            reality["serverName"] = ctx.reality_backhaul_sni
            reality["publicKey"] = ctx.reality_public_key_transit
            reality["shortId"] = ctx.reality_short_id_transit
        elif tag in ("to-transit-ss", "to-transit-ss2") and ctx.shadowsocks2022_backhaul_key:
            # SS2022 legs wrapped by ShadowTLS v3 on the Entry loopback (leg 1 -> the
            # primary ShadowTLS client, leg 2 -> the second ShadowTLS client / front).
            servers = (((outbound.get("settings") or {}).get("servers")) or [])
            if servers:
                servers[0]["password"] = ctx.shadowsocks2022_backhaul_key
    if not ctx.shadowsocks2022_backhaul_key:
        # No SS2022 backhaul key provisioned yet: keep the Entry runtime on the
        # single REALITY-RAW leg. Never emit a placeholder SS2022 password, which
        # would be an invalid key and crash the Xray runtime. Drop the pool
        # machinery too (observatory + balancer) and route Chain straight at the
        # sole `to-transit` outbound so there is no dangling balancerTag.
        entry_xray["outbounds"] = [
            outbound
            for outbound in entry_xray.get("outbounds", [])
            if str(outbound.get("tag") or "") not in ("to-transit-ss", "to-transit-ss2")
        ]
        entry_xray.pop("observatory", None)
        routing = entry_xray.get("routing")
        if isinstance(routing, dict):
            routing.pop("balancers", None)
            for rule in routing.get("rules", []):
                if isinstance(rule, dict) and rule.get("balancerTag") == "backhaul-balancer":
                    rule.pop("balancerTag", None)
                    rule["outboundTag"] = "to-transit"
    elif not ctx.shadowtls_backhaul2_sni:
        # SS2022 key present but no second ShadowTLS front configured: run the pool
        # with one ShadowTLS leg + the REALITY-RAW leg (drop the unwired leg 2).
        entry_xray["outbounds"] = [
            outbound
            for outbound in entry_xray.get("outbounds", [])
            if str(outbound.get("tag") or "") != "to-transit-ss2"
        ]
    if ctx.mtproto_route_mode == "entry-local-endpoint-egress" and ctx.mtproto_domain:
        entry_xray.setdefault("inbounds", []).append(
            {
                "tag": "mtproto-egress-socks-in",
                "listen": "127.0.0.1",
                "port": ctx.mtproto_egress_socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
                "sniffing": {"enabled": False},
            }
        )
        entry_xray.setdefault("outbounds", []).append(
            {
                "tag": "mtproto-egress-endpoint-ws",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": ctx.transit_host,
                            "port": 443,
                            "users": [
                                {
                                    "id": ctx.mtproto_entry_backhaul_uuid,
                                    "encryption": "none",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": ctx.transit_tls_server_name,
                        "allowInsecure": False,
                        "alpn": ["http/1.1"],
                    },
                    "wsSettings": {
                        "path": ctx.ws_path,
                        "headers": {"Host": ctx.transit_tls_server_name},
                    },
                },
            }
        )
        entry_xray.setdefault("routing", {}).setdefault("rules", []).insert(
            0,
            {
                "type": "field",
                "inboundTag": ["mtproto-egress-socks-in"],
                "outboundTag": "mtproto-egress-endpoint-ws",
            },
        )
    _materialize_reality_groups(
        entry_xray,
        source_tag="entry-in",
        groups=ctx.reality_multi_inbound_groups,
    )
    if ctx.runtime_profile == "tracegate-3":
        _strip_xray_hysteria_runtime(entry_xray)
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
    entry_haproxy = entry_haproxy.replace(
        "REPLACE_ENTRY_BIND_HOST",
        ctx.entry_hysteria_listen_host,
    )
    entry_mtproto_acl = ""
    entry_mtproto_route = ""
    entry_mtproto_backend = ""
    entry_mtproto_sni = str(ctx.mtproto_tls_domain or ctx.mtproto_domain or "").strip()
    if ctx.mtproto_domain:
        entry_mtproto_acl = f"  acl mtproto_tls_sni req.ssl_sni -i {entry_mtproto_sni}"
        entry_mtproto_route = "  use_backend be_mtproto_tls if mtproto_tls_sni"
        if ctx.mtproto_route_mode == "entry-local-endpoint-egress":
            # Telemt runs on Entry: hand it the real client address via PROXY v2.
            entry_mtproto_backend = (
                f"\nbackend be_mtproto_tls\n"
                f"  server mtproto {ctx.mtproto_upstream} check send-proxy-v2\n"
            )
        else:
            # Dedicated Telemt-only Entry->Endpoint link. Telemt runs on Endpoint,
            # listening on a source-gated port (default 9445) and terminating the
            # client's FakeTLS itself. Entry relays the ClientHello with PROXY v2 so
            # the real client address survives (Telemt trusts the Entry source and
            # parses the header). There is no Endpoint HAProxy hop on this path.
            entry_mtproto_backend = (
                f"\nbackend be_mtproto_tls\n"
                f"  server mtproto {ctx.mtproto_entry_link_upstream} check-send-proxy send-proxy-v2 inter 10s\n"
            )
    entry_haproxy = entry_haproxy.replace("REPLACE_ENTRY_MTPROTO_ACL", entry_mtproto_acl)
    entry_haproxy = entry_haproxy.replace("REPLACE_ENTRY_MTPROTO_ROUTE", entry_mtproto_route)
    entry_haproxy = entry_haproxy.replace("REPLACE_ENTRY_MTPROTO_BACKEND", entry_mtproto_backend)
    entry_haproxy = entry_haproxy.replace("REPLACE_REALITY_ACLS", entry_reality_acls)
    entry_haproxy = entry_haproxy.replace("REPLACE_REALITY_ROUTES", entry_reality_routes)
    entry_haproxy = entry_haproxy.replace("REPLACE_REALITY_BACKENDS", entry_reality_backends)
    entry_haproxy_path.write_text(entry_haproxy, encoding="utf-8")

    entry_nginx_path = ctx.materialized_root / "base-entry" / "nginx.conf"
    entry_nginx = entry_nginx_path.read_text(encoding="utf-8").replace(
        "REPLACE_TLS_SERVER_NAME",
        ctx.entry_tls_server_name,
    )
    entry_nginx = entry_nginx.replace("REPLACE_ENTRY_BIND_HOST", ctx.entry_hysteria_listen_host)
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
            if ctx.mtproto_route_mode == "entry-local-endpoint-egress" and ctx.mtproto_domain:
                clients = inbound.setdefault("settings", {}).setdefault("clients", [])
                if not any(str(client.get("id") or "") == ctx.mtproto_entry_backhaul_uuid for client in clients):
                    clients.append(
                        {
                            "id": ctx.mtproto_entry_backhaul_uuid,
                            "email": "mtproto-entry-egress",
                        }
                    )
    _materialize_reality_groups(
        transit_xray,
        source_tag="vless-reality-in",
        groups=ctx.reality_multi_inbound_groups,
    )
    if ctx.runtime_profile == "tracegate-3":
        _strip_xray_hysteria_runtime(transit_xray)
    _write_json(transit_xray_path, transit_xray)

    transit_ss2022_path = ctx.materialized_root / "base-transit" / "xray-ss2022.json"
    transit_ss2022 = json.loads(transit_ss2022_path.read_text(encoding="utf-8"))
    if not ctx.shadowsocks2022_password_transit:
        raise MaterializedBundleRenderError(
            "SHADOWSOCKS2022_PASSWORD_TRANSIT or SHADOWSOCKS2022_PASSWORD is required for ss2022-in"
        )
    ss2022_inbound = next(
        (
            inbound
            for inbound in transit_ss2022.get("inbounds", [])
            if isinstance(inbound, dict) and str(inbound.get("tag") or "") == "ss2022-in"
        ),
        None,
    )
    if ss2022_inbound is None:
        raise MaterializedBundleRenderError("base-transit/xray-ss2022.json is missing ss2022-in")
    ss2022_inbound.setdefault("settings", {})["password"] = ctx.shadowsocks2022_password_transit
    _materialize_ss2022_backhaul_inbound(transit_ss2022, key=ctx.shadowsocks2022_backhaul_key)
    _write_json(transit_ss2022_path, transit_ss2022)

    transit_haproxy_path = ctx.materialized_root / "base-transit" / "haproxy.cfg"
    transit_reality_acls, transit_reality_routes, transit_reality_backends = _render_reality_demux(
        role_lower="transit",
        groups=ctx.reality_multi_inbound_groups,
    )
    transit_web_tls_server_names = " ".join(
        dict.fromkeys(
            name
            for name in (ctx.transit_tls_server_name, ctx.grafana_tls_server_name)
            if name
        )
    )
    transit_haproxy = transit_haproxy_path.read_text(encoding="utf-8").replace(
        "REPLACE_TLS_SERVER_NAME",
        transit_web_tls_server_names,
    )
    shadowtls_acl = ""
    shadowtls_route = ""
    shadowtls_backend = ""
    if ctx.shadowtls_server_name_transit:
        shadowtls_acl = f"  acl shadowtls_sni req.ssl_sni -i {ctx.shadowtls_server_name_transit}"
        shadowtls_route = "  use_backend be_transit_shadowtls if shadowtls_sni"
        shadowtls_backend = (
            "\nbackend be_transit_shadowtls\n"
            "  server transit_shadowtls 127.0.0.1:14443 check\n"
        )
    # entry-endpoint-tunnel: Telemt on the Endpoint listens on its own source-gated
    # link port (default 9445) and the Entry relay dials it directly, so the public
    # :443 frontend carries no MTProto backend. entry-local mode terminates Telemt on
    # the Entry, so the Endpoint has no MTProto backend in that mode either.
    mtproto_acl = ""
    mtproto_route = ""
    mtproto_backend = ""
    transit_haproxy = transit_haproxy.replace("REPLACE_MTPROTO_ACL", mtproto_acl)
    transit_haproxy = transit_haproxy.replace("REPLACE_MTPROTO_ROUTE", mtproto_route)
    transit_haproxy = transit_haproxy.replace("REPLACE_MTPROTO_BACKEND", mtproto_backend)
    transit_haproxy = transit_haproxy.replace("REPLACE_SHADOWTLS_ACL", shadowtls_acl)
    transit_haproxy = transit_haproxy.replace("REPLACE_SHADOWTLS_ROUTE", shadowtls_route)
    transit_haproxy = transit_haproxy.replace("REPLACE_SHADOWTLS_BACKEND", shadowtls_backend)
    transit_haproxy = transit_haproxy.replace("REPLACE_REALITY_ACLS", transit_reality_acls)
    transit_haproxy = transit_haproxy.replace("REPLACE_REALITY_ROUTES", transit_reality_routes)
    transit_haproxy = transit_haproxy.replace("REPLACE_REALITY_BACKENDS", transit_reality_backends)
    transit_haproxy_path.write_text(transit_haproxy, encoding="utf-8")

    transit_nginx_path = ctx.materialized_root / "base-transit" / "nginx.conf"
    transit_nginx = transit_nginx_path.read_text(encoding="utf-8").replace(
        "REPLACE_TLS_SERVER_NAME",
        transit_web_tls_server_names,
    )
    transit_nginx = transit_nginx.replace("/var/www/decoy", ctx.decoy_dir)
    transit_nginx = transit_nginx.replace("REPLACE_TRANSIT_DECOY_UPSTREAM", ctx.transit_decoy_agent_upstream)
    transit_nginx = transit_nginx.replace("REPLACE_TRANSIT_SECRET_PATH", ctx.transit_decoy_secret_path)
    transit_nginx_path.write_text(transit_nginx, encoding="utf-8")

    _write_hysteria_server_configs(ctx)
    _apply_private_overlays(ctx)
    _materialize_interserver_firewalls(ctx)
    _materialize_transit_secret_surface(ctx)
    _write_materialized_manifest(ctx)
