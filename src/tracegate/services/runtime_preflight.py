from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from tracegate.constants import (
    TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT,
    TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT,
    TRACEGATE_PUBLIC_UDP_PORT,
)
from tracegate.services.mtproto import MTPROTO_FAKE_TLS_PROFILE_NAME
from tracegate.services.runtime_contract import TRACEGATE21_CLIENT_PROFILES


class RuntimePreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimePreflightFinding:
    severity: str  # error | warning
    code: str
    message: str


@dataclass(frozen=True)
class ZapretProfile:
    path: Path
    profile_name: str
    scope: str
    cpu_budget: str
    apply_mode: str
    target_tcp_ports: tuple[int, ...]
    target_udp_ports: tuple[int, ...]
    target_protocols: tuple[str, ...]
    target_surfaces: tuple[str, ...]
    touch_unrelated_system_traffic: bool
    max_workers: int
    notes: str


@dataclass(frozen=True)
class ZapretScopePolicy:
    expected_scope: str
    recommended_protocols: tuple[str, ...]
    allowed_surfaces: tuple[str, ...]
    recommended_tcp_ports: tuple[int, ...]
    recommended_udp_ports: tuple[int, ...]
    allowed_cpu_budgets: tuple[str, ...] = ("minimal", "low")
    max_workers_soft_limit: int = 1


@dataclass(frozen=True)
class ObfuscationRuntimeState:
    path: Path
    role: str
    interface: str
    runtime_profile: str
    runtime_contract_path: str
    contract_present: bool
    decoy_roots: tuple[str, ...]
    split_hysteria_masquerade_dirs: tuple[str, ...]
    xray_hysteria_masquerade_dirs: tuple[str, ...]
    xray_config_paths: tuple[str, ...]
    xray_hysteria_inbound_tags: tuple[str, ...]
    finalmask_enabled: bool
    ech_enabled: bool
    backend: str
    zapret_profile_file: str
    zapret_interconnect_profile_file: str
    zapret_mtproto_profile_file: str
    zapret_policy_dir: str
    zapret_state_dir: str
    fronting_tcp_owner: str
    fronting_udp_owner: str
    touch_udp_443: bool
    mtproto_domain: str
    mtproto_public_port: int
    mtproto_fronting_mode: str


@dataclass(frozen=True)
class ObfuscationRuntimeEnv:
    path: Path
    role: str
    interface: str
    runtime_profile: str
    runtime_contract_path: str
    contract_present: bool
    runtime_state_json: str
    backend: str
    decoy_roots: tuple[str, ...]
    split_hysteria_masquerade_dirs: tuple[str, ...]
    xray_hysteria_masquerade_dirs: tuple[str, ...]
    xray_config_paths: tuple[str, ...]
    xray_hysteria_inbound_tags: tuple[str, ...]
    finalmask_enabled: bool
    ech_enabled: bool
    zapret_profile_file: str
    zapret_interconnect_profile_file: str
    zapret_mtproto_profile_file: str
    zapret_policy_dir: str
    zapret_state_dir: str
    fronting_tcp_owner: str
    fronting_udp_owner: str
    touch_udp_443: bool
    mtproto_domain: str
    mtproto_public_port: int
    mtproto_fronting_mode: str


@dataclass(frozen=True)
class ObfuscationEnvContract:
    path: Path
    enabled: bool
    backend: str
    private_runtime_dir: str
    zapret_root: str
    zapret_runner: str
    zapret_policy_dir: str
    zapret_state_dir: str
    zapret_profile_dir: str
    zapret_profile_entry: str
    zapret_profile_transit: str
    zapret_profile_interconnect: str
    zapret_profile_mtproto: str
    finalmask_mode: str
    entry_runtime_contract: str
    transit_runtime_contract: str
    entry_interface: str
    transit_interface: str


@dataclass(frozen=True)
class FrontingRuntimeState:
    path: Path
    action: str
    role: str
    backend: str
    runtime_state_json: str
    listen_addr: str
    protocol: str
    reality_upstream: str
    ws_tls_upstream: str
    mtproto_upstream: str
    mtproto_profile_file: str
    touch_udp_443: bool
    mtproto_domain: str
    mtproto_fronting_mode: str
    tcp_443_owner: str
    udp_443_owner: str
    cfg_file: str
    pid_file: str
    ws_sni: str


@dataclass(frozen=True)
class FrontingEnvContract:
    path: Path
    enabled: bool
    role: str
    backend: str
    runtime_state_json: str
    listen_addr: str
    protocol: str
    reality_upstream: str
    ws_tls_upstream: str
    mtproto_upstream: str
    mtproto_profile_file: str
    state_dir: str
    runtime_dir: str
    runner: str
    haproxy_bin: str
    ws_sni: str
    mtproto_domain_override: str
    touch_udp_443: bool
    notes: str


@dataclass(frozen=True)
class MTProtoGatewayState:
    path: Path
    action: str
    role: str
    backend: str
    domain: str
    public_port: int
    upstream_host: str
    upstream_port: int
    profile_file: str
    runtime_state_json: str
    public_profile_file: str
    issued_state_file: str


@dataclass(frozen=True)
class MTProtoEnvContract:
    path: Path
    enabled: bool
    role: str
    backend: str
    runtime_state_json: str
    profile_file: str
    domain: str
    public_port: int
    upstream_host: str
    upstream_port: int
    tls_mode: str
    secret_file: str
    state_dir: str
    issued_state_file: str
    binary: str
    runtime_dir: str
    stats_port: int
    run_as_user: str
    workers: int
    proxy_tag: str
    fetch_secret_url: str
    fetch_config_url: str
    bootstrap_max_age_seconds: int
    proxy_secret_file: str
    proxy_config_file: str
    pid_file: str
    log_file: str
    notes: str


@dataclass(frozen=True)
class MTProtoPublicProfile:
    path: Path
    protocol: str
    profile_name: str
    server: str
    port: int
    transport: str
    domain: str
    client_secret_hex: str
    tg_uri: str
    https_url: str


@dataclass(frozen=True)
class PrivateProfileState:
    path: Path
    schema: str
    version: int
    role: str
    runtime_profile: str
    runtime_contract_path: str
    transport_profiles: dict[str, Any]
    secret_material: bool
    total_count: int
    shadowsocks2022_shadowtls_count: int
    wireguard_wstunnel_count: int
    shadowsocks2022_shadowtls: tuple[dict[str, Any], ...]
    wireguard_wstunnel: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class PrivateProfileEnv:
    path: Path
    role: str
    runtime_profile: str
    state_json: str
    secret_material: bool
    total_count: int
    shadowsocks2022_shadowtls_count: int
    wireguard_wstunnel_count: int


@dataclass(frozen=True)
class LinkCryptoState:
    path: Path
    schema: str
    version: int
    role: str
    runtime_profile: str
    runtime_contract_path: str
    transport_profiles: dict[str, Any]
    secret_material: bool
    total_count: int
    entry_transit_count: int
    router_entry_count: int
    router_transit_count: int
    udp_total_count: int
    entry_transit_udp_count: int
    router_entry_udp_count: int
    router_transit_udp_count: int
    links: tuple[dict[str, Any], ...]
    udp_links: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class LinkCryptoEnv:
    path: Path
    role: str
    runtime_profile: str
    state_json: str
    secret_material: bool
    total_count: int
    classes: tuple[str, ...]
    carrier: str
    outer_carrier_enabled: bool
    outer_carrier_mode: str
    outer_wss_server_name: str
    outer_wss_public_port: int
    outer_wss_path: str
    outer_wss_verify_tls: bool
    outer_wss_spki_pinning_required: bool
    outer_wss_admission_required: bool
    generation: int
    zapret2_enabled: bool
    zapret2_required: bool
    zapret2_host_wide_interception: bool
    zapret2_nfqueue: bool
    tcp_dpi_resistance_required: bool
    tcp_traffic_shaping_required: bool
    promotion_preflight_required: bool


@dataclass(frozen=True)
class RouterHandoffState:
    path: Path
    schema: str
    version: int
    role: str
    runtime_profile: str
    runtime_contract_path: str
    secret_material: bool
    enabled: bool
    placement: str
    contract: dict[str, Any]
    total_count: int
    tcp_count: int
    udp_count: int
    tcp_classes: tuple[str, ...]
    udp_classes: tuple[str, ...]
    tcp_routes: tuple[dict[str, Any], ...]
    udp_routes: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class RouterHandoffEnv:
    path: Path
    role: str
    runtime_profile: str
    state_json: str
    secret_material: bool
    enabled: bool
    total_count: int
    tcp_count: int
    udp_count: int
    tcp_classes: tuple[str, ...]
    udp_classes: tuple[str, ...]
    paired_obfs_enabled: bool
    requires_private_profile: bool
    router_is_entry_replacement: bool
    no_host_wide_interception: bool
    no_nfqueue: bool


@dataclass(frozen=True)
class RouterClientBundle:
    path: Path
    schema: str
    version: int
    role: str
    runtime_profile: str
    handoff_state_json: str
    secret_material: bool
    enabled: bool
    placement: str
    requirements: dict[str, Any]
    total_count: int
    tcp_count: int
    udp_count: int
    tcp_classes: tuple[str, ...]
    udp_classes: tuple[str, ...]
    components: tuple[dict[str, Any], ...]
    tcp_routes: tuple[dict[str, Any], ...]
    udp_routes: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class RouterClientBundleEnv:
    path: Path
    role: str
    runtime_profile: str
    bundle_json: str
    handoff_json: str
    secret_material: bool
    enabled: bool
    components: tuple[str, ...]
    tcp_count: int
    udp_count: int
    requires_both_sides: bool
    fail_closed: bool
    no_host_wide_interception: bool
    no_nfqueue: bool


@dataclass(frozen=True)
class SystemdUnitContract:
    path: Path
    description: str
    after: tuple[str, ...]
    wants: tuple[str, ...]
    condition_path_exists: tuple[str, ...]
    environment_files: tuple[str, ...]
    environments: tuple[str, ...]
    service_type: str
    remain_after_exit: str
    exec_start: str
    exec_reload: str
    exec_stop: str
    wanted_by: tuple[str, ...]


_ZAPRET_SCOPE_POLICIES: dict[str, ZapretScopePolicy] = {
    "entry": ZapretScopePolicy(
        expected_scope="entry",
        recommended_protocols=("v2", "v4", "v6"),
        allowed_surfaces=("vless_reality", "hysteria2", "shadowtls_v3"),
        recommended_tcp_ports=(443,),
        recommended_udp_ports=(TRACEGATE_PUBLIC_UDP_PORT,),
    ),
    "transit": ZapretScopePolicy(
        expected_scope="transit",
        recommended_protocols=("v1", "v3", "v5", "v7"),
        allowed_surfaces=("vless_reality", "vless_ws_tls", "vless_grpc_tls", "hysteria2", "shadowtls_v3", "wstunnel"),
        recommended_tcp_ports=(443,),
        recommended_udp_ports=(TRACEGATE_PUBLIC_UDP_PORT,),
    ),
    "interconnect": ZapretScopePolicy(
        expected_scope="entry-transit",
        recommended_protocols=("v2", "v4", "v6"),
        allowed_surfaces=("entry_transit_private_relay", "link_crypto_outer", "mieru_outer", "wss_carrier"),
        recommended_tcp_ports=(443,),
        recommended_udp_ports=(TRACEGATE_PUBLIC_UDP_PORT,),
        allowed_cpu_budgets=("low",),
        max_workers_soft_limit=1,
    ),
    "mtproto": ZapretScopePolicy(
        expected_scope="mtproto",
        recommended_protocols=("mtproto",),
        allowed_surfaces=("telegram-mtproto",),
        recommended_tcp_ports=(443,),
        recommended_udp_ports=(),
    ),
}
_XRAY_API_ALLOWED_SERVICES = {"HandlerService", "StatsService"}


def load_runtime_contract(path: str | Path) -> dict[str, Any]:
    contract_path = Path(path)
    try:
        payload = json.loads(contract_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"runtime contract not found: {contract_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePreflightError(f"runtime contract is not valid JSON: {contract_path}") from exc
    if not isinstance(payload, dict):
        raise RuntimePreflightError(f"runtime contract must be a JSON object: {contract_path}")
    return payload


def load_obfuscation_runtime_state(path: str | Path) -> ObfuscationRuntimeState:
    state_path = Path(path)
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"obfuscation runtime-state not found: {state_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePreflightError(f"obfuscation runtime-state is not valid JSON: {state_path}") from exc
    if not isinstance(payload, dict):
        raise RuntimePreflightError(f"obfuscation runtime-state must be a JSON object: {state_path}")

    fronting = payload.get("fronting")
    if not isinstance(fronting, dict):
        fronting = {}

    public = payload.get("public")
    if not isinstance(public, dict):
        public = {}

    try:
        mtproto_public_port = int(fronting.get("mtprotoPublicPort") or 443)
    except (TypeError, ValueError) as exc:
        raise RuntimePreflightError(f"invalid mtprotoPublicPort in obfuscation runtime-state: {state_path}") from exc

    return ObfuscationRuntimeState(
        path=state_path,
        role=str(payload.get("role") or "").strip().upper(),
        interface=str(payload.get("interface") or "").strip(),
        runtime_profile=str(payload.get("runtimeProfile") or "").strip().lower(),
        runtime_contract_path=str(payload.get("runtimeContractPath") or "").strip(),
        contract_present=bool(payload.get("contractPresent", False)),
        decoy_roots=tuple(_string_list(payload.get("decoyRoots"))),
        split_hysteria_masquerade_dirs=tuple(_string_list(payload.get("splitHysteriaMasqueradeDirs"))),
        xray_hysteria_masquerade_dirs=tuple(_string_list(payload.get("xrayHysteriaMasqueradeDirs"))),
        xray_config_paths=tuple(_string_list(payload.get("xrayConfigPaths"))),
        xray_hysteria_inbound_tags=tuple(_string_list(payload.get("xrayHysteriaInboundTags"))),
        finalmask_enabled=bool(payload.get("finalMaskEnabled", False)),
        ech_enabled=bool(payload.get("echEnabled", False)),
        backend=str(payload.get("backend") or "").strip().lower(),
        zapret_profile_file=str(public.get("zapretProfileFile") or "").strip(),
        zapret_interconnect_profile_file=str(public.get("zapretInterconnectProfileFile") or "").strip(),
        zapret_mtproto_profile_file=str(public.get("zapretMtprotoProfileFile") or "").strip(),
        zapret_policy_dir=str(public.get("zapretPolicyDir") or "").strip(),
        zapret_state_dir=str(public.get("zapretStateDir") or "").strip(),
        fronting_tcp_owner=str(fronting.get("tcp443Owner") or "").strip(),
        fronting_udp_owner=str(fronting.get("publicUdpOwner") or fronting.get("udp443Owner") or "").strip(),
        touch_udp_443=bool(fronting.get("touchUdp443", False)),
        mtproto_domain=str(fronting.get("mtprotoDomain") or "").strip(),
        mtproto_public_port=mtproto_public_port,
        mtproto_fronting_mode=str(fronting.get("mtprotoFrontingMode") or "dedicated-dns-only").strip().lower(),
    )


def load_obfuscation_runtime_env(path: str | Path) -> ObfuscationRuntimeEnv:
    env_path = Path(path)
    payload = _load_env_file(env_path, label="obfuscation runtime-state env")

    return ObfuscationRuntimeEnv(
        path=env_path,
        role=_require_env_field(payload, env_path, "TRACEGATE_RUNTIME_ROLE", label="obfuscation runtime-state env").upper(),
        interface=str(payload.get("TRACEGATE_NETWORK_INTERFACE") or "").strip(),
        runtime_profile=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_RUNTIME_PROFILE",
            label="obfuscation runtime-state env",
        ).lower(),
        runtime_contract_path=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_RUNTIME_CONTRACT",
            label="obfuscation runtime-state env",
        ),
        contract_present=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_RUNTIME_CONTRACT_PRESENT",
                label="obfuscation runtime-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_RUNTIME_CONTRACT_PRESENT",
            label="obfuscation runtime-state env",
        ),
        runtime_state_json=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_RUNTIME_STATE_JSON",
            label="obfuscation runtime-state env",
        ),
        backend=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_OBFUSCATION_BACKEND",
            label="obfuscation runtime-state env",
        ).lower(),
        decoy_roots=_colon_tokens(str(payload.get("TRACEGATE_DECOY_ROOTS") or "")),
        split_hysteria_masquerade_dirs=_colon_tokens(str(payload.get("TRACEGATE_SPLIT_HYSTERIA_DIRS") or "")),
        xray_hysteria_masquerade_dirs=_colon_tokens(str(payload.get("TRACEGATE_XRAY_HYSTERIA_DIRS") or "")),
        xray_config_paths=_colon_tokens(str(payload.get("TRACEGATE_XRAY_CONFIG_PATHS") or "")),
        xray_hysteria_inbound_tags=_colon_tokens(str(payload.get("TRACEGATE_XRAY_HYSTERIA_TAGS") or "")),
        finalmask_enabled=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_FINALMASK_ENABLED",
                label="obfuscation runtime-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_FINALMASK_ENABLED",
            label="obfuscation runtime-state env",
        ),
        ech_enabled=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_ECH_ENABLED",
                label="obfuscation runtime-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_ECH_ENABLED",
            label="obfuscation runtime-state env",
        ),
        zapret_profile_file=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_ZAPRET_PROFILE_FILE",
            label="obfuscation runtime-state env",
        ),
        zapret_interconnect_profile_file=str(payload.get("TRACEGATE_ZAPRET_INTERCONNECT_PROFILE_FILE") or "").strip(),
        zapret_mtproto_profile_file=str(payload.get("TRACEGATE_ZAPRET_MTPROTO_PROFILE_FILE") or "").strip(),
        zapret_policy_dir=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_ZAPRET_POLICY_DIR",
            label="obfuscation runtime-state env",
        ),
        zapret_state_dir=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_ZAPRET_STATE_DIR",
            label="obfuscation runtime-state env",
        ),
        fronting_tcp_owner=str(payload.get("TRACEGATE_TCP_443_OWNER") or "").strip(),
        fronting_udp_owner=str(
            payload.get("TRACEGATE_PUBLIC_UDP_OWNER") or payload.get("TRACEGATE_UDP_443_OWNER") or ""
        ).strip(),
        touch_udp_443=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_TOUCH_UDP_443",
                label="obfuscation runtime-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_TOUCH_UDP_443",
            label="obfuscation runtime-state env",
        ),
        mtproto_domain=str(payload.get("TRACEGATE_MTPROTO_DOMAIN") or "").strip(),
        mtproto_public_port=_parse_int(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_MTPROTO_PUBLIC_PORT",
                label="obfuscation runtime-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_MTPROTO_PUBLIC_PORT",
            label="obfuscation runtime-state env",
        ),
        mtproto_fronting_mode=str(payload.get("TRACEGATE_MTPROTO_FRONTING_MODE") or "dedicated-dns-only").strip().lower(),
    )


def load_obfuscation_env_contract(path: str | Path) -> ObfuscationEnvContract:
    env_path = Path(path)
    payload = _load_env_file(env_path, label="obfuscation env")

    return ObfuscationEnvContract(
        path=env_path,
        enabled=_parse_bool(
            _require_env_field(payload, env_path, "TRACEGATE_OBFUSCATION_ENABLED", label="obfuscation env"),
            path=env_path,
            field_name="TRACEGATE_OBFUSCATION_ENABLED",
            label="obfuscation env",
        ),
        backend=_require_env_field(payload, env_path, "TRACEGATE_OBFUSCATION_BACKEND", label="obfuscation env").lower(),
        private_runtime_dir=_require_env_field(payload, env_path, "TRACEGATE_PRIVATE_RUNTIME_DIR", label="obfuscation env"),
        zapret_root=_require_env_field(payload, env_path, "TRACEGATE_ZAPRET_ROOT", label="obfuscation env"),
        zapret_runner=_require_env_field(payload, env_path, "TRACEGATE_ZAPRET_RUNNER", label="obfuscation env"),
        zapret_policy_dir=_require_env_field(payload, env_path, "TRACEGATE_ZAPRET_POLICY_DIR", label="obfuscation env"),
        zapret_state_dir=_require_env_field(payload, env_path, "TRACEGATE_ZAPRET_STATE_DIR", label="obfuscation env"),
        zapret_profile_dir=_require_env_field(payload, env_path, "TRACEGATE_ZAPRET_PROFILE_DIR", label="obfuscation env"),
        zapret_profile_entry=_require_env_field(payload, env_path, "TRACEGATE_ZAPRET_PROFILE_ENTRY", label="obfuscation env"),
        zapret_profile_transit=_require_env_field(payload, env_path, "TRACEGATE_ZAPRET_PROFILE_TRANSIT", label="obfuscation env"),
        zapret_profile_interconnect=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_ZAPRET_PROFILE_INTERCONNECT",
            label="obfuscation env",
        ),
        zapret_profile_mtproto=_require_env_field(payload, env_path, "TRACEGATE_ZAPRET_PROFILE_MTPROTO", label="obfuscation env"),
        finalmask_mode=_require_env_field(payload, env_path, "TRACEGATE_FINALMASK_MODE", label="obfuscation env").lower(),
        entry_runtime_contract=_require_env_field(payload, env_path, "TRACEGATE_ENTRY_RUNTIME_CONTRACT", label="obfuscation env"),
        transit_runtime_contract=_require_env_field(payload, env_path, "TRACEGATE_TRANSIT_RUNTIME_CONTRACT", label="obfuscation env"),
        entry_interface=_require_env_field(payload, env_path, "TRACEGATE_ENTRY_INTERFACE", label="obfuscation env"),
        transit_interface=_require_env_field(payload, env_path, "TRACEGATE_TRANSIT_INTERFACE", label="obfuscation env"),
    )


def load_fronting_runtime_state(path: str | Path) -> FrontingRuntimeState:
    state_path = Path(path)
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"fronting runtime-state not found: {state_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePreflightError(f"fronting runtime-state is not valid JSON: {state_path}") from exc
    if not isinstance(payload, dict):
        raise RuntimePreflightError(f"fronting runtime-state must be a JSON object: {state_path}")

    return FrontingRuntimeState(
        path=state_path,
        action=str(payload.get("action") or "").strip().lower(),
        role=str(payload.get("role") or "").strip().upper(),
        backend=str(payload.get("backend") or "").strip().lower(),
        runtime_state_json=str(payload.get("runtimeStateJson") or "").strip(),
        listen_addr=str(payload.get("listenAddr") or "").strip(),
        protocol=str(payload.get("protocol") or "").strip().lower(),
        reality_upstream=str(payload.get("realityUpstream") or "").strip(),
        ws_tls_upstream=str(payload.get("wsTlsUpstream") or "").strip(),
        mtproto_upstream=str(payload.get("mtprotoUpstream") or "").strip(),
        mtproto_profile_file=str(payload.get("mtprotoProfileFile") or "").strip(),
        touch_udp_443=bool(payload.get("touchUdp443", False)),
        mtproto_domain=str(payload.get("mtprotoDomain") or "").strip(),
        mtproto_fronting_mode=str(payload.get("mtprotoFrontingMode") or "").strip().lower(),
        tcp_443_owner=str(payload.get("tcp443Owner") or "").strip(),
        udp_443_owner=str(payload.get("publicUdpOwner") or payload.get("udp443Owner") or "").strip(),
        cfg_file=str(payload.get("cfgFile") or "").strip(),
        pid_file=str(payload.get("pidFile") or "").strip(),
        ws_sni=str(payload.get("wsSni") or "").strip(),
    )


def load_mtproto_gateway_state(path: str | Path) -> MTProtoGatewayState:
    state_path = Path(path)
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"mtproto runtime-state not found: {state_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePreflightError(f"mtproto runtime-state is not valid JSON: {state_path}") from exc
    if not isinstance(payload, dict):
        raise RuntimePreflightError(f"mtproto runtime-state must be a JSON object: {state_path}")

    try:
        public_port = int(payload.get("publicPort") or 0)
        upstream_port = int(payload.get("upstreamPort") or 0)
    except (TypeError, ValueError) as exc:
        raise RuntimePreflightError(f"mtproto runtime-state has invalid numeric fields: {state_path}") from exc

    return MTProtoGatewayState(
        path=state_path,
        action=str(payload.get("action") or "").strip().lower(),
        role=str(payload.get("role") or "").strip().upper(),
        backend=str(payload.get("backend") or "").strip().lower(),
        domain=str(payload.get("domain") or "").strip(),
        public_port=public_port,
        upstream_host=str(payload.get("upstreamHost") or "").strip(),
        upstream_port=upstream_port,
        profile_file=str(payload.get("profileFile") or "").strip(),
        runtime_state_json=str(payload.get("runtimeStateJson") or "").strip(),
        public_profile_file=str(payload.get("publicProfileFile") or "").strip(),
        issued_state_file=str(payload.get("issuedStateFile") or "").strip(),
    )


def load_mtproto_public_profile(path: str | Path) -> MTProtoPublicProfile:
    profile_path = Path(path)
    try:
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"mtproto public profile not found: {profile_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePreflightError(f"mtproto public profile is not valid JSON: {profile_path}") from exc
    if not isinstance(payload, dict):
        raise RuntimePreflightError(f"mtproto public profile must be a JSON object: {profile_path}")

    try:
        port = int(payload.get("port") or 0)
    except (TypeError, ValueError) as exc:
        raise RuntimePreflightError(f"mtproto public profile has invalid port: {profile_path}") from exc

    protocol = str(payload.get("protocol") or "").strip().lower()
    server = str(payload.get("server") or "").strip()
    profile_name = str(payload.get("profile") or MTPROTO_FAKE_TLS_PROFILE_NAME).strip() or MTPROTO_FAKE_TLS_PROFILE_NAME
    transport = str(payload.get("transport") or "").strip().lower()
    domain = str(payload.get("domain") or "").strip()
    client_secret_hex = str(payload.get("clientSecretHex") or "").strip().lower()
    tg_uri = str(payload.get("tgUri") or "").strip()
    https_url = str(payload.get("httpsUrl") or "").strip()

    if protocol != "mtproto":
        raise RuntimePreflightError(f"unexpected protocol in mtproto public profile: {profile_path}")
    if not server or port <= 0 or not transport or not client_secret_hex or not tg_uri or not https_url:
        raise RuntimePreflightError(f"incomplete mtproto public profile payload: {profile_path}")

    return MTProtoPublicProfile(
        path=profile_path,
        protocol=protocol,
        profile_name=profile_name,
        server=server,
        port=port,
        transport=transport,
        domain=domain or server,
        client_secret_hex=client_secret_hex,
        tg_uri=tg_uri,
        https_url=https_url,
    )


def load_private_profile_state(path: str | Path) -> PrivateProfileState:
    state_path = Path(path)
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"private profile desired-state not found: {state_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePreflightError(f"private profile desired-state is not valid JSON: {state_path}") from exc
    if not isinstance(payload, dict):
        raise RuntimePreflightError(f"private profile desired-state must be a JSON object: {state_path}")

    counts = payload.get("counts")
    counts = counts if isinstance(counts, dict) else {}

    return PrivateProfileState(
        path=state_path,
        schema=str(payload.get("schema") or "").strip(),
        version=_json_int(payload.get("version"), path=state_path, field_name="version", label="private profile desired-state"),
        role=str(payload.get("role") or "").strip().upper(),
        runtime_profile=str(payload.get("runtimeProfile") or "").strip().lower(),
        runtime_contract_path=str(payload.get("runtimeContractPath") or "").strip(),
        transport_profiles=payload.get("transportProfiles") if isinstance(payload.get("transportProfiles"), dict) else {},
        secret_material=bool(payload.get("secretMaterial", False)),
        total_count=_json_int(counts.get("total"), path=state_path, field_name="counts.total", label="private profile desired-state"),
        shadowsocks2022_shadowtls_count=_json_int(
            counts.get("shadowsocks2022ShadowTLS"),
            path=state_path,
            field_name="counts.shadowsocks2022ShadowTLS",
            label="private profile desired-state",
        ),
        wireguard_wstunnel_count=_json_int(
            counts.get("wireguardWSTunnel"),
            path=state_path,
            field_name="counts.wireguardWSTunnel",
            label="private profile desired-state",
        ),
        shadowsocks2022_shadowtls=tuple(_dict_list(payload.get("shadowsocks2022ShadowTLS"))),
        wireguard_wstunnel=tuple(_dict_list(payload.get("wireguardWSTunnel"))),
    )


def load_private_profile_env(path: str | Path) -> PrivateProfileEnv:
    env_path = Path(path)
    payload = _load_env_file(env_path, label="private profile desired-state env")

    return PrivateProfileEnv(
        path=env_path,
        role=_require_env_field(payload, env_path, "TRACEGATE_PROFILE_ROLE", label="private profile desired-state env").upper(),
        runtime_profile=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_PROFILE_RUNTIME_PROFILE",
            label="private profile desired-state env",
        ).lower(),
        state_json=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_PROFILE_STATE_JSON",
            label="private profile desired-state env",
        ),
        secret_material=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_PROFILE_SECRET_MATERIAL",
                label="private profile desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_PROFILE_SECRET_MATERIAL",
            label="private profile desired-state env",
        ),
        total_count=_parse_int(
            _require_env_field(payload, env_path, "TRACEGATE_PROFILE_COUNT", label="private profile desired-state env"),
            path=env_path,
            field_name="TRACEGATE_PROFILE_COUNT",
            label="private profile desired-state env",
        ),
        shadowsocks2022_shadowtls_count=_parse_int(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_SHADOWSOCKS2022_SHADOWTLS_COUNT",
                label="private profile desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_SHADOWSOCKS2022_SHADOWTLS_COUNT",
            label="private profile desired-state env",
        ),
        wireguard_wstunnel_count=_parse_int(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_WIREGUARD_WSTUNNEL_COUNT",
                label="private profile desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_WIREGUARD_WSTUNNEL_COUNT",
            label="private profile desired-state env",
        ),
    )


def load_link_crypto_state(path: str | Path) -> LinkCryptoState:
    state_path = Path(path)
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"link-crypto desired-state not found: {state_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePreflightError(f"link-crypto desired-state is not valid JSON: {state_path}") from exc
    if not isinstance(payload, dict):
        raise RuntimePreflightError(f"link-crypto desired-state must be a JSON object: {state_path}")

    counts = payload.get("counts")
    counts = counts if isinstance(counts, dict) else {}
    udp_counts = payload.get("udpCounts")
    udp_counts = udp_counts if isinstance(udp_counts, dict) else {}

    return LinkCryptoState(
        path=state_path,
        schema=str(payload.get("schema") or "").strip(),
        version=_json_int(payload.get("version"), path=state_path, field_name="version", label="link-crypto desired-state"),
        role=str(payload.get("role") or "").strip().upper(),
        runtime_profile=str(payload.get("runtimeProfile") or "").strip().lower(),
        runtime_contract_path=str(payload.get("runtimeContractPath") or "").strip(),
        transport_profiles=payload.get("transportProfiles") if isinstance(payload.get("transportProfiles"), dict) else {},
        secret_material=bool(payload.get("secretMaterial", False)),
        total_count=_json_int(counts.get("total"), path=state_path, field_name="counts.total", label="link-crypto desired-state"),
        entry_transit_count=_json_int(
            counts.get("entryTransit"),
            path=state_path,
            field_name="counts.entryTransit",
            label="link-crypto desired-state",
        ),
        router_entry_count=_json_int(
            counts.get("routerEntry"),
            path=state_path,
            field_name="counts.routerEntry",
            label="link-crypto desired-state",
        ),
        router_transit_count=_json_int(
            counts.get("routerTransit"),
            path=state_path,
            field_name="counts.routerTransit",
            label="link-crypto desired-state",
        ),
        udp_total_count=_json_int(
            udp_counts.get("total", 0),
            path=state_path,
            field_name="udpCounts.total",
            label="link-crypto desired-state",
        ),
        entry_transit_udp_count=_json_int(
            udp_counts.get("entryTransitUdp", 0),
            path=state_path,
            field_name="udpCounts.entryTransitUdp",
            label="link-crypto desired-state",
        ),
        router_entry_udp_count=_json_int(
            udp_counts.get("routerEntryUdp", 0),
            path=state_path,
            field_name="udpCounts.routerEntryUdp",
            label="link-crypto desired-state",
        ),
        router_transit_udp_count=_json_int(
            udp_counts.get("routerTransitUdp", 0),
            path=state_path,
            field_name="udpCounts.routerTransitUdp",
            label="link-crypto desired-state",
        ),
        links=tuple(_dict_list(payload.get("links"))),
        udp_links=tuple(_dict_list(payload.get("udpLinks"))),
    )


def load_link_crypto_env(path: str | Path) -> LinkCryptoEnv:
    env_path = Path(path)
    payload = _load_env_file(env_path, label="link-crypto desired-state env")

    return LinkCryptoEnv(
        path=env_path,
        role=_require_env_field(payload, env_path, "TRACEGATE_LINK_CRYPTO_ROLE", label="link-crypto desired-state env").upper(),
        runtime_profile=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_LINK_CRYPTO_RUNTIME_PROFILE",
            label="link-crypto desired-state env",
        ).lower(),
        state_json=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_LINK_CRYPTO_STATE_JSON",
            label="link-crypto desired-state env",
        ),
        secret_material=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_SECRET_MATERIAL",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_SECRET_MATERIAL",
            label="link-crypto desired-state env",
        ),
        total_count=_parse_int(
            _require_env_field(payload, env_path, "TRACEGATE_LINK_CRYPTO_COUNT", label="link-crypto desired-state env"),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_COUNT",
            label="link-crypto desired-state env",
        ),
        classes=_colon_tokens(str(payload.get("TRACEGATE_LINK_CRYPTO_CLASSES") or "")),
        carrier=_require_env_field(payload, env_path, "TRACEGATE_LINK_CRYPTO_CARRIER", label="link-crypto desired-state env").lower(),
        outer_carrier_enabled=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_ENABLED",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_ENABLED",
            label="link-crypto desired-state env",
        ),
        outer_carrier_mode=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_MODE",
            label="link-crypto desired-state env",
        ).lower(),
        outer_wss_server_name=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_SERVER_NAME",
            label="link-crypto desired-state env",
        ),
        outer_wss_public_port=_parse_int(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_OUTER_WSS_PUBLIC_PORT",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_OUTER_WSS_PUBLIC_PORT",
            label="link-crypto desired-state env",
        ),
        outer_wss_path=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_PATH",
            label="link-crypto desired-state env",
        ),
        outer_wss_verify_tls=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_OUTER_WSS_VERIFY_TLS",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_OUTER_WSS_VERIFY_TLS",
            label="link-crypto desired-state env",
        ),
        outer_wss_spki_pinning_required=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_OUTER_WSS_SPKI_PINNING_REQUIRED",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_OUTER_WSS_SPKI_PINNING_REQUIRED",
            label="link-crypto desired-state env",
        ),
        outer_wss_admission_required=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_OUTER_WSS_ADMISSION_REQUIRED",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_OUTER_WSS_ADMISSION_REQUIRED",
            label="link-crypto desired-state env",
        ),
        generation=_parse_int(
            _require_env_field(payload, env_path, "TRACEGATE_LINK_CRYPTO_GENERATION", label="link-crypto desired-state env"),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_GENERATION",
            label="link-crypto desired-state env",
        ),
        zapret2_enabled=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_ZAPRET2_ENABLED",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_ZAPRET2_ENABLED",
            label="link-crypto desired-state env",
        ),
        zapret2_required=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_ZAPRET2_REQUIRED",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_ZAPRET2_REQUIRED",
            label="link-crypto desired-state env",
        ),
        zapret2_host_wide_interception=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_ZAPRET2_HOST_WIDE_INTERCEPTION",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_ZAPRET2_HOST_WIDE_INTERCEPTION",
            label="link-crypto desired-state env",
        ),
        zapret2_nfqueue=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_ZAPRET2_NFQUEUE",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_ZAPRET2_NFQUEUE",
            label="link-crypto desired-state env",
        ),
        tcp_dpi_resistance_required=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_TCP_DPI_RESISTANCE_REQUIRED",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_TCP_DPI_RESISTANCE_REQUIRED",
            label="link-crypto desired-state env",
        ),
        tcp_traffic_shaping_required=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_TCP_TRAFFIC_SHAPING_REQUIRED",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_TCP_TRAFFIC_SHAPING_REQUIRED",
            label="link-crypto desired-state env",
        ),
        promotion_preflight_required=_parse_bool(
            _require_env_field(
                payload,
                env_path,
                "TRACEGATE_LINK_CRYPTO_PROMOTION_PREFLIGHT_REQUIRED",
                label="link-crypto desired-state env",
            ),
            path=env_path,
            field_name="TRACEGATE_LINK_CRYPTO_PROMOTION_PREFLIGHT_REQUIRED",
            label="link-crypto desired-state env",
        ),
    )


def load_router_handoff_state(path: str | Path) -> RouterHandoffState:
    state_path = Path(path)
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"router handoff desired-state not found: {state_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePreflightError(f"router handoff desired-state is not valid JSON: {state_path}") from exc
    if not isinstance(payload, dict):
        raise RuntimePreflightError(f"router handoff desired-state must be a JSON object: {state_path}")

    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    classes = payload.get("classes") if isinstance(payload.get("classes"), dict) else {}
    routes = payload.get("routes") if isinstance(payload.get("routes"), dict) else {}
    return RouterHandoffState(
        path=state_path,
        schema=str(payload.get("schema") or "").strip(),
        version=_json_int(payload.get("version"), path=state_path, field_name="version", label="router handoff desired-state"),
        role=str(payload.get("role") or "").strip().upper(),
        runtime_profile=str(payload.get("runtimeProfile") or "").strip().lower(),
        runtime_contract_path=str(payload.get("runtimeContractPath") or "").strip(),
        secret_material=bool(payload.get("secretMaterial", False)),
        enabled=bool(payload.get("enabled", False)),
        placement=str(payload.get("placement") or "").strip(),
        contract=payload.get("contract") if isinstance(payload.get("contract"), dict) else {},
        total_count=_json_int(counts.get("total"), path=state_path, field_name="counts.total", label="router handoff desired-state"),
        tcp_count=_json_int(counts.get("tcp"), path=state_path, field_name="counts.tcp", label="router handoff desired-state"),
        udp_count=_json_int(counts.get("udp"), path=state_path, field_name="counts.udp", label="router handoff desired-state"),
        tcp_classes=tuple(_string_list(classes.get("tcp"))),
        udp_classes=tuple(_string_list(classes.get("udp"))),
        tcp_routes=tuple(_dict_list(routes.get("tcp"))),
        udp_routes=tuple(_dict_list(routes.get("udp"))),
    )


def load_router_handoff_env(path: str | Path) -> RouterHandoffEnv:
    env_path = Path(path)
    payload = _load_env_file(env_path, label="router handoff desired-state env")

    def bool_field(key: str) -> bool:
        return _parse_bool(
            _require_env_field(payload, env_path, key, label="router handoff desired-state env"),
            path=env_path,
            field_name=key,
            label="router handoff desired-state env",
        )

    def int_field(key: str) -> int:
        return _parse_int(
            _require_env_field(payload, env_path, key, label="router handoff desired-state env"),
            path=env_path,
            field_name=key,
            label="router handoff desired-state env",
        )

    return RouterHandoffEnv(
        path=env_path,
        role=_require_env_field(payload, env_path, "TRACEGATE_ROUTER_HANDOFF_ROLE", label="router handoff desired-state env").upper(),
        runtime_profile=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_ROUTER_HANDOFF_RUNTIME_PROFILE",
            label="router handoff desired-state env",
        ).lower(),
        state_json=_require_env_field(payload, env_path, "TRACEGATE_ROUTER_HANDOFF_STATE_JSON", label="router handoff desired-state env"),
        secret_material=bool_field("TRACEGATE_ROUTER_HANDOFF_SECRET_MATERIAL"),
        enabled=bool_field("TRACEGATE_ROUTER_HANDOFF_ENABLED"),
        total_count=int_field("TRACEGATE_ROUTER_HANDOFF_COUNT"),
        tcp_count=int_field("TRACEGATE_ROUTER_HANDOFF_TCP_COUNT"),
        udp_count=int_field("TRACEGATE_ROUTER_HANDOFF_UDP_COUNT"),
        tcp_classes=_colon_tokens(str(payload.get("TRACEGATE_ROUTER_HANDOFF_TCP_CLASSES") or "")),
        udp_classes=_colon_tokens(str(payload.get("TRACEGATE_ROUTER_HANDOFF_UDP_CLASSES") or "")),
        paired_obfs_enabled=bool_field("TRACEGATE_ROUTER_HANDOFF_PAIRED_OBFS_ENABLED"),
        requires_private_profile=bool_field("TRACEGATE_ROUTER_HANDOFF_REQUIRES_PRIVATE_PROFILE"),
        router_is_entry_replacement=bool_field("TRACEGATE_ROUTER_HANDOFF_ROUTER_IS_ENTRY_REPLACEMENT"),
        no_host_wide_interception=bool_field("TRACEGATE_ROUTER_HANDOFF_NO_HOST_WIDE_INTERCEPTION"),
        no_nfqueue=bool_field("TRACEGATE_ROUTER_HANDOFF_NO_NFQUEUE"),
    )


def load_router_client_bundle(path: str | Path) -> RouterClientBundle:
    bundle_path = Path(path)
    try:
        payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"router client bundle not found: {bundle_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePreflightError(f"router client bundle is not valid JSON: {bundle_path}") from exc
    if not isinstance(payload, dict):
        raise RuntimePreflightError(f"router client bundle must be a JSON object: {bundle_path}")

    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    classes = payload.get("classes") if isinstance(payload.get("classes"), dict) else {}
    routes = payload.get("routes") if isinstance(payload.get("routes"), dict) else {}
    return RouterClientBundle(
        path=bundle_path,
        schema=str(payload.get("schema") or "").strip(),
        version=_json_int(payload.get("version"), path=bundle_path, field_name="version", label="router client bundle"),
        role=str(payload.get("role") or "").strip().upper(),
        runtime_profile=str(payload.get("runtimeProfile") or "").strip().lower(),
        handoff_state_json=str(payload.get("handoffStateJson") or "").strip(),
        secret_material=bool(payload.get("secretMaterial", False)),
        enabled=bool(payload.get("enabled", False)),
        placement=str(payload.get("placement") or "").strip(),
        requirements=payload.get("requirements") if isinstance(payload.get("requirements"), dict) else {},
        total_count=_json_int(counts.get("total"), path=bundle_path, field_name="counts.total", label="router client bundle"),
        tcp_count=_json_int(counts.get("tcp"), path=bundle_path, field_name="counts.tcp", label="router client bundle"),
        udp_count=_json_int(counts.get("udp"), path=bundle_path, field_name="counts.udp", label="router client bundle"),
        tcp_classes=tuple(_string_list(classes.get("tcp"))),
        udp_classes=tuple(_string_list(classes.get("udp"))),
        components=tuple(_dict_list(payload.get("components"))),
        tcp_routes=tuple(_dict_list(routes.get("tcp"))),
        udp_routes=tuple(_dict_list(routes.get("udp"))),
    )


def load_router_client_bundle_env(path: str | Path) -> RouterClientBundleEnv:
    env_path = Path(path)
    payload = _load_env_file(env_path, label="router client bundle env")

    def bool_field(key: str) -> bool:
        return _parse_bool(
            _require_env_field(payload, env_path, key, label="router client bundle env"),
            path=env_path,
            field_name=key,
            label="router client bundle env",
        )

    def int_field(key: str) -> int:
        return _parse_int(
            _require_env_field(payload, env_path, key, label="router client bundle env"),
            path=env_path,
            field_name=key,
            label="router client bundle env",
        )

    return RouterClientBundleEnv(
        path=env_path,
        role=_require_env_field(payload, env_path, "TRACEGATE_ROUTER_CLIENT_BUNDLE_ROLE", label="router client bundle env").upper(),
        runtime_profile=_require_env_field(
            payload,
            env_path,
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_RUNTIME_PROFILE",
            label="router client bundle env",
        ).lower(),
        bundle_json=_require_env_field(payload, env_path, "TRACEGATE_ROUTER_CLIENT_BUNDLE_JSON", label="router client bundle env"),
        handoff_json=_require_env_field(payload, env_path, "TRACEGATE_ROUTER_CLIENT_BUNDLE_HANDOFF_JSON", label="router client bundle env"),
        secret_material=bool_field("TRACEGATE_ROUTER_CLIENT_BUNDLE_SECRET_MATERIAL"),
        enabled=bool_field("TRACEGATE_ROUTER_CLIENT_BUNDLE_ENABLED"),
        components=_colon_tokens(str(payload.get("TRACEGATE_ROUTER_CLIENT_BUNDLE_COMPONENTS") or "")),
        tcp_count=int_field("TRACEGATE_ROUTER_CLIENT_BUNDLE_TCP_COUNT"),
        udp_count=int_field("TRACEGATE_ROUTER_CLIENT_BUNDLE_UDP_COUNT"),
        requires_both_sides=bool_field("TRACEGATE_ROUTER_CLIENT_BUNDLE_REQUIRES_BOTH_SIDES"),
        fail_closed=bool_field("TRACEGATE_ROUTER_CLIENT_BUNDLE_FAIL_CLOSED"),
        no_host_wide_interception=bool_field("TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_HOST_WIDE_INTERCEPTION"),
        no_nfqueue=bool_field("TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_NFQUEUE"),
    )


def load_systemd_unit_contract(path: str | Path) -> SystemdUnitContract:
    unit_path = Path(path)
    try:
        raw_lines = unit_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"systemd unit not found: {unit_path}") from exc

    payload: dict[str, dict[str, list[str]]] = {}
    current_section = ""
    for raw_line in raw_lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            payload.setdefault(current_section, {})
            continue
        if "=" not in line:
            raise RuntimePreflightError(f"systemd unit contains invalid line: {unit_path}")
        if not current_section:
            raise RuntimePreflightError(f"systemd unit contains key outside a section: {unit_path}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise RuntimePreflightError(f"systemd unit contains empty key: {unit_path}")
        payload.setdefault(current_section, {}).setdefault(key, []).append(value.strip())

    unit = payload.get("Unit", {})
    service = payload.get("Service", {})
    install = payload.get("Install", {})

    return SystemdUnitContract(
        path=unit_path,
        description=str((unit.get("Description") or [""])[0]).strip(),
        after=tuple(sorted({value.strip() for value in unit.get("After", []) if value.strip()})),
        wants=tuple(sorted({value.strip() for value in unit.get("Wants", []) if value.strip()})),
        condition_path_exists=tuple(sorted({value.strip() for value in unit.get("ConditionPathExists", []) if value.strip()})),
        environment_files=tuple(value.strip() for value in service.get("EnvironmentFile", []) if value.strip()),
        environments=tuple(value.strip() for value in service.get("Environment", []) if value.strip()),
        service_type=str((service.get("Type") or [""])[0]).strip().lower(),
        remain_after_exit=str((service.get("RemainAfterExit") or [""])[0]).strip().lower(),
        exec_start=str((service.get("ExecStart") or [""])[0]).strip(),
        exec_reload=str((service.get("ExecReload") or [""])[0]).strip(),
        exec_stop=str((service.get("ExecStop") or [""])[0]).strip(),
        wanted_by=tuple(sorted({value.strip() for value in install.get("WantedBy", []) if value.strip()})),
    )


def _load_env_file(path: str | Path, *, label: str = "env file") -> dict[str, str]:
    env_path = Path(path)
    try:
        raw_lines = env_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise RuntimePreflightError(f"{label} not found: {env_path}") from exc

    payload: dict[str, str] = {}
    for raw_line in raw_lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise RuntimePreflightError(f"{label} contains invalid line: {env_path}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise RuntimePreflightError(f"{label} contains empty key: {env_path}")
        payload[key] = _normalize_env_value(value)
    return payload


def _require_env_field(payload: dict[str, str], path: Path, name: str, *, label: str) -> str:
    value = str(payload.get(name) or "").strip()
    if not value:
        raise RuntimePreflightError(f"{label} missing required field {name}: {path}")
    return value


def _require_profile_field(payload: dict[str, str], path: Path, name: str) -> str:
    return _require_env_field(payload, path, name, label="zapret profile")


def _csv_tokens(value: str) -> tuple[str, ...]:
    return tuple(sorted({token.strip().lower() for token in str(value or "").split(",") if token.strip()}))


def _colon_tokens(value: str) -> tuple[str, ...]:
    return tuple(sorted({token.strip() for token in str(value or "").split(":") if token.strip()}, key=str))


def _normalize_env_value(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw[0] not in {"'", '"'}:
        return raw
    try:
        parsed = shlex.split(f"VALUE={raw}", posix=True)
    except ValueError:
        return raw
    if len(parsed) == 1 and parsed[0].startswith("VALUE="):
        return parsed[0][6:]
    return raw


def _normalize_envfile_entry(value: str) -> str:
    raw = str(value or "").strip()
    return raw[1:] if raw.startswith("-") else raw


def _csv_ports(value: str, *, path: Path, field_name: str) -> tuple[int, ...]:
    ports: set[int] = set()
    for token in _csv_tokens(value):
        try:
            port = int(token)
        except ValueError as exc:
            raise RuntimePreflightError(f"invalid {field_name} value in zapret profile {path}: {token}") from exc
        if port < 1 or port > 65535:
            raise RuntimePreflightError(f"invalid {field_name} port in zapret profile {path}: {port}")
        ports.add(port)
    return tuple(sorted(ports))


def _parse_bool(value: str, *, path: Path, field_name: str, label: str = "env file") -> bool:
    raw = str(value or "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise RuntimePreflightError(f"invalid boolean {field_name} in {label} {path}: {value}")


def _parse_int(value: str, *, path: Path, field_name: str, label: str = "env file") -> int:
    raw = str(value or "").strip()
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise RuntimePreflightError(f"invalid integer {field_name} in {label} {path}: {value}") from exc
    return parsed


def load_zapret_profile(path: str | Path) -> ZapretProfile:
    profile_path = Path(path)
    payload = _load_env_file(profile_path, label="zapret profile")

    return ZapretProfile(
        path=profile_path,
        profile_name=_require_profile_field(payload, profile_path, "TRACEGATE_ZAPRET_PROFILE_NAME"),
        scope=_require_profile_field(payload, profile_path, "TRACEGATE_ZAPRET_SCOPE").lower(),
        cpu_budget=_require_profile_field(payload, profile_path, "TRACEGATE_ZAPRET_CPU_BUDGET").lower(),
        apply_mode=_require_profile_field(payload, profile_path, "TRACEGATE_ZAPRET_APPLY_MODE").lower(),
        target_tcp_ports=_csv_ports(
            _require_profile_field(payload, profile_path, "TRACEGATE_ZAPRET_TARGET_TCP_PORTS"),
            path=profile_path,
            field_name="TRACEGATE_ZAPRET_TARGET_TCP_PORTS",
        ),
        target_udp_ports=_csv_ports(
            str(payload.get("TRACEGATE_ZAPRET_TARGET_UDP_PORTS") or ""),
            path=profile_path,
            field_name="TRACEGATE_ZAPRET_TARGET_UDP_PORTS",
        ),
        target_protocols=_csv_tokens(_require_profile_field(payload, profile_path, "TRACEGATE_ZAPRET_TARGET_PROTOCOLS")),
        target_surfaces=_csv_tokens(_require_profile_field(payload, profile_path, "TRACEGATE_ZAPRET_TARGET_SURFACES")),
        touch_unrelated_system_traffic=_parse_bool(
            _require_profile_field(payload, profile_path, "TRACEGATE_ZAPRET_TOUCH_UNRELATED_SYSTEM_TRAFFIC"),
            path=profile_path,
            field_name="TRACEGATE_ZAPRET_TOUCH_UNRELATED_SYSTEM_TRAFFIC",
            label="zapret profile",
        ),
        max_workers=_parse_int(
            _require_profile_field(payload, profile_path, "TRACEGATE_ZAPRET_MAX_WORKERS"),
            path=profile_path,
            field_name="TRACEGATE_ZAPRET_MAX_WORKERS",
            label="zapret profile",
        ),
        notes=str(payload.get("TRACEGATE_ZAPRET_NOTES") or "").strip(),
    )


def load_fronting_env_contract(path: str | Path) -> FrontingEnvContract:
    contract_path = Path(path)
    payload = _load_env_file(contract_path, label="fronting env")

    return FrontingEnvContract(
        path=contract_path,
        enabled=_parse_bool(
            _require_env_field(payload, contract_path, "TRACEGATE_FRONTING_ENABLED", label="fronting env"),
            path=contract_path,
            field_name="TRACEGATE_FRONTING_ENABLED",
            label="fronting env",
        ),
        role=_require_env_field(payload, contract_path, "TRACEGATE_FRONTING_ROLE", label="fronting env").lower(),
        backend=_require_env_field(payload, contract_path, "TRACEGATE_FRONTING_BACKEND", label="fronting env").lower(),
        runtime_state_json=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_FRONTING_RUNTIME_STATE_JSON",
            label="fronting env",
        ),
        listen_addr=_require_env_field(payload, contract_path, "TRACEGATE_FRONTING_LISTEN_ADDR", label="fronting env"),
        protocol=_require_env_field(payload, contract_path, "TRACEGATE_FRONTING_PROTOCOL", label="fronting env").lower(),
        reality_upstream=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_FRONTING_REALITY_UPSTREAM",
            label="fronting env",
        ),
        ws_tls_upstream=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_FRONTING_WS_TLS_UPSTREAM",
            label="fronting env",
        ),
        mtproto_upstream=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_FRONTING_MTPROTO_UPSTREAM",
            label="fronting env",
        ),
        mtproto_profile_file=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_FRONTING_MTPROTO_PROFILE_FILE",
            label="fronting env",
        ),
        state_dir=_require_env_field(payload, contract_path, "TRACEGATE_FRONTING_STATE_DIR", label="fronting env"),
        runtime_dir=_require_env_field(payload, contract_path, "TRACEGATE_FRONTING_RUNTIME_DIR", label="fronting env"),
        runner=_require_env_field(payload, contract_path, "TRACEGATE_FRONTING_RUNNER", label="fronting env"),
        haproxy_bin=_require_env_field(payload, contract_path, "TRACEGATE_FRONTING_HAPROXY_BIN", label="fronting env"),
        ws_sni=_require_env_field(payload, contract_path, "TRACEGATE_FRONTING_WS_SNI", label="fronting env"),
        mtproto_domain_override=str(payload.get("TRACEGATE_FRONTING_MTPROTO_DOMAIN_OVERRIDE") or "").strip(),
        touch_udp_443=_parse_bool(
            _require_env_field(payload, contract_path, "TRACEGATE_FRONTING_TOUCH_UDP_443", label="fronting env"),
            path=contract_path,
            field_name="TRACEGATE_FRONTING_TOUCH_UDP_443",
            label="fronting env",
        ),
        notes=str(payload.get("TRACEGATE_FRONTING_NOTES") or "").strip(),
    )


def load_mtproto_env_contract(path: str | Path) -> MTProtoEnvContract:
    contract_path = Path(path)
    payload = _load_env_file(contract_path, label="mtproto env")

    return MTProtoEnvContract(
        path=contract_path,
        enabled=_parse_bool(
            _require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_ENABLED", label="mtproto env"),
            path=contract_path,
            field_name="TRACEGATE_MTPROTO_ENABLED",
            label="mtproto env",
        ),
        role=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_ROLE", label="mtproto env").lower(),
        backend=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_BACKEND", label="mtproto env").lower(),
        runtime_state_json=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_MTPROTO_RUNTIME_STATE_JSON",
            label="mtproto env",
        ),
        profile_file=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_PROFILE_FILE", label="mtproto env"),
        domain=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_DOMAIN", label="mtproto env"),
        public_port=_parse_int(
            _require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_PUBLIC_PORT", label="mtproto env"),
            path=contract_path,
            field_name="TRACEGATE_MTPROTO_PUBLIC_PORT",
            label="mtproto env",
        ),
        upstream_host=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_UPSTREAM_HOST", label="mtproto env"),
        upstream_port=_parse_int(
            _require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_UPSTREAM_PORT", label="mtproto env"),
            path=contract_path,
            field_name="TRACEGATE_MTPROTO_UPSTREAM_PORT",
            label="mtproto env",
        ),
        tls_mode=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_TLS_MODE", label="mtproto env").lower(),
        secret_file=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_SECRET_FILE", label="mtproto env"),
        state_dir=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_STATE_DIR", label="mtproto env"),
        issued_state_file=str(payload.get("TRACEGATE_MTPROTO_ISSUED_STATE_FILE") or "").strip(),
        binary=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_BINARY", label="mtproto env"),
        runtime_dir=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_RUNTIME_DIR", label="mtproto env"),
        stats_port=_parse_int(
            _require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_STATS_PORT", label="mtproto env"),
            path=contract_path,
            field_name="TRACEGATE_MTPROTO_STATS_PORT",
            label="mtproto env",
        ),
        run_as_user=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_RUN_AS_USER", label="mtproto env"),
        workers=_parse_int(
            _require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_WORKERS", label="mtproto env"),
            path=contract_path,
            field_name="TRACEGATE_MTPROTO_WORKERS",
            label="mtproto env",
        ),
        proxy_tag=str(payload.get("TRACEGATE_MTPROTO_PROXY_TAG") or "").strip(),
        fetch_secret_url=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_MTPROTO_FETCH_SECRET_URL",
            label="mtproto env",
        ),
        fetch_config_url=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_MTPROTO_FETCH_CONFIG_URL",
            label="mtproto env",
        ),
        bootstrap_max_age_seconds=_parse_int(
            _require_env_field(
                payload,
                contract_path,
                "TRACEGATE_MTPROTO_BOOTSTRAP_MAX_AGE_SECONDS",
                label="mtproto env",
            ),
            path=contract_path,
            field_name="TRACEGATE_MTPROTO_BOOTSTRAP_MAX_AGE_SECONDS",
            label="mtproto env",
        ),
        proxy_secret_file=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_MTPROTO_PROXY_SECRET_FILE",
            label="mtproto env",
        ),
        proxy_config_file=_require_env_field(
            payload,
            contract_path,
            "TRACEGATE_MTPROTO_PROXY_CONFIG_FILE",
            label="mtproto env",
        ),
        pid_file=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_PID_FILE", label="mtproto env"),
        log_file=_require_env_field(payload, contract_path, "TRACEGATE_MTPROTO_LOG_FILE", label="mtproto env"),
        notes=str(payload.get("TRACEGATE_MTPROTO_NOTES") or "").strip(),
    )


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for row in value:
        raw = str(row or "").strip()
        if raw:
            out.append(raw)
    return sorted(set(out), key=str)


def _dict_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(row) for row in value if isinstance(row, dict)]


def _json_int(value: object, *, path: Path, field_name: str, label: str) -> int:
    try:
        return int(value if value is not None else 0)
    except (TypeError, ValueError) as exc:
        raise RuntimePreflightError(f"invalid integer {field_name} in {label} {path}: {value}") from exc


def _role_name(contract: dict[str, Any]) -> str:
    return str(contract.get("role") or "").strip().upper()


def _runtime_profile(contract: dict[str, Any]) -> str:
    return str(contract.get("runtimeProfile") or "").strip().lower()


def _managed_components(contract: dict[str, Any]) -> list[str]:
    contract_block = contract.get("contract")
    if not isinstance(contract_block, dict):
        return []
    return _string_list(contract_block.get("managedComponents"))


def _xray_backhaul_allowed(contract: dict[str, Any]) -> bool:
    contract_block = contract.get("contract")
    if not isinstance(contract_block, dict):
        return True
    return bool(contract_block.get("xrayBackhaulAllowed", True))


def _decoy_roots(contract: dict[str, Any]) -> list[str]:
    decoy = contract.get("decoy")
    if not isinstance(decoy, dict):
        return []
    roots: list[str] = []
    for key in ("nginxRoots", "splitHysteriaMasqueradeDirs", "xrayHysteriaMasqueradeDirs"):
        roots.extend(_string_list(decoy.get(key)))
    return sorted(set(roots), key=str)


def _xray_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("xray")
    return value if isinstance(value, dict) else {}


def _hysteria_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("hysteria")
    return value if isinstance(value, dict) else {}


def _fronting_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("fronting")
    return value if isinstance(value, dict) else {}


def _rollout_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("rollout")
    return value if isinstance(value, dict) else {}


def _transport_profiles_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("transportProfiles")
    return value if isinstance(value, dict) else {}


def _network_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("network")
    return value if isinstance(value, dict) else {}


def _link_crypto_contract_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("linkCrypto")
    return value if isinstance(value, dict) else {}


def _link_crypto_contract_block_for_role(contract: dict[str, Any], *, role_upper: str) -> dict[str, Any]:
    link_crypto = _link_crypto_contract_block(contract)
    roles = _row_dict(link_crypto, "roles")
    role_block = _row_dict(roles, role_upper.strip().lower())
    return role_block or link_crypto


def _rollout_string(rollout: dict[str, Any], key: str) -> str:
    return str(rollout.get(key) or "").strip()


def _rollout_int(rollout: dict[str, Any], key: str, *, default: int = 0) -> int:
    try:
        return int(rollout.get(key) if rollout.get(key) is not None else default)
    except (TypeError, ValueError):
        return default


def _validate_tracegate21_rollout(contract: dict[str, Any], *, role_prefix: str) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    if _runtime_profile(contract) != "tracegate-2.1":
        return findings

    rollout = _rollout_block(contract)
    if not rollout:
        findings.append(_finding("error", f"{role_prefix}-tracegate21-rollout", f"{role_prefix} tracegate-2.1 rollout block is missing"))
        return findings

    if _rollout_string(rollout, "gatewayStrategy") != "RollingUpdate":
        findings.append(_finding("error", f"{role_prefix}-tracegate21-rollout-strategy", f"{role_prefix} gateway rollout strategy must be RollingUpdate"))
    if bool(rollout.get("allowRecreateStrategy", False)):
        findings.append(_finding("error", f"{role_prefix}-tracegate21-rollout-allow-recreate", f"{role_prefix} Recreate rollout override must stay disabled"))
    if _rollout_string(rollout, "maxUnavailable") != "0":
        findings.append(_finding("error", f"{role_prefix}-tracegate21-rollout-max-unavailable", f"{role_prefix} rolling maxUnavailable must stay 0"))
    if _rollout_string(rollout, "maxSurge") in {"", "0", "0%"}:
        findings.append(_finding("error", f"{role_prefix}-tracegate21-rollout-max-surge", f"{role_prefix} rolling maxSurge must be non-zero"))
    if _rollout_int(rollout, "progressDeadlineSeconds", default=0) < 300:
        findings.append(_finding("error", f"{role_prefix}-tracegate21-rollout-progress-deadline", f"{role_prefix} progressDeadlineSeconds must be at least 300"))
    if _rollout_string(rollout, "pdbMinAvailable") != "1":
        findings.append(_finding("error", f"{role_prefix}-tracegate21-rollout-pdb-min-available", f"{role_prefix} PDB minAvailable must stay 1"))
    if not bool(rollout.get("probesEnabled", False)):
        findings.append(_finding("error", f"{role_prefix}-tracegate21-rollout-probes", f"{role_prefix} gateway probes must stay enabled"))
    if not bool(rollout.get("privatePreflightEnabled", False)):
        findings.append(_finding("error", f"{role_prefix}-tracegate21-rollout-private-preflight", f"{role_prefix} private preflight must stay enabled"))
    if not bool(rollout.get("privatePreflightForbidPlaceholders", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-rollout-private-preflight-placeholders",
                f"{role_prefix} private preflight must forbid placeholders",
            )
        )
    return findings


def _validate_tracegate21_transport_profiles(contract: dict[str, Any], *, role_prefix: str) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    if _runtime_profile(contract) != "tracegate-2.1":
        return findings

    transport = _transport_profiles_block(contract)
    if not transport:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-transport-profiles",
                f"{role_prefix} tracegate-2.1 transportProfiles block is missing",
            )
        )
        return findings

    client_names = set(_string_list(transport.get("clientNames")))
    missing = [profile for profile in TRACEGATE21_CLIENT_PROFILES if profile not in client_names]
    if missing:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-client-profiles",
                f"{role_prefix} tracegate-2.1 clientProfiles missing: {', '.join(missing)}",
            )
        )
    if "MTProto-TCP443-Direct" in client_names:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-legacy-mtproto-profile",
                f"{role_prefix} tracegate-2.1 must use {MTPROTO_FAKE_TLS_PROFILE_NAME}, not MTProto-TCP443-Direct",
            )
        )
    lab_only_profiles = {
        "V8-Mieru-TCP-Direct",
        "V8-Mieru-RESTLS-Direct",
        "V9-TUICv5-QUIC-Direct",
        "V9-TUICv5-QUIC-Chain",
    }
    lab_profiles = sorted(client_names.intersection(lab_only_profiles))
    if lab_profiles:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-lab-client-profiles",
                f"{role_prefix} tracegate-2.1 production clientProfiles must not include lab-only profiles: {', '.join(lab_profiles)}",
            )
        )

    local_socks = transport.get("localSocks")
    local_socks_block = local_socks if isinstance(local_socks, dict) else {}
    local_socks_auth = str(local_socks_block.get("auth") or "").strip().lower()
    contract_local_socks_auth = str(contract.get("localSocksAuth") or "").strip().lower()
    if not contract_local_socks_auth:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-local-socks-auth-metadata",
                f"{role_prefix} tracegate-2.1 localSocksAuth metadata must declare required",
            )
        )
    elif contract_local_socks_auth != "required":
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-local-socks-auth-metadata",
                f"{role_prefix} tracegate-2.1 localSocksAuth metadata must stay required",
            )
        )
    if contract_local_socks_auth and contract_local_socks_auth != local_socks_auth:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-local-socks-auth-mismatch",
                f"{role_prefix} tracegate-2.1 localSocksAuth metadata diverges from transportProfiles.localSocks.auth",
            )
        )
    if local_socks_auth != "required":
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-local-socks-auth",
                f"{role_prefix} tracegate-2.1 local SOCKS5 auth must stay required",
            )
        )
    if bool(local_socks_block.get("allowAnonymousLocalhost", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-local-socks-anonymous",
                f"{role_prefix} tracegate-2.1 must not allow anonymous localhost SOCKS5",
            )
        )

    client_exposure = transport.get("clientExposure")
    exposure_block = client_exposure if isinstance(client_exposure, dict) else {}
    expected_exposure = {
        "defaultMode": "vpn-tun",
        "localProxyExports": "advanced-only",
        "lanSharing": "forbidden",
        "unauthenticatedLocalProxy": "forbidden",
    }
    for key, expected in expected_exposure.items():
        if str(exposure_block.get(key) or "").strip() != expected:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-tracegate21-client-exposure-{key}",
                    f"{role_prefix} tracegate-2.1 transportProfiles.clientExposure.{key} must stay {expected}",
                )
            )

    return findings


def _validate_tracegate21_network(contract: dict[str, Any], *, role_prefix: str) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    if _runtime_profile(contract) != "tracegate-2.1":
        return findings

    network = _network_block(contract)
    egress = network.get("egressIsolation") if isinstance(network, dict) else {}
    egress_block = egress if isinstance(egress, dict) else {}
    enforcement = egress_block.get("enforcement")
    enforcement_block = enforcement if isinstance(enforcement, dict) else {}

    if not bool(egress_block.get("required", False)):
        findings.append(_finding("error", f"{role_prefix}-tracegate21-egress-isolation-required", f"{role_prefix} egress isolation must stay required"))
    if str(egress_block.get("mode") or "").strip() != "dedicated-egress-ip":
        findings.append(
            _finding("error", f"{role_prefix}-tracegate21-egress-isolation-mode", f"{role_prefix} egress isolation mode must stay dedicated-egress-ip")
        )
    if not bool(egress_block.get("forbidIngressIpAsEgress", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-egress-isolation-forbid-ingress",
                f"{role_prefix} ingress public IP must be forbidden for user traffic egress",
            )
        )
    if not bool(egress_block.get("requireTransitEgressPublicIP", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-egress-isolation-transit-egress",
                f"{role_prefix} Transit must declare a dedicated egress public IP",
            )
        )
    if str(enforcement_block.get("snat") or "").strip() != "required":
        findings.append(_finding("error", f"{role_prefix}-tracegate21-egress-snat", f"{role_prefix} egress isolation SNAT must stay required"))
    if str(enforcement_block.get("ingressPublicIpOutbound") or "").strip() != "forbidden":
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-egress-ingress-ip-outbound",
                f"{role_prefix} outbound through ingress public IP must stay forbidden",
            )
        )

    ingress_ips = set(_string_list(egress_block.get("ingressPublicIPs")))
    egress_ips = set(_string_list(egress_block.get("egressPublicIPs")))
    if role_prefix == "transit" and not egress_ips:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-egress-public-ips",
                f"{role_prefix} Transit contract must list dedicated egress public IPs",
            )
        )
    overlap = sorted(ingress_ips.intersection(egress_ips))
    if overlap:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate21-egress-ip-overlap",
                f"{role_prefix} ingress and egress public IPs must be disjoint: {', '.join(overlap)}",
            )
        )

    return findings


def _finding(severity: str, code: str, message: str) -> RuntimePreflightFinding:
    return RuntimePreflightFinding(severity=severity, code=code, message=message)


def _parse_endpoint(value: str) -> tuple[str, int]:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("missing endpoint")
    host, sep, port_raw = raw.rpartition(":")
    if not sep or not host or not port_raw:
        raise ValueError(f"invalid host:port endpoint: {raw}")
    normalized_host = host.strip()
    if normalized_host.startswith("[") and normalized_host.endswith("]"):
        normalized_host = normalized_host[1:-1].strip()
    if not normalized_host:
        raise ValueError(f"invalid host in endpoint: {raw}")
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ValueError(f"invalid port in endpoint: {raw}") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"invalid port in endpoint: {raw}")
    return normalized_host, port


def _is_loopback_host(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validate_endpoint(
    *,
    raw_value: str,
    code_prefix: str,
    label: str,
    require_loopback: bool = True,
    loopback_severity: str = "warning",
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    try:
        host, _port = _parse_endpoint(raw_value)
    except ValueError:
        findings.append(_finding("error", code_prefix, f"{label} must use a valid host:port endpoint, got {raw_value or 'missing'}"))
        return findings
    if require_loopback and not _is_loopback_host(host):
        findings.append(_finding(loopback_severity, f"{code_prefix}-loopback", f"{label} is not loopback-bound: {raw_value}"))
    return findings


def _is_clean_absolute_http_path(value: str) -> bool:
    raw = str(value or "").strip()
    return bool(raw) and raw.startswith("/") and not raw.startswith("//") and "://" not in raw and "?" not in raw and "#" not in raw and not any(
        char.isspace() for char in raw
    )


def _validate_xray_api_surface(contract: dict[str, Any], *, role_prefix: str) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    xray = _xray_block(contract)
    services = set(_string_list(xray.get("apiServices")))
    inbounds = _dict_list(xray.get("apiInbounds"))

    if not services and not inbounds:
        return findings

    if "ReflectionService" in services:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-xray-api-reflection-service",
                f"{role_prefix} Xray API must not expose ReflectionService",
            )
        )

    unsupported_services = sorted(services - _XRAY_API_ALLOWED_SERVICES - {"ReflectionService"}, key=str)
    if unsupported_services:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-xray-api-service",
                f"{role_prefix} Xray API exposes unsupported services: {', '.join(unsupported_services)}",
            )
        )

    if services and not inbounds:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-xray-api-inbound",
                f"{role_prefix} Xray API services are enabled but no API inbound is advertised",
            )
        )
    if inbounds and not services:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-xray-api-services",
                f"{role_prefix} Xray API inbound is advertised without an API services allowlist",
            )
        )

    for index, inbound in enumerate(inbounds, start=1):
        listen = str(inbound.get("listen") or "").strip()
        if not listen:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-xray-api-listen",
                    f"{role_prefix} Xray API inbound #{index} must set an explicit loopback listen address",
                )
            )
        elif not _is_loopback_host(listen):
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-xray-api-listen-loopback",
                    f"{role_prefix} Xray API inbound #{index} is not loopback-bound: {listen}",
                )
            )

        try:
            port = int(inbound.get("port") if inbound.get("port") is not None else 0)
        except (TypeError, ValueError):
            port = 0
        if port < 1 or port > 65535:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-xray-api-port",
                    f"{role_prefix} Xray API inbound #{index} must use a valid local port, got {port}",
                )
            )

        protocol = str(inbound.get("protocol") or "").strip().lower()
        if protocol != "dokodemo-door":
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-xray-api-protocol",
                    f"{role_prefix} Xray API inbound #{index} must use dokodemo-door, got {protocol or 'missing'}",
                )
            )

    return findings


def _validate_hysteria_runtime(contract: dict[str, Any], *, role_prefix: str) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    hysteria = _hysteria_block(contract)
    if not bool(hysteria.get("configPresent", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-hysteria-config",
                f"{role_prefix} tracegate-2.2 Hysteria server config is missing from runtime-contract",
            )
        )
        return findings

    listen_port = _row_int(hysteria, "listenPort")
    if listen_port != TRACEGATE_PUBLIC_UDP_PORT:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-hysteria-listen-port",
                f"{role_prefix} Hysteria must listen on udp/{TRACEGATE_PUBLIC_UDP_PORT}, got {listen_port or 'missing'}",
            )
        )

    fronting = _fronting_block(contract)
    udp_owner = str(fronting.get("publicUdpOwner") or fronting.get("udp443Owner") or "").strip().lower()
    if udp_owner != "hysteria":
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate22-udp-owner",
                f"{role_prefix} tracegate-2.2 public udp/{TRACEGATE_PUBLIC_UDP_PORT} owner must be hysteria",
            )
        )

    decoy = contract.get("decoy")
    decoy_block = decoy if isinstance(decoy, dict) else {}
    split_dirs = _string_list(decoy_block.get("splitHysteriaMasqueradeDirs"))
    xray_dirs = _string_list(decoy_block.get("xrayHysteriaMasqueradeDirs"))
    if xray_dirs:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-tracegate22-xray-hysteria-dirs",
                f"{role_prefix} tracegate-2.2 must not publish Xray-native Hysteria masquerade dirs: {', '.join(xray_dirs)}",
            )
        )
    if not split_dirs:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-tracegate22-split-hysteria-dirs",
                f"{role_prefix} tracegate-2.2 has no standalone Hysteria masquerade dir in runtime-contract",
            )
        )

    auth = _row_dict(hysteria, "auth")
    if _row_string(auth, "type").lower() != "http":
        findings.append(_finding("error", f"{role_prefix}-hysteria-auth-type", f"{role_prefix} Hysteria auth.type must be http"))
    auth_url = _row_string(auth, "httpUrl")
    parsed_auth_url = urlparse(auth_url)
    if parsed_auth_url.scheme != "http" or not parsed_auth_url.netloc:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-hysteria-auth-url",
                f"{role_prefix} Hysteria auth HTTP backend must be a loopback http URL",
            )
        )
    elif not _is_loopback_host(parsed_auth_url.hostname or ""):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-hysteria-auth-loopback",
                f"{role_prefix} Hysteria auth HTTP backend is not loopback-bound: {auth_url}",
            )
        )
    if parsed_auth_url.path != "/v1/hysteria/auth" or parsed_auth_url.query or parsed_auth_url.fragment:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-hysteria-auth-path",
                f"{role_prefix} Hysteria auth HTTP backend must use /v1/hysteria/auth without query or fragment",
            )
        )
    if bool(auth.get("httpInsecure", False)):
        findings.append(_finding("error", f"{role_prefix}-hysteria-auth-insecure", f"{role_prefix} Hysteria auth.http.insecure must stay false"))

    obfs = _row_dict(hysteria, "obfs")
    if _row_string(obfs, "type").lower() != "salamander":
        findings.append(_finding("error", f"{role_prefix}-hysteria-obfs", f"{role_prefix} Hysteria obfs.type must stay salamander"))
    if not bool(obfs.get("salamanderPasswordConfigured", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-hysteria-salamander-password",
                f"{role_prefix} Hysteria Salamander password must be configured and non-placeholder",
            )
        )

    traffic_stats = _row_dict(hysteria, "trafficStats")
    stats_listen = _row_string(traffic_stats, "listen")
    if not stats_listen:
        findings.append(_finding("error", f"{role_prefix}-hysteria-stats-listen", f"{role_prefix} Hysteria trafficStats.listen is missing"))
    else:
        findings.extend(
            _validate_endpoint(
                raw_value=stats_listen,
                code_prefix=f"{role_prefix}-hysteria-stats-listen",
                label=f"{role_prefix} Hysteria trafficStats.listen",
                require_loopback=True,
                loopback_severity="error",
            )
        )
    if not bool(traffic_stats.get("secretConfigured", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-hysteria-stats-secret",
                f"{role_prefix} Hysteria trafficStats.secret must be configured and non-placeholder",
            )
        )

    tls = _row_dict(hysteria, "tls")
    if not bool(tls.get("certConfigured", False)):
        findings.append(_finding("error", f"{role_prefix}-hysteria-tls-cert", f"{role_prefix} Hysteria TLS cert path is missing"))
    if not bool(tls.get("keyConfigured", False)):
        findings.append(_finding("error", f"{role_prefix}-hysteria-tls-key", f"{role_prefix} Hysteria TLS key path is missing"))
    if _row_string(tls, "sniGuard") != "dns-san":
        findings.append(_finding("error", f"{role_prefix}-hysteria-sni-guard", f"{role_prefix} Hysteria TLS sniGuard must stay dns-san"))

    udp = _row_dict(hysteria, "udp")
    if not bool(udp.get("enabled", False)):
        findings.append(_finding("error", f"{role_prefix}-hysteria-udp-disabled", f"{role_prefix} Hysteria disableUDP must stay false"))
    if _row_string(udp, "idleTimeout") != "60s":
        findings.append(_finding("error", f"{role_prefix}-hysteria-udp-idle-timeout", f"{role_prefix} Hysteria udpIdleTimeout must stay 60s"))

    quic = _row_dict(hysteria, "quic")
    if bool(quic.get("disablePathMTUDiscovery", True)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-hysteria-quic-pmtu",
                f"{role_prefix} Hysteria QUIC path MTU discovery must stay enabled",
            )
        )
    if _row_string(quic, "maxIdleTimeout") not in {"30s", ""}:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-hysteria-quic-idle-timeout",
                f"{role_prefix} Hysteria QUIC maxIdleTimeout must stay 30s",
            )
        )

    congestion = _row_dict(hysteria, "congestion")
    if _row_string(congestion, "type") not in {"bbr", ""}:
        findings.append(_finding("error", f"{role_prefix}-hysteria-congestion", f"{role_prefix} Hysteria congestion must stay bbr"))

    sniff = _row_dict(hysteria, "sniff")
    if not bool(sniff.get("enabled", False)):
        findings.append(_finding("error", f"{role_prefix}-hysteria-sniff", f"{role_prefix} Hysteria sniff.enable must stay true"))

    if not _string_list(hysteria.get("masqueradeDirs")):
        findings.append(_finding("warning", f"{role_prefix}-hysteria-masquerade", f"{role_prefix} Hysteria masquerade dir is missing"))

    masquerade = _row_dict(hysteria, "masquerade")
    if masquerade and _row_string(masquerade, "type") != "file":
        findings.append(_finding("error", f"{role_prefix}-hysteria-masquerade-type", f"{role_prefix} Hysteria masquerade.type must stay file"))

    hygiene = _row_dict(hysteria, "hygiene")
    if not hygiene:
        findings.append(_finding("error", f"{role_prefix}-hysteria-hygiene", f"{role_prefix} Hysteria hygiene contract is missing"))
    else:
        if not bool(hygiene.get("required", False)):
            findings.append(_finding("error", f"{role_prefix}-hysteria-hygiene-required", f"{role_prefix} Hysteria hygiene.required must stay true"))
        if not bool(hygiene.get("enabled", False)):
            findings.append(_finding("error", f"{role_prefix}-hysteria-hygiene-enabled", f"{role_prefix} Hysteria hygiene.enabled must stay true"))

        required_layers = set(_string_list(hygiene.get("requiredLayers") or hygiene.get("required_layers")))
        for layer in (
            "hysteria2",
            "salamander",
            "file-masquerade",
            "dns-san-sni-guard",
            "http-auth-loopback",
            "reject-anonymous",
            "traffic-stats-loopback",
            "udp-enabled",
            "quic-pmtu",
            "udp-idle-timeout",
            "sniff",
        ):
            if layer not in required_layers:
                findings.append(
                    _finding(
                        "error",
                        f"{role_prefix}-hysteria-hygiene-layer-{layer}",
                        f"{role_prefix} Hysteria hygiene must require {layer}",
                    )
                )

        forbidden_ports = {
            (str(row.get("protocol") or "").strip().lower(), _row_int(row, "port"))
            for row in hygiene.get("forbiddenPublicPorts", [])
            if isinstance(row, dict)
        }
        if ("udp", TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT) not in forbidden_ports:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-hysteria-hygiene-forbidden-udp-4443",
                    f"{role_prefix} Hysteria hygiene must declare udp/{TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT} blocked",
                )
            )
        if ("tcp", TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT) not in forbidden_ports:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-hysteria-hygiene-forbidden-tcp-8443",
                    f"{role_prefix} Hysteria hygiene must declare tcp/{TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT} blocked",
                )
            )

    return findings


def _validate_https_url(*, raw_url: str, code: str, label: str) -> RuntimePreflightFinding | None:
    parsed = urlparse(str(raw_url or "").strip())
    if parsed.scheme != "https" or not parsed.netloc:
        return _finding("warning", code, f"{label} must stay on an https URL, got {raw_url or 'missing'}")
    return None


def validate_zapret_profile(profile: ZapretProfile, *, profile_kind: str) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    policy = _ZAPRET_SCOPE_POLICIES[profile_kind]
    prefix = f"zapret-{profile_kind}"

    if profile.scope != policy.expected_scope:
        findings.append(
            _finding(
                "error",
                f"{prefix}-scope",
                f"{profile_kind} zapret profile scope must be {policy.expected_scope}, got {profile.scope or 'missing'}",
            )
        )

    if profile.apply_mode != "selective":
        findings.append(
            _finding(
                "error",
                f"{prefix}-apply-mode",
                f"{profile_kind} zapret profile must keep TRACEGATE_ZAPRET_APPLY_MODE=selective",
            )
        )

    if profile.touch_unrelated_system_traffic:
        findings.append(
            _finding(
                "error",
                f"{prefix}-unrelated-traffic",
                f"{profile_kind} zapret profile must not touch unrelated system traffic",
            )
        )

    if profile.max_workers < 1:
        findings.append(
            _finding(
                "error",
                f"{prefix}-max-workers-invalid",
                f"{profile_kind} zapret profile must set TRACEGATE_ZAPRET_MAX_WORKERS to a positive integer",
            )
        )
    elif profile.max_workers > policy.max_workers_soft_limit:
        findings.append(
            _finding(
                "warning",
                f"{prefix}-max-workers",
                f"{profile_kind} zapret profile raises worker count above the low-overhead target: {profile.max_workers}",
            )
        )

    if profile.cpu_budget not in set(policy.allowed_cpu_budgets):
        findings.append(
            _finding(
                "warning",
                f"{prefix}-cpu-budget",
                f"{profile_kind} zapret profile leaves the low-overhead budget envelope: {profile.cpu_budget}",
            )
        )

    extra_tcp_ports = sorted(set(profile.target_tcp_ports) - set(policy.recommended_tcp_ports))
    if extra_tcp_ports:
        findings.append(
            _finding(
                "error",
                f"{prefix}-tcp-port-widen",
                f"{profile_kind} zapret profile widens TCP scope beyond the Tracegate 443 surface: {', '.join(map(str, extra_tcp_ports))}",
            )
        )
    missing_tcp_ports = sorted(set(policy.recommended_tcp_ports) - set(profile.target_tcp_ports))
    if missing_tcp_ports:
        findings.append(
            _finding(
                "warning",
                f"{prefix}-tcp-port-coverage",
                f"{profile_kind} zapret profile no longer covers recommended TCP ports: {', '.join(map(str, missing_tcp_ports))}",
            )
        )

    extra_udp_ports = sorted(set(profile.target_udp_ports) - set(policy.recommended_udp_ports))
    if extra_udp_ports:
        findings.append(
            _finding(
                "error",
                f"{prefix}-udp-port-widen",
                f"{profile_kind} zapret profile widens UDP scope beyond the intended surface: {', '.join(map(str, extra_udp_ports))}",
            )
        )
    missing_udp_ports = sorted(set(policy.recommended_udp_ports) - set(profile.target_udp_ports))
    if missing_udp_ports:
        findings.append(
            _finding(
                "warning",
                f"{prefix}-udp-port-coverage",
                f"{profile_kind} zapret profile no longer covers recommended UDP ports: {', '.join(map(str, missing_udp_ports))}",
            )
        )

    extra_protocols = sorted(set(profile.target_protocols) - set(policy.recommended_protocols))
    if extra_protocols:
        findings.append(
            _finding(
                "error",
                f"{prefix}-protocol-widen",
                f"{profile_kind} zapret profile widens protocol scope: {', '.join(extra_protocols)}",
            )
        )
    missing_protocols = sorted(set(policy.recommended_protocols) - set(profile.target_protocols))
    if missing_protocols:
        findings.append(
            _finding(
                "warning",
                f"{prefix}-protocol-coverage",
                f"{profile_kind} zapret profile no longer covers recommended protocols: {', '.join(missing_protocols)}",
            )
        )

    extra_surfaces = sorted(set(profile.target_surfaces) - set(policy.allowed_surfaces))
    if extra_surfaces:
        findings.append(
            _finding(
                "error",
                f"{prefix}-surface-widen",
                f"{profile_kind} zapret profile widens surface scope: {', '.join(extra_surfaces)}",
            )
        )
    missing_surfaces = sorted(set(policy.allowed_surfaces) - set(profile.target_surfaces))
    if missing_surfaces:
        findings.append(
            _finding(
                "warning",
                f"{prefix}-surface-coverage",
                f"{profile_kind} zapret profile no longer covers recommended surfaces: {', '.join(missing_surfaces)}",
            )
        )

    return findings


def validate_zapret_profile_collection(
    *,
    entry_profile: ZapretProfile,
    transit_profile: ZapretProfile,
    interconnect_profile: ZapretProfile,
    mtproto_profile: ZapretProfile | None = None,
    transit_contract: dict[str, Any] | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    findings.extend(validate_zapret_profile(entry_profile, profile_kind="entry"))
    findings.extend(validate_zapret_profile(transit_profile, profile_kind="transit"))
    findings.extend(validate_zapret_profile(interconnect_profile, profile_kind="interconnect"))
    if mtproto_profile is not None:
        findings.extend(validate_zapret_profile(mtproto_profile, profile_kind="mtproto"))

    transit_mtproto_domain = ""
    if transit_contract is not None:
        transit_mtproto_domain = str(_fronting_block(transit_contract).get("mtprotoDomain") or "").strip()

    if mtproto_profile is not None and not transit_mtproto_domain:
        findings.append(
            _finding(
                "warning",
                "zapret-mtproto-no-domain",
                "MTProto zapret profile is present but Transit runtime-contract does not advertise an MTProto domain",
            )
        )
    if mtproto_profile is None and transit_mtproto_domain:
        findings.append(
            _finding(
                "warning",
                "zapret-mtproto-missing-profile",
                "Transit runtime-contract advertises an MTProto domain but no MTProto zapret profile was validated",
            )
        )

    return findings


def validate_obfuscation_runtime_state(
    *,
    state: ObfuscationRuntimeState,
    contract: dict[str, Any],
    expected_role: str,
    contract_path: str | Path | None = None,
    zapret_profile: ZapretProfile | None = None,
    zapret_interconnect_profile: ZapretProfile | None = None,
    zapret_mtproto_profile: ZapretProfile | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    role_prefix = role_upper.lower() or "unknown"

    if state.role != role_upper:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-state-role",
                f"{role_prefix} obfuscation runtime-state role must be {role_upper}, got {state.role or 'missing'}",
            )
        )

    contract_runtime_profile = _runtime_profile(contract)
    if state.runtime_profile != contract_runtime_profile:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-state-profile",
                f"{role_prefix} obfuscation runtime-state profile mismatch: state={state.runtime_profile or 'missing'}, contract={contract_runtime_profile or 'missing'}",
            )
        )

    if not state.contract_present:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-state-contract-missing",
                f"{role_prefix} obfuscation runtime-state says runtime contract is absent",
            )
        )

    if contract_path is not None:
        expected_contract_path = str(Path(contract_path))
        if state.runtime_contract_path != expected_contract_path:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-state-contract-path",
                    f"{role_prefix} obfuscation runtime-state points at a different contract path: state={state.runtime_contract_path or 'missing'}, expected={expected_contract_path}",
                )
            )

    decoy_block = (contract.get("decoy") or {}) if isinstance(contract.get("decoy"), dict) else {}
    expected_decoy_roots = tuple(_string_list(decoy_block.get("nginxRoots")))
    if state.decoy_roots != expected_decoy_roots:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-decoy-roots",
                f"{role_prefix} obfuscation runtime-state decoy roots diverge from nginxRoots in runtime-contract",
            )
        )
    expected_split_dirs = tuple(_string_list(decoy_block.get("splitHysteriaMasqueradeDirs")))
    if state.split_hysteria_masquerade_dirs != expected_split_dirs:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-split-hysteria-dirs",
                f"{role_prefix} obfuscation runtime-state split Hysteria masquerade dirs diverge from runtime-contract",
            )
        )
    expected_xray_dirs = tuple(_string_list(decoy_block.get("xrayHysteriaMasqueradeDirs")))
    if state.xray_hysteria_masquerade_dirs != expected_xray_dirs:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-xray-hysteria-dirs",
                f"{role_prefix} obfuscation runtime-state Xray Hysteria masquerade dirs diverge from runtime-contract",
            )
        )

    expected_xray = _xray_block(contract)
    expected_xray_config_paths = tuple(_string_list(expected_xray.get("configPaths")))
    if state.xray_config_paths != expected_xray_config_paths:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-xray-configs",
                f"{role_prefix} obfuscation runtime-state Xray config paths diverge from runtime-contract",
            )
        )

    expected_hysteria_tags = tuple(_string_list(expected_xray.get("hysteriaInboundTags")))
    if state.xray_hysteria_inbound_tags != expected_hysteria_tags:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-state-hy2-tags",
                f"{role_prefix} obfuscation runtime-state Hysteria inbound tags diverge from runtime-contract",
            )
        )

    expected_finalmask = bool(expected_xray.get("finalMaskEnabled"))
    if state.finalmask_enabled != expected_finalmask:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-finalmask",
                f"{role_prefix} obfuscation runtime-state FinalMask flag diverges from runtime-contract",
            )
        )

    expected_ech = bool(expected_xray.get("echEnabled"))
    if state.ech_enabled != expected_ech:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-ech",
                f"{role_prefix} obfuscation runtime-state ECH flag diverges from runtime-contract",
            )
        )

    expected_fronting = _fronting_block(contract)
    if state.fronting_tcp_owner != str(expected_fronting.get("tcp443Owner") or "").strip():
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-state-tcp-owner",
                f"{role_prefix} obfuscation runtime-state tcp443 owner diverges from runtime-contract",
            )
        )
    expected_udp_owner = str(expected_fronting.get("publicUdpOwner") or expected_fronting.get("udp443Owner") or "").strip()
    if state.fronting_udp_owner != expected_udp_owner:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-state-udp-owner",
                f"{role_prefix} obfuscation runtime-state udp443 owner diverges from runtime-contract",
            )
        )
    if state.touch_udp_443 != bool(expected_fronting.get("touchUdp443", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-state-touch-udp-443",
                f"{role_prefix} obfuscation runtime-state touchUdp443 diverges from runtime-contract",
            )
        )
    if state.mtproto_domain != str(expected_fronting.get("mtprotoDomain") or "").strip():
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-mtproto-domain",
                f"{role_prefix} obfuscation runtime-state MTProto domain diverges from runtime-contract",
            )
        )
    if state.mtproto_public_port != int(expected_fronting.get("mtprotoPublicPort") or 443):
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-mtproto-port",
                f"{role_prefix} obfuscation runtime-state MTProto port diverges from runtime-contract",
            )
        )
    if state.mtproto_fronting_mode != str(expected_fronting.get("mtprotoFrontingMode") or "dedicated-dns-only").strip().lower():
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-mtproto-fronting",
                f"{role_prefix} obfuscation runtime-state MTProto fronting mode diverges from runtime-contract",
            )
        )

    if not state.interface:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-interface",
                f"{role_prefix} obfuscation runtime-state does not advertise a network interface",
            )
        )

    zapret_like_backend = state.backend in {"zapret", "zapret2"}
    if not state.backend:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-backend-missing",
                f"{role_prefix} obfuscation runtime-state does not advertise an obfuscation backend",
            )
        )
    elif not zapret_like_backend:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-state-backend",
                f"{role_prefix} obfuscation runtime-state backend is not zapret-based: {state.backend}",
            )
        )

    if zapret_profile is not None and zapret_like_backend:
        expected_profile_path = str(zapret_profile.path)
        if state.zapret_profile_file != expected_profile_path:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-state-profile-file",
                    f"{role_prefix} obfuscation runtime-state profile file diverges from validated zapret profile: state={state.zapret_profile_file or 'missing'}, expected={expected_profile_path}",
                )
            )
        if not state.zapret_policy_dir:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-state-policy-dir",
                    f"{role_prefix} obfuscation runtime-state does not advertise zapretPolicyDir",
                )
            )
        if not state.zapret_state_dir:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-state-state-dir",
                    f"{role_prefix} obfuscation runtime-state does not advertise zapretStateDir",
                )
            )

    if role_upper == "TRANSIT" and zapret_mtproto_profile is not None and zapret_like_backend:
        expected_mtproto_profile_path = str(zapret_mtproto_profile.path)
        if state.zapret_mtproto_profile_file != expected_mtproto_profile_path:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-state-mtproto-profile-file",
                    f"{role_prefix} obfuscation runtime-state MTProto profile file diverges from validated zapret profile: state={state.zapret_mtproto_profile_file or 'missing'}, expected={expected_mtproto_profile_path}",
                )
            )

    if zapret_interconnect_profile is not None and zapret_like_backend:
        expected_interconnect_profile_path = str(zapret_interconnect_profile.path)
        if state.zapret_interconnect_profile_file != expected_interconnect_profile_path:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-state-interconnect-profile-file",
                    f"{role_prefix} obfuscation runtime-state interconnect profile file diverges from validated zapret profile: state={state.zapret_interconnect_profile_file or 'missing'}, expected={expected_interconnect_profile_path}",
                )
            )

    return findings


def validate_obfuscation_runtime_env(
    *,
    env: ObfuscationRuntimeEnv,
    contract: dict[str, Any],
    expected_role: str,
    runtime_state: ObfuscationRuntimeState | None = None,
    contract_path: str | Path | None = None,
    zapret_profile: ZapretProfile | None = None,
    zapret_interconnect_profile: ZapretProfile | None = None,
    zapret_mtproto_profile: ZapretProfile | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    role_prefix = role_upper.lower() or "unknown"

    if env.role != role_upper:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-env-role",
                f"{role_prefix} obfuscation runtime-state env role must be {role_upper}, got {env.role or 'missing'}",
            )
        )

    contract_runtime_profile = _runtime_profile(contract)
    if env.runtime_profile != contract_runtime_profile:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-env-profile",
                f"{role_prefix} obfuscation runtime-state env profile mismatch: env={env.runtime_profile or 'missing'}, contract={contract_runtime_profile or 'missing'}",
            )
        )

    if not env.contract_present:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-env-contract-missing",
                f"{role_prefix} obfuscation runtime-state env says runtime contract is absent",
            )
        )

    if contract_path is not None:
        expected_contract_path = str(Path(contract_path))
        if env.runtime_contract_path != expected_contract_path:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-contract-path",
                    f"{role_prefix} obfuscation runtime-state env points at a different contract path: env={env.runtime_contract_path or 'missing'}, expected={expected_contract_path}",
                )
            )

    if not env.runtime_state_json:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-state-json",
                f"{role_prefix} obfuscation runtime-state env does not advertise runtime-state.json",
            )
        )

    decoy_block = (contract.get("decoy") or {}) if isinstance(contract.get("decoy"), dict) else {}
    expected_decoy_roots = tuple(_string_list(decoy_block.get("nginxRoots")))
    if env.decoy_roots != expected_decoy_roots:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-decoy-roots",
                f"{role_prefix} obfuscation runtime-state env decoy roots diverge from nginxRoots in runtime-contract",
            )
        )
    expected_split_dirs = tuple(_string_list(decoy_block.get("splitHysteriaMasqueradeDirs")))
    if env.split_hysteria_masquerade_dirs != expected_split_dirs:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-split-hysteria-dirs",
                f"{role_prefix} obfuscation runtime-state env split Hysteria masquerade dirs diverge from runtime-contract",
            )
        )
    expected_xray_dirs = tuple(_string_list(decoy_block.get("xrayHysteriaMasqueradeDirs")))
    if env.xray_hysteria_masquerade_dirs != expected_xray_dirs:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-xray-hysteria-dirs",
                f"{role_prefix} obfuscation runtime-state env Xray Hysteria masquerade dirs diverge from runtime-contract",
            )
        )

    expected_xray = _xray_block(contract)
    expected_xray_config_paths = tuple(_string_list(expected_xray.get("configPaths")))
    if env.xray_config_paths != expected_xray_config_paths:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-xray-configs",
                f"{role_prefix} obfuscation runtime-state env Xray config paths diverge from runtime-contract",
            )
        )

    expected_hysteria_tags = tuple(_string_list(expected_xray.get("hysteriaInboundTags")))
    if env.xray_hysteria_inbound_tags != expected_hysteria_tags:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-env-hy2-tags",
                f"{role_prefix} obfuscation runtime-state env Hysteria inbound tags diverge from runtime-contract",
            )
        )

    expected_finalmask = bool(expected_xray.get("finalMaskEnabled"))
    if env.finalmask_enabled != expected_finalmask:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-finalmask",
                f"{role_prefix} obfuscation runtime-state env FinalMask flag diverges from runtime-contract",
            )
        )

    expected_ech = bool(expected_xray.get("echEnabled"))
    if env.ech_enabled != expected_ech:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-ech",
                f"{role_prefix} obfuscation runtime-state env ECH flag diverges from runtime-contract",
            )
        )

    expected_fronting = _fronting_block(contract)
    if env.fronting_tcp_owner != str(expected_fronting.get("tcp443Owner") or "").strip():
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-env-tcp-owner",
                f"{role_prefix} obfuscation runtime-state env tcp443 owner diverges from runtime-contract",
            )
        )
    expected_udp_owner = str(expected_fronting.get("publicUdpOwner") or expected_fronting.get("udp443Owner") or "").strip()
    if env.fronting_udp_owner != expected_udp_owner:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-env-udp-owner",
                f"{role_prefix} obfuscation runtime-state env udp443 owner diverges from runtime-contract",
            )
        )
    if env.touch_udp_443 != bool(expected_fronting.get("touchUdp443", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-runtime-env-touch-udp-443",
                f"{role_prefix} obfuscation runtime-state env touchUdp443 diverges from runtime-contract",
            )
        )
    if env.mtproto_domain != str(expected_fronting.get("mtprotoDomain") or "").strip():
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-mtproto-domain",
                f"{role_prefix} obfuscation runtime-state env MTProto domain diverges from runtime-contract",
            )
        )
    if env.mtproto_public_port != int(expected_fronting.get("mtprotoPublicPort") or 443):
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-mtproto-port",
                f"{role_prefix} obfuscation runtime-state env MTProto port diverges from runtime-contract",
            )
        )
    if env.mtproto_fronting_mode != str(expected_fronting.get("mtprotoFrontingMode") or "dedicated-dns-only").strip().lower():
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-mtproto-fronting",
                f"{role_prefix} obfuscation runtime-state env MTProto fronting mode diverges from runtime-contract",
            )
        )

    if not env.interface:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-interface",
                f"{role_prefix} obfuscation runtime-state env does not advertise a network interface",
            )
        )

    zapret_like_backend = env.backend in {"zapret", "zapret2"}
    if not env.backend:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-backend-missing",
                f"{role_prefix} obfuscation runtime-state env does not advertise an obfuscation backend",
            )
        )
    elif not zapret_like_backend:
        findings.append(
            _finding(
                "warning",
                f"{role_prefix}-runtime-env-backend",
                f"{role_prefix} obfuscation runtime-state env backend is not zapret-based: {env.backend}",
            )
        )

    if zapret_profile is not None and zapret_like_backend:
        expected_profile_path = str(zapret_profile.path)
        if env.zapret_profile_file != expected_profile_path:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-profile-file",
                    f"{role_prefix} obfuscation runtime-state env profile file diverges from validated zapret profile: env={env.zapret_profile_file or 'missing'}, expected={expected_profile_path}",
                )
            )
        if not env.zapret_policy_dir:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-policy-dir",
                    f"{role_prefix} obfuscation runtime-state env does not advertise zapretPolicyDir",
                )
            )
        if not env.zapret_state_dir:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-dir",
                    f"{role_prefix} obfuscation runtime-state env does not advertise zapretStateDir",
                )
            )

    if role_upper == "TRANSIT" and zapret_mtproto_profile is not None and zapret_like_backend:
        expected_mtproto_profile_path = str(zapret_mtproto_profile.path)
        if env.zapret_mtproto_profile_file != expected_mtproto_profile_path:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-mtproto-profile-file",
                    f"{role_prefix} obfuscation runtime-state env MTProto profile file diverges from validated zapret profile: env={env.zapret_mtproto_profile_file or 'missing'}, expected={expected_mtproto_profile_path}",
                )
            )

    if zapret_interconnect_profile is not None and zapret_like_backend:
        expected_interconnect_profile_path = str(zapret_interconnect_profile.path)
        if env.zapret_interconnect_profile_file != expected_interconnect_profile_path:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-interconnect-profile-file",
                    f"{role_prefix} obfuscation runtime-state env interconnect profile file diverges from validated zapret profile: env={env.zapret_interconnect_profile_file or 'missing'}, expected={expected_interconnect_profile_path}",
                )
            )

    if runtime_state is not None:
        if env.runtime_state_json != str(runtime_state.path):
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-json-path",
                    f"{role_prefix} obfuscation runtime-state env points at a different runtime-state.json path",
                )
            )
        if env.role != runtime_state.role:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-state-role",
                    f"{role_prefix} obfuscation runtime-state env role diverges from runtime-state.json",
                )
            )
        if env.interface != runtime_state.interface:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-interface",
                    f"{role_prefix} obfuscation runtime-state env interface diverges from runtime-state.json",
                )
            )
        if env.runtime_profile != runtime_state.runtime_profile:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-state-profile",
                    f"{role_prefix} obfuscation runtime-state env profile diverges from runtime-state.json",
                )
            )
        if env.runtime_contract_path != runtime_state.runtime_contract_path:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-contract-path",
                    f"{role_prefix} obfuscation runtime-state env contract path diverges from runtime-state.json",
                )
            )
        if env.contract_present != runtime_state.contract_present:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-state-contract-present",
                    f"{role_prefix} obfuscation runtime-state env contractPresent diverges from runtime-state.json",
                )
            )
        if env.decoy_roots != runtime_state.decoy_roots:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-decoy-roots",
                    f"{role_prefix} obfuscation runtime-state env decoy roots diverge from runtime-state.json",
                )
            )
        if env.split_hysteria_masquerade_dirs != runtime_state.split_hysteria_masquerade_dirs:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-split-hysteria-dirs",
                    f"{role_prefix} obfuscation runtime-state env split Hysteria masquerade dirs diverge from runtime-state.json",
                )
            )
        if env.xray_hysteria_masquerade_dirs != runtime_state.xray_hysteria_masquerade_dirs:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-xray-hysteria-dirs",
                    f"{role_prefix} obfuscation runtime-state env Xray Hysteria masquerade dirs diverge from runtime-state.json",
                )
            )
        if env.xray_config_paths != runtime_state.xray_config_paths:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-xray-configs",
                    f"{role_prefix} obfuscation runtime-state env Xray config paths diverge from runtime-state.json",
                )
            )
        if env.xray_hysteria_inbound_tags != runtime_state.xray_hysteria_inbound_tags:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-state-hy2-tags",
                    f"{role_prefix} obfuscation runtime-state env Hysteria inbound tags diverge from runtime-state.json",
                )
            )
        if env.finalmask_enabled != runtime_state.finalmask_enabled:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-finalmask",
                    f"{role_prefix} obfuscation runtime-state env FinalMask flag diverges from runtime-state.json",
                )
            )
        if env.ech_enabled != runtime_state.ech_enabled:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-ech",
                    f"{role_prefix} obfuscation runtime-state env ECH flag diverges from runtime-state.json",
                )
            )
        if env.backend != runtime_state.backend:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-backend",
                    f"{role_prefix} obfuscation runtime-state env backend diverges from runtime-state.json",
                )
            )
        if env.zapret_profile_file != runtime_state.zapret_profile_file:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-state-profile-file",
                    f"{role_prefix} obfuscation runtime-state env zapret profile path diverges from runtime-state.json",
                )
            )
        if env.zapret_interconnect_profile_file != runtime_state.zapret_interconnect_profile_file:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-state-interconnect-profile-file",
                    f"{role_prefix} obfuscation runtime-state env interconnect profile path diverges from runtime-state.json",
                )
            )
        if env.zapret_mtproto_profile_file != runtime_state.zapret_mtproto_profile_file:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-mtproto-profile-file",
                    f"{role_prefix} obfuscation runtime-state env MTProto profile path diverges from runtime-state.json",
                )
            )
        if env.zapret_policy_dir != runtime_state.zapret_policy_dir:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-policy-dir",
                    f"{role_prefix} obfuscation runtime-state env zapretPolicyDir diverges from runtime-state.json",
                )
            )
        if env.zapret_state_dir != runtime_state.zapret_state_dir:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-state-dir",
                    f"{role_prefix} obfuscation runtime-state env zapretStateDir diverges from runtime-state.json",
                )
            )
        if env.fronting_tcp_owner != runtime_state.fronting_tcp_owner:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-state-tcp-owner",
                    f"{role_prefix} obfuscation runtime-state env tcp443 owner diverges from runtime-state.json",
                )
            )
        if env.fronting_udp_owner != runtime_state.fronting_udp_owner:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-state-udp-owner",
                    f"{role_prefix} obfuscation runtime-state env udp443 owner diverges from runtime-state.json",
                )
            )
        if env.touch_udp_443 != runtime_state.touch_udp_443:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-runtime-env-state-touch-udp-443",
                    f"{role_prefix} obfuscation runtime-state env touchUdp443 diverges from runtime-state.json",
                )
            )
        if env.mtproto_domain != runtime_state.mtproto_domain:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-mtproto-domain",
                    f"{role_prefix} obfuscation runtime-state env MTProto domain diverges from runtime-state.json",
                )
            )
        if env.mtproto_public_port != runtime_state.mtproto_public_port:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-mtproto-port",
                    f"{role_prefix} obfuscation runtime-state env MTProto port diverges from runtime-state.json",
                )
            )
        if env.mtproto_fronting_mode != runtime_state.mtproto_fronting_mode:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-runtime-env-state-mtproto-fronting",
                    f"{role_prefix} obfuscation runtime-state env MTProto fronting mode diverges from runtime-state.json",
                )
            )

    return findings


def _role_runtime_contract_from_obfuscation_env(env: ObfuscationEnvContract, role_upper: str) -> str:
    if role_upper == "ENTRY":
        return env.entry_runtime_contract
    return env.transit_runtime_contract


def _role_interface_from_obfuscation_env(env: ObfuscationEnvContract, role_upper: str) -> str:
    if role_upper == "ENTRY":
        return env.entry_interface
    return env.transit_interface


def _role_profile_path_from_obfuscation_env(env: ObfuscationEnvContract, role_upper: str) -> str:
    profile_name = env.zapret_profile_entry if role_upper == "ENTRY" else env.zapret_profile_transit
    return str(Path(env.zapret_profile_dir) / profile_name)


def _mtproto_profile_path_from_obfuscation_env(env: ObfuscationEnvContract) -> str:
    return str(Path(env.zapret_profile_dir) / env.zapret_profile_mtproto)


def _interconnect_profile_path_from_obfuscation_env(env: ObfuscationEnvContract) -> str:
    return str(Path(env.zapret_profile_dir) / env.zapret_profile_interconnect)


def _runtime_state_paths_from_obfuscation_env(env: ObfuscationEnvContract, role_upper: str) -> tuple[str, str]:
    role_lower = role_upper.lower()
    root = Path(env.private_runtime_dir) / "obfuscation" / role_lower
    return str(root / "runtime-state.json"), str(root / "runtime-state.env")


def validate_obfuscation_env_contract(
    *,
    env: ObfuscationEnvContract,
    entry_contract_path: str | Path | None = None,
    transit_contract_path: str | Path | None = None,
    entry_profile: ZapretProfile | None = None,
    transit_profile: ZapretProfile | None = None,
    interconnect_profile: ZapretProfile | None = None,
    mtproto_profile: ZapretProfile | None = None,
    entry_runtime_state: ObfuscationRuntimeState | None = None,
    transit_runtime_state: ObfuscationRuntimeState | None = None,
    entry_runtime_env: ObfuscationRuntimeEnv | None = None,
    transit_runtime_env: ObfuscationRuntimeEnv | None = None,
    fronting_env: FrontingEnvContract | None = None,
    mtproto_env: MTProtoEnvContract | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []

    if not env.backend:
        findings.append(_finding("warning", "obfuscation-env-backend-missing", "obfuscation env does not advertise a backend"))
    elif env.backend not in {"zapret", "zapret2"}:
        findings.append(_finding("warning", "obfuscation-env-backend", f"obfuscation env backend is not zapret-based: {env.backend}"))

    if env.finalmask_mode != "overlay":
        findings.append(_finding("warning", "obfuscation-env-finalmask-mode", f"obfuscation env FinalMask mode diverges from overlay: {env.finalmask_mode or 'missing'}"))

    if not env.entry_interface:
        findings.append(_finding("warning", "obfuscation-env-entry-interface", "obfuscation env is missing TRACEGATE_ENTRY_INTERFACE"))
    if not env.transit_interface:
        findings.append(_finding("warning", "obfuscation-env-transit-interface", "obfuscation env is missing TRACEGATE_TRANSIT_INTERFACE"))

    if entry_contract_path is not None and env.entry_runtime_contract != str(Path(entry_contract_path)):
        findings.append(_finding("warning", "obfuscation-env-entry-contract", "obfuscation env Entry runtime-contract path diverges from preflight input"))
    if transit_contract_path is not None and env.transit_runtime_contract != str(Path(transit_contract_path)):
        findings.append(_finding("warning", "obfuscation-env-transit-contract", "obfuscation env Transit runtime-contract path diverges from preflight input"))

    expected_entry_profile_path = str(Path(env.zapret_profile_dir) / env.zapret_profile_entry)
    expected_transit_profile_path = str(Path(env.zapret_profile_dir) / env.zapret_profile_transit)
    expected_interconnect_profile_path = _interconnect_profile_path_from_obfuscation_env(env)
    expected_mtproto_profile_path = _mtproto_profile_path_from_obfuscation_env(env)

    if entry_profile is not None and expected_entry_profile_path != str(entry_profile.path):
        findings.append(_finding("warning", "obfuscation-env-entry-profile-file", "obfuscation env Entry zapret profile path diverges from validated zapret metadata"))
    if transit_profile is not None and expected_transit_profile_path != str(transit_profile.path):
        findings.append(_finding("warning", "obfuscation-env-transit-profile-file", "obfuscation env Transit zapret profile path diverges from validated zapret metadata"))
    if interconnect_profile is not None and expected_interconnect_profile_path != str(interconnect_profile.path):
        findings.append(_finding("warning", "obfuscation-env-interconnect-profile-file", "obfuscation env Entry-Transit zapret profile path diverges from validated zapret metadata"))
    if mtproto_profile is not None and expected_mtproto_profile_path != str(mtproto_profile.path):
        findings.append(_finding("warning", "obfuscation-env-mtproto-profile-file", "obfuscation env MTProto zapret profile path diverges from validated zapret metadata"))

    for role_upper, runtime_state, runtime_env in (
        ("ENTRY", entry_runtime_state, entry_runtime_env),
        ("TRANSIT", transit_runtime_state, transit_runtime_env),
    ):
        expected_contract_path = _role_runtime_contract_from_obfuscation_env(env, role_upper)
        expected_interface = _role_interface_from_obfuscation_env(env, role_upper)
        expected_profile_path = _role_profile_path_from_obfuscation_env(env, role_upper)
        expected_runtime_state_json, expected_runtime_state_env = _runtime_state_paths_from_obfuscation_env(env, role_upper)

        if runtime_state is not None:
            role_prefix = role_upper.lower()
            if str(runtime_state.path) != expected_runtime_state_json:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-state-path", f"obfuscation env {role_prefix} runtime-state.json path diverges from derived private runtime dir"))
            if runtime_state.runtime_contract_path != expected_contract_path:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-state-contract", f"obfuscation env {role_prefix} runtime-contract path diverges from runtime-state.json"))
            if runtime_state.interface != expected_interface:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-state-interface", f"obfuscation env {role_prefix} interface diverges from runtime-state.json"))
            if runtime_state.backend != env.backend:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-state-backend", f"obfuscation env {role_prefix} backend diverges from runtime-state.json"))
            if runtime_state.zapret_profile_file != expected_profile_path:
                findings.append(_finding("error", f"obfuscation-env-{role_prefix}-state-profile", f"obfuscation env {role_prefix} zapret profile path diverges from runtime-state.json"))
            if runtime_state.zapret_interconnect_profile_file != expected_interconnect_profile_path:
                findings.append(_finding("error", f"obfuscation-env-{role_prefix}-state-interconnect-profile", f"obfuscation env {role_prefix} interconnect zapret profile path diverges from runtime-state.json"))
            if runtime_state.zapret_policy_dir != env.zapret_policy_dir:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-state-policy-dir", f"obfuscation env {role_prefix} zapretPolicyDir diverges from runtime-state.json"))
            if runtime_state.zapret_state_dir != env.zapret_state_dir:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-state-state-dir", f"obfuscation env {role_prefix} zapretStateDir diverges from runtime-state.json"))
            if runtime_env is not None:
                if runtime_state.decoy_roots != runtime_env.decoy_roots:
                    findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-state-decoy-roots", f"obfuscation env {role_prefix} decoy roots diverge between runtime-state.json and runtime-state.env"))
                if runtime_state.split_hysteria_masquerade_dirs != runtime_env.split_hysteria_masquerade_dirs:
                    findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-state-split-hysteria-dirs", f"obfuscation env {role_prefix} split Hysteria dirs diverge between runtime-state.json and runtime-state.env"))
                if runtime_state.xray_hysteria_masquerade_dirs != runtime_env.xray_hysteria_masquerade_dirs:
                    findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-state-xray-hysteria-dirs", f"obfuscation env {role_prefix} Xray Hysteria dirs diverge between runtime-state.json and runtime-state.env"))

        if runtime_env is not None:
            role_prefix = role_upper.lower()
            if str(runtime_env.path) != expected_runtime_state_env:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-env-path", f"obfuscation env {role_prefix} runtime-state.env path diverges from derived private runtime dir"))
            if runtime_env.runtime_state_json != expected_runtime_state_json:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-env-state-json", f"obfuscation env {role_prefix} runtime-state.env JSON path diverges from derived private runtime dir"))
            if runtime_env.runtime_contract_path != expected_contract_path:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-env-contract", f"obfuscation env {role_prefix} runtime-contract path diverges from runtime-state.env"))
            if runtime_env.interface != expected_interface:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-env-interface", f"obfuscation env {role_prefix} interface diverges from runtime-state.env"))
            if runtime_env.backend != env.backend:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-env-backend", f"obfuscation env {role_prefix} backend diverges from runtime-state.env"))
            if runtime_env.zapret_profile_file != expected_profile_path:
                findings.append(_finding("error", f"obfuscation-env-{role_prefix}-env-profile", f"obfuscation env {role_prefix} zapret profile path diverges from runtime-state.env"))
            if runtime_env.zapret_interconnect_profile_file != expected_interconnect_profile_path:
                findings.append(_finding("error", f"obfuscation-env-{role_prefix}-env-interconnect-profile", f"obfuscation env {role_prefix} interconnect zapret profile path diverges from runtime-state.env"))
            if runtime_env.zapret_policy_dir != env.zapret_policy_dir:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-env-policy-dir", f"obfuscation env {role_prefix} zapretPolicyDir diverges from runtime-state.env"))
            if runtime_env.zapret_state_dir != env.zapret_state_dir:
                findings.append(_finding("warning", f"obfuscation-env-{role_prefix}-env-state-dir", f"obfuscation env {role_prefix} zapretStateDir diverges from runtime-state.env"))

    if fronting_env is not None:
        expected_transit_runtime_state_json, _ = _runtime_state_paths_from_obfuscation_env(env, "TRANSIT")
        if fronting_env.runtime_state_json != expected_transit_runtime_state_json:
            findings.append(_finding("warning", "obfuscation-env-fronting-runtime-state-json", "obfuscation env derived Transit runtime-state.json path diverges from fronting env"))
        if fronting_env.mtproto_profile_file != expected_mtproto_profile_path:
            findings.append(_finding("warning", "obfuscation-env-fronting-mtproto-profile", "obfuscation env MTProto profile path diverges from fronting env"))

    if mtproto_env is not None:
        expected_transit_runtime_state_json, _ = _runtime_state_paths_from_obfuscation_env(env, "TRANSIT")
        if mtproto_env.runtime_state_json != expected_transit_runtime_state_json:
            findings.append(_finding("warning", "obfuscation-env-mtproto-runtime-state-json", "obfuscation env derived Transit runtime-state.json path diverges from mtproto env"))
        if mtproto_env.profile_file != expected_mtproto_profile_path:
            findings.append(_finding("warning", "obfuscation-env-mtproto-profile", "obfuscation env MTProto profile path diverges from mtproto env"))

    return findings


_PRIVATE_PROFILE_SCHEMA = "tracegate.private-profiles.v1"
_COMMON_LOCAL_PROXY_PORTS = {1080, 10808, 7890, 7891, 8080}


def _row_string(row: dict[str, Any], key: str) -> str:
    return str(row.get(key) or "").strip()


def _row_int(row: dict[str, Any], key: str, *, default: int = 0) -> int:
    try:
        return int(row.get(key) if row.get(key) is not None else default)
    except (TypeError, ValueError):
        return default


def _row_dict(row: dict[str, Any], key: str) -> dict[str, Any]:
    value = row.get(key)
    return value if isinstance(value, dict) else {}


def _looks_placeholder(value: object) -> bool:
    raw = str(value or "").strip().upper()
    if not raw:
        return True
    return raw.startswith("REPLACE_") or raw in {"CHANGE_ME", "TODO", "TBD"}


def _validate_private_profile_counts(
    *,
    state: PrivateProfileState,
    prefix: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    shadowtls_count = len(state.shadowsocks2022_shadowtls)
    wireguard_count = len(state.wireguard_wstunnel)
    total = shadowtls_count + wireguard_count
    if state.total_count != total:
        findings.append(
            _finding(
                "error",
                f"{prefix}-count-total",
                f"{prefix.replace('-', ' ')} total count diverges from private profile entries",
            )
        )
    if state.shadowsocks2022_shadowtls_count != shadowtls_count:
        findings.append(
            _finding(
                "error",
                f"{prefix}-count-shadowtls",
                f"{prefix.replace('-', ' ')} Shadowsocks2022/ShadowTLS count diverges from private profile entries",
            )
        )
    if state.wireguard_wstunnel_count != wireguard_count:
        findings.append(
            _finding(
                "error",
                f"{prefix}-count-wireguard",
                f"{prefix.replace('-', ' ')} WireGuard/WSTunnel count diverges from private profile entries",
            )
        )
    return findings


def _validate_private_profile_transport_profiles(
    *,
    state: PrivateProfileState,
    contract: dict[str, Any],
    prefix: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    contract_transport = _transport_profiles_block(contract)
    if not contract_transport:
        return findings

    if not state.transport_profiles:
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-profiles",
                f"{prefix.replace('-', ' ')} must mirror runtime-contract transportProfiles",
            )
        )
        return findings

    state_client_names = _string_list(state.transport_profiles.get("clientNames"))
    contract_client_names = _string_list(contract_transport.get("clientNames"))
    if state_client_names != contract_client_names:
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-client-names",
                f"{prefix.replace('-', ' ')} clientNames diverge from runtime-contract",
            )
        )

    state_local_socks = _row_dict(state.transport_profiles, "localSocks")
    contract_local_socks = _row_dict(contract_transport, "localSocks")
    if state_local_socks != contract_local_socks:
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-local-socks",
                f"{prefix.replace('-', ' ')} localSocks policy diverges from runtime-contract",
            )
        )
    if str(state_local_socks.get("auth") or "").strip().lower() != "required":
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-local-socks-auth",
                f"{prefix.replace('-', ' ')} local SOCKS5 auth must stay required",
            )
        )
    if bool(state_local_socks.get("allowAnonymousLocalhost", False)):
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-local-socks-anonymous",
                f"{prefix.replace('-', ' ')} must not allow anonymous localhost SOCKS5",
            )
        )

    return findings


def _validate_private_local_socks(
    *,
    row: dict[str, Any],
    code_prefix: str,
    label: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    local_socks = _row_dict(row, "localSocks")
    auth = _row_dict(local_socks, "auth")
    if not local_socks:
        findings.append(_finding("error", f"{code_prefix}-local-socks", f"{label} must include a localSocks contract"))
        return findings
    findings.extend(
        _validate_endpoint(
            raw_value=_row_string(local_socks, "listen"),
            code_prefix=f"{code_prefix}-local-socks-listen",
            label=f"{label} local SOCKS5 listen endpoint",
            require_loopback=True,
            loopback_severity="error",
        )
    )
    try:
        _host, port = _parse_endpoint(_row_string(local_socks, "listen"))
    except ValueError:
        port = 0
    if port in _COMMON_LOCAL_PROXY_PORTS:
        findings.append(
            _finding(
                "warning",
                f"{code_prefix}-local-socks-common-port",
                f"{label} local SOCKS5 listen port {port} is commonly scanned; prefer generated high ports",
            )
        )
    if not bool(local_socks.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-local-socks-enabled", f"{label} local SOCKS adapter must stay enabled"))
    if not bool(auth.get("required", False)):
        findings.append(_finding("error", f"{code_prefix}-local-socks-auth", f"{label} local SOCKS5 auth must be required"))
    if _row_string(auth, "mode") != "username_password":
        findings.append(_finding("error", f"{code_prefix}-local-socks-auth-mode", f"{label} local SOCKS5 auth must use username_password"))
    if not _row_string(auth, "username") or not _row_string(auth, "password"):
        findings.append(_finding("error", f"{code_prefix}-local-socks-credentials", f"{label} local SOCKS5 auth needs username and password"))
    return findings


def _validate_private_obfuscation(
    *,
    row: dict[str, Any],
    code_prefix: str,
    label: str,
    expected_outer: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    obfuscation = _row_dict(row, "obfuscation")
    if bool(obfuscation.get("hostWideInterception", True)):
        findings.append(_finding("error", f"{code_prefix}-host-wide-interception", f"{label} must not enable host-wide interception"))
    packet_shaping = str(obfuscation.get("packetShaping") or "").strip().lower()
    outer = str(obfuscation.get("outer") or "").strip().lower()
    if expected_outer and outer != expected_outer:
        findings.append(_finding("error", f"{code_prefix}-outer", f"{label} obfuscation outer must be {expected_outer}"))
    expected_packet_shaping = "none" if expected_outer in {"wstunnel", "reality-xhttp", "shadowtls-v3"} else "zapret2-scoped"
    if packet_shaping != expected_packet_shaping:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-packet-shaping",
                f"{label} packet shaping must be {expected_packet_shaping}",
            )
        )
    return findings


def _validate_wireguard_peer_allowed_ips(
    *,
    values: list[object],
    code_prefix: str,
    label: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    for raw_value in values:
        token = str(raw_value or "").strip()
        if not token:
            continue
        try:
            network = ip_network(token, strict=False)
        except ValueError:
            findings.append(_finding("error", f"{code_prefix}-wireguard-allowed-ips-parse", f"{label} WireGuard allowedIps entry is invalid: {token}"))
            continue
        if network.prefixlen != network.max_prefixlen:
            findings.append(
                _finding(
                    "error",
                    f"{code_prefix}-wireguard-allowed-ips-host-route",
                    f"{label} WireGuard allowedIps must be peer host routes, not client default or subnet routes",
                )
            )
    return findings


def _validate_private_shadowtls_profile(
    *,
    row: dict[str, Any],
    role_upper: str,
    index: int,
    prefix: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    variant = _row_string(row, "variant").upper()
    mode = _row_string(row, "mode").lower()
    chain = _row_dict(row, "chain")
    is_chain = mode == "chain" or bool(chain)
    suffix = variant.lower() if variant else f"row-{index}"
    code_prefix = f"{prefix}-shadowtls-{suffix}"
    label = f"{role_upper.lower()} Shadowsocks2022/ShadowTLS {variant or index}"

    if _row_string(row, "protocol") != "shadowsocks2022_shadowtls":
        findings.append(_finding("error", f"{code_prefix}-protocol", f"{label} protocol must be shadowsocks2022_shadowtls"))
    if variant != "V3":
        findings.append(_finding("error", f"{code_prefix}-variant", f"{label} must use V3"))

    expected_profile = "v3-chain-shadowtls-shadowsocks" if is_chain else "v3-direct-shadowtls-shadowsocks"
    if _row_string(row, "profile") != expected_profile:
        findings.append(_finding("error", f"{code_prefix}-profile", f"{label} profile name must be {expected_profile}"))

    expected_stage = "direct-transit-public"
    if is_chain:
        expected_stage = "entry-public-to-transit-relay" if role_upper == "ENTRY" else "transit-private-terminator"
    if _row_string(row, "stage") != expected_stage:
        findings.append(_finding("error", f"{code_prefix}-stage", f"{label} stage must be {expected_stage}"))

    if role_upper == "ENTRY" and not is_chain:
        findings.append(_finding("error", f"{code_prefix}-entry-mode", "Entry private profile handoff must only receive V3 chain relays"))
    if role_upper == "TRANSIT" and variant != "V3":
        findings.append(_finding("error", f"{code_prefix}-transit-variant", "Transit private profile handoff only supports V3 ShadowTLS entries"))

    if _row_int(row, "port") != 443:
        findings.append(_finding("error", f"{code_prefix}-port", f"{label} must stay on tcp/443"))

    ss2022 = _row_dict(row, "shadowsocks2022")
    if not _row_string(ss2022, "method"):
        findings.append(_finding("error", f"{code_prefix}-ss-method", f"{label} missing Shadowsocks 2022 method"))
    if _looks_placeholder(ss2022.get("password")):
        findings.append(_finding("error", f"{code_prefix}-ss-password", f"{label} missing Shadowsocks 2022 password"))

    shadowtls = _row_dict(row, "shadowtls")
    if _row_int(shadowtls, "version") != 3:
        findings.append(_finding("error", f"{code_prefix}-shadowtls-version", f"{label} must use ShadowTLS v3"))
    if not _row_string(shadowtls, "serverName"):
        findings.append(_finding("error", f"{code_prefix}-shadowtls-server-name", f"{label} missing ShadowTLS serverName"))
    if _row_string(shadowtls, "password"):
        findings.append(_finding("error", f"{code_prefix}-shadowtls-password", f"{label} must not carry per-user ShadowTLS password"))
    if _row_string(shadowtls, "credentialScope") != "node-static":
        findings.append(_finding("error", f"{code_prefix}-shadowtls-credential-scope", f"{label} ShadowTLS credentials must stay node-static"))
    profile_ref = _row_dict(shadowtls, "profileRef")
    if _row_string(profile_ref, "kind") != "file":
        findings.append(_finding("error", f"{code_prefix}-shadowtls-profile-ref-kind", f"{label} ShadowTLS profileRef must be file-based"))
    if not _row_string(profile_ref, "path"):
        findings.append(_finding("error", f"{code_prefix}-shadowtls-profile-ref-path", f"{label} ShadowTLS profileRef path is missing"))
    if not bool(profile_ref.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-shadowtls-profile-ref-secret", f"{label} ShadowTLS profileRef must point at private secret material"))
    if bool(shadowtls.get("manageUsers", True)):
        findings.append(_finding("error", f"{code_prefix}-shadowtls-manage-users", f"{label} ShadowTLS outer users must not be managed per user"))
    if bool(shadowtls.get("restartOnUserChange", True)):
        findings.append(_finding("error", f"{code_prefix}-shadowtls-restart-on-user-change", f"{label} ShadowTLS must not restart on user change"))

    findings.extend(_validate_private_local_socks(row=row, code_prefix=code_prefix, label=label))
    expected_outer = "reality-xhttp" if is_chain else "shadowtls-v3"
    findings.extend(_validate_private_obfuscation(row=row, code_prefix=code_prefix, label=label, expected_outer=expected_outer))

    if is_chain:
        if not chain:
            findings.append(_finding("error", f"{code_prefix}-chain", f"{label} must include Entry-Transit chain metadata"))
        else:
            if str(chain.get("type") or "").strip() != "entry_transit_private_relay":
                findings.append(_finding("error", f"{code_prefix}-chain-type", f"{label} chain type must be entry_transit_private_relay"))
            if str(chain.get("linkClass") or "").strip() != "entry-transit":
                findings.append(_finding("error", f"{code_prefix}-chain-class", f"{label} chain linkClass must be entry-transit"))
            if str(chain.get("carrier") or "").strip().lower() != "xray-vless-reality":
                findings.append(_finding("error", f"{code_prefix}-chain-carrier", f"{label} chain carrier must be xray-vless-reality"))
            if str(chain.get("preferredOuter") or "").strip().lower() != "reality-xhttp":
                findings.append(_finding("error", f"{code_prefix}-chain-outer", f"{label} chain preferredOuter must be reality-xhttp"))
            if str(chain.get("outerCarrier") or "").strip().lower() != "tcp-reality-xhttp":
                findings.append(_finding("error", f"{code_prefix}-chain-outer-carrier", f"{label} chain outerCarrier must be tcp-reality-xhttp"))
            if str(chain.get("optionalPacketShaping") or "").strip().lower():
                findings.append(_finding("error", f"{code_prefix}-chain-packet-shaping", f"{label} chain packet shaping must be empty"))
            if str(chain.get("managedBy") or "").strip() != "xray-chain":
                findings.append(_finding("error", f"{code_prefix}-chain-managed-by", f"{label} chain must be managed by xray-chain"))
            selected_profiles = chain.get("selectedProfiles")
            if not isinstance(selected_profiles, list) or not {"V1", "V3"}.issubset(
                {str(item).strip() for item in selected_profiles}
            ):
                findings.append(_finding("error", f"{code_prefix}-chain-selected-profiles", f"{label} chain must cover V1/V3"))
            if bool(chain.get("xrayBackhaul", True)):
                findings.append(_finding("error", f"{code_prefix}-chain-xray-backhaul", f"{label} chain must stay outside Xray backhaul"))
    elif chain:
        findings.append(_finding("warning", f"{code_prefix}-chain", f"{label} direct V3 profile should not carry chain metadata"))

    return findings


def _validate_private_wireguard_profile(
    *,
    row: dict[str, Any],
    role_upper: str,
    index: int,
    prefix: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    suffix = _row_string(row, "variant").lower() or f"row-{index}"
    code_prefix = f"{prefix}-wireguard-{suffix}"
    label = f"{role_upper.lower()} WireGuard/WSTunnel {_row_string(row, 'variant') or index}"

    if role_upper != "TRANSIT":
        findings.append(_finding("error", f"{prefix}-wireguard-entry", "Entry private profile handoff must not receive V0 WireGuard/WSTunnel entries"))
    if _row_string(row, "protocol") != "wireguard_wstunnel":
        findings.append(_finding("error", f"{code_prefix}-protocol", f"{label} protocol must be wireguard_wstunnel"))
    if _row_string(row, "variant").upper() != "V0":
        findings.append(_finding("error", f"{code_prefix}-variant", f"{label} must use V0"))
    if _row_string(row, "profile") != "v0-wgws-wireguard":
        findings.append(_finding("error", f"{code_prefix}-profile", f"{label} profile name must be v0-wgws-wireguard"))
    if _row_string(row, "stage") != "direct-transit-public":
        findings.append(_finding("error", f"{code_prefix}-stage", f"{label} stage must be direct-transit-public"))
    if _row_int(row, "port") != 443:
        findings.append(_finding("error", f"{code_prefix}-port", f"{label} must stay on tcp/443"))

    wstunnel = _row_dict(row, "wstunnel")
    parsed_url = urlparse(_row_string(wstunnel, "url"))
    parsed_url_port = 0
    try:
        parsed_url_port = int(parsed_url.port or 0)
    except ValueError:
        parsed_url_port = 0
    wstunnel_path = _row_string(wstunnel, "path")
    if (
        parsed_url.scheme != "wss"
        or not parsed_url.hostname
        or parsed_url_port != 443
        or not parsed_url.path.startswith("/")
    ):
        findings.append(_finding("error", f"{code_prefix}-wstunnel-url", f"{label} WSTunnel url must be wss://host:443/path"))
    if not wstunnel_path.startswith("/") or "://" in wstunnel_path or any(ch.isspace() for ch in wstunnel_path):
        findings.append(_finding("error", f"{code_prefix}-wstunnel-path", f"{label} WSTunnel path must be absolute"))
    elif parsed_url.path and parsed_url.path != wstunnel_path:
        findings.append(_finding("error", f"{code_prefix}-wstunnel-path-match", f"{label} WSTunnel path must match the URL path"))
    local_udp_listen = _row_string(wstunnel, "localUdpListen")
    if not local_udp_listen:
        findings.append(_finding("error", f"{code_prefix}-wstunnel-local-udp", f"{label} WSTunnel localUdpListen is missing"))
    else:
        findings.extend(
            _validate_endpoint(
                raw_value=local_udp_listen,
                code_prefix=f"{code_prefix}-wstunnel-local-udp",
                label=f"{label} WSTunnel localUdpListen",
                loopback_severity="error",
            )
        )
    if not _row_string(wstunnel, "tlsServerName"):
        findings.append(_finding("warning", f"{code_prefix}-wstunnel-sni", f"{label} WSTunnel tlsServerName is missing"))

    wireguard = _row_dict(row, "wireguard")
    for field_name in ("clientPublicKey", "clientPrivateKey", "serverPublicKey", "address"):
        if _looks_placeholder(wireguard.get(field_name)):
            findings.append(_finding("error", f"{code_prefix}-wireguard-{field_name}", f"{label} WireGuard {field_name} is missing or still a placeholder"))
    if _looks_placeholder(wireguard.get("presharedKey")):
        findings.append(_finding("warning", f"{code_prefix}-wireguard-preshared-key", f"{label} WireGuard presharedKey is missing"))
    allowed_ips = wireguard.get("allowedIps")
    if not isinstance(allowed_ips, list) or not [item for item in allowed_ips if str(item or "").strip()]:
        findings.append(_finding("error", f"{code_prefix}-wireguard-allowed-ips", f"{label} WireGuard allowedIps must not be empty"))
    else:
        findings.extend(_validate_wireguard_peer_allowed_ips(values=allowed_ips, code_prefix=code_prefix, label=label))
    mtu = _row_int(wireguard, "mtu")
    if mtu < 1200 or mtu > 1420:
        findings.append(_finding("error", f"{code_prefix}-wireguard-mtu", f"{label} WireGuard mtu must stay in 1200..1420"))
    keepalive = _row_int(wireguard, "persistentKeepalive", default=25)
    if keepalive < 0 or keepalive > 60:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-wireguard-persistent-keepalive",
                f"{label} WireGuard persistentKeepalive must stay in 0..60",
            )
        )

    sync = _row_dict(row, "sync")
    if not sync:
        findings.append(_finding("error", f"{code_prefix}-sync", f"{label} must include a WireGuard live sync contract"))
    else:
        if _row_string(sync, "strategy") != "wg-set":
            findings.append(_finding("error", f"{code_prefix}-sync-strategy", f"{label} sync strategy must be wg-set"))
        if _row_string(sync, "applyMode") != "live-peer-sync":
            findings.append(_finding("error", f"{code_prefix}-sync-apply-mode", f"{label} sync applyMode must be live-peer-sync"))
        if not _row_string(sync, "interface"):
            findings.append(_finding("error", f"{code_prefix}-sync-interface", f"{label} sync interface is required"))
        if not bool(sync.get("removeStalePeers", False)):
            findings.append(_finding("error", f"{code_prefix}-sync-remove-stale", f"{label} sync must remove stale peers without restarting"))
        if bool(sync.get("restartWireGuard", True)):
            findings.append(_finding("error", f"{code_prefix}-sync-restart-wireguard", f"{label} sync must not restart WireGuard"))
        if bool(sync.get("restartWSTunnel", True)):
            findings.append(_finding("error", f"{code_prefix}-sync-restart-wstunnel", f"{label} sync must not restart WSTunnel"))

    findings.extend(_validate_private_local_socks(row=row, code_prefix=code_prefix, label=label))
    findings.extend(_validate_private_obfuscation(row=row, code_prefix=code_prefix, label=label, expected_outer="wstunnel"))
    return findings


def validate_private_profile_state(
    *,
    state: PrivateProfileState,
    contract: dict[str, Any],
    expected_role: str,
    contract_path: str | Path | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    prefix = f"{role_upper.lower() or 'unknown'}-private-profile"

    if state.schema != _PRIVATE_PROFILE_SCHEMA:
        findings.append(_finding("error", f"{prefix}-schema", f"{prefix.replace('-', ' ')} schema must be {_PRIVATE_PROFILE_SCHEMA}"))
    if state.version != 1:
        findings.append(_finding("error", f"{prefix}-version", f"{prefix.replace('-', ' ')} version must be 1"))
    if state.role != role_upper:
        findings.append(_finding("error", f"{prefix}-role", f"{prefix.replace('-', ' ')} role must be {role_upper}, got {state.role or 'missing'}"))
    contract_runtime_profile = _runtime_profile(contract)
    if state.runtime_profile != contract_runtime_profile:
        findings.append(
            _finding(
                "error",
                f"{prefix}-runtime-profile",
                f"{prefix.replace('-', ' ')} runtimeProfile mismatch: state={state.runtime_profile or 'missing'}, contract={contract_runtime_profile or 'missing'}",
            )
        )
    if contract_path is not None and state.runtime_contract_path != str(Path(contract_path)):
        findings.append(_finding("warning", f"{prefix}-contract-path", f"{prefix.replace('-', ' ')} runtimeContractPath diverges from preflight input"))
    if not state.secret_material:
        findings.append(_finding("error", f"{prefix}-secret-material", f"{prefix.replace('-', ' ')} must mark secretMaterial=true"))

    findings.extend(_validate_private_profile_counts(state=state, prefix=prefix))
    findings.extend(_validate_private_profile_transport_profiles(state=state, contract=contract, prefix=prefix))

    for index, row in enumerate(state.shadowsocks2022_shadowtls):
        findings.extend(_validate_private_shadowtls_profile(row=row, role_upper=role_upper, index=index, prefix=prefix))
    for index, row in enumerate(state.wireguard_wstunnel):
        findings.extend(_validate_private_wireguard_profile(row=row, role_upper=role_upper, index=index, prefix=prefix))

    return findings


def validate_private_profile_env(
    *,
    env: PrivateProfileEnv,
    expected_role: str,
    contract: dict[str, Any] | None = None,
    state: PrivateProfileState | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    prefix = f"{role_upper.lower() or 'unknown'}-private-profile-env"

    if env.role != role_upper:
        findings.append(_finding("error", f"{prefix}-role", f"{prefix.replace('-', ' ')} role must be {role_upper}, got {env.role or 'missing'}"))
    if not env.secret_material:
        findings.append(_finding("error", f"{prefix}-secret-material", f"{prefix.replace('-', ' ')} must mark TRACEGATE_PROFILE_SECRET_MATERIAL=true"))

    if contract is not None:
        contract_runtime_profile = _runtime_profile(contract)
        if env.runtime_profile != contract_runtime_profile:
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-contract-runtime-profile",
                    f"{prefix.replace('-', ' ')} runtimeProfile diverges from runtime-contract",
                )
            )

    if state is not None:
        if env.state_json != str(state.path):
            findings.append(_finding("warning", f"{prefix}-state-json", f"{prefix.replace('-', ' ')} points at a different desired-state.json"))
        if env.runtime_profile != state.runtime_profile:
            findings.append(_finding("error", f"{prefix}-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from desired-state.json"))
        if env.total_count != state.total_count:
            findings.append(_finding("error", f"{prefix}-count-total", f"{prefix.replace('-', ' ')} total count diverges from desired-state.json"))
        if env.shadowsocks2022_shadowtls_count != state.shadowsocks2022_shadowtls_count:
            findings.append(_finding("error", f"{prefix}-count-shadowtls", f"{prefix.replace('-', ' ')} ShadowTLS count diverges from desired-state.json"))
        if env.wireguard_wstunnel_count != state.wireguard_wstunnel_count:
            findings.append(_finding("error", f"{prefix}-count-wireguard", f"{prefix.replace('-', ' ')} WireGuard/WSTunnel count diverges from desired-state.json"))
    elif not env.state_json:
        findings.append(_finding("warning", f"{prefix}-state-json", f"{prefix.replace('-', ' ')} does not advertise desired-state.json"))

    if env.total_count != env.shadowsocks2022_shadowtls_count + env.wireguard_wstunnel_count:
        findings.append(_finding("error", f"{prefix}-count-sum", f"{prefix.replace('-', ' ')} total count diverges from protocol counts"))

    return findings


_LINK_CRYPTO_SCHEMA = "tracegate.link-crypto.v1"
_LINK_CRYPTO_CLASSES = {"entry-transit", "router-entry", "router-transit"}
_LINK_CRYPTO_UDP_CLASSES = {"entry-transit-udp", "router-entry-udp", "router-transit-udp"}
_LINK_CRYPTO_REQUIRED_PROFILES = {
    "entry-transit": {"V1", "V3"},
    "router-entry": {"V1", "V3"},
    "router-transit": {"V0", "V1", "V3"},
}
_LINK_CRYPTO_UDP_REQUIRED_PROFILES = {
    "entry-transit-udp": {"V2"},
    "router-entry-udp": {"V2"},
    "router-transit-udp": {"V2"},
}


def _transport_profile_variants(transport_profiles: dict[str, Any]) -> set[str]:
    variants: set[str] = set()
    for profile_name in _string_list(transport_profiles.get("clientNames")):
        prefix = profile_name.split("-", maxsplit=1)[0].strip().upper()
        if len(prefix) > 1 and prefix.startswith("V") and prefix[1:].isdigit():
            variants.add(prefix)
    return variants


def _validate_link_crypto_transport_profiles(
    *,
    state: LinkCryptoState,
    contract: dict[str, Any],
    prefix: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    contract_transport = _transport_profiles_block(contract)
    if not contract_transport:
        return findings

    if not state.transport_profiles:
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-profiles",
                f"{prefix.replace('-', ' ')} must mirror runtime-contract transportProfiles",
            )
        )
        return findings

    state_client_names = _string_list(state.transport_profiles.get("clientNames"))
    contract_client_names = _string_list(contract_transport.get("clientNames"))
    if state_client_names != contract_client_names:
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-client-names",
                f"{prefix.replace('-', ' ')} clientNames diverge from runtime-contract",
            )
        )

    state_local_socks = _row_dict(state.transport_profiles, "localSocks")
    contract_local_socks = _row_dict(contract_transport, "localSocks")
    if state_local_socks != contract_local_socks:
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-local-socks",
                f"{prefix.replace('-', ' ')} localSocks policy diverges from runtime-contract",
            )
        )
    if str(state_local_socks.get("auth") or "").strip().lower() != "required":
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-local-socks-auth",
                f"{prefix.replace('-', ' ')} local SOCKS5 auth must stay required",
            )
        )
    if bool(state_local_socks.get("allowAnonymousLocalhost", False)):
        findings.append(
            _finding(
                "error",
                f"{prefix}-transport-local-socks-anonymous",
                f"{prefix.replace('-', ' ')} must not allow anonymous localhost SOCKS5",
            )
        )

    return findings


def _validate_private_file_ref(
    ref: dict[str, Any],
    *,
    code_prefix: str,
    label: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    if _row_string(ref, "kind") != "file":
        findings.append(_finding("error", f"{code_prefix}-kind", f"{label} must be file-based"))
    if not _row_string(ref, "path"):
        findings.append(_finding("error", f"{code_prefix}-path", f"{label} path is missing"))
    if not bool(ref.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-secret", f"{label} must point at private secret material"))
    return findings


def _validate_link_crypto_outer_carrier(
    *,
    outer_carrier: dict[str, Any],
    code_prefix: str,
    label: str,
    require_enabled: bool,
    side: str = "",
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    enabled = bool(outer_carrier.get("enabled", False))
    if require_enabled and not enabled:
        findings.append(_finding("error", f"{code_prefix}-enabled", f"{label} must enable the WSS outer carrier"))
        return findings
    if not enabled:
        return findings

    mode = _row_string(outer_carrier, "mode").lower()
    protocol = _row_string(outer_carrier, "protocol").lower()
    if mode != "wss":
        findings.append(_finding("error", f"{code_prefix}-mode", f"{label} outer carrier mode must be wss"))
    if protocol != "websocket-tls":
        findings.append(_finding("error", f"{code_prefix}-protocol", f"{label} outer carrier protocol must be websocket-tls"))
    if bool(outer_carrier.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-secret-material", f"{label} outer carrier must not embed secret material"))
    if not _row_string(outer_carrier, "serverName"):
        findings.append(_finding("error", f"{code_prefix}-server-name", f"{label} outer carrier serverName is missing"))
    if _row_int(outer_carrier, "publicPort") != 443:
        findings.append(_finding("error", f"{code_prefix}-public-port", f"{label} outer carrier must stay on tcp/443"))

    public_path = _row_string(outer_carrier, "publicPath")
    if not _is_clean_absolute_http_path(public_path):
        findings.append(_finding("error", f"{code_prefix}-public-path", f"{label} outer carrier publicPath must be a clean absolute HTTP path"))

    parsed_url = urlparse(_row_string(outer_carrier, "url"))
    parsed_port = 0
    try:
        parsed_port = int(parsed_url.port or 0)
    except ValueError:
        parsed_port = 0
    if parsed_url.scheme != "wss" or not parsed_url.hostname or parsed_port != 443 or not parsed_url.path.startswith("/"):
        findings.append(_finding("error", f"{code_prefix}-url", f"{label} outer carrier url must be wss://host:443/path"))
    elif public_path and parsed_url.path != public_path:
        findings.append(_finding("error", f"{code_prefix}-url-path", f"{label} outer carrier url path must match publicPath"))
    if parsed_url.query or parsed_url.fragment:
        findings.append(_finding("error", f"{code_prefix}-url-clean", f"{label} outer carrier url must not include query or fragment"))

    if not bool(outer_carrier.get("verifyTls", False)):
        findings.append(_finding("error", f"{code_prefix}-verify-tls", f"{label} outer carrier must verify TLS"))

    tls_pinning = _row_dict(outer_carrier, "tlsPinning")
    if not bool(tls_pinning.get("required", False)):
        findings.append(_finding("error", f"{code_prefix}-spki-required", f"{label} outer carrier must require SPKI pinning"))
    if _row_string(tls_pinning, "mode") != "spki-sha256":
        findings.append(_finding("error", f"{code_prefix}-spki-mode", f"{label} outer carrier SPKI mode must be spki-sha256"))
    if bool(tls_pinning.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-spki-secret-material", f"{label} outer carrier must not embed SPKI material"))
    findings.extend(
        _validate_private_file_ref(
            _row_dict(tls_pinning, "profileRef"),
            code_prefix=f"{code_prefix}-spki-profile",
            label=f"{label} outer carrier SPKI profileRef",
        )
    )

    admission = _row_dict(outer_carrier, "admission")
    if not bool(admission.get("required", False)):
        findings.append(_finding("error", f"{code_prefix}-admission-required", f"{label} outer carrier must require HMAC admission"))
    if _row_string(admission, "mode") != "hmac-sha256-generation-bound":
        findings.append(_finding("error", f"{code_prefix}-admission-mode", f"{label} outer carrier admission mode must be hmac-sha256-generation-bound"))
    if _row_string(admission, "header") != "Sec-WebSocket-Protocol":
        findings.append(_finding("error", f"{code_prefix}-admission-header", f"{label} outer carrier admission header must stay Sec-WebSocket-Protocol"))
    if not bool(admission.get("rejectUnauthenticated", False)):
        findings.append(_finding("error", f"{code_prefix}-admission-reject", f"{label} outer carrier must reject unauthenticated bridge attempts"))
    if bool(admission.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-admission-secret-material", f"{label} outer carrier must not embed admission secrets"))
    findings.extend(
        _validate_private_file_ref(
            _row_dict(admission, "profileRef"),
            code_prefix=f"{code_prefix}-admission-profile",
            label=f"{label} outer carrier admission profileRef",
        )
    )

    local_endpoint = _row_string(outer_carrier, "localEndpoint")
    if local_endpoint:
        findings.extend(
            _validate_endpoint(
                raw_value=local_endpoint,
                code_prefix=f"{code_prefix}-local-endpoint",
                label=f"{label} outer carrier localEndpoint",
                require_loopback=True,
                loopback_severity="error",
            )
        )
    elif side:
        findings.append(_finding("error", f"{code_prefix}-local-endpoint", f"{label} outer carrier localEndpoint is missing"))

    endpoints = _row_dict(outer_carrier, "endpoints")
    for field_name, field_label in (
        ("entryClientListen", "entryClientListen"),
        ("transitServerListen", "transitServerListen"),
        ("transitTarget", "transitTarget"),
    ):
        endpoint_value = _row_string(outer_carrier, field_name) or _row_string(endpoints, field_name)
        if not endpoint_value:
            continue
        findings.extend(
            _validate_endpoint(
                raw_value=endpoint_value,
                code_prefix=f"{code_prefix}-{field_label}",
                label=f"{label} outer carrier {field_label}",
                require_loopback=True,
                loopback_severity="error",
            )
        )

    return findings


def _validate_link_crypto_tcp_dpi_resistance(
    *,
    dpi: dict[str, Any],
    zapret2: dict[str, Any],
    outer_carrier: dict[str, Any],
    code_prefix: str,
    label: str,
    require_outer_carrier: bool,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    if not dpi:
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance", f"{label} TCP DPI resistance policy is missing"))
        return findings
    if not bool(dpi.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-enabled", f"{label} TCP DPI resistance must stay enabled"))
    expected_mode = "mieru-wss-spki-hmac-zapret2-scoped" if require_outer_carrier else "mieru-zapret2-scoped"
    if _row_string(dpi, "mode") != expected_mode:
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-mode", f"{label} TCP DPI resistance mode must stay {expected_mode}"))

    required_layers = set(_string_list(dpi.get("requiredLayers")))
    required = {
        "mieru-private-auth",
        "scoped-zapret2",
        "private-zapret2-profile",
        "loopback-only",
        "generation-drain",
        "no-direct-backhaul",
    }
    if require_outer_carrier:
        required.update({"outer-wss-tls", "spki-sha256-pin", "hmac-admission"})
    missing_layers = sorted(required - required_layers)
    if missing_layers:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-dpi-resistance-layers",
                f"{label} TCP DPI resistance missing required layers: {', '.join(missing_layers)}",
            )
        )

    dpi_outer = _row_dict(dpi, "outerCarrier")
    if bool(dpi_outer.get("required", False)) != require_outer_carrier:
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-outer-required", f"{label} outerCarrier.required diverges from link class"))
    if require_outer_carrier:
        if not bool(dpi_outer.get("spkiPinningRequired", False)):
            findings.append(_finding("error", f"{code_prefix}-dpi-resistance-spki", f"{label} must require SPKI pinning"))
        if not bool(dpi_outer.get("hmacAdmissionRequired", False)):
            findings.append(_finding("error", f"{code_prefix}-dpi-resistance-admission", f"{label} must require HMAC admission"))
        if not bool(outer_carrier.get("enabled", False)):
            findings.append(_finding("error", f"{code_prefix}-dpi-resistance-outer-carrier", f"{label} must keep outer WSS carrier enabled"))

    if not bool(zapret2.get("required", False)):
        findings.append(_finding("error", f"{code_prefix}-zapret2-required", f"{label} zapret2 must be required"))
    if not bool(zapret2.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-zapret2-enabled", f"{label} zapret2 must be enabled for TCP DPI resistance"))
    if bool(zapret2.get("hostWideInterception", False)):
        findings.append(_finding("error", f"{code_prefix}-zapret2-host-wide", f"{label} zapret2 must not use host-wide interception"))
    if bool(zapret2.get("nfqueue", False)):
        findings.append(_finding("error", f"{code_prefix}-zapret2-nfqueue", f"{label} zapret2 must not use broad NFQUEUE"))
    if _row_string(zapret2, "packetShaping") != "zapret2-scoped":
        findings.append(_finding("error", f"{code_prefix}-zapret2-packet-shaping", f"{label} zapret2 packetShaping must be zapret2-scoped"))
    if _row_string(zapret2, "applyMode") != "marked-flow-only":
        findings.append(_finding("error", f"{code_prefix}-zapret2-apply-mode", f"{label} zapret2 applyMode must be marked-flow-only"))
    findings.extend(
        _validate_private_file_ref(
            _row_dict(zapret2, "profileRef"),
            code_prefix=f"{code_prefix}-zapret2-profile",
            label=f"{label} zapret2 profileRef",
        )
    )

    dpi_zapret = _row_dict(dpi, "zapret2")
    if not bool(dpi_zapret.get("required", False)):
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-zapret-required", f"{label} DPI policy must require zapret2"))
    if not bool(dpi_zapret.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-zapret-enabled", f"{label} DPI policy must enable zapret2"))
    if _row_string(dpi_zapret, "packetShaping") != "zapret2-scoped":
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-zapret-shaping", f"{label} DPI zapret2 packetShaping must be zapret2-scoped"))
    findings.extend(
        _validate_private_file_ref(
            _row_dict(dpi_zapret, "profileRef"),
            code_prefix=f"{code_prefix}-dpi-resistance-zapret-profile",
            label=f"{label} DPI zapret2 profileRef",
        )
    )

    traffic_shape = _row_dict(dpi, "trafficShaping")
    if not bool(traffic_shape.get("required", False)):
        findings.append(_finding("error", f"{code_prefix}-traffic-shaping-required", f"{label} TCP traffic shaping must be required"))
    if _row_string(traffic_shape, "strategy") != "private-zapret2-profile":
        findings.append(_finding("error", f"{code_prefix}-traffic-shaping-strategy", f"{label} TCP traffic shaping must use private-zapret2-profile"))
    if _row_string(traffic_shape, "scope") != "marked-flow-only":
        findings.append(_finding("error", f"{code_prefix}-traffic-shaping-scope", f"{label} TCP traffic shaping must stay marked-flow-only"))
    if bool(traffic_shape.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-traffic-shaping-secret-material", f"{label} TCP traffic shaping must not embed private material"))
    findings.extend(
        _validate_private_file_ref(
            _row_dict(traffic_shape, "profileRef"),
            code_prefix=f"{code_prefix}-traffic-shaping-profile",
            label=f"{label} TCP traffic shaping profileRef",
        )
    )

    promotion = _row_dict(dpi, "promotionPreflight")
    if not bool(promotion.get("required", False)):
        findings.append(_finding("error", f"{code_prefix}-promotion-preflight-required", f"{label} promotion preflight must be required"))
    if not bool(promotion.get("failClosed", False)):
        findings.append(_finding("error", f"{code_prefix}-promotion-preflight-fail-closed", f"{label} promotion preflight must fail closed"))
    checks = set(_string_list(promotion.get("checks")))
    required_checks = {"mieru-private-auth", "zapret2-scoped-profile", "no-direct-backhaul"}
    if require_outer_carrier:
        required_checks.update({"spki-pin", "hmac-admission"})
    missing_checks = sorted(required_checks - checks)
    if missing_checks:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-promotion-preflight-checks",
                f"{label} promotion preflight missing checks: {', '.join(missing_checks)}",
            )
        )
    if bool(promotion.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-promotion-preflight-secret-material", f"{label} promotion preflight must not embed private material"))
    findings.extend(
        _validate_private_file_ref(
            _row_dict(promotion, "profileRef"),
            code_prefix=f"{code_prefix}-promotion-preflight-profile",
            label=f"{label} promotion preflight profileRef",
        )
    )
    return findings


def _validate_link_crypto_contract_alignment(
    *,
    state: LinkCryptoState,
    contract: dict[str, Any],
    role_upper: str,
    prefix: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    link_crypto = _link_crypto_contract_block(contract)
    role_link_crypto = _link_crypto_contract_block_for_role(contract, role_upper=role_upper)
    if not link_crypto and not role_link_crypto:
        return findings

    state_classes = [_row_string(row, "class") for row in state.links if _row_string(row, "class")]
    contract_classes = _string_list(role_link_crypto.get("classes"))
    if contract_classes and state_classes != contract_classes:
        findings.append(
            _finding(
                "error",
                f"{prefix}-contract-classes",
                f"{prefix.replace('-', ' ')} link classes diverge from runtime-contract linkCrypto.classes",
            )
        )

    contract_enabled = bool(role_link_crypto.get("enabled", link_crypto.get("enabled", False)))
    if contract_enabled != bool(state.total_count or state.udp_total_count):
        findings.append(
            _finding(
                "error",
                f"{prefix}-contract-enabled",
                f"{prefix.replace('-', ' ')} enabled state diverges from runtime-contract linkCrypto.enabled",
            )
        )

    counts = _row_dict(role_link_crypto, "counts")
    expected_counts = {
        "total": _row_int(counts, "total"),
        "entryTransit": _row_int(counts, "entryTransit"),
        "routerEntry": _row_int(counts, "routerEntry"),
        "routerTransit": _row_int(counts, "routerTransit"),
    }
    actual_counts = {
        "total": state.total_count,
        "entryTransit": state.entry_transit_count,
        "routerEntry": state.router_entry_count,
        "routerTransit": state.router_transit_count,
    }
    if counts and expected_counts != actual_counts:
        findings.append(
            _finding(
                "error",
                f"{prefix}-contract-counts",
                f"{prefix.replace('-', ' ')} link counts diverge from runtime-contract linkCrypto.counts",
            )
        )

    carrier = _row_string(link_crypto, "carrier").lower()
    if carrier and carrier != "mieru":
        findings.append(
            _finding(
                "error",
                f"{prefix}-contract-carrier",
                f"{prefix.replace('-', ' ')} carrier must stay mieru in runtime-contract",
            )
        )
    manager = _row_string(link_crypto, "manager")
    if manager and manager != "link-crypto":
        findings.append(
            _finding(
                "error",
                f"{prefix}-contract-manager",
                f"{prefix.replace('-', ' ')} manager must stay link-crypto in runtime-contract",
            )
        )
    profile_source = _row_string(link_crypto, "profileSource")
    if profile_source and profile_source not in {"private-file-reference", "external-secret-file-reference"}:
        findings.append(
            _finding(
                "error",
                f"{prefix}-contract-profile-source",
                f"{prefix.replace('-', ' ')} profileSource must stay a private/external file reference",
            )
        )
    if bool(link_crypto.get("secretMaterial", False)):
        findings.append(
            _finding(
                "error",
                f"{prefix}-contract-secret-material",
                f"{prefix.replace('-', ' ')} runtime-contract must not embed link-crypto secret material",
            )
        )
    if bool(link_crypto.get("xrayBackhaul", False)):
        findings.append(
            _finding(
                "error",
                f"{prefix}-contract-xray-backhaul",
                f"{prefix.replace('-', ' ')} runtime-contract must keep link-crypto outside Xray backhaul",
            )
        )

    expected_generation = _row_int(role_link_crypto, "generation") or _row_int(link_crypto, "generation")
    expected_remote_port = _row_int(role_link_crypto, "remotePort") or _row_int(link_crypto, "remotePort")
    expected_zapret = _row_dict(link_crypto, "zapret2")
    expected_zapret_enabled = bool(expected_zapret.get("enabled", False))
    expected_outer_carrier = _row_dict(link_crypto, "outerCarrier")
    expected_tcp_dpi = _row_dict(link_crypto, "dpiResistance")
    if expected_outer_carrier:
        findings.extend(
            _validate_link_crypto_outer_carrier(
                outer_carrier=expected_outer_carrier,
                code_prefix=f"{prefix}-contract-outer-carrier",
                label=f"{prefix.replace('-', ' ')} runtime-contract outer carrier",
                require_enabled=state.entry_transit_count > 0,
            )
        )
    if expected_zapret:
        if "hostWideInterception" in expected_zapret and bool(expected_zapret.get("hostWideInterception", False)):
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-contract-zapret2-host-wide",
                    f"{prefix.replace('-', ' ')} runtime-contract must not allow host-wide zapret2 interception",
                )
            )
        if "nfqueue" in expected_zapret and bool(expected_zapret.get("nfqueue", False)):
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-contract-zapret2-nfqueue",
                    f"{prefix.replace('-', ' ')} runtime-contract must not allow broad NFQUEUE",
                )
            )
        packet_shaping = str(expected_zapret.get("packetShaping") or "").strip().lower()
        if packet_shaping and packet_shaping != "zapret2-scoped":
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-contract-zapret2-packet-shaping",
                    f"{prefix.replace('-', ' ')} runtime-contract zapret2 packetShaping must be zapret2-scoped",
                )
            )
        apply_mode = str(expected_zapret.get("applyMode") or "").strip().lower()
        if apply_mode and apply_mode != "marked-flow-only":
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-contract-zapret2-apply-mode",
                    f"{prefix.replace('-', ' ')} runtime-contract zapret2 applyMode must be marked-flow-only",
                )
            )
        if "failOpen" in expected_zapret and not bool(expected_zapret.get("failOpen", False)):
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-contract-zapret2-fail-open",
                    f"{prefix.replace('-', ' ')} runtime-contract zapret2 policy must fail open",
                )
            )

    if expected_tcp_dpi or state.total_count:
        findings.extend(
            _validate_link_crypto_tcp_dpi_resistance(
                dpi=expected_tcp_dpi,
                zapret2=expected_zapret,
                outer_carrier=expected_outer_carrier,
                code_prefix=f"{prefix}-contract",
                label=f"{prefix.replace('-', ' ')} runtime-contract",
                require_outer_carrier=state.entry_transit_count > 0,
            )
        )

    expected_local_ports = _row_dict(role_link_crypto, "localPorts") or _row_dict(link_crypto, "localPorts")
    expected_selected_profiles = _row_dict(role_link_crypto, "selectedProfiles") or _row_dict(link_crypto, "selectedProfiles")
    for row in state.links:
        link_class = _row_string(row, "class") or "row"
        code_prefix = f"{prefix}-{link_class}"
        if expected_generation > 0 and _row_int(row, "generation") != expected_generation:
            findings.append(
                _finding(
                    "error",
                    f"{code_prefix}-contract-generation",
                    f"{prefix.replace('-', ' ')} {link_class} generation diverges from runtime-contract",
                )
            )
        if expected_remote_port > 0:
            remote = _row_dict(row, "remote")
            try:
                _host, remote_port = _parse_endpoint(_row_string(remote, "endpoint"))
            except ValueError:
                remote_port = 0
            if remote_port != expected_remote_port:
                findings.append(
                    _finding(
                        "error",
                        f"{code_prefix}-contract-remote-port",
                        f"{prefix.replace('-', ' ')} {link_class} remote port diverges from runtime-contract",
                    )
                )
        if expected_zapret:
            zapret2 = _row_dict(row, "zapret2")
            if bool(zapret2.get("enabled", False)) != expected_zapret_enabled:
                findings.append(
                    _finding(
                        "error",
                        f"{code_prefix}-contract-zapret2-enabled",
                        f"{prefix.replace('-', ' ')} {link_class} zapret2 enabled state diverges from runtime-contract",
                    )
                )
        if expected_outer_carrier and link_class == "entry-transit":
            outer_carrier = _row_dict(row, "outerCarrier")
            for field_name, code_suffix in (
                ("enabled", "enabled"),
                ("mode", "mode"),
                ("serverName", "server-name"),
                ("publicPort", "public-port"),
                ("publicPath", "public-path"),
                ("verifyTls", "verify-tls"),
            ):
                if outer_carrier.get(field_name) != expected_outer_carrier.get(field_name):
                    findings.append(
                        _finding(
                            "error",
                            f"{code_prefix}-contract-outer-carrier-{code_suffix}",
                            f"{prefix.replace('-', ' ')} {link_class} outer carrier diverges from runtime-contract",
                        )
                    )
        expected_local_port = _row_int(expected_local_ports, link_class)
        if expected_local_port > 0:
            local = _row_dict(row, "local")
            try:
                _host, local_port = _parse_endpoint(_row_string(local, "listen"))
            except ValueError:
                local_port = 0
            if local_port != expected_local_port:
                findings.append(
                    _finding(
                        "error",
                        f"{code_prefix}-contract-local-port",
                        f"{prefix.replace('-', ' ')} {link_class} local port diverges from runtime-contract",
                    )
                )
        expected_profiles = _string_list(expected_selected_profiles.get(link_class))
        if expected_profiles:
            actual_profiles = _string_list(row.get("selectedProfiles"))
            if actual_profiles != expected_profiles:
                findings.append(
                    _finding(
                        "error",
                        f"{code_prefix}-contract-selected-profiles",
                        f"{prefix.replace('-', ' ')} {link_class} selectedProfiles diverge from runtime-contract",
                    )
                )

    udp_contract = _row_dict(link_crypto, "udp")
    role_udp_contract = _row_dict(_row_dict(udp_contract, "roles"), role_upper.lower())
    if udp_contract or role_udp_contract:
        udp_enabled = bool(role_udp_contract.get("enabled", udp_contract.get("enabled", False)))
        if udp_enabled != bool(state.udp_total_count):
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-udp-contract-enabled",
                    f"{prefix.replace('-', ' ')} UDP enabled state diverges from runtime-contract linkCrypto.udp",
                )
            )
        if _row_string(udp_contract, "carrier").lower() not in {"", "hysteria2"}:
            findings.append(_finding("error", f"{prefix}-udp-contract-carrier", f"{prefix.replace('-', ' ')} UDP carrier must stay hysteria2"))
        if _row_string(udp_contract, "transport").lower() not in {"", "udp-quic"}:
            findings.append(_finding("error", f"{prefix}-udp-contract-transport", f"{prefix.replace('-', ' ')} UDP transport must stay udp-quic"))
        if _row_string(udp_contract, "manager") not in {"", "link-crypto"}:
            findings.append(_finding("error", f"{prefix}-udp-contract-manager", f"{prefix.replace('-', ' ')} UDP manager must stay link-crypto"))
        if bool(udp_contract.get("secretMaterial", False)):
            findings.append(_finding("error", f"{prefix}-udp-contract-secret-material", f"{prefix.replace('-', ' ')} UDP runtime-contract must not embed secret material"))
        if bool(udp_contract.get("xrayBackhaul", False)):
            findings.append(_finding("error", f"{prefix}-udp-contract-xray-backhaul", f"{prefix.replace('-', ' ')} UDP runtime-contract must stay outside Xray backhaul"))
        if _row_int(udp_contract, "remotePort") not in {0, TRACEGATE_PUBLIC_UDP_PORT}:
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-udp-contract-remote-port",
                    f"{prefix.replace('-', ' ')} UDP remotePort must stay {TRACEGATE_PUBLIC_UDP_PORT}",
                )
            )
        udp_obfs = _row_dict(udp_contract, "obfs")
        if udp_obfs and (_row_string(udp_obfs, "type").lower() != "salamander" or not bool(udp_obfs.get("required", False))):
            findings.append(_finding("error", f"{prefix}-udp-contract-salamander", f"{prefix.replace('-', ' ')} UDP contract must require Salamander"))
        udp_paired_obfs = _row_dict(udp_contract, "pairedObfs")
        if bool(udp_paired_obfs.get("enabled", False)):
            if _row_string(udp_paired_obfs, "backend") != "udp2raw":
                findings.append(_finding("error", f"{prefix}-udp-contract-paired-obfs-backend", f"{prefix.replace('-', ' ')} UDP pairedObfs backend must stay udp2raw"))
            if not bool(udp_paired_obfs.get("requiresBothSides", False)):
                findings.append(_finding("error", f"{prefix}-udp-contract-paired-obfs", f"{prefix.replace('-', ' ')} UDP pairedObfs must require both sides"))
            if not bool(udp_paired_obfs.get("failClosed", False)):
                findings.append(_finding("error", f"{prefix}-udp-contract-paired-obfs-fail-closed", f"{prefix.replace('-', ' ')} UDP pairedObfs must fail closed"))
            if not bool(udp_paired_obfs.get("noHostWideInterception", False)):
                findings.append(_finding("error", f"{prefix}-udp-contract-paired-obfs-host-wide", f"{prefix.replace('-', ' ')} UDP pairedObfs must not use host-wide interception"))
            if not bool(udp_paired_obfs.get("noNfqueue", False)):
                findings.append(_finding("error", f"{prefix}-udp-contract-paired-obfs-nfqueue", f"{prefix.replace('-', ' ')} UDP pairedObfs must not use broad NFQUEUE"))
        if udp_enabled or state.udp_total_count:
            findings.extend(
                _validate_link_crypto_udp_hardening(
                    hardening=_row_dict(udp_contract, "hardening"),
                    code_prefix=f"{prefix}-udp-contract",
                    label=f"{prefix.replace('-', ' ')} UDP runtime-contract",
                )
            )
            findings.extend(
                _validate_link_crypto_udp_dpi_resistance(
                    dpi=_row_dict(udp_contract, "dpiResistance"),
                    code_prefix=f"{prefix}-udp-contract",
                    label=f"{prefix.replace('-', ' ')} UDP runtime-contract",
                )
            )

        udp_state_classes = [_row_string(row, "class") for row in state.udp_links if _row_string(row, "class")]
        udp_contract_classes = _string_list(role_udp_contract.get("classes") or udp_contract.get("classes"))
        if udp_contract_classes and udp_state_classes != udp_contract_classes:
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-udp-contract-classes",
                    f"{prefix.replace('-', ' ')} UDP link classes diverge from runtime-contract linkCrypto.udp.classes",
                )
            )

        udp_counts = _row_dict(role_udp_contract, "counts") or _row_dict(udp_contract, "counts")
        expected_udp_counts = {
            "total": _row_int(udp_counts, "total"),
            "entryTransitUdp": _row_int(udp_counts, "entryTransitUdp"),
            "routerEntryUdp": _row_int(udp_counts, "routerEntryUdp"),
            "routerTransitUdp": _row_int(udp_counts, "routerTransitUdp"),
        }
        actual_udp_counts = {
            "total": state.udp_total_count,
            "entryTransitUdp": state.entry_transit_udp_count,
            "routerEntryUdp": state.router_entry_udp_count,
            "routerTransitUdp": state.router_transit_udp_count,
        }
        if udp_counts and expected_udp_counts != actual_udp_counts:
            findings.append(
                _finding(
                    "error",
                    f"{prefix}-udp-contract-counts",
                    f"{prefix.replace('-', ' ')} UDP link counts diverge from runtime-contract linkCrypto.udp.counts",
                )
            )

        expected_udp_local_ports = _row_dict(role_udp_contract, "localPorts") or _row_dict(udp_contract, "localPorts")
        expected_udp_profiles = _row_dict(role_udp_contract, "selectedProfiles") or _row_dict(udp_contract, "selectedProfiles")
        for row in state.udp_links:
            link_class = _row_string(row, "class") or "udp-row"
            code_prefix = f"{prefix}-{link_class}"
            if _row_int(udp_contract, "remotePort") > 0:
                remote = _row_dict(row, "remote")
                try:
                    _host, remote_port = _parse_endpoint(_row_string(remote, "endpoint"))
                except ValueError:
                    remote_port = 0
                if remote_port != _row_int(udp_contract, "remotePort"):
                    findings.append(
                        _finding(
                            "error",
                            f"{code_prefix}-udp-contract-remote-port",
                            f"{prefix.replace('-', ' ')} {link_class} remote port diverges from runtime-contract",
                        )
                    )
            expected_local_port = _row_int(expected_udp_local_ports, link_class)
            if expected_local_port > 0:
                local = _row_dict(row, "local")
                try:
                    _host, local_port = _parse_endpoint(_row_string(local, "listen"))
                except ValueError:
                    local_port = 0
                if local_port != expected_local_port:
                    findings.append(
                        _finding(
                            "error",
                            f"{code_prefix}-udp-contract-local-port",
                            f"{prefix.replace('-', ' ')} {link_class} local port diverges from runtime-contract",
                        )
                    )
            expected_profiles = _string_list(expected_udp_profiles.get(link_class))
            if expected_profiles and _string_list(row.get("selectedProfiles")) != expected_profiles:
                findings.append(
                    _finding(
                        "error",
                        f"{code_prefix}-udp-contract-selected-profiles",
                        f"{prefix.replace('-', ' ')} {link_class} selectedProfiles diverge from runtime-contract",
                    )
                )

    return findings


def _validate_link_crypto_counts(
    *,
    state: LinkCryptoState,
    prefix: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    by_class = {link_class: len([row for row in state.links if _row_string(row, "class") == link_class]) for link_class in _LINK_CRYPTO_CLASSES}
    udp_by_class = {
        link_class: len([row for row in state.udp_links if _row_string(row, "class") == link_class])
        for link_class in _LINK_CRYPTO_UDP_CLASSES
    }
    if state.total_count != len(state.links):
        findings.append(_finding("error", f"{prefix}-count-total", f"{prefix.replace('-', ' ')} total count diverges from links"))
    if state.entry_transit_count != by_class["entry-transit"]:
        findings.append(_finding("error", f"{prefix}-count-entry-transit", f"{prefix.replace('-', ' ')} entry-transit count diverges from links"))
    if state.router_entry_count != by_class["router-entry"]:
        findings.append(_finding("error", f"{prefix}-count-router-entry", f"{prefix.replace('-', ' ')} router-entry count diverges from links"))
    if state.router_transit_count != by_class["router-transit"]:
        findings.append(_finding("error", f"{prefix}-count-router-transit", f"{prefix.replace('-', ' ')} router-transit count diverges from links"))
    if state.udp_total_count != len(state.udp_links):
        findings.append(_finding("error", f"{prefix}-udp-count-total", f"{prefix.replace('-', ' ')} UDP total count diverges from udpLinks"))
    if state.entry_transit_udp_count != udp_by_class["entry-transit-udp"]:
        findings.append(_finding("error", f"{prefix}-udp-count-entry-transit", f"{prefix.replace('-', ' ')} entry-transit-udp count diverges from udpLinks"))
    if state.router_entry_udp_count != udp_by_class["router-entry-udp"]:
        findings.append(_finding("error", f"{prefix}-udp-count-router-entry", f"{prefix.replace('-', ' ')} router-entry-udp count diverges from udpLinks"))
    if state.router_transit_udp_count != udp_by_class["router-transit-udp"]:
        findings.append(_finding("error", f"{prefix}-udp-count-router-transit", f"{prefix.replace('-', ' ')} router-transit-udp count diverges from udpLinks"))
    return findings


def _validate_link_crypto_row(
    *,
    row: dict[str, Any],
    role_upper: str,
    index: int,
    prefix: str,
    known_profile_variants: set[str],
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    link_class = _row_string(row, "class")
    suffix = link_class or f"row-{index}"
    code_prefix = f"{prefix}-{suffix}"
    label = f"{role_upper.lower()} link-crypto {link_class or index}"

    if link_class not in _LINK_CRYPTO_CLASSES:
        findings.append(_finding("error", f"{code_prefix}-class", f"{label} has unsupported class"))

    allowed_by_role = {
        "ENTRY": {"entry-transit", "router-entry"},
        "TRANSIT": {"entry-transit", "router-transit"},
    }.get(role_upper, set())
    if link_class and link_class not in allowed_by_role:
        findings.append(_finding("error", f"{code_prefix}-role-class", f"{label} is not valid for {role_upper}"))

    expected_side = ""
    if link_class == "entry-transit":
        expected_side = "client" if role_upper == "ENTRY" else "server"
    elif link_class in {"router-entry", "router-transit"}:
        expected_side = "server"
    side = _row_string(row, "side").lower()
    if expected_side and side != expected_side:
        findings.append(_finding("error", f"{code_prefix}-side", f"{label} side must be {expected_side}"))

    if not bool(row.get("enabled", False)):
        findings.append(_finding("warning", f"{code_prefix}-disabled", f"{label} is disabled"))
    if _row_string(row, "carrier").lower() != "mieru":
        findings.append(_finding("error", f"{code_prefix}-carrier", f"{label} carrier must be mieru"))
    if _row_string(row, "managedBy") != "link-crypto":
        findings.append(_finding("error", f"{code_prefix}-managed-by", f"{label} must be managed by link-crypto"))
    if bool(row.get("xrayBackhaul", True)):
        findings.append(_finding("error", f"{code_prefix}-xray-backhaul", f"{label} must stay outside Xray backhaul"))
    if _row_int(row, "generation") < 1:
        findings.append(_finding("error", f"{code_prefix}-generation", f"{label} generation must be positive"))

    profile_ref = _row_dict(row, "profileRef")
    if _row_string(profile_ref, "kind") != "file":
        findings.append(_finding("error", f"{code_prefix}-profile-ref-kind", f"{label} profileRef must be file-based"))
    if not _row_string(profile_ref, "path"):
        findings.append(_finding("error", f"{code_prefix}-profile-ref-path", f"{label} profileRef path is missing"))
    if not bool(profile_ref.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-profile-ref-secret", f"{label} profileRef must point at private secret material"))

    local = _row_dict(row, "local")
    findings.extend(
        _validate_endpoint(
            raw_value=_row_string(local, "listen"),
            code_prefix=f"{code_prefix}-local-listen",
            label=f"{label} local listen endpoint",
            require_loopback=True,
            loopback_severity="error",
        )
    )
    auth = _row_dict(local, "auth")
    if not bool(auth.get("required", False)):
        findings.append(_finding("error", f"{code_prefix}-local-auth", f"{label} local Mieru/SOCKS ingress auth must be required"))
    if _row_string(auth, "mode") != "private-profile":
        findings.append(_finding("error", f"{code_prefix}-local-auth-mode", f"{label} local Mieru/SOCKS auth must use private-profile mode"))

    remote = _row_dict(row, "remote")
    if not _row_string(remote, "role"):
        findings.append(_finding("error", f"{code_prefix}-remote-role", f"{label} remote role is missing"))
    findings.extend(
        _validate_endpoint(
            raw_value=_row_string(remote, "endpoint"),
            code_prefix=f"{code_prefix}-remote-endpoint",
            label=f"{label} remote endpoint",
            require_loopback=False,
        )
    )

    findings.extend(
        _validate_link_crypto_outer_carrier(
            outer_carrier=_row_dict(row, "outerCarrier"),
            code_prefix=f"{code_prefix}-outer-carrier",
            label=f"{label} outer carrier",
            require_enabled=link_class == "entry-transit",
            side=side,
        )
    )

    selected_profiles = row.get("selectedProfiles")
    if not isinstance(selected_profiles, list) or not [item for item in selected_profiles if str(item or "").strip()]:
        findings.append(_finding("error", f"{code_prefix}-selected-profiles", f"{label} must declare selected Tracegate profiles"))
    else:
        selected_profile_set = {str(item).strip().upper() for item in selected_profiles if str(item or "").strip()}
        if known_profile_variants:
            unknown_profiles = sorted(selected_profile_set - known_profile_variants)
            if unknown_profiles:
                findings.append(
                    _finding(
                        "error",
                        f"{code_prefix}-selected-profiles-contract",
                        f"{label} selectedProfiles are not present in runtime-contract: {', '.join(unknown_profiles)}",
                    )
                )
        required_profiles = _LINK_CRYPTO_REQUIRED_PROFILES.get(link_class, set())
        if required_profiles and selected_profile_set != required_profiles:
            findings.append(
                _finding(
                    "error",
                    f"{code_prefix}-selected-profiles",
                    f"{label} must select exactly {'/'.join(sorted(required_profiles))} profiles",
                )
            )

    zapret2 = _row_dict(row, "zapret2")
    if bool(zapret2.get("hostWideInterception", True)):
        findings.append(_finding("error", f"{code_prefix}-zapret2-host-wide", f"{label} must not enable host-wide interception"))
    if bool(zapret2.get("nfqueue", True)):
        findings.append(_finding("error", f"{code_prefix}-zapret2-nfqueue", f"{label} must not enable broad NFQUEUE"))
    if str(zapret2.get("packetShaping") or "").strip().lower() != "zapret2-scoped":
        findings.append(_finding("error", f"{code_prefix}-zapret2-packet-shaping", f"{label} must keep zapret2-scoped packet shaping"))
    if str(zapret2.get("applyMode") or "").strip().lower() != "marked-flow-only":
        findings.append(_finding("error", f"{code_prefix}-zapret2-apply-mode", f"{label} zapret2 applyMode must be marked-flow-only"))
    if bool(zapret2.get("enabled", False)) and not _row_string(zapret2, "profileFile"):
        findings.append(_finding("error", f"{code_prefix}-zapret2-profile-file", f"{label} enabled zapret2 needs profileFile"))
    if not bool(zapret2.get("failOpen", False)):
        findings.append(_finding("error", f"{code_prefix}-zapret2-fail-open", f"{label} zapret2 layer must fail open"))
    findings.extend(
        _validate_link_crypto_tcp_dpi_resistance(
            dpi=_row_dict(row, "dpiResistance"),
            zapret2=zapret2,
            outer_carrier=_row_dict(row, "outerCarrier"),
            code_prefix=code_prefix,
            label=label,
            require_outer_carrier=link_class == "entry-transit",
        )
    )

    rotation = _row_dict(row, "rotation")
    if str(rotation.get("strategy") or "").strip().lower() != "generation-drain":
        findings.append(_finding("error", f"{code_prefix}-rotation", f"{label} rotation strategy must be generation-drain"))
    if bool(rotation.get("restartExisting", True)):
        findings.append(_finding("error", f"{code_prefix}-restart-existing", f"{label} must not restart existing link generation"))

    stability = _row_dict(row, "stability")
    if not bool(stability.get("failOpen", False)):
        findings.append(_finding("error", f"{code_prefix}-fail-open", f"{label} must fail open"))
    if bool(stability.get("dropUnrelatedTraffic", True)):
        findings.append(_finding("error", f"{code_prefix}-drop-unrelated", f"{label} must not drop unrelated traffic"))

    return findings


def _validate_link_crypto_udp_hardening(
    *,
    hardening: dict[str, Any],
    code_prefix: str,
    label: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []

    if not hardening:
        findings.append(_finding("error", f"{code_prefix}-hardening", f"{label} hardening policy is missing"))
        return findings
    if not bool(hardening.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-hardening-enabled", f"{label} hardening must stay enabled"))
    if not bool(hardening.get("failClosed", False)):
        findings.append(_finding("error", f"{code_prefix}-hardening-fail-closed", f"{label} must fail closed"))
    if not bool(hardening.get("requirePrivateAuth", False)):
        findings.append(_finding("error", f"{code_prefix}-hardening-private-auth", f"{label} must require private auth"))
    if not bool(hardening.get("rejectAnonymous", False)):
        findings.append(_finding("error", f"{code_prefix}-hardening-reject-anonymous", f"{label} must reject anonymous UDP sessions"))

    anti_replay = _row_dict(hardening, "antiReplay")
    if not bool(anti_replay.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-hardening-anti-replay", f"{label} antiReplay must stay enabled"))
    if _row_int(anti_replay, "windowPackets") < 1024:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-hardening-replay-window",
                f"{label} antiReplay windowPackets must be at least 1024",
            )
        )

    anti_amplification = _row_dict(hardening, "antiAmplification")
    if not bool(anti_amplification.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-hardening-anti-amplification", f"{label} antiAmplification must stay enabled"))
    max_unvalidated_bytes = _row_int(anti_amplification, "maxUnvalidatedBytes")
    if max_unvalidated_bytes < 1 or max_unvalidated_bytes > 4096:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-hardening-unvalidated-bytes",
                f"{label} antiAmplification maxUnvalidatedBytes must stay in 1..4096",
            )
        )

    rate_limit = _row_dict(hardening, "rateLimit")
    if not bool(rate_limit.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-hardening-rate-limit", f"{label} rateLimit must stay enabled"))
    handshake_per_minute = _row_int(rate_limit, "handshakePerMinute")
    new_session_per_minute = _row_int(rate_limit, "newSessionPerMinute")
    if handshake_per_minute < 1 or handshake_per_minute > 600:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-hardening-handshake-rate",
                f"{label} handshakePerMinute must stay in 1..600",
            )
        )
    if new_session_per_minute < 1 or new_session_per_minute > handshake_per_minute:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-hardening-session-rate",
                f"{label} newSessionPerMinute must stay in 1..handshakePerMinute",
            )
        )

    mtu = _row_dict(hardening, "mtu")
    if _row_string(mtu, "mode") != "clamp":
        findings.append(_finding("error", f"{code_prefix}-hardening-mtu-mode", f"{label} MTU mode must stay clamp"))
    max_packet_size = _row_int(mtu, "maxPacketSize")
    if max_packet_size < 1000 or max_packet_size > 1350:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-hardening-mtu-size",
                f"{label} maxPacketSize must stay in 1000..1350",
            )
        )

    key_rotation = _row_dict(hardening, "keyRotation")
    if not bool(key_rotation.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-hardening-key-rotation", f"{label} keyRotation must stay enabled"))
    if _row_string(key_rotation, "strategy") != "generation-drain":
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-hardening-key-rotation-strategy",
                f"{label} keyRotation strategy must stay generation-drain",
            )
        )
    max_age_seconds = _row_int(key_rotation, "maxAgeSeconds")
    overlap_seconds = _row_int(key_rotation, "overlapSeconds")
    if max_age_seconds < 300 or max_age_seconds > 86400:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-hardening-key-rotation-age",
                f"{label} keyRotation maxAgeSeconds must stay in 300..86400",
            )
        )
    if overlap_seconds < 30 or overlap_seconds > 600 or overlap_seconds >= max_age_seconds:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-hardening-key-rotation-overlap",
                f"{label} keyRotation overlapSeconds must stay in 30..600 and below maxAgeSeconds",
            )
        )

    source_validation = _row_dict(hardening, "sourceValidation")
    if not bool(source_validation.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-hardening-source-validation", f"{label} sourceValidation must stay enabled"))
    if _row_string(source_validation, "mode") != "profile-bound-remote":
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-hardening-source-validation-mode",
                f"{label} sourceValidation mode must stay profile-bound-remote",
            )
        )

    return findings


def _validate_link_crypto_udp_dpi_resistance(
    *,
    dpi: dict[str, Any],
    code_prefix: str,
    label: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    if not dpi:
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance", f"{label} DPI resistance policy is missing"))
        return findings
    if not bool(dpi.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-enabled", f"{label} DPI resistance must stay enabled"))
    if _row_string(dpi, "mode") != "salamander-plus-scoped-paired-obfs":
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-dpi-resistance-mode",
                f"{label} DPI resistance mode must stay salamander-plus-scoped-paired-obfs",
            )
        )

    port_split = _row_dict(dpi, "portSplit")
    if _row_int(port_split, "publicUdpPort") != TRACEGATE_PUBLIC_UDP_PORT:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-dpi-resistance-public-udp",
                f"{label} DPI resistance public UDP port must stay {TRACEGATE_PUBLIC_UDP_PORT}",
            )
        )
    forbid_udp_443_expected = False
    if bool(port_split.get("forbidUdp443", False)) != forbid_udp_443_expected:
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-udp443", f"{label} must keep UDP/443 unclaimed by V2"))
    if not bool(port_split.get("forbidTcp8443", False)):
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-tcp8443", f"{label} must forbid TCP/8443"))

    required_layers = set(_string_list(dpi.get("requiredLayers")))
    missing_layers = sorted(
        {
            "hysteria2-quic",
            "salamander",
            "private-auth",
            "anti-replay",
            "anti-amplification",
            "mtu-clamp",
            "source-validation",
        }
        - required_layers
    )
    if missing_layers:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-dpi-resistance-layers",
                f"{label} DPI resistance missing required layers: {', '.join(missing_layers)}",
            )
        )

    paired_obfs = _row_dict(dpi, "pairedObfs")
    if not bool(paired_obfs.get("supported", False)):
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-paired-supported", f"{label} must support paired UDP obfs"))
    if _row_string(paired_obfs, "backend") != "udp2raw":
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-paired-backend", f"{label} paired UDP obfs backend must stay udp2raw"))
    if not bool(paired_obfs.get("requiresBothSides", False)):
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-paired-both-sides", f"{label} paired UDP obfs must require both sides"))
    if not bool(paired_obfs.get("failClosed", False)):
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-paired-fail-closed", f"{label} paired UDP obfs must fail closed"))

    packet_shape = _row_dict(dpi, "packetShape")
    if _row_string(packet_shape, "mtuMode") != "clamp":
        findings.append(_finding("error", f"{code_prefix}-dpi-resistance-mtu", f"{label} packetShape.mtuMode must stay clamp"))
    packet_size = _row_int(packet_shape, "maxPacketSize")
    if packet_size < 1000 or packet_size > 1350:
        findings.append(
            _finding(
                "error",
                f"{code_prefix}-dpi-resistance-packet-size",
                f"{label} packetShape.maxPacketSize must stay in 1000..1350",
            )
        )

    return findings


def _validate_link_crypto_udp_row(
    *,
    row: dict[str, Any],
    role_upper: str,
    index: int,
    prefix: str,
    known_profile_variants: set[str],
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    link_class = _row_string(row, "class")
    suffix = link_class or f"udp-row-{index}"
    code_prefix = f"{prefix}-{suffix}"
    label = f"{role_upper.lower()} UDP link-crypto {link_class or index}"

    if link_class not in _LINK_CRYPTO_UDP_CLASSES:
        findings.append(_finding("error", f"{code_prefix}-class", f"{label} has unsupported UDP class"))

    allowed_by_role = {
        "ENTRY": {"entry-transit-udp", "router-entry-udp"},
        "TRANSIT": {"entry-transit-udp", "router-transit-udp"},
    }.get(role_upper, set())
    if link_class and link_class not in allowed_by_role:
        findings.append(_finding("error", f"{code_prefix}-role-class", f"{label} is not valid for {role_upper}"))

    expected_side = ""
    if link_class == "entry-transit-udp":
        expected_side = "client" if role_upper == "ENTRY" else "server"
    elif link_class in {"router-entry-udp", "router-transit-udp"}:
        expected_side = "server"
    side = _row_string(row, "side").lower()
    if expected_side and side != expected_side:
        findings.append(_finding("error", f"{code_prefix}-side", f"{label} side must be {expected_side}"))

    if _row_string(row, "carrier").lower() != "hysteria2":
        findings.append(_finding("error", f"{code_prefix}-carrier", f"{label} carrier must be hysteria2"))
    if _row_string(row, "transport").lower() != "udp-quic":
        findings.append(_finding("error", f"{code_prefix}-transport", f"{label} transport must be udp-quic"))
    if _row_string(row, "managedBy") != "link-crypto":
        findings.append(_finding("error", f"{code_prefix}-managed-by", f"{label} must be managed by link-crypto"))
    if bool(row.get("xrayBackhaul", True)):
        findings.append(_finding("error", f"{code_prefix}-xray-backhaul", f"{label} must stay outside Xray backhaul"))
    if _row_int(row, "generation") < 1:
        findings.append(_finding("error", f"{code_prefix}-generation", f"{label} generation must be positive"))

    profile_ref = _row_dict(row, "profileRef")
    if _row_string(profile_ref, "kind") != "file" or not _row_string(profile_ref, "path"):
        findings.append(_finding("error", f"{code_prefix}-profile-ref", f"{label} profileRef must be a private file"))
    if not bool(profile_ref.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-profile-ref-secret", f"{label} profileRef must point at secret material"))

    local = _row_dict(row, "local")
    findings.extend(
        _validate_endpoint(
            raw_value=_row_string(local, "listen"),
            code_prefix=f"{code_prefix}-local-listen",
            label=f"{label} local listen endpoint",
            require_loopback=True,
            loopback_severity="error",
        )
    )
    if _row_string(local, "protocol").lower() != "udp":
        findings.append(_finding("error", f"{code_prefix}-local-protocol", f"{label} local protocol must be udp"))
    auth = _row_dict(local, "auth")
    if not bool(auth.get("required", False)) or _row_string(auth, "mode") != "private-profile":
        findings.append(_finding("error", f"{code_prefix}-local-auth", f"{label} local auth must be required private-profile"))

    remote = _row_dict(row, "remote")
    if not _row_string(remote, "role"):
        findings.append(_finding("error", f"{code_prefix}-remote-role", f"{label} remote role is missing"))
    if _row_string(remote, "protocol").lower() != "udp-quic":
        findings.append(_finding("error", f"{code_prefix}-remote-protocol", f"{label} remote protocol must be udp-quic"))
    findings.extend(
        _validate_endpoint(
            raw_value=_row_string(remote, "endpoint"),
            code_prefix=f"{code_prefix}-remote-endpoint",
            label=f"{label} remote endpoint",
            require_loopback=False,
        )
    )

    datagram = _row_dict(row, "datagram")
    if not bool(datagram.get("udpCapable", False)):
        findings.append(_finding("error", f"{code_prefix}-udp-capable", f"{label} must declare udpCapable=true"))

    obfs = _row_dict(row, "obfs")
    if _row_string(obfs, "type").lower() != "salamander" or not bool(obfs.get("required", False)):
        findings.append(_finding("error", f"{code_prefix}-salamander", f"{label} must require Salamander obfs"))
    obfs_ref = _row_dict(obfs, "profileRef")
    if _row_string(obfs_ref, "kind") != "file" or not _row_string(obfs_ref, "path"):
        findings.append(_finding("error", f"{code_prefix}-salamander-profile", f"{label} Salamander profileRef must be a private file"))
    if not bool(obfs_ref.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-salamander-secret", f"{label} Salamander profileRef must point at secret material"))

    paired_obfs = _row_dict(row, "pairedObfs")
    if bool(paired_obfs.get("enabled", False)):
        if _row_string(paired_obfs, "backend") != "udp2raw":
            findings.append(_finding("error", f"{code_prefix}-paired-obfs-backend", f"{label} pairedObfs backend must stay udp2raw"))
        mode = _row_string(paired_obfs, "mode")
        if mode not in {"udp2raw-faketcp", "udp2raw-icmp"}:
            findings.append(_finding("error", f"{code_prefix}-paired-obfs-mode", f"{label} pairedObfs mode is unsupported"))
        if not bool(paired_obfs.get("requiresBothSides", False)):
            findings.append(_finding("error", f"{code_prefix}-paired-obfs-both-sides", f"{label} pairedObfs must require both sides"))
        if not bool(paired_obfs.get("failClosed", False)):
            findings.append(_finding("error", f"{code_prefix}-paired-obfs-fail-closed", f"{label} pairedObfs must fail closed"))
        if not bool(paired_obfs.get("noHostWideInterception", False)):
            findings.append(_finding("error", f"{code_prefix}-paired-obfs-host-wide", f"{label} pairedObfs must not use host-wide interception"))
        if not bool(paired_obfs.get("noNfqueue", False)):
            findings.append(_finding("error", f"{code_prefix}-paired-obfs-nfqueue", f"{label} pairedObfs must not use broad NFQUEUE"))
        paired_ref = _row_dict(paired_obfs, "profileRef")
        if _row_string(paired_ref, "kind") != "file" or not _row_string(paired_ref, "path"):
            findings.append(_finding("error", f"{code_prefix}-paired-obfs-profile", f"{label} pairedObfs profileRef must be a private file"))
        if not bool(paired_ref.get("secretMaterial", False)):
            findings.append(_finding("error", f"{code_prefix}-paired-obfs-secret", f"{label} pairedObfs profileRef must point at secret material"))

    findings.extend(
        _validate_link_crypto_udp_hardening(
            hardening=_row_dict(row, "hardening"),
            code_prefix=code_prefix,
            label=label,
        )
    )
    findings.extend(
        _validate_link_crypto_udp_dpi_resistance(
            dpi=_row_dict(row, "dpiResistance"),
            code_prefix=code_prefix,
            label=label,
        )
    )

    selected_profiles = row.get("selectedProfiles")
    if not isinstance(selected_profiles, list) or not [item for item in selected_profiles if str(item or "").strip()]:
        findings.append(_finding("error", f"{code_prefix}-selected-profiles", f"{label} must declare selected Tracegate profiles"))
    else:
        selected_profile_set = {str(item).strip().upper() for item in selected_profiles if str(item or "").strip()}
        if known_profile_variants:
            unknown_profiles = sorted(selected_profile_set - known_profile_variants)
            if unknown_profiles:
                findings.append(
                    _finding(
                        "error",
                        f"{code_prefix}-selected-profiles-contract",
                        f"{label} selectedProfiles are not present in runtime-contract: {', '.join(unknown_profiles)}",
                    )
                )
        required_profiles = _LINK_CRYPTO_UDP_REQUIRED_PROFILES.get(link_class, set())
        if required_profiles and selected_profile_set != required_profiles:
            findings.append(
                _finding(
                    "error",
                    f"{code_prefix}-selected-profiles",
                    f"{label} must select exactly {'/'.join(sorted(required_profiles))} profiles",
                )
            )

    stability = _row_dict(row, "stability")
    if bool(stability.get("failOpen", True)):
        findings.append(_finding("error", f"{code_prefix}-fail-open", f"{label} must fail closed"))
    if bool(stability.get("bypassOnFailure", True)):
        findings.append(_finding("error", f"{code_prefix}-bypass", f"{label} must not bypass on failure"))
    if bool(stability.get("dropUnrelatedTraffic", True)):
        findings.append(_finding("error", f"{code_prefix}-drop-unrelated", f"{label} must not drop unrelated traffic"))

    return findings


def validate_link_crypto_state(
    *,
    state: LinkCryptoState,
    contract: dict[str, Any],
    expected_role: str,
    contract_path: str | Path | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    prefix = f"{role_upper.lower() or 'unknown'}-link-crypto"

    if state.schema != _LINK_CRYPTO_SCHEMA:
        findings.append(_finding("error", f"{prefix}-schema", f"{prefix.replace('-', ' ')} schema must be {_LINK_CRYPTO_SCHEMA}"))
    if state.version != 1:
        findings.append(_finding("error", f"{prefix}-version", f"{prefix.replace('-', ' ')} version must be 1"))
    if state.role != role_upper:
        findings.append(_finding("error", f"{prefix}-role", f"{prefix.replace('-', ' ')} role must be {role_upper}, got {state.role or 'missing'}"))
    contract_runtime_profile = _runtime_profile(contract)
    if state.runtime_profile != contract_runtime_profile:
        findings.append(_finding("error", f"{prefix}-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from runtime-contract"))
    if contract_path is not None and state.runtime_contract_path != str(Path(contract_path)):
        findings.append(_finding("warning", f"{prefix}-contract-path", f"{prefix.replace('-', ' ')} runtimeContractPath diverges from preflight input"))
    if state.secret_material:
        findings.append(_finding("error", f"{prefix}-secret-material", f"{prefix.replace('-', ' ')} must not embed Mieru or zapret2 secrets"))

    findings.extend(_validate_link_crypto_counts(state=state, prefix=prefix))
    findings.extend(_validate_link_crypto_transport_profiles(state=state, contract=contract, prefix=prefix))
    findings.extend(_validate_link_crypto_contract_alignment(state=state, contract=contract, role_upper=role_upper, prefix=prefix))

    known_profile_variants = _transport_profile_variants(state.transport_profiles)
    for index, row in enumerate(state.links):
        findings.extend(
            _validate_link_crypto_row(
                row=row,
                role_upper=role_upper,
                index=index,
                prefix=prefix,
                known_profile_variants=known_profile_variants,
            )
        )
    for index, row in enumerate(state.udp_links):
        findings.extend(
            _validate_link_crypto_udp_row(
                row=row,
                role_upper=role_upper,
                index=index,
                prefix=prefix,
                known_profile_variants=known_profile_variants,
            )
        )

    return findings


def validate_link_crypto_env(
    *,
    env: LinkCryptoEnv,
    expected_role: str,
    contract: dict[str, Any] | None = None,
    state: LinkCryptoState | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    prefix = f"{role_upper.lower() or 'unknown'}-link-crypto-env"

    if env.role != role_upper:
        findings.append(_finding("error", f"{prefix}-role", f"{prefix.replace('-', ' ')} role must be {role_upper}, got {env.role or 'missing'}"))
    if env.secret_material:
        findings.append(_finding("error", f"{prefix}-secret-material", f"{prefix.replace('-', ' ')} must not embed secrets"))
    if env.carrier != "mieru":
        findings.append(_finding("error", f"{prefix}-carrier", f"{prefix.replace('-', ' ')} carrier must be mieru"))
    if "entry-transit" in env.classes and not env.outer_carrier_enabled:
        findings.append(_finding("error", f"{prefix}-outer-carrier-enabled", f"{prefix.replace('-', ' ')} must enable WSS outer carrier for entry-transit"))
    if env.outer_carrier_enabled and env.outer_carrier_mode != "wss":
        findings.append(_finding("error", f"{prefix}-outer-carrier-mode", f"{prefix.replace('-', ' ')} outer carrier mode must be wss"))
    if env.outer_carrier_enabled and not env.outer_wss_server_name:
        findings.append(_finding("error", f"{prefix}-outer-wss-server-name", f"{prefix.replace('-', ' ')} outer WSS serverName is missing"))
    if env.outer_carrier_enabled and env.outer_wss_public_port != 443:
        findings.append(_finding("error", f"{prefix}-outer-wss-public-port", f"{prefix.replace('-', ' ')} outer WSS public port must stay 443"))
    if env.outer_carrier_enabled and not _is_clean_absolute_http_path(env.outer_wss_path):
        findings.append(_finding("error", f"{prefix}-outer-wss-path", f"{prefix.replace('-', ' ')} outer WSS path must be a clean absolute HTTP path"))
    if env.outer_carrier_enabled and not env.outer_wss_verify_tls:
        findings.append(_finding("error", f"{prefix}-outer-wss-verify-tls", f"{prefix.replace('-', ' ')} outer WSS must verify TLS"))
    if env.outer_carrier_enabled and not env.outer_wss_spki_pinning_required:
        findings.append(_finding("error", f"{prefix}-outer-wss-spki", f"{prefix.replace('-', ' ')} outer WSS must require SPKI pinning"))
    if env.outer_carrier_enabled and not env.outer_wss_admission_required:
        findings.append(_finding("error", f"{prefix}-outer-wss-admission", f"{prefix.replace('-', ' ')} outer WSS must require HMAC admission"))
    if env.generation < 1:
        findings.append(_finding("error", f"{prefix}-generation", f"{prefix.replace('-', ' ')} generation must be positive"))
    if env.total_count > 0 and not env.zapret2_required:
        findings.append(_finding("error", f"{prefix}-zapret2-required", f"{prefix.replace('-', ' ')} zapret2 must be required"))
    if env.total_count > 0 and not env.zapret2_enabled:
        findings.append(_finding("error", f"{prefix}-zapret2-enabled", f"{prefix.replace('-', ' ')} zapret2 must be enabled for TCP link-crypto"))
    if env.zapret2_host_wide_interception:
        findings.append(_finding("error", f"{prefix}-zapret2-host-wide", f"{prefix.replace('-', ' ')} must not enable host-wide interception"))
    if env.zapret2_nfqueue:
        findings.append(_finding("error", f"{prefix}-zapret2-nfqueue", f"{prefix.replace('-', ' ')} must not enable broad NFQUEUE"))
    if env.total_count > 0 and not env.tcp_dpi_resistance_required:
        findings.append(_finding("error", f"{prefix}-tcp-dpi-resistance", f"{prefix.replace('-', ' ')} TCP DPI resistance must be required"))
    if env.total_count > 0 and not env.tcp_traffic_shaping_required:
        findings.append(_finding("error", f"{prefix}-tcp-traffic-shaping", f"{prefix.replace('-', ' ')} TCP traffic shaping must be required"))
    if env.total_count > 0 and not env.promotion_preflight_required:
        findings.append(_finding("error", f"{prefix}-promotion-preflight", f"{prefix.replace('-', ' ')} promotion preflight must be required"))

    if contract is not None and env.runtime_profile != _runtime_profile(contract):
        findings.append(_finding("error", f"{prefix}-contract-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from runtime-contract"))
    if state is not None:
        if env.state_json != str(state.path):
            findings.append(_finding("warning", f"{prefix}-state-json", f"{prefix.replace('-', ' ')} points at a different desired-state.json"))
        if env.runtime_profile != state.runtime_profile:
            findings.append(_finding("error", f"{prefix}-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from desired-state.json"))
        if env.total_count != state.total_count:
            findings.append(_finding("error", f"{prefix}-count-total", f"{prefix.replace('-', ' ')} count diverges from desired-state.json"))
        state_classes = tuple(sorted({_row_string(row, "class") for row in state.links if _row_string(row, "class")}))
        if env.classes != state_classes:
            findings.append(_finding("warning", f"{prefix}-classes", f"{prefix.replace('-', ' ')} classes diverge from desired-state.json"))
    elif env.total_count != len(env.classes):
        findings.append(_finding("error", f"{prefix}-count-classes", f"{prefix.replace('-', ' ')} count diverges from class list"))

    return findings


_ROUTER_HANDOFF_SCHEMA = "tracegate.router-handoff.v1"
_ROUTER_CLIENT_BUNDLE_SCHEMA = "tracegate.router-client-bundle.v1"


def _router_expected_classes(
    *,
    contract: dict[str, Any],
    role_upper: str,
    transport: str,
    link_crypto_state: LinkCryptoState | None,
) -> tuple[str, ...]:
    if link_crypto_state is not None:
        rows = link_crypto_state.udp_links if transport == "udp" else link_crypto_state.links
        return tuple(
            _row_string(row, "class")
            for row in rows
            if _row_string(row, "class") in ({"router-entry-udp", "router-transit-udp"} if transport == "udp" else {"router-entry", "router-transit"})
        )
    link_crypto = _link_crypto_contract_block_for_role(contract, role_upper=role_upper)
    if transport == "udp":
        udp_contract = _row_dict(_link_crypto_contract_block(contract), "udp")
        role_udp_contract = _row_dict(_row_dict(udp_contract, "roles"), role_upper.lower())
        classes = _string_list(role_udp_contract.get("classes") or udp_contract.get("classes"))
        allowed = {"router-entry-udp", "router-transit-udp"}
    else:
        classes = _string_list(link_crypto.get("classes"))
        allowed = {"router-entry", "router-transit"}
    return tuple(link_class for link_class in classes if link_class in allowed)


def _validate_router_client_profile_ref(
    *,
    refs: dict[str, Any],
    key: str,
    code_prefix: str,
    label: str,
) -> list[RuntimePreflightFinding]:
    ref = _row_dict(refs, key)
    if _row_string(ref, "kind") != "file" or not _row_string(ref, "path"):
        return [_finding("error", f"{code_prefix}-router-client-profile-{key}", f"{label} router client {key} profileRef must be a private file")]
    if not bool(ref.get("secretMaterial", False)):
        return [
            _finding(
                "error",
                f"{code_prefix}-router-client-profile-{key}-secret",
                f"{label} router client {key} profileRef must point at secret material",
            )
        ]
    return []


def _validate_router_route(
    *,
    row: dict[str, Any],
    role_upper: str,
    index: int,
    prefix: str,
    transport: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    link_class = _row_string(row, "class")
    code_prefix = f"{prefix}-{link_class or f'{transport}-route-{index}'}"
    label = f"{role_upper.lower()} router handoff {link_class or index}"
    allowed = {
        "ENTRY": {"router-entry", "router-entry-udp"},
        "TRANSIT": {"router-transit", "router-transit-udp"},
    }.get(role_upper, set())

    if link_class not in allowed:
        findings.append(_finding("error", f"{code_prefix}-class", f"{label} is not valid for {role_upper}"))
    if not bool(row.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-enabled", f"{label} route must be enabled"))
    if _row_string(row, "serverRole") != role_upper:
        findings.append(_finding("error", f"{code_prefix}-server-role", f"{label} serverRole must be {role_upper}"))
    if _row_string(row, "serverSide") != "server":
        findings.append(_finding("error", f"{code_prefix}-server-side", f"{label} serverSide must be server"))
    if _row_string(row, "remoteRole") != "ROUTER":
        findings.append(_finding("error", f"{code_prefix}-remote-role", f"{label} remoteRole must be ROUTER"))
    if _row_string(row, "managedBy") != "link-crypto":
        findings.append(_finding("error", f"{code_prefix}-managed-by", f"{label} must be managed by link-crypto"))
    if bool(row.get("xrayBackhaul", True)):
        findings.append(_finding("error", f"{code_prefix}-xray-backhaul", f"{label} must stay outside Xray backhaul"))
    if _row_int(row, "generation") < 1:
        findings.append(_finding("error", f"{code_prefix}-generation", f"{label} generation must be positive"))

    findings.extend(
        _validate_endpoint(
            raw_value=_row_string(row, "serverListen"),
            code_prefix=f"{code_prefix}-server-listen",
            label=f"{label} serverListen",
            require_loopback=True,
            loopback_severity="error",
        )
    )
    findings.extend(
        _validate_endpoint(
            raw_value=_row_string(row, "publicEndpoint"),
            code_prefix=f"{code_prefix}-public-endpoint",
            label=f"{label} publicEndpoint",
            require_loopback=False,
        )
    )
    try:
        public_host, _public_port = _parse_endpoint(_row_string(row, "publicEndpoint"))
    except ValueError:
        public_host = ""
    if public_host and _is_loopback_host(public_host):
        findings.append(_finding("error", f"{code_prefix}-public-endpoint-loopback", f"{label} publicEndpoint must not be loopback"))

    auth = _row_dict(row, "auth")
    if not bool(auth.get("required", False)) or _row_string(auth, "mode") != "private-profile":
        findings.append(_finding("error", f"{code_prefix}-auth", f"{label} server auth must be required private-profile"))
    profile_ref = _row_dict(row, "profileRef")
    if _row_string(profile_ref, "kind") != "file" or not _row_string(profile_ref, "path"):
        findings.append(_finding("error", f"{code_prefix}-profile-ref", f"{label} profileRef must be a private file"))
    if not bool(profile_ref.get("secretMaterial", False)):
        findings.append(_finding("error", f"{code_prefix}-profile-ref-secret", f"{label} profileRef must point at secret material"))

    router_client = _row_dict(row, "routerClient")
    if not bool(router_client.get("requiresPrivateProfile", False)):
        findings.append(_finding("error", f"{code_prefix}-router-client-private-profile", f"{label} router client must require a private profile"))
    if bool(router_client.get("hostWideInterception", True)):
        findings.append(_finding("error", f"{code_prefix}-router-client-host-wide", f"{label} router client must not request host-wide interception"))
    if bool(router_client.get("nfqueue", True)):
        findings.append(_finding("error", f"{code_prefix}-router-client-nfqueue", f"{label} router client must not request broad NFQUEUE"))
    router_client_profile_refs = _row_dict(router_client, "profileRefs")
    if transport == "tcp":
        findings.extend(
            _validate_router_client_profile_ref(
                refs=router_client_profile_refs,
                key="mieruClient",
                code_prefix=code_prefix,
                label=label,
            )
        )
    else:
        for key in ("hysteriaClient", "salamander"):
            findings.extend(
                _validate_router_client_profile_ref(
                    refs=router_client_profile_refs,
                    key=key,
                    code_prefix=code_prefix,
                    label=label,
                )
            )
        if bool(_row_dict(row, "pairedObfs").get("enabled", False)):
            findings.extend(
                _validate_router_client_profile_ref(
                    refs=router_client_profile_refs,
                    key="pairedObfs",
                    code_prefix=code_prefix,
                    label=label,
                )
            )

    selected_profile_set = {value.upper() for value in _string_list(row.get("selectedProfiles"))}
    required_profiles = _LINK_CRYPTO_UDP_REQUIRED_PROFILES.get(link_class) if transport == "udp" else _LINK_CRYPTO_REQUIRED_PROFILES.get(link_class)
    if required_profiles and selected_profile_set != required_profiles:
        findings.append(_finding("error", f"{code_prefix}-selected-profiles", f"{label} selectedProfiles diverge from required router class profile set"))

    if transport == "tcp":
        if _row_string(row, "carrier") != "mieru":
            findings.append(_finding("error", f"{code_prefix}-carrier", f"{label} TCP carrier must be mieru"))
        if _row_string(row, "transport") != "tcp":
            findings.append(_finding("error", f"{code_prefix}-transport", f"{label} TCP transport must be tcp"))
        zapret2 = _row_dict(row, "zapret2")
        if bool(zapret2.get("hostWideInterception", False)):
            findings.append(_finding("error", f"{code_prefix}-zapret2-host-wide", f"{label} zapret2 must not use host-wide interception"))
        if bool(zapret2.get("nfqueue", False)):
            findings.append(_finding("error", f"{code_prefix}-zapret2-nfqueue", f"{label} zapret2 must not use broad NFQUEUE"))
    else:
        if _row_string(row, "carrier") != "hysteria2":
            findings.append(_finding("error", f"{code_prefix}-carrier", f"{label} UDP carrier must be hysteria2"))
        if _row_string(row, "transport") != "udp-quic":
            findings.append(_finding("error", f"{code_prefix}-transport", f"{label} UDP transport must be udp-quic"))
        obfs = _row_dict(row, "obfs")
        if _row_string(obfs, "type") != "salamander" or not bool(obfs.get("required", False)):
            findings.append(_finding("error", f"{code_prefix}-salamander", f"{label} must require Salamander"))
        paired_obfs = _row_dict(row, "pairedObfs")
        if bool(paired_obfs.get("enabled", False)):
            if _row_string(paired_obfs, "backend") != "udp2raw":
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-backend", f"{label} pairedObfs backend must stay udp2raw"))
            if not bool(paired_obfs.get("requiresBothSides", False)):
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-both-sides", f"{label} pairedObfs must require both sides"))
            if not bool(paired_obfs.get("failClosed", False)):
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-fail-closed", f"{label} pairedObfs must fail closed"))
            if not bool(paired_obfs.get("noHostWideInterception", False)):
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-host-wide", f"{label} pairedObfs must not use host-wide interception"))
            if not bool(paired_obfs.get("noNfqueue", False)):
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-nfqueue", f"{label} pairedObfs must not use broad NFQUEUE"))
        findings.extend(
            _validate_link_crypto_udp_hardening(
                hardening=_row_dict(row, "hardening"),
                code_prefix=code_prefix,
                label=label,
            )
        )
        findings.extend(
            _validate_link_crypto_udp_dpi_resistance(
                dpi=_row_dict(row, "dpiResistance"),
                code_prefix=code_prefix,
                label=label,
            )
        )
        stability = _row_dict(row, "stability")
        if bool(stability.get("failOpen", True)):
            findings.append(_finding("error", f"{code_prefix}-fail-open", f"{label} must fail closed"))
        if bool(stability.get("bypassOnFailure", True)):
            findings.append(_finding("error", f"{code_prefix}-bypass", f"{label} must not bypass on failure"))

    return findings


def validate_router_handoff_state(
    *,
    state: RouterHandoffState,
    contract: dict[str, Any],
    expected_role: str,
    contract_path: str | Path | None = None,
    link_crypto_state: LinkCryptoState | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    prefix = f"{role_upper.lower() or 'unknown'}-router-handoff"

    if state.schema != _ROUTER_HANDOFF_SCHEMA:
        findings.append(_finding("error", f"{prefix}-schema", f"{prefix.replace('-', ' ')} schema must be {_ROUTER_HANDOFF_SCHEMA}"))
    if state.version != 1:
        findings.append(_finding("error", f"{prefix}-version", f"{prefix.replace('-', ' ')} version must be 1"))
    if state.role != role_upper:
        findings.append(_finding("error", f"{prefix}-role", f"{prefix.replace('-', ' ')} role must be {role_upper}, got {state.role or 'missing'}"))
    if state.runtime_profile != _runtime_profile(contract):
        findings.append(_finding("error", f"{prefix}-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from runtime-contract"))
    if contract_path is not None and state.runtime_contract_path != str(Path(contract_path)):
        findings.append(_finding("warning", f"{prefix}-contract-path", f"{prefix.replace('-', ' ')} runtimeContractPath diverges from preflight input"))
    if state.secret_material:
        findings.append(_finding("error", f"{prefix}-secret-material", f"{prefix.replace('-', ' ')} must not embed router secret material"))

    expected_placement = "personal-router-before-entry" if role_upper == "ENTRY" else "personal-router-before-transit"
    if state.placement != expected_placement:
        findings.append(_finding("error", f"{prefix}-placement", f"{prefix.replace('-', ' ')} placement must be {expected_placement}"))
    if state.enabled != bool(state.tcp_count or state.udp_count):
        findings.append(_finding("error", f"{prefix}-enabled", f"{prefix.replace('-', ' ')} enabled flag diverges from route counts"))
    if state.total_count != state.tcp_count + state.udp_count:
        findings.append(_finding("error", f"{prefix}-count-total", f"{prefix.replace('-', ' ')} total count diverges from route counts"))
    if state.tcp_count != len(state.tcp_routes):
        findings.append(_finding("error", f"{prefix}-count-tcp", f"{prefix.replace('-', ' ')} tcp count diverges from routes"))
    if state.udp_count != len(state.udp_routes):
        findings.append(_finding("error", f"{prefix}-count-udp", f"{prefix.replace('-', ' ')} udp count diverges from routes"))

    actual_tcp_classes = tuple(_row_string(row, "class") for row in state.tcp_routes if _row_string(row, "class"))
    actual_udp_classes = tuple(_row_string(row, "class") for row in state.udp_routes if _row_string(row, "class"))
    if state.tcp_classes != actual_tcp_classes:
        findings.append(_finding("error", f"{prefix}-tcp-classes", f"{prefix.replace('-', ' ')} tcp classes diverge from routes"))
    if state.udp_classes != actual_udp_classes:
        findings.append(_finding("error", f"{prefix}-udp-classes", f"{prefix.replace('-', ' ')} udp classes diverge from routes"))

    expected_tcp_classes = _router_expected_classes(contract=contract, role_upper=role_upper, transport="tcp", link_crypto_state=link_crypto_state)
    expected_udp_classes = _router_expected_classes(contract=contract, role_upper=role_upper, transport="udp", link_crypto_state=link_crypto_state)
    if actual_tcp_classes != expected_tcp_classes:
        findings.append(_finding("error", f"{prefix}-tcp-contract-classes", f"{prefix.replace('-', ' ')} tcp classes diverge from link-crypto router classes"))
    if actual_udp_classes != expected_udp_classes:
        findings.append(_finding("error", f"{prefix}-udp-contract-classes", f"{prefix.replace('-', ' ')} udp classes diverge from link-crypto router classes"))

    handoff_contract = state.contract
    if bool(handoff_contract.get("routerIsEntryReplacement", True)):
        findings.append(_finding("error", f"{prefix}-entry-replacement", f"{prefix.replace('-', ' ')} router must not be marked as an Entry replacement"))
    if state.enabled and not bool(handoff_contract.get("requiresServerSideLinkCrypto", False)):
        findings.append(_finding("error", f"{prefix}-server-link-crypto", f"{prefix.replace('-', ' ')} enabled router handoff must require server-side link-crypto"))
    if state.enabled and not bool(handoff_contract.get("requiresPrivateRouterProfile", False)):
        findings.append(_finding("error", f"{prefix}-private-router-profile", f"{prefix.replace('-', ' ')} enabled router handoff must require a private router profile"))
    if not bool(handoff_contract.get("noHostWideInterception", False)):
        findings.append(_finding("error", f"{prefix}-host-wide", f"{prefix.replace('-', ' ')} must forbid host-wide interception"))
    if not bool(handoff_contract.get("noNfqueue", False)):
        findings.append(_finding("error", f"{prefix}-nfqueue", f"{prefix.replace('-', ' ')} must forbid broad NFQUEUE"))

    for index, row in enumerate(state.tcp_routes):
        findings.extend(_validate_router_route(row=row, role_upper=role_upper, index=index, prefix=prefix, transport="tcp"))
    for index, row in enumerate(state.udp_routes):
        findings.extend(_validate_router_route(row=row, role_upper=role_upper, index=index, prefix=prefix, transport="udp"))

    return findings


def validate_router_handoff_env(
    *,
    env: RouterHandoffEnv,
    expected_role: str,
    contract: dict[str, Any] | None = None,
    state: RouterHandoffState | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    prefix = f"{role_upper.lower() or 'unknown'}-router-handoff-env"

    if env.role != role_upper:
        findings.append(_finding("error", f"{prefix}-role", f"{prefix.replace('-', ' ')} role must be {role_upper}, got {env.role or 'missing'}"))
    if env.secret_material:
        findings.append(_finding("error", f"{prefix}-secret-material", f"{prefix.replace('-', ' ')} must not embed secrets"))
    if env.router_is_entry_replacement:
        findings.append(_finding("error", f"{prefix}-entry-replacement", f"{prefix.replace('-', ' ')} router must not be marked as an Entry replacement"))
    if not env.no_host_wide_interception:
        findings.append(_finding("error", f"{prefix}-host-wide", f"{prefix.replace('-', ' ')} must forbid host-wide interception"))
    if not env.no_nfqueue:
        findings.append(_finding("error", f"{prefix}-nfqueue", f"{prefix.replace('-', ' ')} must forbid broad NFQUEUE"))
    if env.enabled and not env.requires_private_profile:
        findings.append(_finding("error", f"{prefix}-private-profile", f"{prefix.replace('-', ' ')} enabled router handoff must require a private profile"))
    if env.total_count != env.tcp_count + env.udp_count:
        findings.append(_finding("error", f"{prefix}-count-total", f"{prefix.replace('-', ' ')} total count diverges from tcp/udp counts"))

    if contract is not None and env.runtime_profile != _runtime_profile(contract):
        findings.append(_finding("error", f"{prefix}-contract-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from runtime-contract"))
    if state is not None:
        if env.state_json != str(state.path):
            findings.append(_finding("warning", f"{prefix}-state-json", f"{prefix.replace('-', ' ')} points at a different desired-state.json"))
        if env.runtime_profile != state.runtime_profile:
            findings.append(_finding("error", f"{prefix}-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from desired-state.json"))
        if env.enabled != state.enabled:
            findings.append(_finding("error", f"{prefix}-enabled", f"{prefix.replace('-', ' ')} enabled flag diverges from desired-state.json"))
        if env.total_count != state.total_count or env.tcp_count != state.tcp_count or env.udp_count != state.udp_count:
            findings.append(_finding("error", f"{prefix}-counts", f"{prefix.replace('-', ' ')} counts diverge from desired-state.json"))
        if env.tcp_classes != state.tcp_classes:
            findings.append(_finding("error", f"{prefix}-tcp-classes", f"{prefix.replace('-', ' ')} tcp classes diverge from desired-state.json"))
        if env.udp_classes != state.udp_classes:
            findings.append(_finding("error", f"{prefix}-udp-classes", f"{prefix.replace('-', ' ')} udp classes diverge from desired-state.json"))
        paired_enabled = any(bool(_row_dict(row, "pairedObfs").get("enabled", False)) for row in state.udp_routes)
        if env.paired_obfs_enabled != paired_enabled:
            findings.append(_finding("error", f"{prefix}-paired-obfs", f"{prefix.replace('-', ' ')} paired-obfs flag diverges from desired-state.json"))
    elif env.total_count != len(env.tcp_classes) + len(env.udp_classes):
        findings.append(_finding("error", f"{prefix}-count-classes", f"{prefix.replace('-', ' ')} count diverges from class lists"))

    return findings


def _router_component_map(bundle: RouterClientBundle) -> dict[str, dict[str, Any]]:
    return {_row_string(row, "name"): row for row in bundle.components if _row_string(row, "name")}


def _validate_router_client_component(
    *,
    component: dict[str, Any],
    name: str,
    required: bool,
    transport: str,
    prefix: str,
    paired_obfs: bool = False,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    label = f"{prefix.replace('-', ' ')} component {name}"
    if not component:
        findings.append(_finding("error", f"{prefix}-component-{name}", f"{label} is missing"))
        return findings
    if bool(component.get("required", False)) != required:
        findings.append(_finding("error", f"{prefix}-component-{name}-required", f"{label} required flag diverges from routes"))
    transports = set(_string_list(component.get("transports")))
    if transport and transport not in transports:
        findings.append(_finding("error", f"{prefix}-component-{name}-transport", f"{label} must declare {transport} transport"))
    if name == "hysteria2-client" and _row_string(component, "obfs") != "salamander":
        findings.append(_finding("error", f"{prefix}-component-{name}-salamander", f"{label} must require Salamander"))
    if name == "paired-udp-obfs":
        if bool(component.get("required", False)) != paired_obfs:
            findings.append(_finding("error", f"{prefix}-component-{name}-paired", f"{label} required flag must follow UDP paired-obfs routes"))
        if _row_string(component, "backend") != "udp2raw":
            findings.append(_finding("error", f"{prefix}-component-{name}-backend", f"{label} backend must stay udp2raw"))
        if not bool(component.get("requiresBothSides", False)):
            findings.append(_finding("error", f"{prefix}-component-{name}-both-sides", f"{label} must require both sides"))
    if not bool(component.get("failClosed", False)):
        findings.append(_finding("error", f"{prefix}-component-{name}-fail-closed", f"{label} must fail closed"))
    if not bool(component.get("noHostWideInterception", False)):
        findings.append(_finding("error", f"{prefix}-component-{name}-host-wide", f"{label} must forbid host-wide interception"))
    if not bool(component.get("noNfqueue", False)):
        findings.append(_finding("error", f"{prefix}-component-{name}-nfqueue", f"{label} must forbid broad NFQUEUE"))
    return findings


def _handoff_route_by_class(state: RouterHandoffState | None, *, transport: str) -> dict[str, dict[str, Any]]:
    if state is None:
        return {}
    routes = state.udp_routes if transport == "udp-quic" else state.tcp_routes
    return {_row_string(row, "class"): row for row in routes if _row_string(row, "class")}


def _validate_router_client_route(
    *,
    row: dict[str, Any],
    role_upper: str,
    index: int,
    prefix: str,
    transport: str,
    handoff_routes: dict[str, dict[str, Any]],
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    link_class = _row_string(row, "class")
    code_prefix = f"{prefix}-{link_class or f'{transport}-route-{index}'}"
    label = f"{role_upper.lower()} router client bundle {link_class or index}"
    allowed = {
        "ENTRY": {"router-entry", "router-entry-udp"},
        "TRANSIT": {"router-transit", "router-transit-udp"},
    }.get(role_upper, set())

    if link_class not in allowed:
        findings.append(_finding("error", f"{code_prefix}-class", f"{label} is not valid for {role_upper}"))
    if not bool(row.get("enabled", False)):
        findings.append(_finding("error", f"{code_prefix}-enabled", f"{label} route must be enabled"))
    if _row_string(row, "serverRole") != role_upper:
        findings.append(_finding("error", f"{code_prefix}-server-role", f"{label} serverRole must be {role_upper}"))
    if _row_string(row, "routerRole") != "ROUTER":
        findings.append(_finding("error", f"{code_prefix}-router-role", f"{label} routerRole must be ROUTER"))

    findings.extend(
        _validate_endpoint(
            raw_value=_row_string(row, "serverEndpoint"),
            code_prefix=f"{code_prefix}-server-endpoint",
            label=f"{label} serverEndpoint",
            require_loopback=False,
        )
    )
    try:
        endpoint_host, _endpoint_port = _parse_endpoint(_row_string(row, "serverEndpoint"))
    except ValueError:
        endpoint_host = ""
    if endpoint_host and _is_loopback_host(endpoint_host):
        findings.append(_finding("error", f"{code_prefix}-server-endpoint-loopback", f"{label} serverEndpoint must not be loopback"))

    router_side = _row_dict(row, "routerSide")
    if _row_string(router_side, "mode") != "client":
        findings.append(_finding("error", f"{code_prefix}-router-mode", f"{label} routerSide mode must be client"))
    if not bool(router_side.get("requiresPrivateProfile", False)):
        findings.append(_finding("error", f"{code_prefix}-router-private-profile", f"{label} routerSide must require a private profile"))
    if not bool(router_side.get("failClosed", False)):
        findings.append(_finding("error", f"{code_prefix}-router-fail-closed", f"{label} routerSide must fail closed"))
    if bool(router_side.get("hostWideInterception", True)):
        findings.append(_finding("error", f"{code_prefix}-router-host-wide", f"{label} routerSide must not request host-wide interception"))
    if bool(router_side.get("nfqueue", True)):
        findings.append(_finding("error", f"{code_prefix}-router-nfqueue", f"{label} routerSide must not request broad NFQUEUE"))

    profile_refs = _row_dict(router_side, "profileRefs")
    if transport == "tcp":
        findings.extend(
            _validate_router_client_profile_ref(
                refs=profile_refs,
                key="mieruClient",
                code_prefix=code_prefix,
                label=label,
            )
        )
    else:
        for key in ("hysteriaClient", "salamander"):
            findings.extend(
                _validate_router_client_profile_ref(
                    refs=profile_refs,
                    key=key,
                    code_prefix=code_prefix,
                    label=label,
                )
            )
        if bool(_row_dict(row, "pairedObfs").get("enabled", False)):
            findings.extend(
                _validate_router_client_profile_ref(
                    refs=profile_refs,
                    key="pairedObfs",
                    code_prefix=code_prefix,
                    label=label,
                )
            )

    server_side = _row_dict(row, "serverSide")
    if _row_string(server_side, "mode") != "server":
        findings.append(_finding("error", f"{code_prefix}-server-mode", f"{label} serverSide mode must be server"))
    findings.extend(
        _validate_endpoint(
            raw_value=_row_string(server_side, "listen"),
            code_prefix=f"{code_prefix}-server-listen",
            label=f"{label} serverSide listen",
            require_loopback=True,
            loopback_severity="error",
        )
    )
    auth = _row_dict(server_side, "auth")
    if not bool(auth.get("required", False)) or _row_string(auth, "mode") != "private-profile":
        findings.append(_finding("error", f"{code_prefix}-server-auth", f"{label} serverSide auth must be required private-profile"))

    selected_profile_set = {value.upper() for value in _string_list(row.get("selectedProfiles"))}
    required_profiles = _LINK_CRYPTO_UDP_REQUIRED_PROFILES.get(link_class) if transport == "udp-quic" else _LINK_CRYPTO_REQUIRED_PROFILES.get(link_class)
    if required_profiles and selected_profile_set != required_profiles:
        findings.append(_finding("error", f"{code_prefix}-selected-profiles", f"{label} selectedProfiles diverge from required router class profile set"))

    if transport == "tcp":
        if _row_string(row, "transport") != "tcp":
            findings.append(_finding("error", f"{code_prefix}-transport", f"{label} transport must be tcp"))
        if _row_string(row, "carrier") != "mieru":
            findings.append(_finding("error", f"{code_prefix}-carrier", f"{label} carrier must be mieru"))
    else:
        if _row_string(row, "transport") != "udp-quic":
            findings.append(_finding("error", f"{code_prefix}-transport", f"{label} transport must be udp-quic"))
        if _row_string(row, "carrier") != "hysteria2":
            findings.append(_finding("error", f"{code_prefix}-carrier", f"{label} carrier must be hysteria2"))
        obfs = _row_dict(row, "obfs")
        if _row_string(obfs, "type") != "salamander" or not bool(obfs.get("required", False)):
            findings.append(_finding("error", f"{code_prefix}-salamander", f"{label} must require Salamander"))
        paired_obfs = _row_dict(row, "pairedObfs")
        if bool(paired_obfs.get("enabled", False)):
            if _row_string(paired_obfs, "backend") != "udp2raw":
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-backend", f"{label} pairedObfs backend must stay udp2raw"))
            if not bool(paired_obfs.get("requiresBothSides", False)):
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-both-sides", f"{label} pairedObfs must require both sides"))
            if not bool(paired_obfs.get("failClosed", False)):
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-fail-closed", f"{label} pairedObfs must fail closed"))
            if not bool(paired_obfs.get("noHostWideInterception", False)):
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-host-wide", f"{label} pairedObfs must not use host-wide interception"))
            if not bool(paired_obfs.get("noNfqueue", False)):
                findings.append(_finding("error", f"{code_prefix}-paired-obfs-nfqueue", f"{label} pairedObfs must not use broad NFQUEUE"))
        findings.extend(
            _validate_link_crypto_udp_hardening(
                hardening=_row_dict(row, "hardening"),
                code_prefix=code_prefix,
                label=label,
            )
        )
        findings.extend(
            _validate_link_crypto_udp_dpi_resistance(
                dpi=_row_dict(row, "dpiResistance"),
                code_prefix=code_prefix,
                label=label,
            )
        )

    handoff_route = handoff_routes.get(link_class)
    if handoff_route:
        if _row_string(row, "serverEndpoint") != _row_string(handoff_route, "publicEndpoint"):
            findings.append(_finding("error", f"{code_prefix}-handoff-endpoint", f"{label} serverEndpoint diverges from router handoff"))
        if _row_string(server_side, "listen") != _row_string(handoff_route, "serverListen"):
            findings.append(_finding("error", f"{code_prefix}-handoff-listen", f"{label} serverSide listen diverges from router handoff"))
        if _string_list(row.get("selectedProfiles")) != _string_list(handoff_route.get("selectedProfiles")):
            findings.append(_finding("error", f"{code_prefix}-handoff-profiles", f"{label} selectedProfiles diverge from router handoff"))
        if profile_refs != _row_dict(_row_dict(handoff_route, "routerClient"), "profileRefs"):
            findings.append(_finding("error", f"{code_prefix}-handoff-profile-refs", f"{label} profileRefs diverge from router handoff"))
    elif handoff_routes:
        findings.append(_finding("error", f"{code_prefix}-handoff-route", f"{label} has no matching router handoff route"))

    return findings


def validate_router_client_bundle(
    *,
    bundle: RouterClientBundle,
    expected_role: str,
    contract: dict[str, Any] | None = None,
    handoff_state: RouterHandoffState | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    prefix = f"{role_upper.lower() or 'unknown'}-router-client-bundle"

    if bundle.schema != _ROUTER_CLIENT_BUNDLE_SCHEMA:
        findings.append(_finding("error", f"{prefix}-schema", f"{prefix.replace('-', ' ')} schema must be {_ROUTER_CLIENT_BUNDLE_SCHEMA}"))
    if bundle.version != 1:
        findings.append(_finding("error", f"{prefix}-version", f"{prefix.replace('-', ' ')} version must be 1"))
    if bundle.role != role_upper:
        findings.append(_finding("error", f"{prefix}-role", f"{prefix.replace('-', ' ')} role must be {role_upper}, got {bundle.role or 'missing'}"))
    if contract is not None and bundle.runtime_profile != _runtime_profile(contract):
        findings.append(_finding("error", f"{prefix}-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from runtime-contract"))
    if bundle.secret_material:
        findings.append(_finding("error", f"{prefix}-secret-material", f"{prefix.replace('-', ' ')} must not embed router secret material"))

    expected_placement = "personal-router-before-entry" if role_upper == "ENTRY" else "personal-router-before-transit"
    if bundle.placement != expected_placement:
        findings.append(_finding("error", f"{prefix}-placement", f"{prefix.replace('-', ' ')} placement must be {expected_placement}"))
    if bundle.enabled != bool(bundle.tcp_count or bundle.udp_count):
        findings.append(_finding("error", f"{prefix}-enabled", f"{prefix.replace('-', ' ')} enabled flag diverges from route counts"))
    if bundle.total_count != bundle.tcp_count + bundle.udp_count:
        findings.append(_finding("error", f"{prefix}-count-total", f"{prefix.replace('-', ' ')} total count diverges from route counts"))
    if bundle.tcp_count != len(bundle.tcp_routes):
        findings.append(_finding("error", f"{prefix}-count-tcp", f"{prefix.replace('-', ' ')} tcp count diverges from routes"))
    if bundle.udp_count != len(bundle.udp_routes):
        findings.append(_finding("error", f"{prefix}-count-udp", f"{prefix.replace('-', ' ')} udp count diverges from routes"))

    actual_tcp_classes = tuple(_row_string(row, "class") for row in bundle.tcp_routes if _row_string(row, "class"))
    actual_udp_classes = tuple(_row_string(row, "class") for row in bundle.udp_routes if _row_string(row, "class"))
    if bundle.tcp_classes != actual_tcp_classes:
        findings.append(_finding("error", f"{prefix}-tcp-classes", f"{prefix.replace('-', ' ')} tcp classes diverge from routes"))
    if bundle.udp_classes != actual_udp_classes:
        findings.append(_finding("error", f"{prefix}-udp-classes", f"{prefix.replace('-', ' ')} udp classes diverge from routes"))

    requirements = bundle.requirements
    if bool(requirements.get("routerIsEntryReplacement", True)):
        findings.append(_finding("error", f"{prefix}-entry-replacement", f"{prefix.replace('-', ' ')} router must not be marked as an Entry replacement"))
    routes_present = bool(bundle.tcp_routes or bundle.udp_routes)
    if routes_present and not bool(requirements.get("requiresPrivateProfile", False)):
        findings.append(_finding("error", f"{prefix}-private-profile", f"{prefix.replace('-', ' ')} router routes must require private profiles"))
    if routes_present and not bool(requirements.get("requiresServerSideLinkCrypto", False)):
        findings.append(_finding("error", f"{prefix}-server-link-crypto", f"{prefix.replace('-', ' ')} router routes must require server-side link-crypto"))
    if bool(requirements.get("requiresBothSides", False)) != routes_present:
        findings.append(_finding("error", f"{prefix}-both-sides", f"{prefix.replace('-', ' ')} requiresBothSides flag diverges from routes"))
    if not bool(requirements.get("failClosed", False)):
        findings.append(_finding("error", f"{prefix}-fail-closed", f"{prefix.replace('-', ' ')} router bundle must fail closed"))
    if not bool(requirements.get("noHostWideInterception", False)):
        findings.append(_finding("error", f"{prefix}-host-wide", f"{prefix.replace('-', ' ')} router bundle must forbid host-wide interception"))
    if not bool(requirements.get("noNfqueue", False)):
        findings.append(_finding("error", f"{prefix}-nfqueue", f"{prefix.replace('-', ' ')} router bundle must forbid broad NFQUEUE"))
    if _row_string(requirements, "profileDistribution") != "external-private-files":
        findings.append(_finding("error", f"{prefix}-profile-distribution", f"{prefix.replace('-', ' ')} profileDistribution must be external-private-files"))

    paired_obfs_enabled = any(bool(_row_dict(row, "pairedObfs").get("enabled", False)) for row in bundle.udp_routes)
    components = _router_component_map(bundle)
    findings.extend(
        _validate_router_client_component(
            component=components.get("mieru-client", {}),
            name="mieru-client",
            required=bool(bundle.tcp_routes),
            transport="tcp",
            prefix=prefix,
        )
    )
    findings.extend(
        _validate_router_client_component(
            component=components.get("hysteria2-client", {}),
            name="hysteria2-client",
            required=bool(bundle.udp_routes),
            transport="udp-quic",
            prefix=prefix,
        )
    )
    findings.extend(
        _validate_router_client_component(
            component=components.get("paired-udp-obfs", {}),
            name="paired-udp-obfs",
            required=paired_obfs_enabled,
            transport="",
            prefix=prefix,
            paired_obfs=paired_obfs_enabled,
        )
    )

    tcp_handoff_routes = _handoff_route_by_class(handoff_state, transport="tcp")
    udp_handoff_routes = _handoff_route_by_class(handoff_state, transport="udp-quic")
    for index, row in enumerate(bundle.tcp_routes):
        findings.extend(
            _validate_router_client_route(
                row=row,
                role_upper=role_upper,
                index=index,
                prefix=prefix,
                transport="tcp",
                handoff_routes=tcp_handoff_routes,
            )
        )
    for index, row in enumerate(bundle.udp_routes):
        findings.extend(
            _validate_router_client_route(
                row=row,
                role_upper=role_upper,
                index=index,
                prefix=prefix,
                transport="udp-quic",
                handoff_routes=udp_handoff_routes,
            )
        )

    if handoff_state is not None:
        if bundle.handoff_state_json != str(handoff_state.path):
            findings.append(_finding("warning", f"{prefix}-handoff-json", f"{prefix.replace('-', ' ')} points at a different desired-state.json"))
        if bundle.runtime_profile != handoff_state.runtime_profile:
            findings.append(_finding("error", f"{prefix}-handoff-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from router handoff"))
        if bundle.enabled != handoff_state.enabled:
            findings.append(_finding("error", f"{prefix}-handoff-enabled", f"{prefix.replace('-', ' ')} enabled flag diverges from router handoff"))
        if bundle.total_count != handoff_state.total_count or bundle.tcp_count != handoff_state.tcp_count or bundle.udp_count != handoff_state.udp_count:
            findings.append(_finding("error", f"{prefix}-handoff-counts", f"{prefix.replace('-', ' ')} counts diverge from router handoff"))
        if bundle.tcp_classes != handoff_state.tcp_classes:
            findings.append(_finding("error", f"{prefix}-handoff-tcp-classes", f"{prefix.replace('-', ' ')} tcp classes diverge from router handoff"))
        if bundle.udp_classes != handoff_state.udp_classes:
            findings.append(_finding("error", f"{prefix}-handoff-udp-classes", f"{prefix.replace('-', ' ')} udp classes diverge from router handoff"))

    return findings


def validate_router_client_bundle_env(
    *,
    env: RouterClientBundleEnv,
    expected_role: str,
    contract: dict[str, Any] | None = None,
    bundle: RouterClientBundle | None = None,
    handoff_state: RouterHandoffState | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    role_upper = str(expected_role or "").strip().upper()
    prefix = f"{role_upper.lower() or 'unknown'}-router-client-bundle-env"

    if env.role != role_upper:
        findings.append(_finding("error", f"{prefix}-role", f"{prefix.replace('-', ' ')} role must be {role_upper}, got {env.role or 'missing'}"))
    if env.secret_material:
        findings.append(_finding("error", f"{prefix}-secret-material", f"{prefix.replace('-', ' ')} must not embed secrets"))
    if not env.fail_closed:
        findings.append(_finding("error", f"{prefix}-fail-closed", f"{prefix.replace('-', ' ')} must fail closed"))
    if not env.no_host_wide_interception:
        findings.append(_finding("error", f"{prefix}-host-wide", f"{prefix.replace('-', ' ')} must forbid host-wide interception"))
    if not env.no_nfqueue:
        findings.append(_finding("error", f"{prefix}-nfqueue", f"{prefix.replace('-', ' ')} must forbid broad NFQUEUE"))
    if env.tcp_count < 0 or env.udp_count < 0:
        findings.append(_finding("error", f"{prefix}-counts", f"{prefix.replace('-', ' ')} route counts must be non-negative"))
    if env.enabled != bool(env.tcp_count or env.udp_count):
        findings.append(_finding("error", f"{prefix}-enabled", f"{prefix.replace('-', ' ')} enabled flag diverges from route counts"))
    if env.requires_both_sides != bool(env.tcp_count or env.udp_count):
        findings.append(_finding("error", f"{prefix}-both-sides", f"{prefix.replace('-', ' ')} requiresBothSides flag diverges from route counts"))
    if contract is not None and env.runtime_profile != _runtime_profile(contract):
        findings.append(_finding("error", f"{prefix}-contract-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from runtime-contract"))

    if bundle is not None:
        required_components = tuple(
            sorted(
                _row_string(row, "name") for row in bundle.components if bool(row.get("required", False)) and _row_string(row, "name")
            )
        )
        if env.bundle_json != str(bundle.path):
            findings.append(_finding("warning", f"{prefix}-bundle-json", f"{prefix.replace('-', ' ')} points at a different client-bundle.json"))
        if env.handoff_json != bundle.handoff_state_json:
            findings.append(_finding("warning", f"{prefix}-handoff-json", f"{prefix.replace('-', ' ')} handoff path diverges from client-bundle.json"))
        if env.runtime_profile != bundle.runtime_profile:
            findings.append(_finding("error", f"{prefix}-runtime-profile", f"{prefix.replace('-', ' ')} runtimeProfile diverges from client-bundle.json"))
        if env.enabled != bundle.enabled:
            findings.append(_finding("error", f"{prefix}-bundle-enabled", f"{prefix.replace('-', ' ')} enabled flag diverges from client-bundle.json"))
        if env.tcp_count != bundle.tcp_count or env.udp_count != bundle.udp_count:
            findings.append(_finding("error", f"{prefix}-bundle-counts", f"{prefix.replace('-', ' ')} counts diverge from client-bundle.json"))
        if env.components != required_components:
            findings.append(_finding("error", f"{prefix}-components", f"{prefix.replace('-', ' ')} components diverge from required client-bundle components"))
        if env.requires_both_sides != bool(bundle.requirements.get("requiresBothSides", False)):
            findings.append(_finding("error", f"{prefix}-bundle-both-sides", f"{prefix.replace('-', ' ')} requiresBothSides diverges from client-bundle.json"))

    if handoff_state is not None and env.handoff_json != str(handoff_state.path):
        findings.append(_finding("warning", f"{prefix}-state-json", f"{prefix.replace('-', ' ')} points at a different router handoff state"))

    return findings


def _validate_mtproto_share_url(
    *,
    raw_url: str,
    expected_server: str,
    expected_port: int,
    code_prefix: str,
    label: str,
) -> RuntimePreflightFinding | None:
    parsed = urlparse(raw_url)
    query = parse_qs(parsed.query)
    server = str((query.get("server") or [""])[0]).strip()
    port_raw = str((query.get("port") or [""])[0]).strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 0
    if server != expected_server or port != expected_port:
        return _finding(
            "warning",
            f"{code_prefix}-{label}",
            f"MTProto public profile {label} diverges from expected server/port handoff",
        )
    return None


def validate_fronting_runtime_state(
    *,
    state: FrontingRuntimeState,
    transit_contract: dict[str, Any],
    transit_runtime_state: ObfuscationRuntimeState | None = None,
    mtproto_profile: ZapretProfile | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []

    if state.role != "TRANSIT":
        findings.append(_finding("error", "fronting-role", f"fronting runtime-state role must be TRANSIT, got {state.role or 'missing'}"))
    if state.protocol != "tcp":
        findings.append(_finding("error", "fronting-protocol", f"fronting runtime-state must keep TCP-only demux, got {state.protocol or 'missing'}"))
    if state.touch_udp_443:
        findings.append(_finding("error", "fronting-touch-udp-443", "fronting runtime-state must not claim public udp/443"))

    fronting = _fronting_block(transit_contract)
    if state.mtproto_domain != str(fronting.get("mtprotoDomain") or "").strip():
        findings.append(_finding("warning", "fronting-mtproto-domain", "fronting MTProto domain diverges from Transit runtime-contract"))
    if state.mtproto_fronting_mode != str(fronting.get("mtprotoFrontingMode") or "dedicated-dns-only").strip().lower():
        findings.append(_finding("warning", "fronting-mtproto-fronting-mode", "fronting MTProto mode diverges from Transit runtime-contract"))

    if transit_runtime_state is not None:
        if state.runtime_state_json != str(transit_runtime_state.path):
            findings.append(_finding("warning", "fronting-runtime-state-json", "fronting runtime-state points at a different obfuscation runtime-state path"))
        if state.tcp_443_owner != transit_runtime_state.fronting_tcp_owner:
            findings.append(_finding("error", "fronting-tcp-owner", "fronting runtime-state tcp443 owner diverges from obfuscation runtime-state"))
        if state.udp_443_owner != transit_runtime_state.fronting_udp_owner:
            findings.append(_finding("error", "fronting-udp-owner", "fronting runtime-state udp443 owner diverges from obfuscation runtime-state"))
        if state.mtproto_domain != transit_runtime_state.mtproto_domain:
            findings.append(_finding("warning", "fronting-obfuscation-mtproto-domain", "fronting runtime-state MTProto domain diverges from obfuscation runtime-state"))

    if mtproto_profile is not None and state.mtproto_profile_file != str(mtproto_profile.path):
        findings.append(_finding("warning", "fronting-mtproto-profile-file", "fronting runtime-state MTProto profile file diverges from validated zapret MTProto profile"))

    for code, value in (
        ("fronting-listen-addr", state.listen_addr),
        ("fronting-reality-upstream", state.reality_upstream),
        ("fronting-ws-upstream", state.ws_tls_upstream),
        ("fronting-mtproto-upstream", state.mtproto_upstream),
        ("fronting-cfg-file", state.cfg_file),
        ("fronting-pid-file", state.pid_file),
    ):
        if not value:
            findings.append(_finding("warning", code, f"fronting runtime-state missing {code.split('-', 1)[1].replace('-', ' ')}"))

    if not state.backend:
        findings.append(_finding("warning", "fronting-backend", "fronting runtime-state does not advertise a backend"))

    return findings


def validate_fronting_env_contract(
    *,
    env: FrontingEnvContract,
    transit_contract: dict[str, Any],
    transit_runtime_state: ObfuscationRuntimeState | None = None,
    mtproto_profile: ZapretProfile | None = None,
    fronting_state: FrontingRuntimeState | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []

    if env.role != "transit":
        findings.append(_finding("error", "fronting-env-role", f"fronting env role must be transit, got {env.role or 'missing'}"))
    if env.protocol != "tcp":
        findings.append(_finding("error", "fronting-env-protocol", f"fronting env must keep tcp demux, got {env.protocol or 'missing'}"))
    if env.touch_udp_443:
        findings.append(_finding("error", "fronting-env-touch-udp-443", "fronting env must not claim public udp/443"))
    if not env.backend:
        findings.append(_finding("warning", "fronting-env-backend", "fronting env does not advertise a backend"))
    elif env.backend != "private":
        findings.append(_finding("warning", "fronting-env-backend-private", f"fronting env backend drifted from private: {env.backend}"))

    findings.extend(_validate_endpoint(raw_value=env.listen_addr, code_prefix="fronting-env-listen-addr", label="fronting listenAddr"))
    findings.extend(
        _validate_endpoint(
            raw_value=env.reality_upstream,
            code_prefix="fronting-env-reality-upstream",
            label="fronting reality upstream",
        )
    )
    findings.extend(
        _validate_endpoint(
            raw_value=env.ws_tls_upstream,
            code_prefix="fronting-env-ws-upstream",
            label="fronting ws/tls upstream",
        )
    )
    findings.extend(
        _validate_endpoint(
            raw_value=env.mtproto_upstream,
            code_prefix="fronting-env-mtproto-upstream",
            label="fronting mtproto upstream",
        )
    )

    if not env.runtime_state_json:
        findings.append(_finding("warning", "fronting-env-runtime-state-json", "fronting env does not advertise runtime-state.json"))
    if transit_runtime_state is not None and env.runtime_state_json != str(transit_runtime_state.path):
        findings.append(_finding("warning", "fronting-env-runtime-state-json", "fronting env points at a different obfuscation runtime-state path"))

    fronting = _fronting_block(transit_contract)
    expected_domain = str(fronting.get("mtprotoDomain") or "").strip()
    effective_domain = env.mtproto_domain_override or expected_domain
    if env.mtproto_domain_override and expected_domain and env.mtproto_domain_override != expected_domain:
        findings.append(_finding("warning", "fronting-env-mtproto-domain-override", "fronting env MTProto domain override diverges from Transit runtime-contract"))

    if mtproto_profile is not None and env.mtproto_profile_file != str(mtproto_profile.path):
        findings.append(_finding("warning", "fronting-env-mtproto-profile-file", "fronting env MTProto profile file diverges from validated zapret MTProto profile"))

    for code, value in (
        ("fronting-env-state-dir", env.state_dir),
        ("fronting-env-runtime-dir", env.runtime_dir),
        ("fronting-env-runner", env.runner),
        ("fronting-env-haproxy-bin", env.haproxy_bin),
        ("fronting-env-ws-sni", env.ws_sni),
    ):
        if not value:
            findings.append(_finding("warning", code, f"fronting env missing {code.split('-', 2)[2].replace('-', ' ')}"))

    if env.runtime_dir and env.state_dir:
        runtime_dir = Path(env.runtime_dir)
        state_dir = Path(env.state_dir)
        if runtime_dir.parent != state_dir:
            findings.append(_finding("warning", "fronting-env-runtime-dir-layout", "fronting env runtimeDir no longer sits under stateDir"))

    if fronting_state is not None:
        if str(fronting_state.path) != str(Path(env.state_dir) / "last-action.json"):
            findings.append(_finding("warning", "fronting-env-state-file", "fronting env stateDir no longer matches fronting last-action.json location"))
        if env.runtime_state_json != fronting_state.runtime_state_json:
            findings.append(_finding("warning", "fronting-env-state-runtime-path", "fronting env runtime-state path diverges from fronting last-action.json"))
        if env.listen_addr != fronting_state.listen_addr:
            findings.append(_finding("warning", "fronting-env-state-listen-addr", "fronting env listenAddr diverges from fronting last-action.json"))
        if env.protocol != fronting_state.protocol:
            findings.append(_finding("error", "fronting-env-state-protocol", "fronting env protocol diverges from fronting last-action.json"))
        if env.reality_upstream != fronting_state.reality_upstream:
            findings.append(_finding("warning", "fronting-env-state-reality-upstream", "fronting env reality upstream diverges from fronting last-action.json"))
        if env.ws_tls_upstream != fronting_state.ws_tls_upstream:
            findings.append(_finding("warning", "fronting-env-state-ws-upstream", "fronting env ws/tls upstream diverges from fronting last-action.json"))
        if env.mtproto_upstream != fronting_state.mtproto_upstream:
            findings.append(_finding("warning", "fronting-env-state-mtproto-upstream", "fronting env MTProto upstream diverges from fronting last-action.json"))
        if env.mtproto_profile_file != fronting_state.mtproto_profile_file:
            findings.append(_finding("warning", "fronting-env-state-mtproto-profile-file", "fronting env MTProto profile file diverges from fronting last-action.json"))
        if env.touch_udp_443 != fronting_state.touch_udp_443:
            findings.append(_finding("error", "fronting-env-state-touch-udp-443", "fronting env touchUdp443 diverges from fronting last-action.json"))
        if env.ws_sni != fronting_state.ws_sni:
            findings.append(_finding("warning", "fronting-env-state-ws-sni", "fronting env ws SNI diverges from fronting last-action.json"))
        if effective_domain and fronting_state.mtproto_domain != effective_domain:
            findings.append(_finding("warning", "fronting-env-state-mtproto-domain", "fronting env effective MTProto domain diverges from fronting last-action.json"))
        if fronting_state.cfg_file and not str(fronting_state.cfg_file).startswith(f"{Path(env.runtime_dir)}/"):
            findings.append(_finding("warning", "fronting-env-state-cfg-file", "fronting runtime cfgFile no longer lives under fronting runtimeDir"))
        if fronting_state.pid_file and not str(fronting_state.pid_file).startswith(f"{Path(env.runtime_dir)}/"):
            findings.append(_finding("warning", "fronting-env-state-pid-file", "fronting runtime pidFile no longer lives under fronting runtimeDir"))

    return findings


def validate_mtproto_gateway_state(
    *,
    state: MTProtoGatewayState,
    transit_contract: dict[str, Any],
    transit_runtime_state: ObfuscationRuntimeState | None = None,
    mtproto_profile: ZapretProfile | None = None,
    public_profile: MTProtoPublicProfile | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []

    if state.role != "TRANSIT":
        findings.append(_finding("error", "mtproto-role", f"mtproto runtime-state role must be TRANSIT, got {state.role or 'missing'}"))

    fronting = _fronting_block(transit_contract)
    if state.domain != str(fronting.get("mtprotoDomain") or "").strip():
        findings.append(_finding("warning", "mtproto-domain", "mtproto runtime-state domain diverges from Transit runtime-contract"))
    if state.public_port != int(fronting.get("mtprotoPublicPort") or 443):
        findings.append(_finding("warning", "mtproto-public-port", "mtproto runtime-state public port diverges from Transit runtime-contract"))

    if transit_runtime_state is not None and state.runtime_state_json != str(transit_runtime_state.path):
        findings.append(_finding("warning", "mtproto-runtime-state-json", "mtproto runtime-state points at a different obfuscation runtime-state path"))

    if mtproto_profile is not None and state.profile_file != str(mtproto_profile.path):
        findings.append(_finding("warning", "mtproto-profile-file", "mtproto runtime-state profile file diverges from validated zapret MTProto profile"))

    if not state.upstream_host:
        findings.append(_finding("warning", "mtproto-upstream-host", "mtproto runtime-state missing upstreamHost"))
    elif state.upstream_host not in {"127.0.0.1", "localhost", "::1"}:
        findings.append(_finding("warning", "mtproto-upstream-loopback", f"mtproto runtime-state upstreamHost is not loopback: {state.upstream_host}"))

    if state.upstream_port <= 0:
        findings.append(_finding("error", "mtproto-upstream-port", "mtproto runtime-state has invalid upstreamPort"))

    if not state.backend:
        findings.append(_finding("warning", "mtproto-backend", "mtproto runtime-state does not advertise a backend"))
    if not state.issued_state_file:
        findings.append(_finding("warning", "mtproto-issued-state-file", "mtproto runtime-state does not advertise issuedStateFile"))
    elif state.public_profile_file:
        state_dir = Path(state.public_profile_file).parent
        if not str(state.issued_state_file).startswith(f"{state_dir}/"):
            findings.append(_finding("warning", "mtproto-issued-state-file-layout", "mtproto runtime-state issuedStateFile no longer follows the mtproto state dir layout"))

    if public_profile is not None:
        expected_domain = str(fronting.get("mtprotoDomain") or "").strip()
        expected_port = int(fronting.get("mtprotoPublicPort") or 443)
        if state.public_profile_file and state.public_profile_file != str(public_profile.path):
            findings.append(_finding("warning", "mtproto-public-profile-file", "mtproto runtime-state public profile path diverges from the validated public-profile.json"))
        if public_profile.server != state.domain or public_profile.server != expected_domain:
            findings.append(_finding("warning", "mtproto-public-profile-server", "MTProto public profile server diverges from mtproto runtime-state domain"))
        if public_profile.port != state.public_port or public_profile.port != expected_port:
            findings.append(_finding("warning", "mtproto-public-profile-port", "MTProto public profile port diverges from mtproto runtime-state publicPort"))
        if public_profile.domain != state.domain or public_profile.domain != expected_domain:
            findings.append(_finding("warning", "mtproto-public-profile-domain", "MTProto public profile domain diverges from mtproto runtime-state domain"))
        if public_profile.transport != "tls":
            findings.append(_finding("warning", "mtproto-public-profile-transport", f"MTProto public profile transport is not tls: {public_profile.transport}"))
        if public_profile.profile_name != MTPROTO_FAKE_TLS_PROFILE_NAME:
            findings.append(
                _finding(
                    "warning",
                    "mtproto-public-profile-name",
                    f"MTProto public profile name must be {MTPROTO_FAKE_TLS_PROFILE_NAME}",
                )
            )
        tg_finding = _validate_mtproto_share_url(
            raw_url=public_profile.tg_uri,
            expected_server=expected_domain,
            expected_port=expected_port,
            code_prefix="mtproto-public-profile",
            label="tg-uri",
        )
        if tg_finding is not None:
            findings.append(tg_finding)
        https_finding = _validate_mtproto_share_url(
            raw_url=public_profile.https_url,
            expected_server=expected_domain,
            expected_port=expected_port,
            code_prefix="mtproto-public-profile",
            label="https-url",
        )
        if https_finding is not None:
            findings.append(https_finding)

    return findings


def validate_mtproto_env_contract(
    *,
    env: MTProtoEnvContract,
    transit_contract: dict[str, Any],
    transit_runtime_state: ObfuscationRuntimeState | None = None,
    mtproto_profile: ZapretProfile | None = None,
    fronting_env: FrontingEnvContract | None = None,
    fronting_state: FrontingRuntimeState | None = None,
    gateway_state: MTProtoGatewayState | None = None,
    public_profile: MTProtoPublicProfile | None = None,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []

    if env.role != "transit":
        findings.append(_finding("error", "mtproto-env-role", f"mtproto env role must be transit, got {env.role or 'missing'}"))
    if not env.backend:
        findings.append(_finding("warning", "mtproto-env-backend", "mtproto env does not advertise a backend"))
    elif env.backend != "private":
        findings.append(_finding("warning", "mtproto-env-backend-private", f"mtproto env backend drifted from private: {env.backend}"))
    if env.public_port < 1 or env.public_port > 65535:
        findings.append(_finding("error", "mtproto-env-public-port", "mtproto env has invalid public port"))
    if not _is_loopback_host(env.upstream_host):
        findings.append(_finding("warning", "mtproto-env-upstream-loopback", f"mtproto env upstreamHost is not loopback: {env.upstream_host or 'missing'}"))
    if env.upstream_port < 1 or env.upstream_port > 65535:
        findings.append(_finding("error", "mtproto-env-upstream-port", "mtproto env has invalid upstream port"))
    if env.tls_mode != "private-fronting":
        findings.append(_finding("error", "mtproto-env-tls-mode", f"mtproto env must keep TRACEGATE_MTPROTO_TLS_MODE=private-fronting, got {env.tls_mode or 'missing'}"))
    if env.stats_port < 1 or env.stats_port > 65535:
        findings.append(_finding("error", "mtproto-env-stats-port", "mtproto env has invalid stats port"))
    if env.bootstrap_max_age_seconds < 60:
        findings.append(_finding("warning", "mtproto-env-bootstrap-max-age", "mtproto env refreshes official bootstrap files too aggressively"))
    elif env.bootstrap_max_age_seconds > 172800:
        findings.append(_finding("warning", "mtproto-env-bootstrap-max-age", "mtproto env keeps official bootstrap files for too long"))
    if env.workers < 0:
        findings.append(_finding("error", "mtproto-env-workers", "mtproto env must set TRACEGATE_MTPROTO_WORKERS to a non-negative integer"))
    elif env.workers > 1:
        findings.append(_finding("warning", "mtproto-env-workers", f"mtproto env raises worker count above the low-overhead target: {env.workers}"))
    if env.run_as_user.lower() == "root":
        findings.append(_finding("warning", "mtproto-env-run-as-user", "mtproto env should not run MTProto as root"))

    if not env.runtime_state_json:
        findings.append(_finding("warning", "mtproto-env-runtime-state-json", "mtproto env does not advertise runtime-state.json"))
    if transit_runtime_state is not None and env.runtime_state_json != str(transit_runtime_state.path):
        findings.append(_finding("warning", "mtproto-env-runtime-state-json", "mtproto env points at a different obfuscation runtime-state path"))

    if mtproto_profile is not None and env.profile_file != str(mtproto_profile.path):
        findings.append(_finding("warning", "mtproto-env-profile-file", "mtproto env profile file diverges from validated zapret MTProto profile"))

    fronting = _fronting_block(transit_contract)
    expected_domain = str(fronting.get("mtprotoDomain") or "").strip()
    expected_port = int(fronting.get("mtprotoPublicPort") or 443)
    if env.domain != expected_domain:
        findings.append(_finding("warning", "mtproto-env-domain", "mtproto env domain diverges from Transit runtime-contract"))
    if env.public_port != expected_port:
        findings.append(_finding("warning", "mtproto-env-public-port-contract", "mtproto env public port diverges from Transit runtime-contract"))

    if fronting_env is not None:
        expected_upstream = f"{env.upstream_host}:{env.upstream_port}"
        if fronting_env.runtime_state_json != env.runtime_state_json:
            findings.append(_finding("warning", "mtproto-env-fronting-runtime-state-json", "fronting env and mtproto env point at different obfuscation runtime-state paths"))
        if fronting_env.mtproto_upstream != expected_upstream:
            findings.append(_finding("warning", "mtproto-env-fronting-upstream", "fronting env MTProto upstream diverges from mtproto env host/port"))
        if fronting_env.mtproto_profile_file != env.profile_file:
            findings.append(_finding("warning", "mtproto-env-fronting-profile-file", "fronting env MTProto profile file diverges from mtproto env"))

    if fronting_state is not None and fronting_state.mtproto_upstream != f"{env.upstream_host}:{env.upstream_port}":
        findings.append(_finding("warning", "mtproto-env-fronting-state-upstream", "mtproto env host/port diverges from fronting last-action.json"))

    for code, value in (
        ("mtproto-env-secret-file", env.secret_file),
        ("mtproto-env-state-dir", env.state_dir),
        ("mtproto-env-issued-state-file", env.issued_state_file),
        ("mtproto-env-binary", env.binary),
        ("mtproto-env-runtime-dir", env.runtime_dir),
        ("mtproto-env-proxy-secret-file", env.proxy_secret_file),
        ("mtproto-env-proxy-config-file", env.proxy_config_file),
        ("mtproto-env-pid-file", env.pid_file),
        ("mtproto-env-log-file", env.log_file),
    ):
        if not value:
            findings.append(_finding("warning", code, f"mtproto env missing {code.split('-', 2)[2].replace('-', ' ')}"))

    if env.runtime_dir and env.state_dir:
        runtime_dir = Path(env.runtime_dir)
        state_dir = Path(env.state_dir)
        if runtime_dir.parent != state_dir:
            findings.append(_finding("warning", "mtproto-env-runtime-dir-layout", "mtproto env runtimeDir no longer sits under stateDir"))
    if env.issued_state_file and env.state_dir and not str(env.issued_state_file).startswith(f"{Path(env.state_dir)}/"):
        findings.append(_finding("warning", "mtproto-env-issued-state-file-layout", "mtproto env issuedStateFile no longer lives under stateDir"))
    if env.proxy_secret_file and env.runtime_dir and not str(env.proxy_secret_file).startswith(f"{Path(env.runtime_dir)}/"):
        findings.append(_finding("warning", "mtproto-env-proxy-secret-file-layout", "mtproto env proxySecretFile no longer lives under runtimeDir"))
    if env.proxy_config_file and env.runtime_dir and not str(env.proxy_config_file).startswith(f"{Path(env.runtime_dir)}/"):
        findings.append(_finding("warning", "mtproto-env-proxy-config-file-layout", "mtproto env proxyConfigFile no longer lives under runtimeDir"))
    if env.pid_file and env.runtime_dir and not str(env.pid_file).startswith(f"{Path(env.runtime_dir)}/"):
        findings.append(_finding("warning", "mtproto-env-pid-file-layout", "mtproto env pidFile no longer lives under runtimeDir"))
    if env.log_file and env.runtime_dir and not str(env.log_file).startswith(f"{Path(env.runtime_dir)}/"):
        findings.append(_finding("warning", "mtproto-env-log-file-layout", "mtproto env logFile no longer lives under runtimeDir"))

    secret_url_finding = _validate_https_url(
        raw_url=env.fetch_secret_url,
        code="mtproto-env-fetch-secret-url",
        label="TRACEGATE_MTPROTO_FETCH_SECRET_URL",
    )
    if secret_url_finding is not None:
        findings.append(secret_url_finding)
    config_url_finding = _validate_https_url(
        raw_url=env.fetch_config_url,
        code="mtproto-env-fetch-config-url",
        label="TRACEGATE_MTPROTO_FETCH_CONFIG_URL",
    )
    if config_url_finding is not None:
        findings.append(config_url_finding)

    if gateway_state is not None:
        if str(gateway_state.path) != str(Path(env.state_dir) / "last-action.json"):
            findings.append(_finding("warning", "mtproto-env-state-file", "mtproto env stateDir no longer matches mtproto last-action.json location"))
        if env.runtime_state_json != gateway_state.runtime_state_json:
            findings.append(_finding("warning", "mtproto-env-state-runtime-path", "mtproto env runtime-state path diverges from mtproto last-action.json"))
        if env.domain != gateway_state.domain:
            findings.append(_finding("warning", "mtproto-env-state-domain", "mtproto env domain diverges from mtproto last-action.json"))
        if env.public_port != gateway_state.public_port:
            findings.append(_finding("warning", "mtproto-env-state-public-port", "mtproto env public port diverges from mtproto last-action.json"))
        if env.upstream_host != gateway_state.upstream_host:
            findings.append(_finding("warning", "mtproto-env-state-upstream-host", "mtproto env upstream host diverges from mtproto last-action.json"))
        if env.upstream_port != gateway_state.upstream_port:
            findings.append(_finding("warning", "mtproto-env-state-upstream-port", "mtproto env upstream port diverges from mtproto last-action.json"))
        if env.profile_file != gateway_state.profile_file:
            findings.append(_finding("warning", "mtproto-env-state-profile-file", "mtproto env profile file diverges from mtproto last-action.json"))
        if env.issued_state_file != gateway_state.issued_state_file:
            findings.append(_finding("warning", "mtproto-env-state-issued-state-file", "mtproto env issuedStateFile diverges from mtproto last-action.json"))
        expected_public_profile_file = str(Path(env.state_dir) / "public-profile.json")
        if gateway_state.public_profile_file and gateway_state.public_profile_file != expected_public_profile_file:
            findings.append(_finding("warning", "mtproto-env-state-public-profile-file", "mtproto runtime-state publicProfileFile no longer follows the mtproto stateDir contract"))
        expected_issued_state_file = str(Path(env.state_dir) / "issued.json")
        if gateway_state.issued_state_file and gateway_state.issued_state_file != expected_issued_state_file:
            findings.append(_finding("warning", "mtproto-env-state-issued-state-file-layout", "mtproto runtime-state issuedStateFile no longer follows the mtproto stateDir contract"))

    if public_profile is not None:
        if str(public_profile.path) != str(Path(env.state_dir) / "public-profile.json"):
            findings.append(_finding("warning", "mtproto-env-public-profile-file", "public-profile.json no longer lives under mtproto stateDir"))
        if env.domain != public_profile.server:
            findings.append(_finding("warning", "mtproto-env-public-profile-server", "mtproto env domain diverges from public-profile server"))
        if env.public_port != public_profile.port:
            findings.append(_finding("warning", "mtproto-env-public-profile-port", "mtproto env public port diverges from public-profile port"))
        if public_profile.profile_name != MTPROTO_FAKE_TLS_PROFILE_NAME:
            findings.append(
                _finding(
                    "warning",
                    "mtproto-env-public-profile-name",
                    f"MTProto public profile name must be {MTPROTO_FAKE_TLS_PROFILE_NAME}",
                )
            )

    return findings


def validate_private_helper_unit_contract(
    *,
    unit: SystemdUnitContract,
    unit_kind: str,
    expected_runner_path: str,
    expected_env_path: str,
    expected_description_fragment: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    prefix = f"{unit_kind}-unit"

    if expected_description_fragment not in unit.description:
        findings.append(_finding("warning", f"{prefix}-description", f"{unit_kind} systemd unit description diverges from the expected helper label"))
    if "network-online.target" not in unit.after:
        findings.append(_finding("warning", f"{prefix}-after", f"{unit_kind} systemd unit should order after network-online.target"))
    if "network-online.target" not in unit.wants:
        findings.append(_finding("warning", f"{prefix}-wants", f"{unit_kind} systemd unit should want network-online.target"))
    if expected_runner_path not in unit.condition_path_exists:
        findings.append(_finding("error", f"{prefix}-condition-path", f"{unit_kind} systemd unit ConditionPathExists diverges from the expected runner path"))
    normalized_env_files = {_normalize_envfile_entry(value) for value in unit.environment_files}
    if expected_env_path not in normalized_env_files:
        findings.append(_finding("warning", f"{prefix}-environment-file", f"{unit_kind} systemd unit EnvironmentFile diverges from the expected env path"))
    if "CONFIG_DIR=/etc/tracegate" not in unit.environments:
        findings.append(_finding("warning", f"{prefix}-config-dir", f"{unit_kind} systemd unit no longer exports CONFIG_DIR=/etc/tracegate"))
    if "TRACEGATE_RUNTIME_ROLE=%i" not in unit.environments:
        findings.append(_finding("warning", f"{prefix}-runtime-role", f"{unit_kind} systemd unit no longer exports TRACEGATE_RUNTIME_ROLE=%i"))
    if unit.service_type != "oneshot":
        findings.append(_finding("error", f"{prefix}-type", f"{unit_kind} systemd unit must stay Type=oneshot"))
    if unit.remain_after_exit != "yes":
        findings.append(_finding("error", f"{prefix}-remain-after-exit", f"{unit_kind} systemd unit must keep RemainAfterExit=yes"))
    expected_exec_start = f"/usr/bin/env bash {expected_runner_path} start %i"
    expected_exec_reload = f"/usr/bin/env bash {expected_runner_path} reload %i"
    expected_exec_stop = f"/usr/bin/env bash {expected_runner_path} stop %i"
    if unit.exec_start != expected_exec_start:
        findings.append(_finding("error", f"{prefix}-exec-start", f"{unit_kind} systemd unit ExecStart diverges from the helper start contract"))
    if unit.exec_reload != expected_exec_reload:
        findings.append(_finding("error", f"{prefix}-exec-reload", f"{unit_kind} systemd unit ExecReload diverges from the helper reload contract"))
    if unit.exec_stop != expected_exec_stop:
        findings.append(_finding("error", f"{prefix}-exec-stop", f"{unit_kind} systemd unit ExecStop diverges from the helper stop contract"))
    if "multi-user.target" not in unit.wanted_by:
        findings.append(_finding("warning", f"{prefix}-wanted-by", f"{unit_kind} systemd unit should remain WantedBy=multi-user.target"))

    return findings


def _validate_forbidden_public_ports(contract: dict[str, Any], *, role_prefix: str) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    contract_block = contract.get("contract")
    contract_block = contract_block if isinstance(contract_block, dict) else {}
    fronting = _fronting_block(contract)
    rows = _dict_list(contract_block.get("forbiddenPorts"))
    actual = {
        (_row_string(row, "protocol").lower(), _row_int(row, "port")): _row_string(row, "name")
        for row in rows
    }
    required = {
        ("tcp", TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT): f"blocked tcp/{TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT}",
    }
    for (protocol, port), expected_name in required.items():
        actual_name = actual.get((protocol, port))
        if actual_name != expected_name:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-forbidden-{protocol}-{port}",
                    f"{role_prefix} runtime-contract must declare {expected_name} as a forbidden public surface",
                )
            )

    forbidden_public_ports = _dict_list(fronting.get("forbiddenPublicPorts"))
    fronting_actual = {
        (_row_string(row, "protocol").lower(), _row_int(row, "port")): _row_string(row, "action").lower()
        for row in forbidden_public_ports
    }
    for protocol, port in required:
        if fronting_actual.get((protocol, port)) != "drop":
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-fronting-forbidden-{protocol}-{port}",
                    f"{role_prefix} fronting contract must mark {protocol}/{port} as drop-only",
                )
            )

    if bool(fronting.get("forbiddenUdp443", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-fronting-forbidden-udp-443-flag",
                f"{role_prefix} fronting contract has an invalid forbiddenUdp443 flag",
            )
        )
    if not bool(fronting.get("forbiddenTcp8443", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-fronting-forbidden-tcp-8443-flag",
                f"{role_prefix} fronting contract must keep forbiddenTcp8443=true",
            )
        )

    return findings


def validate_runtime_contract_single(
    contract: dict[str, Any],
    *,
    expected_role: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []

    role_upper = str(expected_role or "").strip().upper()
    role_prefix = role_upper.lower() or "unknown"
    actual_role = _role_name(contract)
    if actual_role != role_upper:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-role",
                f"{role_prefix} contract role must be {role_upper}, got {actual_role or 'missing'}",
            )
        )

    profile = _runtime_profile(contract)
    if not profile:
        findings.append(_finding("error", f"{role_prefix}-profile", f"{role_prefix} runtimeProfile is missing"))
    findings.extend(_validate_tracegate21_rollout(contract, role_prefix=role_prefix))
    findings.extend(_validate_tracegate21_transport_profiles(contract, role_prefix=role_prefix))
    findings.extend(_validate_tracegate21_network(contract, role_prefix=role_prefix))
    findings.extend(_validate_xray_api_surface(contract, role_prefix=role_prefix))
    findings.extend(_validate_forbidden_public_ports(contract, role_prefix=role_prefix))

    components = _managed_components(contract)
    if "xray" not in components:
        findings.append(_finding("error", f"{role_prefix}-xray", f"{role_prefix} managedComponents must include xray"))

    roots = _decoy_roots(contract)
    if not roots:
        findings.append(_finding("warning", f"{role_prefix}-decoy-missing", f"{role_prefix} has no decoy root in runtime-contract"))
    elif len(roots) > 1:
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-decoy-diverge",
                f"{role_prefix} decoy roots diverge across nginx/hysteria/xray: {', '.join(roots)}",
            )
        )

    if bool(_fronting_block(contract).get("touchUdp443", False)):
        findings.append(
            _finding(
                "error",
                f"{role_prefix}-fronting-touch-udp-443",
                f"{role_prefix} private fronting must not claim public udp/{TRACEGATE_PUBLIC_UDP_PORT}; keep it on the runtime owner",
            )
        )

    if profile in {"xray-centric", "tracegate-2.1"}:
        if "hysteria" in components:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-{profile}-managed-hysteria",
                    f"{profile} contracts must not declare hysteria as a managed component",
                )
            )
        if profile == "tracegate-2.1" and _xray_backhaul_allowed(contract):
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-tracegate21-xray-backhaul",
                    "tracegate-2.1 contracts must keep xrayBackhaulAllowed=false",
                )
            )
        decoy = contract.get("decoy")
        split_dirs = _string_list(decoy.get("splitHysteriaMasqueradeDirs")) if isinstance(decoy, dict) else []
        if split_dirs:
            findings.append(
                _finding(
                    "warning",
                    f"{role_prefix}-split-hysteria-stale",
                    f"{role_prefix} still exposes split Hysteria masquerade dirs in {profile} mode: {', '.join(split_dirs)}",
                )
            )
        xray_tags = _string_list(_xray_block(contract).get("hysteriaInboundTags"))
        if not xray_tags:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-hy2-inbound-missing",
                    f"{role_prefix} is {profile} but has no Xray-native Hysteria inbound tags",
                )
            )

    if profile == "tracegate-2.2":
        findings.extend(_validate_hysteria_runtime(contract, role_prefix=role_prefix))
        if "hysteria" not in components:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-tracegate22-hysteria-component",
                    "tracegate-2.2 contracts must declare hysteria as the public UDP runtime component",
                )
            )
        if _xray_backhaul_allowed(contract):
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-tracegate22-xray-backhaul",
                    "tracegate-2.2 contracts must keep xrayBackhaulAllowed=false",
                )
            )
        xray_tags = _string_list(_xray_block(contract).get("hysteriaInboundTags"))
        if xray_tags:
            findings.append(
                _finding(
                    "error",
                    f"{role_prefix}-tracegate22-xray-hysteria",
                    f"{role_prefix} tracegate-2.2 Xray config must not expose Hysteria inbound tags: {', '.join(xray_tags)}",
                )
            )

    return findings


def validate_runtime_contract_pair(
    entry_contract: dict[str, Any],
    transit_contract: dict[str, Any],
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []

    entry_role = _role_name(entry_contract)
    transit_role = _role_name(transit_contract)
    if entry_role != "ENTRY":
        findings.append(_finding("error", "entry-role", f"entry contract role must be ENTRY, got {entry_role or 'missing'}"))
    if transit_role != "TRANSIT":
        findings.append(
            _finding("error", "transit-role", f"transit contract role must be TRANSIT, got {transit_role or 'missing'}")
        )

    entry_profile = _runtime_profile(entry_contract)
    transit_profile = _runtime_profile(transit_contract)
    if not entry_profile:
        findings.append(_finding("error", "entry-profile", "entry runtimeProfile is missing"))
    if not transit_profile:
        findings.append(_finding("error", "transit-profile", "transit runtimeProfile is missing"))
    if entry_profile and transit_profile and entry_profile != transit_profile:
        findings.append(
            _finding(
                "error",
                "profile-mismatch",
                f"runtimeProfile mismatch: entry={entry_profile}, transit={transit_profile}",
            )
        )

    for role_name, contract in (("entry", entry_contract), ("transit", transit_contract)):
        findings.extend(_validate_xray_api_surface(contract, role_prefix=role_name))
        findings.extend(_validate_forbidden_public_ports(contract, role_prefix=role_name))
        components = _managed_components(contract)
        if "xray" not in components:
            findings.append(_finding("error", f"{role_name}-xray", f"{role_name} managedComponents must include xray"))

        roots = _decoy_roots(contract)
        if not roots:
            findings.append(_finding("warning", f"{role_name}-decoy-missing", f"{role_name} has no decoy root in runtime-contract"))
        elif len(roots) > 1:
            findings.append(
                _finding(
                    "error",
                    f"{role_name}-decoy-diverge",
                    f"{role_name} decoy roots diverge across nginx/hysteria/xray: {', '.join(roots)}",
                )
            )

        if bool(_fronting_block(contract).get("touchUdp443", False)):
            findings.append(
                _finding(
                    "error",
                    f"{role_name}-fronting-touch-udp-443",
                    f"{role_name} private fronting must not claim public udp/{TRACEGATE_PUBLIC_UDP_PORT}; keep it on the runtime owner",
                )
            )

    profile = entry_profile or transit_profile
    entry_xray = _xray_block(entry_contract)
    transit_xray = _xray_block(transit_contract)

    if profile in {"xray-centric", "tracegate-2.1"}:
        if "hysteria" in _managed_components(entry_contract) or "hysteria" in _managed_components(transit_contract):
            findings.append(
                _finding("error", f"{profile}-managed-hysteria", f"{profile} contracts must not declare hysteria as a managed component")
            )
        if profile == "tracegate-2.1":
            for role_name, contract in (("entry", entry_contract), ("transit", transit_contract)):
                findings.extend(_validate_tracegate21_rollout(contract, role_prefix=role_name))
                findings.extend(_validate_tracegate21_transport_profiles(contract, role_prefix=role_name))
                findings.extend(_validate_tracegate21_network(contract, role_prefix=role_name))
                if _xray_backhaul_allowed(contract):
                    findings.append(
                        _finding(
                            "error",
                            f"{role_name}-tracegate21-xray-backhaul",
                            f"{role_name} tracegate-2.1 contract must keep xrayBackhaulAllowed=false",
                        )
                    )

        for role_name, contract in (("entry", entry_contract), ("transit", transit_contract)):
            decoy = contract.get("decoy")
            split_dirs = _string_list(decoy.get("splitHysteriaMasqueradeDirs")) if isinstance(decoy, dict) else []
            if split_dirs:
                findings.append(
                    _finding(
                        "warning",
                        f"{role_name}-split-hysteria-stale",
                        f"{role_name} still exposes split Hysteria masquerade dirs in {profile} mode: {', '.join(split_dirs)}",
                    )
                )
            xray_tags = _string_list(_xray_block(contract).get("hysteriaInboundTags"))
            if not xray_tags:
                findings.append(
                    _finding(
                        "error",
                        f"{role_name}-hy2-inbound-missing",
                        f"{role_name} is {profile} but has no Xray-native Hysteria inbound tags",
                    )
                )
    if profile == "tracegate-2.2":
        for role_name, contract in (("entry", entry_contract), ("transit", transit_contract)):
            findings.extend(_validate_hysteria_runtime(contract, role_prefix=role_name))
            components = _managed_components(contract)
            if "hysteria" not in components:
                findings.append(
                    _finding(
                        "error",
                        f"{role_name}-tracegate22-hysteria-component",
                        f"{role_name} tracegate-2.2 contract must declare hysteria as the public UDP runtime component",
                    )
                )
            if _xray_backhaul_allowed(contract):
                findings.append(
                    _finding(
                        "error",
                        f"{role_name}-tracegate22-xray-backhaul",
                        f"{role_name} tracegate-2.2 contract must keep xrayBackhaulAllowed=false",
                    )
                )
            xray_tags = _string_list(_xray_block(contract).get("hysteriaInboundTags"))
            if xray_tags:
                findings.append(
                    _finding(
                        "error",
                        f"{role_name}-tracegate22-xray-hysteria",
                        f"{role_name} tracegate-2.2 Xray config must not expose Hysteria inbound tags: {', '.join(xray_tags)}",
                    )
                )
    entry_finalmask = bool(entry_xray.get("finalMaskEnabled"))
    transit_finalmask = bool(transit_xray.get("finalMaskEnabled"))
    if entry_finalmask != transit_finalmask:
        findings.append(
            _finding(
                "warning",
                "finalmask-asymmetry",
                f"FinalMask differs across roles: entry={str(entry_finalmask).lower()}, transit={str(transit_finalmask).lower()}",
            )
        )

    entry_ech = bool(entry_xray.get("echEnabled"))
    transit_ech = bool(transit_xray.get("echEnabled"))
    if entry_ech != transit_ech:
        findings.append(
            _finding(
                "warning",
                "ech-asymmetry",
                f"ECH differs across roles: entry={str(entry_ech).lower()}, transit={str(transit_ech).lower()}",
            )
        )

    return findings
