from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

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
    links: tuple[dict[str, Any], ...]


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
    generation: int
    zapret2_enabled: bool
    zapret2_host_wide_interception: bool
    zapret2_nfqueue: bool


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
        recommended_udp_ports=(443,),
    ),
    "transit": ZapretScopePolicy(
        expected_scope="transit",
        recommended_protocols=("v1", "v3", "v5", "v7"),
        allowed_surfaces=("vless_reality", "vless_ws_tls", "vless_grpc_tls", "hysteria2", "shadowtls_v3", "wstunnel"),
        recommended_tcp_ports=(443,),
        recommended_udp_ports=(443,),
    ),
    "interconnect": ZapretScopePolicy(
        expected_scope="entry-transit",
        recommended_protocols=("v2", "v4", "v6"),
        allowed_surfaces=("entry_transit_private_relay", "link_crypto_outer", "mieru_outer", "wss_carrier"),
        recommended_tcp_ports=(443,),
        recommended_udp_ports=(443,),
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
        fronting_udp_owner=str(fronting.get("udp443Owner") or "").strip(),
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
        fronting_udp_owner=str(payload.get("TRACEGATE_UDP_443_OWNER") or "").strip(),
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
        udp_443_owner=str(payload.get("udp443Owner") or "").strip(),
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
        links=tuple(_dict_list(payload.get("links"))),
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


def _fronting_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("fronting")
    return value if isinstance(value, dict) else {}


def _rollout_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("rollout")
    return value if isinstance(value, dict) else {}


def _transport_profiles_block(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("transportProfiles")
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
    if state.fronting_udp_owner != str(expected_fronting.get("udp443Owner") or "").strip():
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
    if env.fronting_udp_owner != str(expected_fronting.get("udp443Owner") or "").strip():
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
    if packet_shaping != "zapret2-scoped":
        findings.append(_finding("error", f"{code_prefix}-packet-shaping", f"{label} must keep zapret2-scoped packet shaping"))
    outer = str(obfuscation.get("outer") or "").strip().lower()
    if expected_outer and outer != expected_outer:
        findings.append(_finding("error", f"{code_prefix}-outer", f"{label} obfuscation outer must be {expected_outer}"))
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
    suffix = variant.lower() if variant else f"row-{index}"
    code_prefix = f"{prefix}-shadowtls-{suffix}"
    label = f"{role_upper.lower()} Shadowsocks2022/ShadowTLS {variant or index}"

    if _row_string(row, "protocol") != "shadowsocks2022_shadowtls":
        findings.append(_finding("error", f"{code_prefix}-protocol", f"{label} protocol must be shadowsocks2022_shadowtls"))
    if variant not in {"V5", "V6"}:
        findings.append(_finding("error", f"{code_prefix}-variant", f"{label} must use V5 or V6"))

    expected_profile = "V6-Shadowsocks2022-ShadowTLS-Chain" if variant == "V6" else "V5-Shadowsocks2022-ShadowTLS-Direct"
    if _row_string(row, "profile") != expected_profile:
        findings.append(_finding("error", f"{code_prefix}-profile", f"{label} profile name must be {expected_profile}"))

    expected_stage = "direct-transit-public"
    if variant == "V6":
        expected_stage = "entry-public-to-transit-relay" if role_upper == "ENTRY" else "transit-private-terminator"
    if _row_string(row, "stage") != expected_stage:
        findings.append(_finding("error", f"{code_prefix}-stage", f"{label} stage must be {expected_stage}"))

    if role_upper == "ENTRY" and variant != "V6":
        findings.append(_finding("error", f"{code_prefix}-entry-variant", "Entry private profile handoff must only receive V6 chain relays"))
    if role_upper == "TRANSIT" and variant not in {"V5", "V6"}:
        findings.append(_finding("error", f"{code_prefix}-transit-variant", "Transit private profile handoff only supports V5/V6 ShadowTLS entries"))

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
    expected_outer = "wss-carrier" if variant == "V6" else "shadowtls-v3"
    findings.extend(_validate_private_obfuscation(row=row, code_prefix=code_prefix, label=label, expected_outer=expected_outer))

    chain = _row_dict(row, "chain")
    if variant == "V6":
        if not chain:
            findings.append(_finding("error", f"{code_prefix}-chain", f"{label} must include Entry-Transit chain metadata"))
        else:
            if str(chain.get("type") or "").strip() != "entry_transit_private_relay":
                findings.append(_finding("error", f"{code_prefix}-chain-type", f"{label} chain type must be entry_transit_private_relay"))
            if str(chain.get("linkClass") or "").strip() != "entry-transit":
                findings.append(_finding("error", f"{code_prefix}-chain-class", f"{label} chain linkClass must be entry-transit"))
            if str(chain.get("carrier") or "").strip().lower() != "mieru":
                findings.append(_finding("error", f"{code_prefix}-chain-carrier", f"{label} chain carrier must be mieru"))
            if str(chain.get("preferredOuter") or "").strip().lower() != "wss-carrier":
                findings.append(_finding("error", f"{code_prefix}-chain-outer", f"{label} chain preferredOuter must be wss-carrier"))
            if str(chain.get("outerCarrier") or "").strip().lower() != "websocket-tls":
                findings.append(_finding("error", f"{code_prefix}-chain-outer-carrier", f"{label} chain outerCarrier must be websocket-tls"))
            if str(chain.get("optionalPacketShaping") or "").strip().lower() != "zapret2-scoped":
                findings.append(_finding("error", f"{code_prefix}-chain-packet-shaping", f"{label} chain packet shaping must be zapret2-scoped"))
            if str(chain.get("managedBy") or "").strip() != "link-crypto":
                findings.append(_finding("error", f"{code_prefix}-chain-managed-by", f"{label} chain must be managed by link-crypto"))
            selected_profiles = chain.get("selectedProfiles")
            if not isinstance(selected_profiles, list) or not {"V2", "V4", "V6"}.issubset(
                {str(item).strip() for item in selected_profiles}
            ):
                findings.append(_finding("error", f"{code_prefix}-chain-selected-profiles", f"{label} chain must cover V2/V4/V6"))
            if bool(chain.get("xrayBackhaul", True)):
                findings.append(_finding("error", f"{code_prefix}-chain-xray-backhaul", f"{label} chain must stay outside Xray backhaul"))
    elif chain:
        findings.append(_finding("warning", f"{code_prefix}-chain", f"{label} direct V5 profile should not carry chain metadata"))

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
        findings.append(_finding("error", f"{prefix}-wireguard-entry", "Entry private profile handoff must not receive V7 WireGuard/WSTunnel entries"))
    if _row_string(row, "protocol") != "wireguard_wstunnel":
        findings.append(_finding("error", f"{code_prefix}-protocol", f"{label} protocol must be wireguard_wstunnel"))
    if _row_string(row, "variant").upper() != "V7":
        findings.append(_finding("error", f"{code_prefix}-variant", f"{label} must use V7"))
    if _row_string(row, "profile") != "V7-WireGuard-WSTunnel-Direct":
        findings.append(_finding("error", f"{code_prefix}-profile", f"{label} profile name must be V7-WireGuard-WSTunnel-Direct"))
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
_LINK_CRYPTO_REQUIRED_PROFILES = {
    "entry-transit": {"V2", "V4", "V6"},
    "router-entry": {"V2", "V4", "V6"},
    "router-transit": {"V1", "V3", "V5", "V7"},
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
    if contract_enabled != bool(state.total_count):
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

    return findings


def _validate_link_crypto_counts(
    *,
    state: LinkCryptoState,
    prefix: str,
) -> list[RuntimePreflightFinding]:
    findings: list[RuntimePreflightFinding] = []
    by_class = {link_class: len([row for row in state.links if _row_string(row, "class") == link_class]) for link_class in _LINK_CRYPTO_CLASSES}
    if state.total_count != len(state.links):
        findings.append(_finding("error", f"{prefix}-count-total", f"{prefix.replace('-', ' ')} total count diverges from links"))
    if state.entry_transit_count != by_class["entry-transit"]:
        findings.append(_finding("error", f"{prefix}-count-entry-transit", f"{prefix.replace('-', ' ')} entry-transit count diverges from links"))
    if state.router_entry_count != by_class["router-entry"]:
        findings.append(_finding("error", f"{prefix}-count-router-entry", f"{prefix.replace('-', ' ')} router-entry count diverges from links"))
    if state.router_transit_count != by_class["router-transit"]:
        findings.append(_finding("error", f"{prefix}-count-router-transit", f"{prefix.replace('-', ' ')} router-transit count diverges from links"))
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
        if required_profiles and not required_profiles.issubset(selected_profile_set):
            findings.append(
                _finding(
                    "error",
                    f"{code_prefix}-selected-profiles",
                    f"{label} must cover {'/'.join(sorted(required_profiles))} profiles",
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
    if env.generation < 1:
        findings.append(_finding("error", f"{prefix}-generation", f"{prefix.replace('-', ' ')} generation must be positive"))
    if env.zapret2_host_wide_interception:
        findings.append(_finding("error", f"{prefix}-zapret2-host-wide", f"{prefix.replace('-', ' ')} must not enable host-wide interception"))
    if env.zapret2_nfqueue:
        findings.append(_finding("error", f"{prefix}-zapret2-nfqueue", f"{prefix.replace('-', ' ')} must not enable broad NFQUEUE"))

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
        findings.append(_finding("error", "fronting-touch-udp-443", "fronting runtime-state must not claim udp/443"))

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
        findings.append(_finding("error", "fronting-env-touch-udp-443", "fronting env must not claim udp/443"))
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
    findings.extend(_validate_xray_api_surface(contract, role_prefix=role_prefix))

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
                f"{role_prefix} private fronting must not claim udp/443; keep udp/443 on the runtime owner",
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
                    f"{role_name} private fronting must not claim udp/443; keep udp/443 on the runtime owner",
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
