import json
from pathlib import Path

import pytest

from tracegate.cli import validate_runtime_contracts
from tracegate.constants import (
    TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT,
    TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT,
    TRACEGATE_PUBLIC_UDP_PORT,
)
from tracegate.services.runtime_preflight import (
    RuntimePreflightError,
    load_link_crypto_env,
    load_link_crypto_state,
    load_obfuscation_env_contract,
    load_fronting_env_contract,
    load_fronting_runtime_state,
    load_mtproto_env_contract,
    load_mtproto_gateway_state,
    load_mtproto_public_profile,
    load_obfuscation_runtime_env,
    load_obfuscation_runtime_state,
    load_private_profile_env,
    load_private_profile_state,
    load_router_client_bundle,
    load_router_client_bundle_env,
    load_router_handoff_env,
    load_router_handoff_state,
    load_runtime_contract,
    load_systemd_unit_contract,
    load_zapret_profile,
    validate_obfuscation_env_contract,
    validate_obfuscation_runtime_env,
    validate_fronting_env_contract,
    validate_fronting_runtime_state,
    validate_link_crypto_env,
    validate_link_crypto_state,
    validate_mtproto_env_contract,
    validate_mtproto_gateway_state,
    validate_private_helper_unit_contract,
    validate_private_profile_env,
    validate_private_profile_state,
    validate_router_client_bundle,
    validate_router_client_bundle_env,
    validate_obfuscation_runtime_state,
    validate_router_handoff_env,
    validate_router_handoff_state,
    validate_runtime_contract_pair,
    validate_runtime_contract_single,
    validate_zapret_profile_collection,
)
from tracegate.services.runtime_contract import (
    TRACEGATE21_CLIENT_PROFILES,
    TRACEGATE22_CLIENT_PROFILES,
    XRAY_CENTRIC_CLIENT_PROFILES,
)


def _runtime_contract(
    *,
    role: str,
    runtime_profile: str = "xray-centric",
    managed_components: list[str] | None = None,
    nginx_roots: list[str] | None = None,
    split_hysteria_dirs: list[str] | None = None,
    xray_hysteria_dirs: list[str] | None = None,
    hysteria_tags: list[str] | None = None,
    xray_config_paths: list[str] | None = None,
    finalmask: bool = False,
    ech: bool = False,
    touch_udp_443: bool = False,
    transport_profiles: dict | None = None,
) -> dict:
    role_suffix = role.strip().lower()
    if transport_profiles is None:
        if runtime_profile == "tracegate-2.2":
            client_names = TRACEGATE22_CLIENT_PROFILES
        elif runtime_profile == "tracegate-2.1":
            client_names = TRACEGATE21_CLIENT_PROFILES
        else:
            client_names = XRAY_CENTRIC_CLIENT_PROFILES
        transport_profiles = {
            "clientNames": list(client_names),
            "localSocks": {"auth": "required", "allowAnonymousLocalhost": False},
            "clientExposure": {
                "defaultMode": "vpn-tun",
                "localProxyExports": "advanced-only",
                "lanSharing": "forbidden",
                "unauthenticatedLocalProxy": "forbidden",
            },
        }
    local_socks = transport_profiles.get("localSocks") if isinstance(transport_profiles, dict) else {}
    local_socks_auth = str(local_socks.get("auth") or "").strip().lower() if isinstance(local_socks, dict) else ""
    default_managed_components = ["xray", "haproxy", "nginx"]
    if runtime_profile == "tracegate-2.2":
        default_managed_components.append("hysteria")
    default_split_hysteria_dirs = ["/srv/decoy"] if runtime_profile == "tracegate-2.2" else []
    default_xray_hysteria_dirs = [] if runtime_profile == "tracegate-2.2" else ["/srv/decoy"]
    default_hysteria_tags = [] if runtime_profile == "tracegate-2.2" else ["hy2-in"]
    return {
        "role": role,
        "runtimeProfile": runtime_profile,
        "localSocksAuth": local_socks_auth or "disabled",
        "contract": {
            "managedComponents": managed_components if managed_components is not None else default_managed_components,
            "xrayBackhaulAllowed": runtime_profile not in {"tracegate-2.1", "tracegate-2.2"},
            "forbiddenPorts": [
                {"protocol": "udp", "port": TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, "name": "blocked udp/443"},
                {"protocol": "tcp", "port": TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT, "name": "blocked tcp/8443"},
            ],
        },
        "rollout": {
            "gatewayStrategy": "RollingUpdate",
            "allowRecreateStrategy": False,
            "maxUnavailable": "0",
            "maxSurge": "1",
            "progressDeadlineSeconds": 600,
            "pdbMinAvailable": "1",
            "probesEnabled": True,
            "privatePreflightEnabled": True,
            "privatePreflightForbidPlaceholders": True,
        },
        "fronting": {
            "tcp443Owner": "haproxy",
            "publicUdpPort": TRACEGATE_PUBLIC_UDP_PORT,
            "publicUdpOwner": "xray" if runtime_profile == "xray-centric" else "hysteria",
            "udp443Owner": "xray" if runtime_profile == "xray-centric" else "hysteria",
            "udpPublicPort": TRACEGATE_PUBLIC_UDP_PORT,
            "forbiddenUdp443": True,
            "forbiddenTcp8443": True,
            "forbiddenPublicPorts": [
                {"protocol": "udp", "port": TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, "action": "drop"},
                {"protocol": "tcp", "port": TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT, "action": "drop"},
            ],
            "touchUdp443": touch_udp_443,
            "mtprotoDomain": "proxied.tracegate.su" if role == "TRANSIT" else "",
            "mtprotoPublicPort": 443,
            "mtprotoFrontingMode": "dedicated-dns-only",
        },
        "transportProfiles": transport_profiles,
        "network": {
            "egressIsolation": {
                "required": True,
                "mode": "dedicated-egress-ip",
                "ingressPublicIPs": ["203.0.113.10"],
                "egressPublicIPs": ["198.51.100.20"],
                "forbidIngressIpAsEgress": True,
                "requireTransitEgressPublicIP": True,
                "clientLeakMitigation": "egress-ip-only",
                "enforcement": {
                    "mode": "operator-managed",
                    "managedBy": "/etc/tracegate/private/egress-isolation",
                    "snat": "required",
                    "ingressPublicIpOutbound": "forbidden",
                },
            }
        },
        "decoy": {
            "nginxRoots": nginx_roots if nginx_roots is not None else ["/srv/decoy"],
            "splitHysteriaMasqueradeDirs": split_hysteria_dirs
            if split_hysteria_dirs is not None
            else default_split_hysteria_dirs,
            "xrayHysteriaMasqueradeDirs": xray_hysteria_dirs
            if xray_hysteria_dirs is not None
            else default_xray_hysteria_dirs,
        },
        "xray": {
            "configPaths": (
                xray_config_paths
                if xray_config_paths is not None
                else [f"/var/lib/tracegate/agent-{role_suffix}/runtime/xray/config.json"]
            ),
            "hysteriaInboundTags": hysteria_tags if hysteria_tags is not None else default_hysteria_tags,
            "finalMaskEnabled": finalmask,
            "echEnabled": ech,
        },
        "hysteria": {
            "configPath": f"/var/lib/tracegate/agent-{role_suffix}/runtime/hysteria/server.yaml",
            "configPresent": runtime_profile == "tracegate-2.2",
            "listen": f":{TRACEGATE_PUBLIC_UDP_PORT}",
            "listenPort": TRACEGATE_PUBLIC_UDP_PORT,
            "auth": {
                "type": "http",
                "httpUrl": "http://127.0.0.1:8070/v1/hysteria/auth",
                "httpInsecure": False,
            },
            "obfs": {"type": "salamander", "salamanderPasswordConfigured": True},
            "trafficStats": {"listen": "127.0.0.1:9999", "secretConfigured": True},
            "tls": {"certConfigured": True, "keyConfigured": True, "sniGuard": "dns-san"},
            "udp": {"enabled": True, "idleTimeout": "60s"},
            "quic": {"disablePathMTUDiscovery": False, "maxIdleTimeout": "30s"},
            "congestion": {"type": "bbr"},
            "sniff": {"enabled": True, "timeout": "2s"},
            "masqueradeDirs": default_split_hysteria_dirs,
        },
    }


def _write_zapret_profile(tmp_path: Path, file_name: str, **overrides: str) -> Path:
    defaults = {
        "entry-lite.env": {
            "TRACEGATE_ZAPRET_PROFILE_NAME": "entry-lite",
            "TRACEGATE_ZAPRET_SCOPE": "entry",
            "TRACEGATE_ZAPRET_CPU_BUDGET": "low",
            "TRACEGATE_ZAPRET_APPLY_MODE": "selective",
            "TRACEGATE_ZAPRET_TARGET_TCP_PORTS": "443",
            "TRACEGATE_ZAPRET_TARGET_UDP_PORTS": "8443",
            "TRACEGATE_ZAPRET_TARGET_PROTOCOLS": "v2,v4,v6",
            "TRACEGATE_ZAPRET_TARGET_SURFACES": "vless_reality,hysteria2,shadowtls_v3",
            "TRACEGATE_ZAPRET_TOUCH_UNRELATED_SYSTEM_TRAFFIC": "false",
            "TRACEGATE_ZAPRET_MAX_WORKERS": "1",
            "TRACEGATE_ZAPRET_NOTES": "Entry profile",
        },
        "transit-lite.env": {
            "TRACEGATE_ZAPRET_PROFILE_NAME": "transit-lite",
            "TRACEGATE_ZAPRET_SCOPE": "transit",
            "TRACEGATE_ZAPRET_CPU_BUDGET": "low",
            "TRACEGATE_ZAPRET_APPLY_MODE": "selective",
            "TRACEGATE_ZAPRET_TARGET_TCP_PORTS": "443",
            "TRACEGATE_ZAPRET_TARGET_UDP_PORTS": "8443",
            "TRACEGATE_ZAPRET_TARGET_PROTOCOLS": "v1,v3,v5,v7",
            "TRACEGATE_ZAPRET_TARGET_SURFACES": "vless_reality,vless_ws_tls,vless_grpc_tls,hysteria2,shadowtls_v3,wstunnel",
            "TRACEGATE_ZAPRET_TOUCH_UNRELATED_SYSTEM_TRAFFIC": "false",
            "TRACEGATE_ZAPRET_MAX_WORKERS": "1",
            "TRACEGATE_ZAPRET_NOTES": "Transit profile",
        },
        "entry-transit-stealth.env": {
            "TRACEGATE_ZAPRET_PROFILE_NAME": "entry-transit-stealth",
            "TRACEGATE_ZAPRET_SCOPE": "entry-transit",
            "TRACEGATE_ZAPRET_CPU_BUDGET": "low",
            "TRACEGATE_ZAPRET_APPLY_MODE": "selective",
            "TRACEGATE_ZAPRET_TARGET_TCP_PORTS": "443",
            "TRACEGATE_ZAPRET_TARGET_UDP_PORTS": "8443",
            "TRACEGATE_ZAPRET_TARGET_PROTOCOLS": "v2,v4,v6",
            "TRACEGATE_ZAPRET_TARGET_SURFACES": "entry_transit_private_relay,link_crypto_outer,mieru_outer,wss_carrier",
            "TRACEGATE_ZAPRET_TOUCH_UNRELATED_SYSTEM_TRAFFIC": "false",
            "TRACEGATE_ZAPRET_MAX_WORKERS": "1",
            "TRACEGATE_ZAPRET_NOTES": "Entry-Transit interconnect profile",
        },
        "mtproto-extra.env": {
            "TRACEGATE_ZAPRET_PROFILE_NAME": "mtproto-extra",
            "TRACEGATE_ZAPRET_SCOPE": "mtproto",
            "TRACEGATE_ZAPRET_CPU_BUDGET": "low",
            "TRACEGATE_ZAPRET_APPLY_MODE": "selective",
            "TRACEGATE_ZAPRET_TARGET_TCP_PORTS": "443",
            "TRACEGATE_ZAPRET_TARGET_UDP_PORTS": "",
            "TRACEGATE_ZAPRET_TARGET_PROTOCOLS": "mtproto",
            "TRACEGATE_ZAPRET_TARGET_SURFACES": "telegram-mtproto",
            "TRACEGATE_ZAPRET_TOUCH_UNRELATED_SYSTEM_TRAFFIC": "false",
            "TRACEGATE_ZAPRET_MAX_WORKERS": "1",
            "TRACEGATE_ZAPRET_NOTES": "MTProto profile",
        },
    }[file_name]
    payload = {**defaults, **overrides}
    path = tmp_path / file_name
    path.write_text(
        "\n".join(f"{key}={value}" for key, value in payload.items()) + "\n",
        encoding="utf-8",
    )
    return path


def _write_runtime_state(
    tmp_path: Path,
    file_name: str,
    *,
    contract: dict,
    role: str,
    runtime_contract_path: str | None = None,
    interface: str = "eth0",
    backend: str = "zapret2",
    zapret_profile_file: str = "",
    zapret_interconnect_profile_file: str = "",
    zapret_mtproto_profile_file: str = "",
    zapret_policy_dir: str = "/etc/tracegate/private/zapret",
    zapret_state_dir: str = "/var/lib/tracegate/private/zapret",
    overrides: dict | None = None,
) -> Path:
    role_upper = role.strip().upper()
    role_lower = role.strip().lower()
    if not zapret_interconnect_profile_file:
        zapret_interconnect_profile_file = str(tmp_path / "zapret" / "entry-transit-stealth.env")
    fronting = contract["fronting"]
    xray = contract["xray"]
    payload = {
        "role": role_upper,
        "interface": interface,
        "runtimeProfile": contract["runtimeProfile"],
        "runtimeContractPath": runtime_contract_path or f"/var/lib/tracegate/agent-{role_lower}/runtime/runtime-contract.json",
        "contractPresent": True,
        "backend": backend,
        "decoyRoots": list(contract["decoy"]["nginxRoots"]),
        "splitHysteriaMasqueradeDirs": list(contract["decoy"]["splitHysteriaMasqueradeDirs"]),
        "xrayHysteriaMasqueradeDirs": list(contract["decoy"]["xrayHysteriaMasqueradeDirs"]),
        "xrayConfigPaths": list(xray["configPaths"]),
        "xrayHysteriaInboundTags": list(xray["hysteriaInboundTags"]),
        "finalMaskEnabled": bool(xray["finalMaskEnabled"]),
        "echEnabled": bool(xray["echEnabled"]),
        "public": {
            "zapretProfileFile": zapret_profile_file,
            "zapretInterconnectProfileFile": zapret_interconnect_profile_file,
            "zapretMtprotoProfileFile": zapret_mtproto_profile_file,
            "zapretPolicyDir": zapret_policy_dir,
            "zapretStateDir": zapret_state_dir,
        },
        "fronting": {
            "tcp443Owner": fronting["tcp443Owner"],
            "publicUdpPort": fronting.get("publicUdpPort", TRACEGATE_PUBLIC_UDP_PORT),
            "publicUdpOwner": fronting["udp443Owner"],
            "udp443Owner": fronting["udp443Owner"],
            "touchUdp443": bool(fronting["touchUdp443"]),
            "mtprotoDomain": fronting["mtprotoDomain"],
            "mtprotoPublicPort": int(fronting["mtprotoPublicPort"]),
            "mtprotoFrontingMode": fronting["mtprotoFrontingMode"],
        },
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path


def _shell_quote(value: object) -> str:
    raw = str(value)
    return "'" + raw.replace("'", "'\"'\"'") + "'"


def _write_runtime_env(
    tmp_path: Path,
    file_name: str,
    *,
    contract: dict,
    role: str,
    runtime_state_json: str,
    runtime_contract_path: str | None = None,
    interface: str = "eth0",
    backend: str = "zapret2",
    zapret_profile_file: str = "",
    zapret_interconnect_profile_file: str = "",
    zapret_mtproto_profile_file: str = "",
    zapret_policy_dir: str = "/etc/tracegate/private/zapret",
    zapret_state_dir: str = "/var/lib/tracegate/private/zapret",
    contract_present: bool = True,
    overrides: dict[str, object] | None = None,
) -> Path:
    role_upper = role.strip().upper()
    role_lower = role.strip().lower()
    if not zapret_interconnect_profile_file:
        zapret_interconnect_profile_file = str(tmp_path / "zapret" / "entry-transit-stealth.env")
    fronting = contract["fronting"]
    xray = contract["xray"]
    payload: dict[str, object] = {
        "TRACEGATE_RUNTIME_ROLE": role_upper,
        "TRACEGATE_NETWORK_INTERFACE": interface,
        "TRACEGATE_RUNTIME_PROFILE": contract["runtimeProfile"],
        "TRACEGATE_RUNTIME_CONTRACT": runtime_contract_path or f"/var/lib/tracegate/agent-{role_lower}/runtime/runtime-contract.json",
        "TRACEGATE_RUNTIME_CONTRACT_PRESENT": str(contract_present).lower(),
        "TRACEGATE_RUNTIME_STATE_JSON": runtime_state_json,
        "TRACEGATE_OBFUSCATION_BACKEND": backend,
        "TRACEGATE_DECOY_ROOTS": ":".join(contract["decoy"]["nginxRoots"]),
        "TRACEGATE_SPLIT_HYSTERIA_DIRS": ":".join(contract["decoy"]["splitHysteriaMasqueradeDirs"]),
        "TRACEGATE_XRAY_HYSTERIA_DIRS": ":".join(contract["decoy"]["xrayHysteriaMasqueradeDirs"]),
        "TRACEGATE_XRAY_CONFIG_PATHS": ":".join(xray["configPaths"]),
        "TRACEGATE_XRAY_HYSTERIA_TAGS": ":".join(xray["hysteriaInboundTags"]),
        "TRACEGATE_FINALMASK_ENABLED": str(bool(xray["finalMaskEnabled"])).lower(),
        "TRACEGATE_ECH_ENABLED": str(bool(xray["echEnabled"])).lower(),
        "TRACEGATE_ZAPRET_PROFILE_FILE": zapret_profile_file,
        "TRACEGATE_ZAPRET_INTERCONNECT_PROFILE_FILE": zapret_interconnect_profile_file,
        "TRACEGATE_ZAPRET_MTPROTO_PROFILE_FILE": zapret_mtproto_profile_file,
        "TRACEGATE_ZAPRET_POLICY_DIR": zapret_policy_dir,
        "TRACEGATE_ZAPRET_STATE_DIR": zapret_state_dir,
        "TRACEGATE_TCP_443_OWNER": fronting["tcp443Owner"],
        "TRACEGATE_PUBLIC_UDP_PORT": fronting.get("publicUdpPort", TRACEGATE_PUBLIC_UDP_PORT),
        "TRACEGATE_PUBLIC_UDP_OWNER": fronting["udp443Owner"],
        "TRACEGATE_UDP_443_OWNER": fronting["udp443Owner"],
        "TRACEGATE_TOUCH_UDP_443": str(bool(fronting["touchUdp443"])).lower(),
        "TRACEGATE_MTPROTO_DOMAIN": fronting["mtprotoDomain"],
        "TRACEGATE_MTPROTO_PUBLIC_PORT": int(fronting["mtprotoPublicPort"]),
        "TRACEGATE_MTPROTO_FRONTING_MODE": fronting["mtprotoFrontingMode"],
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(f"{key}={_shell_quote(value)}" for key, value in payload.items()) + "\n",
        encoding="utf-8",
    )
    return path


def _write_obfuscation_env(tmp_path: Path, file_name: str, **overrides: str) -> Path:
    payload = {
        "TRACEGATE_OBFUSCATION_ENABLED": "true",
        "TRACEGATE_OBFUSCATION_BACKEND": "zapret2",
        "TRACEGATE_PRIVATE_RUNTIME_DIR": str(tmp_path / "private"),
        "TRACEGATE_ZAPRET_ROOT": str(tmp_path / "zapret2-private"),
        "TRACEGATE_ZAPRET_RUNNER": str(tmp_path / "zapret2-private" / "tracegate-zapret-wrapper"),
        "TRACEGATE_ZAPRET_POLICY_DIR": str(tmp_path / "etc" / "tracegate" / "private" / "zapret"),
        "TRACEGATE_ZAPRET_STATE_DIR": str(tmp_path / "private" / "zapret"),
        "TRACEGATE_ZAPRET_PROFILE_DIR": str(tmp_path / "zapret"),
        "TRACEGATE_ZAPRET_PROFILE_ENTRY": "entry-lite.env",
        "TRACEGATE_ZAPRET_PROFILE_TRANSIT": "transit-lite.env",
        "TRACEGATE_ZAPRET_PROFILE_INTERCONNECT": "entry-transit-stealth.env",
        "TRACEGATE_ZAPRET_PROFILE_MTPROTO": "mtproto-extra.env",
        "TRACEGATE_FINALMASK_MODE": "overlay",
        "TRACEGATE_ENTRY_RUNTIME_CONTRACT": str(tmp_path / "entry.json"),
        "TRACEGATE_TRANSIT_RUNTIME_CONTRACT": str(tmp_path / "transit.json"),
        "TRACEGATE_ENTRY_INTERFACE": "eth0",
        "TRACEGATE_TRANSIT_INTERFACE": "eth0",
    }
    payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"{key}={value}" for key, value in payload.items()) + "\n", encoding="utf-8")
    return path


def _write_private_helper_unit(
    tmp_path: Path,
    file_name: str,
    *,
    description: str,
    condition_path_exists: str,
    environment_file: str,
    runner_path: str,
    overrides: dict[str, str] | None = None,
) -> Path:
    payload = {
        "Description": description,
        "ConditionPathExists": condition_path_exists,
        "EnvironmentFile": f"-{environment_file}",
        "ExecStart": f"/usr/bin/env bash {runner_path} start %i",
        "ExecReload": f"/usr/bin/env bash {runner_path} reload %i",
        "ExecStop": f"/usr/bin/env bash {runner_path} stop %i",
        "Type": "oneshot",
        "RemainAfterExit": "yes",
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "[Unit]",
                f"Description={payload['Description']}",
                "After=network-online.target",
                "Wants=network-online.target",
                f"ConditionPathExists={payload['ConditionPathExists']}",
                "",
                "[Service]",
                f"Type={payload['Type']}",
                f"RemainAfterExit={payload['RemainAfterExit']}",
                f"EnvironmentFile={payload['EnvironmentFile']}",
                "Environment=CONFIG_DIR=/etc/tracegate",
                "Environment=TRACEGATE_RUNTIME_ROLE=%i",
                f"ExecStart={payload['ExecStart']}",
                f"ExecReload={payload['ExecReload']}",
                f"ExecStop={payload['ExecStop']}",
                "",
                "[Install]",
                "WantedBy=multi-user.target",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def _write_fronting_state(
    tmp_path: Path,
    file_name: str,
    *,
    runtime_state_json: str,
    overrides: dict | None = None,
) -> Path:
    payload = {
        "timestamp": "2026-04-17T00:00:00+00:00",
        "action": "start",
        "role": "TRANSIT",
        "backend": "private",
        "runtimeStateJson": runtime_state_json,
        "listenAddr": "127.0.0.1:10443",
        "protocol": "tcp",
        "realityUpstream": "127.0.0.1:2443",
        "wsTlsUpstream": "127.0.0.1:4443",
        "mtprotoUpstream": "127.0.0.1:9443",
        "mtprotoProfileFile": "/etc/tracegate/private/zapret/mtproto-extra.env",
        "touchUdp443": False,
        "mtprotoDomain": "proxied.tracegate.su",
        "mtprotoFrontingMode": "dedicated-dns-only",
        "tcp443Owner": "haproxy",
        "publicUdpPort": TRACEGATE_PUBLIC_UDP_PORT,
        "publicUdpOwner": "xray",
        "udp443Owner": "xray",
        "cfgFile": "/var/lib/tracegate/private/fronting/runtime/haproxy.cfg",
        "pidFile": "/var/lib/tracegate/private/fronting/runtime/haproxy.pid",
        "wsSni": "nlconn.tracegate.su",
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path


def _write_mtproto_state(
    tmp_path: Path,
    file_name: str,
    *,
    runtime_state_json: str,
    overrides: dict | None = None,
) -> Path:
    payload = {
        "timestamp": "2026-04-17T00:00:00+00:00",
        "action": "start",
        "role": "TRANSIT",
        "backend": "private",
        "domain": "proxied.tracegate.su",
        "publicPort": 443,
        "upstreamHost": "127.0.0.1",
        "upstreamPort": 9443,
        "profileFile": "/etc/tracegate/private/zapret/mtproto-extra.env",
        "runtimeStateJson": runtime_state_json,
        "publicProfileFile": "/var/lib/tracegate/private/mtproto/public-profile.json",
    }
    if overrides:
        payload.update(overrides)
    if "issuedStateFile" not in payload:
        payload["issuedStateFile"] = str(Path(str(payload["publicProfileFile"])).with_name("issued.json"))
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path


def _write_mtproto_public_profile(tmp_path: Path, file_name: str, *, overrides: dict | None = None) -> Path:
    payload = {
        "protocol": "mtproto",
        "profile": "MTProto-FakeTLS-Direct",
        "server": "proxied.tracegate.su",
        "port": 443,
        "transport": "tls",
        "domain": "proxied.tracegate.su",
        "clientSecretHex": "ee00112233445566778899aabbccddeeff70726f786965642e7472616365676174652e7375",
        "tgUri": "tg://proxy?server=proxied.tracegate.su&port=443&secret=ee0011",
        "httpsUrl": "https://t.me/proxy?server=proxied.tracegate.su&port=443&secret=ee0011",
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path


def _write_fronting_env(tmp_path: Path, file_name: str, **overrides: str) -> Path:
    payload = {
        "TRACEGATE_FRONTING_ENABLED": "true",
        "TRACEGATE_FRONTING_ROLE": "transit",
        "TRACEGATE_FRONTING_BACKEND": "private",
        "TRACEGATE_FRONTING_RUNTIME_STATE_JSON": str(tmp_path / "transit-runtime-state.json"),
        "TRACEGATE_FRONTING_LISTEN_ADDR": "127.0.0.1:10443",
        "TRACEGATE_FRONTING_PROTOCOL": "tcp",
        "TRACEGATE_FRONTING_REALITY_UPSTREAM": "127.0.0.1:2443",
        "TRACEGATE_FRONTING_WS_TLS_UPSTREAM": "127.0.0.1:4443",
        "TRACEGATE_FRONTING_MTPROTO_UPSTREAM": "127.0.0.1:9443",
        "TRACEGATE_FRONTING_MTPROTO_PROFILE_FILE": str(tmp_path / "mtproto-extra.env"),
        "TRACEGATE_FRONTING_STATE_DIR": "/var/lib/tracegate/private/fronting",
        "TRACEGATE_FRONTING_RUNTIME_DIR": "/var/lib/tracegate/private/fronting/runtime",
        "TRACEGATE_FRONTING_RUNNER": "/opt/fronting-private/tracegate-fronting-gateway",
        "TRACEGATE_FRONTING_HAPROXY_BIN": "/usr/sbin/haproxy",
        "TRACEGATE_FRONTING_WS_SNI": "nlconn.tracegate.su",
        "TRACEGATE_FRONTING_MTPROTO_DOMAIN_OVERRIDE": "",
        "TRACEGATE_FRONTING_TOUCH_UDP_443": "false",
        "TRACEGATE_FRONTING_NOTES": "test fronting env",
    }
    payload.update(overrides)
    path = tmp_path / file_name
    path.write_text("\n".join(f"{key}={value}" for key, value in payload.items()) + "\n", encoding="utf-8")
    return path


def _write_mtproto_env(tmp_path: Path, file_name: str, **overrides: str) -> Path:
    payload = {
        "TRACEGATE_MTPROTO_ENABLED": "true",
        "TRACEGATE_MTPROTO_ROLE": "transit",
        "TRACEGATE_MTPROTO_BACKEND": "private",
        "TRACEGATE_MTPROTO_RUNTIME_STATE_JSON": str(tmp_path / "transit-runtime-state.json"),
        "TRACEGATE_MTPROTO_PROFILE_FILE": str(tmp_path / "mtproto-extra.env"),
        "TRACEGATE_MTPROTO_DOMAIN": "proxied.tracegate.su",
        "TRACEGATE_MTPROTO_PUBLIC_PORT": "443",
        "TRACEGATE_MTPROTO_UPSTREAM_HOST": "127.0.0.1",
        "TRACEGATE_MTPROTO_UPSTREAM_PORT": "9443",
        "TRACEGATE_MTPROTO_TLS_MODE": "private-fronting",
        "TRACEGATE_MTPROTO_SECRET_FILE": "/etc/tracegate/private/mtproto/secret.txt",
        "TRACEGATE_MTPROTO_STATE_DIR": "/var/lib/tracegate/private/mtproto",
        "TRACEGATE_MTPROTO_ISSUED_STATE_FILE": "/var/lib/tracegate/private/mtproto/issued.json",
        "TRACEGATE_MTPROTO_BINARY": "/opt/MTProxy/objs/bin/mtproto-proxy",
        "TRACEGATE_MTPROTO_RUNTIME_DIR": "/var/lib/tracegate/private/mtproto/runtime",
        "TRACEGATE_MTPROTO_STATS_PORT": "9888",
        "TRACEGATE_MTPROTO_RUN_AS_USER": "nobody",
        "TRACEGATE_MTPROTO_WORKERS": "1",
        "TRACEGATE_MTPROTO_PROXY_TAG": "",
        "TRACEGATE_MTPROTO_FETCH_SECRET_URL": "https://core.telegram.org/getProxySecret",
        "TRACEGATE_MTPROTO_FETCH_CONFIG_URL": "https://core.telegram.org/getProxyConfig",
        "TRACEGATE_MTPROTO_BOOTSTRAP_MAX_AGE_SECONDS": "86400",
        "TRACEGATE_MTPROTO_NOTES": "test mtproto env",
    }
    payload.update(overrides)
    state_dir = str(payload["TRACEGATE_MTPROTO_STATE_DIR"])
    runtime_dir = str(payload["TRACEGATE_MTPROTO_RUNTIME_DIR"])
    payload["TRACEGATE_MTPROTO_ISSUED_STATE_FILE"] = overrides.get(
        "TRACEGATE_MTPROTO_ISSUED_STATE_FILE",
        f"{state_dir}/issued.json",
    )
    payload["TRACEGATE_MTPROTO_PROXY_SECRET_FILE"] = overrides.get(
        "TRACEGATE_MTPROTO_PROXY_SECRET_FILE",
        f"{runtime_dir}/proxy-secret",
    )
    payload["TRACEGATE_MTPROTO_PROXY_CONFIG_FILE"] = overrides.get(
        "TRACEGATE_MTPROTO_PROXY_CONFIG_FILE",
        f"{runtime_dir}/proxy-multi.conf",
    )
    payload["TRACEGATE_MTPROTO_PID_FILE"] = overrides.get(
        "TRACEGATE_MTPROTO_PID_FILE",
        f"{runtime_dir}/mtproto-proxy.pid",
    )
    payload["TRACEGATE_MTPROTO_LOG_FILE"] = overrides.get(
        "TRACEGATE_MTPROTO_LOG_FILE",
        f"{runtime_dir}/mtproto-proxy.log",
    )
    path = tmp_path / file_name
    path.write_text("\n".join(f"{key}={value}" for key, value in payload.items()) + "\n", encoding="utf-8")
    return path


def _private_local_socks(username: str = "tg_user", password: str = "tg_pass") -> dict:
    return {
        "enabled": True,
        "listen": "127.0.0.1:28108",
        "auth": {
            "required": True,
            "mode": "username_password",
            "username": username,
            "password": password,
        },
    }


def _private_shadowtls_profile(
    *,
    role: str,
    mode: str = "chain",
    variant: str = "V3",
    overrides: dict | None = None,
) -> dict:
    role_upper = role.strip().upper()
    variant_upper = variant.strip().upper()
    mode_lower = mode.strip().lower()
    is_chain = mode_lower == "chain"
    payload = {
        "role": role_upper,
        "userId": "101",
        "userDisplay": "@alpha",
        "deviceId": "dev-a",
        "deviceName": "Laptop",
        "connectionId": f"conn-{variant_upper.lower()}-{mode_lower}",
        "connectionAlias": "",
        "revisionId": f"rev-{variant_upper.lower()}-{mode_lower}",
        "mode": mode_lower,
        "variant": variant_upper,
        "profile": "v3-chain-shadowtls-shadowsocks" if is_chain else "v3-direct-shadowtls-shadowsocks",
        "protocol": "shadowsocks2022_shadowtls",
        "stage": (
            "entry-public-to-transit-relay"
            if role_upper == "ENTRY" and is_chain
            else "transit-private-terminator"
            if is_chain
            else "direct-transit-public"
        ),
        "server": "entry.tracegate.test" if is_chain else "transit.tracegate.test",
        "port": 443,
        "sni": "cdn.tracegate.test",
        "shadowsocks2022": {
            "method": "2022-blake3-aes-128-gcm",
            "password": f"ss-secret-{variant_upper.lower()}-{mode_lower}",
        },
        "shadowtls": {
            "version": 3,
            "serverName": "cdn.tracegate.test",
            "alpn": ["h2", "http/1.1"],
            "credentialScope": "node-static",
            "profileRef": {
                "kind": "file",
                "path": (
                    "/etc/tracegate/private/shadowtls/entry-config.yaml"
                    if role_upper == "ENTRY"
                    else "/etc/tracegate/private/shadowtls/transit-config.yaml"
                ),
                "secretMaterial": True,
            },
            "manageUsers": False,
            "restartOnUserChange": False,
        },
        "localSocks": _private_local_socks(username=f"tg_{variant_upper.lower()}_{mode_lower}"),
        "chain": (
            {
                "type": "entry_transit_private_relay",
                "entry": "entry.tracegate.test",
                "transit": "transit.tracegate.test",
                "linkClass": "entry-transit",
                "carrier": "mieru",
                "preferredOuter": "wss-carrier",
                "outerCarrier": "websocket-tls",
                "optionalPacketShaping": "zapret2-scoped",
                "managedBy": "link-crypto",
                "selectedProfiles": ["V1", "V3"],
                "innerTransport": "shadowsocks2022-shadowtls-v3",
                "xrayBackhaul": False,
            }
            if is_chain
            else None
        ),
        "obfuscation": {
            "scope": "entry-transit-private-relay" if is_chain else "public-tcp-443",
            "outer": "wss-carrier" if is_chain else "shadowtls-v3",
            "packetShaping": "zapret2-scoped",
            "hostWideInterception": False,
        },
    }
    if overrides:
        payload.update(overrides)
    return payload


def _private_wireguard_profile(overrides: dict | None = None) -> dict:
    payload = {
        "role": "TRANSIT",
        "userId": "102",
        "userDisplay": "@router",
        "deviceId": "dev-router",
        "deviceName": "Router",
        "connectionId": "conn-v0",
        "connectionAlias": "",
        "revisionId": "rev-v0",
        "variant": "V0",
        "profile": "v0-wgws-wireguard",
        "protocol": "wireguard_wstunnel",
        "stage": "direct-transit-public",
        "server": "transit.tracegate.test",
        "port": 443,
        "sni": "transit.tracegate.test",
        "wstunnel": {
            "mode": "wireguard-over-websocket",
            "url": "wss://transit.tracegate.test:443/cdn-cgi/tracegate",
            "path": "/cdn-cgi/tracegate",
            "tlsServerName": "transit.tracegate.test",
            "localUdpListen": "127.0.0.1:51820",
        },
        "wireguard": {
            "clientPublicKey": "client-public",
            "clientPrivateKey": "client-private",
            "serverPublicKey": "server-public",
            "presharedKey": "wg-psk",
            "address": "10.7.0.10/32",
            "allowedIps": ["10.7.0.10/32"],
            "clientRouteAllowedIps": ["0.0.0.0/0", "::/0"],
            "dns": "1.1.1.1",
            "mtu": 1280,
            "persistentKeepalive": 25,
        },
        "sync": {
            "strategy": "wg-set",
            "interface": "wg0",
            "applyMode": "live-peer-sync",
            "removeStalePeers": True,
            "restartWireGuard": False,
            "restartWSTunnel": False,
        },
        "localSocks": _private_local_socks(username="tg_v0"),
        "chain": None,
        "obfuscation": {
            "scope": "public-wss-443",
            "outer": "wstunnel",
            "packetShaping": "zapret2-scoped",
            "hostWideInterception": False,
        },
    }
    if overrides:
        payload.update(overrides)
    return payload


def _write_private_profile_state(
    tmp_path: Path,
    file_name: str,
    *,
    contract: dict,
    role: str,
    runtime_contract_path: str,
    shadowtls_profiles: list[dict] | None = None,
    wireguard_profiles: list[dict] | None = None,
    overrides: dict | None = None,
) -> Path:
    role_upper = role.strip().upper()
    if shadowtls_profiles is None:
        shadowtls_profiles = (
            [_private_shadowtls_profile(role=role_upper, mode="chain")]
            if role_upper == "ENTRY"
            else [
                _private_shadowtls_profile(role=role_upper, mode="direct"),
                _private_shadowtls_profile(role=role_upper, mode="chain"),
            ]
        )
    if wireguard_profiles is None:
        wireguard_profiles = [] if role_upper == "ENTRY" else [_private_wireguard_profile()]

    payload = {
        "schema": "tracegate.private-profiles.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": contract["runtimeProfile"],
        "runtimeContractPath": runtime_contract_path,
        "transportProfiles": contract["transportProfiles"],
        "secretMaterial": True,
        "counts": {
            "total": len(shadowtls_profiles) + len(wireguard_profiles),
            "shadowsocks2022ShadowTLS": len(shadowtls_profiles),
            "wireguardWSTunnel": len(wireguard_profiles),
        },
        "shadowsocks2022ShadowTLS": shadowtls_profiles,
        "wireguardWSTunnel": wireguard_profiles,
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path


def _write_private_profile_env(
    tmp_path: Path,
    file_name: str,
    *,
    state_path: Path,
    state_payload: dict,
    overrides: dict[str, object] | None = None,
) -> Path:
    counts = state_payload["counts"]
    payload: dict[str, object] = {
        "TRACEGATE_PROFILE_ROLE": state_payload["role"],
        "TRACEGATE_PROFILE_RUNTIME_PROFILE": state_payload["runtimeProfile"],
        "TRACEGATE_PROFILE_STATE_JSON": str(state_path),
        "TRACEGATE_PROFILE_SECRET_MATERIAL": "true",
        "TRACEGATE_PROFILE_COUNT": counts["total"],
        "TRACEGATE_SHADOWSOCKS2022_SHADOWTLS_COUNT": counts["shadowsocks2022ShadowTLS"],
        "TRACEGATE_WIREGUARD_WSTUNNEL_COUNT": counts["wireguardWSTunnel"],
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(f"{key}={_shell_quote(value)}" for key, value in payload.items()) + "\n",
        encoding="utf-8",
    )
    return path


def _private_file_ref(path: str) -> dict:
    return {"kind": "file", "path": path, "secretMaterial": True}


def _link_crypto_zapret2_policy() -> dict:
    return {
        "enabled": True,
        "required": True,
        "profileFile": "/etc/tracegate/private/zapret/entry-transit-stealth.env",
        "profileSource": "private-file-reference",
        "profileRef": _private_file_ref("/etc/tracegate/private/zapret/entry-transit-stealth.env"),
        "packetShaping": "zapret2-scoped",
        "applyMode": "marked-flow-only",
        "scope": "link-crypto-flow-only",
        "targetSurfaces": ["tcp/443", "entry-transit", "router-link-crypto"],
        "hostWideInterception": False,
        "nfqueue": False,
        "failOpen": True,
    }


def _link_crypto_tcp_dpi_resistance(*, require_outer_carrier: bool = True, link_class: str = "entry-transit") -> dict:
    required_layers = [
        "mieru-private-auth",
        "scoped-zapret2",
        "private-zapret2-profile",
        "loopback-only",
        "generation-drain",
        "no-direct-backhaul",
    ]
    if require_outer_carrier:
        required_layers.extend(["outer-wss-tls", "spki-sha256-pin", "hmac-admission"])
    return {
        "enabled": True,
        "mode": "mieru-wss-spki-hmac-zapret2-scoped" if require_outer_carrier else "mieru-zapret2-scoped",
        "requiredLayers": required_layers,
        "outerCarrier": {
            "required": require_outer_carrier,
            "spkiPinningRequired": require_outer_carrier,
            "hmacAdmissionRequired": require_outer_carrier,
        },
        "zapret2": {
            "required": True,
            "enabled": True,
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref("/etc/tracegate/private/zapret/entry-transit-stealth.env"),
            "packetShaping": "zapret2-scoped",
            "applyMode": "marked-flow-only",
            "scope": "link-crypto-flow-only",
            "hostWideInterception": False,
            "nfqueue": False,
        },
        "trafficShaping": {
            "required": True,
            "strategy": "private-zapret2-profile",
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref("/etc/tracegate/private/link-crypto/tcp-shaping.env"),
            "scope": "marked-flow-only",
            "target": "tcp/443-outer-wss" if require_outer_carrier else "tcp/443-link-crypto",
            "secretMaterial": False,
        },
        "promotionPreflight": {
            "required": True,
            "failClosed": True,
            "profileSource": "private-file-reference",
            "profileRef": _private_file_ref("/etc/tracegate/private/link-crypto/promotion-preflight.env"),
            "checks": [
                "mieru-private-auth",
                "zapret2-scoped-profile",
                "no-direct-backhaul",
            ]
            + (["spki-pin", "hmac-admission"] if require_outer_carrier else []),
            "secretMaterial": False,
        },
        "linkClass": link_class,
    }


def _link_crypto_row(*, role: str, link_class: str = "entry-transit", overrides: dict | None = None) -> dict:
    role_upper = role.strip().upper()
    side = "client" if role_upper == "ENTRY" and link_class == "entry-transit" else "server"
    remote_role = "TRANSIT" if role_upper == "ENTRY" else "ENTRY"
    outer_carrier = {
        "enabled": link_class == "entry-transit",
        "mode": "wss" if link_class == "entry-transit" else "direct",
        "protocol": "websocket-tls" if link_class == "entry-transit" else "",
        "serverName": "bridge.tracegate.test" if link_class == "entry-transit" else "",
        "publicPort": 443 if link_class == "entry-transit" else 0,
        "publicPath": "/cdn-cgi/tracegate-link" if link_class == "entry-transit" else "",
        "url": "wss://bridge.tracegate.test:443/cdn-cgi/tracegate-link" if link_class == "entry-transit" else "",
        "verifyTls": link_class == "entry-transit",
        "secretMaterial": False,
        "side": side,
        "localEndpoint": f"127.0.0.1:{14081 if side == 'client' else 14082}" if link_class == "entry-transit" else "",
        "entryClientListen": "127.0.0.1:14081" if link_class == "entry-transit" else "",
        "transitServerListen": "127.0.0.1:14082" if link_class == "entry-transit" else "",
        "transitTarget": "127.0.0.1:10882" if link_class == "entry-transit" else "",
        "tlsPinning": (
            {
                "required": True,
                "mode": "spki-sha256",
                "profileSource": "private-file-reference",
                "profileRef": _private_file_ref("/etc/tracegate/private/link-crypto/outer-wss-spki.env"),
                "secretMaterial": False,
            }
            if link_class == "entry-transit"
            else {"required": False, "mode": "none", "secretMaterial": False}
        ),
        "admission": (
            {
                "required": True,
                "mode": "hmac-sha256-generation-bound",
                "carrier": "websocket-subprotocol",
                "header": "Sec-WebSocket-Protocol",
                "profileSource": "private-file-reference",
                "profileRef": _private_file_ref("/etc/tracegate/private/link-crypto/outer-wss-admission.env"),
                "rejectUnauthenticated": True,
                "secretMaterial": False,
            }
            if link_class == "entry-transit"
            else {"required": False, "mode": "none", "secretMaterial": False}
        ),
    }
    payload = {
        "class": link_class,
        "enabled": True,
        "role": role_upper,
        "side": side,
        "carrier": "mieru",
        "managedBy": "link-crypto",
        "xrayBackhaul": False,
        "generation": 1,
        "profileRef": {
            "kind": "file",
            "path": f"/etc/tracegate/private/mieru/{'client' if side == 'client' else 'server'}.json",
            "secretMaterial": True,
        },
        "local": {
            "listen": "127.0.0.1:10881" if role_upper == "ENTRY" else "127.0.0.1:10882",
            "auth": {
                "required": True,
                "mode": "private-profile",
            },
        },
        "remote": {
            "role": remote_role,
            "endpoint": "transit.tracegate.test:443" if role_upper == "ENTRY" else "entry.tracegate.test:443",
        },
        "outerCarrier": outer_carrier,
        "selectedProfiles": ["V1", "V3"],
        "zapret2": _link_crypto_zapret2_policy(),
        "dpiResistance": _link_crypto_tcp_dpi_resistance(
            require_outer_carrier=link_class == "entry-transit",
            link_class=link_class,
        ),
        "rotation": {
            "strategy": "generation-drain",
            "restartExisting": False,
        },
        "stability": {
            "failOpen": True,
            "bypassOnFailure": True,
            "dropUnrelatedTraffic": False,
        },
    }
    if overrides:
        payload.update(overrides)
    return payload


def _link_crypto_udp_hardening() -> dict:
    return {
        "enabled": True,
        "failClosed": True,
        "requirePrivateAuth": True,
        "rejectAnonymous": True,
        "antiReplay": {"enabled": True, "windowPackets": 4096},
        "antiAmplification": {"enabled": True, "maxUnvalidatedBytes": 1200},
        "rateLimit": {"enabled": True, "handshakePerMinute": 120, "newSessionPerMinute": 60},
        "mtu": {"mode": "clamp", "maxPacketSize": 1252},
        "keyRotation": {
            "enabled": True,
            "strategy": "generation-drain",
            "maxAgeSeconds": 3600,
            "overlapSeconds": 120,
        },
        "sourceValidation": {"enabled": True, "mode": "profile-bound-remote"},
    }


def _link_crypto_udp_dpi_resistance() -> dict:
    return {
        "enabled": True,
        "mode": "salamander-plus-scoped-paired-obfs",
        "portSplit": {
            "publicUdpPort": TRACEGATE_PUBLIC_UDP_PORT,
            "forbidUdp443": True,
            "forbidTcp8443": True,
        },
        "requiredLayers": [
            "hysteria2-quic",
            "salamander",
            "private-auth",
            "anti-replay",
            "anti-amplification",
            "mtu-clamp",
            "source-validation",
        ],
        "pairedObfs": {
            "supported": True,
            "enabled": True,
            "backend": "udp2raw",
            "requiresBothSides": True,
            "failClosed": True,
        },
        "packetShape": {
            "strategy": "bounded-profile",
            "mtuMode": "clamp",
            "maxPacketSize": 1252,
        },
    }


def _link_crypto_udp_row(
    *,
    role: str,
    link_class: str = "entry-transit-udp",
    overrides: dict | None = None,
) -> dict:
    role_upper = role.strip().upper()
    side = "client" if role_upper == "ENTRY" and link_class == "entry-transit-udp" else "server"
    remote_role = (
        "TRANSIT"
        if role_upper == "ENTRY" and link_class == "entry-transit-udp"
        else "ENTRY"
        if link_class == "entry-transit-udp"
        else "ROUTER"
    )
    local_port = {
        ("ENTRY", "entry-transit-udp"): 14481,
        ("TRANSIT", "entry-transit-udp"): 14482,
        ("ENTRY", "router-entry-udp"): 14483,
        ("TRANSIT", "router-transit-udp"): 14484,
    }.get((role_upper, link_class), 14481)
    selected_profiles = ["V2"]
    payload = {
        "class": link_class,
        "enabled": True,
        "role": role_upper,
        "side": side,
        "carrier": "hysteria2",
        "transport": "udp-quic",
        "managedBy": "link-crypto",
        "xrayBackhaul": False,
        "generation": 1,
        "profileRef": {
            "kind": "file",
            "path": f"/etc/tracegate/private/udp-link/{'client' if side == 'client' else 'server'}.yaml",
            "secretMaterial": True,
        },
        "local": {
            "listen": f"127.0.0.1:{local_port}",
            "protocol": "udp",
            "auth": {"required": True, "mode": "private-profile"},
        },
        "remote": {
            "role": remote_role,
            "endpoint": "transit.tracegate.test:8443" if role_upper == "ENTRY" else "entry.tracegate.test:8443",
            "protocol": "udp-quic",
        },
        "datagram": {
            "udpCapable": True,
            "innerTransports": ["hysteria2-quic"],
            "preferredForProfiles": selected_profiles,
        },
        "obfs": {
            "type": "salamander",
            "required": True,
            "profileRef": {
                "kind": "file",
                "path": "/etc/tracegate/private/udp-link/salamander.env",
                "secretMaterial": True,
            },
        },
        "pairedObfs": {
            "enabled": True,
            "backend": "udp2raw",
            "mode": "udp2raw-faketcp",
            "requiresBothSides": True,
            "failClosed": True,
            "noHostWideInterception": True,
            "noNfqueue": True,
            "profileRef": {
                "kind": "file",
                "path": "/etc/tracegate/private/udp-link/paired-obfs.env",
                "secretMaterial": True,
            },
        },
        "hardening": _link_crypto_udp_hardening(),
        "dpiResistance": _link_crypto_udp_dpi_resistance(),
        "selectedProfiles": selected_profiles,
        "rotation": {
            "strategy": "generation-drain",
            "restartExisting": False,
        },
        "stability": {
            "failOpen": False,
            "bypassOnFailure": False,
            "dropUnrelatedTraffic": False,
        },
    }
    if overrides:
        payload.update(overrides)
    return payload


def _link_crypto_outer_carrier_contract(*, enabled: bool = True) -> dict:
    return {
        "enabled": enabled,
        "mode": "wss" if enabled else "direct",
        "protocol": "websocket-tls" if enabled else "",
        "serverName": "bridge.tracegate.test" if enabled else "",
        "publicPort": 443 if enabled else 0,
        "publicPath": "/cdn-cgi/tracegate-link" if enabled else "",
        "url": "wss://bridge.tracegate.test:443/cdn-cgi/tracegate-link" if enabled else "",
        "verifyTls": enabled,
        "secretMaterial": False,
        "tlsPinning": (
            {
                "required": True,
                "mode": "spki-sha256",
                "profileSource": "private-file-reference",
                "profileRef": _private_file_ref("/etc/tracegate/private/link-crypto/outer-wss-spki.env"),
                "secretMaterial": False,
            }
            if enabled
            else {"required": False, "mode": "none", "secretMaterial": False}
        ),
        "admission": (
            {
                "required": True,
                "mode": "hmac-sha256-generation-bound",
                "carrier": "websocket-subprotocol",
                "header": "Sec-WebSocket-Protocol",
                "profileSource": "private-file-reference",
                "profileRef": _private_file_ref("/etc/tracegate/private/link-crypto/outer-wss-admission.env"),
                "rejectUnauthenticated": True,
                "secretMaterial": False,
            }
            if enabled
            else {"required": False, "mode": "none", "secretMaterial": False}
        ),
        "localPorts": {
            "entryClient": 14081,
            "transitServer": 14082,
        },
        "endpoints": {
            "entryClientListen": "127.0.0.1:14081",
            "transitServerListen": "127.0.0.1:14082",
            "transitTarget": "127.0.0.1:10882",
        },
    }


def _router_link_crypto_contract(*, role: str) -> dict:
    role_upper = role.strip().upper()
    tcp_class = "router-entry" if role_upper == "ENTRY" else "router-transit"
    udp_class = "router-entry-udp" if role_upper == "ENTRY" else "router-transit-udp"
    tcp_profiles = ["V1", "V3"] if role_upper == "ENTRY" else ["V0", "V1", "V3"]
    udp_profiles = ["V2"]
    tcp_count_key = "routerEntry" if role_upper == "ENTRY" else "routerTransit"
    udp_count_key = "routerEntryUdp" if role_upper == "ENTRY" else "routerTransitUdp"
    tcp_port = 10883 if role_upper == "ENTRY" else 10884
    udp_port = 14483 if role_upper == "ENTRY" else 14484
    tcp_counts = {"total": 1, "entryTransit": 0, "routerEntry": 0, "routerTransit": 0}
    udp_counts = {"total": 1, "entryTransitUdp": 0, "routerEntryUdp": 0, "routerTransitUdp": 0}
    tcp_counts[tcp_count_key] = 1
    udp_counts[udp_count_key] = 1
    return {
        "enabled": True,
        "carrier": "mieru",
        "manager": "link-crypto",
        "profileSource": "private-file-reference",
        "secretMaterial": False,
        "xrayBackhaul": False,
        "generation": 1,
        "remotePort": 443,
        "outerCarrier": _link_crypto_outer_carrier_contract(enabled=False),
        "dpiResistance": _link_crypto_tcp_dpi_resistance(require_outer_carrier=False, link_class=tcp_class),
        "classes": [tcp_class],
        "counts": tcp_counts,
        "localPorts": {tcp_class: tcp_port},
        "selectedProfiles": {tcp_class: tcp_profiles},
        "udp": {
            "enabled": True,
            "carrier": "hysteria2",
            "transport": "udp-quic",
            "manager": "link-crypto",
            "profileSource": "private-file-reference",
            "secretMaterial": False,
            "xrayBackhaul": False,
            "remotePort": TRACEGATE_PUBLIC_UDP_PORT,
            "obfs": {"type": "salamander", "required": True},
            "pairedObfs": {
                "enabled": True,
                "backend": "udp2raw",
                "mode": "udp2raw-faketcp",
                "requiresBothSides": True,
                "failClosed": True,
                "noHostWideInterception": True,
                "noNfqueue": True,
            },
            "hardening": _link_crypto_udp_hardening(),
            "dpiResistance": _link_crypto_udp_dpi_resistance(),
            "classes": [udp_class],
            "counts": udp_counts,
            "localPorts": {udp_class: udp_port},
            "selectedProfiles": {udp_class: udp_profiles},
        },
        "zapret2": _link_crypto_zapret2_policy(),
    }


def _write_link_crypto_state(
    tmp_path: Path,
    file_name: str,
    *,
    contract: dict,
    role: str,
    runtime_contract_path: str,
    links: list[dict] | None = None,
    udp_links: list[dict] | None = None,
    overrides: dict | None = None,
) -> Path:
    role_upper = role.strip().upper()
    links = links if links is not None else [_link_crypto_row(role=role_upper)]
    udp_links = udp_links if udp_links is not None else []
    payload = {
        "schema": "tracegate.link-crypto.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": contract["runtimeProfile"],
        "runtimeContractPath": runtime_contract_path,
        "transportProfiles": contract["transportProfiles"],
        "secretMaterial": False,
        "counts": {
            "total": len(links),
            "entryTransit": len([row for row in links if row.get("class") == "entry-transit"]),
            "routerEntry": len([row for row in links if row.get("class") == "router-entry"]),
            "routerTransit": len([row for row in links if row.get("class") == "router-transit"]),
        },
        "links": links,
        "udpCounts": {
            "total": len(udp_links),
            "entryTransitUdp": len([row for row in udp_links if row.get("class") == "entry-transit-udp"]),
            "routerEntryUdp": len([row for row in udp_links if row.get("class") == "router-entry-udp"]),
            "routerTransitUdp": len([row for row in udp_links if row.get("class") == "router-transit-udp"]),
        },
        "udpLinks": udp_links,
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path


def _router_route_from_link(row: dict, *, transport: str) -> dict:
    local = row["local"]
    remote = row["remote"]
    route = {
        "class": row["class"],
        "enabled": True,
        "serverRole": row["role"],
        "serverSide": row["side"],
        "remoteRole": remote["role"],
        "carrier": row["carrier"],
        "transport": transport,
        "managedBy": row["managedBy"],
        "xrayBackhaul": row["xrayBackhaul"],
        "generation": row["generation"],
        "serverListen": local["listen"],
        "publicEndpoint": remote["endpoint"],
        "selectedProfiles": row["selectedProfiles"],
        "profileRef": row["profileRef"],
        "auth": local["auth"],
        "rotation": row["rotation"],
        "stability": row["stability"],
        "routerClient": {
            "requiresPrivateProfile": True,
            "secretMaterial": "external-private-file",
            "hostWideInterception": False,
            "nfqueue": False,
            "profileRefs": (
                {
                    "hysteriaClient": {
                        "kind": "file",
                        "path": f"/etc/tracegate/private/router/{row['role'].lower()}/{row['class']}/hysteria-client.yaml",
                        "secretMaterial": True,
                    },
                    "salamander": {
                        "kind": "file",
                        "path": f"/etc/tracegate/private/router/{row['role'].lower()}/{row['class']}/salamander.env",
                        "secretMaterial": True,
                    },
                    "pairedObfs": {
                        "kind": "file",
                        "path": f"/etc/tracegate/private/router/{row['role'].lower()}/{row['class']}/paired-obfs.env",
                        "secretMaterial": True,
                    },
                }
                if transport == "udp-quic"
                else {
                    "mieruClient": {
                        "kind": "file",
                        "path": f"/etc/tracegate/private/router/{row['role'].lower()}/{row['class']}/mieru-client.json",
                        "secretMaterial": True,
                    }
                }
            ),
        },
    }
    if transport == "udp-quic":
        route["datagram"] = row["datagram"]
        route["obfs"] = row["obfs"]
        route["pairedObfs"] = row["pairedObfs"]
        route["hardening"] = row["hardening"]
        route["dpiResistance"] = row["dpiResistance"]
    else:
        route["outerCarrier"] = row["outerCarrier"]
        route["zapret2"] = row["zapret2"]
        route["dpiResistance"] = row["dpiResistance"]
    return route


def _router_tcp_link(*, role: str) -> dict:
    role_upper = role.strip().upper()
    link_class = "router-entry" if role_upper == "ENTRY" else "router-transit"
    listen_port = 10883 if role_upper == "ENTRY" else 10884
    endpoint_host = "entry.tracegate.test" if role_upper == "ENTRY" else "transit.tracegate.test"
    selected_profiles = ["V1", "V3"] if role_upper == "ENTRY" else ["V0", "V1", "V3"]
    return _link_crypto_row(
        role=role_upper,
        link_class=link_class,
        overrides={
            "local": {"listen": f"127.0.0.1:{listen_port}", "auth": {"required": True, "mode": "private-profile"}},
            "remote": {"role": "ROUTER", "endpoint": f"{endpoint_host}:443"},
            "selectedProfiles": selected_profiles,
        },
    )


def _router_udp_link(*, role: str) -> dict:
    role_upper = role.strip().upper()
    link_class = "router-entry-udp" if role_upper == "ENTRY" else "router-transit-udp"
    endpoint_host = "entry.tracegate.test" if role_upper == "ENTRY" else "transit.tracegate.test"
    return _link_crypto_udp_row(
        role=role_upper,
        link_class=link_class,
        overrides={
            "remote": {"role": "ROUTER", "endpoint": f"{endpoint_host}:8443", "protocol": "udp-quic"},
        },
    )


def _write_router_handoff_state(
    tmp_path: Path,
    file_name: str,
    *,
    contract: dict,
    role: str,
    runtime_contract_path: str,
    tcp_routes: list[dict] | None = None,
    udp_routes: list[dict] | None = None,
    overrides: dict | None = None,
) -> Path:
    role_upper = role.strip().upper()
    tcp_routes = tcp_routes if tcp_routes is not None else []
    udp_routes = udp_routes if udp_routes is not None else []
    payload = {
        "schema": "tracegate.router-handoff.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": contract["runtimeProfile"],
        "runtimeContractPath": runtime_contract_path,
        "secretMaterial": False,
        "enabled": bool(tcp_routes or udp_routes),
        "placement": "personal-router-before-entry" if role_upper == "ENTRY" else "personal-router-before-transit",
        "contract": {
            "routerIsEntryReplacement": False,
            "requiresServerSideLinkCrypto": True,
            "requiresPrivateRouterProfile": bool(tcp_routes or udp_routes),
            "noHostWideInterception": True,
            "noNfqueue": True,
        },
        "counts": {"total": len(tcp_routes) + len(udp_routes), "tcp": len(tcp_routes), "udp": len(udp_routes)},
        "classes": {
            "tcp": [row["class"] for row in tcp_routes],
            "udp": [row["class"] for row in udp_routes],
        },
        "routes": {"tcp": tcp_routes, "udp": udp_routes},
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path


def _write_router_handoff_env(
    tmp_path: Path,
    file_name: str,
    *,
    state_path: Path,
    state: dict,
    overrides: dict[str, object] | None = None,
) -> Path:
    routes = state["routes"]
    paired_obfs_enabled = any(bool(row.get("pairedObfs", {}).get("enabled", False)) for row in routes["udp"])
    payload: dict[str, object] = {
        "TRACEGATE_ROUTER_HANDOFF_ROLE": state["role"],
        "TRACEGATE_ROUTER_HANDOFF_RUNTIME_PROFILE": state["runtimeProfile"],
        "TRACEGATE_ROUTER_HANDOFF_STATE_JSON": str(state_path),
        "TRACEGATE_ROUTER_HANDOFF_SECRET_MATERIAL": "false",
        "TRACEGATE_ROUTER_HANDOFF_ENABLED": str(bool(state["enabled"])).lower(),
        "TRACEGATE_ROUTER_HANDOFF_COUNT": state["counts"]["total"],
        "TRACEGATE_ROUTER_HANDOFF_TCP_COUNT": state["counts"]["tcp"],
        "TRACEGATE_ROUTER_HANDOFF_UDP_COUNT": state["counts"]["udp"],
        "TRACEGATE_ROUTER_HANDOFF_TCP_CLASSES": ":".join(state["classes"]["tcp"]),
        "TRACEGATE_ROUTER_HANDOFF_UDP_CLASSES": ":".join(state["classes"]["udp"]),
        "TRACEGATE_ROUTER_HANDOFF_PAIRED_OBFS_ENABLED": str(paired_obfs_enabled).lower(),
        "TRACEGATE_ROUTER_HANDOFF_REQUIRES_PRIVATE_PROFILE": str(bool(state["enabled"])).lower(),
        "TRACEGATE_ROUTER_HANDOFF_ROUTER_IS_ENTRY_REPLACEMENT": "false",
        "TRACEGATE_ROUTER_HANDOFF_NO_HOST_WIDE_INTERCEPTION": "true",
        "TRACEGATE_ROUTER_HANDOFF_NO_NFQUEUE": "true",
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"{key}={value}" for key, value in payload.items()) + "\n", encoding="utf-8")
    return path


def _router_client_route_from_handoff(row: dict, *, transport: str) -> dict:
    router_client = row["routerClient"]
    route = {
        "class": row["class"],
        "enabled": row["enabled"],
        "transport": transport,
        "serverRole": row["serverRole"],
        "routerRole": "ROUTER",
        "serverEndpoint": row["publicEndpoint"],
        "selectedProfiles": row["selectedProfiles"],
        "routerSide": {
            "mode": "client",
            "requiresPrivateProfile": True,
            "profileRefs": router_client["profileRefs"],
            "failClosed": True,
            "hostWideInterception": False,
            "nfqueue": False,
        },
        "serverSide": {
            "mode": "server",
            "listen": row["serverListen"],
            "auth": row["auth"],
        },
    }
    if transport == "tcp":
        route["carrier"] = "mieru"
        route["outerCarrier"] = row["outerCarrier"]
        route["zapret2"] = row["zapret2"]
        route["dpiResistance"] = row["dpiResistance"]
    else:
        route["carrier"] = "hysteria2"
        route["datagram"] = row["datagram"]
        route["obfs"] = row["obfs"]
        route["pairedObfs"] = row["pairedObfs"]
        route["hardening"] = row["hardening"]
        route["dpiResistance"] = row["dpiResistance"]
    return route


def _write_router_client_bundle(
    tmp_path: Path,
    file_name: str,
    *,
    state_path: Path,
    state: dict,
    overrides: dict | None = None,
) -> Path:
    tcp_routes = [_router_client_route_from_handoff(row, transport="tcp") for row in state["routes"]["tcp"]]
    udp_routes = [_router_client_route_from_handoff(row, transport="udp-quic") for row in state["routes"]["udp"]]
    paired_obfs_enabled = any(bool(row.get("pairedObfs", {}).get("enabled", False)) for row in udp_routes)
    payload = {
        "schema": "tracegate.router-client-bundle.v1",
        "version": 1,
        "role": state["role"],
        "runtimeProfile": state["runtimeProfile"],
        "handoffStateJson": str(state_path),
        "secretMaterial": False,
        "enabled": state["enabled"],
        "placement": state["placement"],
        "counts": state["counts"],
        "classes": state["classes"],
        "requirements": {
            "routerIsEntryReplacement": False,
            "requiresPrivateProfile": state["enabled"],
            "requiresServerSideLinkCrypto": True,
            "requiresBothSides": bool(tcp_routes or udp_routes),
            "failClosed": True,
            "noHostWideInterception": True,
            "noNfqueue": True,
            "profileDistribution": "external-private-files",
        },
        "components": [
            {
                "name": "mieru-client",
                "required": bool(tcp_routes),
                "transports": ["tcp"],
                "failClosed": True,
                "noHostWideInterception": True,
                "noNfqueue": True,
            },
            {
                "name": "hysteria2-client",
                "required": bool(udp_routes),
                "transports": ["udp-quic"],
                "obfs": "salamander",
                "failClosed": True,
                "noHostWideInterception": True,
                "noNfqueue": True,
            },
            {
                "name": "paired-udp-obfs",
                "required": paired_obfs_enabled,
                "backend": "udp2raw",
                "requiresBothSides": True,
                "failClosed": True,
                "noHostWideInterception": True,
                "noNfqueue": True,
            },
        ],
        "routes": {"tcp": tcp_routes, "udp": udp_routes},
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path


def _write_router_client_bundle_env(
    tmp_path: Path,
    file_name: str,
    *,
    bundle_path: Path,
    handoff_path: Path,
    bundle: dict,
    overrides: dict[str, object] | None = None,
) -> Path:
    components = [row["name"] for row in bundle["components"] if row.get("required")]
    payload: dict[str, object] = {
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_ROLE": bundle["role"],
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_RUNTIME_PROFILE": bundle["runtimeProfile"],
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_JSON": str(bundle_path),
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_HANDOFF_JSON": str(handoff_path),
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_SECRET_MATERIAL": "false",
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_ENABLED": str(bool(bundle["enabled"])).lower(),
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_COMPONENTS": ":".join(components),
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_TCP_COUNT": bundle["counts"]["tcp"],
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_UDP_COUNT": bundle["counts"]["udp"],
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_REQUIRES_BOTH_SIDES": str(
            bool(bundle["requirements"]["requiresBothSides"])
        ).lower(),
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_FAIL_CLOSED": "true",
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_HOST_WIDE_INTERCEPTION": "true",
        "TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_NFQUEUE": "true",
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"{key}={value}" for key, value in payload.items()) + "\n", encoding="utf-8")
    return path


def _write_link_crypto_env(
    tmp_path: Path,
    file_name: str,
    *,
    state_path: Path,
    state_payload: dict,
    overrides: dict[str, object] | None = None,
) -> Path:
    has_entry_transit = any(row.get("class") == "entry-transit" for row in state_payload["links"])
    payload: dict[str, object] = {
        "TRACEGATE_LINK_CRYPTO_ROLE": state_payload["role"],
        "TRACEGATE_LINK_CRYPTO_RUNTIME_PROFILE": state_payload["runtimeProfile"],
        "TRACEGATE_LINK_CRYPTO_STATE_JSON": str(state_path),
        "TRACEGATE_LINK_CRYPTO_SECRET_MATERIAL": "false",
        "TRACEGATE_LINK_CRYPTO_COUNT": state_payload["counts"]["total"],
        "TRACEGATE_LINK_CRYPTO_CLASSES": ":".join(row["class"] for row in state_payload["links"]),
        "TRACEGATE_LINK_CRYPTO_CARRIER": "mieru",
        "TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_ENABLED": "true" if has_entry_transit else "false",
        "TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_MODE": "wss" if has_entry_transit else "direct",
        "TRACEGATE_LINK_CRYPTO_OUTER_WSS_SERVER_NAME": "bridge.tracegate.test",
        "TRACEGATE_LINK_CRYPTO_OUTER_WSS_PUBLIC_PORT": "443",
        "TRACEGATE_LINK_CRYPTO_OUTER_WSS_PATH": "/cdn-cgi/tracegate-link",
        "TRACEGATE_LINK_CRYPTO_OUTER_WSS_VERIFY_TLS": "true",
        "TRACEGATE_LINK_CRYPTO_OUTER_WSS_SPKI_PINNING_REQUIRED": "true" if has_entry_transit else "false",
        "TRACEGATE_LINK_CRYPTO_OUTER_WSS_ADMISSION_REQUIRED": "true" if has_entry_transit else "false",
        "TRACEGATE_LINK_CRYPTO_GENERATION": "1",
        "TRACEGATE_LINK_CRYPTO_ZAPRET2_ENABLED": "true",
        "TRACEGATE_LINK_CRYPTO_ZAPRET2_REQUIRED": "true" if state_payload["counts"]["total"] else "false",
        "TRACEGATE_LINK_CRYPTO_ZAPRET2_HOST_WIDE_INTERCEPTION": "false",
        "TRACEGATE_LINK_CRYPTO_ZAPRET2_NFQUEUE": "false",
        "TRACEGATE_LINK_CRYPTO_TCP_DPI_RESISTANCE_REQUIRED": "true" if state_payload["counts"]["total"] else "false",
        "TRACEGATE_LINK_CRYPTO_TCP_TRAFFIC_SHAPING_REQUIRED": "true" if state_payload["counts"]["total"] else "false",
        "TRACEGATE_LINK_CRYPTO_PROMOTION_PREFLIGHT_REQUIRED": "true" if state_payload["counts"]["total"] else "false",
    }
    if overrides:
        payload.update(overrides)
    path = tmp_path / file_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(f"{key}={_shell_quote(value)}" for key, value in payload.items()) + "\n",
        encoding="utf-8",
    )
    return path


def test_validate_runtime_contract_pair_accepts_consistent_xray_centric_pair() -> None:
    findings = validate_runtime_contract_pair(
        _runtime_contract(role="ENTRY"),
        _runtime_contract(role="TRANSIT"),
    )

    assert findings == []


def test_validate_runtime_contract_pair_accepts_tracegate21_without_xray_backhaul() -> None:
    findings = validate_runtime_contract_pair(
        _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.1"),
        _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1"),
    )

    assert findings == []


def test_validate_runtime_contract_single_accepts_loopback_xray_api_surface() -> None:
    contract = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1")
    contract["xray"]["apiServices"] = ["HandlerService", "StatsService"]
    contract["xray"]["apiInbounds"] = [
        {"tag": "api", "listen": "127.0.0.1", "port": 8080, "protocol": "dokodemo-door"}
    ]

    findings = validate_runtime_contract_single(contract, expected_role="TRANSIT")

    assert findings == []


def test_validate_runtime_contract_pair_rejects_tracegate21_xray_backhaul_flag() -> None:
    entry = _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.1")
    transit = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1")
    entry["contract"]["xrayBackhaulAllowed"] = True

    findings = validate_runtime_contract_pair(entry, transit)

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-tracegate21-xray-backhaul"].severity == "error"


def test_validate_runtime_contract_pair_rejects_tracegate21_unsafe_rollout() -> None:
    entry = _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.1")
    transit = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1")
    entry["rollout"]["maxUnavailable"] = "1"
    entry["rollout"]["privatePreflightEnabled"] = False
    transit["rollout"]["gatewayStrategy"] = "Recreate"
    transit["rollout"]["allowRecreateStrategy"] = True
    transit["rollout"]["maxSurge"] = "0"
    transit["rollout"]["progressDeadlineSeconds"] = 60
    transit["rollout"]["pdbMinAvailable"] = "0"
    transit["rollout"]["probesEnabled"] = False
    transit["rollout"]["privatePreflightForbidPlaceholders"] = False

    findings = validate_runtime_contract_pair(entry, transit)

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-tracegate21-rollout-max-unavailable"].severity == "error"
    assert by_code["entry-tracegate21-rollout-private-preflight"].severity == "error"
    assert by_code["transit-tracegate21-rollout-strategy"].severity == "error"
    assert by_code["transit-tracegate21-rollout-allow-recreate"].severity == "error"
    assert by_code["transit-tracegate21-rollout-max-surge"].severity == "error"
    assert by_code["transit-tracegate21-rollout-progress-deadline"].severity == "error"
    assert by_code["transit-tracegate21-rollout-pdb-min-available"].severity == "error"
    assert by_code["transit-tracegate21-rollout-probes"].severity == "error"
    assert by_code["transit-tracegate21-rollout-private-preflight-placeholders"].severity == "error"


def test_validate_runtime_contract_pair_rejects_tracegate21_unsafe_transport_profiles() -> None:
    entry = _runtime_contract(
        role="ENTRY",
        runtime_profile="tracegate-2.1",
        transport_profiles={
            "clientNames": [
                "V1-VLESS-Reality-Direct",
                "MTProto-TCP443-Direct",
                "V8-Mieru-TCP-Direct",
            ],
            "localSocks": {"auth": "disabled", "allowAnonymousLocalhost": True},
        },
    )
    transit = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1")

    findings = validate_runtime_contract_pair(entry, transit)

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-tracegate21-client-profiles"].severity == "error"
    assert by_code["entry-tracegate21-legacy-mtproto-profile"].severity == "error"
    assert by_code["entry-tracegate21-lab-client-profiles"].severity == "error"
    assert by_code["entry-tracegate21-local-socks-auth-metadata"].severity == "error"
    assert by_code["entry-tracegate21-local-socks-auth"].severity == "error"
    assert by_code["entry-tracegate21-local-socks-anonymous"].severity == "error"
    assert by_code["entry-tracegate21-client-exposure-defaultMode"].severity == "error"


def test_validate_runtime_contract_pair_rejects_tracegate21_local_socks_metadata_mismatch() -> None:
    entry = _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.1")
    transit = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1")
    entry["localSocksAuth"] = "required"
    entry["transportProfiles"]["localSocks"]["auth"] = "disabled"

    findings = validate_runtime_contract_pair(entry, transit)

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-tracegate21-local-socks-auth-mismatch"].severity == "error"
    assert by_code["entry-tracegate21-local-socks-auth"].severity == "error"


def test_validate_runtime_contract_pair_rejects_tracegate21_unsafe_egress_isolation() -> None:
    entry = _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.1")
    transit = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1")
    transit["network"]["egressIsolation"] = {
        "required": False,
        "mode": "shared-ingress-ip",
        "ingressPublicIPs": ["198.51.100.20"],
        "egressPublicIPs": ["198.51.100.20"],
        "forbidIngressIpAsEgress": False,
        "requireTransitEgressPublicIP": False,
        "enforcement": {"snat": "optional", "ingressPublicIpOutbound": "allowed"},
    }

    findings = validate_runtime_contract_pair(entry, transit)

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-tracegate21-egress-isolation-required"].severity == "error"
    assert by_code["transit-tracegate21-egress-isolation-mode"].severity == "error"
    assert by_code["transit-tracegate21-egress-isolation-forbid-ingress"].severity == "error"
    assert by_code["transit-tracegate21-egress-isolation-transit-egress"].severity == "error"
    assert by_code["transit-tracegate21-egress-snat"].severity == "error"
    assert by_code["transit-tracegate21-egress-ingress-ip-outbound"].severity == "error"
    assert by_code["transit-tracegate21-egress-ip-overlap"].severity == "error"


def test_validate_runtime_contract_pair_requires_tracegate21_local_socks_metadata() -> None:
    entry = _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.1")
    transit = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1")
    entry.pop("localSocksAuth")

    findings = validate_runtime_contract_pair(entry, transit)

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-tracegate21-local-socks-auth-metadata"].severity == "error"


def test_validate_runtime_contract_pair_rejects_unsafe_xray_api_surface() -> None:
    entry = _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.1")
    transit = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1")
    entry["xray"]["apiServices"] = ["HandlerService", "ReflectionService", "DebugService"]
    entry["xray"]["apiInbounds"] = [
        {"tag": "api", "listen": "0.0.0.0", "port": 8080, "protocol": "dokodemo-door"}
    ]
    transit["xray"]["apiServices"] = ["HandlerService", "StatsService"]
    transit["xray"]["apiInbounds"] = []

    findings = validate_runtime_contract_pair(entry, transit)

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-xray-api-reflection-service"].severity == "error"
    assert by_code["entry-xray-api-service"].severity == "error"
    assert by_code["entry-xray-api-listen-loopback"].severity == "error"
    assert by_code["transit-xray-api-inbound"].severity == "error"


def test_validate_runtime_contract_pair_accepts_tracegate22_standalone_hysteria() -> None:
    findings = validate_runtime_contract_pair(
        _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.2"),
        _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.2"),
    )

    assert findings == []


def test_validate_runtime_contract_pair_rejects_missing_forbidden_public_ports() -> None:
    entry = _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.2")
    transit = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.2")
    entry["contract"]["forbiddenPorts"] = [{"protocol": "udp", "port": 8443, "name": "listen udp/8443"}]
    entry["fronting"]["forbiddenUdp443"] = False
    entry["fronting"]["forbiddenPublicPorts"] = [{"protocol": "tcp", "port": 443, "action": "accept"}]

    findings = validate_runtime_contract_pair(entry, transit)

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-forbidden-udp-443"].severity == "error"
    assert by_code["entry-forbidden-tcp-8443"].severity == "error"
    assert by_code["entry-fronting-forbidden-udp-443"].severity == "error"
    assert by_code["entry-fronting-forbidden-tcp-8443"].severity == "error"
    assert by_code["entry-fronting-forbidden-udp-443-flag"].severity == "error"


def test_validate_runtime_contract_pair_rejects_tracegate22_unsafe_hysteria_config() -> None:
    entry = _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.2")
    transit = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.2")
    entry["fronting"]["publicUdpOwner"] = "xray"
    entry["fronting"]["udp443Owner"] = "xray"
    entry["decoy"]["xrayHysteriaMasqueradeDirs"] = ["/srv/legacy-hy2"]
    entry["hysteria"]["listenPort"] = 443
    entry["hysteria"]["auth"]["httpUrl"] = "http://198.51.100.10/v1/hysteria/auth"
    entry["hysteria"]["obfs"] = {"type": "none", "salamanderPasswordConfigured": False}
    entry["hysteria"]["trafficStats"] = {"listen": "0.0.0.0:9999", "secretConfigured": False}
    entry["hysteria"]["udp"]["enabled"] = False
    entry["hysteria"]["tls"]["sniGuard"] = "disabled"
    entry["hysteria"]["quic"]["disablePathMTUDiscovery"] = True
    entry["hysteria"]["sniff"]["enabled"] = False

    findings = validate_runtime_contract_pair(entry, transit)

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-tracegate22-udp-owner"].severity == "error"
    assert by_code["entry-tracegate22-xray-hysteria-dirs"].severity == "error"
    assert by_code["entry-hysteria-listen-port"].severity == "error"
    assert by_code["entry-hysteria-auth-loopback"].severity == "error"
    assert by_code["entry-hysteria-obfs"].severity == "error"
    assert by_code["entry-hysteria-salamander-password"].severity == "error"
    assert by_code["entry-hysteria-stats-listen-loopback"].severity == "error"
    assert by_code["entry-hysteria-stats-secret"].severity == "error"
    assert by_code["entry-hysteria-udp-disabled"].severity == "error"
    assert by_code["entry-hysteria-sni-guard"].severity == "error"
    assert by_code["entry-hysteria-quic-pmtu"].severity == "error"
    assert by_code["entry-hysteria-sniff"].severity == "error"


def test_validate_runtime_contract_single_rejects_tracegate22_missing_hysteria_config() -> None:
    contract = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.2")
    contract["hysteria"]["configPresent"] = False

    findings = validate_runtime_contract_single(contract, expected_role="TRANSIT")

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-hysteria-config"].severity == "error"


def test_validate_runtime_contract_single_rejects_tracegate21_missing_rollout() -> None:
    contract = _runtime_contract(role="ENTRY", runtime_profile="tracegate-2.1")
    contract.pop("rollout")

    findings = validate_runtime_contract_single(contract, expected_role="ENTRY")

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-tracegate21-rollout"].severity == "error"


def test_validate_runtime_contract_pair_detects_errors_and_warnings() -> None:
    findings = validate_runtime_contract_pair(
        _runtime_contract(
            role="TRANSIT",
            nginx_roots=["/srv/decoy-a"],
            xray_hysteria_dirs=["/srv/decoy-b"],
            hysteria_tags=[],
            finalmask=True,
            ech=False,
            touch_udp_443=True,
        ),
        _runtime_contract(
            role="ENTRY",
            split_hysteria_dirs=["/var/www/legacy"],
            finalmask=False,
            ech=True,
        ),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-role"].severity == "error"
    assert by_code["transit-role"].severity == "error"
    assert by_code["transit-split-hysteria-stale"].severity == "warning"
    assert by_code["entry-decoy-diverge"].severity == "error"
    assert by_code["entry-hy2-inbound-missing"].severity == "error"
    assert by_code["entry-fronting-touch-udp-443"].severity == "error"
    assert by_code["finalmask-asymmetry"].severity == "warning"
    assert by_code["ech-asymmetry"].severity == "warning"


def test_validate_zapret_profile_collection_accepts_low_overhead_defaults(tmp_path: Path) -> None:
    entry_profile = load_zapret_profile(_write_zapret_profile(tmp_path, "entry-lite.env"))
    transit_profile = load_zapret_profile(_write_zapret_profile(tmp_path, "transit-lite.env"))
    interconnect_profile = load_zapret_profile(_write_zapret_profile(tmp_path, "entry-transit-stealth.env"))
    mtproto_profile = load_zapret_profile(_write_zapret_profile(tmp_path, "mtproto-extra.env"))

    findings = validate_zapret_profile_collection(
        entry_profile=entry_profile,
        transit_profile=transit_profile,
        interconnect_profile=interconnect_profile,
        mtproto_profile=mtproto_profile,
        transit_contract=_runtime_contract(role="TRANSIT"),
    )

    assert findings == []


def test_validate_zapret_profile_collection_detects_scope_widening_and_drift(tmp_path: Path) -> None:
    entry_profile = load_zapret_profile(
        _write_zapret_profile(
            tmp_path,
            "entry-lite.env",
            TRACEGATE_ZAPRET_SCOPE="transit",
            TRACEGATE_ZAPRET_APPLY_MODE="global",
        )
    )
    transit_profile = load_zapret_profile(
        _write_zapret_profile(
            tmp_path,
            "transit-lite.env",
            TRACEGATE_ZAPRET_TARGET_PROTOCOLS="v1,v3,v4",
            TRACEGATE_ZAPRET_MAX_WORKERS="3",
        )
    )
    interconnect_profile = load_zapret_profile(
        _write_zapret_profile(
            tmp_path,
            "entry-transit-stealth.env",
            TRACEGATE_ZAPRET_TOUCH_UNRELATED_SYSTEM_TRAFFIC="true",
            TRACEGATE_ZAPRET_CPU_BUDGET="high",
        )
    )
    mtproto_profile = load_zapret_profile(_write_zapret_profile(tmp_path, "mtproto-extra.env"))

    findings = validate_zapret_profile_collection(
        entry_profile=entry_profile,
        transit_profile=transit_profile,
        interconnect_profile=interconnect_profile,
        mtproto_profile=mtproto_profile,
        transit_contract=_runtime_contract(role="TRANSIT", touch_udp_443=False) | {"fronting": {"mtprotoDomain": ""}},
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["zapret-entry-scope"].severity == "error"
    assert by_code["zapret-entry-apply-mode"].severity == "error"
    assert by_code["zapret-transit-protocol-widen"].severity == "error"
    assert by_code["zapret-transit-max-workers"].severity == "warning"
    assert by_code["zapret-interconnect-unrelated-traffic"].severity == "error"
    assert by_code["zapret-interconnect-cpu-budget"].severity == "warning"
    assert by_code["zapret-mtproto-no-domain"].severity == "warning"


def test_validate_obfuscation_runtime_state_accepts_consistent_handoff(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY", finalmask=True, ech=True)
    profile_path = _write_zapret_profile(tmp_path, "entry-lite.env")
    profile = load_zapret_profile(profile_path)
    state_path = _write_runtime_state(
        tmp_path,
        "entry-runtime-state.json",
        contract=contract,
        role="ENTRY",
        zapret_profile_file=str(profile_path),
    )
    state = load_obfuscation_runtime_state(state_path)

    findings = validate_obfuscation_runtime_state(
        state=state,
        contract=contract,
        expected_role="ENTRY",
        contract_path="/var/lib/tracegate/agent-entry/runtime/runtime-contract.json",
        zapret_profile=profile,
    )

    assert findings == []


def test_validate_obfuscation_runtime_state_detects_divergence(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT")
    transit_profile_path = _write_zapret_profile(tmp_path, "transit-lite.env")
    mtproto_profile_path = _write_zapret_profile(tmp_path, "mtproto-extra.env")
    transit_profile = load_zapret_profile(transit_profile_path)
    mtproto_profile = load_zapret_profile(mtproto_profile_path)
    state_path = _write_runtime_state(
        tmp_path,
        "transit-runtime-state.json",
        contract=contract,
        role="ENTRY",
        interface="",
        zapret_profile_file=str(tmp_path / "wrong-transit.env"),
        zapret_mtproto_profile_file=str(tmp_path / "wrong-mtproto.env"),
        overrides={
            "runtimeProfile": "split",
            "contractPresent": False,
            "splitHysteriaMasqueradeDirs": ["/var/www/legacy-hy2"],
            "xrayHysteriaMasqueradeDirs": ["/srv/other-hy2"],
            "finalMaskEnabled": True,
            "xrayHysteriaInboundTags": [],
            "fronting": {
                "tcp443Owner": "nginx",
                "udp443Owner": "haproxy",
                "touchUdp443": True,
                "mtprotoDomain": "",
                "mtprotoPublicPort": 8443,
                "mtprotoFrontingMode": "cloudflare",
            },
        },
    )
    state = load_obfuscation_runtime_state(state_path)

    findings = validate_obfuscation_runtime_state(
        state=state,
        contract=contract,
        expected_role="TRANSIT",
        contract_path="/var/lib/tracegate/agent-transit/runtime/runtime-contract.json",
        zapret_profile=transit_profile,
        zapret_mtproto_profile=mtproto_profile,
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-runtime-state-role"].severity == "error"
    assert by_code["transit-runtime-state-profile"].severity == "error"
    assert by_code["transit-runtime-state-contract-missing"].severity == "error"
    assert by_code["transit-runtime-state-hy2-tags"].severity == "error"
    assert by_code["transit-runtime-state-split-hysteria-dirs"].severity == "warning"
    assert by_code["transit-runtime-state-xray-hysteria-dirs"].severity == "warning"
    assert by_code["transit-runtime-state-finalmask"].severity == "warning"
    assert by_code["transit-runtime-state-tcp-owner"].severity == "error"
    assert by_code["transit-runtime-state-udp-owner"].severity == "error"
    assert by_code["transit-runtime-state-touch-udp-443"].severity == "error"
    assert by_code["transit-runtime-state-mtproto-domain"].severity == "warning"
    assert by_code["transit-runtime-state-mtproto-port"].severity == "warning"
    assert by_code["transit-runtime-state-mtproto-fronting"].severity == "warning"
    assert by_code["transit-runtime-state-interface"].severity == "warning"
    assert by_code["transit-runtime-state-profile-file"].severity == "error"
    assert by_code["transit-runtime-state-mtproto-profile-file"].severity == "warning"


def test_validate_obfuscation_runtime_env_accepts_consistent_handoff(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY", finalmask=True, ech=True)
    profile_path = _write_zapret_profile(tmp_path, "entry-lite.env")
    profile = load_zapret_profile(profile_path)
    state_path = _write_runtime_state(
        tmp_path,
        "entry-runtime-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path="/var/lib/tracegate/agent-entry/runtime/runtime-contract.json",
        zapret_profile_file=str(profile_path),
    )
    runtime_state = load_obfuscation_runtime_state(state_path)
    env_path = _write_runtime_env(
        tmp_path,
        "entry-runtime-state.env",
        contract=contract,
        role="ENTRY",
        runtime_state_json=str(state_path),
        runtime_contract_path="/var/lib/tracegate/agent-entry/runtime/runtime-contract.json",
        zapret_profile_file=str(profile_path),
    )
    runtime_env = load_obfuscation_runtime_env(env_path)

    findings = validate_obfuscation_runtime_env(
        env=runtime_env,
        contract=contract,
        expected_role="ENTRY",
        runtime_state=runtime_state,
        contract_path="/var/lib/tracegate/agent-entry/runtime/runtime-contract.json",
        zapret_profile=profile,
    )

    assert findings == []


def test_validate_obfuscation_runtime_env_detects_divergence(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT")
    transit_profile_path = _write_zapret_profile(tmp_path, "transit-lite.env")
    mtproto_profile_path = _write_zapret_profile(tmp_path, "mtproto-extra.env")
    transit_profile = load_zapret_profile(transit_profile_path)
    mtproto_profile = load_zapret_profile(mtproto_profile_path)
    state_path = _write_runtime_state(
        tmp_path,
        "transit-runtime-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path="/var/lib/tracegate/agent-transit/runtime/runtime-contract.json",
        zapret_profile_file=str(transit_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
    )
    runtime_state = load_obfuscation_runtime_state(state_path)
    env_path = _write_runtime_env(
        tmp_path,
        "transit-runtime-state.env",
        contract=contract,
        role="ENTRY",
        runtime_state_json=str(tmp_path / "other-runtime-state.json"),
        runtime_contract_path=str(tmp_path / "other-contract.json"),
        interface="",
        backend="iptables",
        zapret_profile_file=str(tmp_path / "wrong-transit.env"),
        zapret_mtproto_profile_file=str(tmp_path / "wrong-mtproto.env"),
        zapret_policy_dir=str(tmp_path / "other-policy"),
        zapret_state_dir=str(tmp_path / "other-state"),
        contract_present=False,
        overrides={
            "TRACEGATE_DECOY_ROOTS": "/srv/other-decoy",
            "TRACEGATE_SPLIT_HYSTERIA_DIRS": "/srv/other-split-hy2",
            "TRACEGATE_XRAY_HYSTERIA_DIRS": "/srv/other-xray-hy2",
            "TRACEGATE_XRAY_CONFIG_PATHS": "/other/xray/config.json",
            "TRACEGATE_XRAY_HYSTERIA_TAGS": "",
            "TRACEGATE_FINALMASK_ENABLED": "true",
            "TRACEGATE_ECH_ENABLED": "true",
            "TRACEGATE_TCP_443_OWNER": "nginx",
            "TRACEGATE_PUBLIC_UDP_OWNER": "haproxy",
            "TRACEGATE_UDP_443_OWNER": "haproxy",
            "TRACEGATE_TOUCH_UDP_443": "true",
            "TRACEGATE_MTPROTO_DOMAIN": "",
            "TRACEGATE_MTPROTO_PUBLIC_PORT": "8443",
            "TRACEGATE_MTPROTO_FRONTING_MODE": "cloudflare",
            "TRACEGATE_RUNTIME_PROFILE": "split",
        },
    )
    runtime_env = load_obfuscation_runtime_env(env_path)

    findings = validate_obfuscation_runtime_env(
        env=runtime_env,
        contract=contract,
        expected_role="TRANSIT",
        runtime_state=runtime_state,
        contract_path="/var/lib/tracegate/agent-transit/runtime/runtime-contract.json",
        zapret_profile=transit_profile,
        zapret_mtproto_profile=mtproto_profile,
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-runtime-env-role"].severity == "error"
    assert by_code["transit-runtime-env-profile"].severity == "error"
    assert by_code["transit-runtime-env-contract-missing"].severity == "error"
    assert by_code["transit-runtime-env-contract-path"].severity == "warning"
    assert by_code["transit-runtime-env-hy2-tags"].severity == "error"
    assert by_code["transit-runtime-env-split-hysteria-dirs"].severity == "warning"
    assert by_code["transit-runtime-env-xray-hysteria-dirs"].severity == "warning"
    assert by_code["transit-runtime-env-finalmask"].severity == "warning"
    assert by_code["transit-runtime-env-ech"].severity == "warning"
    assert by_code["transit-runtime-env-tcp-owner"].severity == "error"
    assert by_code["transit-runtime-env-udp-owner"].severity == "error"
    assert by_code["transit-runtime-env-touch-udp-443"].severity == "error"
    assert by_code["transit-runtime-env-mtproto-domain"].severity == "warning"
    assert by_code["transit-runtime-env-mtproto-port"].severity == "warning"
    assert by_code["transit-runtime-env-mtproto-fronting"].severity == "warning"
    assert by_code["transit-runtime-env-interface"].severity == "warning"
    assert by_code["transit-runtime-env-backend"].severity == "warning"
    assert by_code["transit-runtime-env-state-json-path"].severity == "warning"
    assert by_code["transit-runtime-env-state-role"].severity == "error"
    assert by_code["transit-runtime-env-state-profile"].severity == "error"
    assert by_code["transit-runtime-env-state-contract-path"].severity == "warning"
    assert by_code["transit-runtime-env-state-contract-present"].severity == "error"
    assert by_code["transit-runtime-env-state-hy2-tags"].severity == "error"
    assert by_code["transit-runtime-env-state-split-hysteria-dirs"].severity == "warning"
    assert by_code["transit-runtime-env-state-xray-hysteria-dirs"].severity == "warning"
    assert by_code["transit-runtime-env-state-profile-file"].severity == "error"
    assert by_code["transit-runtime-env-state-mtproto-profile-file"].severity == "warning"
    assert by_code["transit-runtime-env-state-tcp-owner"].severity == "error"
    assert by_code["transit-runtime-env-state-udp-owner"].severity == "error"
    assert by_code["transit-runtime-env-state-touch-udp-443"].severity == "error"


def test_validate_private_profile_state_accepts_consistent_handoff(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT")
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(contract_path),
    )

    findings = validate_private_profile_state(
        state=load_private_profile_state(state_path),
        contract=contract,
        expected_role="TRANSIT",
        contract_path=str(contract_path),
    )

    assert findings == []


def test_validate_private_profile_state_rejects_transport_policy_drift(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.1")
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(contract_path),
        overrides={
            "transportProfiles": {
                "clientNames": ["V1-VLESS-Reality-Direct"],
                "localSocks": {"auth": "disabled", "allowAnonymousLocalhost": True},
            }
        },
    )

    findings = validate_private_profile_state(
        state=load_private_profile_state(state_path),
        contract=contract,
        expected_role="TRANSIT",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-private-profile-transport-client-names"].severity == "error"
    assert by_code["transit-private-profile-transport-local-socks"].severity == "error"
    assert by_code["transit-private-profile-transport-local-socks-auth"].severity == "error"
    assert by_code["transit-private-profile-transport-local-socks-anonymous"].severity == "error"


def test_validate_private_profile_state_warns_on_common_local_socks_port(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT")
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    shadowtls = _private_shadowtls_profile(
        role="TRANSIT",
        mode="direct",
        overrides={"localSocks": _private_local_socks(username="tg_v3", password="local-pass") | {"listen": "127.0.0.1:1080"}},
    )
    state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(contract_path),
        shadowtls_profiles=[shadowtls],
        wireguard_profiles=[],
    )

    findings = validate_private_profile_state(
        state=load_private_profile_state(state_path),
        contract=contract,
        expected_role="TRANSIT",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-private-profile-shadowtls-v3-local-socks-common-port"].severity == "warning"


def test_validate_private_profile_state_rejects_wstunnel_url_drift(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT")
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    wireguard = _private_wireguard_profile(
        overrides={
            "wstunnel": {
                "mode": "wireguard-over-websocket",
                "url": "wss://transit.tracegate.test:8443/other-path",
                "path": "/cdn-cgi/tracegate",
                "tlsServerName": "transit.tracegate.test",
                "localUdpListen": "127.0.0.1:51820",
            }
        }
    )
    state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(contract_path),
        shadowtls_profiles=[],
        wireguard_profiles=[wireguard],
    )

    findings = validate_private_profile_state(
        state=load_private_profile_state(state_path),
        contract=contract,
        expected_role="TRANSIT",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-private-profile-wireguard-v0-wstunnel-url"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-wstunnel-path-match"].severity == "error"


def test_validate_private_profile_state_rejects_wireguard_stability_drift(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT")
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    wireguard = _private_wireguard_profile(
        overrides={
            "wstunnel": {
                "mode": "wireguard-over-websocket",
                "url": "wss://transit.tracegate.test:443/cdn-cgi/tracegate",
                "path": "/cdn-cgi/tracegate",
                "tlsServerName": "transit.tracegate.test",
                "localUdpListen": "0.0.0.0:51820",
            },
            "wireguard": {
                "clientPublicKey": "client-public",
                "clientPrivateKey": "client-private",
                "serverPublicKey": "server-public",
                "presharedKey": "wg-psk",
                "address": "10.7.0.10/32",
                "allowedIps": ["0.0.0.0/0", "::/0"],
                "clientRouteAllowedIps": ["0.0.0.0/0", "::/0"],
                "dns": "1.1.1.1",
                "mtu": 9000,
                "persistentKeepalive": 300,
            },
            "sync": {
                "strategy": "restart",
                "interface": "",
                "applyMode": "restart",
                "removeStalePeers": False,
                "restartWireGuard": True,
                "restartWSTunnel": True,
            },
        }
    )
    state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(contract_path),
        shadowtls_profiles=[],
        wireguard_profiles=[wireguard],
    )

    findings = validate_private_profile_state(
        state=load_private_profile_state(state_path),
        contract=contract,
        expected_role="TRANSIT",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-private-profile-wireguard-v0-wstunnel-local-udp-loopback"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-wireguard-allowed-ips-host-route"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-wireguard-mtu"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-wireguard-persistent-keepalive"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-sync-strategy"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-sync-apply-mode"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-sync-interface"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-sync-remove-stale"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-sync-restart-wireguard"].severity == "error"
    assert by_code["transit-private-profile-wireguard-v0-sync-restart-wstunnel"].severity == "error"


def test_validate_private_profile_state_detects_security_drift(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    bad_shadowtls = _private_shadowtls_profile(
        role="TRANSIT",
        mode="direct",
        overrides={
            "profile": "legacy-shadowtls",
            "port": 8443,
            "shadowsocks2022": {"method": "", "password": "REPLACE_SS_PASSWORD"},
            "shadowtls": {
                "version": 2,
                "serverName": "",
                "password": "REPLACE_SHADOWTLS_PASSWORD",
                "profileRef": {"kind": "inline", "path": "", "secretMaterial": False},
                "manageUsers": True,
                "restartOnUserChange": True,
            },
            "localSocks": {
                "enabled": True,
                "listen": "0.0.0.0:1080",
                "auth": {"required": False, "mode": "none", "username": "", "password": ""},
            },
            "obfuscation": {
                "scope": "public-tcp-443",
                "outer": "shadowtls-v3",
                "packetShaping": "global",
                "hostWideInterception": True,
            },
        },
    )
    bad_wireguard = _private_wireguard_profile(
        overrides={
            "wstunnel": {
                "mode": "wireguard-over-websocket",
                "url": "http://transit.tracegate.test/cdn-cgi/tracegate",
                "path": "cdn-cgi/tracegate",
                "tlsServerName": "",
            },
            "wireguard": {
                "clientPublicKey": "REPLACE_CLIENT_WIREGUARD_PUBLIC_KEY",
                "clientPrivateKey": "REPLACE_CLIENT_WIREGUARD_PRIVATE_KEY",
                "serverPublicKey": "REPLACE_WIREGUARD_SERVER_PUBLIC_KEY",
                "presharedKey": "",
                "address": "",
                "allowedIps": [],
            },
            "localSocks": {
                "enabled": True,
                "listen": "0.0.0.0:1080",
                "auth": {"required": False, "mode": "none", "username": "", "password": ""},
            },
            "obfuscation": {
                "scope": "public-wss-443",
                "outer": "wstunnel",
                "packetShaping": "global",
                "hostWideInterception": True,
            },
        }
    )
    state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(tmp_path / "other-contract.json"),
        shadowtls_profiles=[bad_shadowtls],
        wireguard_profiles=[bad_wireguard],
        overrides={
            "secretMaterial": False,
            "counts": {
                "total": 99,
                "shadowsocks2022ShadowTLS": 2,
                "wireguardWSTunnel": 0,
            },
        },
    )

    findings = validate_private_profile_state(
        state=load_private_profile_state(state_path),
        contract=contract,
        expected_role="ENTRY",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-private-profile-role"].severity == "error"
    assert by_code["entry-private-profile-secret-material"].severity == "error"
    assert by_code["entry-private-profile-count-total"].severity == "error"
    assert by_code["entry-private-profile-count-shadowtls"].severity == "error"
    assert by_code["entry-private-profile-count-wireguard"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-entry-mode"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-profile"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-port"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-ss-password"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-shadowtls-version"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-shadowtls-password"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-shadowtls-credential-scope"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-shadowtls-profile-ref-kind"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-shadowtls-profile-ref-path"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-shadowtls-profile-ref-secret"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-shadowtls-manage-users"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-shadowtls-restart-on-user-change"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-local-socks-listen-loopback"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-local-socks-auth"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-local-socks-auth-mode"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-host-wide-interception"].severity == "error"
    assert by_code["entry-private-profile-shadowtls-v3-packet-shaping"].severity == "error"
    assert by_code["entry-private-profile-wireguard-entry"].severity == "error"
    assert by_code["entry-private-profile-wireguard-v0-wstunnel-url"].severity == "error"
    assert by_code["entry-private-profile-wireguard-v0-wstunnel-path"].severity == "error"
    assert by_code["entry-private-profile-wireguard-v0-wireguard-clientPublicKey"].severity == "error"
    assert by_code["entry-private-profile-wireguard-v0-local-socks-listen-loopback"].severity == "error"
    assert by_code["entry-private-profile-wireguard-v0-local-socks-auth"].severity == "error"
    assert by_code["entry-private-profile-wireguard-v0-local-socks-auth-mode"].severity == "error"
    assert by_code["entry-private-profile-wireguard-v0-host-wide-interception"].severity == "error"


def test_validate_private_profile_env_accepts_consistent_handoff(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
    )
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    env_path = _write_private_profile_env(
        tmp_path,
        "private/profiles/entry/desired-state.env",
        state_path=state_path,
        state_payload=state_payload,
    )

    findings = validate_private_profile_env(
        env=load_private_profile_env(env_path),
        expected_role="ENTRY",
        state=load_private_profile_state(state_path),
    )

    assert findings == []


def test_validate_private_profile_env_detects_divergence(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT")
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(contract_path),
    )
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    env_path = _write_private_profile_env(
        tmp_path,
        "private/profiles/transit/desired-state.env",
        state_path=state_path,
        state_payload=state_payload,
        overrides={
            "TRACEGATE_PROFILE_ROLE": "ENTRY",
            "TRACEGATE_PROFILE_RUNTIME_PROFILE": "split",
            "TRACEGATE_PROFILE_STATE_JSON": str(tmp_path / "other-state.json"),
            "TRACEGATE_PROFILE_SECRET_MATERIAL": "false",
            "TRACEGATE_PROFILE_COUNT": 1,
            "TRACEGATE_SHADOWSOCKS2022_SHADOWTLS_COUNT": 1,
            "TRACEGATE_WIREGUARD_WSTUNNEL_COUNT": 1,
        },
    )

    findings = validate_private_profile_env(
        env=load_private_profile_env(env_path),
        expected_role="TRANSIT",
        state=load_private_profile_state(state_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-private-profile-env-role"].severity == "error"
    assert by_code["transit-private-profile-env-secret-material"].severity == "error"
    assert by_code["transit-private-profile-env-state-json"].severity == "warning"
    assert by_code["transit-private-profile-env-runtime-profile"].severity == "error"
    assert by_code["transit-private-profile-env-count-total"].severity == "error"
    assert by_code["transit-private-profile-env-count-shadowtls"].severity == "error"
    assert by_code["transit-private-profile-env-count-sum"].severity == "error"


def test_validate_link_crypto_state_accepts_consistent_handoff(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract["linkCrypto"] = {
        "enabled": True,
        "carrier": "mieru",
        "manager": "link-crypto",
        "profileSource": "private-file-reference",
        "secretMaterial": False,
        "xrayBackhaul": False,
        "generation": 1,
        "remotePort": 443,
        "outerCarrier": _link_crypto_outer_carrier_contract(),
        "dpiResistance": _link_crypto_tcp_dpi_resistance(),
        "classes": ["entry-transit"],
        "counts": {
            "total": 1,
            "entryTransit": 1,
            "routerEntry": 0,
            "routerTransit": 0,
        },
        "localPorts": {"entry-transit": 10881},
        "selectedProfiles": {"entry-transit": ["V1", "V3"]},
        "zapret2": _link_crypto_zapret2_policy(),
    }
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
    )

    findings = validate_link_crypto_state(
        state=load_link_crypto_state(state_path),
        contract=contract,
        expected_role="ENTRY",
        contract_path=str(contract_path),
    )

    assert findings == []


def test_validate_link_crypto_state_accepts_udp_hysteria2_handoff(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract["linkCrypto"] = {
        "enabled": True,
        "carrier": "mieru",
        "manager": "link-crypto",
        "profileSource": "private-file-reference",
        "secretMaterial": False,
        "xrayBackhaul": False,
        "generation": 1,
        "remotePort": 443,
        "outerCarrier": _link_crypto_outer_carrier_contract(),
        "dpiResistance": _link_crypto_tcp_dpi_resistance(),
        "classes": ["entry-transit"],
        "counts": {
            "total": 1,
            "entryTransit": 1,
            "routerEntry": 0,
            "routerTransit": 0,
        },
        "localPorts": {"entry-transit": 10881},
        "selectedProfiles": {"entry-transit": ["V1", "V3"]},
        "udp": {
            "enabled": True,
            "carrier": "hysteria2",
            "transport": "udp-quic",
            "manager": "link-crypto",
            "profileSource": "private-file-reference",
            "secretMaterial": False,
            "xrayBackhaul": False,
            "remotePort": 8443,
            "obfs": {"type": "salamander", "required": True},
            "pairedObfs": {
                "enabled": True,
                "backend": "udp2raw",
                "mode": "udp2raw-faketcp",
                "requiresBothSides": True,
                "failClosed": True,
                "noHostWideInterception": True,
                "noNfqueue": True,
            },
            "hardening": _link_crypto_udp_hardening(),
            "dpiResistance": _link_crypto_udp_dpi_resistance(),
            "classes": ["entry-transit-udp"],
            "counts": {
                "total": 1,
                "entryTransitUdp": 1,
                "routerEntryUdp": 0,
                "routerTransitUdp": 0,
            },
            "localPorts": {"entry-transit-udp": 14481},
            "selectedProfiles": {"entry-transit-udp": ["V2"]},
        },
        "zapret2": _link_crypto_zapret2_policy(),
    }
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        udp_links=[_link_crypto_udp_row(role="ENTRY")],
    )

    findings = validate_link_crypto_state(
        state=load_link_crypto_state(state_path),
        contract=contract,
        expected_role="ENTRY",
        contract_path=str(contract_path),
    )

    assert findings == []


def test_validate_link_crypto_state_rejects_cross_protocol_profile_partition(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        links=[
            _link_crypto_row(
                role="ENTRY",
                overrides={
                    "selectedProfiles": ["V1", "V2", "V3"],
                },
            )
        ],
        udp_links=[
            _link_crypto_udp_row(
                role="ENTRY",
                overrides={
                    "selectedProfiles": ["V1", "V3"],
                },
            )
        ],
    )

    findings = validate_link_crypto_state(
        state=load_link_crypto_state(state_path),
        contract=contract,
        expected_role="ENTRY",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-link-crypto-entry-transit-selected-profiles"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-selected-profiles"].severity == "error"


def test_validate_link_crypto_state_rejects_unsafe_udp_handoff(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract["linkCrypto"] = {
        "enabled": True,
        "carrier": "mieru",
        "manager": "link-crypto",
        "profileSource": "private-file-reference",
        "secretMaterial": False,
        "xrayBackhaul": False,
        "generation": 1,
        "remotePort": 443,
        "outerCarrier": _link_crypto_outer_carrier_contract(),
        "dpiResistance": _link_crypto_tcp_dpi_resistance(),
        "classes": ["entry-transit"],
        "counts": {
            "total": 1,
            "entryTransit": 1,
            "routerEntry": 0,
            "routerTransit": 0,
        },
        "localPorts": {"entry-transit": 10881},
        "selectedProfiles": {"entry-transit": ["V1", "V3"]},
        "udp": {
            "enabled": True,
            "carrier": "direct",
            "transport": "tcp",
            "manager": "xray",
            "secretMaterial": True,
            "xrayBackhaul": True,
            "remotePort": 443,
            "obfs": {"type": "none", "required": False},
            "pairedObfs": {
                "enabled": True,
                "backend": "direct",
                "mode": "direct",
                "requiresBothSides": False,
                "failClosed": False,
                "noHostWideInterception": False,
                "noNfqueue": False,
            },
            "hardening": {
                "enabled": False,
                "failClosed": False,
                "requirePrivateAuth": False,
                "rejectAnonymous": False,
                "antiReplay": {"enabled": False, "windowPackets": 64},
                "antiAmplification": {"enabled": False, "maxUnvalidatedBytes": 8192},
                "rateLimit": {"enabled": False, "handshakePerMinute": 1000, "newSessionPerMinute": 1001},
                "mtu": {"mode": "off", "maxPacketSize": 1500},
                "keyRotation": {
                    "enabled": False,
                    "strategy": "restart",
                    "maxAgeSeconds": 60,
                    "overlapSeconds": 60,
                },
                "sourceValidation": {"enabled": False, "mode": "none"},
            },
            "dpiResistance": {
                "enabled": False,
                "mode": "off",
                "portSplit": {"publicUdpPort": 443, "forbidUdp443": False, "forbidTcp8443": False},
                "requiredLayers": ["hysteria2-quic"],
                "pairedObfs": {
                    "supported": False,
                    "backend": "direct",
                    "requiresBothSides": False,
                    "failClosed": False,
                },
                "packetShape": {"mtuMode": "off", "maxPacketSize": 1500},
            },
            "classes": ["entry-transit-udp"],
            "counts": {
                "total": 1,
                "entryTransitUdp": 1,
                "routerEntryUdp": 0,
                "routerTransitUdp": 0,
            },
            "localPorts": {"entry-transit-udp": 14481},
            "selectedProfiles": {"entry-transit-udp": ["V2"]},
        },
        "zapret2": _link_crypto_zapret2_policy(),
    }
    bad_udp_link = _link_crypto_udp_row(
        role="ENTRY",
        overrides={
            "carrier": "direct",
            "transport": "tcp",
            "managedBy": "xray",
            "xrayBackhaul": True,
            "local": {"listen": "0.0.0.0:14481", "protocol": "tcp", "auth": {"required": False, "mode": "none"}},
            "remote": {"role": "TRANSIT", "endpoint": "transit.tracegate.test:443", "protocol": "tcp"},
            "datagram": {"udpCapable": False},
            "obfs": {"type": "none", "required": False, "profileRef": {"kind": "inline", "secretMaterial": False}},
            "pairedObfs": {
                "enabled": True,
                "backend": "direct",
                "mode": "direct",
                "requiresBothSides": False,
                "failClosed": False,
                "noHostWideInterception": False,
                "noNfqueue": False,
                "profileRef": {"kind": "inline", "secretMaterial": False},
            },
            "hardening": {
                "enabled": False,
                "failClosed": False,
                "requirePrivateAuth": False,
                "rejectAnonymous": False,
                "antiReplay": {"enabled": False, "windowPackets": 64},
                "antiAmplification": {"enabled": False, "maxUnvalidatedBytes": 8192},
                "rateLimit": {"enabled": False, "handshakePerMinute": 1000, "newSessionPerMinute": 1001},
                "mtu": {"mode": "off", "maxPacketSize": 1500},
                "keyRotation": {
                    "enabled": False,
                    "strategy": "restart",
                    "maxAgeSeconds": 60,
                    "overlapSeconds": 60,
                },
                "sourceValidation": {"enabled": False, "mode": "none"},
            },
            "dpiResistance": {
                "enabled": False,
                "mode": "off",
                "portSplit": {"publicUdpPort": 443, "forbidUdp443": False, "forbidTcp8443": False},
                "requiredLayers": ["hysteria2-quic"],
                "pairedObfs": {
                    "supported": False,
                    "backend": "direct",
                    "requiresBothSides": False,
                    "failClosed": False,
                },
                "packetShape": {"mtuMode": "off", "maxPacketSize": 1500},
            },
            "stability": {"failOpen": True, "bypassOnFailure": True, "dropUnrelatedTraffic": True},
        },
    )
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        udp_links=[bad_udp_link],
    )

    findings = validate_link_crypto_state(
        state=load_link_crypto_state(state_path),
        contract=contract,
        expected_role="ENTRY",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-link-crypto-udp-contract-carrier"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-transport"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-manager"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-secret-material"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-xray-backhaul"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-remote-port"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-salamander"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-paired-obfs-backend"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-paired-obfs"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-paired-obfs-fail-closed"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-paired-obfs-host-wide"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-paired-obfs-nfqueue"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-hardening-enabled"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-hardening-anti-replay"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-hardening-unvalidated-bytes"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-hardening-rate-limit"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-hardening-mtu-mode"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-hardening-key-rotation-strategy"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-hardening-source-validation-mode"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-dpi-resistance-enabled"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-dpi-resistance-mode"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-dpi-resistance-udp443"].severity == "error"
    assert by_code["entry-link-crypto-udp-contract-dpi-resistance-tcp8443"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-carrier"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-transport"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-managed-by"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-xray-backhaul"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-local-listen-loopback"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-local-protocol"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-local-auth"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-remote-protocol"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-udp-capable"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-salamander"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-paired-obfs-backend"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-paired-obfs-mode"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-paired-obfs-both-sides"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-paired-obfs-fail-closed"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-paired-obfs-host-wide"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-paired-obfs-nfqueue"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-hardening-fail-closed"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-hardening-private-auth"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-hardening-replay-window"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-hardening-session-rate"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-hardening-mtu-size"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-hardening-key-rotation-overlap"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-dpi-resistance-enabled"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-dpi-resistance-paired-backend"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-fail-open"].severity == "error"
    assert by_code["entry-link-crypto-entry-transit-udp-bypass"].severity == "error"


@pytest.mark.parametrize(
    ("role", "link_class", "selected_profiles", "local_listen", "remote_endpoint"),
    [
        ("ENTRY", "router-entry", ["V1", "V3"], "127.0.0.1:10883", "entry.tracegate.test:443"),
        ("TRANSIT", "router-transit", ["V0", "V1", "V3"], "127.0.0.1:10884", "transit.tracegate.test:443"),
    ],
)
def test_validate_link_crypto_state_accepts_router_only_handoff(
    tmp_path: Path,
    role: str,
    link_class: str,
    selected_profiles: list[str],
    local_listen: str,
    remote_endpoint: str,
) -> None:
    contract = _runtime_contract(role=role, runtime_profile="tracegate-2.2")
    contract["linkCrypto"] = {
        "enabled": True,
        "carrier": "mieru",
        "manager": "link-crypto",
        "profileSource": "private-file-reference",
        "secretMaterial": False,
        "xrayBackhaul": False,
        "generation": 1,
        "remotePort": 443,
        "outerCarrier": _link_crypto_outer_carrier_contract(enabled=False),
        "dpiResistance": _link_crypto_tcp_dpi_resistance(require_outer_carrier=False, link_class=link_class),
        "classes": [link_class],
        "counts": {
            "total": 1,
            "entryTransit": 0,
            "routerEntry": 1 if link_class == "router-entry" else 0,
            "routerTransit": 1 if link_class == "router-transit" else 0,
        },
        "localPorts": {link_class: int(local_listen.rsplit(":", 1)[1])},
        "selectedProfiles": {link_class: selected_profiles},
        "zapret2": _link_crypto_zapret2_policy(),
    }
    contract_path = tmp_path / f"{role.lower()}.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        f"private/link-crypto/{role.lower()}/desired-state.json",
        contract=contract,
        role=role,
        runtime_contract_path=str(contract_path),
        links=[
            _link_crypto_row(
                role=role,
                link_class=link_class,
                overrides={
                    "local": {"listen": local_listen, "auth": {"required": True, "mode": "private-profile"}},
                    "remote": {"role": "ROUTER", "endpoint": remote_endpoint},
                    "selectedProfiles": selected_profiles,
                },
            )
        ],
    )

    findings = validate_link_crypto_state(
        state=load_link_crypto_state(state_path),
        contract=contract,
        expected_role=role,
        contract_path=str(contract_path),
    )

    assert findings == []


def test_validate_link_crypto_state_detects_runtime_contract_alignment_drift(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract["linkCrypto"] = {
        "enabled": True,
        "carrier": "direct",
        "manager": "xray",
        "profileSource": "inline",
        "secretMaterial": True,
        "xrayBackhaul": True,
        "generation": 2,
        "remotePort": 8443,
        "outerCarrier": {
            "enabled": True,
            "mode": "direct",
            "protocol": "tcp",
            "serverName": "",
            "publicPort": 8443,
            "publicPath": "bad path",
            "url": "http://bridge.tracegate.test:8443/bad path?x=1",
            "verifyTls": False,
            "secretMaterial": True,
        },
        "classes": ["entry-transit"],
        "counts": {
            "total": 1,
            "entryTransit": 1,
            "routerEntry": 0,
            "routerTransit": 0,
        },
        "localPorts": {"router-entry": 10899},
        "selectedProfiles": {"router-entry": ["V1"]},
        "zapret2": {
            "enabled": True,
            "packetShaping": "global",
            "applyMode": "host-wide",
            "hostWideInterception": True,
            "nfqueue": True,
            "failOpen": False,
        },
    }
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        links=[
            _link_crypto_row(
                role="ENTRY",
                link_class="router-entry",
                overrides={
                    "local": {"listen": "127.0.0.1:10883", "auth": {"required": True, "mode": "private-profile"}},
                    "remote": {"role": "ROUTER", "endpoint": "entry.tracegate.test:443"},
                    "selectedProfiles": ["V1", "V3"],
                    "zapret2": _link_crypto_zapret2_policy() | {"enabled": False},
                },
            )
        ],
    )

    findings = validate_link_crypto_state(
        state=load_link_crypto_state(state_path),
        contract=contract,
        expected_role="ENTRY",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-link-crypto-contract-classes"].severity == "error"
    assert by_code["entry-link-crypto-contract-counts"].severity == "error"
    assert by_code["entry-link-crypto-contract-carrier"].severity == "error"
    assert by_code["entry-link-crypto-contract-manager"].severity == "error"
    assert by_code["entry-link-crypto-contract-profile-source"].severity == "error"
    assert by_code["entry-link-crypto-contract-secret-material"].severity == "error"
    assert by_code["entry-link-crypto-contract-xray-backhaul"].severity == "error"
    assert by_code["entry-link-crypto-contract-zapret2-host-wide"].severity == "error"
    assert by_code["entry-link-crypto-contract-zapret2-nfqueue"].severity == "error"
    assert by_code["entry-link-crypto-contract-zapret2-packet-shaping"].severity == "error"
    assert by_code["entry-link-crypto-contract-zapret2-apply-mode"].severity == "error"
    assert by_code["entry-link-crypto-contract-zapret2-fail-open"].severity == "error"
    assert by_code["entry-link-crypto-router-entry-contract-generation"].severity == "error"
    assert by_code["entry-link-crypto-router-entry-contract-remote-port"].severity == "error"
    assert by_code["entry-link-crypto-router-entry-contract-zapret2-enabled"].severity == "error"
    assert by_code["entry-link-crypto-router-entry-contract-local-port"].severity == "error"
    assert by_code["entry-link-crypto-router-entry-contract-selected-profiles"].severity == "error"


def test_validate_link_crypto_state_accepts_role_scoped_runtime_contract(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.2")
    contract["linkCrypto"] = {
        "enabled": True,
        "carrier": "mieru",
        "manager": "link-crypto",
        "profileSource": "private-file-reference",
        "secretMaterial": False,
        "xrayBackhaul": False,
        "generation": 1,
        "remotePort": 443,
        "outerCarrier": _link_crypto_outer_carrier_contract(enabled=False),
        "dpiResistance": _link_crypto_tcp_dpi_resistance(require_outer_carrier=False, link_class="router-transit"),
        "zapret2": _link_crypto_zapret2_policy(),
        "roles": {
            "entry": {
                "enabled": False,
                "classes": [],
                "counts": {"total": 0, "entryTransit": 0, "routerEntry": 0, "routerTransit": 0},
                "localPorts": {},
                "selectedProfiles": {},
            },
            "transit": {
                "enabled": True,
                "classes": ["router-transit"],
                "counts": {"total": 1, "entryTransit": 0, "routerEntry": 0, "routerTransit": 1},
                "localPorts": {"router-transit": 10884},
                "selectedProfiles": {"router-transit": ["V0", "V1", "V3"]},
            },
        },
    }
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(contract_path),
        links=[
            _link_crypto_row(
                role="TRANSIT",
                link_class="router-transit",
                overrides={
                    "local": {"listen": "127.0.0.1:10884", "auth": {"required": True, "mode": "private-profile"}},
                    "remote": {"role": "ROUTER", "endpoint": "transit.tracegate.test:443"},
                    "selectedProfiles": ["V0", "V1", "V3"],
                },
            )
        ],
    )

    findings = validate_link_crypto_state(
        state=load_link_crypto_state(state_path),
        contract=contract,
        expected_role="TRANSIT",
        contract_path=str(contract_path),
    )

    assert findings == []


def test_validate_link_crypto_state_uses_top_level_role_metadata_fallback(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT", runtime_profile="tracegate-2.2")
    contract["linkCrypto"] = {
        "enabled": True,
        "carrier": "mieru",
        "manager": "link-crypto",
        "profileSource": "private-file-reference",
        "secretMaterial": False,
        "xrayBackhaul": False,
        "generation": 1,
        "remotePort": 443,
        "outerCarrier": _link_crypto_outer_carrier_contract(enabled=False),
        "dpiResistance": _link_crypto_tcp_dpi_resistance(require_outer_carrier=False, link_class="router-transit"),
        "localPorts": {"router-transit": 10999},
        "selectedProfiles": {"router-transit": ["V1"]},
        "zapret2": _link_crypto_zapret2_policy(),
        "roles": {
            "transit": {
                "enabled": True,
                "classes": ["router-transit"],
                "counts": {"total": 1, "entryTransit": 0, "routerEntry": 0, "routerTransit": 1},
            },
        },
    }
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(contract_path),
        links=[
            _link_crypto_row(
                role="TRANSIT",
                link_class="router-transit",
                overrides={
                    "local": {"listen": "127.0.0.1:10884", "auth": {"required": True, "mode": "private-profile"}},
                    "remote": {"role": "ROUTER", "endpoint": "transit.tracegate.test:443"},
                    "selectedProfiles": ["V0", "V1", "V3"],
                },
            )
        ],
    )

    findings = validate_link_crypto_state(
        state=load_link_crypto_state(state_path),
        contract=contract,
        expected_role="TRANSIT",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-link-crypto-router-transit-contract-local-port"].severity == "error"
    assert by_code["transit-link-crypto-router-transit-contract-selected-profiles"].severity == "error"


def test_validate_link_crypto_state_detects_security_drift(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT")
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    bad_link = _link_crypto_row(
        role="ENTRY",
        overrides={
            "class": "router-entry",
            "side": "client",
            "carrier": "direct",
            "managedBy": "xray",
            "xrayBackhaul": True,
            "generation": 0,
            "profileRef": {"kind": "inline", "path": "", "secretMaterial": False},
            "local": {"listen": "", "auth": {"required": False, "mode": "none"}},
            "remote": {"role": "", "endpoint": ""},
            "selectedProfiles": ["V1"],
            "zapret2": {
                "enabled": True,
                "profileFile": "",
                "packetShaping": "global",
                "applyMode": "host-wide",
                "hostWideInterception": True,
                "nfqueue": True,
                "failOpen": False,
            },
            "rotation": {"strategy": "restart", "restartExisting": True},
            "stability": {"failOpen": False, "dropUnrelatedTraffic": True},
        },
    )
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/transit/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(tmp_path / "other.json"),
        links=[bad_link],
        overrides={
            "secretMaterial": True,
            "transportProfiles": {
                "clientNames": ["V1-VLESS-Reality-Direct"],
                "localSocks": {"auth": "disabled", "allowAnonymousLocalhost": True},
            },
            "counts": {
                "total": 2,
                "entryTransit": 1,
                "routerEntry": 0,
                "routerTransit": 0,
            },
        },
    )

    findings = validate_link_crypto_state(
        state=load_link_crypto_state(state_path),
        contract=contract,
        expected_role="TRANSIT",
        contract_path=str(contract_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["transit-link-crypto-role"].severity == "error"
    assert by_code["transit-link-crypto-secret-material"].severity == "error"
    assert by_code["transit-link-crypto-transport-client-names"].severity == "error"
    assert by_code["transit-link-crypto-transport-local-socks"].severity == "error"
    assert by_code["transit-link-crypto-transport-local-socks-auth"].severity == "error"
    assert by_code["transit-link-crypto-transport-local-socks-anonymous"].severity == "error"
    assert by_code["transit-link-crypto-count-total"].severity == "error"
    assert by_code["transit-link-crypto-count-entry-transit"].severity == "error"
    assert by_code["transit-link-crypto-count-router-entry"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-role-class"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-side"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-carrier"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-managed-by"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-xray-backhaul"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-generation"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-profile-ref-kind"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-local-auth"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-local-auth-mode"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-remote-endpoint"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-selected-profiles"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-zapret2-host-wide"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-zapret2-nfqueue"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-zapret2-apply-mode"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-restart-existing"].severity == "error"
    assert by_code["transit-link-crypto-router-entry-drop-unrelated"].severity == "error"


def test_validate_link_crypto_env_accepts_consistent_handoff(tmp_path: Path) -> None:
    contract = _runtime_contract(role="TRANSIT")
    contract_path = tmp_path / "transit.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/transit/desired-state.json",
        contract=contract,
        role="TRANSIT",
        runtime_contract_path=str(contract_path),
    )
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    env_path = _write_link_crypto_env(
        tmp_path,
        "private/link-crypto/transit/desired-state.env",
        state_path=state_path,
        state_payload=state_payload,
    )

    findings = validate_link_crypto_env(
        env=load_link_crypto_env(env_path),
        expected_role="TRANSIT",
        contract=contract,
        state=load_link_crypto_state(state_path),
    )

    assert findings == []


def test_validate_link_crypto_env_detects_divergence(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
    )
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    env_path = _write_link_crypto_env(
        tmp_path,
        "private/link-crypto/entry/desired-state.env",
        state_path=state_path,
        state_payload=state_payload,
        overrides={
            "TRACEGATE_LINK_CRYPTO_ROLE": "TRANSIT",
            "TRACEGATE_LINK_CRYPTO_RUNTIME_PROFILE": "split",
            "TRACEGATE_LINK_CRYPTO_STATE_JSON": str(tmp_path / "other-state.json"),
            "TRACEGATE_LINK_CRYPTO_SECRET_MATERIAL": "true",
            "TRACEGATE_LINK_CRYPTO_COUNT": 2,
            "TRACEGATE_LINK_CRYPTO_CLASSES": "entry-transit:router-entry",
            "TRACEGATE_LINK_CRYPTO_CARRIER": "direct",
            "TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_MODE": "direct",
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_SERVER_NAME": "bridge.tracegate.test",
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_PUBLIC_PORT": "8443",
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_PATH": "bad path",
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_VERIFY_TLS": "false",
            "TRACEGATE_LINK_CRYPTO_GENERATION": "0",
            "TRACEGATE_LINK_CRYPTO_ZAPRET2_HOST_WIDE_INTERCEPTION": "true",
            "TRACEGATE_LINK_CRYPTO_ZAPRET2_NFQUEUE": "true",
        },
    )

    findings = validate_link_crypto_env(
        env=load_link_crypto_env(env_path),
        expected_role="ENTRY",
        contract=contract,
        state=load_link_crypto_state(state_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-link-crypto-env-role"].severity == "error"
    assert by_code["entry-link-crypto-env-secret-material"].severity == "error"
    assert by_code["entry-link-crypto-env-carrier"].severity == "error"
    assert by_code["entry-link-crypto-env-outer-carrier-mode"].severity == "error"
    assert by_code["entry-link-crypto-env-outer-wss-public-port"].severity == "error"
    assert by_code["entry-link-crypto-env-outer-wss-path"].severity == "error"
    assert by_code["entry-link-crypto-env-outer-wss-verify-tls"].severity == "error"
    assert by_code["entry-link-crypto-env-generation"].severity == "error"
    assert by_code["entry-link-crypto-env-zapret2-host-wide"].severity == "error"
    assert by_code["entry-link-crypto-env-zapret2-nfqueue"].severity == "error"
    assert by_code["entry-link-crypto-env-contract-runtime-profile"].severity == "error"
    assert by_code["entry-link-crypto-env-state-json"].severity == "warning"
    assert by_code["entry-link-crypto-env-runtime-profile"].severity == "error"
    assert by_code["entry-link-crypto-env-count-total"].severity == "error"
    assert by_code["entry-link-crypto-env-classes"].severity == "warning"


def test_validate_router_handoff_state_and_env_accept_consistent_router_routes(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    tcp_link = _router_tcp_link(role="ENTRY")
    udp_link = _router_udp_link(role="ENTRY")
    link_state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        links=[tcp_link],
        udp_links=[udp_link],
    )
    router_state_path = _write_router_handoff_state(
        tmp_path,
        "private/router/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        tcp_routes=[_router_route_from_link(tcp_link, transport="tcp")],
        udp_routes=[_router_route_from_link(udp_link, transport="udp-quic")],
    )
    router_payload = json.loads(router_state_path.read_text(encoding="utf-8"))
    router_env_path = _write_router_handoff_env(
        tmp_path,
        "private/router/entry/desired-state.env",
        state_path=router_state_path,
        state=router_payload,
    )
    router_state = load_router_handoff_state(router_state_path)

    state_findings = validate_router_handoff_state(
        state=router_state,
        contract=contract,
        expected_role="ENTRY",
        contract_path=str(contract_path),
        link_crypto_state=load_link_crypto_state(link_state_path),
    )
    env_findings = validate_router_handoff_env(
        env=load_router_handoff_env(router_env_path),
        expected_role="ENTRY",
        contract=contract,
        state=router_state,
    )

    assert state_findings == []
    assert env_findings == []


def test_validate_router_handoff_state_rejects_unsafe_router_routes(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    udp_link = _router_udp_link(role="ENTRY")
    bad_udp_route = _router_route_from_link(udp_link, transport="udp-quic")
    bad_udp_route.update(
        {
            "enabled": False,
            "publicEndpoint": "127.0.0.1:8443",
            "selectedProfiles": ["V3"],
            "routerClient": {
                "requiresPrivateProfile": False,
                "secretMaterial": "external-private-file",
                "hostWideInterception": True,
                "nfqueue": True,
            },
            "pairedObfs": bad_udp_route["pairedObfs"]
            | {
                "failClosed": False,
                "noHostWideInterception": False,
                "noNfqueue": False,
            },
            "hardening": bad_udp_route["hardening"] | {"failClosed": False},
        }
    )
    link_state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        links=[],
        udp_links=[udp_link],
    )
    router_state_path = _write_router_handoff_state(
        tmp_path,
        "private/router/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        udp_routes=[bad_udp_route],
        overrides={
            "schema": "legacy.router-handoff",
            "version": 0,
            "role": "TRANSIT",
            "runtimeProfile": "split",
            "secretMaterial": True,
            "contract": {
                "routerIsEntryReplacement": True,
                "requiresServerSideLinkCrypto": False,
                "requiresPrivateRouterProfile": False,
                "noHostWideInterception": False,
                "noNfqueue": False,
            },
        },
    )

    findings = validate_router_handoff_state(
        state=load_router_handoff_state(router_state_path),
        contract=contract,
        expected_role="ENTRY",
        contract_path=str(contract_path),
        link_crypto_state=load_link_crypto_state(link_state_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-router-handoff-schema"].severity == "error"
    assert by_code["entry-router-handoff-version"].severity == "error"
    assert by_code["entry-router-handoff-role"].severity == "error"
    assert by_code["entry-router-handoff-runtime-profile"].severity == "error"
    assert by_code["entry-router-handoff-secret-material"].severity == "error"
    assert by_code["entry-router-handoff-entry-replacement"].severity == "error"
    assert by_code["entry-router-handoff-server-link-crypto"].severity == "error"
    assert by_code["entry-router-handoff-private-router-profile"].severity == "error"
    assert by_code["entry-router-handoff-host-wide"].severity == "error"
    assert by_code["entry-router-handoff-nfqueue"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-enabled"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-public-endpoint-loopback"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-router-client-private-profile"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-router-client-host-wide"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-router-client-nfqueue"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-router-client-profile-hysteriaClient"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-router-client-profile-salamander"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-router-client-profile-pairedObfs"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-selected-profiles"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-paired-obfs-fail-closed"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-paired-obfs-host-wide"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-paired-obfs-nfqueue"].severity == "error"
    assert by_code["entry-router-handoff-router-entry-udp-hardening-fail-closed"].severity == "error"


def test_validate_router_handoff_env_rejects_divergence(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    udp_link = _router_udp_link(role="ENTRY")
    router_state_path = _write_router_handoff_state(
        tmp_path,
        "private/router/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        udp_routes=[_router_route_from_link(udp_link, transport="udp-quic")],
    )
    router_payload = json.loads(router_state_path.read_text(encoding="utf-8"))
    router_env_path = _write_router_handoff_env(
        tmp_path,
        "private/router/entry/desired-state.env",
        state_path=router_state_path,
        state=router_payload,
        overrides={
            "TRACEGATE_ROUTER_HANDOFF_ROLE": "TRANSIT",
            "TRACEGATE_ROUTER_HANDOFF_RUNTIME_PROFILE": "split",
            "TRACEGATE_ROUTER_HANDOFF_STATE_JSON": str(tmp_path / "other-router-state.json"),
            "TRACEGATE_ROUTER_HANDOFF_SECRET_MATERIAL": "true",
            "TRACEGATE_ROUTER_HANDOFF_COUNT": 99,
            "TRACEGATE_ROUTER_HANDOFF_TCP_COUNT": 1,
            "TRACEGATE_ROUTER_HANDOFF_UDP_COUNT": 0,
            "TRACEGATE_ROUTER_HANDOFF_PAIRED_OBFS_ENABLED": "false",
            "TRACEGATE_ROUTER_HANDOFF_REQUIRES_PRIVATE_PROFILE": "false",
            "TRACEGATE_ROUTER_HANDOFF_ROUTER_IS_ENTRY_REPLACEMENT": "true",
            "TRACEGATE_ROUTER_HANDOFF_NO_HOST_WIDE_INTERCEPTION": "false",
            "TRACEGATE_ROUTER_HANDOFF_NO_NFQUEUE": "false",
        },
    )

    findings = validate_router_handoff_env(
        env=load_router_handoff_env(router_env_path),
        expected_role="ENTRY",
        contract=contract,
        state=load_router_handoff_state(router_state_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-router-handoff-env-role"].severity == "error"
    assert by_code["entry-router-handoff-env-secret-material"].severity == "error"
    assert by_code["entry-router-handoff-env-entry-replacement"].severity == "error"
    assert by_code["entry-router-handoff-env-host-wide"].severity == "error"
    assert by_code["entry-router-handoff-env-nfqueue"].severity == "error"
    assert by_code["entry-router-handoff-env-private-profile"].severity == "error"
    assert by_code["entry-router-handoff-env-count-total"].severity == "error"
    assert by_code["entry-router-handoff-env-contract-runtime-profile"].severity == "error"
    assert by_code["entry-router-handoff-env-state-json"].severity == "warning"
    assert by_code["entry-router-handoff-env-runtime-profile"].severity == "error"
    assert by_code["entry-router-handoff-env-counts"].severity == "error"
    assert by_code["entry-router-handoff-env-paired-obfs"].severity == "error"


def test_validate_router_client_bundle_and_env_accept_consistent_routes(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract["linkCrypto"] = _router_link_crypto_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    tcp_link = _router_tcp_link(role="ENTRY")
    udp_link = _router_udp_link(role="ENTRY")
    router_state_path = _write_router_handoff_state(
        tmp_path,
        "private/router/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        tcp_routes=[_router_route_from_link(tcp_link, transport="tcp")],
        udp_routes=[_router_route_from_link(udp_link, transport="udp-quic")],
    )
    router_state_payload = json.loads(router_state_path.read_text(encoding="utf-8"))
    bundle_path = _write_router_client_bundle(
        tmp_path,
        "private/router/entry/client-bundle.json",
        state_path=router_state_path,
        state=router_state_payload,
    )
    bundle_payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle_env_path = _write_router_client_bundle_env(
        tmp_path,
        "private/router/entry/client-bundle.env",
        bundle_path=bundle_path,
        handoff_path=router_state_path,
        bundle=bundle_payload,
    )
    router_state = load_router_handoff_state(router_state_path)
    bundle = load_router_client_bundle(bundle_path)

    state_findings = validate_router_client_bundle(
        bundle=bundle,
        expected_role="ENTRY",
        contract=contract,
        handoff_state=router_state,
    )
    env_findings = validate_router_client_bundle_env(
        env=load_router_client_bundle_env(bundle_env_path),
        expected_role="ENTRY",
        contract=contract,
        bundle=bundle,
        handoff_state=router_state,
    )

    assert state_findings == []
    assert env_findings == []


def test_validate_router_client_bundle_rejects_unsafe_routes(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract["linkCrypto"] = _router_link_crypto_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    udp_link = _router_udp_link(role="ENTRY")
    router_state_path = _write_router_handoff_state(
        tmp_path,
        "private/router/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        udp_routes=[_router_route_from_link(udp_link, transport="udp-quic")],
    )
    router_state_payload = json.loads(router_state_path.read_text(encoding="utf-8"))
    bundle_path = _write_router_client_bundle(
        tmp_path,
        "private/router/entry/client-bundle.json",
        state_path=router_state_path,
        state=router_state_payload,
        overrides={
            "schema": "legacy.router-client-bundle",
            "version": 0,
            "role": "TRANSIT",
            "runtimeProfile": "split",
            "secretMaterial": True,
            "enabled": False,
            "placement": "personal-router-before-transit",
            "requirements": {
                "routerIsEntryReplacement": True,
                "requiresPrivateProfile": False,
                "requiresServerSideLinkCrypto": False,
                "requiresBothSides": False,
                "failClosed": False,
                "noHostWideInterception": False,
                "noNfqueue": False,
                "profileDistribution": "inline-secrets",
            },
        },
    )
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    bad_route = payload["routes"]["udp"][0]
    bad_route.update(
        {
            "enabled": False,
            "serverEndpoint": "127.0.0.1:8443",
            "selectedProfiles": ["V3"],
            "routerSide": {
                "mode": "server",
                "requiresPrivateProfile": False,
                "profileRefs": {},
                "failClosed": False,
                "hostWideInterception": True,
                "nfqueue": True,
            },
            "serverSide": {
                "mode": "client",
                "listen": "0.0.0.0:14483",
                "auth": {},
            },
            "pairedObfs": bad_route["pairedObfs"]
            | {
                "failClosed": False,
                "noHostWideInterception": False,
                "noNfqueue": False,
            },
            "hardening": bad_route["hardening"] | {"failClosed": False},
        }
    )
    payload["components"][1].update({"obfs": "none", "failClosed": False})
    payload["components"][2].update({"backend": "raw-udp", "requiresBothSides": False, "noNfqueue": False})
    bundle_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    findings = validate_router_client_bundle(
        bundle=load_router_client_bundle(bundle_path),
        expected_role="ENTRY",
        contract=contract,
        handoff_state=load_router_handoff_state(router_state_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-router-client-bundle-schema"].severity == "error"
    assert by_code["entry-router-client-bundle-version"].severity == "error"
    assert by_code["entry-router-client-bundle-role"].severity == "error"
    assert by_code["entry-router-client-bundle-runtime-profile"].severity == "error"
    assert by_code["entry-router-client-bundle-secret-material"].severity == "error"
    assert by_code["entry-router-client-bundle-placement"].severity == "error"
    assert by_code["entry-router-client-bundle-enabled"].severity == "error"
    assert by_code["entry-router-client-bundle-entry-replacement"].severity == "error"
    assert by_code["entry-router-client-bundle-private-profile"].severity == "error"
    assert by_code["entry-router-client-bundle-server-link-crypto"].severity == "error"
    assert by_code["entry-router-client-bundle-both-sides"].severity == "error"
    assert by_code["entry-router-client-bundle-fail-closed"].severity == "error"
    assert by_code["entry-router-client-bundle-host-wide"].severity == "error"
    assert by_code["entry-router-client-bundle-nfqueue"].severity == "error"
    assert by_code["entry-router-client-bundle-profile-distribution"].severity == "error"
    assert by_code["entry-router-client-bundle-component-hysteria2-client-salamander"].severity == "error"
    assert by_code["entry-router-client-bundle-component-hysteria2-client-fail-closed"].severity == "error"
    assert by_code["entry-router-client-bundle-component-paired-udp-obfs-backend"].severity == "error"
    assert by_code["entry-router-client-bundle-component-paired-udp-obfs-both-sides"].severity == "error"
    assert by_code["entry-router-client-bundle-component-paired-udp-obfs-nfqueue"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-enabled"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-server-endpoint-loopback"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-router-mode"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-router-private-profile"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-router-fail-closed"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-router-host-wide"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-router-nfqueue"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-router-client-profile-hysteriaClient"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-router-client-profile-salamander"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-router-client-profile-pairedObfs"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-server-mode"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-server-listen-loopback"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-server-auth"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-selected-profiles"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-paired-obfs-fail-closed"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-paired-obfs-host-wide"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-paired-obfs-nfqueue"].severity == "error"
    assert by_code["entry-router-client-bundle-router-entry-udp-hardening-fail-closed"].severity == "error"


def test_validate_router_client_bundle_env_rejects_divergence(tmp_path: Path) -> None:
    contract = _runtime_contract(role="ENTRY")
    contract["linkCrypto"] = _router_link_crypto_contract(role="ENTRY")
    contract_path = tmp_path / "entry.json"
    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
    udp_link = _router_udp_link(role="ENTRY")
    router_state_path = _write_router_handoff_state(
        tmp_path,
        "private/router/entry/desired-state.json",
        contract=contract,
        role="ENTRY",
        runtime_contract_path=str(contract_path),
        udp_routes=[_router_route_from_link(udp_link, transport="udp-quic")],
    )
    router_state_payload = json.loads(router_state_path.read_text(encoding="utf-8"))
    bundle_path = _write_router_client_bundle(
        tmp_path,
        "private/router/entry/client-bundle.json",
        state_path=router_state_path,
        state=router_state_payload,
    )
    bundle_payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle_env_path = _write_router_client_bundle_env(
        tmp_path,
        "private/router/entry/client-bundle.env",
        bundle_path=bundle_path,
        handoff_path=router_state_path,
        bundle=bundle_payload,
        overrides={
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_ROLE": "TRANSIT",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_RUNTIME_PROFILE": "split",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_JSON": "/tmp/other-client-bundle.json",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_HANDOFF_JSON": "/tmp/other-router-state.json",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_SECRET_MATERIAL": "true",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_ENABLED": "false",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_COMPONENTS": "mieru-client",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_TCP_COUNT": "1",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_UDP_COUNT": "0",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_REQUIRES_BOTH_SIDES": "false",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_FAIL_CLOSED": "false",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_HOST_WIDE_INTERCEPTION": "false",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_NFQUEUE": "false",
        },
    )

    findings = validate_router_client_bundle_env(
        env=load_router_client_bundle_env(bundle_env_path),
        expected_role="ENTRY",
        contract=contract,
        bundle=load_router_client_bundle(bundle_path),
        handoff_state=load_router_handoff_state(router_state_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["entry-router-client-bundle-env-role"].severity == "error"
    assert by_code["entry-router-client-bundle-env-secret-material"].severity == "error"
    assert by_code["entry-router-client-bundle-env-fail-closed"].severity == "error"
    assert by_code["entry-router-client-bundle-env-host-wide"].severity == "error"
    assert by_code["entry-router-client-bundle-env-nfqueue"].severity == "error"
    assert by_code["entry-router-client-bundle-env-both-sides"].severity == "error"
    assert by_code["entry-router-client-bundle-env-contract-runtime-profile"].severity == "error"
    assert by_code["entry-router-client-bundle-env-bundle-json"].severity == "warning"
    assert by_code["entry-router-client-bundle-env-handoff-json"].severity == "warning"
    assert by_code["entry-router-client-bundle-env-runtime-profile"].severity == "error"
    assert by_code["entry-router-client-bundle-env-bundle-enabled"].severity == "error"
    assert by_code["entry-router-client-bundle-env-bundle-counts"].severity == "error"
    assert by_code["entry-router-client-bundle-env-components"].severity == "error"
    assert by_code["entry-router-client-bundle-env-bundle-both-sides"].severity == "error"
    assert by_code["entry-router-client-bundle-env-state-json"].severity == "warning"


def test_validate_obfuscation_env_contract_accepts_consistent_handoff(tmp_path: Path) -> None:
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    entry_profile_path = _write_zapret_profile(zapret_root, "entry-lite.env")
    transit_profile_path = _write_zapret_profile(zapret_root, "transit-lite.env")
    interconnect_profile_path = _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    mtproto_profile_path = _write_zapret_profile(zapret_root, "mtproto-extra.env")

    entry_contract = _runtime_contract(role="ENTRY")
    transit_contract = _runtime_contract(role="TRANSIT")
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")

    private_runtime_dir = tmp_path / "private"
    zapret_policy_dir = tmp_path / "etc" / "tracegate" / "private" / "zapret"
    zapret_state_dir = private_runtime_dir / "zapret"

    entry_state_path = _write_runtime_state(
        tmp_path,
        "private/obfuscation/entry/runtime-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
        interface="eth0",
        zapret_profile_file=str(entry_profile_path),
        zapret_interconnect_profile_file=str(interconnect_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    transit_state_path = _write_runtime_state(
        tmp_path,
        "private/obfuscation/transit/runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
        interface="eth0",
        zapret_profile_file=str(transit_profile_path),
        zapret_interconnect_profile_file=str(interconnect_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    entry_env_path = _write_runtime_env(
        tmp_path,
        "private/obfuscation/entry/runtime-state.env",
        contract=entry_contract,
        role="ENTRY",
        runtime_state_json=str(entry_state_path),
        runtime_contract_path=str(entry_path),
        interface="eth0",
        zapret_profile_file=str(entry_profile_path),
        zapret_interconnect_profile_file=str(interconnect_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    transit_env_path = _write_runtime_env(
        tmp_path,
        "private/obfuscation/transit/runtime-state.env",
        contract=transit_contract,
        role="TRANSIT",
        runtime_state_json=str(transit_state_path),
        runtime_contract_path=str(transit_path),
        interface="eth0",
        zapret_profile_file=str(transit_profile_path),
        zapret_interconnect_profile_file=str(interconnect_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    fronting_env_path = _write_fronting_env(
        tmp_path,
        "fronting.env",
        TRACEGATE_FRONTING_RUNTIME_STATE_JSON=str(transit_state_path),
        TRACEGATE_FRONTING_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
    )
    mtproto_env_path = _write_mtproto_env(
        tmp_path,
        "mtproto.env",
        TRACEGATE_MTPROTO_RUNTIME_STATE_JSON=str(transit_state_path),
        TRACEGATE_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
    )
    obfuscation_env_path = _write_obfuscation_env(
        tmp_path,
        "obfuscation.env",
        TRACEGATE_ZAPRET_PROFILE_DIR=str(zapret_root),
        TRACEGATE_PRIVATE_RUNTIME_DIR=str(private_runtime_dir),
        TRACEGATE_ZAPRET_POLICY_DIR=str(zapret_policy_dir),
        TRACEGATE_ZAPRET_STATE_DIR=str(zapret_state_dir),
        TRACEGATE_ENTRY_RUNTIME_CONTRACT=str(entry_path),
        TRACEGATE_TRANSIT_RUNTIME_CONTRACT=str(transit_path),
    )

    findings = validate_obfuscation_env_contract(
        env=load_obfuscation_env_contract(obfuscation_env_path),
        entry_contract_path=str(entry_path),
        transit_contract_path=str(transit_path),
        entry_profile=load_zapret_profile(entry_profile_path),
        transit_profile=load_zapret_profile(transit_profile_path),
        interconnect_profile=load_zapret_profile(interconnect_profile_path),
        mtproto_profile=load_zapret_profile(mtproto_profile_path),
        entry_runtime_state=load_obfuscation_runtime_state(entry_state_path),
        transit_runtime_state=load_obfuscation_runtime_state(transit_state_path),
        entry_runtime_env=load_obfuscation_runtime_env(entry_env_path),
        transit_runtime_env=load_obfuscation_runtime_env(transit_env_path),
        fronting_env=load_fronting_env_contract(fronting_env_path),
        mtproto_env=load_mtproto_env_contract(mtproto_env_path),
    )

    assert findings == []


def test_validate_obfuscation_env_contract_detects_divergence(tmp_path: Path) -> None:
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    entry_profile_path = _write_zapret_profile(zapret_root, "entry-lite.env")
    transit_profile_path = _write_zapret_profile(zapret_root, "transit-lite.env")
    interconnect_profile_path = _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    mtproto_profile_path = _write_zapret_profile(zapret_root, "mtproto-extra.env")

    entry_contract = _runtime_contract(role="ENTRY")
    transit_contract = _runtime_contract(role="TRANSIT")
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")

    private_runtime_dir = tmp_path / "private"
    zapret_policy_dir = tmp_path / "etc" / "tracegate" / "private" / "zapret"
    zapret_state_dir = private_runtime_dir / "zapret"

    entry_state_path = _write_runtime_state(
        tmp_path,
        "private/obfuscation/entry/runtime-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
        interface="eth0",
        zapret_profile_file=str(entry_profile_path),
        zapret_interconnect_profile_file=str(interconnect_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    transit_state_path = _write_runtime_state(
        tmp_path,
        "private/obfuscation/transit/runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
        interface="eth0",
        zapret_profile_file=str(transit_profile_path),
        zapret_interconnect_profile_file=str(interconnect_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    entry_env_path = _write_runtime_env(
        tmp_path,
        "private/obfuscation/entry/runtime-state.env",
        contract=entry_contract,
        role="ENTRY",
        runtime_state_json=str(entry_state_path),
        runtime_contract_path=str(entry_path),
        interface="eth0",
        zapret_profile_file=str(entry_profile_path),
        zapret_interconnect_profile_file=str(interconnect_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
        overrides={
            "TRACEGATE_SPLIT_HYSTERIA_DIRS": "/srv/legacy-split-hy2",
            "TRACEGATE_XRAY_HYSTERIA_DIRS": "/srv/legacy-xray-hy2",
        },
    )
    transit_env_path = _write_runtime_env(
        tmp_path,
        "private/obfuscation/transit/runtime-state.env",
        contract=transit_contract,
        role="TRANSIT",
        runtime_state_json=str(transit_state_path),
        runtime_contract_path=str(transit_path),
        interface="eth0",
        zapret_profile_file=str(transit_profile_path),
        zapret_interconnect_profile_file=str(interconnect_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    fronting_env_path = _write_fronting_env(
        tmp_path,
        "fronting.env",
        TRACEGATE_FRONTING_RUNTIME_STATE_JSON=str(transit_state_path),
        TRACEGATE_FRONTING_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
    )
    mtproto_env_path = _write_mtproto_env(
        tmp_path,
        "mtproto.env",
        TRACEGATE_MTPROTO_RUNTIME_STATE_JSON=str(transit_state_path),
        TRACEGATE_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
    )
    obfuscation_env_path = _write_obfuscation_env(
        tmp_path,
        "obfuscation.env",
        TRACEGATE_ZAPRET_PROFILE_DIR=str(tmp_path / "wrong-zapret"),
        TRACEGATE_PRIVATE_RUNTIME_DIR=str(tmp_path / "wrong-private"),
        TRACEGATE_OBFUSCATION_BACKEND="iptables",
        TRACEGATE_FINALMASK_MODE="inline",
        TRACEGATE_ENTRY_RUNTIME_CONTRACT=str(tmp_path / "wrong-entry.json"),
        TRACEGATE_TRANSIT_RUNTIME_CONTRACT=str(tmp_path / "wrong-transit.json"),
        TRACEGATE_ENTRY_INTERFACE="ens3",
        TRACEGATE_TRANSIT_INTERFACE="ens4",
    )

    findings = validate_obfuscation_env_contract(
        env=load_obfuscation_env_contract(obfuscation_env_path),
        entry_contract_path=str(entry_path),
        transit_contract_path=str(transit_path),
        entry_profile=load_zapret_profile(entry_profile_path),
        transit_profile=load_zapret_profile(transit_profile_path),
        interconnect_profile=load_zapret_profile(interconnect_profile_path),
        mtproto_profile=load_zapret_profile(mtproto_profile_path),
        entry_runtime_state=load_obfuscation_runtime_state(entry_state_path),
        transit_runtime_state=load_obfuscation_runtime_state(transit_state_path),
        entry_runtime_env=load_obfuscation_runtime_env(entry_env_path),
        transit_runtime_env=load_obfuscation_runtime_env(transit_env_path),
        fronting_env=load_fronting_env_contract(fronting_env_path),
        mtproto_env=load_mtproto_env_contract(mtproto_env_path),
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["obfuscation-env-backend"].severity == "warning"
    assert by_code["obfuscation-env-finalmask-mode"].severity == "warning"
    assert by_code["obfuscation-env-entry-contract"].severity == "warning"
    assert by_code["obfuscation-env-transit-contract"].severity == "warning"
    assert by_code["obfuscation-env-entry-profile-file"].severity == "warning"
    assert by_code["obfuscation-env-mtproto-profile-file"].severity == "warning"
    assert by_code["obfuscation-env-entry-state-path"].severity == "warning"
    assert by_code["obfuscation-env-entry-state-interface"].severity == "warning"
    assert by_code["obfuscation-env-entry-state-backend"].severity == "warning"
    assert by_code["obfuscation-env-entry-state-profile"].severity == "error"
    assert by_code["obfuscation-env-entry-env-path"].severity == "warning"
    assert by_code["obfuscation-env-entry-env-interface"].severity == "warning"
    assert by_code["obfuscation-env-entry-env-profile"].severity == "error"
    assert by_code["obfuscation-env-transit-state-path"].severity == "warning"
    assert by_code["obfuscation-env-transit-env-path"].severity == "warning"
    assert by_code["obfuscation-env-entry-state-split-hysteria-dirs"].severity == "warning"
    assert by_code["obfuscation-env-entry-state-xray-hysteria-dirs"].severity == "warning"
    assert by_code["obfuscation-env-fronting-runtime-state-json"].severity == "warning"
    assert by_code["obfuscation-env-fronting-mtproto-profile"].severity == "warning"
    assert by_code["obfuscation-env-mtproto-runtime-state-json"].severity == "warning"
    assert by_code["obfuscation-env-mtproto-profile"].severity == "warning"


def test_validate_private_helper_unit_contract_accepts_consistent_surface(tmp_path: Path) -> None:
    unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-obfuscation@.service",
        description="Tracegate private obfuscation helper (%i)",
        condition_path_exists="/etc/tracegate/private/systemd/run-obfuscation.sh",
        environment_file="/etc/tracegate/private/systemd/obfuscation.env",
        runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
    )

    findings = validate_private_helper_unit_contract(
        unit=load_systemd_unit_contract(unit_path),
        unit_kind="obfuscation",
        expected_runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
        expected_env_path="/etc/tracegate/private/systemd/obfuscation.env",
        expected_description_fragment="private obfuscation helper",
    )

    assert findings == []


def test_validate_private_helper_unit_contract_detects_divergence(tmp_path: Path) -> None:
    unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-fronting@.service",
        description="Tracegate front helper (%i)",
        condition_path_exists="/opt/fronting/run-fronting.sh",
        environment_file="/opt/fronting/fronting.env",
        runner_path="/opt/fronting/run-fronting.sh",
        overrides={
            "Type": "simple",
            "RemainAfterExit": "no",
            "ExecReload": "/usr/bin/env bash /opt/fronting/run-fronting.sh hup %i",
        },
    )

    findings = validate_private_helper_unit_contract(
        unit=load_systemd_unit_contract(unit_path),
        unit_kind="fronting",
        expected_runner_path="/etc/tracegate/private/fronting/run-fronting.sh",
        expected_env_path="/etc/tracegate/private/fronting/fronting.env",
        expected_description_fragment="private TCP/443 fronting helper",
    )

    by_code = {finding.code: finding for finding in findings}
    assert by_code["fronting-unit-description"].severity == "warning"
    assert by_code["fronting-unit-condition-path"].severity == "error"
    assert by_code["fronting-unit-environment-file"].severity == "warning"
    assert by_code["fronting-unit-type"].severity == "error"
    assert by_code["fronting-unit-remain-after-exit"].severity == "error"
    assert by_code["fronting-unit-exec-start"].severity == "error"
    assert by_code["fronting-unit-exec-reload"].severity == "error"
    assert by_code["fronting-unit-exec-stop"].severity == "error"


def test_validate_fronting_and_mtproto_states_accept_consistent_handoff(tmp_path: Path) -> None:
    transit_contract = _runtime_contract(role="TRANSIT")
    mtproto_profile_path = _write_zapret_profile(tmp_path, "mtproto-extra.env")
    mtproto_profile = load_zapret_profile(mtproto_profile_path)
    transit_runtime_state_path = _write_runtime_state(
        tmp_path,
        "transit-runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path="/var/lib/tracegate/agent-transit/runtime/runtime-contract.json",
        zapret_profile_file=str(tmp_path / "transit-lite.env"),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
    )
    transit_runtime_state = load_obfuscation_runtime_state(transit_runtime_state_path)
    fronting_state_path = _write_fronting_state(
        tmp_path,
        "fronting-last-action.json",
        runtime_state_json=str(transit_runtime_state_path),
        overrides={"mtprotoProfileFile": str(mtproto_profile_path)},
    )
    mtproto_public_profile_path = _write_mtproto_public_profile(tmp_path, "public-profile.json")
    mtproto_state_path = _write_mtproto_state(
        tmp_path,
        "mtproto-last-action.json",
        runtime_state_json=str(transit_runtime_state_path),
        overrides={
            "profileFile": str(mtproto_profile_path),
            "publicProfileFile": str(mtproto_public_profile_path),
        },
    )

    fronting_state = load_fronting_runtime_state(fronting_state_path)
    mtproto_state = load_mtproto_gateway_state(mtproto_state_path)
    public_profile = load_mtproto_public_profile(mtproto_public_profile_path)

    fronting_findings = validate_fronting_runtime_state(
        state=fronting_state,
        transit_contract=transit_contract,
        transit_runtime_state=transit_runtime_state,
        mtproto_profile=mtproto_profile,
    )
    mtproto_findings = validate_mtproto_gateway_state(
        state=mtproto_state,
        transit_contract=transit_contract,
        transit_runtime_state=transit_runtime_state,
        mtproto_profile=mtproto_profile,
        public_profile=public_profile,
    )

    assert fronting_findings == []
    assert mtproto_findings == []


def test_validate_fronting_and_mtproto_states_detect_divergence(tmp_path: Path) -> None:
    transit_contract = _runtime_contract(role="TRANSIT")
    mtproto_profile_path = _write_zapret_profile(tmp_path, "mtproto-extra.env")
    mtproto_profile = load_zapret_profile(mtproto_profile_path)
    transit_runtime_state_path = _write_runtime_state(
        tmp_path,
        "transit-runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path="/var/lib/tracegate/agent-transit/runtime/runtime-contract.json",
        zapret_profile_file=str(tmp_path / "transit-lite.env"),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
    )
    transit_runtime_state = load_obfuscation_runtime_state(transit_runtime_state_path)
    fronting_state = load_fronting_runtime_state(
        _write_fronting_state(
            tmp_path,
            "fronting-last-action.json",
            runtime_state_json=str(tmp_path / "other-runtime-state.json"),
            overrides={
                "role": "ENTRY",
                "protocol": "udp",
                "touchUdp443": True,
                "mtprotoDomain": "",
                "tcp443Owner": "nginx",
                "publicUdpOwner": "haproxy",
                "udp443Owner": "haproxy",
                "mtprotoProfileFile": str(tmp_path / "other-mtproto.env"),
                "backend": "",
                "cfgFile": "",
            },
        )
    )
    mtproto_state = load_mtproto_gateway_state(
        _write_mtproto_state(
            tmp_path,
            "mtproto-last-action.json",
            runtime_state_json=str(tmp_path / "other-runtime-state.json"),
            overrides={
                "role": "ENTRY",
                "domain": "panel.tracegate.su",
                "publicPort": 8443,
                "upstreamHost": "10.0.0.5",
                "upstreamPort": 0,
                "profileFile": str(tmp_path / "other-mtproto.env"),
                "backend": "",
                "publicProfileFile": str(tmp_path / "other-public-profile.json"),
            },
        )
    )
    public_profile = load_mtproto_public_profile(
        _write_mtproto_public_profile(
            tmp_path,
            "public-profile.json",
            overrides={
                "server": "panel.tracegate.su",
                "port": 8443,
                "transport": "random_padding",
                "profile": "MTProto-TCP443-Direct",
                "domain": "panel.tracegate.su",
                "tgUri": "tg://proxy?server=panel.tracegate.su&port=8443&secret=ee0011",
                "httpsUrl": "https://t.me/proxy?server=panel.tracegate.su&port=8443&secret=ee0011",
            },
        )
    )

    fronting_findings = validate_fronting_runtime_state(
        state=fronting_state,
        transit_contract=transit_contract,
        transit_runtime_state=transit_runtime_state,
        mtproto_profile=mtproto_profile,
    )
    mtproto_findings = validate_mtproto_gateway_state(
        state=mtproto_state,
        transit_contract=transit_contract,
        transit_runtime_state=transit_runtime_state,
        mtproto_profile=mtproto_profile,
        public_profile=public_profile,
    )

    fronting_by_code = {finding.code: finding for finding in fronting_findings}
    assert fronting_by_code["fronting-role"].severity == "error"
    assert fronting_by_code["fronting-protocol"].severity == "error"
    assert fronting_by_code["fronting-touch-udp-443"].severity == "error"
    assert fronting_by_code["fronting-runtime-state-json"].severity == "warning"
    assert fronting_by_code["fronting-tcp-owner"].severity == "error"
    assert fronting_by_code["fronting-udp-owner"].severity == "error"
    assert fronting_by_code["fronting-mtproto-profile-file"].severity == "warning"
    assert fronting_by_code["fronting-backend"].severity == "warning"
    assert fronting_by_code["fronting-cfg-file"].severity == "warning"

    mtproto_by_code = {finding.code: finding for finding in mtproto_findings}
    assert mtproto_by_code["mtproto-role"].severity == "error"
    assert mtproto_by_code["mtproto-domain"].severity == "warning"
    assert mtproto_by_code["mtproto-public-port"].severity == "warning"
    assert mtproto_by_code["mtproto-runtime-state-json"].severity == "warning"
    assert mtproto_by_code["mtproto-profile-file"].severity == "warning"
    assert mtproto_by_code["mtproto-upstream-loopback"].severity == "warning"
    assert mtproto_by_code["mtproto-upstream-port"].severity == "error"
    assert mtproto_by_code["mtproto-backend"].severity == "warning"
    assert mtproto_by_code["mtproto-public-profile-server"].severity == "warning"
    assert mtproto_by_code["mtproto-public-profile-port"].severity == "warning"
    assert mtproto_by_code["mtproto-public-profile-domain"].severity == "warning"
    assert mtproto_by_code["mtproto-public-profile-transport"].severity == "warning"
    assert mtproto_by_code["mtproto-public-profile-name"].severity == "warning"


def test_validate_fronting_and_mtproto_env_contracts_accept_consistent_handoff(tmp_path: Path) -> None:
    transit_contract = _runtime_contract(role="TRANSIT")
    mtproto_profile_path = _write_zapret_profile(tmp_path, "mtproto-extra.env")
    mtproto_profile = load_zapret_profile(mtproto_profile_path)
    fronting_state_dir = tmp_path / "fronting"
    fronting_runtime_dir = fronting_state_dir / "runtime"
    mtproto_state_dir = tmp_path / "mtproto"
    mtproto_runtime_dir = mtproto_state_dir / "runtime"
    transit_runtime_state_path = _write_runtime_state(
        tmp_path,
        "transit-runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path="/var/lib/tracegate/agent-transit/runtime/runtime-contract.json",
        zapret_profile_file=str(tmp_path / "transit-lite.env"),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
    )
    transit_runtime_state = load_obfuscation_runtime_state(transit_runtime_state_path)
    fronting_state_path = _write_fronting_state(
        tmp_path,
        "fronting/last-action.json",
        runtime_state_json=str(transit_runtime_state_path),
        overrides={
            "mtprotoProfileFile": str(mtproto_profile_path),
            "cfgFile": str(fronting_runtime_dir / "haproxy.cfg"),
            "pidFile": str(fronting_runtime_dir / "haproxy.pid"),
        },
    )
    mtproto_public_profile_path = _write_mtproto_public_profile(tmp_path, "mtproto/public-profile.json")
    mtproto_state_path = _write_mtproto_state(
        tmp_path,
        "mtproto/last-action.json",
        runtime_state_json=str(transit_runtime_state_path),
        overrides={
            "profileFile": str(mtproto_profile_path),
            "publicProfileFile": str(mtproto_public_profile_path),
        },
    )
    fronting_env_path = _write_fronting_env(
        tmp_path,
        "fronting.env",
        TRACEGATE_FRONTING_RUNTIME_STATE_JSON=str(transit_runtime_state_path),
        TRACEGATE_FRONTING_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
        TRACEGATE_FRONTING_STATE_DIR=str(fronting_state_dir),
        TRACEGATE_FRONTING_RUNTIME_DIR=str(fronting_runtime_dir),
    )
    mtproto_env_path = _write_mtproto_env(
        tmp_path,
        "mtproto.env",
        TRACEGATE_MTPROTO_RUNTIME_STATE_JSON=str(transit_runtime_state_path),
        TRACEGATE_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
        TRACEGATE_MTPROTO_STATE_DIR=str(mtproto_state_dir),
        TRACEGATE_MTPROTO_RUNTIME_DIR=str(mtproto_runtime_dir),
    )

    fronting_state = load_fronting_runtime_state(fronting_state_path)
    mtproto_state = load_mtproto_gateway_state(mtproto_state_path)
    public_profile = load_mtproto_public_profile(mtproto_public_profile_path)
    fronting_env = load_fronting_env_contract(fronting_env_path)
    mtproto_env = load_mtproto_env_contract(mtproto_env_path)

    fronting_findings = validate_fronting_env_contract(
        env=fronting_env,
        transit_contract=transit_contract,
        transit_runtime_state=transit_runtime_state,
        mtproto_profile=mtproto_profile,
        fronting_state=fronting_state,
    )
    mtproto_findings = validate_mtproto_env_contract(
        env=mtproto_env,
        transit_contract=transit_contract,
        transit_runtime_state=transit_runtime_state,
        mtproto_profile=mtproto_profile,
        fronting_env=fronting_env,
        fronting_state=fronting_state,
        gateway_state=mtproto_state,
        public_profile=public_profile,
    )

    assert fronting_findings == []
    assert mtproto_findings == []


def test_validate_fronting_and_mtproto_env_contracts_detect_divergence(tmp_path: Path) -> None:
    transit_contract = _runtime_contract(role="TRANSIT")
    mtproto_profile_path = _write_zapret_profile(tmp_path, "mtproto-extra.env")
    mtproto_profile = load_zapret_profile(mtproto_profile_path)
    transit_runtime_state_path = _write_runtime_state(
        tmp_path,
        "transit-runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path="/var/lib/tracegate/agent-transit/runtime/runtime-contract.json",
        zapret_profile_file=str(tmp_path / "transit-lite.env"),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
    )
    transit_runtime_state = load_obfuscation_runtime_state(transit_runtime_state_path)
    fronting_state = load_fronting_runtime_state(
        _write_fronting_state(
            tmp_path,
            "fronting-last-action.json",
            runtime_state_json=str(transit_runtime_state_path),
            overrides={"mtprotoProfileFile": str(mtproto_profile_path)},
        )
    )
    mtproto_state = load_mtproto_gateway_state(
        _write_mtproto_state(
            tmp_path,
            "mtproto-last-action.json",
            runtime_state_json=str(transit_runtime_state_path),
            overrides={
                "profileFile": str(mtproto_profile_path),
            },
        )
    )
    public_profile = load_mtproto_public_profile(_write_mtproto_public_profile(tmp_path, "public-profile.json"))
    fronting_env = load_fronting_env_contract(
        _write_fronting_env(
            tmp_path,
            "fronting.env",
            TRACEGATE_FRONTING_ROLE="entry",
            TRACEGATE_FRONTING_BACKEND="custom",
            TRACEGATE_FRONTING_RUNTIME_STATE_JSON=str(tmp_path / "other-runtime-state.json"),
            TRACEGATE_FRONTING_LISTEN_ADDR="0.0.0.0:10443",
            TRACEGATE_FRONTING_PROTOCOL="udp",
            TRACEGATE_FRONTING_REALITY_UPSTREAM="10.0.0.2:2443",
            TRACEGATE_FRONTING_WS_TLS_UPSTREAM="10.0.0.3:4443",
            TRACEGATE_FRONTING_MTPROTO_UPSTREAM="10.0.0.5:10443",
            TRACEGATE_FRONTING_MTPROTO_PROFILE_FILE=str(tmp_path / "other-mtproto.env"),
            TRACEGATE_FRONTING_STATE_DIR="/var/lib/tracegate/private/fronting-alt",
            TRACEGATE_FRONTING_RUNTIME_DIR="/var/lib/tracegate/private/fronting-runtime",
            TRACEGATE_FRONTING_RUNNER="/opt/fronting-private/custom-runner",
            TRACEGATE_FRONTING_HAPROXY_BIN="/usr/local/sbin/haproxy",
            TRACEGATE_FRONTING_WS_SNI="other.tracegate.su",
            TRACEGATE_FRONTING_MTPROTO_DOMAIN_OVERRIDE="panel.tracegate.su",
            TRACEGATE_FRONTING_TOUCH_UDP_443="true",
        )
    )
    mtproto_env = load_mtproto_env_contract(
        _write_mtproto_env(
            tmp_path,
            "mtproto.env",
            TRACEGATE_MTPROTO_ROLE="entry",
            TRACEGATE_MTPROTO_BACKEND="custom",
            TRACEGATE_MTPROTO_RUNTIME_STATE_JSON=str(tmp_path / "other-runtime-state.json"),
            TRACEGATE_MTPROTO_PROFILE_FILE=str(tmp_path / "third-mtproto.env"),
            TRACEGATE_MTPROTO_DOMAIN="panel.tracegate.su",
            TRACEGATE_MTPROTO_PUBLIC_PORT="8443",
            TRACEGATE_MTPROTO_UPSTREAM_HOST="10.0.0.5",
            TRACEGATE_MTPROTO_UPSTREAM_PORT="0",
            TRACEGATE_MTPROTO_TLS_MODE="direct",
            TRACEGATE_MTPROTO_SECRET_FILE="/etc/tracegate/private/mtproto/other-secret.txt",
            TRACEGATE_MTPROTO_STATE_DIR="/var/lib/tracegate/private/mtproto-alt",
            TRACEGATE_MTPROTO_BINARY="/opt/MTProxy/custom/mtproto-proxy",
            TRACEGATE_MTPROTO_RUNTIME_DIR="/var/lib/tracegate/private/mtproto-runtime",
            TRACEGATE_MTPROTO_STATS_PORT="0",
            TRACEGATE_MTPROTO_RUN_AS_USER="root",
            TRACEGATE_MTPROTO_WORKERS="4",
            TRACEGATE_MTPROTO_FETCH_SECRET_URL="http://core.telegram.org/getProxySecret",
            TRACEGATE_MTPROTO_FETCH_CONFIG_URL="http://core.telegram.org/getProxyConfig",
            TRACEGATE_MTPROTO_BOOTSTRAP_MAX_AGE_SECONDS="30",
            TRACEGATE_MTPROTO_PROXY_SECRET_FILE="/var/lib/tracegate/private/mtproto-other/proxy-secret",
            TRACEGATE_MTPROTO_PROXY_CONFIG_FILE="/var/lib/tracegate/private/mtproto-other/proxy-multi.conf",
            TRACEGATE_MTPROTO_PID_FILE="/var/lib/tracegate/private/mtproto-other/mtproto-proxy.pid",
            TRACEGATE_MTPROTO_LOG_FILE="/var/log/tracegate/mtproto-proxy.log",
        )
    )

    fronting_findings = validate_fronting_env_contract(
        env=fronting_env,
        transit_contract=transit_contract,
        transit_runtime_state=transit_runtime_state,
        mtproto_profile=mtproto_profile,
        fronting_state=fronting_state,
    )
    mtproto_findings = validate_mtproto_env_contract(
        env=mtproto_env,
        transit_contract=transit_contract,
        transit_runtime_state=transit_runtime_state,
        mtproto_profile=mtproto_profile,
        fronting_env=fronting_env,
        fronting_state=fronting_state,
        gateway_state=mtproto_state,
        public_profile=public_profile,
    )

    fronting_by_code = {finding.code: finding for finding in fronting_findings}
    assert fronting_by_code["fronting-env-role"].severity == "error"
    assert fronting_by_code["fronting-env-protocol"].severity == "error"
    assert fronting_by_code["fronting-env-touch-udp-443"].severity == "error"
    assert fronting_by_code["fronting-env-backend-private"].severity == "warning"
    assert fronting_by_code["fronting-env-listen-addr-loopback"].severity == "warning"
    assert fronting_by_code["fronting-env-reality-upstream-loopback"].severity == "warning"
    assert fronting_by_code["fronting-env-runtime-state-json"].severity == "warning"
    assert fronting_by_code["fronting-env-mtproto-domain-override"].severity == "warning"
    assert fronting_by_code["fronting-env-mtproto-profile-file"].severity == "warning"
    assert fronting_by_code["fronting-env-runtime-dir-layout"].severity == "warning"
    assert fronting_by_code["fronting-env-state-file"].severity == "warning"
    assert fronting_by_code["fronting-env-state-cfg-file"].severity == "warning"
    assert fronting_by_code["fronting-env-state-pid-file"].severity == "warning"
    assert fronting_by_code["fronting-env-state-protocol"].severity == "error"
    assert fronting_by_code["fronting-env-state-ws-sni"].severity == "warning"

    mtproto_by_code = {finding.code: finding for finding in mtproto_findings}
    assert mtproto_by_code["mtproto-env-role"].severity == "error"
    assert mtproto_by_code["mtproto-env-backend-private"].severity == "warning"
    assert mtproto_by_code["mtproto-env-upstream-loopback"].severity == "warning"
    assert mtproto_by_code["mtproto-env-upstream-port"].severity == "error"
    assert mtproto_by_code["mtproto-env-tls-mode"].severity == "error"
    assert mtproto_by_code["mtproto-env-stats-port"].severity == "error"
    assert mtproto_by_code["mtproto-env-bootstrap-max-age"].severity == "warning"
    assert mtproto_by_code["mtproto-env-workers"].severity == "warning"
    assert mtproto_by_code["mtproto-env-run-as-user"].severity == "warning"
    assert mtproto_by_code["mtproto-env-runtime-state-json"].severity == "warning"
    assert mtproto_by_code["mtproto-env-profile-file"].severity == "warning"
    assert mtproto_by_code["mtproto-env-domain"].severity == "warning"
    assert mtproto_by_code["mtproto-env-public-port-contract"].severity == "warning"
    assert mtproto_by_code["mtproto-env-fronting-upstream"].severity == "warning"
    assert mtproto_by_code["mtproto-env-fronting-profile-file"].severity == "warning"
    assert mtproto_by_code["mtproto-env-fetch-secret-url"].severity == "warning"
    assert mtproto_by_code["mtproto-env-fetch-config-url"].severity == "warning"
    assert mtproto_by_code["mtproto-env-runtime-dir-layout"].severity == "warning"
    assert mtproto_by_code["mtproto-env-proxy-secret-file-layout"].severity == "warning"
    assert mtproto_by_code["mtproto-env-proxy-config-file-layout"].severity == "warning"
    assert mtproto_by_code["mtproto-env-pid-file-layout"].severity == "warning"
    assert mtproto_by_code["mtproto-env-log-file-layout"].severity == "warning"
    assert mtproto_by_code["mtproto-env-state-file"].severity == "warning"
    assert mtproto_by_code["mtproto-env-state-public-profile-file"].severity == "warning"
    assert mtproto_by_code["mtproto-env-public-profile-file"].severity == "warning"


def test_load_runtime_contract_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimePreflightError, match="runtime contract not found"):
        load_runtime_contract(tmp_path / "missing.json")


def test_load_obfuscation_runtime_state_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimePreflightError, match="obfuscation runtime-state not found"):
        load_obfuscation_runtime_state(tmp_path / "missing-state.json")


def test_load_obfuscation_runtime_env_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimePreflightError, match="obfuscation runtime-state env not found"):
        load_obfuscation_runtime_env(tmp_path / "missing-state.env")


def test_load_private_profile_state_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimePreflightError, match="private profile desired-state not found"):
        load_private_profile_state(tmp_path / "missing-desired-state.json")


def test_load_private_profile_env_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimePreflightError, match="private profile desired-state env not found"):
        load_private_profile_env(tmp_path / "missing-desired-state.env")


def test_load_obfuscation_env_contract_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimePreflightError, match="obfuscation env not found"):
        load_obfuscation_env_contract(tmp_path / "missing-obfuscation.env")


def test_load_systemd_unit_contract_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimePreflightError, match="systemd unit not found"):
        load_systemd_unit_contract(tmp_path / "missing.service")


def test_validate_runtime_contracts_cli_exits_zero_for_clean_pair(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    _write_zapret_profile(zapret_root, "entry-lite.env")
    _write_zapret_profile(zapret_root, "transit-lite.env")
    _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    _write_zapret_profile(zapret_root, "mtproto-extra.env")
    entry_path.write_text(json.dumps(_runtime_contract(role="ENTRY")) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(_runtime_contract(role="TRANSIT")) + "\n", encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
            "--zapret-root",
            str(zapret_root),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "OK runtime contracts and zapret profiles are internally consistent" in out


def test_validate_runtime_contract_single_accepts_clean_transit_contract() -> None:
    findings = validate_runtime_contract_single(_runtime_contract(role="TRANSIT"), expected_role="TRANSIT")
    assert findings == []


def test_validate_runtime_contracts_cli_supports_transit_only_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    transit_path = tmp_path / "transit.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    transit_profile_path = _write_zapret_profile(zapret_root, "transit-lite.env")
    client_profile_path = _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    mtproto_profile_path = _write_zapret_profile(zapret_root, "mtproto-extra.env")
    transit_contract = _runtime_contract(role="TRANSIT")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")

    private_runtime_dir = tmp_path / "private"
    zapret_policy_dir = tmp_path / "etc" / "tracegate" / "private" / "zapret"
    zapret_state_dir = private_runtime_dir / "zapret"
    fronting_state_dir = private_runtime_dir / "fronting"
    fronting_runtime_dir = fronting_state_dir / "runtime"
    mtproto_state_dir = private_runtime_dir / "mtproto"
    mtproto_runtime_dir = mtproto_state_dir / "runtime"

    transit_state_path = _write_runtime_state(
        tmp_path,
        "private/obfuscation/transit/runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
        interface="eth0",
        zapret_profile_file=str(transit_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    transit_env_path = _write_runtime_env(
        tmp_path,
        "private/obfuscation/transit/runtime-state.env",
        contract=transit_contract,
        role="TRANSIT",
        runtime_state_json=str(transit_state_path),
        runtime_contract_path=str(transit_path),
        interface="eth0",
        zapret_profile_file=str(transit_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    obfuscation_env_path = _write_obfuscation_env(
        tmp_path,
        "obfuscation.env",
        TRACEGATE_ZAPRET_PROFILE_DIR=str(zapret_root),
        TRACEGATE_PRIVATE_RUNTIME_DIR=str(private_runtime_dir),
        TRACEGATE_ZAPRET_POLICY_DIR=str(zapret_policy_dir),
        TRACEGATE_ZAPRET_STATE_DIR=str(zapret_state_dir),
        TRACEGATE_ENTRY_RUNTIME_CONTRACT="/var/lib/tracegate/agent-entry/runtime/runtime-contract.json",
        TRACEGATE_TRANSIT_RUNTIME_CONTRACT=str(transit_path),
    )
    obfuscation_unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-obfuscation@.service",
        description="Tracegate private obfuscation helper",
        condition_path_exists="/etc/tracegate/private/systemd/run-obfuscation.sh",
        environment_file=str(obfuscation_env_path),
        runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
    )
    fronting_state_path = _write_fronting_state(
        tmp_path,
        "private/fronting/last-action.json",
        runtime_state_json=str(transit_state_path),
        overrides={
            "mtprotoProfileFile": str(mtproto_profile_path),
            "cfgFile": str(fronting_runtime_dir / "haproxy.cfg"),
            "pidFile": str(fronting_runtime_dir / "haproxy.pid"),
        },
    )
    fronting_env_path = _write_fronting_env(
        tmp_path,
        "fronting.env",
        TRACEGATE_FRONTING_RUNTIME_STATE_JSON=str(transit_state_path),
        TRACEGATE_FRONTING_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
        TRACEGATE_FRONTING_STATE_DIR=str(fronting_state_dir),
        TRACEGATE_FRONTING_RUNTIME_DIR=str(fronting_runtime_dir),
    )
    fronting_unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-fronting@.service",
        description="Tracegate private TCP/443 fronting helper",
        condition_path_exists="/etc/tracegate/private/fronting/run-fronting.sh",
        environment_file=str(fronting_env_path),
        runner_path="/etc/tracegate/private/fronting/run-fronting.sh",
    )
    mtproto_public_profile_path = _write_mtproto_public_profile(tmp_path, "private/mtproto/public-profile.json")
    mtproto_state_path = _write_mtproto_state(
        tmp_path,
        "private/mtproto/last-action.json",
        runtime_state_json=str(transit_state_path),
        overrides={
            "profileFile": str(mtproto_profile_path),
            "publicProfileFile": str(mtproto_public_profile_path),
        },
    )
    mtproto_env_path = _write_mtproto_env(
        tmp_path,
        "mtproto.env",
        TRACEGATE_MTPROTO_RUNTIME_STATE_JSON=str(transit_state_path),
        TRACEGATE_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
        TRACEGATE_MTPROTO_STATE_DIR=str(mtproto_state_dir),
        TRACEGATE_MTPROTO_ISSUED_STATE_FILE=str(mtproto_state_dir / "issued.json"),
        TRACEGATE_MTPROTO_RUNTIME_DIR=str(mtproto_runtime_dir),
    )
    mtproto_unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-mtproto@.service",
        description="Tracegate private MTProto gateway",
        condition_path_exists="/etc/tracegate/private/mtproto/run-mtproto.sh",
        environment_file=str(mtproto_env_path),
        runner_path="/etc/tracegate/private/mtproto/run-mtproto.sh",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--mode",
            "transit",
            "--transit",
            str(transit_path),
            "--zapret-root",
            str(zapret_root),
            "--obfuscation-env",
            str(obfuscation_env_path),
            "--obfuscation-unit",
            str(obfuscation_unit_path),
            "--transit-runtime-state",
            str(transit_state_path),
            "--transit-runtime-env",
            str(transit_env_path),
            "--fronting-state",
            str(fronting_state_path),
            "--fronting-env",
            str(fronting_env_path),
            "--fronting-unit",
            str(fronting_unit_path),
            "--mtproto-state",
            str(mtproto_state_path),
            "--mtproto-env",
            str(mtproto_env_path),
            "--mtproto-unit",
            str(mtproto_unit_path),
            "--mtproto-public-profile",
            str(mtproto_public_profile_path),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "mode=transit" in out
    assert f"zapret_interconnect={client_profile_path}" in out
    assert "OK transit runtime contract, zapret profiles and private handoffs are internally consistent" in out


def test_validate_runtime_contracts_cli_supports_entry_only_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    entry_profile_path = _write_zapret_profile(zapret_root, "entry-lite.env")
    client_profile_path = _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    entry_contract = _runtime_contract(role="ENTRY")
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")

    private_runtime_dir = tmp_path / "private"
    zapret_policy_dir = tmp_path / "etc" / "tracegate" / "private" / "zapret"
    zapret_state_dir = private_runtime_dir / "zapret"
    entry_state_path = _write_runtime_state(
        tmp_path,
        "private/obfuscation/entry/runtime-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
        interface="eth0",
        zapret_profile_file=str(entry_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    entry_env_path = _write_runtime_env(
        tmp_path,
        "private/obfuscation/entry/runtime-state.env",
        contract=entry_contract,
        role="ENTRY",
        runtime_state_json=str(entry_state_path),
        runtime_contract_path=str(entry_path),
        interface="eth0",
        zapret_profile_file=str(entry_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    obfuscation_env_path = _write_obfuscation_env(
        tmp_path,
        "obfuscation.env",
        TRACEGATE_ZAPRET_PROFILE_DIR=str(zapret_root),
        TRACEGATE_PRIVATE_RUNTIME_DIR=str(private_runtime_dir),
        TRACEGATE_ZAPRET_POLICY_DIR=str(zapret_policy_dir),
        TRACEGATE_ZAPRET_STATE_DIR=str(zapret_state_dir),
        TRACEGATE_ENTRY_RUNTIME_CONTRACT=str(entry_path),
        TRACEGATE_TRANSIT_RUNTIME_CONTRACT="/var/lib/tracegate/agent-transit/runtime/runtime-contract.json",
    )
    obfuscation_unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-obfuscation@.service",
        description="Tracegate private obfuscation helper",
        condition_path_exists="/etc/tracegate/private/systemd/run-obfuscation.sh",
        environment_file=str(obfuscation_env_path),
        runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--mode",
            "entry",
            "--entry",
            str(entry_path),
            "--zapret-root",
            str(zapret_root),
            "--obfuscation-env",
            str(obfuscation_env_path),
            "--obfuscation-unit",
            str(obfuscation_unit_path),
            "--entry-runtime-state",
            str(entry_state_path),
            "--entry-runtime-env",
            str(entry_env_path),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "mode=entry" in out
    assert f"zapret_interconnect={client_profile_path}" in out
    assert "OK entry runtime contract, zapret profiles and private handoffs are internally consistent" in out


def test_validate_runtime_contracts_cli_validates_runtime_state_when_provided(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    entry_profile_path = _write_zapret_profile(zapret_root, "entry-lite.env")
    transit_profile_path = _write_zapret_profile(zapret_root, "transit-lite.env")
    _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    mtproto_profile_path = _write_zapret_profile(zapret_root, "mtproto-extra.env")
    entry_contract = _runtime_contract(role="ENTRY")
    transit_contract = _runtime_contract(role="TRANSIT")
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")
    entry_state_path = _write_runtime_state(
        tmp_path,
        "entry-runtime-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
        zapret_profile_file=str(entry_profile_path),
    )
    transit_state_path = _write_runtime_state(
        tmp_path,
        "transit-runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
        zapret_profile_file=str(transit_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
            "--zapret-root",
            str(zapret_root),
            "--entry-runtime-state",
            str(entry_state_path),
            "--transit-runtime-state",
            str(transit_state_path),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "OK runtime contracts, zapret profiles and private handoffs are internally consistent" in out


def test_validate_runtime_contracts_cli_validates_runtime_state_env_when_provided(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    entry_profile_path = _write_zapret_profile(zapret_root, "entry-lite.env")
    transit_profile_path = _write_zapret_profile(zapret_root, "transit-lite.env")
    _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    mtproto_profile_path = _write_zapret_profile(zapret_root, "mtproto-extra.env")
    entry_contract = _runtime_contract(role="ENTRY")
    transit_contract = _runtime_contract(role="TRANSIT")
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")
    entry_state_path = _write_runtime_state(
        tmp_path,
        "entry-runtime-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
        zapret_profile_file=str(entry_profile_path),
    )
    transit_state_path = _write_runtime_state(
        tmp_path,
        "transit-runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
        zapret_profile_file=str(transit_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
    )
    entry_env_path = _write_runtime_env(
        tmp_path,
        "entry-runtime-state.env",
        contract=entry_contract,
        role="ENTRY",
        runtime_state_json=str(entry_state_path),
        runtime_contract_path=str(entry_path),
        zapret_profile_file=str(entry_profile_path),
    )
    transit_env_path = _write_runtime_env(
        tmp_path,
        "transit-runtime-state.env",
        contract=transit_contract,
        role="TRANSIT",
        runtime_state_json=str(transit_state_path),
        runtime_contract_path=str(transit_path),
        zapret_profile_file=str(transit_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
            "--zapret-root",
            str(zapret_root),
            "--entry-runtime-state",
            str(entry_state_path),
            "--transit-runtime-state",
            str(transit_state_path),
            "--entry-runtime-env",
            str(entry_env_path),
            "--transit-runtime-env",
            str(transit_env_path),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "entry_runtime_env=" in out
    assert "transit_runtime_env=" in out
    assert "OK runtime contracts, zapret profiles and private handoffs are internally consistent" in out


def test_validate_runtime_contracts_cli_validates_private_profile_handoffs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    _write_zapret_profile(zapret_root, "entry-lite.env")
    _write_zapret_profile(zapret_root, "transit-lite.env")
    _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    _write_zapret_profile(zapret_root, "mtproto-extra.env")
    entry_contract = _runtime_contract(role="ENTRY")
    transit_contract = _runtime_contract(role="TRANSIT")
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")
    entry_profile_state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/entry/desired-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
    )
    transit_profile_state_path = _write_private_profile_state(
        tmp_path,
        "private/profiles/transit/desired-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
    )
    entry_profile_env_path = _write_private_profile_env(
        tmp_path,
        "private/profiles/entry/desired-state.env",
        state_path=entry_profile_state_path,
        state_payload=json.loads(entry_profile_state_path.read_text(encoding="utf-8")),
    )
    transit_profile_env_path = _write_private_profile_env(
        tmp_path,
        "private/profiles/transit/desired-state.env",
        state_path=transit_profile_state_path,
        state_payload=json.loads(transit_profile_state_path.read_text(encoding="utf-8")),
    )
    profiles_unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-profiles@.service",
        description="Tracegate private profile adapter helper",
        condition_path_exists="/etc/tracegate/private/profiles/run-profiles.sh",
        environment_file="/etc/tracegate/private/profiles/profiles.env",
        runner_path="/etc/tracegate/private/profiles/run-profiles.sh",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
            "--zapret-root",
            str(zapret_root),
            "--entry-profile-state",
            str(entry_profile_state_path),
            "--transit-profile-state",
            str(transit_profile_state_path),
            "--entry-profile-env",
            str(entry_profile_env_path),
            "--transit-profile-env",
            str(transit_profile_env_path),
            "--profiles-unit",
            str(profiles_unit_path),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "entry_profile_state=" in out
    assert "transit_profile_env=" in out
    assert "profiles_unit=" in out
    assert "OK runtime contracts, zapret profiles and private handoffs are internally consistent" in out


def test_validate_runtime_contracts_cli_validates_link_crypto_handoffs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    _write_zapret_profile(zapret_root, "entry-lite.env")
    _write_zapret_profile(zapret_root, "transit-lite.env")
    _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    _write_zapret_profile(zapret_root, "mtproto-extra.env")
    entry_contract = _runtime_contract(role="ENTRY")
    transit_contract = _runtime_contract(role="TRANSIT")
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")
    entry_state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/entry/desired-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
    )
    transit_state_path = _write_link_crypto_state(
        tmp_path,
        "private/link-crypto/transit/desired-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
    )
    entry_env_path = _write_link_crypto_env(
        tmp_path,
        "private/link-crypto/entry/desired-state.env",
        state_path=entry_state_path,
        state_payload=json.loads(entry_state_path.read_text(encoding="utf-8")),
    )
    transit_env_path = _write_link_crypto_env(
        tmp_path,
        "private/link-crypto/transit/desired-state.env",
        state_path=transit_state_path,
        state_payload=json.loads(transit_state_path.read_text(encoding="utf-8")),
    )
    link_crypto_unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-link-crypto@.service",
        description="Tracegate private link-crypto helper",
        condition_path_exists="/etc/tracegate/private/link-crypto/run-link-crypto.sh",
        environment_file="/etc/tracegate/private/link-crypto/link-crypto.env",
        runner_path="/etc/tracegate/private/link-crypto/run-link-crypto.sh",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
            "--zapret-root",
            str(zapret_root),
            "--entry-link-crypto-state",
            str(entry_state_path),
            "--transit-link-crypto-state",
            str(transit_state_path),
            "--entry-link-crypto-env",
            str(entry_env_path),
            "--transit-link-crypto-env",
            str(transit_env_path),
            "--link-crypto-unit",
            str(link_crypto_unit_path),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "entry_link_crypto_state=" in out
    assert "transit_link_crypto_env=" in out
    assert "link_crypto_unit=" in out
    assert "OK runtime contracts, zapret profiles and private handoffs are internally consistent" in out


def test_validate_runtime_contracts_cli_validates_router_handoffs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    entry_contract = _runtime_contract(role="ENTRY")
    transit_contract = _runtime_contract(role="TRANSIT")
    entry_contract["linkCrypto"] = _router_link_crypto_contract(role="ENTRY")
    transit_contract["linkCrypto"] = _router_link_crypto_contract(role="TRANSIT")
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")

    entry_tcp_link = _router_tcp_link(role="ENTRY")
    entry_udp_link = _router_udp_link(role="ENTRY")
    transit_tcp_link = _router_tcp_link(role="TRANSIT")
    transit_udp_link = _router_udp_link(role="TRANSIT")
    entry_router_state_path = _write_router_handoff_state(
        tmp_path,
        "private/router/entry/desired-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
        tcp_routes=[_router_route_from_link(entry_tcp_link, transport="tcp")],
        udp_routes=[_router_route_from_link(entry_udp_link, transport="udp-quic")],
    )
    transit_router_state_path = _write_router_handoff_state(
        tmp_path,
        "private/router/transit/desired-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
        tcp_routes=[_router_route_from_link(transit_tcp_link, transport="tcp")],
        udp_routes=[_router_route_from_link(transit_udp_link, transport="udp-quic")],
    )
    entry_router_env_path = _write_router_handoff_env(
        tmp_path,
        "private/router/entry/desired-state.env",
        state_path=entry_router_state_path,
        state=json.loads(entry_router_state_path.read_text(encoding="utf-8")),
    )
    transit_router_env_path = _write_router_handoff_env(
        tmp_path,
        "private/router/transit/desired-state.env",
        state_path=transit_router_state_path,
        state=json.loads(transit_router_state_path.read_text(encoding="utf-8")),
    )
    entry_router_bundle_path = _write_router_client_bundle(
        tmp_path,
        "private/router/entry/client-bundle.json",
        state_path=entry_router_state_path,
        state=json.loads(entry_router_state_path.read_text(encoding="utf-8")),
    )
    transit_router_bundle_path = _write_router_client_bundle(
        tmp_path,
        "private/router/transit/client-bundle.json",
        state_path=transit_router_state_path,
        state=json.loads(transit_router_state_path.read_text(encoding="utf-8")),
    )
    entry_router_client_env_path = _write_router_client_bundle_env(
        tmp_path,
        "private/router/entry/client-bundle.env",
        bundle_path=entry_router_bundle_path,
        handoff_path=entry_router_state_path,
        bundle=json.loads(entry_router_bundle_path.read_text(encoding="utf-8")),
    )
    transit_router_client_env_path = _write_router_client_bundle_env(
        tmp_path,
        "private/router/transit/client-bundle.env",
        bundle_path=transit_router_bundle_path,
        handoff_path=transit_router_state_path,
        bundle=json.loads(transit_router_bundle_path.read_text(encoding="utf-8")),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
            "--entry-router-state",
            str(entry_router_state_path),
            "--transit-router-state",
            str(transit_router_state_path),
            "--entry-router-env",
            str(entry_router_env_path),
            "--transit-router-env",
            str(transit_router_env_path),
            "--entry-router-client-bundle",
            str(entry_router_bundle_path),
            "--transit-router-client-bundle",
            str(transit_router_bundle_path),
            "--entry-router-client-env",
            str(entry_router_client_env_path),
            "--transit-router-client-env",
            str(transit_router_client_env_path),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "entry_router_state=" in out
    assert "transit_router_env=" in out
    assert "entry_router_client_bundle=" in out
    assert "transit_router_client_env=" in out
    assert "OK runtime contracts and private runtime/env handoffs are internally consistent" in out


def test_validate_runtime_contracts_cli_validates_obfuscation_env_when_provided(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    entry_profile_path = _write_zapret_profile(zapret_root, "entry-lite.env")
    transit_profile_path = _write_zapret_profile(zapret_root, "transit-lite.env")
    _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    mtproto_profile_path = _write_zapret_profile(zapret_root, "mtproto-extra.env")
    entry_contract = _runtime_contract(role="ENTRY")
    transit_contract = _runtime_contract(role="TRANSIT")
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")

    private_runtime_dir = tmp_path / "private"
    zapret_policy_dir = tmp_path / "etc" / "tracegate" / "private" / "zapret"
    zapret_state_dir = private_runtime_dir / "zapret"

    entry_state_path = _write_runtime_state(
        tmp_path,
        "private/obfuscation/entry/runtime-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
        interface="eth0",
        zapret_profile_file=str(entry_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    transit_state_path = _write_runtime_state(
        tmp_path,
        "private/obfuscation/transit/runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
        interface="eth0",
        zapret_profile_file=str(transit_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    entry_env_path = _write_runtime_env(
        tmp_path,
        "private/obfuscation/entry/runtime-state.env",
        contract=entry_contract,
        role="ENTRY",
        runtime_state_json=str(entry_state_path),
        runtime_contract_path=str(entry_path),
        interface="eth0",
        zapret_profile_file=str(entry_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    transit_env_path = _write_runtime_env(
        tmp_path,
        "private/obfuscation/transit/runtime-state.env",
        contract=transit_contract,
        role="TRANSIT",
        runtime_state_json=str(transit_state_path),
        runtime_contract_path=str(transit_path),
        interface="eth0",
        zapret_profile_file=str(transit_profile_path),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
        zapret_policy_dir=str(zapret_policy_dir),
        zapret_state_dir=str(zapret_state_dir),
    )
    obfuscation_env_path = _write_obfuscation_env(
        tmp_path,
        "obfuscation.env",
        TRACEGATE_ZAPRET_PROFILE_DIR=str(zapret_root),
        TRACEGATE_PRIVATE_RUNTIME_DIR=str(private_runtime_dir),
        TRACEGATE_ZAPRET_POLICY_DIR=str(zapret_policy_dir),
        TRACEGATE_ZAPRET_STATE_DIR=str(zapret_state_dir),
        TRACEGATE_ENTRY_RUNTIME_CONTRACT=str(entry_path),
        TRACEGATE_TRANSIT_RUNTIME_CONTRACT=str(transit_path),
    )
    obfuscation_unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-obfuscation@.service",
        description="Tracegate private obfuscation helper",
        condition_path_exists="/etc/tracegate/private/systemd/run-obfuscation.sh",
        environment_file=str(obfuscation_env_path),
        runner_path="/etc/tracegate/private/systemd/run-obfuscation.sh",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
            "--zapret-root",
            str(zapret_root),
            "--obfuscation-env",
            str(obfuscation_env_path),
            "--obfuscation-unit",
            str(obfuscation_unit_path),
            "--entry-runtime-state",
            str(entry_state_path),
            "--transit-runtime-state",
            str(transit_state_path),
            "--entry-runtime-env",
            str(entry_env_path),
            "--transit-runtime-env",
            str(transit_env_path),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "obfuscation_env=" in out
    assert "obfuscation_unit=" in out
    assert "OK runtime contracts, zapret profiles and private handoffs are internally consistent" in out


def test_validate_runtime_contracts_cli_validates_fronting_and_mtproto_handoffs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    _write_zapret_profile(zapret_root, "entry-lite.env")
    _write_zapret_profile(zapret_root, "transit-lite.env")
    _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    mtproto_profile_path = _write_zapret_profile(zapret_root, "mtproto-extra.env")
    entry_contract = _runtime_contract(role="ENTRY")
    transit_contract = _runtime_contract(role="TRANSIT")
    fronting_state_dir = tmp_path / "fronting"
    fronting_runtime_dir = fronting_state_dir / "runtime"
    mtproto_state_dir = tmp_path / "mtproto"
    mtproto_runtime_dir = mtproto_state_dir / "runtime"
    entry_path.write_text(json.dumps(entry_contract) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(transit_contract) + "\n", encoding="utf-8")
    entry_state_path = _write_runtime_state(
        tmp_path,
        "entry-runtime-state.json",
        contract=entry_contract,
        role="ENTRY",
        runtime_contract_path=str(entry_path),
        zapret_profile_file=str(zapret_root / "entry-lite.env"),
    )
    transit_state_path = _write_runtime_state(
        tmp_path,
        "transit-runtime-state.json",
        contract=transit_contract,
        role="TRANSIT",
        runtime_contract_path=str(transit_path),
        zapret_profile_file=str(zapret_root / "transit-lite.env"),
        zapret_mtproto_profile_file=str(mtproto_profile_path),
    )
    fronting_state_path = _write_fronting_state(
        tmp_path,
        "fronting/last-action.json",
        runtime_state_json=str(transit_state_path),
        overrides={
            "mtprotoProfileFile": str(mtproto_profile_path),
            "cfgFile": str(fronting_runtime_dir / "haproxy.cfg"),
            "pidFile": str(fronting_runtime_dir / "haproxy.pid"),
        },
    )
    mtproto_public_profile_path = _write_mtproto_public_profile(tmp_path, "mtproto/public-profile.json")
    mtproto_state_path = _write_mtproto_state(
        tmp_path,
        "mtproto/last-action.json",
        runtime_state_json=str(transit_state_path),
        overrides={
            "profileFile": str(mtproto_profile_path),
            "publicProfileFile": str(mtproto_public_profile_path),
        },
    )
    fronting_env_path = _write_fronting_env(
        tmp_path,
        "fronting.env",
        TRACEGATE_FRONTING_RUNTIME_STATE_JSON=str(transit_state_path),
        TRACEGATE_FRONTING_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
        TRACEGATE_FRONTING_STATE_DIR=str(fronting_state_dir),
        TRACEGATE_FRONTING_RUNTIME_DIR=str(fronting_runtime_dir),
    )
    mtproto_env_path = _write_mtproto_env(
        tmp_path,
        "mtproto.env",
        TRACEGATE_MTPROTO_RUNTIME_STATE_JSON=str(transit_state_path),
        TRACEGATE_MTPROTO_PROFILE_FILE=str(mtproto_profile_path),
        TRACEGATE_MTPROTO_STATE_DIR=str(mtproto_state_dir),
        TRACEGATE_MTPROTO_RUNTIME_DIR=str(mtproto_runtime_dir),
    )
    fronting_unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-fronting@.service",
        description="Tracegate private TCP/443 fronting helper",
        condition_path_exists="/etc/tracegate/private/fronting/run-fronting.sh",
        environment_file=str(fronting_env_path),
        runner_path="/etc/tracegate/private/fronting/run-fronting.sh",
    )
    mtproto_unit_path = _write_private_helper_unit(
        tmp_path,
        "tracegate-mtproto@.service",
        description="Tracegate private MTProto gateway",
        condition_path_exists="/etc/tracegate/private/mtproto/run-mtproto.sh",
        environment_file=str(mtproto_env_path),
        runner_path="/etc/tracegate/private/mtproto/run-mtproto.sh",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
            "--zapret-root",
            str(zapret_root),
            "--entry-runtime-state",
            str(entry_state_path),
            "--transit-runtime-state",
            str(transit_state_path),
            "--fronting-state",
            str(fronting_state_path),
            "--fronting-env",
            str(fronting_env_path),
            "--fronting-unit",
            str(fronting_unit_path),
            "--mtproto-state",
            str(mtproto_state_path),
            "--mtproto-env",
            str(mtproto_env_path),
            "--mtproto-unit",
            str(mtproto_unit_path),
            "--mtproto-public-profile",
            str(mtproto_public_profile_path),
        ],
    )

    validate_runtime_contracts.main()
    out = capsys.readouterr().out
    assert "fronting_unit=" in out
    assert "mtproto_unit=" in out
    assert "OK runtime contracts, zapret profiles and private handoffs are internally consistent" in out


def test_validate_runtime_contracts_cli_exits_nonzero_on_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    entry_path.write_text(json.dumps(_runtime_contract(role="ENTRY", hysteria_tags=[])) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(_runtime_contract(role="TRANSIT")) + "\n", encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
        ],
    )

    with pytest.raises(SystemExit, match="1"):
        validate_runtime_contracts.main()

    out = capsys.readouterr().out
    assert "ERROR [entry-hy2-inbound-missing]" in out


def test_validate_runtime_contracts_cli_reports_zapret_profile_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    entry_path = tmp_path / "entry.json"
    transit_path = tmp_path / "transit.json"
    zapret_root = tmp_path / "zapret"
    zapret_root.mkdir()
    _write_zapret_profile(zapret_root, "entry-lite.env", TRACEGATE_ZAPRET_TARGET_TCP_PORTS="443,8443")
    _write_zapret_profile(zapret_root, "transit-lite.env")
    _write_zapret_profile(zapret_root, "entry-transit-stealth.env")
    entry_path.write_text(json.dumps(_runtime_contract(role="ENTRY")) + "\n", encoding="utf-8")
    transit_path.write_text(json.dumps(_runtime_contract(role="TRANSIT")) + "\n", encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "tracegate-validate-runtime-contracts",
            "--entry",
            str(entry_path),
            "--transit",
            str(transit_path),
            "--zapret-root",
            str(zapret_root),
        ],
    )

    with pytest.raises(SystemExit, match="1"):
        validate_runtime_contracts.main()

    out = capsys.readouterr().out
    assert "ERROR [zapret-entry-tcp-port-widen]" in out
