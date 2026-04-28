from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracegate.cli.k3s_private_reload import K3sPrivateReloadError, main, run_private_reload
from tracegate.services.runtime_contract import TRACEGATE22_CLIENT_PROFILES


PRIVATE_RELOAD_SECRET_CANARIES = (
    "ss-secret",
    "shadow-secret",
    "shadowtls-secret",
    "client-private-secret",
    "server-private-secret",
    "preshared-secret",
    "local-secret",
    "transit.example.com",
    "/etc/tracegate/private",
)


def _assert_no_private_canaries(text: str) -> None:
    for canary in PRIVATE_RELOAD_SECRET_CANARIES:
        assert canary not in text


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def _write_env(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"{key}={value}" for key, value in payload.items()) + "\n", encoding="utf-8")


def _contract(path: Path) -> dict:
    payload = {
        "role": "ENTRY",
        "runtimeProfile": "tracegate-2.2",
        "contract": {"managedComponents": ["xray", "hysteria"], "xrayBackhaulAllowed": False},
        "transportProfiles": {
            "clientNames": list(TRACEGATE22_CLIENT_PROFILES),
            "localSocks": {"auth": "required", "allowAnonymousLocalhost": False},
        },
    }
    _write_json(path, payload)
    return payload


def _private_file_ref(path: str) -> dict:
    return {"kind": "file", "path": path, "secretMaterial": True}


def _zapret2_policy() -> dict:
    return {
        "enabled": True,
        "required": True,
        "profileFile": "/etc/tracegate/private/zapret/entry-transit.env",
        "profileSource": "private-file-reference",
        "profileRef": _private_file_ref("/etc/tracegate/private/zapret/entry-transit.env"),
        "packetShaping": "zapret2-scoped",
        "applyMode": "marked-flow-only",
        "scope": "link-crypto-flow-only",
        "targetSurfaces": ["tcp/443", "entry-transit", "router-link-crypto"],
        "hostWideInterception": False,
        "nfqueue": False,
        "failOpen": True,
    }


def _tcp_dpi_resistance(*, require_outer_carrier: bool, link_class: str) -> dict:
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
            "profileRef": _private_file_ref("/etc/tracegate/private/zapret/entry-transit.env"),
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


def _write_empty_profile_handoff(root: Path, *, role: str, contract: dict, contract_path: Path) -> Path:
    role_lower = role.lower()
    state_path = root / "profiles" / role_lower / "desired-state.json"
    state = {
        "schema": "tracegate.private-profiles.v1",
        "version": 1,
        "role": role.upper(),
        "runtimeProfile": contract["runtimeProfile"],
        "runtimeContractPath": str(contract_path),
        "transportProfiles": contract["transportProfiles"],
        "secretMaterial": True,
        "counts": {"total": 0, "shadowsocks2022ShadowTLS": 0, "wireguardWSTunnel": 0},
        "shadowsocks2022ShadowTLS": [],
        "wireguardWSTunnel": [],
    }
    _write_json(state_path, state)
    _write_env(
        root / "profiles" / role_lower / "desired-state.env",
        {
            "TRACEGATE_PROFILE_ROLE": role.upper(),
            "TRACEGATE_PROFILE_RUNTIME_PROFILE": contract["runtimeProfile"],
            "TRACEGATE_PROFILE_STATE_JSON": state_path,
            "TRACEGATE_PROFILE_SECRET_MATERIAL": "true",
            "TRACEGATE_PROFILE_COUNT": 0,
            "TRACEGATE_SHADOWSOCKS2022_SHADOWTLS_COUNT": 0,
            "TRACEGATE_WIREGUARD_WSTUNNEL_COUNT": 0,
        },
    )
    return state_path


def _local_socks() -> dict:
    return {
        "enabled": True,
        "listen": "127.0.0.1:1080",
        "auth": {"required": True, "mode": "username_password", "username": "local-user", "password": "local-secret"},
    }


def _shadowtls_profile(*, mode: str) -> dict:
    mode_lower = mode.strip().lower()
    is_chain = mode_lower == "chain"
    chain = None
    stage = "direct-transit-public"
    outer = "shadowtls-v3"
    if is_chain:
        stage = "transit-private-terminator"
        outer = "wss-carrier"
        chain = {
            "type": "entry_transit_private_relay",
            "entry": "entry.example.com",
            "transit": "transit.example.com",
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
    return {
        "role": "TRANSIT",
        "userId": "101",
        "userDisplay": "@user",
        "deviceId": "device",
        "deviceName": "Laptop",
        "connectionId": f"conn-v3-{mode_lower}",
        "revisionId": f"rev-v3-{mode_lower}",
        "mode": mode_lower,
        "variant": "V3",
        "profile": "v3-chain-shadowtls-shadowsocks" if is_chain else "v3-direct-shadowtls-shadowsocks",
        "protocol": "shadowsocks2022_shadowtls",
        "stage": stage,
        "server": "transit.example.com",
        "port": 443,
        "sni": "cdn.example.com",
        "shadowsocks2022": {"method": "2022-blake3-aes-128-gcm", "password": f"ss-secret-v3-{mode_lower}"},
        "shadowtls": {
            "version": 3,
            "serverName": "cdn.example.com",
            "credentialScope": "node-static",
            "profileRef": {
                "kind": "file",
                "path": "/etc/tracegate/private/shadowtls/transit-config.yaml",
                "secretMaterial": True,
            },
            "manageUsers": False,
            "restartOnUserChange": False,
        },
        "localSocks": _local_socks(),
        "chain": chain,
        "obfuscation": {
            "scope": "entry-transit-private-relay" if is_chain else "public-tcp-443",
            "outer": outer,
            "packetShaping": "zapret2-scoped",
            "hostWideInterception": False,
        },
    }


def _wireguard_profile() -> dict:
    return {
        "role": "TRANSIT",
        "connectionId": "conn-v0",
        "revisionId": "rev-v0",
        "variant": "V0",
        "profile": "v0-wgws-wireguard",
        "protocol": "wireguard_wstunnel",
        "stage": "direct-transit-public",
        "server": "transit.example.com",
        "port": 443,
        "sni": "transit.example.com",
        "wstunnel": {
            "mode": "wireguard-over-websocket",
            "url": "wss://transit.example.com:443/cdn-cgi/tracegate",
            "path": "/cdn-cgi/tracegate",
            "tlsServerName": "transit.example.com",
            "localUdpListen": "127.0.0.1:51820",
        },
        "wireguard": {
            "clientPublicKey": "client-public",
            "clientPrivateKey": "client-private-secret",
            "serverPublicKey": "server-public",
            "presharedKey": "preshared-secret",
            "address": "10.7.0.10/32",
            "allowedIps": ["10.7.0.10/32"],
            "clientRouteAllowedIps": ["0.0.0.0/0"],
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
        "localSocks": _local_socks(),
        "chain": None,
        "obfuscation": {
            "scope": "public-wss-443",
            "outer": "wstunnel",
            "packetShaping": "zapret2-scoped",
            "hostWideInterception": False,
        },
    }


def _write_transit_profile_handoff(root: Path, *, contract: dict, contract_path: Path) -> Path:
    state_path = root / "profiles" / "transit" / "desired-state.json"
    state = {
        "schema": "tracegate.private-profiles.v1",
        "version": 1,
        "role": "TRANSIT",
        "runtimeProfile": contract["runtimeProfile"],
        "runtimeContractPath": str(contract_path),
        "transportProfiles": contract["transportProfiles"],
        "secretMaterial": True,
        "counts": {"total": 3, "shadowsocks2022ShadowTLS": 2, "wireguardWSTunnel": 1},
        "shadowsocks2022ShadowTLS": [_shadowtls_profile(mode="direct"), _shadowtls_profile(mode="chain")],
        "wireguardWSTunnel": [_wireguard_profile()],
    }
    _write_json(state_path, state)
    _write_env(
        root / "profiles" / "transit" / "desired-state.env",
        {
            "TRACEGATE_PROFILE_ROLE": "TRANSIT",
            "TRACEGATE_PROFILE_RUNTIME_PROFILE": contract["runtimeProfile"],
            "TRACEGATE_PROFILE_STATE_JSON": state_path,
            "TRACEGATE_PROFILE_SECRET_MATERIAL": "true",
            "TRACEGATE_PROFILE_COUNT": 3,
            "TRACEGATE_SHADOWSOCKS2022_SHADOWTLS_COUNT": 2,
            "TRACEGATE_WIREGUARD_WSTUNNEL_COUNT": 1,
        },
    )
    return state_path


def _write_link_crypto_handoff(
    root: Path,
    *,
    role: str,
    contract: dict,
    contract_path: Path,
    link_class: str = "entry-transit",
) -> Path:
    role_upper = role.upper()
    role_lower = role.lower()
    side = "client" if role_upper == "ENTRY" and link_class == "entry-transit" else "server"
    local_port = {
        "entry-transit": 10881 if role_upper == "ENTRY" else 10882,
        "router-entry": 10883,
        "router-transit": 10884,
    }[link_class]
    remote_role = "ROUTER" if link_class in {"router-entry", "router-transit"} else ("TRANSIT" if role_upper == "ENTRY" else "ENTRY")
    selected_profiles = ["V0", "V1", "V3"] if link_class == "router-transit" else ["V1", "V3"]
    outer_carrier = {
        "enabled": link_class == "entry-transit",
        "mode": "wss" if link_class == "entry-transit" else "direct",
        "protocol": "websocket-tls" if link_class == "entry-transit" else "",
        "serverName": "bridge.example.com" if link_class == "entry-transit" else "",
        "publicPort": 443 if link_class == "entry-transit" else 0,
        "publicPath": "/cdn-cgi/tracegate-link" if link_class == "entry-transit" else "",
        "url": "wss://bridge.example.com:443/cdn-cgi/tracegate-link" if link_class == "entry-transit" else "",
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
    state_path = root / "link-crypto" / role_lower / "desired-state.json"
    state = {
        "schema": "tracegate.link-crypto.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": contract["runtimeProfile"],
        "runtimeContractPath": str(contract_path),
        "transportProfiles": contract["transportProfiles"],
        "secretMaterial": False,
        "counts": {
            "total": 1,
            "entryTransit": 1 if link_class == "entry-transit" else 0,
            "routerEntry": 1 if link_class == "router-entry" else 0,
            "routerTransit": 1 if link_class == "router-transit" else 0,
        },
        "links": [
            {
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
                "local": {"listen": f"127.0.0.1:{local_port}", "auth": {"required": True, "mode": "private-profile"}},
                "remote": {"role": remote_role, "endpoint": "transit.example.com:443"},
                "outerCarrier": outer_carrier,
                "selectedProfiles": selected_profiles,
                "zapret2": _zapret2_policy(),
                "dpiResistance": _tcp_dpi_resistance(
                    require_outer_carrier=link_class == "entry-transit",
                    link_class=link_class,
                ),
                "rotation": {"strategy": "generation-drain", "restartExisting": False},
                "stability": {"failOpen": True, "bypassOnFailure": True, "dropUnrelatedTraffic": False},
            }
        ],
    }
    _write_json(state_path, state)
    _write_env(
        root / "link-crypto" / role_lower / "desired-state.env",
        {
            "TRACEGATE_LINK_CRYPTO_ROLE": role_upper,
            "TRACEGATE_LINK_CRYPTO_RUNTIME_PROFILE": contract["runtimeProfile"],
            "TRACEGATE_LINK_CRYPTO_STATE_JSON": state_path,
            "TRACEGATE_LINK_CRYPTO_SECRET_MATERIAL": "false",
            "TRACEGATE_LINK_CRYPTO_COUNT": 1,
            "TRACEGATE_LINK_CRYPTO_CLASSES": link_class,
            "TRACEGATE_LINK_CRYPTO_CARRIER": "mieru",
            "TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_ENABLED": "true" if link_class == "entry-transit" else "false",
            "TRACEGATE_LINK_CRYPTO_OUTER_CARRIER_MODE": "wss" if link_class == "entry-transit" else "direct",
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_SERVER_NAME": "bridge.example.com",
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_PUBLIC_PORT": 443,
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_PATH": "/cdn-cgi/tracegate-link",
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_VERIFY_TLS": "true" if link_class == "entry-transit" else "false",
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_SPKI_PINNING_REQUIRED": "true" if link_class == "entry-transit" else "false",
            "TRACEGATE_LINK_CRYPTO_OUTER_WSS_ADMISSION_REQUIRED": "true" if link_class == "entry-transit" else "false",
            "TRACEGATE_LINK_CRYPTO_GENERATION": 1,
            "TRACEGATE_LINK_CRYPTO_ZAPRET2_ENABLED": "true",
            "TRACEGATE_LINK_CRYPTO_ZAPRET2_REQUIRED": "true",
            "TRACEGATE_LINK_CRYPTO_ZAPRET2_HOST_WIDE_INTERCEPTION": "false",
            "TRACEGATE_LINK_CRYPTO_ZAPRET2_NFQUEUE": "false",
            "TRACEGATE_LINK_CRYPTO_TCP_DPI_RESISTANCE_REQUIRED": "true",
            "TRACEGATE_LINK_CRYPTO_TCP_TRAFFIC_SHAPING_REQUIRED": "true",
            "TRACEGATE_LINK_CRYPTO_PROMOTION_PREFLIGHT_REQUIRED": "true",
        },
    )
    return state_path


def _router_route_from_link(row: dict) -> dict:
    local = row["local"]
    remote = row["remote"]
    role_lower = row["role"].lower()
    link_class = row["class"]
    return {
        "class": link_class,
        "enabled": True,
        "serverRole": row["role"],
        "serverSide": row["side"],
        "remoteRole": remote["role"],
        "carrier": row["carrier"],
        "transport": "tcp",
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
            "profileRefs": {
                "mieruClient": {
                    "kind": "file",
                    "path": f"/etc/tracegate/private/router/{role_lower}/{link_class}/mieru-client.json",
                    "secretMaterial": True,
                }
            },
        },
        "outerCarrier": row["outerCarrier"],
        "zapret2": row["zapret2"],
        "dpiResistance": row["dpiResistance"],
    }


def _write_router_handoff_bundle(root: Path, *, role: str, contract: dict, contract_path: Path) -> None:
    role_upper = role.upper()
    role_lower = role.lower()
    link_state = json.loads((root / "link-crypto" / role_lower / "desired-state.json").read_text(encoding="utf-8"))
    tcp_routes = [_router_route_from_link(row) for row in link_state["links"] if row["class"] in {"router-entry", "router-transit"}]
    state_path = root / "router" / role_lower / "desired-state.json"
    state = {
        "schema": "tracegate.router-handoff.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": contract["runtimeProfile"],
        "runtimeContractPath": str(contract_path),
        "secretMaterial": False,
        "enabled": bool(tcp_routes),
        "placement": "personal-router-before-entry" if role_upper == "ENTRY" else "personal-router-before-transit",
        "contract": {
            "routerIsEntryReplacement": False,
            "requiresServerSideLinkCrypto": True,
            "requiresPrivateRouterProfile": bool(tcp_routes),
            "noHostWideInterception": True,
            "noNfqueue": True,
        },
        "counts": {"total": len(tcp_routes), "tcp": len(tcp_routes), "udp": 0},
        "classes": {"tcp": [row["class"] for row in tcp_routes], "udp": []},
        "routes": {"tcp": tcp_routes, "udp": []},
    }
    _write_json(state_path, state)
    _write_env(
        root / "router" / role_lower / "desired-state.env",
        {
            "TRACEGATE_ROUTER_HANDOFF_ROLE": role_upper,
            "TRACEGATE_ROUTER_HANDOFF_RUNTIME_PROFILE": contract["runtimeProfile"],
            "TRACEGATE_ROUTER_HANDOFF_STATE_JSON": state_path,
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_JSON": root / "router" / role_lower / "client-bundle.json",
            "TRACEGATE_ROUTER_HANDOFF_SECRET_MATERIAL": "false",
            "TRACEGATE_ROUTER_HANDOFF_ENABLED": "true" if tcp_routes else "false",
            "TRACEGATE_ROUTER_HANDOFF_COUNT": len(tcp_routes),
            "TRACEGATE_ROUTER_HANDOFF_TCP_COUNT": len(tcp_routes),
            "TRACEGATE_ROUTER_HANDOFF_UDP_COUNT": 0,
            "TRACEGATE_ROUTER_HANDOFF_TCP_CLASSES": ":".join(row["class"] for row in tcp_routes),
            "TRACEGATE_ROUTER_HANDOFF_UDP_CLASSES": "",
            "TRACEGATE_ROUTER_HANDOFF_PAIRED_OBFS_ENABLED": "false",
            "TRACEGATE_ROUTER_HANDOFF_REQUIRES_PRIVATE_PROFILE": "true" if tcp_routes else "false",
            "TRACEGATE_ROUTER_HANDOFF_ROUTER_IS_ENTRY_REPLACEMENT": "false",
            "TRACEGATE_ROUTER_HANDOFF_NO_HOST_WIDE_INTERCEPTION": "true",
            "TRACEGATE_ROUTER_HANDOFF_NO_NFQUEUE": "true",
        },
    )

    bundle_routes = [
        {
            "class": row["class"],
            "enabled": row["enabled"],
            "transport": "tcp",
            "serverRole": row["serverRole"],
            "routerRole": "ROUTER",
            "serverEndpoint": row["publicEndpoint"],
            "selectedProfiles": row["selectedProfiles"],
            "routerSide": {
                "mode": "client",
                "requiresPrivateProfile": True,
                "profileRefs": row["routerClient"]["profileRefs"],
                "failClosed": True,
                "hostWideInterception": False,
                "nfqueue": False,
            },
            "serverSide": {
                "mode": "server",
                "listen": row["serverListen"],
                "auth": row["auth"],
            },
            "carrier": "mieru",
            "outerCarrier": row["outerCarrier"],
        }
        for row in tcp_routes
    ]
    bundle_path = root / "router" / role_lower / "client-bundle.json"
    bundle = {
        "schema": "tracegate.router-client-bundle.v1",
        "version": 1,
        "role": role_upper,
        "runtimeProfile": contract["runtimeProfile"],
        "handoffStateJson": str(state_path),
        "secretMaterial": False,
        "enabled": bool(bundle_routes),
        "placement": state["placement"],
        "counts": state["counts"],
        "classes": state["classes"],
        "requirements": {
            "routerIsEntryReplacement": False,
            "requiresPrivateProfile": bool(bundle_routes),
            "requiresServerSideLinkCrypto": True,
            "requiresBothSides": bool(bundle_routes),
            "failClosed": True,
            "noHostWideInterception": True,
            "noNfqueue": True,
            "profileDistribution": "external-private-files",
        },
        "components": [
            {
                "name": "mieru-client",
                "required": bool(bundle_routes),
                "transports": ["tcp"],
                "failClosed": True,
                "noHostWideInterception": True,
                "noNfqueue": True,
            },
            {
                "name": "hysteria2-client",
                "required": False,
                "transports": ["udp-quic"],
                "obfs": "salamander",
                "failClosed": True,
                "noHostWideInterception": True,
                "noNfqueue": True,
            },
            {
                "name": "paired-udp-obfs",
                "required": False,
                "backend": "udp2raw",
                "requiresBothSides": True,
                "failClosed": True,
                "noHostWideInterception": True,
                "noNfqueue": True,
            },
        ],
        "routes": {"tcp": bundle_routes, "udp": []},
    }
    _write_json(bundle_path, bundle)
    _write_env(
        root / "router" / role_lower / "client-bundle.env",
        {
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_ROLE": role_upper,
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_RUNTIME_PROFILE": contract["runtimeProfile"],
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_JSON": bundle_path,
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_HANDOFF_JSON": state_path,
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_SECRET_MATERIAL": "false",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_ENABLED": "true" if bundle_routes else "false",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_COMPONENTS": "mieru-client" if bundle_routes else "",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_TCP_COUNT": len(bundle_routes),
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_UDP_COUNT": 0,
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_REQUIRES_BOTH_SIDES": "true" if bundle_routes else "false",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_FAIL_CLOSED": "true",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_HOST_WIDE_INTERCEPTION": "true",
            "TRACEGATE_ROUTER_CLIENT_BUNDLE_NO_NFQUEUE": "true",
        },
    )


def test_k3s_private_reload_validates_profiles_and_writes_redacted_marker(tmp_path: Path) -> None:
    contract_path = tmp_path / "runtime" / "runtime-contract.json"
    contract = _contract(contract_path)
    private_root = tmp_path / "private"
    _write_empty_profile_handoff(private_root, role="ENTRY", contract=contract, contract_path=contract_path)

    result = run_private_reload(
        component="profiles",
        role="ENTRY",
        private_runtime_root=private_root,
        runtime_contract=contract_path,
    )

    marker_path = Path(str(result["markerPath"]))
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["schema"] == "tracegate.k3s-private-reload.v1"
    assert marker["summarySchema"] == "tracegate.k3s-private-reload-summary.v1"
    assert marker["component"] == "profiles"
    assert marker["summary"]["total"] == 0
    assert marker["summary"]["protocols"]["shadowsocks2022ShadowTLS"] == 0
    assert marker["summary"]["transportProfiles"]["clientCount"] == len(TRACEGATE22_CLIENT_PROFILES)
    assert marker["summary"]["transportProfiles"]["localSocks"] == {
        "auth": "required",
        "allowAnonymousLocalhost": False,
    }
    assert marker["summary"]["sources"]["state"]["sizeBytes"] > 0
    assert marker["summary"]["sources"]["env"]["sizeBytes"] > 0
    assert "desired-state" not in json.dumps(marker)


def test_k3s_private_reload_profile_marker_summarizes_without_profile_secrets(tmp_path: Path) -> None:
    contract_path = tmp_path / "runtime" / "runtime-contract.json"
    contract = _contract(contract_path)
    private_root = tmp_path / "private"
    _write_transit_profile_handoff(private_root, contract=contract, contract_path=contract_path)

    result = run_private_reload(
        component="profiles",
        role="TRANSIT",
        private_runtime_root=private_root,
        runtime_contract=contract_path,
    )

    marker = json.loads(Path(str(result["markerPath"])).read_text(encoding="utf-8"))
    summary = marker["summary"]
    assert summary["protocols"] == {"shadowsocks2022ShadowTLS": 2, "wireguardWSTunnel": 1}
    assert summary["variants"] == ["V0", "V3"]
    assert summary["transportProfiles"]["clientNames"] == sorted(TRACEGATE22_CLIENT_PROFILES)
    assert summary["transportProfiles"]["localSocks"]["auth"] == "required"
    assert summary["localSocks"]["authRequired"] == 3
    assert summary["localSocks"]["anonymous"] == 0
    assert summary["chain"]["managedBy"] == ["link-crypto"]
    assert summary["obfuscation"]["outers"] == ["shadowtls-v3", "wss-carrier", "wstunnel"]
    assert summary["shadowtlsOuter"] == {
        "total": 2,
        "credentialScopes": ["node-static"],
        "fileProfileRefs": 2,
        "secretProfileRefs": 2,
        "perUserPasswords": 0,
        "manageUsers": 0,
        "restartOnUserChange": 0,
    }
    assert summary["wireguardSync"] == {
        "total": 1,
        "strategies": ["wg-set"],
        "interfaces": ["wg0"],
        "livePeerSync": 1,
        "removeStalePeers": 1,
        "restartWireGuard": 0,
        "restartWSTunnel": 0,
    }
    assert summary["sources"]["state"]["mtimeNs"] > 0
    assert summary["sources"]["env"]["mtimeNs"] > 0
    _assert_no_private_canaries(json.dumps(marker))


def test_k3s_private_reload_validates_link_crypto_and_writes_marker(tmp_path: Path) -> None:
    contract_path = tmp_path / "runtime" / "runtime-contract.json"
    contract = _contract(contract_path)
    private_root = tmp_path / "private"
    _write_link_crypto_handoff(private_root, role="ENTRY", contract=contract, contract_path=contract_path)

    result = run_private_reload(
        component="link-crypto",
        role="ENTRY",
        private_runtime_root=private_root,
        runtime_contract=contract_path,
    )

    marker = json.loads(Path(str(result["markerPath"])).read_text(encoding="utf-8"))
    assert marker["component"] == "link-crypto"
    assert marker["summary"]["classes"]["entryTransit"] == 1
    assert marker["summary"]["carriers"] == ["mieru"]
    assert marker["summary"]["remote"] == {"roles": ["TRANSIT"], "endpointCount": 1}
    assert marker["summary"]["outerCarrier"] == {
        "enabled": 1,
        "modes": ["wss"],
        "protocols": ["websocket-tls"],
        "verifyTls": 1,
        "secretMaterial": 0,
    }
    assert marker["summary"]["profileRefs"] == {
        "fileRefs": 1,
        "inlineRefs": 0,
        "secretMaterial": 1,
        "missingPath": 0,
    }
    assert marker["summary"]["localAuth"]["authRequired"] == 1
    assert marker["summary"]["zapret2"]["hostWideInterception"] == 0
    assert marker["summary"]["zapret2"]["nfqueue"] == 0
    assert marker["summary"]["stability"]["restartExisting"] == 0
    assert marker["summary"]["selectedProfiles"] == ["V1", "V3"]
    assert marker["summary"]["transportProfiles"]["clientCount"] == len(TRACEGATE22_CLIENT_PROFILES)
    assert marker["summary"]["transportProfiles"]["localSocks"]["auth"] == "required"
    assert marker["summary"]["sources"]["state"]["sizeBytes"] > 0
    assert marker["summary"]["sources"]["env"]["sizeBytes"] > 0
    _assert_no_private_canaries(json.dumps(marker))


@pytest.mark.parametrize(
    ("role", "link_class", "selected_profiles"),
    [
        ("ENTRY", "router-entry", ["V1", "V3"]),
        ("TRANSIT", "router-transit", ["V0", "V1", "V3"]),
    ],
)
def test_k3s_private_reload_validates_router_only_link_crypto_marker(
    tmp_path: Path,
    role: str,
    link_class: str,
    selected_profiles: list[str],
) -> None:
    contract_path = tmp_path / "runtime" / "runtime-contract.json"
    contract = _contract(contract_path)
    contract["role"] = role
    _write_json(contract_path, contract)
    private_root = tmp_path / "private"
    _write_link_crypto_handoff(
        private_root,
        role=role,
        contract=contract,
        contract_path=contract_path,
        link_class=link_class,
    )
    _write_router_handoff_bundle(private_root, role=role, contract=contract, contract_path=contract_path)

    result = run_private_reload(
        component="link-crypto",
        role=role,
        private_runtime_root=private_root,
        runtime_contract=contract_path,
    )

    marker = json.loads(Path(str(result["markerPath"])).read_text(encoding="utf-8"))
    summary = marker["summary"]
    assert summary["classes"] == {
        "entryTransit": 0,
        "routerEntry": 1 if link_class == "router-entry" else 0,
        "routerTransit": 1 if link_class == "router-transit" else 0,
    }
    assert summary["remote"] == {"roles": ["ROUTER"], "endpointCount": 1}
    assert summary["profileRefs"] == {
        "fileRefs": 1,
        "inlineRefs": 0,
        "secretMaterial": 1,
        "missingPath": 0,
    }
    assert summary["sides"] == ["server"]
    assert summary["selectedProfiles"] == selected_profiles
    assert summary["localAuth"] == {
        "total": 1,
        "authRequired": 1,
        "anonymous": 0,
        "modes": ["private-profile"],
    }
    _assert_no_private_canaries(json.dumps(marker))


def test_k3s_private_reload_link_crypto_validates_router_client_bundle(tmp_path: Path) -> None:
    contract_path = tmp_path / "runtime" / "runtime-contract.json"
    contract = _contract(contract_path)
    private_root = tmp_path / "private"
    _write_link_crypto_handoff(
        private_root,
        role="ENTRY",
        contract=contract,
        contract_path=contract_path,
        link_class="router-entry",
    )
    _write_router_handoff_bundle(private_root, role="ENTRY", contract=contract, contract_path=contract_path)

    result = run_private_reload(
        component="link-crypto",
        role="ENTRY",
        private_runtime_root=private_root,
        runtime_contract=contract_path,
    )

    marker = json.loads(Path(str(result["markerPath"])).read_text(encoding="utf-8"))
    router = marker["summary"]["router"]
    assert router["enabled"] is True
    assert router["counts"] == {"total": 1, "tcp": 1, "udp": 0}
    assert router["classes"] == {"tcp": ["router-entry"], "udp": []}
    assert router["bundle"]["components"]["required"] == ["mieru-client"]
    assert router["bundle"]["profileDistribution"] == "external-private-files"
    assert router["profileRefs"] == {
        "total": 2,
        "fileRefs": 2,
        "secretMaterial": 2,
        "missingPath": 0,
    }
    assert router["env"]["clientComponents"] == ["mieru-client"]
    assert router["env"]["clientFailClosed"] is True
    assert router["sources"]["clientBundle"]["sizeBytes"] > 0
    assert router["sources"]["clientEnv"]["mtimeNs"] > 0
    _assert_no_private_canaries(json.dumps(marker))


def test_k3s_private_reload_link_crypto_fails_on_invalid_router_bundle(tmp_path: Path) -> None:
    contract_path = tmp_path / "runtime" / "runtime-contract.json"
    contract = _contract(contract_path)
    private_root = tmp_path / "private"
    _write_link_crypto_handoff(
        private_root,
        role="ENTRY",
        contract=contract,
        contract_path=contract_path,
        link_class="router-entry",
    )
    _write_router_handoff_bundle(private_root, role="ENTRY", contract=contract, contract_path=contract_path)
    bundle_path = private_root / "router" / "entry" / "client-bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["requirements"]["noNfqueue"] = False
    _write_json(bundle_path, bundle)

    with pytest.raises(K3sPrivateReloadError, match="router handoff validation failed"):
        run_private_reload(
            component="link-crypto",
            role="ENTRY",
            private_runtime_root=private_root,
            runtime_contract=contract_path,
        )


def test_k3s_private_reload_fails_on_invalid_handoff(tmp_path: Path) -> None:
    contract_path = tmp_path / "runtime" / "runtime-contract.json"
    contract = _contract(contract_path)
    private_root = tmp_path / "private"
    state_path = _write_link_crypto_handoff(private_root, role="ENTRY", contract=contract, contract_path=contract_path)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["links"][0]["zapret2"]["nfqueue"] = True
    _write_json(state_path, state)

    with pytest.raises(K3sPrivateReloadError, match="nfqueue"):
        run_private_reload(
            component="link-crypto",
            role="ENTRY",
            private_runtime_root=private_root,
            runtime_contract=contract_path,
        )


def test_k3s_private_reload_cli_prints_marker_without_secrets(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    contract_path = tmp_path / "runtime" / "runtime-contract.json"
    contract = _contract(contract_path)
    private_root = tmp_path / "private"
    _write_transit_profile_handoff(private_root, contract=contract, contract_path=contract_path)

    main(
        [
            "--component",
            "profiles",
            "--role",
            "TRANSIT",
            "--private-runtime-root",
            str(private_root),
            "--runtime-contract",
            str(contract_path),
        ]
    )

    out = capsys.readouterr().out
    assert "OK k3s private reload component=profiles role=TRANSIT" in out
    assert "desired-state.json" not in out
    _assert_no_private_canaries(out)
