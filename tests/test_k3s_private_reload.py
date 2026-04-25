from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracegate.cli.k3s_private_reload import K3sPrivateReloadError, main, run_private_reload
from tracegate.services.runtime_contract import TRACEGATE21_CLIENT_PROFILES


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
        "runtimeProfile": "tracegate-2.1",
        "contract": {"managedComponents": ["xray"], "xrayBackhaulAllowed": False},
        "transportProfiles": {
            "clientNames": list(TRACEGATE21_CLIENT_PROFILES),
            "localSocks": {"auth": "required", "allowAnonymousLocalhost": False},
        },
    }
    _write_json(path, payload)
    return payload


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


def _shadowtls_profile(*, variant: str) -> dict:
    chain = None
    stage = "direct-transit-public"
    outer = "shadowtls-v3"
    if variant == "V6":
        stage = "transit-private-terminator"
        outer = "mieru"
        chain = {
            "type": "entry_transit_private_relay",
            "entry": "entry.example.com",
            "transit": "transit.example.com",
            "linkClass": "entry-transit",
            "carrier": "mieru",
            "preferredOuter": "mieru",
            "optionalPacketShaping": "zapret2-scoped",
            "managedBy": "link-crypto",
            "selectedProfiles": ["V2", "V4", "V6"],
            "innerTransport": "shadowsocks2022-shadowtls-v3",
            "xrayBackhaul": False,
        }
    return {
        "role": "TRANSIT",
        "userId": "101",
        "userDisplay": "@user",
        "deviceId": "device",
        "deviceName": "Laptop",
        "connectionId": f"conn-{variant.lower()}",
        "revisionId": f"rev-{variant.lower()}",
        "variant": variant,
        "profile": f"{variant}-Shadowsocks2022-ShadowTLS-{'Chain' if variant == 'V6' else 'Direct'}",
        "protocol": "shadowsocks2022_shadowtls",
        "stage": stage,
        "server": "transit.example.com",
        "port": 443,
        "sni": "cdn.example.com",
        "shadowsocks2022": {"method": "2022-blake3-aes-128-gcm", "password": f"ss-secret-{variant.lower()}"},
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
            "scope": "entry-transit-private-relay" if variant == "V6" else "public-tcp-443",
            "outer": outer,
            "packetShaping": "zapret2-scoped",
            "hostWideInterception": False,
        },
    }


def _wireguard_profile() -> dict:
    return {
        "role": "TRANSIT",
        "connectionId": "conn-v7",
        "revisionId": "rev-v7",
        "variant": "V7",
        "profile": "V7-WireGuard-WSTunnel-Direct",
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
        "shadowsocks2022ShadowTLS": [_shadowtls_profile(variant="V5"), _shadowtls_profile(variant="V6")],
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
    selected_profiles = ["V1", "V3", "V5", "V7"] if link_class == "router-transit" else ["V2", "V4", "V6"]
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
                "selectedProfiles": selected_profiles,
                "zapret2": {
                    "enabled": False,
                    "profileFile": "/etc/tracegate/private/zapret/entry-transit.env",
                    "packetShaping": "zapret2-scoped",
                    "applyMode": "marked-flow-only",
                    "hostWideInterception": False,
                    "nfqueue": False,
                    "failOpen": True,
                },
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
            "TRACEGATE_LINK_CRYPTO_GENERATION": 1,
            "TRACEGATE_LINK_CRYPTO_ZAPRET2_ENABLED": "false",
            "TRACEGATE_LINK_CRYPTO_ZAPRET2_HOST_WIDE_INTERCEPTION": "false",
            "TRACEGATE_LINK_CRYPTO_ZAPRET2_NFQUEUE": "false",
        },
    )
    return state_path


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
    assert marker["summary"]["transportProfiles"]["clientCount"] == len(TRACEGATE21_CLIENT_PROFILES)
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
    assert summary["variants"] == ["V5", "V6", "V7"]
    assert summary["transportProfiles"]["clientNames"] == sorted(TRACEGATE21_CLIENT_PROFILES)
    assert summary["transportProfiles"]["localSocks"]["auth"] == "required"
    assert summary["localSocks"]["authRequired"] == 3
    assert summary["localSocks"]["anonymous"] == 0
    assert summary["chain"]["managedBy"] == ["link-crypto"]
    assert summary["obfuscation"]["outers"] == ["mieru", "shadowtls-v3", "wstunnel"]
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
    assert marker["summary"]["selectedProfiles"] == ["V2", "V4", "V6"]
    assert marker["summary"]["transportProfiles"]["clientCount"] == len(TRACEGATE21_CLIENT_PROFILES)
    assert marker["summary"]["transportProfiles"]["localSocks"]["auth"] == "required"
    assert marker["summary"]["sources"]["state"]["sizeBytes"] > 0
    assert marker["summary"]["sources"]["env"]["sizeBytes"] > 0
    _assert_no_private_canaries(json.dumps(marker))


@pytest.mark.parametrize(
    ("role", "link_class", "selected_profiles"),
    [
        ("ENTRY", "router-entry", ["V2", "V4", "V6"]),
        ("TRANSIT", "router-transit", ["V1", "V3", "V5", "V7"]),
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
