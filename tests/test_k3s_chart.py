import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tracegate.services.runtime_contract import TRACEGATE3_CLIENT_PROFILES


CHART_ROOT = Path("deploy/k3s/tracegate")
K3S_PROD_EXAMPLE = Path("deploy/k3s/values-prod.example.yaml")
ENTRY_ENDPOINT_EXAMPLE = Path("deploy/k3s/values-entry-endpoint.example.yaml")
ENDPOINT_FIRST_EXAMPLE = Path("deploy/k3s/values-endpoint-first.example.yaml")
PRIVATE_PROFILE_BODY_CANARIES = (
    "client-private-secret",
    "server-private-secret",
    "preshared-secret",
    "ss-secret",
    "shadow-secret",
    "shadowtls-secret",
    "local-secret",
    "mtproto-secret-body",
    "Shadowsocks2022ShadowTLSCredential",
    "TRACEGATE_ZAPRET_PACKET_POLICY",
    "nfqws",
    "dpi-desync",
    "desync-profile",
    "REPLACE_CLIENT_WIREGUARD_PRIVATE_KEY",
    "REPLACE_SHADOWTLS_PASSWORD",
    "REPLACE_SS_PASSWORD",
)


def _values() -> dict:
    return yaml.safe_load((CHART_ROOT / "values.yaml").read_text(encoding="utf-8"))


def _chart_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(CHART_ROOT.rglob("*")) if path.is_file())


def _public_k3s_text() -> str:
    paths = [path for path in CHART_ROOT.rglob("*") if path.is_file()]
    paths.extend([K3S_PROD_EXAMPLE, ENTRY_ENDPOINT_EXAMPLE, ENDPOINT_FIRST_EXAMPLE])
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(paths, key=str))


def _helm_docs(rendered: str) -> list[dict]:
    return [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]


def _gateway_deployment_templates(rendered: str) -> dict[str, dict]:
    templates: dict[str, dict] = {}
    for doc in _helm_docs(rendered):
        if doc.get("kind") != "Deployment":
            continue
        labels = doc.get("metadata", {}).get("labels", {})
        component = labels.get("app.kubernetes.io/component", "")
        if not str(component).startswith("gateway-"):
            continue
        templates[component] = doc["spec"]["template"]
    return templates


def _gateway_deployments(rendered: str) -> dict[str, dict]:
    deployments: dict[str, dict] = {}
    for doc in _helm_docs(rendered):
        if doc.get("kind") != "Deployment":
            continue
        labels = doc.get("metadata", {}).get("labels", {})
        component = labels.get("app.kubernetes.io/component", "")
        if not str(component).startswith("gateway-"):
            continue
        deployments[component] = doc
    return deployments


def _deployment_by_component(rendered: str, component: str) -> dict:
    for doc in _helm_docs(rendered):
        if doc.get("kind") != "Deployment":
            continue
        labels = doc.get("metadata", {}).get("labels", {})
        if labels.get("app.kubernetes.io/component") == component:
            return doc
    raise AssertionError(f"Deployment with component {component!r} was not found")


def _rendered_runtime_contract(rendered: str) -> dict:
    for doc in _helm_docs(rendered):
        if doc.get("kind") != "ConfigMap":
            continue
        data = doc.get("data")
        if not isinstance(data, dict):
            continue
        raw = data.get("tracegate-3-runtime.yaml")
        if isinstance(raw, str):
            return yaml.safe_load(raw)
    raise AssertionError("rendered runtime contract ConfigMap was not found")


def _containers_by_name(template: dict) -> dict[str, dict]:
    return {container["name"]: container for container in template["spec"]["containers"]}


def _env_value(container: dict, name: str) -> str:
    return next(row["value"] for row in container["env"] if row["name"] == name)


def _helm_template_with_values(tmp_path: Path, values: dict) -> subprocess.CompletedProcess[str]:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")
    values_path = tmp_path / "values.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")
    return subprocess.run(
        [
            helm,
            "template",
            "tracegate",
            str(CHART_ROOT),
            "--namespace",
            "tracegate",
            "-f",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_tracegate21_chart_uses_entry_transit_roles() -> None:
    values = _values()

    assert values["global"]["runtimeProfile"] == "tracegate-3"
    assert values["architecture"]["mode"] == "legacy-three-node"
    assert values["architecture"]["ingressRotation"]["strategy"] == "revision-sticky"
    assert values["architecture"]["ingressRotation"]["enabled"] is False
    assert values["architecture"]["ingressRotation"]["rotateEndpointEgress"] is False
    assert values["architecture"]["entryIngress"]["enabled"] is False
    assert values["architecture"]["entryIngress"]["firewall"]["required"] is True
    assert values["architecture"]["entryIngress"]["channel"]["tcp"]["bindShardIpsOnly"] is True
    assert values["architecture"]["entryIngress"]["channel"]["udp"]["serviceIpRejectRequired"] is True
    assert values["controlPlane"]["auth"]["existingSecretName"] == "tracegate-control-plane-auth"
    assert values["controlPlane"]["database"]["embedded"]["enabled"] is False
    assert values["controlPlane"]["database"]["externalUrlSecret"]["name"] == "tracegate-database-url"
    assert values["controlPlane"]["env"]["realityPublicKeyTransit"] == ""
    assert values["controlPlane"]["env"]["realityShortIdTransit"] == ""
    assert set(values["gateway"]["roles"]) == {"entry", "transit"}
    assert values["gateway"]["roles"]["entry"]["role"] == "ENTRY"
    assert values["gateway"]["roles"]["transit"]["role"] == "TRANSIT"
    assert values["gateway"]["roles"]["entry"]["canonicalServer"] == "entry"
    assert values["gateway"]["roles"]["transit"]["canonicalServer"] == "transit"
    assert values["gateway"]["roles"]["entry"]["nodeSelector"] == {"tracegate.io/role": "entry"}
    assert values["gateway"]["roles"]["transit"]["nodeSelector"] == {"tracegate.io/role": "transit"}
    assert values["gateway"]["strategy"] == "RollingUpdate"
    assert values["gateway"]["allowRecreateStrategy"] is False
    assert values["gateway"]["rollingUpdate"]["maxUnavailable"] == 0
    assert values["gateway"]["rollingUpdate"]["maxSurge"] == 1
    assert values["gateway"]["progressDeadlineSeconds"] == 600
    assert values["gateway"]["terminationGracePeriodSeconds"] == 60
    assert values["gateway"]["trafficShaping"]["entry"]["runtimeSidecar"] is True
    assert values["gateway"]["nodeEncryption"]["runtimeInitValidation"] is True
    assert values["gateway"]["pdb"]["enabled"] is True
    assert values["gateway"]["pdb"]["minAvailable"] == 1
    assert values["gateway"]["probes"]["enabled"] is True
    assert values["gateway"]["privatePreflight"]["enabled"] is True
    assert values["gateway"]["privatePreflight"]["forbidPlaceholders"] is True
    assert values["gateway"]["trafficShaping"]["entry"] == {
        "enabled": True,
        "runtimeSidecar": True,
        "interface": "eth0",
        "maxMbit": 65,
        "burstKbit": 2048,
        "applyEgress": True,
        "applyIngressPolicing": True,
        "cleanupOnExit": False,
        "failClosed": True,
    }
    assert values["gateway"]["trafficShaping"]["chainClient"] == {
        "enabled": True,
        "maxMbit": 10,
        "requireDeclaredHysteriaTx": True,
    }
    assert values["gateway"]["trafficShaping"]["hysteria"] == {
        "ignoreClientBandwidth": True,
        "entryChainIgnoreClientBandwidth": False,
    }
    assert values["gateway"]["nodeEncryption"] == {
        "enabled": True,
        "required": True,
        "runtimeInitValidation": True,
        "markerFile": ".tracegate-encrypted",
        "markerValue": "tracegate-encrypted-runtime-v1",
        "requireDeviceMapperSource": True,
        "nodeAnnotations": {
            "enabled": True,
            "encryptedRuntime": "tracegate.io/encrypted-runtime",
            "expectedValue": "true",
        },
    }
    assert values["gateway"]["entrySmall"]["enabled"] is False
    assert values["gateway"]["entrySmall"]["profile"] == "1g-1vcpu"
    assert values["gateway"]["entrySmall"]["memoryBudgetMi"] == 900
    assert values["gateway"]["entrySmall"]["cpuLimitBudgetMillis"] == 1000
    assert values["gateway"]["entrySmall"]["forbidWireGuard"] is True
    assert values["gateway"]["entrySmall"]["forbidExperimental"] is True
    assert values["gateway"]["entrySmall"]["rollout"] == {
        "strategy": "Recreate",
        "allowRecreateStrategy": True,
        "maxUnavailable": 0,
        "maxSurge": 0,
    }
    assert values["network"]["egressIsolation"]["required"] is True
    assert values["network"]["egressIsolation"]["mode"] == "dedicated-egress-ip"
    assert values["network"]["egressIsolation"]["forbidIngressIpAsEgress"] is True
    assert values["network"]["egressIsolation"]["requireTransitEgressPublicIP"] is True
    assert values["network"]["egressIsolation"]["enforcement"]["snat"] == "required"
    assert values["network"]["egressIsolation"]["enforcement"]["ingressPublicIpOutbound"] == "forbidden"
    assert values["transportProfiles"]["clientExposure"] == {
        "defaultMode": "vpn-tun",
        "localProxyExports": "advanced-only",
        "lanSharing": "forbidden",
        "unauthenticatedLocalProxy": "forbidden",
    }
    assert "tracegate-k3s-private-reload --component profiles" in values["gateway"]["agent"]["reloadCommands"]["profiles"]
    assert "tracegate-k3s-private-reload --component link-crypto" in values["gateway"]["agent"]["reloadCommands"]["linkCrypto"]
    assert set(values["gateway"]["agent"]["reloadCommands"]) == {
        "xray",
        "haproxy",
        "nginx",
        "obfuscation",
        "fronting",
        "mtproto",
        "profiles",
        "linkCrypto",
    }


def test_k3s_deploy_ready_check_covers_release_gate() -> None:
    script_path = Path("deploy/k3s/deploy-ready-check.sh")
    deploy_path = Path("deploy/k3s/deploy-prod.sh")
    checker_path = Path("deploy/k3s/prod-overlay-check.py")
    cluster_checker_path = Path("deploy/k3s/cluster-preflight-check.py")
    script = script_path.read_text(encoding="utf-8")
    deploy = deploy_path.read_text(encoding="utf-8")
    readme = Path("deploy/k3s/README.md").read_text(encoding="utf-8")

    assert script_path.stat().st_mode & 0o111
    assert deploy_path.stat().st_mode & 0o111
    assert checker_path.stat().st_mode & 0o111
    assert cluster_checker_path.stat().st_mode & 0o111
    assert "public decoy" in script
    assert "public decoy" in deploy
    assert "exit 2" in script
    assert "exit 2" in deploy
    assert "helm upgrade --install" not in deploy
    assert "kubectl" not in deploy
    assert "TRACEGATE_K3S_PROD_VALUES" not in deploy
    assert "python3 -m ruff check ." not in script
    assert "pytest -q" not in script
    assert "deploy-ready-check.sh" not in readme
    assert "deploy-prod.sh" not in readme
    assert "production promotion scripts live with the operator material" in readme.lower()


def _prod_overlay_values() -> dict:
    tracegate_digest = "sha256:" + ("a" * 64)
    return {
        "global": {
            "publicBaseUrl": "https://tracegate.prod.test",
            "image": {"repository": "ghcr.io/acme/tracegate", "digest": tracegate_digest},
        },
        "controlPlane": {
            "env": {
                "defaultEntryHost": "entry.prod.test",
                "defaultTransitHost": "transit.prod.test",
                "naiveproxyHost": "auth.prod.test",
                "mtprotoDomain": "mtproto.prod.test",
            }
        },
        "decoy": {"hostPath": "/srv/tracegate/decoy"},
        "topology": {
            "servers": {
                "endpoint": {
                    "displayName": "Endpoint",
                    "publicIp": "1.1.1.1",
                    "nodeSelector": {"tracegate.io/role": "endpoint"},
                },
                "transit": {
                    "displayName": "Transit",
                    "publicIp": "8.8.8.8",
                    "nodeSelector": {"tracegate.io/role": "transit"},
                },
                "entry": {
                    "displayName": "Entry",
                    "publicIp": "8.8.4.4",
                    "nodeSelector": {"tracegate.io/role": "entry"},
                },
            }
        },
        "network": {
            "egressIsolation": {
                "ingressPublicIPs": ["8.8.8.8", "8.8.4.4"],
                "egressPublicIPs": ["1.1.1.1"],
                "nodeAnnotations": {"enabled": True},
            }
        },
        "gateway": {
            "rollingUpdate": {"maxUnavailable": 1, "maxSurge": 0},
            "images": {
                **{
                    name: {"tag": "pinned-test"}
                    for name in (
                        "haproxy",
                        "nginx",
                        "xray",
                        "hysteria",
                        "shadowsocks2022",
                        "zapret2",
                        "wstunnel",
                        "wireguard",
                        "shadowtls",
                        "shadowsocks",
                        "singbox",
                        "mtproto",
                    )
                },
                "naiveproxy": {"repository": "ghcr.io/acme/tracegate-naiveproxy-caddy", "tag": "pinned-test"},
            },
            "roles": {
                "entry": {"canonicalServer": "entry", "tls": {"serverName": "entry.prod.test"}},
                "transit": {
                    "canonicalServer": "endpoint",
                    "nodeSelector": {"tracegate.io/role": "endpoint"},
                    "tls": {"serverName": "transit.prod.test"},
                },
            },
        },
        "naiveproxy": {
            "canonicalServer": "endpoint",
            "domain": "auth.prod.test",
            "tcpExposure": "demux",
            "demux": {"role": "transit", "backendHost": "127.0.0.1", "backendPort": 11443},
            "nodeSelector": {"tracegate.io/role": "endpoint"},
            "tls": {"existingSecretName": "tracegate-naiveproxy-tls"},
        },
        "transitRouter": {
            "enabled": True,
            "endpoint": {"host": "transit.prod.test"},
            "entry": {"allowedSources": ["8.8.4.4"]},
            "tls": {"serverName": "transit.prod.test", "existingSecretName": "tracegate-transit-router-tls"},
            "xray": {"existingSecretName": "tracegate-transit-router-xray"},
            "sni": {"decoy": "transit.prod.test"},
        },
        "interconnect": {
            "entryTransit": {
                "outerCarrier": {
                    "serverName": "bridge.prod.test",
                    "publicPath": "/cdn-cgi/tracegate-link",
                }
            }
        },
        "mtproto": {
            "domain": "mtproto.prod.test",
            "route": {
                "mode": "entry-transit-endpoint",
                "entry": {"upstreamHost": "8.8.8.8"},
                "endpoint": {"allowedProxySources": ["8.8.8.8"]},
            },
        },
    }


def _entry_endpoint_overlay_values(*, rotation: bool = False) -> dict:
    values = _prod_overlay_values()
    env = values["controlPlane"]["env"]
    env["defaultEndpointHost"] = "endpoint.prod.test"
    env.pop("defaultTransitHost", None)
    env.pop("naiveproxyHost", None)
    values["topology"]["servers"].pop("transit", None)
    endpoint_role = values["gateway"]["roles"].pop("transit")
    endpoint_role["tls"]["serverName"] = "endpoint.prod.test"
    values["gateway"]["roles"]["endpoint"] = endpoint_role
    values.pop("naiveproxy", None)
    values.pop("transitRouter", None)
    values["architecture"] = {
        "mode": "entry-endpoint",
        "ingressRotation": {
            "enabled": rotation,
            "strategy": "revision-sticky",
            "entryHosts": ["edge-a.prod.test", "edge-b.prod.test"] if rotation else [],
            "endpointHosts": [],
            "minimumPoolSize": 2,
            "overlapSeconds": 600,
            "requireDistinctPublicIPs": True,
            "requireDistinctAsns": True,
            "rotateEndpointEgress": False,
        },
    }
    values["network"]["egressIsolation"]["ingressPublicIPs"] = (
        ["8.8.4.4", "9.9.9.9"] if rotation else ["8.8.4.4"]
    )
    values["gateway"]["nodeEncryption"] = {
        "enabled": False,
        "required": False,
        "runtimeInitValidation": False,
        "markerFile": "",
        "markerValue": "",
        "requireDeviceMapperSource": False,
        "nodeAnnotations": {
            "enabled": False,
            "encryptedRuntime": "",
            "expectedValue": "",
        },
    }
    values["interconnect"] = {
        "emergencyXrayChain": {
            "enabled": True,
            "endpointHost": "198.51.100.20",
            "allowedSources": ["8.8.4.4"],
            "shards": [
                {
                    "id": "mail",
                    "serverName": "rbc.ru",
                    "dest": "rbc.ru:443",
                    "endpointListenPort": 2451,
                    "path": "/api/v1/backhaul/mail",
                }
            ],
        },
        "endpointBackhaul": _values()["interconnect"]["endpointBackhaul"],
        "shadowsocks2022": {"enabled": False},
        "zapret2": {"enabled": False},
    }
    values["interconnect"]["endpointBackhaul"]["enabled"] = True
    values["mtproto"].update(
        {
            "runtime": "mtg",
            "domain": "proto.prod.test",
            "tlsDomain": "2gis.ru",
            "fallback": {"enabled": False},
            "stealth": {
                "requireWhitelistedTlsDomain": True,
                "forbiddenTlsDomains": ["old-forbidden.tracegate-sni.ru", "old-mtproto-a.tracegate-sni.ru"],
                "validatedTlsDomains": ["2gis.ru"],
            },
            "route": {
                "mode": "entry-endpoint-tunnel",
                "entry": {"tunnelPort": 11087},
                "endpoint": {"allowedProxySources": ["8.8.4.4"]},
            },
        }
    )
    return values


def _four_ip_entry_overlay_values() -> dict:
    values = _entry_endpoint_overlay_values(rotation=True)
    values["architecture"]["entryIngress"] = {
        "enabled": True,
        "serviceFacing": {"publicIp": "1.0.0.2", "hostname": "status.prod.test"},
        "shards": [
            {"id": "a", "publicIp": "8.8.4.4", "hostnameTemplate": "{token}.a.prod.test", "mtprotoHost": "mt-a.prod.test", "state": "active"},
            {"id": "b", "publicIp": "9.9.9.9", "hostnameTemplate": "{token}.b.prod.test", "mtprotoHost": "mt-b.prod.test", "state": "active"},
            {"id": "c", "publicIp": "1.0.0.1", "hostnameTemplate": "{token}.c.prod.test", "mtprotoHost": "mt-c.prod.test", "state": "active"},
        ],
        "alias": {"tokenLength": 20},
        "firewall": {"required": True},
        "channel": {
            "tcp": {
                "bindShardIpsOnly": True,
                "maxConnections": 20000,
                "maxConnectionsPerSource": 8,
                "newConnectionsPer10Seconds": 12,
                "inspectDelay": "5s",
                "connectTimeout": "5s",
                "clientTimeout": "5m",
                "serverTimeout": "5m",
                "tunnelTimeout": "1h",
            },
            "udp": {"serviceIpRejectRequired": True},
        },
    }
    values["architecture"]["ingressRotation"]["entryHosts"] = []
    values["network"]["egressIsolation"]["ingressPublicIPs"] = ["1.0.0.2", "8.8.4.4", "9.9.9.9", "1.0.0.1"]
    return values


def _universal_entry_overlay_values() -> dict:
    values = _entry_endpoint_overlay_values(rotation=False)
    values["architecture"]["universalEntry"] = {
        "enabled": True,
        "publicHost": "entry.prod.test",
        "provider": "cloudflare",
        "transport": "grpc-tls-h2",
        "originFirewall": {
            "required": True,
            "denyDirectAccess": True,
            "allowedSourceCidrs": ["173.245.48.0/20", "103.21.244.0/22"],
        },
        "clientPolicy": {
            "multiplexSingleTls": True,
            "maxParallelHandshakes": 1,
            "reconnectBaseSeconds": 5,
            "reconnectMaxSeconds": 120,
            "jitter": True,
        },
        "serverPolicy": {"grpcReadTimeout": "1h", "grpcSendTimeout": "1h"},
        "backhaul": {
            "requireMultiTransportPool": True,
            "failClosed": True,
            "endpointEgressOnly": True,
        },
    }
    values["controlPlane"]["env"]["enabledClientProfiles"] = [
        "reality",
        "hysteria",
        "entry",
        "backup-grpc",
        "backup-ws",
        "backup-shadowtls",
        "backup-wgws",
    ]
    values["interconnect"]["emergencyXrayChain"]["allowedSources"] = ["8.8.4.4"]
    values["interconnect"]["emergencyXrayChain"]["shards"] = [
        {
            "id": "mail",
            "serverName": "rbc.ru",
            "dest": "rbc.ru:443",
            "endpointListenPort": 2451,
            "path": "/api/v1/backhaul/mail",
        },
        {
            "id": "2gis-reviews",
            "serverName": "www.rbc.ru",
            "dest": "www.rbc.ru:443",
            "endpointListenPort": 2452,
            "path": "/api/v1/backhaul/2gis-reviews",
        },
    ]
    values["interconnect"]["endpointBackhaul"] = _values()["interconnect"]["endpointBackhaul"]
    values["interconnect"]["endpointBackhaul"]["enabled"] = True
    values["interconnect"]["endpointBackhaul"]["hysteria2"]["enabled"] = True
    values["interconnect"]["endpointBackhaul"]["hysteria2"]["endpointHost"] = "198.51.100.20"
    values["interconnect"]["endpointBackhaul"]["hysteria2"]["serverName"] = "endpoint.prod.test"
    values["interconnect"]["endpointBackhaul"]["hysteria2"]["allowedSources"] = ["8.8.4.4"]
    return values


def _pod_only_new_prod_overlay_values(*, phase: str) -> dict:
    values = _universal_entry_overlay_values() if phase == "full" else _entry_endpoint_overlay_values(rotation=False)
    example = yaml.safe_load(ENDPOINT_FIRST_EXAMPLE.read_text(encoding="utf-8"))
    entry_deployed = phase in {"entry-staged", "full"}
    values["architecture"].update(
        {
            "deploymentPhase": phase,
            "podRuntimeOnly": True,
            "entryIngress": {"enabled": False},
            "endpointIngress": example["architecture"]["endpointIngress"],
            "universalEntry": values["architecture"].get("universalEntry", {"enabled": False})
            if phase == "full"
            else {"enabled": False},
        }
    )
    values["architecture"]["endpointIngress"]["serviceFacing"] = {"publicIp": "1.1.1.1", "hostname": "status.prod.test"}
    for shard, public_ip in zip(values["architecture"]["endpointIngress"]["shards"], ["8.8.8.8", "9.9.9.9", "1.0.0.1"], strict=True):
        shard["publicIp"] = public_ip
        shard["hostnameTemplate"] = shard["hostnameTemplate"].replace("example.net", "prod.test")
    values["topology"]["servers"]["endpoint"]["publicIp"] = "8.8.8.8"
    values["gateway"]["realityMultiInboundGroups"] = example["gateway"]["realityMultiInboundGroups"]
    values["gateway"]["stateStorage"] = {
        "mode": "pvc",
        "existingClaims": {"entry": "tracegate-entry-state" if entry_deployed else "", "endpoint": "tracegate-endpoint-state"},
    }
    values["gateway"]["roles"]["entry"]["enabled"] = entry_deployed
    values["gateway"]["roles"]["endpoint"]["enabled"] = True
    values["decoy"] = {
        "hostPath": "",
        "existingConfigMap": "",
        "roleSources": {
            "entry": {"existingConfigMap": "tracegate-decoy-entry"},
            "endpoint": {"existingConfigMap": "tracegate-decoy-endpoint"},
        },
    }
    values["network"]["egressIsolation"]["egressPublicIPs"] = ["1.1.1.1"]
    values["network"]["egressIsolation"]["ingressPublicIPs"] = ["8.8.8.8", "9.9.9.9", "1.0.0.1"] + (["8.8.4.4"] if entry_deployed else [])
    values["interconnect"]["zapret2"] = {"enabled": False}
    if phase == "endpoint-first":
        values["interconnect"]["endpointBackhaul"] = {"enabled": False}
        values["interconnect"]["emergencyXrayChain"] = {"enabled": False}
        values["controlPlane"]["env"]["enabledClientProfiles"] = [
            "reality",
            "hysteria",
            "backup-grpc",
            "backup-ws",
            "backup-shadowtls",
            "backup-wgws",
        ]
    if phase == "entry-staged":
        values["controlPlane"]["env"]["defaultEntryHost"] = "entry-disabled.invalid"
        values["controlPlane"]["env"]["enabledClientProfiles"] = [
            "reality",
            "hysteria",
            "backup-grpc",
            "backup-ws",
            "backup-shadowtls",
            "backup-wgws",
        ]
        values["gateway"]["roles"]["entry"]["tls"]["serverName"] = "entry-disabled.invalid"
        values["interconnect"]["emergencyXrayChain"]["shards"] = [
            {
                "id": "mail",
                "serverName": "rbc.ru",
                "dest": "rbc.ru:443",
                "endpointListenPort": 2451,
                "path": "/api/v1/backhaul/mail",
            },
            {
                "id": "2gis-reviews",
                "serverName": "www.rbc.ru",
                "dest": "www.rbc.ru:443",
                "endpointListenPort": 2452,
                "path": "/api/v1/backhaul/2gis-reviews",
            },
        ]
        values["interconnect"]["endpointBackhaul"]["hysteria2"]["enabled"] = True
        values["interconnect"]["endpointBackhaul"]["hysteria2"]["endpointHost"] = "198.51.100.20"
        values["interconnect"]["endpointBackhaul"]["hysteria2"]["serverName"] = "endpoint.prod.test"
        values["interconnect"]["endpointBackhaul"]["hysteria2"]["allowedSources"] = ["8.8.4.4"]
    values["experimentalProfiles"] = {"enabled": False}
    values["wireguard"] = {"enabled": True, "wstunnel": {"enabled": True, "mode": "wireguard-over-websocket"}}
    values["shadowsocks2022"] = {"enabled": True}
    return values


def _endpoint_cdn_fallback_values() -> dict:
    values = _pod_only_new_prod_overlay_values(phase="entry-staged")
    endpoint_ingress = values["architecture"]["endpointIngress"]
    endpoint_host = values["controlPlane"]["env"]["defaultEndpointHost"]
    endpoint_ingress["serviceFacing"]["hostname"] = endpoint_host
    endpoint_ingress["cdnFallback"] = {
        "enabled": True,
        "publicHost": endpoint_host,
        "provider": "cloudflare",
        "transport": "grpc-tls-h2",
        "originShardId": endpoint_ingress["shards"][0]["id"],
        "originFirewall": {
            "required": True,
            "denyDirectAccess": True,
            "allowedSourceCidrs": ["173.245.48.0/20", "103.21.244.0/22"],
        },
        "clientPolicy": {
            "maxParallelHandshakes": 1,
            "reconnectBaseSeconds": 5,
            "reconnectMaxSeconds": 120,
            "jitter": True,
        },
        "serverPolicy": {"grpcReadTimeout": "1h", "grpcSendTimeout": "1h"},
    }
    return values


def test_k3s_strict_prod_overlay_check_accepts_private_overlay(tmp_path: Path) -> None:
    values_path = tmp_path / "values-prod.yaml"
    values_path.write_text(yaml.safe_dump(_prod_overlay_values(), sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "prod-overlay-check: OK" in result.stdout


@pytest.mark.parametrize("phase", ["endpoint-first", "entry-staged", "full"])
def test_k3s_strict_prod_overlay_check_accepts_pod_only_new_prod(tmp_path: Path, phase: str) -> None:
    values_path = tmp_path / f"values-{phase}.yaml"
    values_path.write_text(yaml.safe_dump(_pod_only_new_prod_overlay_values(phase=phase), sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_k3s_strict_prod_overlay_accepts_active_entry_host_before_universal_entry(tmp_path: Path) -> None:
    values = _pod_only_new_prod_overlay_values(phase="entry-staged")
    values["controlPlane"]["env"]["defaultEntryHost"] = "entry.prod.test"
    values["gateway"]["roles"]["entry"]["tls"] = {
        "serverName": "entry.prod.test",
        "existingSecretName": "tracegate-entry-tls",
    }
    values_path = tmp_path / "values-entry-staged-active-host.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_endpoint_cdn_fallback_is_scoped_to_cloudflare_and_one_endpoint_shard(tmp_path: Path) -> None:
    values = _endpoint_cdn_fallback_values()
    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    configmaps = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap" and isinstance(doc.get("data"), dict)
    }
    endpoint_haproxy = configmaps["tracegate-tracegate-gateway-endpoint-haproxy"]["data"]["haproxy.cfg"]
    endpoint_nginx = configmaps["tracegate-tracegate-gateway-endpoint-nginx"]["data"]["nginx.conf"]
    entry_haproxy = configmaps["tracegate-tracegate-gateway-entry-haproxy"]["data"]["haproxy.cfg"]

    assert "acl endpoint_cdn_fallback_sni req.ssl_sni -i endpoint.prod.test" in endpoint_haproxy
    assert "acl endpoint_cdn_fallback_src src" in endpoint_haproxy
    assert "173.245.48.0/20" in endpoint_haproxy
    assert "acl endpoint_cdn_fallback_dst dst 8.8.8.8" in endpoint_haproxy
    assert "tcp-request content reject if endpoint_cdn_fallback_sni !endpoint_cdn_fallback_src" in endpoint_haproxy
    assert "tcp-request content reject if endpoint_cdn_fallback_sni !endpoint_cdn_fallback_dst" in endpoint_haproxy
    assert "use_backend be_https_adapter if endpoint_cdn_fallback_sni endpoint_cdn_fallback_src endpoint_cdn_fallback_dst" in endpoint_haproxy
    assert "tcp-request connection track-sc0 src unless endpoint_trusted_proxy_src" in endpoint_haproxy
    assert "grpc_read_timeout 1h;" in endpoint_nginx
    assert "grpc_send_timeout 1h;" in endpoint_nginx
    assert "endpoint_cdn_fallback" not in entry_haproxy


def test_k3s_strict_prod_overlay_accepts_endpoint_cdn_fallback(tmp_path: Path) -> None:
    values_path = tmp_path / "values-endpoint-cdn-fallback.yaml"
    values_path.write_text(yaml.safe_dump(_endpoint_cdn_fallback_values(), sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda cfg: cfg.update({"originShardId": "missing"}), "originShardId"),
        (lambda cfg: cfg["originFirewall"].update({"denyDirectAccess": False}), "direct origin access"),
        (lambda cfg: cfg.update({"publicHost": "other.prod.test"}), "publicHost"),
        (lambda cfg: cfg["originFirewall"].update({"allowedSourceCidrs": []}), "allowedSourceCidrs"),
    ],
)
def test_k3s_strict_prod_overlay_rejects_unsafe_endpoint_cdn_fallback(
    tmp_path: Path, mutation, expected: str
) -> None:
    values = _endpoint_cdn_fallback_values()
    mutation(values["architecture"]["endpointIngress"]["cdnFallback"])
    values_path = tmp_path / "values-unsafe-endpoint-cdn-fallback.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert expected in result.stderr


def test_pod_runtime_readiness_accepts_official_mtproto_runtime(tmp_path: Path) -> None:
    manifest_path = tmp_path / "official-mtproto.yaml"
    manifest_path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"labels": {"app.kubernetes.io/component": "gateway-endpoint"}},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"name": name}
                                for name in (
                                    "agent",
                                    "haproxy",
                                    "nginx",
                                    "xray",
                                    "hysteria",
                                    "mtproto-official",
                                    "shadowtls-v3",
                                    "wireguard",
                                    "wireguard-sync",
                                    "wstunnel-wireguard",
                                )
                            ],
                            "volumes": [
                                {"name": "decoy", "configMap": {"name": "tracegate-decoy-endpoint"}},
                                {"name": "gateway-state", "persistentVolumeClaim": {"claimName": "endpoint-state"}},
                            ],
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/pod-runtime-readiness.py",
            "--manifest",
            str(manifest_path),
            "--phase",
            "endpoint-first",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("rotation", [False, True])
def test_k3s_strict_prod_overlay_check_accepts_entry_endpoint_overlay(tmp_path: Path, rotation: bool) -> None:
    values_path = tmp_path / "values-entry-endpoint.yaml"
    values_path.write_text(yaml.safe_dump(_entry_endpoint_overlay_values(rotation=rotation), sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "prod-overlay-check: OK" in result.stdout


def test_k3s_strict_prod_overlay_check_accepts_official_entry_endpoint_mtproto_without_sni(tmp_path: Path) -> None:
    values = _entry_endpoint_overlay_values()
    values["mtproto"].update(
        {
            "runtime": "official",
            "transport": "random_padding",
            "tlsDomain": "",
            "fallback": {
                "enabled": False,
                "officialBindAddress": "",
                "officialExternalIp": "1.1.1.1",
                "officialInternalIp": "1.1.1.1",
            },
        }
    )
    values_path = tmp_path / "values-entry-endpoint-official.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "prod-overlay-check: OK" in result.stdout


def test_k3s_strict_prod_overlay_check_rejects_mutable_official_mtproto_image(tmp_path: Path) -> None:
    values = _entry_endpoint_overlay_values()
    values["mtproto"].update(
        {
            "runtime": "official",
            "transport": "random_padding",
            "tlsDomain": "",
            "fallback": {"enabled": False},
        }
    )
    values["gateway"]["images"]["mtprotoOfficial"] = {
        "repository": "mtproxy/mtproxy",
        "tag": "latest",
        "digest": "",
    }
    values_path = tmp_path / "values-entry-endpoint-official-latest.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "gateway.images.mtprotoOfficial" in result.stderr
    assert "pinned tag or digest" in result.stderr


def test_k3s_strict_prod_overlay_check_accepts_universal_entry_overlay(tmp_path: Path) -> None:
    values_path = tmp_path / "values-universal-entry.yaml"
    values_path.write_text(yaml.safe_dump(_universal_entry_overlay_values(), sort_keys=True), encoding="utf-8")

    validation = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    firewall = subprocess.run(
        [
            "python3",
            "deploy/k3s/universal-entry-origin-firewall.py",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert validation.returncode == 0, validation.stderr
    assert "prod-overlay-check: OK" in validation.stdout
    assert firewall.returncode == 0, firewall.stderr
    assert "ip daddr 8.8.4.4 tcp dport 443" in firewall.stdout
    assert "HAProxy enforces the" in firewall.stdout
    assert "reject with tcp reset" not in firewall.stdout


def test_k3s_strict_prod_overlay_check_rejects_conflicting_xhttp_xmux_limits(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["interconnect"]["emergencyXrayChain"]["xhttp"] = {"xmux": {"maxConcurrency": "8-16"}}
    values_path = tmp_path / "values-universal-entry.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    validation = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert validation.returncode != 0
    assert "XHTTP xmux.maxConcurrency conflicts with maxConnections" in validation.stderr


def test_k3s_four_ip_entry_overlay_binds_only_shards_and_renders_firewall(tmp_path: Path) -> None:
    values = _four_ip_entry_overlay_values()
    values_path = tmp_path / "values-four-ip.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    validation = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    firewall = subprocess.run(
        [
            "python3",
            "deploy/k3s/entry-ingress-firewall.py",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    rendered = _helm_template_with_values(tmp_path, values)

    assert validation.returncode == 0, validation.stderr
    assert firewall.returncode == 0, firewall.stderr
    assert "ip daddr { 1.0.0.2 } tcp dport { 443 } reject with tcp reset" in firewall.stdout
    assert "ip daddr { 1.0.0.2 } udp dport { 443 } drop" in firewall.stdout
    assert rendered.returncode == 0, rendered.stderr
    assert "bind 8.8.4.4:443" in rendered.stdout
    assert "bind 9.9.9.9:443" in rendered.stdout
    assert "bind 1.0.0.1:443" in rendered.stdout
    assert "bind 1.0.0.2:443" not in rendered.stdout
    assert "stick-table type ip size 1m expire 30s store conn_cur,conn_rate(10s)" in rendered.stdout
    templates = _gateway_deployment_templates(rendered.stdout)
    for component in ("gateway-entry", "gateway-endpoint"):
        init_names = {container["name"] for container in templates[component]["spec"].get("initContainers", [])}
        assert "validate-node-encryption" not in init_names
    contract = _rendered_runtime_contract(rendered.stdout)
    assert contract["nodeEncryption"]["enabled"] is False
    assert contract["nodeEncryption"]["required"] is False
    assert contract["nodeEncryption"]["roles"] == []
    assert contract["nodeEncryption"]["markerFile"] == ""
    assert contract["nodeEncryption"]["futureEndpointRecommended"] is False


def test_k3s_entry_endpoint_rejects_host_level_node_encryption(tmp_path: Path) -> None:
    values = _entry_endpoint_overlay_values()
    values["gateway"]["nodeEncryption"]["enabled"] = True
    values_path = tmp_path / "values-entry-endpoint-encrypted.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    rendered = _helm_template_with_values(tmp_path, values)
    validation = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert rendered.returncode != 0
    assert "architecture.mode=entry-endpoint forbids gateway.nodeEncryption host-level encryption guards" in rendered.stderr
    assert validation.returncode != 0
    assert "entry-endpoint requires gateway.nodeEncryption.enabled=false" in validation.stderr


def test_k3s_strict_prod_overlay_check_rejects_transit_in_entry_endpoint(tmp_path: Path) -> None:
    values = _entry_endpoint_overlay_values()
    values["transitRouter"] = {"enabled": True}
    values_path = tmp_path / "values-entry-endpoint.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Entry/Endpoint naming only" in result.stderr


def test_k3s_strict_prod_overlay_check_accepts_derived_entry_hosts(tmp_path: Path) -> None:
    values = _prod_overlay_values()
    values["controlPlane"]["env"]["defaultEntryHost"] = "entry.example.com"
    values["controlPlane"]["env"]["defaultTransitHost"] = "transit.example.com"
    values_path = tmp_path / "values-prod.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "prod-overlay-check: OK" in result.stdout


def test_k3s_strict_prod_overlay_check_rejects_noop_private_reload(tmp_path: Path) -> None:
    values = _prod_overlay_values()
    values["gateway"]["agent"] = {"reloadCommands": {"profiles": "sh -lc 'true'", "linkCrypto": "sh -lc 'true'"}}
    values_path = tmp_path / "values-prod.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode != 0
    assert "gateway.agent.reloadCommands.profiles must run tracegate-k3s-private-reload --component profiles" in output
    assert "gateway.agent.reloadCommands.linkCrypto must run tracegate-k3s-private-reload --component link-crypto" in output


def test_k3s_strict_prod_overlay_check_rejects_removed_naiveproxy_surface(tmp_path: Path) -> None:
    values = _prod_overlay_values()
    values["naiveproxy"]["enabled"] = True
    values_path = tmp_path / "values-prod.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode != 0
    assert "naiveproxy.enabled must stay false in Tracegate 3" in output


def test_k3s_strict_prod_overlay_requires_restore_checks_for_enabled_backups(tmp_path: Path) -> None:
    values = _prod_overlay_values()
    values["controlPlane"].setdefault("database", {})["backup"] = {
        "enabled": True,
        "repositorySecretName": "tracegate-postgres-backup",
        "postgresImage": {"repository": "postgres", "tag": "16"},
        "resticImage": {"repository": "restic/restic", "tag": "0.18.0"},
        "restoreCheck": {"enabled": False},
    }
    values_path = tmp_path / "values-prod.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "production PostgreSQL backups require restoreCheck.enabled=true" in result.stderr


def test_tracegate21_image_helper_supports_digest_pins(tmp_path: Path) -> None:
    tracegate_digest = "sha256:" + ("a" * 64)
    xray_digest = "sha256:" + ("b" * 64)
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "global": {"image": {"repository": "ghcr.io/acme/tracegate", "digest": tracegate_digest}},
            "gateway": {"images": {"xray": {"repository": "ghcr.io/acme/xray", "digest": xray_digest}}},
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    assert f"image: \"ghcr.io/acme/tracegate@{tracegate_digest}\"" in rendered.stdout
    assert f"image: \"ghcr.io/acme/xray@{xray_digest}\"" in rendered.stdout


def _fake_kubectl(tmp_path: Path, *, omit_private_key: str = "", include_legacy_nodes: bool = True) -> Path:
    script = tmp_path / "kubectl"
    private_keys = {
        "reality-entry-private-key",
        "reality-transit-private-key",
        "hysteria-entry-salamander-password",
        "hysteria-transit-salamander-password",
        "hysteria-entry-stats-secret",
        "hysteria-transit-stats-secret",
        "hysteria-endpoint-backhaul-auth",
        "xray-chain-bridge-client-id",
        "shadowsocks2022-link-client-json",
        "shadowsocks2022-link-server-json",
        "mtproto-secret-txt",
        "wireguard-wg-conf",
        "shadowsocks2022-entry-server-json",
        "shadowsocks2022-transit-server-json",
        "shadowsocks2022-entry-password",
        "shadowsocks2022-transit-password",
        "shadowtls-entry-config-yaml",
        "shadowtls-transit-config-yaml",
        "shadowtls-entry-password",
        "shadowtls-transit-password",
        "zapret-entry-env",
        "zapret-transit-env",
        "zapret-entry-transit-env",
        "zapret-mtproto-extra-env",
    }
    if omit_private_key:
        private_keys.discard(omit_private_key)
    script.write_text(
        f"""#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if args[:1] == ["--context"]:
    args = args[2:]
include_legacy_nodes = {include_legacy_nodes!r}

def emit(obj):
    print(json.dumps(obj))
    raise SystemExit(0)

if args[:2] == ["get", "namespace"] and args[2] == "tracegate":
    emit({{"metadata": {{"name": "tracegate"}}}})

if args[:2] == ["get", "nodes"]:
    selector = args[args.index("-l") + 1] if "-l" in args else ""
    if selector == "tracegate.io/role=entry":
        emit({{"items": [{{"metadata": {{"name": "entry-node", "annotations": {{"tracegate.io/ingress-public-ip": "203.0.113.10", "tracegate.io/encrypted-runtime": "true"}}}}}}]}})
    if selector == "tracegate.io/role=endpoint":
        emit({{"items": [{{"metadata": {{"name": "endpoint-node", "annotations": {{"tracegate.io/ingress-public-ip": "203.0.113.10,8.8.8.8,9.9.9.9,1.0.0.1", "tracegate.io/egress-public-ip": "198.51.100.20,1.1.1.1", "tracegate.io/encrypted-runtime": "true"}}}}}}]}})
    if selector == "tracegate.io/role=transit":
        if include_legacy_nodes:
            emit({{"items": [{{"metadata": {{"name": "transit-node", "annotations": {{"tracegate.io/ingress-public-ip": "203.0.113.10", "tracegate.io/egress-public-ip": "198.51.100.20", "tracegate.io/encrypted-runtime": "true"}}}}}}]}})
        emit({{"items": []}})
    if selector == "tracegate.io/role=chain-transit":
        emit({{"items": []}})
    if selector == "tracegate.io/role=naiveproxy":
        emit({{"items": [{{"metadata": {{"name": "naiveproxy-node", "annotations": {{"tracegate.io/ingress-public-ip": "203.0.113.10", "tracegate.io/encrypted-runtime": "true"}}}}}}]}})
    emit({{"items": []}})

if args[:2] == ["get", "secret"]:
    name = args[2]
    secrets = {{
        "tracegate-control-plane-auth": {{"api-internal-token", "agent-auth-token"}},
        "tracegate-database-url": {{"url"}},
        "tracegate-entry-tls": {{"tls.crt", "tls.key"}},
        "tracegate-endpoint-tls": {{"tls.crt", "tls.key"}},
        "tracegate-transit-tls": {{"tls.crt", "tls.key"}},
        "tracegate-naiveproxy-tls": {{"tls.crt", "tls.key"}},
        "tracegate-transit-router-tls": {{"tls.crt", "tls.key"}},
        "tracegate-private-profiles": {sorted(private_keys)!r},
    }}
    if name not in secrets:
        print("not found", file=sys.stderr)
        raise SystemExit(1)
    emit({{"data": {{key: "cmVkYWN0ZWQ=" for key in secrets[name]}}}})

if args[:2] in (["get", "pvc"], ["get", "configmap"]):
    emit({{"metadata": {{"name": args[2]}}}})

print("unsupported kubectl args: " + " ".join(args), file=sys.stderr)
raise SystemExit(1)
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_k3s_cluster_preflight_accepts_existing_cluster_prerequisites(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/cluster-preflight-check.py",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(K3S_PROD_EXAMPLE),
            "--kubectl",
            str(_fake_kubectl(tmp_path, include_legacy_nodes=False)),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "cluster-preflight: OK namespace=tracegate" in result.stdout
    assert "secrets=5" in result.stdout
    assert "nodes=2" in result.stdout
    assert "encrypted_nodes=0" in result.stdout


def test_k3s_cluster_preflight_accepts_two_node_architecture(tmp_path: Path) -> None:
    values = _entry_endpoint_overlay_values()
    values["network"]["egressIsolation"]["ingressPublicIPs"] = ["203.0.113.10"]
    values["network"]["egressIsolation"]["egressPublicIPs"] = ["198.51.100.20"]
    values_path = tmp_path / "values-entry-endpoint.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/cluster-preflight-check.py",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
            "--kubectl",
            str(_fake_kubectl(tmp_path, include_legacy_nodes=False)),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "nodes=2" in result.stdout


def test_k3s_cluster_preflight_accepts_endpoint_first_pod_only_prerequisites(tmp_path: Path) -> None:
    values = _pod_only_new_prod_overlay_values(phase="endpoint-first")
    values_path = tmp_path / "values-endpoint-first.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/cluster-preflight-check.py",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
            "--kubectl",
            str(_fake_kubectl(tmp_path, include_legacy_nodes=False)),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "nodes=1" in result.stdout
    assert "gateway_state_claims=1" in result.stdout


def test_k3s_cluster_preflight_rejects_legacy_node_in_two_node_architecture(tmp_path: Path) -> None:
    values_path = tmp_path / "values-entry-endpoint.yaml"
    values_path.write_text(yaml.safe_dump(_entry_endpoint_overlay_values(), sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/cluster-preflight-check.py",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
            "--kubectl",
            str(_fake_kubectl(tmp_path)),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "entry-endpoint forbids nodes labeled tracegate.io/role=transit" in result.stderr


def test_k3s_cluster_preflight_rejects_missing_private_secret_key(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/cluster-preflight-check.py",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(K3S_PROD_EXAMPLE),
            "--kubectl",
            str(_fake_kubectl(tmp_path, omit_private_key="mtproto-secret-txt")),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Secret tracegate/tracegate-private-profiles is missing data keys: mtproto-secret-txt" in result.stderr


def test_k3s_strict_prod_overlay_check_rejects_example_overlay() -> None:
    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--strict",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(K3S_PROD_EXAMPLE),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode != 0
    assert "strict production validation must use an ignored private values file" in output
    assert "global.image.repository must not be the example repository" in output
    assert "gateway.images.xray" in output


def test_k3s_prod_overlay_check_rejects_namespace_mismatch(tmp_path: Path) -> None:
    values_path = tmp_path / "values-prod.yaml"
    values_path.write_text(
        yaml.safe_dump({"namespace": {"name": "tracegate-prod"}}, sort_keys=True),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            "deploy/k3s/prod-overlay-check.py",
            "--chart-values",
            str(CHART_ROOT / "values.yaml"),
            "--values",
            str(values_path),
            "--expected-namespace",
            "tracegate",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "namespace.name (tracegate-prod) must match TRACEGATE_NAMESPACE/Helm namespace (tracegate)" in result.stderr


def test_tracegate21_chart_does_not_reintroduce_legacy_vps_labels() -> None:
    text = _chart_text()

    for legacy_name in ("vpsT", "vpsE", "VPS_T", "VPS_E", "defaultVps"):
        assert legacy_name not in text


def test_tracegate21_chart_externalizes_private_profiles() -> None:
    values = _values()
    gitignore = Path(".gitignore").read_text(encoding="utf-8")

    assert values["privateProfiles"]["inlineProfiles"] is False
    assert values["privateProfiles"]["required"] is True
    assert values["privateProfiles"]["existingSecretName"] == "tracegate-private-profiles"
    assert values["privateProfiles"]["defaultMode"] == 256
    assert values["privateProfiles"]["secretKeys"]["shadowsocks2022LinkClient"] == "shadowsocks2022-link-client-json"
    assert values["privateProfiles"]["secretKeys"]["shadowsocks2022LinkServer"] == "shadowsocks2022-link-server-json"
    assert values["privateProfiles"]["secretKeys"]["realityPrivateKeyEntry"] == "reality-entry-private-key"
    assert values["privateProfiles"]["secretKeys"]["hysteriaSalamanderEntry"] == "hysteria-entry-salamander-password"
    assert values["privateProfiles"]["secretKeys"]["hysteriaSalamanderTransit"] == "hysteria-transit-salamander-password"
    assert values["privateProfiles"]["secretKeys"]["hysteriaStatsEntry"] == "hysteria-entry-stats-secret"
    assert values["privateProfiles"]["secretKeys"]["hysteriaStatsTransit"] == "hysteria-transit-stats-secret"
    assert values["privateProfiles"]["secretKeys"]["hysteriaEndpointBackhaulAuth"] == "hysteria-endpoint-backhaul-auth"
    assert values["privateProfiles"]["secretKeys"]["shadowsocks2022Entry"] == "shadowsocks2022-entry-server-json"
    assert values["privateProfiles"]["secretKeys"]["shadowsocks2022Transit"] == "shadowsocks2022-transit-server-json"
    assert values["privateProfiles"]["secretKeys"]["shadowtlsEntry"] == "shadowtls-entry-config-yaml"
    assert values["privateProfiles"]["secretKeys"]["shadowtlsTransit"] == "shadowtls-transit-config-yaml"
    assert values["privateProfiles"]["keys"]["shadowsocks2022LinkClient"] == "link-crypto-ss2022/client.json"
    assert values["privateProfiles"]["keys"]["shadowsocks2022LinkServer"] == "link-crypto-ss2022/server.json"
    assert values["privateProfiles"]["keys"]["realityPrivateKeyEntry"] == "reality/entry-private-key"
    assert values["privateProfiles"]["keys"]["hysteriaSalamanderEntry"] == "hysteria/entry-salamander-password"
    assert values["privateProfiles"]["keys"]["hysteriaSalamanderTransit"] == "hysteria/transit-salamander-password"
    assert values["privateProfiles"]["keys"]["hysteriaStatsEntry"] == "hysteria/entry-stats-secret"
    assert values["privateProfiles"]["keys"]["hysteriaStatsTransit"] == "hysteria/transit-stats-secret"
    assert values["privateProfiles"]["keys"]["shadowsocks2022Entry"] == "shadowsocks2022/entry-server.json"
    assert values["privateProfiles"]["keys"]["shadowsocks2022Transit"] == "shadowsocks2022/transit-server.json"
    assert values["privateProfiles"]["keys"]["shadowtlsEntry"] == "shadowtls/entry-config.yaml"
    assert values["privateProfiles"]["keys"]["shadowtlsTransit"] == "shadowtls/transit-config.yaml"
    assert ".tracegate-secrets/" in gitignore
    assert "*.luks-key" in gitignore
    assert "deploy/k3s/values-prod.yaml" in gitignore
    assert "deploy/k3s/link-profiles/" in gitignore
    assert "privateProfiles.required=false is forbidden" in _chart_text()
    assert "privateProfiles.inlineProfiles=true is forbidden" in _chart_text()
    assert "privateProfiles.defaultMode must be one of 0400, 0440, 0600 or 0640" in _chart_text()
    assert "controlPlane.auth.apiInternalToken is required" in _chart_text()
    assert "controlPlane.database requires externalUrl, externalUrlSecret.name, or embedded.enabled=true" in _chart_text()
    assert "gateway.hostNetwork=true with both Entry and Endpoint enabled requires non-empty per-role nodeSelector" in _chart_text()
    assert "gateway.hostNetwork=true with both Entry and Endpoint enabled requires distinct Entry and Endpoint nodeSelector" in _chart_text()
    assert "gateway.strategy must be RollingUpdate or Recreate" in _chart_text()
    assert "gateway.strategy=Recreate is forbidden by default" in _chart_text()
    assert "gateway.rollingUpdate must be either maxUnavailable=0/maxSurge>0 or single-hostNetwork maxUnavailable=1/maxSurge=0" in _chart_text()
    assert "gateway.progressDeadlineSeconds must be at least 300 seconds" in _chart_text()
    assert "gateway.pdb.enabled=false is forbidden" in _chart_text()
    assert "gateway.pdb.minAvailable must stay 1" in _chart_text()
    assert "gateway.probes.enabled=false is forbidden" in _chart_text()
    assert "gateway.privatePreflight.enabled=false is forbidden" in _chart_text()
    assert "gateway.privatePreflight.forbidPlaceholders=false is forbidden" in _chart_text()
    assert "architecture.mode=entry-endpoint forbids transitRouter.enabled=true" in _chart_text()
    assert "architecture.ingressRotation.rotateEndpointEgress=true is forbidden" in _chart_text()
    assert "architecture.entryIngress.shards must contain exactly three shards" in _chart_text()
    assert "architecture.entryIngress.channel.tcp.bindShardIpsOnly=false is forbidden" in _chart_text()
    assert "architecture.mode=entry-endpoint forbids gateway.nodeEncryption host-level encryption guards" in _chart_text()
    assert "gateway.trafficShaping.entry.enabled=false is forbidden" in _chart_text()
    assert "gateway.trafficShaping.entry.maxMbit must stay at the Tracegate 3 global Entry cap of 65 Mbit/s" in _chart_text()
    assert "gateway.trafficShaping.chainClient.maxMbit must be in 1..10" in _chart_text()
    assert "gateway.trafficShaping.hysteria.entryChainIgnoreClientBandwidth=true is forbidden" in _chart_text()
    assert "gateway.nodeEncryption.enabled=false is forbidden" in _chart_text()
    assert "gateway.nodeEncryption.nodeAnnotations.encryptedRuntime must be set" in _chart_text()
    assert "at least one gateway role must be enabled in Tracegate 3" in _chart_text()
    assert "interconnect.entryTransit.enabled=true requires both Entry and Endpoint gateway roles" in _chart_text()
    assert "wireguard.enabled=true requires the Endpoint gateway role" in _chart_text()
    assert "mtproto.enabled=true requires the Endpoint gateway role" in _chart_text()
    assert "shadowsocks2022.enabled=true requires both Entry and Endpoint gateway roles with entryTransit or emergencyXrayChain enabled" in _chart_text()
    assert "interconnect.entryTransit.routerEntry.enabled=true requires the Entry gateway role" in _chart_text()
    assert "interconnect.entryTransit.routerTransit.enabled=true requires the Endpoint gateway role" in _chart_text()
    assert "router link-crypto profiles require interconnect.shadowsocks2022.enabled=true" in _chart_text()
    assert values["controlPlane"]["env"]["botWelcomeRequired"] is True
    assert values["controlPlane"]["env"]["botWelcomeVersion"] == "tracegate-3.0.0-ui-v1"
    assert values["controlPlane"]["env"]["botWelcomeMessageSecret"] == {
        "name": "tracegate-bot-welcome",
        "key": "message",
    }
    assert values["controlPlane"]["env"]["botGuideMessageSecret"] == {
        "name": "tracegate-bot-guide",
        "key": "message",
    }
    assert "controlPlane.env.botWelcomeMessageSecret.name is required" in _chart_text()
    assert "controlPlane.env.botGuideMessageSecret.name is required" in _chart_text()
    assert "[TRACEGATE_BOT_WELCOME_MESSAGE_PLACEHOLDER]" not in _public_k3s_text()
    assert "defaultMode: 256" in Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")


def test_tracegate21_public_k3s_files_do_not_commit_private_profile_bodies() -> None:
    public_text = _public_k3s_text()

    for canary in PRIVATE_PROFILE_BODY_CANARIES:
        assert canary not in public_text


def test_tracegate21_rendered_manifests_do_not_embed_private_profile_bodies(tmp_path: Path) -> None:
    default = _helm_template_with_values(tmp_path, {})
    prod_example_values = yaml.safe_load(K3S_PROD_EXAMPLE.read_text(encoding="utf-8"))
    prod_example = _helm_template_with_values(tmp_path, prod_example_values)

    assert default.returncode == 0, default.stderr
    assert prod_example.returncode == 0, prod_example.stderr
    rendered = f"{default.stdout}\n{prod_example.stdout}"
    for canary in PRIVATE_PROFILE_BODY_CANARIES:
        assert canary not in rendered


def test_tracegate21_bot_welcome_message_is_secret_backed(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {"controlPlane": {"replicas": {"bot": 1}}})

    assert rendered.returncode == 0, rendered.stderr
    bot = next(
        doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "Deployment"
        and doc.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component") == "bot"
    )
    container = bot["spec"]["template"]["spec"]["containers"][0]
    env_by_name = {row["name"]: row for row in container["env"]}
    assert env_by_name["BOT_WELCOME_REQUIRED"]["value"] == "true"
    assert env_by_name["BOT_WELCOME_VERSION"]["value"] == "tracegate-3.0.0-ui-v1"
    assert env_by_name["BOT_WELCOME_MESSAGE"]["valueFrom"]["secretKeyRef"] == {
        "name": "tracegate-bot-welcome",
        "key": "message",
    }
    assert env_by_name["BOT_GUIDE_MESSAGE"]["valueFrom"]["secretKeyRef"] == {
        "name": "tracegate-bot-guide",
        "key": "message",
    }
    assert "secretName: tracegate-private-profiles" in rendered.stdout
    assert "link-crypto-ss2022/client.json" in rendered.stdout


def test_tracegate21_chart_preserves_external_decoy_content() -> None:
    values = _values()
    configmaps = (CHART_ROOT / "templates" / "configmaps.yaml").read_text(encoding="utf-8")
    gateways = (CHART_ROOT / "templates" / "gateways.yaml").read_text(encoding="utf-8")
    secrets = (CHART_ROOT / "templates" / "secrets.yaml").read_text(encoding="utf-8")
    prod_values = Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")
    readme = Path("deploy/k3s/README.md").read_text(encoding="utf-8")

    assert values["decoy"]["enabled"] is True
    assert values["decoy"]["preserveExisting"] is True
    assert values["decoy"]["existingConfigMap"] == ""
    assert values["decoy"]["existingClaim"] == ""
    assert values["decoy"]["hostPath"] == "/srv/tracegate/decoy"
    assert values["decoy"]["hostPathType"] == "Directory"
    assert "kind: ConfigMap" in configmaps
    assert "decoy.files" not in configmaps
    assert "preserveExisting: {{ .Values.decoy.preserveExisting }}" in configmaps
    assert "source: {{ if .Values.decoy.hostPath }}hostPath" in configmaps
    assert "mountPath: {{ .Values.decoy.mountPath }}" in configmaps
    assert "$.Values.decoy.hostPath" in gateways
    assert "$.Values.decoy.hostPathType" in gateways
    assert "persistentVolumeClaim:" in gateways
    assert "$.Values.decoy.existingClaim" in gateways
    assert "$.Values.decoy.existingConfigMap" in gateways
    assert "tracegate.fullname\" $ }}-decoy" not in gateways
    assert "Only one decoy source is allowed" in secrets
    assert "decoy.files is forbidden" in secrets
    assert "an external decoy source is required" in secrets
    assert "decoy.hostPath must be an absolute host path" in secrets
    assert "decoy.mountPath must be a clean absolute container path" in secrets
    assert "controlPlane.env.vlessWsPath must be a clean absolute HTTP path" in secrets
    assert "controlPlane.env.vlessGrpcPath must be a clean absolute HTTP path" in secrets
    assert "existingConfigMap: tracegate-decoy" in prod_values
    assert "Production decoy sites must stay outside the chart" in readme
    assert "does not ship a built-in decoy page" in readme


def test_tracegate21_chart_rejects_inline_decoy_files(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {"decoy": {"files": {"index.html": "[PRIVATE_DECOY_HTML_PLACEHOLDER]"}}},
    )

    assert rendered.returncode != 0
    assert "decoy.files is forbidden" in rendered.stderr


def test_tracegate21_chart_disables_hostwide_interception_by_default() -> None:
    values = _values()
    entry_transit = values["interconnect"]["entryTransit"]
    zapret2 = values["interconnect"]["zapret2"]
    zapret2_resources = values["gateway"]["containerResources"]["zapret2"]

    assert entry_transit["generation"] == 1
    assert entry_transit["remotePort"] == 443
    assert entry_transit["primary"] == "shadowsocks2022"
    assert entry_transit["fallback"] == "none"
    assert entry_transit["chainBridgeOwner"] == "link-crypto"
    assert entry_transit["xrayBackhaul"] is False
    assert entry_transit["outerCarrier"]["enabled"] is True
    assert entry_transit["outerCarrier"]["mode"] == "wss"
    assert entry_transit["outerCarrier"]["protocol"] == "websocket-tls"
    assert entry_transit["outerCarrier"]["serverName"] == "www.rbc.ru"
    assert entry_transit["outerCarrier"]["publicPort"] == 443
    assert entry_transit["outerCarrier"]["publicPath"] == "/cdn-cgi/tracegate-link"
    assert entry_transit["outerCarrier"]["verifyTls"] is True
    assert entry_transit["outerCarrier"]["spkiPinning"]["required"] is True
    assert entry_transit["outerCarrier"]["admission"]["mode"] == "hmac-sha256-generation-bound"
    assert entry_transit["outerCarrier"]["admission"]["header"] == "Sec-WebSocket-Protocol"
    assert entry_transit["outerCarrier"]["tcpShapingProfileFile"].endswith("/tcp-shaping.env")
    assert entry_transit["outerCarrier"]["promotionPreflightProfileFile"].endswith("/promotion-preflight.env")
    assert entry_transit["scope"] == ["V1", "V3"]
    assert values["interconnect"]["shadowsocks2022"]["localSocks"]["routerEntryPort"] == 10883
    assert values["interconnect"]["shadowsocks2022"]["localSocks"]["routerTransitPort"] == 10884
    assert zapret2["enabled"] is True
    assert zapret2["nfqueue"] is False
    assert zapret2["hostWideInterception"] is False
    assert zapret2["scope"] == "scoped-egress"
    assert zapret2["applyTo"] == ["mtproto"]
    assert zapret2_resources["requests"]["cpu"] == "10m"
    assert zapret2_resources["limits"]["cpu"] == "100m"
    assert zapret2_resources["limits"]["memory"] == "128Mi"
    assert "interconnect.zapret2.hostWideInterception=true is forbidden" in _chart_text()
    assert "interconnect.zapret2.nfqueue=true is forbidden" in _chart_text()
    assert "interconnect.entryTransit.xrayBackhaul=true is forbidden" in _chart_text()
    assert "interconnect.entryTransit.chainBridgeOwner must stay link-crypto" in _chart_text()
    assert "interconnect.entryTransit.primary must stay shadowsocks2022" in _chart_text()
    assert "interconnect.entryTransit.fallback must stay none" in _chart_text()
    assert "interconnect.shadowsocks2022.enabled=false is forbidden while entryTransit is enabled" in _chart_text()
    assert "interconnect.entryTransit.remotePort must stay 443" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.enabled=false is forbidden" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.mode must stay wss" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.serverName must be separate" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.publicPath must be a clean absolute HTTP path" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.publicPath must be separate from wireguard.wstunnel.publicPath" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.verifyTls=false is forbidden" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.spkiPinning.required=false is forbidden" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.admission.mode must stay hmac-sha256-generation-bound" in _chart_text()
    assert "interconnect.zapret2.enabled=false is forbidden for TCP link-crypto DPI resistance" not in _chart_text()
    assert "interconnect.entryTransit.udp.hardening.enabled=false is forbidden" in _chart_text()
    assert "interconnect.entryTransit.udp.hardening.antiReplay.enabled=false is forbidden" in _chart_text()
    assert "interconnect.entryTransit.udp.hardening.antiAmplification.enabled=false is forbidden" in _chart_text()
    assert "interconnect.entryTransit.udp.hardening.mtu.mode must stay clamp" in _chart_text()
    assert "interconnect.entryTransit.udp.hardening.sourceValidation.mode must stay profile-bound-remote" in _chart_text()
    assert "shadowsocks2022.enabled=false is forbidden when gateway.entrySmall.enabled=true" in _chart_text()
    assert "gateway.roles.%s.ports.publicTcp must stay 443; use mtproto.publicPort=8443" in _chart_text()
    assert "mtproto.publicPort must be 443 or the dedicated MTProto fallback port 8443" in _chart_text()
    assert "gateway.roles.%s.ports.publicUdp must stay 443 for Tracegate 3 Hysteria2" in _chart_text()
    assert "Keep rollout and preflight guards enabled" in Path("deploy/k3s/README.md").read_text(encoding="utf-8")
    assert "endpointBackhaul:" in Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")
    assert "serverNameEndpoint: 2gis.ru" in Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")
    assert "emergencyXrayChain:" in Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")
    assert "hysteria2:" in Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")


def test_entry_small_profile_scopes_rollout_and_resources_to_entry(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "gateway": {"entrySmall": {"enabled": True}},
            "shadowsocks2022": {"enabled": True},
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    deployments = _gateway_deployments(rendered.stdout)
    entry = deployments["gateway-entry"]
    transit = deployments["gateway-transit"]
    assert entry["spec"]["strategy"] == {"type": "Recreate"}
    assert transit["spec"]["strategy"]["type"] == "RollingUpdate"
    assert transit["spec"]["strategy"]["rollingUpdate"]["maxSurge"] == 1

    entry_containers = _containers_by_name(entry["spec"]["template"])
    transit_containers = _containers_by_name(transit["spec"]["template"])
    assert _env_value(entry_containers["agent"], "AGENT_GATEWAY_STRATEGY") == "Recreate"
    assert _env_value(entry_containers["agent"], "AGENT_GATEWAY_MAX_SURGE") == "0"
    assert _env_value(transit_containers["agent"], "AGENT_GATEWAY_STRATEGY") == "RollingUpdate"
    assert entry_containers["xray"]["resources"]["limits"]["memory"] == "160Mi"
    assert entry_containers["hysteria"]["resources"]["limits"]["cpu"] == "180m"
    assert entry_containers["sing-box-link-crypto"]["resources"]["limits"]["memory"] == "96Mi"
    assert entry_containers["sing-box-link-crypto"]["resources"]["limits"]["cpu"] == "130m"
    assert entry_containers["entry-traffic-shaper"]["resources"]["limits"]["memory"] == "32Mi"
    assert entry_containers["entry-traffic-shaper"]["resources"]["limits"]["cpu"] == "20m"
    assert "shadowsocks-2022" not in entry_containers
    assert entry_containers["shadowtls-v3"]["resources"]["limits"]["memory"] == "64Mi"
    assert entry_containers["shadowtls-v3"]["resources"]["limits"]["cpu"] == "40m"
    assert "resources" not in transit_containers["xray"]


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (
            {"gateway": {"entrySmall": {"enabled": True}}},
            "shadowsocks2022.enabled=false is forbidden when gateway.entrySmall.enabled=true",
        ),
        (
            {"gateway": {"entrySmall": {"enabled": True}}, "shadowsocks2022": {"enabled": True}, "wireguard": {"enabled": True}},
            "wireguard.enabled=true is forbidden when gateway.entrySmall.enabled=true",
        ),
        (
            {
                "gateway": {"entrySmall": {"enabled": True}},
                "shadowsocks2022": {"enabled": True},
                "experimentalProfiles": {"enabled": True},
            },
            "experimentalProfiles are forbidden when gateway.entrySmall.enabled=true",
        ),
        (
            {
                "gateway": {"entrySmall": {"enabled": True, "rollout": {"strategy": "RollingUpdate"}}},
                "shadowsocks2022": {"enabled": True},
            },
            "gateway.entrySmall.rollout.strategy must be Recreate",
        ),
        (
            {
                "gateway": {
                    "entrySmall": {
                        "enabled": True,
                        "containerResources": {"xray": {"limits": {"cpu": "180m", "memory": "901Mi"}}},
                    }
                },
                "shadowsocks2022": {"enabled": True},
            },
            "gateway.entrySmall container memory limits total",
        ),
    ],
)
def test_entry_small_profile_rejects_unsafe_overlays(tmp_path: Path, values: dict, message: str) -> None:
    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert message in rendered.stderr


def test_tracegate21_zapret2_sidecar_runs_scoped_mtproto_profile_on_transit(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "interconnect": {"zapret2": {"enabled": True}},
            "mtproto": {"enabled": True, "domain": "mtproto.example.com"},
        },
    )
    without_mtproto = _helm_template_with_values(
        tmp_path,
        {
            "interconnect": {"zapret2": {"enabled": True}},
            "mtproto": {"enabled": False},
        },
    )
    without_bridge = _helm_template_with_values(
        tmp_path,
        {
            "interconnect": {"entryTransit": {"enabled": False}, "zapret2": {"enabled": True}},
            "mtproto": {"enabled": True, "domain": "mtproto.example.com"},
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    assert without_mtproto.returncode == 0, without_mtproto.stderr
    assert without_bridge.returncode == 0, without_bridge.stderr
    assert rendered.stdout.count("name: zapret2") == 2
    zapret_scripts = [
        container["command"][-1]
        for doc in _helm_docs(rendered.stdout)
        for container in doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        if container.get("name") == "zapret2"
    ]
    assert len(zapret_scripts) == 2
    for script in zapret_scripts:
        syntax = subprocess.run(["sh", "-n"], input=script, check=False, capture_output=True, text=True)
        assert syntax.returncode == 0, syntax.stderr
    assert 'status_dir="/tmp/tracegate-zapret2-status"' in rendered.stdout
    assert "shutdown_zapret_profiles()" in rendered.stdout
    assert 'trap \'shutdown_zapret_profiles; exit 143\' TERM INT' in rendered.stdout
    assert 'exit "${code:-1}"' in rendered.stdout
    assert 'start_zapret_profile "/etc/tracegate/private/zapret/entry.env"' in rendered.stdout
    assert 'start_zapret_profile "/etc/tracegate/private/zapret/transit.env"' in rendered.stdout
    assert 'start_zapret_profile "/etc/tracegate/private/zapret/entry-transit.env"' not in rendered.stdout
    assert rendered.stdout.count('start_zapret_profile "/etc/tracegate/private/zapret/mtproto-extra.env"') == 1
    assert 'start_zapret_profile "/etc/tracegate/private/zapret/mtproto-extra.env"' not in without_mtproto.stdout
    assert without_bridge.stdout.count('start_zapret_profile "/etc/tracegate/private/zapret/mtproto-extra.env"') == 1


def test_tracegate21_chart_forbids_xray_entry_transit_backhaul() -> None:
    values = _values()
    configmaps = (CHART_ROOT / "templates" / "configmaps.yaml").read_text(encoding="utf-8")
    readme = Path("deploy/k3s/README.md").read_text(encoding="utf-8")

    assert values["interconnect"]["entryTransit"]["chainBridgeOwner"] == "link-crypto"
    assert values["interconnect"]["entryTransit"]["xrayBackhaul"] is False
    assert '"to-transit"' not in configmaps
    assert "toYaml .Values.interconnect.entryTransit" in configmaps
    assert "linkCrypto:" in configmaps
    assert "manager: link-crypto" in configmaps
    assert "profileSource: external-secret-file-reference" in configmaps
    assert "enabled: false" in configmaps
    assert "packetShaping: zapret2-scoped" not in configmaps
    assert "rollout:" in configmaps
    assert "gatewayStrategy: {{ .Values.gateway.strategy }}" in configmaps
    assert "allowRecreateStrategy: {{ .Values.gateway.allowRecreateStrategy }}" in configmaps
    assert "maxUnavailable: {{ .Values.gateway.rollingUpdate.maxUnavailable | quote }}" in configmaps
    assert "pdbMinAvailable: {{ .Values.gateway.pdb.minAvailable | quote }}" in configmaps
    assert "privatePreflightForbidPlaceholders: {{ .Values.gateway.privatePreflight.forbidPlaceholders }}" in configmaps
    assert "overlay supplies the actual deployment-specific values" in readme


def test_tracegate22_k3s_runs_hysteria2_outside_xray(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {})

    assert rendered.returncode == 0, rendered.stderr
    hysteria_configs = [
        doc["data"]["server.yaml"]
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name", "").endswith("-hysteria")
    ]
    assert hysteria_configs
    assert all("maxIdleTimeout: 2m" in config for config in hysteria_configs)
    assert all("udpIdleTimeout: 5m" in config for config in hysteria_configs)
    assert '"hy2-in"' not in rendered.stdout
    assert "REPLACE_HYSTERIA_AUTH" not in rendered.stdout
    assert "REPLACE_HYSTERIA_SALAMANDER_PASSWORD" in rendered.stdout
    assert "REPLACE_HYSTERIA_STATS_SECRET" in rendered.stdout

    for component, template in _gateway_deployment_templates(rendered.stdout).items():
        containers = _containers_by_name(template)
        assert "xray" in containers
        assert "hysteria" in containers
        assert "hy2" not in {port["name"] for port in containers["xray"].get("ports", [])}
        hysteria_ports = {port["name"]: port for port in containers["hysteria"].get("ports", [])}
        assert hysteria_ports["hy2"]["protocol"] == "UDP", component
        assert containers["hysteria"]["command"] == ["hysteria", "server", "-c", "/etc/hysteria/server.yaml"]


def test_quic_host_sysctl_profile_uses_hysteria_recommended_buffers() -> None:
    profile = Path("deploy/k3s/host-sysctl/90-tracegate-quic.conf").read_text(encoding="utf-8")

    assert "net.core.rmem_default = 16777216" in profile
    assert "net.core.rmem_max = 16777216" in profile
    assert "net.core.wmem_default = 16777216" in profile
    assert "net.core.wmem_max = 16777216" in profile


def test_entry_traffic_shaping_and_encrypted_runtime_guards_render(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {})

    assert rendered.returncode == 0, rendered.stderr
    templates = _gateway_deployment_templates(rendered.stdout)
    entry_template = templates["gateway-entry"]
    transit_template = templates["gateway-transit"]
    entry_containers = _containers_by_name(entry_template)
    transit_containers = _containers_by_name(transit_template)

    shaper = entry_containers["entry-traffic-shaper"]
    shaper_script = shaper["command"][-1]
    syntax = subprocess.run(["sh", "-n"], input=shaper_script, check=False, capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr
    assert shaper["securityContext"]["capabilities"]["add"] == ["NET_ADMIN"]
    assert 'max_mbit="65"' in shaper_script
    assert 'rate="${max_mbit}mbit"' in shaper_script
    assert 'tc qdisc del dev "${iface}" root' in shaper_script
    assert "tc qdisc add" in shaper_script
    assert "htb rate" in shaper_script
    assert "police rate" in shaper_script
    assert "Entry egress qdisc disappeared" in shaper_script
    assert "entry-traffic-shaper" not in transit_containers

    entry_inits = {container["name"]: container for container in entry_template["spec"]["initContainers"]}
    transit_inits = {container["name"]: container for container in transit_template["spec"]["initContainers"]}
    for init in (entry_inits["validate-node-encryption"], transit_inits["validate-node-encryption"]):
        script = init["command"][-1]
        assert 'marker="/state/.tracegate-encrypted"' in script
        assert 'expected="tracegate-encrypted-runtime-v1"' in script
        assert "dm-crypt-looking source" in script
        assert init["volumeMounts"] == [{"name": "gateway-state", "mountPath": "/state"}]

    entry_agent = entry_containers["agent"]
    assert _env_value(entry_agent, "AGENT_ENTRY_TRAFFIC_SHAPING_MAX_MBIT") == "65"
    assert _env_value(entry_agent, "HYSTERIA_CHAIN_CLIENT_MAX_MBIT") == "10"
    assert _env_value(entry_agent, "HYSTERIA_CHAIN_CLIENT_REQUIRE_DECLARED_TX") == "true"
    assert _env_value(entry_agent, "AGENT_NODE_ENCRYPTION_MARKER_FILE") == ".tracegate-encrypted"

    hysteria_configs = {
        doc["metadata"]["labels"]["app.kubernetes.io/component"]: yaml.safe_load(doc["data"]["server.yaml"])
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap" and str(doc.get("metadata", {}).get("name") or "").endswith("-hysteria")
    }
    assert hysteria_configs["gateway-entry"]["bandwidth"] == {"up": "10 mbps", "down": "10 mbps"}
    assert hysteria_configs["gateway-entry"]["ignoreClientBandwidth"] is False
    assert "bandwidth" not in hysteria_configs["gateway-transit"]
    assert hysteria_configs["gateway-transit"]["ignoreClientBandwidth"] is True


def test_tracegate21_runtime_contract_renders_role_link_crypto_metadata(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "interconnect": {
                "entryTransit": {
                    "routerEntry": {"enabled": True},
                    "routerTransit": {"enabled": True},
                }
            }
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    contract = _rendered_runtime_contract(rendered.stdout)
    link_crypto = contract["linkCrypto"]

    assert contract["network"]["egressIsolation"]["required"] is True
    assert contract["network"]["egressIsolation"]["mode"] == "dedicated-egress-ip"
    assert contract["network"]["egressIsolation"]["forbidIngressIpAsEgress"] is True
    assert contract["network"]["egressIsolation"]["enforcement"]["snat"] == "required"
    assert contract["trafficShaping"]["entry"] == {
        "enabled": True,
        "runtimeSidecar": True,
        "strategy": "tc-htb-egress-plus-ingress-police",
        "interface": "eth0",
        "maxMbit": 65,
        "burstKbit": 2048,
        "applyEgress": True,
        "applyIngressPolicing": True,
        "cleanupOnExit": False,
        "failClosed": True,
        "scope": "host-public-interface",
    }
    assert contract["trafficShaping"]["chainClient"]["enabled"] is True
    assert contract["trafficShaping"]["chainClient"]["maxMbit"] == 10
    assert contract["trafficShaping"]["hysteria"]["entryChainIgnoreClientBandwidth"] is False
    assert contract["nodeEncryption"]["required"] is True
    assert contract["nodeEncryption"]["roles"] == ["entry", "transit"]
    assert contract["nodeEncryption"]["markerFile"] == ".tracegate-encrypted"
    assert contract["nodeEncryption"]["nodeAnnotations"]["encryptedRuntime"] == "tracegate.io/encrypted-runtime"
    assert contract["transportProfiles"]["clientExposure"] == {
        "defaultMode": "vpn-tun",
        "localProxyExports": "advanced-only",
        "lanSharing": "forbidden",
        "unauthenticatedLocalProxy": "forbidden",
    }
    assert link_crypto["enabled"] is True
    assert link_crypto["classes"] == ["entry-transit", "router-entry", "router-transit"]
    assert link_crypto["counts"] == {
        "total": 3,
        "entryTransit": 1,
        "routerEntry": 1,
        "routerTransit": 1,
    }
    assert link_crypto["outerCarrier"] == {
        "enabled": True,
        "mode": "wss",
        "protocol": "websocket-tls",
        "serverName": "www.rbc.ru",
        "publicPort": 443,
        "publicPath": "/cdn-cgi/tracegate-link",
        "url": "wss://www.rbc.ru:443/cdn-cgi/tracegate-link",
        "verifyTls": True,
        "secretMaterial": False,
        "tlsPinning": {
            "required": True,
            "mode": "spki-sha256",
            "profileSource": "private-file-reference",
            "profileRef": {
                "kind": "file",
                "path": "/etc/tracegate/private/link-crypto/outer-wss-spki.env",
                "secretMaterial": True,
            },
            "secretMaterial": False,
        },
        "admission": {
            "required": True,
            "mode": "hmac-sha256-generation-bound",
            "carrier": "websocket-subprotocol",
            "header": "Sec-WebSocket-Protocol",
            "profileSource": "private-file-reference",
            "profileRef": {
                "kind": "file",
                "path": "/etc/tracegate/private/link-crypto/outer-wss-admission.env",
                "secretMaterial": True,
            },
            "rejectUnauthenticated": True,
            "secretMaterial": False,
        },
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
    assert link_crypto["dpiResistance"]["mode"] == "shadowsocks2022-wss-spki-hmac"
    assert link_crypto["dpiResistance"]["outerCarrier"] == {
        "required": True,
        "spkiPinningRequired": True,
        "hmacAdmissionRequired": True,
    }
    assert "shadowsocks2022-aead" in link_crypto["dpiResistance"]["requiredLayers"]
    assert "shadowtls-v3" in link_crypto["dpiResistance"]["requiredLayers"]
    assert "tls13-camouflage" in link_crypto["dpiResistance"]["requiredLayers"]
    assert "sing-box-runtime" in link_crypto["dpiResistance"]["requiredLayers"]
    assert "scoped-zapret2" not in link_crypto["dpiResistance"]["requiredLayers"]
    assert "spki-sha256-pin" in link_crypto["dpiResistance"]["requiredLayers"]
    assert "trafficShaping" not in link_crypto["dpiResistance"]
    assert link_crypto["dpiResistance"]["promotionPreflight"]["failClosed"] is True
    assert link_crypto["roles"]["entry"]["classes"] == ["entry-transit", "router-entry"]
    assert link_crypto["roles"]["entry"]["counts"] == {
        "total": 2,
        "entryTransit": 1,
        "routerEntry": 1,
        "routerTransit": 0,
    }
    assert link_crypto["roles"]["entry"]["localPorts"] == {
        "entry-transit": 10881,
        "router-entry": 10883,
    }
    assert link_crypto["roles"]["entry"]["selectedProfiles"] == {
        "entry-transit": ["V1", "V3"],
        "router-entry": ["V1", "V3"],
    }
    assert link_crypto["roles"]["transit"]["classes"] == ["entry-transit", "router-transit"]
    assert link_crypto["roles"]["transit"]["counts"] == {
        "total": 2,
        "entryTransit": 1,
        "routerEntry": 0,
        "routerTransit": 1,
    }
    assert link_crypto["roles"]["transit"]["localPorts"] == {
        "entry-transit": 10882,
        "router-transit": 10884,
    }
    assert link_crypto["roles"]["transit"]["selectedProfiles"] == {
        "entry-transit": ["V1", "V3"],
        "router-transit": ["V0", "V1", "V3"],
    }
    assert link_crypto["udp"]["enabled"] is True
    assert link_crypto["udp"]["carrier"] == "hysteria2"
    assert link_crypto["udp"]["transport"] == "udp-quic"
    assert link_crypto["udp"]["manager"] == "link-crypto"
    assert link_crypto["udp"]["profileSource"] == "external-secret-file-reference"
    assert link_crypto["udp"]["secretMaterial"] is False
    assert link_crypto["udp"]["xrayBackhaul"] is False
    assert link_crypto["udp"]["remotePort"] == 4443
    assert link_crypto["udp"]["obfs"] == {"type": "salamander", "required": True}
    assert link_crypto["udp"]["pairedObfs"] == {
        "enabled": False,
        "backend": "udp2raw",
        "mode": "udp2raw-faketcp",
        "requiresBothSides": True,
        "failClosed": True,
        "noHostWideInterception": True,
        "noNfqueue": True,
    }
    assert link_crypto["udp"]["hardening"] == {
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
    assert link_crypto["udp"]["dpiResistance"]["enabled"] is True
    assert link_crypto["udp"]["dpiResistance"]["mode"] == "salamander-plus-scoped-paired-obfs"
    assert link_crypto["udp"]["dpiResistance"]["portSplit"] == {
            "publicUdpPort": 443,
        "forbidUdp443": False,
        "forbidTcp8443": True,
    }
    assert "salamander" in link_crypto["udp"]["dpiResistance"]["requiredLayers"]
    assert link_crypto["udp"]["classes"] == ["entry-transit-udp", "router-entry-udp", "router-transit-udp"]
    assert link_crypto["udp"]["counts"] == {
        "total": 3,
        "entryTransitUdp": 1,
        "routerEntryUdp": 1,
        "routerTransitUdp": 1,
    }
    assert link_crypto["udp"]["roles"]["entry"]["classes"] == ["entry-transit-udp", "router-entry-udp"]
    assert link_crypto["udp"]["roles"]["entry"]["localPorts"] == {
        "entry-transit-udp": 14481,
        "router-entry-udp": 14483,
    }
    assert link_crypto["udp"]["roles"]["entry"]["selectedProfiles"] == {
        "entry-transit-udp": ["V2"],
        "router-entry-udp": ["V2"],
    }
    assert link_crypto["udp"]["roles"]["transit"]["classes"] == ["entry-transit-udp", "router-transit-udp"]
    assert link_crypto["udp"]["roles"]["transit"]["localPorts"] == {
        "entry-transit-udp": 14482,
        "router-transit-udp": 14484,
    }
    assert link_crypto["udp"]["roles"]["transit"]["selectedProfiles"] == {
        "entry-transit-udp": ["V2"],
        "router-transit-udp": ["V2"],
    }
    assert link_crypto["zapret2"]["hostWideInterception"] is False
    assert link_crypto["zapret2"]["nfqueue"] is False
    assert link_crypto["zapret2"]["enabled"] is False
    assert link_crypto["zapret2"]["required"] is False


def test_tracegate21_chart_omits_link_crypto_sidecar_when_entry_transit_bridge_is_disabled(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {"interconnect": {"entryTransit": {"enabled": False}}})

    assert rendered.returncode == 0, rendered.stderr
    contract = _rendered_runtime_contract(rendered.stdout)
    assert contract["linkCrypto"]["enabled"] is False
    assert "dpiResistance" not in contract["linkCrypto"]
    assert contract["linkCrypto"]["udp"]["enabled"] is False
    assert contract["linkCrypto"]["udp"]["remotePort"] == 4443
    assert contract["linkCrypto"]["udp"]["dpiResistance"]["enabled"] is False
    assert "name: sing-box-link-crypto\n" not in rendered.stdout
    assert "sing-box run -c" not in rendered.stdout
    assert "link-crypto-ss2022/client.json" not in rendered.stdout
    assert "link-crypto-ss2022/server.json" not in rendered.stdout


def test_tracegate21_chart_runs_shadowtls_server_profile_for_router_only_link_crypto(tmp_path: Path) -> None:
    entry_router = _helm_template_with_values(
        tmp_path,
        {"interconnect": {"entryTransit": {"enabled": False, "routerEntry": {"enabled": True}}}},
    )
    transit_router = _helm_template_with_values(
        tmp_path,
        {"interconnect": {"entryTransit": {"enabled": False, "routerTransit": {"enabled": True}}}},
    )

    assert entry_router.returncode == 0, entry_router.stderr
    assert transit_router.returncode == 0, transit_router.stderr

    entry_templates = _gateway_deployment_templates(entry_router.stdout)
    entry_containers = _containers_by_name(entry_templates["gateway-entry"])
    transit_containers = _containers_by_name(entry_templates["gateway-transit"])
    assert "sing-box-link-crypto" in entry_containers
    assert "sing-box-link-crypto" not in transit_containers
    entry_script = entry_containers["sing-box-link-crypto"]["command"][-1]
    entry_syntax = subprocess.run(["sh", "-n"], input=entry_script, check=False, capture_output=True, text=True)
    assert entry_syntax.returncode == 0, entry_syntax.stderr
    assert 'start_link_crypto_profile "/etc/tracegate/private/link-crypto-ss2022/server.json"' in entry_script
    assert 'start_link_crypto_profile "/etc/tracegate/private/link-crypto-ss2022/client.json"' not in entry_script
    assert _env_value(entry_containers["agent"], "PRIVATE_LINK_CRYPTO_ENABLED") == "false"
    assert _env_value(entry_containers["agent"], "PRIVATE_LINK_CRYPTO_ROUTER_ENTRY_ENABLED") == "true"
    assert _env_value(entry_containers["agent"], "PRIVATE_LINK_CRYPTO_ROUTER_ENTRY_PORT") == "10883"

    transit_templates = _gateway_deployment_templates(transit_router.stdout)
    transit_only_containers = _containers_by_name(transit_templates["gateway-transit"])
    entry_only_containers = _containers_by_name(transit_templates["gateway-entry"])
    assert "sing-box-link-crypto" in transit_only_containers
    assert "sing-box-link-crypto" not in entry_only_containers
    transit_script = transit_only_containers["sing-box-link-crypto"]["command"][-1]
    transit_syntax = subprocess.run(["sh", "-n"], input=transit_script, check=False, capture_output=True, text=True)
    assert transit_syntax.returncode == 0, transit_syntax.stderr
    assert 'start_link_crypto_profile "/etc/tracegate/private/link-crypto-ss2022/server.json"' in transit_script
    assert 'start_link_crypto_profile "/etc/tracegate/private/link-crypto-ss2022/client.json"' not in transit_script
    assert _env_value(transit_only_containers["agent"], "PRIVATE_LINK_CRYPTO_ENABLED") == "false"
    assert _env_value(transit_only_containers["agent"], "PRIVATE_LINK_CRYPTO_ROUTER_TRANSIT_ENABLED") == "true"
    assert _env_value(transit_only_containers["agent"], "PRIVATE_LINK_CRYPTO_ROUTER_TRANSIT_PORT") == "10884"


def test_tracegate21_chart_renders_transit_only_when_entry_bridge_is_disabled(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "gateway": {"roles": {"entry": {"enabled": False}}},
            "interconnect": {"entryTransit": {"enabled": False}},
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    assert "app.kubernetes.io/component: gateway-entry" not in rendered.stdout
    assert "app.kubernetes.io/component: gateway-transit" in rendered.stdout
    assert "name: sing-box-link-crypto\n" not in rendered.stdout
    assert "link-crypto-ss2022/client.json" not in rendered.stdout
    assert "link-crypto-ss2022/server.json" not in rendered.stdout


def test_tracegate21_chart_declares_required_client_profiles_and_socks_auth() -> None:
    values = _values()
    profiles = set(values["transportProfiles"]["clientNames"])

    assert values["transportProfiles"]["socks5"]["required"] is True
    assert values["transportProfiles"]["socks5"]["allowAnonymousLocalhost"] is False
    assert tuple(values["transportProfiles"]["clientNames"]) == TRACEGATE3_CLIENT_PROFILES
    assert "v1-direct-reality-vless" in profiles
    assert "v0-grpc-vless" in profiles
    assert "v3-direct-shadowtls-shadowsocks" in profiles
    assert "v3-chain-shadowtls-shadowsocks" not in profiles
    assert "v4-direct-naiveproxy" not in profiles
    assert "v0-encrypted-reality-vless" not in profiles
    assert "v0-wgws-wireguard" in profiles
    assert "MTProto-FakeTLS-Direct" in profiles
    assert "MTProto-TCP443-Direct" not in profiles
    assert "V8-RESTLS-Direct" not in profiles
    assert "V9-TUICv5-QUIC-Direct" not in profiles
    assert "transportProfiles.socks5.required=false is forbidden" in _chart_text()
    assert "transportProfiles.socks5.allowAnonymousLocalhost=true is forbidden" in _chart_text()
    assert "transportProfiles.clientExposure.defaultMode must stay vpn-tun" in _chart_text()
    assert "network.egressIsolation.required=false is forbidden" in _chart_text()
    assert "network.egressIsolation.enforcement.ingressPublicIpOutbound must stay forbidden" in _chart_text()
    assert "transportProfiles.clientNames must include %s" in _chart_text()
    assert "transportProfiles.clientNames must not include lab-only profile %s" in _chart_text()
    assert "MTProto-TCP443-Direct is legacy" in _chart_text()


def test_tracegate21_chart_declares_lab_only_v8_v9_surfaces() -> None:
    values = _values()
    text = _chart_text()
    gateways = (CHART_ROOT / "templates" / "gateways.yaml").read_text(encoding="utf-8")
    secrets = (CHART_ROOT / "templates" / "secrets.yaml").read_text(encoding="utf-8")
    readme = Path("deploy/k3s/README.md").read_text(encoding="utf-8")

    experimental = values["experimentalProfiles"]
    assert experimental["enabled"] is False
    assert experimental["directTransitObfuscation"]["enabled"] is False
    assert experimental["directTransitObfuscation"]["restls"]["enabled"] is False
    assert experimental["tuicV5"]["enabled"] is False
    assert experimental["tuicV5"]["directEnabled"] is False
    assert experimental["tuicV5"]["chainEnabled"] is False
    assert experimental["tuicV5"]["productionReplacementAllowed"] is False
    assert experimental["directTransitObfuscation"]["variants"] == []
    assert "V9-TUICv5-QUIC-Direct" in experimental["tuicV5"]["variants"]
    assert "V9-TUICv5-QUIC-Chain" in experimental["tuicV5"]["variants"]
    assert values["privateProfiles"]["keys"]["labRestlsDirect"] == "lab/restls-direct.yaml"
    assert values["privateProfiles"]["keys"]["labTuicEntry"] == "lab/tuic-entry.json"
    assert values["privateProfiles"]["keys"]["labTuicTransit"] == "lab/tuic-transit.json"
    assert values["gateway"]["images"]["singbox"]["repository"] == "ghcr.io/sagernet/sing-box"
    assert values["gateway"]["images"]["wireguard"]["repository"] == "lscr.io/linuxserver/wireguard"
    assert values["gateway"]["images"]["mtproto"]["repository"] == "nineseconds/mtg"
    assert values["gateway"]["images"]["mtproto"]["digest"].startswith("sha256:")
    assert values["gateway"]["images"]["mtprotoOfficial"]["repository"] == "mtproxy/mtproxy"
    assert values["gateway"]["images"]["mtprotoOfficial"]["digest"].startswith("sha256:")
    assert "experimentalProfiles:" in text
    assert "shadowsocks2022-direct-lab" not in gateways
    assert "restls-direct-lab" in gateways
    assert "tuic-v5-lab" in gateways
    assert "sing-box run -c" in gateways
    assert "labRestlsDirect" in gateways
    assert "keys.labRestlsDirect" in gateways
    assert "labTuicEntry" in gateways
    assert "labTuicTransit" in gateways
    assert "experimentalProfiles.enabled=false cannot enable V8/V9 lab surfaces" in secrets
    assert "experimentalProfiles.directTransitObfuscation.enabled=false cannot enable RESTLS layers" in secrets
    assert "experimentalProfiles.directTransitObfuscation.enabled=true requires restls.enabled" in secrets
    assert "experimentalProfiles.tuicV5.enabled=false cannot enable TUIC v5 lab routes" in secrets
    assert "experimentalProfiles.tuicV5.enabled=true requires directEnabled or chainEnabled" in secrets
    assert "productionReplacementAllowed=true is forbidden" in secrets
    assert "exact public endpoint layout" in readme
    assert "live hostnames" in readme


def test_tracegate21_chart_guards_v5_v6_v7_transport_shape() -> None:
    values = _values()
    text = _chart_text()

    assert values["shadowsocks2022"]["variants"]["direct"] == "V3"
    assert values["shadowsocks2022"]["variants"]["chain"] == "V3"
    assert values["shadowsocks2022"]["shadowtls"]["enabled"] is True
    assert values["shadowsocks2022"]["shadowtls"]["version"] == 3
    assert values["wireguard"]["variant"] == "V0"
    assert values["wireguard"]["clientCidr"] == "10.70.0.0/16"
    assert values["wireguard"]["wstunnel"]["enabled"] is True
    assert values["wireguard"]["wstunnel"]["mode"] == "wireguard-over-websocket"
    assert values["wireguard"]["wstunnel"]["publicPath"].startswith("/")
    assert "shadowsocks2022.variants.direct must stay V3" in text
    assert "shadowsocks2022.variants.chain must stay V3" in text
    assert "shadowsocks2022.shadowtls.enabled=false is forbidden" in text
    assert "shadowsocks2022.shadowtls.version must stay 3" in text
    assert "wireguard.variant must stay V0" in text
    assert "wireguard.wstunnel.enabled=false is forbidden" in text
    assert "wireguard.wstunnel.mode must stay wireguard-over-websocket" in text
    assert "wireguard.clientCidr must be an IPv4 CIDR for WGWS egress NAT" in text
    assert "wireguard.wstunnel.publicPath must be an absolute HTTP path" in text
    assert "wireguard.wstunnel.publicPath must be a clean absolute HTTP path" in text


def test_tracegate21_wireguard_sidecar_uses_portable_lifecycle_script(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {"wireguard": {"enabled": True}})

    assert rendered.returncode == 0, rendered.stderr
    transit_template = _gateway_deployment_templates(rendered.stdout)["gateway-transit"]
    containers = _containers_by_name(transit_template)
    assert "wireguard-sync" in containers
    assert containers["wireguard-sync"]["command"] == ["tracegate-wireguard-sync-runner"]
    assert _env_value(containers["wireguard-sync"], "WIREGUARD_SYNC_INTERFACE") == "wg"
    assert containers["wireguard-sync"]["securityContext"]["capabilities"]["add"] == ["NET_ADMIN", "NET_RAW"]
    scripts = [
        container["command"][-1]
        for doc in _helm_docs(rendered.stdout)
        for container in doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        if container.get("name") == "wireguard"
    ]
    assert len(scripts) == 1
    script = scripts[0]
    syntax = subprocess.run(["sh", "-n"], input=script, check=False, capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr
    assert "wg-quick up /etc/tracegate/private/wireguard/wg.conf" in script
    assert 'wireguard_client_cidr="10.70.0.0/16"' in script
    assert 'iptables -t nat -A POSTROUTING -s "$wireguard_client_cidr" -o "$wireguard_out_if" -j MASQUERADE' in script
    assert "teardown_wireguard_egress()" in script
    assert "teardown_wireguard()" in script
    assert "sleep infinity" not in script
    assert 'while :; do sleep 3600 & wait "$!"; done' in script


@pytest.mark.parametrize(
    ("override", "message"),
    [
        (
            {"controlPlane": {"auth": {"existingSecretName": ""}}},
            "controlPlane.auth.apiInternalToken is required",
        ),
        (
            {"controlPlane": {"database": {"embedded": {"enabled": True, "password": ""}}}},
            "controlPlane.database.embedded.password is required",
        ),
        (
            {
                "controlPlane": {
                    "database": {
                        "embedded": {"enabled": False},
                        "externalUrl": "",
                        "externalUrlSecret": {"name": ""},
                    }
                }
            },
            "controlPlane.database requires externalUrl, externalUrlSecret.name, or embedded.enabled=true",
        ),
        (
            {"privateProfiles": {"defaultMode": 511}},
            "privateProfiles.defaultMode must be one of 0400, 0440, 0600 or 0640",
        ),
        (
            {"gateway": {"roles": {"entry": {"nodeSelector": None}, "transit": {"nodeSelector": None}}}},
            "gateway.hostNetwork=true with both Entry and Endpoint enabled requires non-empty per-role nodeSelector",
        ),
        (
            {"gateway": {"trafficShaping": {"entry": {"maxMbit": 101}}}},
            "gateway.trafficShaping.entry.maxMbit must stay at the Tracegate 3 global Entry cap of 65 Mbit/s",
        ),
        (
            {"gateway": {"trafficShaping": {"chainClient": {"maxMbit": 11}}}},
            "gateway.trafficShaping.chainClient.maxMbit must be in 1..10",
        ),
        (
            {"gateway": {"trafficShaping": {"hysteria": {"entryChainIgnoreClientBandwidth": True}}}},
            "gateway.trafficShaping.hysteria.entryChainIgnoreClientBandwidth=true is forbidden",
        ),
        (
            {"gateway": {"nodeEncryption": {"markerFile": ""}}},
            "gateway.nodeEncryption.markerFile must be set",
        ),
        (
            {
                "gateway": {
                    "roles": {
                        "entry": {"nodeSelector": {"tracegate.io/role": "gateway"}},
                        "transit": {"nodeSelector": {"tracegate.io/role": "gateway"}},
                    }
                }
            },
            "gateway.hostNetwork=true with both Entry and Endpoint enabled requires distinct Entry and Endpoint nodeSelector",
        ),
        (
            {"decoy": {"hostPath": "srv/tracegate/decoy"}},
            "decoy.hostPath must be an absolute host path",
        ),
        (
            {"decoy": {"mountPath": "/bad path"}},
            "decoy.mountPath must be a clean absolute container path",
        ),
        (
            {"controlPlane": {"env": {"vlessWsPath": "/bad path"}}},
            "controlPlane.env.vlessWsPath must be a clean absolute HTTP path",
        ),
        (
            {"controlPlane": {"env": {"vlessGrpcPath": "tracegate.v1.Edge/"}}},
            "controlPlane.env.vlessGrpcPath must be a clean absolute HTTP path",
        ),
        (
            {"controlPlane": {"replicas": {"bot": 1}, "env": {"botWelcomeMessageSecret": {"name": ""}}}},
            "controlPlane.env.botWelcomeMessageSecret.name is required",
        ),
        (
            {"controlPlane": {"replicas": {"bot": 1}, "env": {"botGuideMessageSecret": {"name": ""}}}},
            "controlPlane.env.botGuideMessageSecret.name is required",
        ),
        (
            {"decoy": {"hostPath": "", "existingClaim": "", "existingConfigMap": ""}},
            "an external decoy source is required",
        ),
        (
            {"interconnect": {"zapret2": {"hostWideInterception": True}}},
            "interconnect.zapret2.hostWideInterception=true is forbidden",
        ),
        (
            {"shadowsocks2022": {"enabled": True, "shadowtls": {"version": 2}}},
            "shadowsocks2022.shadowtls.version must stay 3",
        ),
        (
            {"wireguard": {"enabled": True, "wstunnel": {"enabled": False}}},
            "wireguard.wstunnel.enabled=false is forbidden",
        ),
        (
            {"wireguard": {"enabled": True, "wstunnel": {"publicPath": "/bad path"}}},
            "wireguard.wstunnel.publicPath must be a clean absolute HTTP path",
        ),
        (
            {"experimentalProfiles": {"tuicV5": {"productionReplacementAllowed": True}}},
            "experimentalProfiles.tuicV5.productionReplacementAllowed=true is forbidden",
        ),
        (
            {"gateway": {"roles": {"entry": {"enabled": False}}}},
            "interconnect.entryTransit.enabled=true requires both Entry and Endpoint gateway roles",
        ),
        (
            {
                "gateway": {"roles": {"entry": {"enabled": False}, "transit": {"enabled": False}}},
                "interconnect": {"entryTransit": {"enabled": False}},
                "mtproto": {"enabled": False},
            },
            "at least one gateway role must be enabled in Tracegate 3",
        ),
        (
            {
                "gateway": {"roles": {"transit": {"enabled": False}}},
                "interconnect": {"entryTransit": {"enabled": False}},
                "wireguard": {"enabled": True},
                "mtproto": {"enabled": False},
            },
            "wireguard.enabled=true requires the Endpoint gateway role",
        ),
        (
            {
                "gateway": {"roles": {"transit": {"enabled": False}}},
                "interconnect": {"entryTransit": {"enabled": False}},
                "mtproto": {"enabled": True},
            },
            "mtproto.enabled=true requires the Endpoint gateway role",
        ),
        (
            {"interconnect": {"entryTransit": {"enabled": False}}, "shadowsocks2022": {"enabled": True}},
            "shadowsocks2022.enabled=true requires both Entry and Endpoint gateway roles with entryTransit or emergencyXrayChain enabled",
        ),
        (
            {
                "gateway": {"roles": {"entry": {"enabled": False}}},
                "interconnect": {"entryTransit": {"enabled": False, "routerEntry": {"enabled": True}}},
            },
            "interconnect.entryTransit.routerEntry.enabled=true requires the Entry gateway role",
        ),
        (
            {
                "gateway": {"roles": {"transit": {"enabled": False}}},
                "interconnect": {"entryTransit": {"enabled": False, "routerTransit": {"enabled": True}}},
                "mtproto": {"enabled": False},
            },
            "interconnect.entryTransit.routerTransit.enabled=true requires the Endpoint gateway role",
        ),
        (
            {"interconnect": {"entryTransit": {"enabled": False, "routerTransit": {"enabled": True}}, "shadowsocks2022": {"enabled": False}}},
            "router link-crypto profiles require interconnect.shadowsocks2022.enabled=true",
        ),
        (
            {"experimentalProfiles": {"directTransitObfuscation": {"restls": {"enabled": True}}}},
            "experimentalProfiles.enabled=false cannot enable V8/V9 lab surfaces",
        ),
        (
            {
                "experimentalProfiles": {
                    "enabled": True,
                    "directTransitObfuscation": {"enabled": False, "restls": {"enabled": True}},
                }
            },
            "experimentalProfiles.directTransitObfuscation.enabled=false cannot enable RESTLS layers",
        ),
        (
            {"experimentalProfiles": {"enabled": True, "directTransitObfuscation": {"enabled": True}}},
            "experimentalProfiles.directTransitObfuscation.enabled=true requires restls.enabled",
        ),
        (
            {"experimentalProfiles": {"tuicV5": {"directEnabled": True}}},
            "experimentalProfiles.enabled=false cannot enable V8/V9 lab surfaces",
        ),
        (
            {"experimentalProfiles": {"enabled": True, "tuicV5": {"enabled": False, "directEnabled": True}}},
            "experimentalProfiles.tuicV5.enabled=false cannot enable TUIC v5 lab routes",
        ),
        (
            {"experimentalProfiles": {"enabled": True, "tuicV5": {"enabled": True}}},
            "experimentalProfiles.tuicV5.enabled=true requires directEnabled or chainEnabled",
        ),
        (
            {"transportProfiles": {"clientNames": ["v5-universal-entry", "v1-direct-reality-vless", "MTProto-TCP443-Direct"]}},
            "transportProfiles.clientNames must include v2-direct-quic-hysteria",
        ),
        (
            {
                "transportProfiles": {
                    "clientNames": [
                        profile for profile in TRACEGATE3_CLIENT_PROFILES if profile != "MTProto-FakeTLS-Direct"
                    ]
                }
            },
            "transportProfiles.clientNames must include MTProto-FakeTLS-Direct",
        ),
        (
            {
                "transportProfiles": {
                    "clientNames": [
                        *TRACEGATE3_CLIENT_PROFILES,
                        "V8-RESTLS-Direct",
                    ]
                }
            },
            "transportProfiles.clientNames must not include lab-only profile V8-RESTLS-Direct",
        ),
    ],
)
def test_tracegate21_chart_rejects_unsafe_transport_overrides(tmp_path: Path, override: dict, message: str) -> None:
    rendered = _helm_template_with_values(tmp_path, override)

    assert rendered.returncode != 0
    assert message in f"{rendered.stdout}\n{rendered.stderr}"


def test_tracegate21_chart_rejects_legacy_mtproto_client_profile_name(tmp_path: Path) -> None:
    values = _values()
    values["transportProfiles"]["clientNames"] = [
        *values["transportProfiles"]["clientNames"],
        "MTProto-TCP443-Direct",
    ]

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "transportProfiles.clientNames must use MTProto-FakeTLS-Direct" in f"{rendered.stdout}\n{rendered.stderr}"


def test_tracegate21_templates_keep_user_state_out_of_rollout_checksums() -> None:
    gateways = (CHART_ROOT / "templates" / "gateways.yaml").read_text(encoding="utf-8")

    assert "kind: PodDisruptionBudget" in gateways
    assert "minAvailable: {{ $.Values.gateway.pdb.minAvailable }}" in gateways
    assert "$entrySmallRole" in gateways
    assert "type: {{ $roleGatewayStrategy }}" in gateways
    assert "maxUnavailable: {{ $roleRollingMaxUnavailable | quote }}" in gateways
    assert "maxSurge: {{ $roleRollingMaxSurge | quote }}" in gateways
    assert "progressDeadlineSeconds: {{ int $.Values.gateway.progressDeadlineSeconds }}" in gateways
    assert "checksum/users" not in gateways
    assert "checksum/secrets" not in gateways
    assert "checksum/tracegate-configmaps" in gateways
    assert "static-topology-only" in gateways
    assert "shareProcessNamespace" in gateways
    assert "terminationGracePeriodSeconds: {{ int $.Values.gateway.terminationGracePeriodSeconds }}" in gateways
    assert "AGENT_XRAY_API_ENABLED" in gateways
    assert "reloadCommands.xray" in gateways
    assert "reloadCommands.fronting" in gateways
    assert "reloadCommands.mtproto" in gateways
    assert "reloadCommands.profiles" in gateways
    assert "reloadCommands.linkCrypto" in gateways
    assert "validate-private-profiles" in gateways
    assert '\\\\\\"auth\\\\\\": \\\\\\"required\\\\\\"' in gateways
    assert '\\\\\\"allowAnonymousLocalhost\\\\\\": false' in gateways
    assert '\\\\\\"private-profile\\\\\\"' in gateways
    assert "tracegate-k3s-private-preflight" in gateways
    assert "defaultMode: {{ int $.Values.privateProfiles.defaultMode }}" in gateways
    assert "gateway.privatePreflight.enabled" in gateways
    assert "--allow-placeholders" not in gateways
    assert "AGENT_RUNTIME_PROFILE" in gateways
    assert gateways.count("name: AGENT_RUNTIME_PROFILE") == 1
    assert "Values.global.runtimeProfile" in gateways
    assert "AGENT_GATEWAY_STRATEGY" in gateways
    assert "AGENT_GATEWAY_ALLOW_RECREATE_STRATEGY" in gateways
    assert "AGENT_GATEWAY_MAX_UNAVAILABLE" in gateways
    assert "AGENT_GATEWAY_MAX_SURGE" in gateways
    assert "AGENT_GATEWAY_PROGRESS_DEADLINE_SECONDS" in gateways
    assert "AGENT_GATEWAY_PDB_MIN_AVAILABLE" in gateways
    assert "AGENT_GATEWAY_PROBES_ENABLED" in gateways
    assert "AGENT_GATEWAY_PRIVATE_PREFLIGHT_ENABLED" in gateways
    assert "AGENT_GATEWAY_PRIVATE_PREFLIGHT_FORBID_PLACEHOLDERS" in gateways
    assert "AGENT_RELOAD_PROFILES_CMD" in gateways
    assert "AGENT_RELOAD_LINK_CRYPTO_CMD" in gateways
    assert "AGENT_ENTRY_TRAFFIC_SHAPING_MAX_MBIT" in gateways
    assert "HYSTERIA_CHAIN_CLIENT_MAX_MBIT" in gateways
    assert "HYSTERIA_CHAIN_CLIENT_REQUIRE_DECLARED_TX" in gateways
    assert "HYSTERIA_ENTRY_CHAIN_IGNORE_CLIENT_BANDWIDTH" in gateways
    assert "AGENT_NODE_ENCRYPTION_MARKER_FILE" in gateways
    assert "entry-traffic-shaper" in gateways
    assert "validate-node-encryption" in gateways
    assert "DEFAULT_ENTRY_HOST" in gateways
    assert "DEFAULT_TRANSIT_HOST" in gateways
    assert "$roleContainerResources" in gateways
    assert 'index $roleContainerResources "agent"' in gateways
    assert 'index $roleContainerResources "zapret2"' in gateways
    assert 'index $roleContainerResources "wireguard"' in gateways
    assert 'index $roleContainerResources "wireguardSync"' in gateways
    assert 'index $roleContainerResources "singbox"' in gateways
    assert 'value: "/var/lib/tracegate/private"' in gateways
    assert "PRIVATE_ZAPRET_PROFILE_DIR" in gateways
    assert "PRIVATE_ZAPRET_PROFILE_ENTRY" in gateways
    assert "PRIVATE_ZAPRET_PROFILE_TRANSIT" in gateways
    assert "PRIVATE_SHADOWSOCKS2022_LINK_PROFILE_DIR" in gateways
    assert "PRIVATE_LINK_CRYPTO_INNER_CARRIER" in gateways
    assert "PRIVATE_SHADOWSOCKS2022_LINK_PROFILE_DIR" in gateways
    assert "PRIVATE_SHADOWTLS_PROFILE_DIR" in gateways
    assert "PRIVATE_SHADOWTLS_PROFILE_ENTRY" in gateways
    assert "PRIVATE_SHADOWTLS_PROFILE_TRANSIT" in gateways
    assert "PRIVATE_LINK_CRYPTO_ENABLED" in gateways
    assert "$roleLinkCryptoClientEnabled" in gateways
    assert "$roleLinkCryptoServerEnabled" in gateways
    assert "$roleLinkCryptoEnabled" in gateways
    assert "shutdown_link_crypto_profiles()" in gateways
    assert "start_link_crypto_profile" in gateways
    assert "PRIVATE_LINK_CRYPTO_GENERATION" in gateways
    assert "PRIVATE_LINK_CRYPTO_BIND_HOST" in gateways
    assert "PRIVATE_LINK_CRYPTO_ENTRY_PORT" in gateways
    assert "PRIVATE_LINK_CRYPTO_TRANSIT_PORT" in gateways
    assert "PRIVATE_LINK_CRYPTO_ROUTER_ENTRY_PORT" in gateways
    assert "PRIVATE_LINK_CRYPTO_ROUTER_TRANSIT_PORT" in gateways
    assert "PRIVATE_LINK_CRYPTO_REMOTE_PORT" in gateways
    assert "roleProfileReloadMarker" in gateways
    assert "roleLinkCryptoReloadMarker" in gateways
    assert "roleProfileEnv" in gateways
    assert "roleLinkCryptoEnv" in gateways
    assert "roleRouterState" in gateways
    assert "roleRouterEnv" in gateways
    assert "roleRouterClientBundle" in gateways
    assert "roleRouterClientEnv" in gateways
    assert "roleRouterRequired" in gateways
    assert "roleRouterAbsentTest" in gateways
    assert "roleRouterValidatedTest" in gateways
    assert "roleRouterReadyTest" in gateways
    assert "roleProfileReadyTest" in gateways
    assert "roleLinkCryptoReadyTest" in gateways
    assert "roleProfileMarkerTest" in gateways
    assert "roleLinkCryptoMarkerTest" in gateways
    assert "TRACEGATE_PROFILE_STATE_JSON" in gateways
    assert "TRACEGATE_PROFILE_STATE_ENV" in gateways
    assert "TRACEGATE_PROFILE_RELOAD_MARKER" in gateways
    assert "TRACEGATE_LINK_CRYPTO_STATE_JSON" in gateways
    assert "TRACEGATE_LINK_CRYPTO_STATE_ENV" in gateways
    assert "TRACEGATE_LINK_CRYPTO_RELOAD_MARKER" in gateways
    assert "tracegate.k3s-private-reload-summary.v1" in gateways
    assert "[ ! %s -nt %s ]" in gateways
    assert "tracegate.k3s-private-reload.v1" in gateways
    assert '\\\\\\"component\\\\\\": \\\\\\"profiles\\\\\\"' in gateways
    assert '\\\\\\"component\\\\\\": \\\\\\"link-crypto\\\\\\"' in gateways
    assert '\\\\\\"router\\\\\\"' in gateways
    assert '\\\\\\"clientBundle\\\\\\"' in gateways
    assert '\\\\\\"clientEnv\\\\\\"' in gateways
    assert "cp /state/base/haproxy/haproxy.cfg /state/runtime/haproxy/haproxy.cfg" in gateways
    assert "cp /state/base/nginx/nginx.conf /state/runtime/nginx/nginx.conf" in gateways
    assert "[ -f /state/runtime/haproxy/haproxy.cfg ] ||" not in gateways
    assert "[ -f /state/runtime/nginx/nginx.conf ] ||" not in gateways


def test_tracegate21_gateway_probes_are_local_only() -> None:
    gateways = (CHART_ROOT / "templates" / "gateways.yaml").read_text(encoding="utf-8")

    assert "startupProbe:" in gateways
    assert "readinessProbe:" in gateways
    assert "livenessProbe:" in gateways
    assert "path: /v1/live" in gateways
    assert "path: /v1/health" in gateways
    assert "port: agent" in gateways
    assert "tcpSocket:" in gateways
    assert "host: 127.0.0.1" in gateways
    assert "port: 8404" in gateways
    assert 'command: ["sh", "-lc", "nc -z -w 1 127.0.0.1 9999"]' in gateways
    assert "test -s /usr/local/etc/haproxy/haproxy.cfg" in gateways
    assert "test -s /etc/nginx/nginx.conf" in gateways
    assert "host: 127.0.0.1" in gateways
    assert "port: reality" in gateways
    assert "http://example" not in gateways
    # Runtime bootstrap may download upstream-owned control files, but kubelet
    # probes themselves stay local tcpSocket/file checks.
    assert "curl -f http://example" not in gateways
    assert "wget -q http://example" not in gateways


def test_mtg_loopback_listener_does_not_render_node_local_tcp_probe(tmp_path: Path) -> None:
    values = _values()
    values["mtproto"]["enabled"] = True
    values["mtproto"]["runtime"] = "mtg"

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    deployments = [doc for doc in _helm_docs(rendered.stdout) if doc.get("kind") == "Deployment"]
    mtg = next(
        containers["mtproto"]
        for deployment in deployments
        if "mtproto" in (containers := _containers_by_name(deployment["spec"]["template"]))
    )
    assert "startupProbe" not in mtg
    assert "readinessProbe" not in mtg
    assert "livenessProbe" not in mtg


def test_tracegate21_templates_include_grpc_mtproto_and_shadowsocks2022_surfaces() -> None:
    text = _chart_text()

    assert "vless-grpc-in" in text
    assert "grpc_pass grpc://127.0.0.1" in text
    assert "client_max_body_size 0;" in text
    assert "be_mtproto" in text
    assert "proxy-protocol-listener = true" in text
    assert "send-proxy-v2" in text
    assert "mtproto-entry-tunnel-in" in text
    assert "/mtg" in text
    assert "/var/lib/tracegate/private/mtproto/runtime/config.toml" in text
    assert 'mtproto_config="/state/private/mtproto/runtime/config.toml"' in text
    assert "MTProto secret must contain exactly 16 bytes in hex" in text
    assert "private/mtproto/runtime/config.toml" in text
    assert "simple-run" not in text
    assert "sing-box run -c" in text
    assert "/home/app/wstunnel server" in text
    assert "wstunnel-link-crypto" in text
    assert "/home/app/wstunnel client --http-upgrade-path-prefix" in text


def test_vless_encryption_renders_separate_xray_surfaces(tmp_path: Path) -> None:
    values = _values()
    values["vlessEncryption"]["enabled"] = True
    values["vlessEncryption"]["encryption"] = "mlkem768x25519plus.native.0rtt.CLIENT"
    values["vlessEncryption"]["realitySni"] = "passport.old-forbidden.tracegate-sni.ru"

    result = _helm_template_with_values(tmp_path, values)
    assert result.returncode == 0, result.stderr
    rendered = result.stdout

    assert "acl vless_encryption_reality_sni req.ssl_sni -i passport.old-forbidden.tracegate-sni.ru" in rendered
    assert "server xray_reality_enc 127.0.0.1:2444 check" in rendered
    assert '"tag": "entry-enc-in"' in rendered
    assert '"tag": "vless-reality-enc-in"' in rendered
    assert '"tag": "vless-ws-enc-in"' in rendered
    assert '"tag": "vless-grpc-enc-in"' in rendered
    assert "REPLACE_VLESS_ENCRYPTION_DECRYPTION" in rendered
    assert "VLESS_ENCRYPTION_DECRYPTION" in rendered


def test_vless_encryption_rejects_legacy_reality_sni_collision(tmp_path: Path) -> None:
    values = _values()
    values["vlessEncryption"]["enabled"] = True
    values["vlessEncryption"]["encryption"] = "mlkem768x25519plus.native.0rtt.CLIENT"
    values["vlessEncryption"]["realitySni"] = "old-forbidden.tracegate-sni.ru"
    values["gateway"]["realityMultiInboundGroups"] = [
        {"id": "legacy", "port": 2515, "dest": "old-forbidden.tracegate-sni.ru", "snis": ["old-forbidden.tracegate-sni.ru"]},
    ]

    result = _helm_template_with_values(tmp_path, values)
    assert result.returncode != 0
    assert "vlessEncryption.realitySni must not reuse legacy REALITY demux SNI old-forbidden.tracegate-sni.ru" in result.stderr


def test_vless_encryption_rejects_emergency_xray_chain_sni_collision(tmp_path: Path) -> None:
    values = _values()
    values["vlessEncryption"]["enabled"] = True
    values["vlessEncryption"]["encryption"] = "mlkem768x25519plus.native.0rtt.CLIENT"
    values["vlessEncryption"]["realitySni"] = "avito.ru"
    values["interconnect"]["emergencyXrayChain"]["enabled"] = True
    values["interconnect"]["emergencyXrayChain"]["serverName"] = "avito.ru"

    result = _helm_template_with_values(tmp_path, values)
    assert result.returncode != 0
    assert "vlessEncryption.realitySni must not reuse emergency Xray chain SNI avito.ru" in result.stderr


def test_vless_encryption_rejects_tls_demux_sni_collision(tmp_path: Path) -> None:
    values = _values()
    values["vlessEncryption"]["enabled"] = True
    values["vlessEncryption"]["encryption"] = "mlkem768x25519plus.native.0rtt.CLIENT"
    values["vlessEncryption"]["realitySni"] = "2gis.ru"
    values["mtproto"]["enabled"] = True
    values["mtproto"]["tlsDomain"] = "2gis.ru"
    values["mtproto"]["stealth"]["validatedTlsDomains"] = ["2gis.ru"]

    result = _helm_template_with_values(tmp_path, values)
    assert result.returncode != 0
    assert "vlessEncryption.realitySni must not reuse TLS demux SNI 2gis.ru" in result.stderr


def test_mtproto_public_port_8443_renders_dedicated_fallback_frontend(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {"mtproto": {"publicPort": 8443}})

    assert rendered.returncode == 0, rendered.stderr
    assert "frontend fe_tracegate_transit_mtproto_8443" in rendered.stdout
    assert "frontend fe_tracegate_entry_mtproto_8443" not in rendered.stdout
    fallback_frontend = rendered.stdout.split("frontend fe_tracegate_transit_mtproto_8443", 1)[
        1
    ].split("frontend fe_tracegate_transit_tls", 1)[0]
    assert "bind :8443" in rendered.stdout
    assert "tcp-request inspect-delay" not in fallback_frontend
    assert "req.ssl_sni" not in fallback_frontend
    assert "default_backend be_mtproto" in rendered.stdout
    assert 'bind-to = "127.0.0.1:9443"' in rendered.stdout
    assert "name: mtproto-fb" in rendered.stdout
    assert "containerPort: 8443" in rendered.stdout
    assert "forbidTcp8443: false" in rendered.stdout
    transit = _deployment_by_component(rendered.stdout, "gateway-transit")
    transit_agent = _containers_by_name(transit["spec"]["template"])["agent"]
    assert _env_value(transit_agent, "MTPROTO_PUBLIC_PORT") == "8443"


def test_mtproto_entry_route_can_split_tls_and_public_upstreams(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "mtproto": {
                "domain": "proto.tracegate.test",
                "publicPort": 8443,
                "route": {
                    "mode": "entry-transit-endpoint",
                    "entry": {
                        "upstreamHost": "198.51.100.109",
                        "tlsUpstreamHost": "192.0.2.10",
                        "publicUpstreamHost": "192.0.2.11",
                        "fallbackHost": "endpoint.tracegate.test",
                        "tlsFallbackHost": "",
                        "publicFallbackHost": "",
                    },
                    "endpoint": {"allowedProxySources": ["198.51.100.109", "203.0.113.10"]},
                },
            }
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    assert "server mtproto_transit_tls 192.0.2.10:443 check" in rendered.stdout
    assert "server mtproto_endpoint_tls endpoint.tracegate.test:443 check backup" not in rendered.stdout
    assert "server mtproto_transit 192.0.2.11:8443 check" in rendered.stdout
    assert "server mtproto_endpoint endpoint.tracegate.test:8443 check backup" not in rendered.stdout


def test_mtproto_fallback_is_not_supported_with_mtg_runtime(tmp_path: Path) -> None:
    unsupported = _helm_template_with_values(
        tmp_path,
        {"mtproto": {"fallback": {"enabled": True, "mode": "mirror", "prefer": "parallel"}}},
    )
    assert unsupported.returncode != 0
    assert "mtproto.fallback is not supported with the MTG runtime" in unsupported.stderr


def test_mtproto_entry_transit_endpoint_route_renders_entry_proxy_and_endpoint_acl(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "mtproto": {
                "domain": "proto.tracegate.test",
                "tlsDomain": "2gis.ru",
                "stealth": {"validatedTlsDomains": ["2gis.ru"]},
                "publicPort": 8443,
                "route": {
                    "mode": "entry-transit-endpoint",
                    "entry": {"upstreamHost": "198.51.100.109", "fallbackHost": "endpoint.tracegate.test"},
                    "endpoint": {"allowedProxySources": ["198.51.100.109", "203.0.113.10"]},
                },
            }
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    assert "frontend fe_tracegate_entry_mtproto_8443" in rendered.stdout
    assert "frontend fe_tracegate_transit_mtproto_8443" in rendered.stdout
    entry_fallback = rendered.stdout.split("frontend fe_tracegate_entry_mtproto_8443", 1)[
        1
    ].split("frontend fe_tracegate_entry_tls", 1)[0]
    endpoint_fallback = rendered.stdout.split("frontend fe_tracegate_transit_mtproto_8443", 1)[
        1
    ].split("frontend fe_tracegate_transit_tls", 1)[0]
    assert "server mtproto_transit_tls 198.51.100.109:443 check" in rendered.stdout
    assert "server mtproto_endpoint_tls endpoint.tracegate.test:443 check backup" in rendered.stdout
    assert "server mtproto_transit 198.51.100.109:8443 check" in rendered.stdout
    assert "server mtproto_endpoint endpoint.tracegate.test:8443 check backup" in rendered.stdout
    assert "use_backend be_mtproto_tls if mtproto_sni" in rendered.stdout
    assert "acl mtproto_sni req.ssl_sni -i" in rendered.stdout
    assert "use_backend be_mtproto if mtproto_sni mtproto_proxy_src" in rendered.stdout
    assert "acl mtproto_proxy_src src 198.51.100.109 203.0.113.10" in endpoint_fallback
    assert "tcp-request connection reject unless mtproto_proxy_src" in endpoint_fallback
    assert "tcp-request connection reject unless mtproto_proxy_src" not in entry_fallback
    assert "MTPROTO_ROUTE_MODE" in rendered.stdout
    assert "entry-transit-endpoint" in rendered.stdout


def test_mtproto_entry_endpoint_tunnel_routes_tls_to_endpoint_public_edge(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["mtproto"] = {
        "enabled": True,
        "runtime": "mtg",
        "domain": "proto.tracegate.test",
        "tlsDomain": "2gis.ru",
        "publicPort": 443,
        "backendPort": 9443,
        "fallback": {"enabled": False},
        "stealth": {
            "requireWhitelistedTlsDomain": True,
            "forbiddenTlsDomains": ["old-forbidden.tracegate-sni.ru", "old-mtproto-a.tracegate-sni.ru"],
            "validatedTlsDomains": ["2gis.ru"],
        },
        "route": {"mode": "entry-endpoint-tunnel", "entry": {"tunnelPort": 11087}},
    }

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    configmaps = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap" and isinstance(doc.get("data"), dict)
    }
    entry_haproxy = configmaps["tracegate-tracegate-gateway-entry-haproxy"]["data"]["haproxy.cfg"]
    endpoint_haproxy = configmaps["tracegate-tracegate-gateway-endpoint-haproxy"]["data"]["haproxy.cfg"]
    entry = _deployment_by_component(rendered.stdout, "gateway-entry")
    endpoint = _deployment_by_component(rendered.stdout, "gateway-endpoint")
    assert "mtproto" not in _containers_by_name(entry["spec"]["template"])
    endpoint_containers = _containers_by_name(endpoint["spec"]["template"])
    assert endpoint_containers["mtproto"]["command"] == ["/mtg"]
    assert "acl mtproto_sni req.ssl_sni -i 2gis.ru" in entry_haproxy
    assert "use_backend be_mtproto_tls if mtproto_sni" in entry_haproxy
    assert "acl request_payload_prefix_ready req.len gt 1" not in entry_haproxy
    assert "server mtproto_endpoint_tls 198.51.100.20:443 check" in entry_haproxy
    assert "server mtproto_endpoint_tunnel 127.0.0.1:11087 check" not in entry_haproxy
    assert "acl mtproto_sni req.ssl_sni -i 2gis.ru" in endpoint_haproxy
    assert "use_backend be_mtproto if mtproto_sni" in endpoint_haproxy
    assert "acl request_payload_prefix_ready req.len gt 1" not in endpoint_haproxy
    assert "server mtproto 127.0.0.1:9443 send-proxy-v2" in endpoint_haproxy
    assert '"tag": "mtproto-entry-tunnel-in"' in rendered.stdout
    assert '"inboundTag": ["mtproto-entry-tunnel-in"], "balancerTag": "endpoint-backhaul"' in rendered.stdout
    assert "proxy-protocol-listener = true" in rendered.stdout
    assert 'proxies = ["socks5://127.0.0.1' not in rendered.stdout
    assert "frontend fe_tracegate_transit_mtproto" not in rendered.stdout


def test_mtproto_entry_endpoint_tunnel_routes_official_proxy_without_sni(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["mtproto"] = {
        "enabled": True,
        "runtime": "official",
        "transport": "random_padding",
        "domain": "entry.prod.test",
        "tlsDomain": "",
        "publicPort": 443,
        "backendPort": 9443,
        "fallback": {
            "enabled": False,
            "officialExternalIp": "198.51.100.20",
            "officialInternalIp": "198.51.100.20",
        },
        "route": {
            "mode": "entry-endpoint-tunnel",
            "inspectDelay": "1s",
            "entry": {"tunnelPort": 11087},
            "endpoint": {"allowedProxySources": ["8.8.4.4"]},
        },
    }

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    configmaps = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap" and isinstance(doc.get("data"), dict)
    }
    entry_haproxy = configmaps["tracegate-tracegate-gateway-entry-haproxy"]["data"]["haproxy.cfg"]
    endpoint_haproxy = configmaps["tracegate-tracegate-gateway-endpoint-haproxy"]["data"]["haproxy.cfg"]
    endpoint_nginx = configmaps["tracegate-tracegate-gateway-endpoint-nginx"]["data"]["nginx.conf"]
    entry = _deployment_by_component(rendered.stdout, "gateway-entry")
    endpoint = _deployment_by_component(rendered.stdout, "gateway-endpoint")
    api = _deployment_by_component(rendered.stdout, "api")
    api_container = _containers_by_name(api["spec"]["template"])["api"]
    assert "mtproto" not in _containers_by_name(entry["spec"]["template"])
    endpoint_containers = _containers_by_name(endpoint["spec"]["template"])
    assert "mtproto" not in endpoint_containers
    assert "mtproto-official" in endpoint_containers
    official = endpoint_containers["mtproto-official"]
    assert official["image"].startswith("mtproxy/mtproxy@sha256:")
    assert official["command"] == ["/bin/bash", "-ec"]
    official_runner = official["args"][0]
    assert 'runtime_dir="${RUNTIME_DIR:-/data}"' in official_runner
    assert '"${runtime_dir}/proxy.secret"' in official_runner
    assert 'exec "${proxy_args[@]}" "${runtime_dir}/proxy.conf"' in official_runner
    assert '${destination}.tmp.${HOSTNAME:-pod}.$$' in official_runner
    assert "getProxySecret" in official_runner
    assert "getProxyConfig" in official_runner
    assert "tg://proxy" not in official_runner
    assert "t.me/proxy" not in official_runner
    assert "echo \"${secret}\"" not in official_runner
    assert _env_value(official, "IP") == "198.51.100.20"
    assert _env_value(official, "INTERNAL_IP") == "198.51.100.20"
    assert _env_value(official, "RUNTIME_DIR") == "/var/lib/tracegate/mtproxy-official"
    assert {
        "name": "gateway-state",
        "mountPath": "/var/lib/tracegate/mtproxy-official",
        "subPath": "mtproxy-official",
    } in official["volumeMounts"]
    assert all(row["name"] != "ARGS" for row in official["env"])
    for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
        assert official[probe_name]["exec"]["command"] == [
            "/bin/bash",
            "-ec",
            'exec 3<>"/dev/tcp/127.0.0.1/${PORT:-9444}"',
        ]
    assert _env_value(endpoint_containers["agent"], "PRIVATE_MTPROTO_UPSTREAM_PORT") == "9444"
    assert _env_value(api_container, "MTPROTO_DOMAIN") == "entry.prod.test"
    assert _env_value(api_container, "MTPROTO_TLS_DOMAIN") == ""
    assert _env_value(api_container, "MTPROTO_TRANSPORT") == "random_padding"
    assert "acl mtproto_sni" not in entry_haproxy
    assert "acl mtproto_sni" not in endpoint_haproxy
    assert "tcp-request inspect-delay 1s" in entry_haproxy
    assert "tcp-request inspect-delay 1s" in endpoint_haproxy
    assert "acl request_payload_prefix_ready req.len gt 1" in entry_haproxy
    assert "acl request_tls_record_prefix req.payload(0,2) -m bin 1603" in entry_haproxy
    assert (
        "tcp-request content accept if request_payload_prefix_ready !request_tls_record_prefix"
        in entry_haproxy
    )
    assert "acl request_payload_prefix_ready req.len gt 1" in endpoint_haproxy
    assert "tcp-request content reject if WAIT_END !universal_origin_allowed_src" not in entry_haproxy
    assert "use_backend be_mtproto_tls if !request_sni_found" in entry_haproxy
    assert "use_backend be_mtproto if !request_sni_found mtproto_proxy_src" in endpoint_haproxy
    assert "server mtproto_official 127.0.0.1:9444 check" in endpoint_haproxy
    assert "send-proxy-v2" not in endpoint_haproxy.split("backend be_mtproto", 1)[1]
    assert "alias /tmp/acme-challenge/;" in endpoint_nginx


def test_mtproto_entry_endpoint_tunnel_exempts_trusted_entry_from_endpoint_rate_limits(tmp_path: Path) -> None:
    values = _pod_only_new_prod_overlay_values(phase="full")
    values["mtproto"] = {
        "enabled": True,
        "runtime": "official",
        "transport": "random_padding",
        "domain": "entry.prod.test",
        "tlsDomain": "",
        "publicPort": 443,
        "backendPort": 9443,
        "fallback": {
            "enabled": False,
            "officialExternalIp": "1.1.1.1",
            "officialInternalIp": "198.51.100.20",
        },
        "route": {
            "mode": "entry-endpoint-tunnel",
            "inspectDelay": "1s",
            "entry": {"tunnelPort": 11087},
            "endpoint": {"allowedProxySources": ["8.8.4.4"]},
        },
    }

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    configmaps = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap" and isinstance(doc.get("data"), dict)
    }
    entry_haproxy = configmaps["tracegate-tracegate-gateway-entry-haproxy"]["data"]["haproxy.cfg"]
    endpoint_haproxy = configmaps["tracegate-tracegate-gateway-endpoint-haproxy"]["data"]["haproxy.cfg"]
    assert "acl endpoint_trusted_proxy_src src" not in entry_haproxy
    endpoint_trusted_line = next(
        line
        for line in endpoint_haproxy.splitlines()
        if "acl endpoint_trusted_proxy_src src" in line
    )
    # The configured proxy source plus the node's own loopback and ingress IPs
    # (shards + service-facing) are exempt from the abuse rate limiter, so the
    # node-local readiness probe and TLS-adapter traffic are never reset.
    for trusted_ip in ("8.8.4.4", "127.0.0.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "1.1.1.1"):
        assert trusted_ip in endpoint_trusted_line
    # The mtproto access-control ACL stays scoped to the configured proxy sources only.
    assert "acl mtproto_proxy_src src 8.8.4.4" in endpoint_haproxy
    assert "tcp-request connection track-sc0 src unless endpoint_trusted_proxy_src" in endpoint_haproxy
    assert (
        "tcp-request connection reject if { sc_conn_cur(0) gt 8 } !endpoint_trusted_proxy_src"
        in endpoint_haproxy
    )
    assert (
        "tcp-request connection reject if { sc_conn_rate(0) gt 12 } !endpoint_trusted_proxy_src"
        in endpoint_haproxy
    )


def test_mtproto_mtg_runs_on_entry_with_fail_closed_endpoint_egress(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "gateway": {"images": {"mtproto": {"repository": "nineseconds/mtg", "tag": "2"}}},
            "mtproto": {
                "runtime": "mtg",
                "domain": "proto.tracegate.test",
                "tlsDomain": "tracegate.test",
                "stealth": {"validatedTlsDomains": ["tracegate.test"]},
                "publicPort": 8443,
                "fallback": {"enabled": False},
                "egress": {
                    "mode": "socks5-only",
                    "socksPort": 11084,
                    "domainFrontingHost": "tracegate.test",
                    "domainFrontingPort": 443,
                },
                "route": {"mode": "entry-local-endpoint-egress"},
            },
            "interconnect": {"emergencyXrayChain": {"enabled": True}},
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    entry = _deployment_by_component(rendered.stdout, "gateway-entry")
    transit = _deployment_by_component(rendered.stdout, "gateway-transit")
    entry_containers = _containers_by_name(entry["spec"]["template"])
    transit_containers = _containers_by_name(transit["spec"]["template"])

    assert entry_containers["mtproto"]["command"] == ["/mtg"]
    assert "mtproto" not in transit_containers
    assert "frontend fe_tracegate_entry_mtproto_8443" in rendered.stdout
    entry_fallback = rendered.stdout.split("frontend fe_tracegate_entry_mtproto_8443", 1)[
        1
    ].split("frontend fe_tracegate_entry_tls", 1)[0]
    assert "req.ssl_sni" not in entry_fallback
    assert "default_backend be_mtproto" in entry_fallback
    assert "server mtproto 127.0.0.1:9443 send-proxy-v2" in rendered.stdout
    assert "server mtproto 127.0.0.1:9443 check send-proxy-v2" not in rendered.stdout
    assert "acl mtproto_sni req.ssl_sni -i tracegate.test" in rendered.stdout
    assert "acl mtproto_sni req.ssl_sni -i tracegate.test proto.tracegate.test" not in rendered.stdout
    assert '"tag": "mtproto-egress-socks-in"' in rendered.stdout
    assert '"port": 11084' in rendered.stdout
    assert '"inboundTag": ["mtproto-egress-socks-in"], "outboundTag": "chain-to-transit"' in rendered.stdout
    assert 'proxies = ["socks5://127.0.0.1:11084"]' in rendered.stdout
    assert {"name": "MTPROTO_DOMAIN_FRONTING_HOST", "value": "tracegate.test"} in entry_containers["agent"]["env"]
    assert {"name": "MTPROTO_DOMAIN_FRONTING_PORT", "value": "443"} in entry_containers["agent"]["env"]
    assert {"name": "MTPROTO_TOLERATE_TIME_SKEWNESS", "value": "5m"} in entry_containers["agent"]["env"]


def test_mtproto_mtg_can_use_source_restricted_shadowtls_endpoint_egress(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "gateway": {"images": {"mtproto": {"repository": "nineseconds/mtg", "tag": "2"}}},
            "mtproto": {
                "runtime": "mtg",
                "domain": "proto.tracegate.test",
                "tlsDomain": "2gis.ru",
                "stealth": {"validatedTlsDomains": ["2gis.ru"]},
                "publicPort": 8443,
                "fallback": {"enabled": False},
                "egress": {
                    "mode": "socks5-only",
                    "socksPort": 11084,
                    "domainFrontingHost": "192.0.2.12",
                    "domainFrontingPort": 443,
                    "shadowtls": {
                        "enabled": True,
                        "serverName": "avito.ru",
                        "endpointHost": "endpoint.tracegate.test",
                        "endpointPort": 443,
                        "serverListenPort": 14444,
                        "endpointSocksPort": 11085,
                        "allowedSources": ["203.0.113.10"],
                    },
                },
                "route": {"mode": "entry-local-endpoint-egress"},
            },
            "interconnect": {"emergencyXrayChain": {"enabled": True}},
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    entry = _deployment_by_component(rendered.stdout, "gateway-entry")
    transit = _deployment_by_component(rendered.stdout, "gateway-transit")
    entry_containers = _containers_by_name(entry["spec"]["template"])
    transit_containers = _containers_by_name(transit["spec"]["template"])
    configmaps = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap" and isinstance(doc.get("data"), dict)
    }
    entry_xray = json.loads(configmaps["tracegate-tracegate-gateway-entry-xray"]["data"]["config.json"])
    transit_xray = json.loads(configmaps["tracegate-tracegate-gateway-transit-xray"]["data"]["config.json"])
    transit_haproxy = configmaps["tracegate-tracegate-gateway-transit-haproxy"]["data"]["haproxy.cfg"]

    assert "mtproto-egress-shadowtls" in entry_containers
    assert "mtproto-egress-shadowtls" in transit_containers
    assert "shadow-tls --v3 client" in entry_containers["mtproto-egress-shadowtls"]["command"][2]
    assert "shadow-tls --v3 server" in transit_containers["mtproto-egress-shadowtls"]["command"][2]
    assert not any(row.get("tag") == "mtproto-egress-socks-in" for row in entry_xray["inbounds"])
    assert any(row.get("tag") == "mtproto-egress-endpoint-socks-in" for row in transit_xray["inbounds"])
    assert "acl mtproto_egress_shadowtls_sni req.ssl_sni -i avito.ru" in transit_haproxy
    assert "acl mtproto_egress_shadowtls_src src 203.0.113.10" in transit_haproxy
    assert (
        "use_backend be_mtproto_egress_shadowtls if mtproto_egress_shadowtls_sni mtproto_egress_shadowtls_src"
        in transit_haproxy
    )
    assert "tcp-request content reject if mtproto_egress_shadowtls_sni" not in transit_haproxy
    assert "server mtproto_egress_shadowtls 127.0.0.1:14444 check" in transit_haproxy


def test_mtproto_mtg_seed_runtime_pins_legacy_fronting_ip(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "mtproto": {
                "runtime": "mtg",
                "domain": "proto.tracegate.test",
                "tlsDomain": "2gis.ru",
                "stealth": {"validatedTlsDomains": ["2gis.ru"]},
                "publicPort": 8443,
                "fallback": {"enabled": False},
                "egress": {
                    "mode": "socks5-only",
                    "socksPort": 11084,
                    "domainFrontingHost": "192.0.2.12",
                    "domainFrontingPort": 443,
                },
                "route": {"mode": "entry-local-endpoint-egress"},
            },
            "interconnect": {"emergencyXrayChain": {"enabled": True}},
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    assert 'domain-fronting-ip = "192.0.2.12"' in rendered.stdout
    assert 'host = "192.0.2.12"' in rendered.stdout


def test_transit_router_renders_gitops_managed_transit_hop(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "transitRouter": {
                "enabled": True,
                "name": "tracegate-transit-router",
                "endpoint": {"host": "endpoint.tracegate.test"},
                "entry": {"allowedSources": ["203.0.113.10"]},
                "tls": {"serverName": "transit.tracegate.test", "existingSecretName": "tracegate-transit-router-tls"},
                "xray": {"existingSecretName": "tracegate-transit-router-xray"},
                "sni": {
                    "decoy": "transit.tracegate.test",
                    "reality": ["www.rbc.ru"],
                },
            },
            "mtproto": {
                "domain": "proto.tracegate.test",
                "tlsDomain": "2gis.ru",
                "stealth": {"validatedTlsDomains": ["2gis.ru"]},
            },
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    router = _deployment_by_component(rendered.stdout, "transit-router")
    assert router["metadata"]["name"] == "tracegate-transit-router"
    assert router["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "Helm"
    assert router["metadata"]["labels"]["tracegate.io/canonical-server"] == "transit"
    assert router["metadata"]["labels"]["tracegate.io/display-name"] == "Transit"
    assert router["spec"]["selector"]["matchLabels"] == {
        "app.kubernetes.io/name": "tracegate-transit-router",
        "app.kubernetes.io/component": "transit-router",
    }
    template = router["spec"]["template"]
    assert template["spec"]["hostNetwork"] is True
    assert template["spec"]["nodeSelector"] == {"tracegate.io/role": "transit"}
    containers = _containers_by_name(template)
    assert containers["haproxy"]["securityContext"]["capabilities"]["add"] == ["NET_BIND_SERVICE"]
    assert containers["xray"]["volumeMounts"][0]["subPath"] == "config.json"

    docs = _helm_docs(rendered.stdout)
    haproxy = next(
        doc["data"]["haproxy.cfg"]
        for doc in docs
        if doc.get("kind") == "ConfigMap" and doc.get("metadata", {}).get("name") == "tracegate-transit-router-haproxy"
    )
    nginx = next(
        doc["data"]["transit-decoy.conf"]
        for doc in docs
        if doc.get("kind") == "ConfigMap" and doc.get("metadata", {}).get("name") == "tracegate-transit-router-nginx"
    )
    assert "acl entry_src src 203.0.113.10" in haproxy
    assert "tcp-request content accept if { req.ssl_hello_type 1 }" not in haproxy
    assert "server endpoint endpoint.tracegate.test:443 check" in haproxy
    assert "server endpoint_mtproto_8443 endpoint.tracegate.test:8443 check" in haproxy
    assert "acl mtproto_sni req.ssl_sni -i proto.tracegate.test 2gis.ru" in haproxy
    assert "server_name transit.tracegate.test;" in nginx
    assert "http2 on;" in nginx


def test_runtime_contract_renders_canonical_server_topology(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "topology": {
                "servers": {
                    "endpoint": {"displayName": "Endpoint", "publicIp": "198.51.100.20"},
                    "transit": {"displayName": "Transit", "publicIp": "203.0.113.30"},
                    "entry": {"displayName": "Entry", "publicIp": "203.0.113.10"},
                }
            }
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    contract = _rendered_runtime_contract(rendered.stdout)
    assert contract["network"]["topology"]["servers"]["endpoint"]["displayName"] == "Endpoint"
    assert contract["network"]["topology"]["servers"]["endpoint"]["publicIp"] == "198.51.100.20"
    assert contract["network"]["topology"]["servers"]["transit"]["publicIp"] == "203.0.113.30"
    assert contract["network"]["topology"]["servers"]["entry"]["publicIp"] == "203.0.113.10"


def test_endpoint_gateway_is_canonically_labeled_when_transit_role_runs_on_endpoint(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "topology": {
                "servers": {
                    "endpoint": {"displayName": "Endpoint", "nodeSelector": {"tracegate.io/role": "endpoint"}},
                    "entry": {"displayName": "Entry", "nodeSelector": {"tracegate.io/role": "entry"}},
                }
            },
            "gateway": {
                "roles": {
                    "transit": {
                        "canonicalServer": "endpoint",
                        "nodeSelector": {"tracegate.io/role": "endpoint"},
                    }
                }
            },
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    gateway_doc = _gateway_deployments(rendered.stdout)["gateway-transit"]
    gateway = gateway_doc["spec"]["template"]
    assert gateway_doc["metadata"]["labels"]["tracegate.io/canonical-server"] == "endpoint"
    assert gateway_doc["metadata"]["labels"]["tracegate.io/display-name"] == "Endpoint"
    assert gateway["metadata"]["labels"]["tracegate.io/canonical-server"] == "endpoint"
    assert gateway["metadata"]["labels"]["tracegate.io/display-name"] == "Endpoint"


def test_tracegate22_transit_nginx_proxies_public_client_config_url(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {})

    assert rendered.returncode == 0, rendered.stderr
    docs = _helm_docs(rendered.stdout)
    transit_nginx = next(
        doc["data"]["nginx.conf"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-transit-nginx"
    )
    entry_nginx = next(
        doc["data"]["nginx.conf"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-entry-nginx"
    )

    assert transit_nginx.count("location ^~ /client-config/") == 2
    assert "proxy_pass http://tracegate-tracegate-api:8080;" in transit_nginx
    assert "proxy_set_header X-Forwarded-Proto https;" in transit_nginx
    assert "location ^~ /client-config/" not in entry_nginx


def test_tracegate22_grafana_host_redirect_preserves_requested_path(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {"controlPlane": {"env": {"grafanaHost": "grafana.example.com"}}},
    )

    assert rendered.returncode == 0, rendered.stderr
    docs = _helm_docs(rendered.stdout)
    transit_nginx = next(
        doc["data"]["nginx.conf"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-transit-nginx"
    )
    transit_haproxy = next(
        doc["data"]["haproxy.cfg"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-transit-haproxy"
    )

    assert transit_nginx.count('if ($host = "grafana.example.com")') == 2
    assert transit_nginx.count("return 302 /grafana$request_uri;") == 2
    assert "acl tls_adapter_sni req.ssl_sni -i transit.example.com grafana.example.com" in transit_haproxy
    assert "server_name transit.example.com grafana.example.com " in transit_nginx


def test_entry_web_surface_redirects_to_endpoint_site_without_replacing_protocol_routes(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {"decoy": {"entryRedirectBaseUrl": "https://main.prod.test"}},
    )

    assert rendered.returncode == 0, rendered.stderr
    docs = _helm_docs(rendered.stdout)
    entry_nginx = next(
        doc["data"]["nginx.conf"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-entry-nginx"
    )
    transit_nginx = next(
        doc["data"]["nginx.conf"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-transit-nginx"
    )
    entry = _deployment_by_component(rendered.stdout, "gateway-entry")["spec"]["template"]
    entry_nginx_container = _containers_by_name(entry)["nginx"]

    assert entry_nginx.count('return 302 "https://main.prod.test$request_uri";') == 2
    assert "listen 80;" in entry_nginx
    assert "location /ws" in entry_nginx
    assert "location /tracegate.v1.Edge/" in entry_nginx
    assert "https://main.prod.test" not in transit_nginx
    assert entry_nginx_container["ports"] == [{"name": "http", "containerPort": 80, "protocol": "TCP"}]


def test_entry_web_redirect_rejects_non_origin_values(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {"decoy": {"entryRedirectBaseUrl": "https://main.prod.test/path"}},
    )

    assert rendered.returncode != 0
    assert "decoy.entryRedirectBaseUrl must be an HTTPS origin without a path" in rendered.stderr


def test_gateway_decoy_configmaps_can_be_scoped_by_canonical_role(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "decoy": {
                "hostPath": "",
                "existingConfigMap": "fallback-decoy",
                "roleSources": {
                    "entry": {"existingConfigMap": "entry-redirect-only"},
                    "endpoint": {
                        "existingConfigMap": "endpoint-site",
                        "existingConfigMapItems": [
                            {"key": "index.html", "path": "index.html"},
                            {"key": "vault.html", "path": "vault/mtproto/index.html"},
                        ],
                    },
                },
            }
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    gateways = _gateway_deployment_templates(rendered.stdout)
    entry_decoy = next(row for row in gateways["gateway-entry"]["spec"]["volumes"] if row["name"] == "decoy")
    endpoint_decoy = next(row for row in gateways["gateway-transit"]["spec"]["volumes"] if row["name"] == "decoy")

    assert entry_decoy == {"name": "decoy", "configMap": {"name": "entry-redirect-only"}}
    assert endpoint_decoy == {
        "name": "decoy",
        "configMap": {
            "name": "endpoint-site",
            "items": [
                {"key": "index.html", "path": "index.html"},
                {"key": "vault.html", "path": "vault/mtproto/index.html"},
            ],
        },
    }


def test_tracegate22_control_plane_receives_reality_client_material(tmp_path: Path) -> None:
    values = {
        "controlPlane": {
            "env": {
                "realityPublicKeyEntry": "entry-pbk",
                "realityPublicKeyTransit": "transit-pbk",
            }
        },
        "gateway": {
            "roles": {
                "entry": {"reality": {"shortIds": ["entry-sid"]}},
                "transit": {"reality": {"shortIds": ["transit-sid"]}},
            }
        },
    }

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    api = _deployment_by_component(rendered.stdout, "api")
    api_container = _containers_by_name(api["spec"]["template"])["api"]
    assert _env_value(api_container, "REALITY_PUBLIC_KEY_ENTRY") == "entry-pbk"
    assert _env_value(api_container, "REALITY_SHORT_ID_ENTRY") == "entry-sid"
    assert _env_value(api_container, "REALITY_PUBLIC_KEY_TRANSIT") == "transit-pbk"
    assert _env_value(api_container, "REALITY_SHORT_ID_TRANSIT") == "transit-sid"


def test_tracegate22_entry_hosts_are_shared_between_client_env_and_gateway_mux(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "controlPlane": {
                "env": {
                    "defaultEntryHost": "entry.prod.test",
                    "defaultTransitHost": "transit.prod.test",
                }
            }
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    api = _deployment_by_component(rendered.stdout, "api")
    api_container = _containers_by_name(api["spec"]["template"])["api"]
    assert _env_value(api_container, "DEFAULT_ENTRY_HOST") == "entry.prod.test"
    assert _env_value(api_container, "DEFAULT_TRANSIT_HOST") == "transit.prod.test"

    gateway_entry = _deployment_by_component(rendered.stdout, "gateway-entry")
    entry_agent = _containers_by_name(gateway_entry["spec"]["template"])["agent"]
    assert _env_value(entry_agent, "DEFAULT_ENTRY_HOST") == "entry.prod.test"
    assert _env_value(entry_agent, "DEFAULT_TRANSIT_HOST") == "transit.prod.test"

    docs = _helm_docs(rendered.stdout)
    entry_haproxy = next(
        doc["data"]["haproxy.cfg"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-entry-haproxy"
    )
    assert "acl tls_adapter_sni req.ssl_sni -i entry.prod.test" in entry_haproxy


def test_tracegate22_gateway_role_hosts_backfill_client_env(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "gateway": {
                "roles": {
                    "entry": {"tls": {"serverName": "entry.prod.test"}},
                    "transit": {"tls": {"serverName": "transit.prod.test"}},
                }
            }
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    api = _deployment_by_component(rendered.stdout, "api")
    api_container = _containers_by_name(api["spec"]["template"])["api"]
    assert _env_value(api_container, "DEFAULT_ENTRY_HOST") == "entry.prod.test"
    assert _env_value(api_container, "DEFAULT_TRANSIT_HOST") == "transit.prod.test"


def test_universal_entry_origin_firewall_can_allow_dns_only_tls_adapter_sni(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["architecture"]["universalEntry"]["originFirewall"]["allowDirectTlsAdapterSni"] = True
    values["controlPlane"]["env"]["defaultEntryHost"] = "entry.prod.test"
    values["gateway"]["roles"]["entry"]["tls"]["serverName"] = "entry.prod.test"
    values["mtproto"] = {
        "enabled": True,
        "runtime": "official",
        "transport": "random_padding",
        "domain": "entry.prod.test",
        "tlsDomain": "",
        "publicPort": 443,
        "backendPort": 9443,
        "fallback": {"enabled": False},
        "route": {
            "mode": "entry-endpoint-tunnel",
            "inspectDelay": "1s",
            "entry": {"tunnelPort": 11087},
            "endpoint": {"allowedProxySources": ["8.8.4.4"]},
        },
    }

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    docs = _helm_docs(rendered.stdout)
    entry_haproxy = next(
        doc["data"]["haproxy.cfg"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-entry-haproxy"
    )
    assert "acl universal_origin_tls_adapter_sni req.ssl_sni -i entry.prod.test" in entry_haproxy
    assert (
        "tcp-request content reject if request_sni_found !universal_origin_allowed_src !universal_origin_tls_adapter_sni"
        in entry_haproxy
    )
    assert "tcp-request content reject if WAIT_END !universal_origin_allowed_src" not in entry_haproxy
    assert "use_backend be_https_adapter if tls_adapter_sni" in entry_haproxy
    assert "use_backend be_mtproto_tls if !request_sni_found" in entry_haproxy


def test_tracegate22_control_plane_receives_enabled_client_profiles(tmp_path: Path) -> None:
    values = {
        "controlPlane": {
            "replicas": {"bot": 1},
            "env": {
                "enabledClientProfiles": [
                    "v1-direct-reality-vless",
                    "v2-direct-quic-hysteria",
                ]
            }
        }
    }

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    api = _deployment_by_component(rendered.stdout, "api")
    bot = _deployment_by_component(rendered.stdout, "bot")
    expected = '["v1-direct-reality-vless","v2-direct-quic-hysteria"]'
    assert _env_value(_containers_by_name(api["spec"]["template"])["api"], "ENABLED_CLIENT_PROFILES") == expected
    assert _env_value(_containers_by_name(bot["spec"]["template"])["bot"], "ENABLED_CLIENT_PROFILES") == expected


def test_tracegate22_k3s_renders_reality_sni_demux_groups(tmp_path: Path) -> None:
    values = {
        "gateway": {
            "realityMultiInboundGroups": [
                {"id": "sni-067", "port": 2510, "dest": "old-mtproto-a.tracegate-sni.ru", "snis": ["old-mtproto-a.tracegate-sni.ru"]},
                {"id": "sni-069", "port": 2511, "dest": "old-mtproto-b.tracegate-sni.ru", "snis": ["old-mtproto-b.tracegate-sni.ru"]},
            ]
        }
    }

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    docs = _helm_docs(rendered.stdout)
    transit_haproxy = next(
        doc["data"]["haproxy.cfg"]
        for doc in docs
        if doc.get("kind") == "ConfigMap" and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-transit-haproxy"
    )
    assert "tcp-request content accept if { req.ssl_hello_type 1 }" not in transit_haproxy
    assert "acl reality_sni_067_sni req.ssl_sni -i old-mtproto-a.tracegate-sni.ru" in transit_haproxy
    assert "use_backend be_reality_sni_067 if reality_sni_067_sni" in transit_haproxy
    assert "backend be_reality_sni_069" in transit_haproxy
    assert "server xray_reality_sni_069 127.0.0.1:2511 check" in transit_haproxy
    transit_agent = _containers_by_name(_gateway_deployment_templates(rendered.stdout)["gateway-transit"])["agent"]
    groups = yaml.safe_load(_env_value(transit_agent, "REALITY_MULTI_INBOUND_GROUPS"))
    assert groups == values["gateway"]["realityMultiInboundGroups"]


def test_tracegate22_exclusive_entry_sni_pairs_render_control_plane_contract(tmp_path: Path) -> None:
    values = _four_ip_entry_overlay_values()
    pool = [f"camouflage-{idx}.prod.test" for idx in range(12)]
    values["architecture"]["entryIngress"]["exclusiveSniPairs"] = {"enabled": True, "pool": pool}
    values["gateway"]["realityMultiInboundGroups"] = [
        {"id": f"sni-{idx}", "port": 2500 + idx, "dest": sni, "snis": [sni]}
        for idx, sni in enumerate(pool, start=1)
    ]

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    api = _deployment_by_component(rendered.stdout, "api")
    api_container = _containers_by_name(api["spec"]["template"])["api"]
    assert _env_value(api_container, "ENTRY_INGRESS_EXCLUSIVE_SNI_PAIRS_ENABLED") == "true"
    assert yaml.safe_load(_env_value(api_container, "ENTRY_INGRESS_SNI_POOL")) == pool


def test_tracegate22_exclusive_entry_sni_pairs_reject_mismatched_inbounds(tmp_path: Path) -> None:
    values = _four_ip_entry_overlay_values()
    pool = [f"camouflage-{idx}.prod.test" for idx in range(12)]
    values["architecture"]["entryIngress"]["exclusiveSniPairs"] = {"enabled": True, "pool": pool}
    values["gateway"]["realityMultiInboundGroups"] = [
        {"id": "only-one", "port": 2501, "dest": pool[0], "snis": [pool[0]]}
    ]

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "exactly one realityMultiInboundGroups row per pool domain" in rendered.stderr


def test_tracegate22_entry_ingress_rejects_duplicate_client_ip(tmp_path: Path) -> None:
    values = _four_ip_entry_overlay_values()
    values["architecture"]["entryIngress"]["shards"][1]["publicIp"] = values["architecture"]["entryIngress"]["shards"][0][
        "publicIp"
    ]

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "architecture.entryIngress.shards[].publicIp values must be unique" in rendered.stderr


def test_tracegate22_universal_entry_routes_all_entry_traffic_through_dual_transport_pool(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    configmaps = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap" and isinstance(doc.get("data"), dict)
    }
    deployments = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "Deployment"
    }
    entry_xray = json.loads(configmaps["tracegate-tracegate-gateway-entry-xray"]["data"]["config.json"])
    entry_nginx = configmaps["tracegate-tracegate-gateway-entry-nginx"]["data"]["nginx.conf"]
    entry_hysteria = configmaps["tracegate-tracegate-gateway-entry-hysteria"]["data"]
    endpoint_xray = json.loads(configmaps["tracegate-tracegate-gateway-endpoint-xray"]["data"]["config.json"])
    endpoint_hysteria = configmaps["tracegate-tracegate-gateway-endpoint-hysteria"]["data"]
    endpoint_haproxy = configmaps["tracegate-tracegate-gateway-endpoint-haproxy"]["data"]["haproxy.cfg"]
    entry_containers = _containers_by_name(deployments["tracegate-tracegate-gateway-entry"]["spec"]["template"])
    user_rules = [
        rule
        for rule in entry_xray["routing"]["rules"]
        if "vless-grpc-in" in rule.get("inboundTag", [])
    ]

    assert any(rule.get("balancerTag") == "endpoint-backhaul" for rule in user_rules)
    assert not any(rule.get("outboundTag") == "direct" for rule in user_rules)
    xhttp_outbounds = [row for row in entry_xray["outbounds"] if str(row.get("tag", "")).startswith("chain-xhttp-")]
    assert len(xhttp_outbounds) == 2
    assert {row["streamSettings"]["realitySettings"]["serverName"] for row in xhttp_outbounds} == {
        "rbc.ru",
        "www.rbc.ru",
    }
    assert all(row["streamSettings"]["xhttpSettings"]["mode"] == "stream-one" for row in xhttp_outbounds)
    assert all(row["streamSettings"]["xhttpSettings"]["extra"]["xmux"]["maxConnections"] == 1 for row in xhttp_outbounds)
    assert any(row.get("tag") == "chain-hysteria2" for row in entry_xray["outbounds"])
    assert entry_xray["routing"]["balancers"] == [
        {
            "tag": "endpoint-backhaul",
            "selector": ["chain-xhttp-"],
            "fallbackTag": "chain-hysteria2",
            "strategy": {"type": "roundRobin"},
        }
    ]
    assert entry_xray["observatory"]["subjectSelector"] == ["chain-xhttp-"]
    assert entry_xray["observatory"]["probeURL"] == "https://rbc.ru/"
    assert "backhaul-client.yaml" in entry_hysteria
    assert "REPLACE_HYSTERIA_ENDPOINT_BACKHAUL_AUTH" in entry_hysteria["backhaul-client.yaml"]
    backhaul_client = yaml.safe_load(entry_hysteria["backhaul-client.yaml"])
    assert backhaul_client["server"] == "198.51.100.20:443"
    assert backhaul_client["obfs"]["type"] == "salamander"
    assert backhaul_client["quic"]["keepAlivePeriod"] == "10s"
    assert backhaul_client["congestion"] == {"type": "bbr", "bbrProfile": "conservative"}
    assert backhaul_client["socks5"] == {"listen": "127.0.0.1:11086", "disableUDP": False}
    assert "hysteria-backhaul-client" in entry_containers
    backhaul_runtime = entry_containers["hysteria-backhaul-client"]
    assert backhaul_runtime["command"] == ["sh", "-lc"]
    assert "retrying in ${delay}s" in backhaul_runtime["args"][0]
    assert backhaul_runtime["readinessProbe"]["tcpSocket"] == {"host": "127.0.0.1", "port": 11086}
    assert {row["tag"] for row in endpoint_xray["inbounds"] if str(row.get("tag", "")).startswith("chain-bridge-")} == {
        "chain-bridge-mail-in",
        "chain-bridge-2gis_reviews-in",
    }
    assert all(
        row.get("sniffing") == {"enabled": False}
        for row in endpoint_xray["inbounds"]
        if str(row.get("tag", "")).startswith("chain-bridge-")
    )
    endpoint_hysteria_server = yaml.safe_load(endpoint_hysteria["server.yaml"])
    assert endpoint_hysteria_server["sniff"]["enable"] is False
    assert endpoint_hysteria_server["outbounds"] == [
        {"name": "direct-v4", "type": "direct", "direct": {"mode": 4}}
    ]
    assert next(row for row in entry_xray["outbounds"] if row["tag"] == "direct")["settings"] == {
        "domainStrategy": "ForceIPv4"
    }
    assert next(row for row in endpoint_xray["outbounds"] if row["tag"] == "direct")["settings"] == {
        "domainStrategy": "ForceIPv4"
    }
    assert any(rule.get("ip") == ["::/0"] and rule.get("outboundTag") == "block" for rule in entry_xray["routing"]["rules"])
    assert any(rule.get("ip") == ["::/0"] and rule.get("outboundTag") == "block" for rule in endpoint_xray["routing"]["rules"])
    assert "use_backend be_chain_bridge_mail if chain_bridge_mail_sni chain_bridge_mail_src" in endpoint_haproxy
    assert (
        "use_backend be_chain_bridge_2gis_reviews if chain_bridge_2gis_reviews_sni chain_bridge_2gis_reviews_src"
        in endpoint_haproxy
    )
    assert "grpc_read_timeout 1h;" in entry_nginx
    assert "grpc_send_timeout 1h;" in entry_nginx


def test_tracegate3_entry_endpoint_routes_all_entry_user_traffic_to_endpoint(tmp_path: Path) -> None:
    values = _entry_endpoint_overlay_values()

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    configmaps = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap" and isinstance(doc.get("data"), dict)
    }
    entry_xray = json.loads(configmaps["tracegate-tracegate-gateway-entry-xray"]["data"]["config.json"])
    user_rules = [
        rule
        for rule in entry_xray["routing"]["rules"]
        if "vless-grpc-in" in rule.get("inboundTag", [])
    ]

    assert any(rule.get("balancerTag") == "endpoint-backhaul" for rule in user_rules)
    assert not any(rule.get("outboundTag") == "direct" for rule in user_rules)


def test_tracegate22_universal_entry_rejects_direct_origin_exposure(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["architecture"]["universalEntry"]["originFirewall"]["denyDirectAccess"] = False

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "architecture.universalEntry.originFirewall.denyDirectAccess=false is forbidden" in rendered.stderr


def test_tracegate22_universal_entry_rejects_parallel_ingress_rotation(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["architecture"]["ingressRotation"]["enabled"] = True
    values["architecture"]["ingressRotation"]["entryHosts"] = ["edge-a.prod.test", "edge-b.prod.test"]

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "architecture.universalEntry.enabled=true forbids architecture.ingressRotation.enabled=true" in rendered.stderr


def test_tracegate22_universal_entry_rejects_parallel_backhaul_dials(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["interconnect"]["endpointBackhaul"]["selection"]["maxParallelDials"] = 2

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "interconnect.endpointBackhaul.selection.maxParallelDials must stay 1" in rendered.stderr


def test_tracegate22_universal_entry_rejects_conflicting_xhttp_xmux_limits(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["interconnect"]["emergencyXrayChain"]["xhttp"] = {"xmux": {"maxConcurrency": "8-16"}}

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "xhttp.xmux.maxConnections and maxConcurrency cannot be set together" in rendered.stderr


def test_tracegate22_universal_entry_rejects_duplicate_xhttp_shard_sni(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["interconnect"]["emergencyXrayChain"]["shards"][1]["serverName"] = "rbc.ru"

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "interconnect.emergencyXrayChain.shards[].serverName values must be unique" in rendered.stderr


def test_tracegate3_entry_staged_rejects_endpoint_direct_sni_reused_by_xhttp_shard(tmp_path: Path) -> None:
    values = _pod_only_new_prod_overlay_values(phase="entry-staged")
    values["interconnect"]["emergencyXrayChain"]["shards"][0]["serverName"] = "yandex.ru"
    values["interconnect"]["emergencyXrayChain"]["shards"][0]["dest"] = "yandex.ru:443"

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "Endpoint direct SNI pool must not overlap Entry-to-Endpoint XHTTP shard SNI values" in rendered.stderr


def test_tracegate3_entry_staged_rejects_endpoint_direct_sni_reused_by_shadowtls(tmp_path: Path) -> None:
    values = _pod_only_new_prod_overlay_values(phase="entry-staged")
    values["shadowsocks2022"]["shadowtls"] = {"serverNameTransit": "yandex.ru"}

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "shadowsocks2022.shadowtls.serverNameTransit must not reuse an Endpoint direct SNI" in rendered.stderr


def test_tracegate22_universal_entry_rejects_disabled_hysteria_fallback(tmp_path: Path) -> None:
    values = _universal_entry_overlay_values()
    values["interconnect"]["endpointBackhaul"]["hysteria2"]["enabled"] = False

    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode != 0
    assert "requires interconnect.endpointBackhaul.hysteria2.enabled=true" in rendered.stderr


def test_tracegate3_k3s_does_not_render_removed_naiveproxy_runtime(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {})

    assert rendered.returncode == 0, rendered.stderr
    docs = _helm_docs(rendered.stdout)
    transit_haproxy = next(
        doc["data"]["haproxy.cfg"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-tracegate-gateway-transit-haproxy"
    )
    components = {
        doc.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component")
        for doc in docs
        if doc.get("kind") == "Deployment"
    }

    assert "naiveproxy" not in components
    assert "naiveproxy_sni" not in transit_haproxy
    assert "be_naiveproxy" not in transit_haproxy


def test_prometheus_scrapes_gateway_agents_when_observability_enabled(tmp_path: Path) -> None:
    values = {
        "observability": {
            "prometheus": {
                "enabled": True,
                "nodeSelector": {"tracegate.io/role": "endpoint"},
            }
        }
    }
    rendered = _helm_template_with_values(tmp_path, values)

    assert rendered.returncode == 0, rendered.stderr
    docs = _helm_docs(rendered.stdout)
    prometheus_config = next(
        doc["data"]["prometheus.yml"]
        for doc in docs
        if doc.get("kind") == "ConfigMap"
        and doc.get("metadata", {}).get("name") == "tracegate-prometheus-config"
    )

    assert "job_name: tracegate-agent" in prometheus_config
    assert "regex: gateway-.+" in prometheus_config
    assert "gateway-.+|naiveproxy" not in prometheus_config
    assert "job_name: kubernetes-probes" in prometheus_config
    assert "replacement: /api/v1/nodes/${1}/proxy/metrics/probes" in prometheus_config

    prometheus = _deployment_by_component(rendered.stdout, "prometheus")
    assert prometheus["spec"]["template"]["metadata"]["annotations"] == {
        "tracegate.io/release-revision": "1"
    }
    assert prometheus["spec"]["template"]["spec"]["nodeSelector"] == {
        "tracegate.io/role": "endpoint"
    }


def test_postgres_backup_renders_encrypted_off_node_backup_and_restore_check(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "controlPlane": {
                "database": {
                    "backup": {
                        "enabled": True,
                        "repositorySecretName": "tracegate-postgres-backup-test",
                    }
                },
                "nodeSelector": {"tracegate.io/role": "endpoint"},
            }
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    docs = _helm_docs(rendered.stdout)
    cronjobs = {
        doc["metadata"]["name"]: doc
        for doc in docs
        if doc.get("kind") == "CronJob"
    }
    backup = cronjobs["tracegate-tracegate-postgres-backup"]
    restore = cronjobs["tracegate-tracegate-postgres-restore-check"]

    backup_pod = backup["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert backup_pod["nodeSelector"] == {"tracegate.io/role": "endpoint"}
    init_by_name = {row["name"]: row for row in backup_pod["initContainers"]}
    assert set(init_by_name) == {"pg-dump", "restic-repository-check", "restic-backup"}
    database_env = init_by_name["pg-dump"]["env"][0]
    assert database_env["valueFrom"]["secretKeyRef"] == {
        "name": "tracegate-database-url",
        "key": "url",
    }
    assert init_by_name["restic-backup"]["envFrom"][0]["secretRef"]["name"] == (
        "tracegate-postgres-backup-test"
    )
    retention = backup_pod["containers"][0]
    assert retention["name"] == "restic-retention"
    assert "--prune" in retention["args"]

    restore_pod = restore["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert restore_pod["initContainers"][0]["name"] == "restic-restore"
    restore_check = restore_pod["containers"][0]
    restore_script = restore_check["args"][0]
    assert "pg_restore --exit-on-error" in restore_script
    assert "public.alembic_version" in restore_script
    assert "RESTIC_PASSWORD" not in rendered.stdout


def test_postgres_backup_is_disabled_by_default(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {})

    assert rendered.returncode == 0, rendered.stderr
    assert "kind: CronJob" not in rendered.stdout
    assert "postgres-backup" not in rendered.stdout


def test_grafana_renders_as_helm_managed_observability_resource(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "controlPlane": {
                "env": {
                    "grafanaEnabled": True,
                    "grafanaPublicBaseUrl": "https://grafana.example.com",
                    "grafanaAdminPasswordSecret": {"name": "tracegate-grafana-auth", "key": "admin-password"},
                }
            }
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    docs = _helm_docs(rendered.stdout)
    deployment = _deployment_by_component(rendered.stdout, "grafana")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    env_by_name = {row["name"]: row for row in container["env"]}

    assert deployment["metadata"]["name"] == "tracegate-grafana"
    assert deployment["spec"]["template"]["metadata"]["labels"] == {
        "app.kubernetes.io/name": "tracegate-grafana",
        "app.kubernetes.io/part-of": "tracegate",
    }
    assert container["image"].startswith("grafana/grafana@sha256:")
    assert env_by_name["GF_SERVER_ROOT_URL"]["value"] == "https://grafana.example.com/grafana/"
    assert env_by_name["GF_SECURITY_ADMIN_PASSWORD"]["valueFrom"]["secretKeyRef"] == {
        "name": "tracegate-grafana-auth",
        "key": "admin-password",
    }

    pvc = next(doc for doc in docs if doc.get("kind") == "PersistentVolumeClaim" and doc["metadata"]["name"] == "tracegate-grafana-data")
    service = next(doc for doc in docs if doc.get("kind") == "Service" and doc["metadata"]["name"] == "tracegate-grafana")
    assert pvc["spec"]["resources"]["requests"]["storage"] == "5Gi"
    assert service["spec"]["ports"] == [{"name": "http", "port": 3000, "targetPort": "http", "protocol": "TCP"}]


def test_tracegate22_xray_defaults_client_traffic_to_direct(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {})

    assert rendered.returncode == 0, rendered.stderr
    xray_configmaps = [
        doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap"
        and str(doc.get("metadata", {}).get("name") or "").endswith("-xray")
        and isinstance(doc.get("data", {}).get("config.json"), str)
    ]
    assert xray_configmaps

    for configmap in xray_configmaps:
        config = json.loads(configmap["data"]["config.json"])
        outbounds = config["outbounds"]
        assert outbounds[0]["tag"] == "direct"
        assert {row["tag"] for row in outbounds} >= {"api", "direct", "block"}
        assert any(
            rule.get("inboundTag") == ["api"] and rule.get("outboundTag") == "api"
            for rule in config["routing"]["rules"]
        )


def test_tracegate22_emergency_chain_bridge_routes_entry_via_transit(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {
            "interconnect": {
                "emergencyXrayChain": {
                    "enabled": True,
                    "endpointHost": "endpoint.tracegate.test",
                    "endpointPort": 443,
                    "endpointListenHost": "127.0.0.1",
                    "allowedSources": ["203.0.113.10"],
                    "failover": {
                        "enabled": True,
                        "localPort": 11083,
                        "primaryHost": "198.51.100.109",
                        "primaryPort": 443,
                        "fallbackHost": "endpoint.tracegate.test",
                        "fallbackPort": 443,
                    },
                }
            },
            "topology": {"servers": {"endpoint": {"publicIp": "198.51.100.20"}}},
            "shadowsocks2022": {"enabled": True},
            "controlPlane": {
                "env": {
                    "defaultTransitHost": "transit.tracegate.test",
                    "realityPublicKeyTransit": "test-pbk",
                    "realityShortIdTransit": "abc123",
                }
            },
        },
    )

    assert rendered.returncode == 0, rendered.stderr
    configmaps = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "ConfigMap" and isinstance(doc.get("data"), dict)
    }
    deployments = {
        doc["metadata"]["name"]: doc
        for doc in _helm_docs(rendered.stdout)
        if doc.get("kind") == "Deployment"
    }
    entry_xray = json.loads(configmaps["tracegate-tracegate-gateway-entry-xray"]["data"]["config.json"])
    entry_hysteria = yaml.safe_load(configmaps["tracegate-tracegate-gateway-entry-hysteria"]["data"]["server.yaml"])
    entry_haproxy = configmaps["tracegate-tracegate-gateway-entry-haproxy"]["data"]["haproxy.cfg"]
    transit_haproxy = configmaps["tracegate-tracegate-gateway-transit-haproxy"]["data"]["haproxy.cfg"]
    transit_xray = json.loads(configmaps["tracegate-tracegate-gateway-transit-xray"]["data"]["config.json"])
    entry_containers = deployments["tracegate-tracegate-gateway-entry"]["spec"]["template"]["spec"]["containers"]
    transit_containers = deployments["tracegate-tracegate-gateway-transit"]["spec"]["template"]["spec"]["containers"]

    assert any(row.get("tag") == "entry-chain-socks-in" for row in entry_xray["inbounds"])
    assert any(row.get("tag") == "ss2022-in" for row in entry_xray["inbounds"])
    assert any(row.get("tag") == "ss2022-in" for row in transit_xray["inbounds"])
    transit_reality = next(row for row in transit_xray["inbounds"] if row.get("tag") == "vless-reality-in")
    assert transit_reality["listen"] == "127.0.0.1"
    chain_outbound = next(row for row in entry_xray["outbounds"] if row.get("tag") == "chain-to-transit")
    assert chain_outbound["settings"]["vnext"][0]["address"] == "127.0.0.1"
    assert chain_outbound["settings"]["vnext"][0]["port"] == 11083
    assert chain_outbound["streamSettings"]["realitySettings"]["publicKey"] == "test-pbk"
    assert chain_outbound["streamSettings"]["realitySettings"]["shortId"] == "abc123"
    assert "listen fe_tracegate_entry_chain_bridge_failover" in entry_haproxy
    assert "bind 127.0.0.1:11083" in entry_haproxy
    assert "server chain_transit 198.51.100.109:443 check" in entry_haproxy
    assert "server chain_endpoint endpoint.tracegate.test:443 check backup" in entry_haproxy
    assert "acl chain_bridge_src src 203.0.113.10" in transit_haproxy
    assert "tcp-request content reject if chain_bridge_sni !chain_bridge_src" in transit_haproxy
    assert "use_backend be_reality if chain_bridge_sni chain_bridge_src" in transit_haproxy
    routing_rules = entry_xray["routing"]["rules"]
    chain_rule_index, chain_rule = next(
        (idx, rule) for idx, rule in enumerate(routing_rules) if rule.get("outboundTag") == "chain-to-transit"
    )
    assert {"entry-in", "entry-chain-socks-in", "ss2022-in"} <= set(chain_rule["inboundTag"])
    ru_domain_rule_index, ru_domain_rule = next(
        (idx, rule)
        for idx, rule in enumerate(routing_rules)
        if rule.get("outboundTag") == "direct" and "domain" in rule
    )
    ru_ip_rule_index, ru_ip_rule = next(
        (idx, rule) for idx, rule in enumerate(routing_rules) if rule.get("outboundTag") == "direct" and "ip" in rule
    )
    assert ru_domain_rule_index < chain_rule_index
    assert ru_ip_rule_index < chain_rule_index
    assert {"entry-in", "entry-chain-socks-in", "ss2022-in"} <= set(ru_domain_rule["inboundTag"])
    assert ru_ip_rule["ip"] == ["geoip:ru"]
    assert "geosite:category-ru" in ru_domain_rule["domain"]
    assert "geosite:ru" not in ru_domain_rule["domain"]
    assert "regexp:(?i)\\.ru$" in ru_domain_rule["domain"]
    assert "regexp:(?i)\\.su$" in ru_domain_rule["domain"]
    assert "regexp:(?i)\\.xn--p1ai$" in ru_domain_rule["domain"]
    assert "regexp:(?i)\\.moscow$" in ru_domain_rule["domain"]
    assert "regexp:(?i)\\.xn--80adxhks$" in ru_domain_rule["domain"]
    assert "regexp:(?i)\\.tatar$" in ru_domain_rule["domain"]
    assert "regexp:(?i)\\.xn--p1acf$" in ru_domain_rule["domain"]
    assert "regexp:(?i)\\.xn--d1acj3b$" in ru_domain_rule["domain"]
    assert "domain:example-bank.example.net" in ru_domain_rule["domain"]
    assert "domain:example-rail.example.net" in ru_domain_rule["domain"]
    assert not any(
        "domain:example-bank.example.net" in rule.get("domain", []) for rule in transit_xray["routing"]["rules"]
    )
    assert entry_hysteria["outbounds"][0]["socks5"]["addr"] == "127.0.0.1:11082"
    assert all(row["name"] != "shadowsocks-2022" for row in entry_containers)
    assert all(row["name"] != "shadowsocks-2022" for row in transit_containers)
    transit_clients = transit_reality["settings"]["clients"]
    assert transit_clients == [{"id": "REPLACE_XRAY_CHAIN_BRIDGE_CLIENT_ID", "email": "Tracegate Entry-Transit Chain Bridge"}]


def test_tracegate21_gateway_projects_private_profile_secret_paths() -> None:
    gateways = (CHART_ROOT / "templates" / "gateways.yaml").read_text(encoding="utf-8")
    configmaps = (CHART_ROOT / "templates" / "configmaps.yaml").read_text(encoding="utf-8")

    assert "items:" in gateways
    assert "secretKeys.shadowsocks2022LinkClient" in gateways
    assert "secretKeys.shadowsocks2022LinkServer" in gateways
    assert "path: {{ $.Values.privateProfiles.keys.shadowsocks2022LinkClient }}" in gateways
    assert "path: {{ $.Values.privateProfiles.keys.shadowsocks2022LinkServer }}" in gateways
    assert "--required-file" in gateways
    assert "--zapret-file" in gateways
    assert "keys.realityPrivateKeyEntry" in gateways
    assert "keys.realityPrivateKeyTransit" in gateways
    assert "keys.hysteriaSalamanderEntry" in gateways
    assert "keys.hysteriaSalamanderTransit" in gateways
    assert "keys.hysteriaStatsEntry" in gateways
    assert "keys.hysteriaStatsTransit" in gateways
    assert "keys.shadowsocks2022Entry" in gateways
    assert "keys.shadowsocks2022Transit" in gateways
    assert "secretKeys.shadowsocks2022Entry" in gateways
    assert "secretKeys.shadowsocks2022Transit" in gateways
    assert "keys.shadowsocks2022PasswordEntry" in gateways
    assert "keys.shadowsocks2022PasswordTransit" in gateways
    assert "secretKeys.shadowsocks2022PasswordEntry" in gateways
    assert "secretKeys.shadowsocks2022PasswordTransit" in gateways
    assert "keys.shadowtlsEntry" in gateways
    assert "keys.shadowtlsTransit" in gateways
    assert "keys.shadowtlsPasswordEntry" in gateways
    assert "keys.shadowtlsPasswordTransit" in gateways
    assert "secretKeys.shadowtlsPasswordEntry" in gateways
    assert "secretKeys.shadowtlsPasswordTransit" in gateways
    assert '(eq $roleName "transit") $.Values.shadowsocks2022.enabled' not in gateways
    assert "{{- if $.Values.shadowsocks2022.enabled }}" in gateways
    assert "name: shadowsocks-2022" not in gateways
    assert "REPLACE_SHADOWSOCKS2022_PASSWORD" in configmaps
    assert "replace_xray_literal REPLACE_SHADOWSOCKS2022_PASSWORD" in gateways
    assert '"tag": "ss2022-in"' in configmaps
    assert "fingerprint()" not in gateways
    assert 'kill "${child}"' not in gateways
    assert "shadow-tls --v3 server" in gateways
    assert '--tls "{{ $roleShadowtlsServerName }}:443"' in gateways
    assert 'start_zapret_profile "{{ $.Values.privateProfiles.mountPath }}/{{ $zapretProfileKey }}"' in gateways
    assert "keys.zapretInterconnect" not in gateways
    assert (
        'start_zapret_profile "{{ $.Values.privateProfiles.mountPath }}/{{ $.Values.privateProfiles.keys.zapretMtproto }}"'
        in gateways
    )
    assert '$roleIsEndpoint $.Values.wireguard.enabled' in gateways
    assert '$roleIsEndpoint $.Values.mtproto.enabled' in gateways
    assert "name: wireguard" in gateways
    assert "name: wireguard-sync" in gateways
    assert "tracegate-wireguard-sync-runner" in gateways
    assert "wg-quick up {{ $.Values.privateProfiles.mountPath }}/{{ $.Values.privateProfiles.keys.wireguard }}" in gateways
    assert "wstunnel-wireguard" in gateways
    assert "wstunnel-link-crypto" in gateways
    assert (
        'exec /home/app/wstunnel client --http-upgrade-path-prefix "{{ $linkOuterCarrierPathPrefix }}" '
        '-L "tcp://127.0.0.1:{{ int $linkOuterCarrier.clientLocalPort }}:127.0.0.1:{{ int $.Values.interconnect.shadowsocks2022.localSocks.transitPort }}"'
        in gateways
    )
    assert 'exec /home/app/wstunnel server "ws://127.0.0.1:{{ int $linkOuterCarrier.serverLocalPort }}"' in gateways
    assert '$roleIsEndpoint $.Values.wireguard.enabled $.Values.wireguard.wstunnel.enabled' in gateways
    assert "location {{ $.Values.wireguard.wstunnel.publicPath }}" in configmaps
    assert "proxy_pass http://127.0.0.1:{{ int $.Values.wireguard.wstunnel.websocketPort }}" in configmaps
    assert "location {{ $linkOuterCarrier.publicPath }}" in configmaps
    assert "proxy_pass http://127.0.0.1:{{ int $linkOuterCarrier.serverLocalPort }}" in configmaps
    assert "bridge_wss_sni" in configmaps
    assert "until {{ $roleLinkCryptoReadyTest }}; do sleep 2; done" in gateways
    assert "start_link_crypto_profile" in gateways
    assert 'until {{ $roleProfileReadyTest }} && [ -s "${password_file}" ]; do sleep 2; done' in gateways
    assert "until {{ $roleProfileReadyTest }}; do sleep 2; done; /home/app/wstunnel server" in gateways
    assert "value: {{ $roleProfileState | quote }}" in gateways
    assert "value: {{ $roleProfileReloadMarker | quote }}" in gateways
    assert "value: {{ $roleLinkCryptoState | quote }}" in gateways
    assert "value: {{ $roleLinkCryptoReloadMarker | quote }}" in gateways
    assert "PRIVATE_LINK_CRYPTO_OUTER_WSS_SERVER_NAME" in gateways
    assert "value: {{ $linkOuterCarrier.serverName | quote }}" in gateways
    assert "PRIVATE_LINK_CRYPTO_OUTER_WSS_PATH" in gateways
    assert "mountPath: /var/lib/tracegate" in gateways
    assert "readOnly: true" in gateways
    assert "REALITY_PRIVATE_KEY" in gateways
    assert "AGENT_STATS_SECRET" in gateways
    assert "HYSTERIA_SALAMANDER_PASSWORD_ENTRY" in (CHART_ROOT / "templates" / "control-plane.yaml").read_text(encoding="utf-8")
    assert "escape_sed_replacement()" in gateways
    assert "replace_xray_literal REPLACE_REALITY_PRIVATE_KEY" in gateways
    assert "replace_hysteria_literal REPLACE_HYSTERIA_SALAMANDER_PASSWORD" in gateways
    assert "replace_hysteria_literal REPLACE_HYSTERIA_STATS_SECRET" in gateways
    assert "REPLACE_REALITY_PRIVATE_KEY" in configmaps
    assert "REPLACE_HYSTERIA_AUTH" not in configmaps
    assert "REPLACE_HYSTERIA_SALAMANDER_PASSWORD" in configmaps
    assert "REPLACE_HYSTERIA_STATS_SECRET" in configmaps
    assert '"hy2-in"' not in configmaps
    assert 'protocol": "hysteria"' not in configmaps
    assert "REPLACE_FROM_PRIVATE_SECRET" not in configmaps


@pytest.mark.parametrize(
    ("values_path", "phase"),
    [
        (ENDPOINT_FIRST_EXAMPLE, "endpoint-first"),
        (ENTRY_ENDPOINT_EXAMPLE, "full"),
    ],
)
def test_new_production_examples_render_as_pod_only_runtime(tmp_path: Path, values_path: Path, phase: str) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")
    adapted_values = tmp_path / f"{phase}-chart-values.yaml"
    adapted = subprocess.run(
        [
            "python3",
            "deploy/k3s/new-production-values-adapter.py",
            "--values",
            str(values_path),
            "--output",
            str(adapted_values),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert adapted.returncode == 0, adapted.stderr
    manifest = tmp_path / f"{phase}.yaml"
    rendered = subprocess.run(
        [helm, "template", "tracegate", str(CHART_ROOT), "-f", str(adapted_values)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rendered.returncode == 0, rendered.stderr
    manifest.write_text(rendered.stdout, encoding="utf-8")

    readiness = subprocess.run(
        ["python3", "deploy/k3s/pod-runtime-readiness.py", "--manifest", str(manifest), "--phase", phase],
        check=False,
        capture_output=True,
        text=True,
    )
    assert readiness.returncode == 0, readiness.stdout + readiness.stderr
    if phase == "endpoint-first":
        endpoint = _gateway_deployment_templates(rendered.stdout)["gateway-endpoint"]
        haproxy = _containers_by_name(endpoint)["haproxy"]
        assert haproxy["readinessProbe"]["tcpSocket"] == {"host": "127.0.0.1", "port": 8404}


def test_new_production_values_adapter_rejects_removed_surfaces(tmp_path: Path) -> None:
    values = yaml.safe_load(ENDPOINT_FIRST_EXAMPLE.read_text(encoding="utf-8"))
    values["gateway"]["roles"]["transit"] = values["gateway"]["roles"].pop("endpoint")
    source = tmp_path / "values.yaml"
    source.write_text(yaml.safe_dump(values, sort_keys=False), encoding="utf-8")

    adapted = subprocess.run(
        [
            "python3",
            "deploy/k3s/new-production-values-adapter.py",
            "--values",
            str(source),
            "--output",
            str(tmp_path / "chart-values.yaml"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert adapted.returncode != 0
    assert "removed surfaces" in adapted.stderr


def test_tracegate_chart_runs_singbox_inner_carrier_for_shadowsocks2022(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {"interconnect": {"entryTransit": {"innerCarrier": "shadowsocks2022"}}},
    )
    assert rendered.returncode == 0, rendered.stderr
    templates = _gateway_deployment_templates(rendered.stdout)
    sidecar = _containers_by_name(templates["gateway-entry"])["sing-box-link-crypto"]
    assert "ghcr.io/sagernet/sing-box" in sidecar["image"]
    script = sidecar["command"][-1]
    assert "sing-box run -c" in script
    assert "/link-crypto-ss2022/client.json" in script
    assert "shadowsocks2022 run -c" not in script
    # the rendered SS-2022 launcher is valid shell
    syntax = subprocess.run(["sh", "-n"], input=script, check=False, capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr


def test_tracegate_chart_runtime_contract_follows_shadowsocks2022_inner_carrier(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(
        tmp_path,
        {"interconnect": {"entryTransit": {"innerCarrier": "shadowsocks2022"}}},
    )
    assert rendered.returncode == 0, rendered.stderr
    link_crypto = _rendered_runtime_contract(rendered.stdout)["linkCrypto"]
    assert link_crypto["carrier"] == "shadowsocks2022"
    dpi = link_crypto["dpiResistance"]
    assert dpi["mode"] == "shadowsocks2022-wss-spki-hmac"
    assert "shadowsocks2022-aead" in dpi["requiredLayers"]
    assert "scoped-zapret2" not in dpi["requiredLayers"]
    assert "zapret2" not in dpi
