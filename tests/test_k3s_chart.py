import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tracegate.services.runtime_contract import TRACEGATE21_CLIENT_PROFILES


CHART_ROOT = Path("deploy/k3s/tracegate")
K3S_PROD_EXAMPLE = Path("deploy/k3s/values-prod.example.yaml")
PRIVATE_PROFILE_BODY_CANARIES = (
    "client-private-secret",
    "server-private-secret",
    "preshared-secret",
    "ss-secret",
    "shadow-secret",
    "shadowtls-secret",
    "local-secret",
    "mtproto-secret-body",
    "MieruCredential",
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
    paths.append(K3S_PROD_EXAMPLE)
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


def _rendered_runtime_contract(rendered: str) -> dict:
    for doc in _helm_docs(rendered):
        if doc.get("kind") != "ConfigMap":
            continue
        data = doc.get("data")
        if not isinstance(data, dict):
            continue
        raw = data.get("tracegate-2.1-runtime.yaml")
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

    assert values["global"]["runtimeProfile"] == "tracegate-2.1"
    assert values["controlPlane"]["auth"]["existingSecretName"] == "tracegate-control-plane-auth"
    assert values["controlPlane"]["database"]["embedded"]["enabled"] is False
    assert values["controlPlane"]["database"]["externalUrlSecret"]["name"] == "tracegate-database-url"
    assert set(values["gateway"]["roles"]) == {"entry", "transit"}
    assert values["gateway"]["roles"]["entry"]["role"] == "ENTRY"
    assert values["gateway"]["roles"]["transit"]["role"] == "TRANSIT"
    assert values["gateway"]["roles"]["entry"]["nodeSelector"] == {"tracegate.io/role": "entry"}
    assert values["gateway"]["roles"]["transit"]["nodeSelector"] == {"tracegate.io/role": "transit"}
    assert values["gateway"]["strategy"] == "RollingUpdate"
    assert values["gateway"]["allowRecreateStrategy"] is False
    assert values["gateway"]["rollingUpdate"]["maxUnavailable"] == 0
    assert values["gateway"]["rollingUpdate"]["maxSurge"] == 1
    assert values["gateway"]["progressDeadlineSeconds"] == 600
    assert values["gateway"]["terminationGracePeriodSeconds"] == 60
    assert values["gateway"]["pdb"]["enabled"] is True
    assert values["gateway"]["pdb"]["minAvailable"] == 1
    assert values["gateway"]["probes"]["enabled"] is True
    assert values["gateway"]["privatePreflight"]["enabled"] is True
    assert values["gateway"]["privatePreflight"]["forbidPlaceholders"] is True
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
    assert "python3 -m ruff check ." in script
    assert "pytest -q" in script
    assert "helm lint" in script
    assert "helm template tracegate" in script
    assert "values-prod.example.yaml" in script
    assert "git diff --check" in script
    assert "python3 -m alembic heads" in script
    assert "TRACEGATE_STRICT_PROD" in script
    assert "TRACEGATE_CLUSTER_PREFLIGHT" in script
    assert "TRACEGATE_KUBE_SERVER_DRY_RUN" in script
    assert "prod-overlay-check.py --strict" in script
    assert "--expected-namespace" in script
    assert "cluster-preflight-check.py" in script
    assert "--namespace" in script
    assert "apply --dry-run=server" in script
    assert "tracegate-helm-default.yaml" in script
    assert "tracegate-helm-prod-example.yaml" in script
    assert "TRACEGATE_K3S_PROD_VALUES must point at an ignored private production values file" in deploy
    assert "refusing to deploy values-prod.example.yaml" in deploy
    assert "TRACEGATE_STRICT_PROD=1" in deploy
    assert "TRACEGATE_CLUSTER_PREFLIGHT=1" in deploy
    assert "TRACEGATE_KUBE_SERVER_DRY_RUN=1" in deploy
    assert 'export TRACEGATE_NAMESPACE="${NAMESPACE}"' in deploy
    assert "helm upgrade --install" in deploy
    assert "--atomic" in deploy
    assert "--wait" in deploy
    assert "TRACEGATE_POST_DEPLOY_CHECKS" in deploy
    assert "TRACEGATE_ROLLOUT_TIMEOUT" in deploy
    assert "rollout status deployment" in deploy
    assert "wait pod" in deploy
    assert "--for=condition=Ready" in deploy
    assert "get pdb" in deploy
    assert "--force" not in deploy
    assert "deploy-ready-check.sh" in readme
    assert "deploy-prod.sh" in readme
    assert "TRACEGATE_K3S_PROD_VALUES" in readme
    assert "TRACEGATE_STRICT_PROD=1" in readme
    assert "TRACEGATE_CLUSTER_PREFLIGHT=1" in readme
    assert "TRACEGATE_HELM_DRY_RUN=1" in readme
    assert "TRACEGATE_POST_DEPLOY_CHECKS=0" in readme
    assert "rendered chart namespace matches `TRACEGATE_NAMESPACE`" in readme


def test_k3s_strict_prod_overlay_check_accepts_private_overlay(tmp_path: Path) -> None:
    values_path = tmp_path / "values-prod.yaml"
    tracegate_digest = "sha256:" + ("a" * 64)
    values_path.write_text(
        yaml.safe_dump(
            {
                "global": {
                    "publicBaseUrl": "https://tracegate.prod.test",
                    "image": {"repository": "ghcr.io/acme/tracegate", "digest": tracegate_digest},
                },
                "controlPlane": {
                    "env": {
                        "defaultEntryHost": "entry.prod.test",
                        "defaultTransitHost": "transit.prod.test",
                        "mtprotoDomain": "mtproto.prod.test",
                    }
                },
                "decoy": {"hostPath": "/srv/tracegate/decoy"},
                "gateway": {
                    "images": {
                        name: {"tag": "pinned-test"}
                        for name in (
                            "haproxy",
                            "nginx",
                            "xray",
                            "mieru",
                            "zapret2",
                            "wstunnel",
                            "wireguard",
                            "shadowtls",
                            "shadowsocks",
                            "singbox",
                            "mtproto",
                        )
                    },
                    "roles": {
                        "entry": {"tls": {"serverName": "entry.prod.test"}},
                        "transit": {"tls": {"serverName": "transit.prod.test"}},
                    },
                },
                "interconnect": {
                    "entryTransit": {
                        "outerCarrier": {
                            "serverName": "bridge.prod.test",
                            "publicPath": "/cdn-cgi/tracegate-link",
                        }
                    }
                },
                "mtproto": {"domain": "mtproto.prod.test"},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

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


def _fake_kubectl(tmp_path: Path, *, omit_private_key: str = "") -> Path:
    script = tmp_path / "kubectl"
    private_keys = {
        "reality-entry-private-key",
        "reality-transit-private-key",
        "hysteria-entry-auth",
        "hysteria-transit-auth",
        "mieru-client-json",
        "mieru-server-json",
        "mtproto-secret-txt",
        "wireguard-wg-conf",
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

def emit(obj):
    print(json.dumps(obj))
    raise SystemExit(0)

if args[:2] == ["get", "namespace"] and args[2] == "tracegate":
    emit({{"metadata": {{"name": "tracegate"}}}})

if args[:2] == ["get", "nodes"]:
    selector = args[args.index("-l") + 1] if "-l" in args else ""
    if selector == "tracegate.io/role=entry":
        emit({{"items": [{{"metadata": {{"name": "entry-node"}}}}]}})
    if selector == "tracegate.io/role=transit":
        emit({{"items": [{{"metadata": {{"name": "transit-node"}}}}]}})
    emit({{"items": []}})

if args[:2] == ["get", "secret"]:
    name = args[2]
    secrets = {{
        "tracegate-control-plane-auth": {{"api-internal-token", "agent-auth-token"}},
        "tracegate-database-url": {{"url"}},
        "tracegate-entry-tls": {{"tls.crt", "tls.key"}},
        "tracegate-transit-tls": {{"tls.crt", "tls.key"}},
        "tracegate-private-profiles": {sorted(private_keys)!r},
    }}
    if name not in secrets:
        print("not found", file=sys.stderr)
        raise SystemExit(1)
    emit({{"data": {{key: "cmVkYWN0ZWQ=" for key in secrets[name]}}}})

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
            str(_fake_kubectl(tmp_path)),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "cluster-preflight: OK namespace=tracegate" in result.stdout
    assert "secrets=5" in result.stdout
    assert "nodes=2" in result.stdout


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
    assert values["privateProfiles"]["secretKeys"]["mieruClient"] == "mieru-client-json"
    assert values["privateProfiles"]["secretKeys"]["realityPrivateKeyEntry"] == "reality-entry-private-key"
    assert values["privateProfiles"]["secretKeys"]["shadowsocks2022Entry"] == "shadowsocks2022-entry-server-json"
    assert values["privateProfiles"]["secretKeys"]["shadowsocks2022Transit"] == "shadowsocks2022-transit-server-json"
    assert values["privateProfiles"]["secretKeys"]["shadowtlsEntry"] == "shadowtls-entry-config-yaml"
    assert values["privateProfiles"]["secretKeys"]["shadowtlsTransit"] == "shadowtls-transit-config-yaml"
    assert values["privateProfiles"]["keys"]["mieruClient"] == "mieru/client.json"
    assert values["privateProfiles"]["keys"]["realityPrivateKeyEntry"] == "reality/entry-private-key"
    assert values["privateProfiles"]["keys"]["shadowsocks2022Entry"] == "shadowsocks2022/entry-server.json"
    assert values["privateProfiles"]["keys"]["shadowsocks2022Transit"] == "shadowsocks2022/transit-server.json"
    assert values["privateProfiles"]["keys"]["shadowtlsEntry"] == "shadowtls/entry-config.yaml"
    assert values["privateProfiles"]["keys"]["shadowtlsTransit"] == "shadowtls/transit-config.yaml"
    assert values["privateProfiles"]["keys"]["zapretInterconnect"] == "zapret/entry-transit.env"
    assert "deploy/k3s/values-prod.yaml" in gitignore
    assert "deploy/k3s/link-profiles/" in gitignore
    assert "privateProfiles.required=false is forbidden" in _chart_text()
    assert "privateProfiles.inlineProfiles=true is forbidden" in _chart_text()
    assert "privateProfiles.defaultMode must be one of 0400, 0440, 0600 or 0640" in _chart_text()
    assert "controlPlane.auth.apiInternalToken is required" in _chart_text()
    assert "controlPlane.database requires externalUrl, externalUrlSecret.name, or embedded.enabled=true" in _chart_text()
    assert "gateway.hostNetwork=true with both Entry and Transit enabled requires non-empty per-role nodeSelector" in _chart_text()
    assert "gateway.hostNetwork=true with both Entry and Transit enabled requires distinct Entry and Transit nodeSelector" in _chart_text()
    assert "gateway.strategy must be RollingUpdate or Recreate" in _chart_text()
    assert "gateway.strategy=Recreate is forbidden by default" in _chart_text()
    assert "gateway.rollingUpdate.maxUnavailable must stay 0" in _chart_text()
    assert "gateway.rollingUpdate.maxSurge must be non-zero" in _chart_text()
    assert "gateway.progressDeadlineSeconds must be at least 300 seconds" in _chart_text()
    assert "gateway.pdb.enabled=false is forbidden" in _chart_text()
    assert "gateway.pdb.minAvailable must stay 1" in _chart_text()
    assert "gateway.probes.enabled=false is forbidden" in _chart_text()
    assert "gateway.privatePreflight.enabled=false is forbidden" in _chart_text()
    assert "gateway.privatePreflight.forbidPlaceholders=false is forbidden" in _chart_text()
    assert "at least one gateway role must be enabled in Tracegate 2.1" in _chart_text()
    assert "interconnect.entryTransit.enabled=true requires both Entry and Transit gateway roles" in _chart_text()
    assert "wireguard.enabled=true requires the Transit gateway role" in _chart_text()
    assert "mtproto.enabled=true requires the Transit gateway role" in _chart_text()
    assert "shadowsocks2022.enabled=true requires both Entry and Transit gateway roles" in _chart_text()
    assert "interconnect.entryTransit.routerEntry.enabled=true requires the Entry gateway role" in _chart_text()
    assert "interconnect.entryTransit.routerTransit.enabled=true requires the Transit gateway role" in _chart_text()
    assert "router link-crypto profiles require interconnect.mieru.enabled=true" in _chart_text()
    assert values["controlPlane"]["env"]["botWelcomeRequired"] is True
    assert values["controlPlane"]["env"]["botWelcomeVersion"] == "tracegate-2.1-client-safety-v1"
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
    assert env_by_name["BOT_WELCOME_VERSION"]["value"] == "tracegate-2.1-client-safety-v1"
    assert env_by_name["BOT_WELCOME_MESSAGE"]["valueFrom"]["secretKeyRef"] == {
        "name": "tracegate-bot-welcome",
        "key": "message",
    }
    assert env_by_name["BOT_GUIDE_MESSAGE"]["valueFrom"]["secretKeyRef"] == {
        "name": "tracegate-bot-guide",
        "key": "message",
    }
    assert "secretName: tracegate-private-profiles" in rendered.stdout
    assert "mieru/client.json" in rendered.stdout
    assert "zapret/entry-transit.env" in rendered.stdout


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
    assert "hostPath: /srv/tracegate/decoy" in prod_values
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
    assert entry_transit["primary"] == "mieru"
    assert entry_transit["fallback"] == "none"
    assert entry_transit["chainBridgeOwner"] == "link-crypto"
    assert entry_transit["xrayBackhaul"] is False
    assert entry_transit["outerCarrier"]["enabled"] is True
    assert entry_transit["outerCarrier"]["mode"] == "wss"
    assert entry_transit["outerCarrier"]["protocol"] == "websocket-tls"
    assert entry_transit["outerCarrier"]["serverName"] == "bridge.example.com"
    assert entry_transit["outerCarrier"]["publicPort"] == 443
    assert entry_transit["outerCarrier"]["publicPath"] == "/cdn-cgi/tracegate-link"
    assert entry_transit["outerCarrier"]["verifyTls"] is True
    assert entry_transit["scope"] == ["V2", "V4", "V6"]
    assert values["interconnect"]["mieru"]["localSocks"]["routerEntryPort"] == 10883
    assert values["interconnect"]["mieru"]["localSocks"]["routerTransitPort"] == 10884
    assert zapret2["enabled"] is False
    assert zapret2["nfqueue"] is False
    assert zapret2["hostWideInterception"] is False
    assert zapret2["scope"] == "scoped-egress"
    assert "entry-transit" in zapret2["applyTo"]
    assert zapret2_resources["requests"]["cpu"] == "10m"
    assert zapret2_resources["limits"]["cpu"] == "100m"
    assert zapret2_resources["limits"]["memory"] == "128Mi"
    assert "interconnect.zapret2.hostWideInterception=true is forbidden" in _chart_text()
    assert "interconnect.zapret2.nfqueue=true is forbidden" in _chart_text()
    assert "interconnect.entryTransit.xrayBackhaul=true is forbidden" in _chart_text()
    assert "interconnect.entryTransit.chainBridgeOwner must stay link-crypto" in _chart_text()
    assert "interconnect.entryTransit.primary must stay mieru" in _chart_text()
    assert "interconnect.entryTransit.fallback must stay none" in _chart_text()
    assert "interconnect.mieru.enabled=false is forbidden while entryTransit is enabled" in _chart_text()
    assert "interconnect.entryTransit.remotePort must stay 443" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.enabled=false is forbidden" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.mode must stay wss" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.serverName must be separate" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.publicPath must be a clean absolute HTTP path" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.publicPath must be separate from wireguard.wstunnel.publicPath" in _chart_text()
    assert "interconnect.entryTransit.outerCarrier.verifyTls=false is forbidden" in _chart_text()
    assert "containerResources.zapret2" in Path("deploy/k3s/README.md").read_text(encoding="utf-8")
    assert "fallback: none" in Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")
    assert "chainBridgeOwner: link-crypto" in Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")
    assert "xrayBackhaul: false" in Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")
    assert "outerCarrier:" in Path("deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8")


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
    assert rendered.stdout.count('start_zapret_profile "/etc/tracegate/private/zapret/entry-transit.env"') == 2
    assert rendered.stdout.count('start_zapret_profile "/etc/tracegate/private/zapret/mtproto-extra.env"') == 1
    assert 'start_zapret_profile "/etc/tracegate/private/zapret/mtproto-extra.env"' not in without_mtproto.stdout
    assert 'start_zapret_profile "/etc/tracegate/private/zapret/entry-transit.env"' not in without_bridge.stdout
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
    assert "packetShaping: zapret2-scoped" in configmaps
    assert "rollout:" in configmaps
    assert "gatewayStrategy: {{ .Values.gateway.strategy }}" in configmaps
    assert "allowRecreateStrategy: {{ .Values.gateway.allowRecreateStrategy }}" in configmaps
    assert "maxUnavailable: {{ .Values.gateway.rollingUpdate.maxUnavailable | quote }}" in configmaps
    assert "pdbMinAvailable: {{ .Values.gateway.pdb.minAvailable | quote }}" in configmaps
    assert "privatePreflightForbidPlaceholders: {{ .Values.gateway.privatePreflight.forbidPlaceholders }}" in configmaps
    assert "Keep Entry-to-Transit chaining outside Xray" in readme


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
        "serverName": "bridge.example.com",
        "publicPort": 443,
        "publicPath": "/cdn-cgi/tracegate-link",
        "url": "wss://bridge.example.com:443/cdn-cgi/tracegate-link",
        "verifyTls": True,
        "secretMaterial": False,
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
        "entry-transit": ["V2", "V4", "V6"],
        "router-entry": ["V2", "V4", "V6"],
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
        "entry-transit": ["V2", "V4", "V6"],
        "router-transit": ["V1", "V3", "V5", "V7"],
    }
    assert link_crypto["zapret2"]["hostWideInterception"] is False
    assert link_crypto["zapret2"]["nfqueue"] is False


def test_tracegate21_chart_omits_mieru_sidecar_when_entry_transit_bridge_is_disabled(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {"interconnect": {"entryTransit": {"enabled": False}}})

    assert rendered.returncode == 0, rendered.stderr
    assert "name: mieru\n" not in rendered.stdout
    assert "mieru run -c" not in rendered.stdout
    assert "mieru/client.json" not in rendered.stdout
    assert "mieru/server.json" not in rendered.stdout


def test_tracegate21_chart_runs_mieru_server_profile_for_router_only_link_crypto(tmp_path: Path) -> None:
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
    assert "mieru" in entry_containers
    assert "mieru" not in transit_containers
    entry_script = entry_containers["mieru"]["command"][-1]
    entry_syntax = subprocess.run(["sh", "-n"], input=entry_script, check=False, capture_output=True, text=True)
    assert entry_syntax.returncode == 0, entry_syntax.stderr
    assert 'start_mieru_profile "/etc/tracegate/private/mieru/server.json"' in entry_script
    assert 'start_mieru_profile "/etc/tracegate/private/mieru/client.json"' not in entry_script
    assert _env_value(entry_containers["agent"], "PRIVATE_LINK_CRYPTO_ENABLED") == "false"
    assert _env_value(entry_containers["agent"], "PRIVATE_LINK_CRYPTO_ROUTER_ENTRY_ENABLED") == "true"
    assert _env_value(entry_containers["agent"], "PRIVATE_LINK_CRYPTO_ROUTER_ENTRY_PORT") == "10883"

    transit_templates = _gateway_deployment_templates(transit_router.stdout)
    transit_only_containers = _containers_by_name(transit_templates["gateway-transit"])
    entry_only_containers = _containers_by_name(transit_templates["gateway-entry"])
    assert "mieru" in transit_only_containers
    assert "mieru" not in entry_only_containers
    transit_script = transit_only_containers["mieru"]["command"][-1]
    transit_syntax = subprocess.run(["sh", "-n"], input=transit_script, check=False, capture_output=True, text=True)
    assert transit_syntax.returncode == 0, transit_syntax.stderr
    assert 'start_mieru_profile "/etc/tracegate/private/mieru/server.json"' in transit_script
    assert 'start_mieru_profile "/etc/tracegate/private/mieru/client.json"' not in transit_script
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
    assert "name: mieru\n" not in rendered.stdout
    assert "mieru/client.json" not in rendered.stdout
    assert "mieru/server.json" not in rendered.stdout


def test_tracegate21_chart_declares_required_client_profiles_and_socks_auth() -> None:
    values = _values()
    profiles = set(values["transportProfiles"]["clientNames"])

    assert values["transportProfiles"]["socks5"]["required"] is True
    assert values["transportProfiles"]["socks5"]["allowAnonymousLocalhost"] is False
    assert tuple(values["transportProfiles"]["clientNames"]) == TRACEGATE21_CLIENT_PROFILES
    assert "V1-VLESS-Reality-Direct" in profiles
    assert "V1-VLESS-gRPC-TLS-Direct" in profiles
    assert "V5-Shadowsocks2022-ShadowTLS-Direct" in profiles
    assert "V6-Shadowsocks2022-ShadowTLS-Chain" in profiles
    assert "V7-WireGuard-WSTunnel-Direct" in profiles
    assert "MTProto-FakeTLS-Direct" in profiles
    assert "MTProto-TCP443-Direct" not in profiles
    assert "V8-Mieru-TCP-Direct" not in profiles
    assert "V9-TUICv5-QUIC-Direct" not in profiles
    assert "transportProfiles.socks5.required=false is forbidden" in _chart_text()
    assert "transportProfiles.socks5.allowAnonymousLocalhost=true is forbidden" in _chart_text()
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
    assert experimental["directTransitObfuscation"]["mieru"]["enabled"] is False
    assert experimental["directTransitObfuscation"]["restls"]["enabled"] is False
    assert experimental["tuicV5"]["enabled"] is False
    assert experimental["tuicV5"]["directEnabled"] is False
    assert experimental["tuicV5"]["chainEnabled"] is False
    assert experimental["tuicV5"]["productionReplacementAllowed"] is False
    assert "V8-Mieru-TCP-Direct" in experimental["directTransitObfuscation"]["variants"]
    assert "V8-Mieru-RESTLS-Direct" in experimental["directTransitObfuscation"]["variants"]
    assert "V9-TUICv5-QUIC-Direct" in experimental["tuicV5"]["variants"]
    assert "V9-TUICv5-QUIC-Chain" in experimental["tuicV5"]["variants"]
    assert values["privateProfiles"]["keys"]["labMieruDirect"] == "lab/mieru-direct-server.json"
    assert values["privateProfiles"]["keys"]["labRestlsDirect"] == "lab/restls-direct.yaml"
    assert values["privateProfiles"]["keys"]["labTuicEntry"] == "lab/tuic-entry.json"
    assert values["privateProfiles"]["keys"]["labTuicTransit"] == "lab/tuic-transit.json"
    assert values["gateway"]["images"]["singbox"]["repository"] == "ghcr.io/sagernet/sing-box"
    assert values["gateway"]["images"]["wireguard"]["repository"] == "lscr.io/linuxserver/wireguard"
    assert "experimentalProfiles:" in text
    assert "mieru-direct-lab" in gateways
    assert "restls-direct-lab" in gateways
    assert "tuic-v5-lab" in gateways
    assert "sing-box run -c" in gateways
    assert "labMieruDirect" in gateways
    assert "labRestlsDirect" in gateways
    assert "keys.labRestlsDirect" in gateways
    assert "labTuicEntry" in gateways
    assert "labTuicTransit" in gateways
    assert "experimentalProfiles.enabled=false cannot enable V8/V9 lab surfaces" in secrets
    assert "experimentalProfiles.directTransitObfuscation.enabled=false cannot enable V8 Mieru/RESTLS layers" in secrets
    assert "experimentalProfiles.directTransitObfuscation.enabled=true requires mieru.enabled or restls.enabled" in secrets
    assert "experimentalProfiles.tuicV5.enabled=false cannot enable TUIC v5 lab routes" in secrets
    assert "experimentalProfiles.tuicV5.enabled=true requires directEnabled or chainEnabled" in secrets
    assert "productionReplacementAllowed=true is forbidden" in secrets
    assert "V8-Mieru-TCP-Direct" in readme
    assert "V9-TUICv5-QUIC-Direct" in readme


def test_tracegate21_chart_guards_v5_v6_v7_transport_shape() -> None:
    values = _values()
    text = _chart_text()

    assert values["shadowsocks2022"]["variants"]["direct"] == "V5"
    assert values["shadowsocks2022"]["variants"]["chain"] == "V6"
    assert values["shadowsocks2022"]["shadowtls"]["enabled"] is True
    assert values["shadowsocks2022"]["shadowtls"]["version"] == 3
    assert values["wireguard"]["variant"] == "V7"
    assert values["wireguard"]["wstunnel"]["enabled"] is True
    assert values["wireguard"]["wstunnel"]["mode"] == "wireguard-over-websocket"
    assert values["wireguard"]["wstunnel"]["publicPath"].startswith("/")
    assert "shadowsocks2022.variants.direct must stay V5" in text
    assert "shadowsocks2022.variants.chain must stay V6" in text
    assert "shadowsocks2022.shadowtls.enabled=false is forbidden" in text
    assert "shadowsocks2022.shadowtls.version must stay 3" in text
    assert "wireguard.variant must stay V7" in text
    assert "wireguard.wstunnel.enabled=false is forbidden" in text
    assert "wireguard.wstunnel.mode must stay wireguard-over-websocket" in text
    assert "wireguard.wstunnel.publicPath must be an absolute HTTP path" in text
    assert "wireguard.wstunnel.publicPath must be a clean absolute HTTP path" in text


def test_tracegate21_wireguard_sidecar_uses_portable_lifecycle_script(tmp_path: Path) -> None:
    rendered = _helm_template_with_values(tmp_path, {"wireguard": {"enabled": True}})

    assert rendered.returncode == 0, rendered.stderr
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
            "gateway.hostNetwork=true with both Entry and Transit enabled requires non-empty per-role nodeSelector",
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
            "gateway.hostNetwork=true with both Entry and Transit enabled requires distinct Entry and Transit nodeSelector",
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
            "interconnect.entryTransit.enabled=true requires both Entry and Transit gateway roles",
        ),
        (
            {
                "gateway": {"roles": {"entry": {"enabled": False}, "transit": {"enabled": False}}},
                "interconnect": {"entryTransit": {"enabled": False}},
                "mtproto": {"enabled": False},
            },
            "at least one gateway role must be enabled in Tracegate 2.1",
        ),
        (
            {
                "gateway": {"roles": {"transit": {"enabled": False}}},
                "interconnect": {"entryTransit": {"enabled": False}},
                "wireguard": {"enabled": True},
                "mtproto": {"enabled": False},
            },
            "wireguard.enabled=true requires the Transit gateway role",
        ),
        (
            {
                "gateway": {"roles": {"transit": {"enabled": False}}},
                "interconnect": {"entryTransit": {"enabled": False}},
                "mtproto": {"enabled": True},
            },
            "mtproto.enabled=true requires the Transit gateway role",
        ),
        (
            {"interconnect": {"entryTransit": {"enabled": False}}, "shadowsocks2022": {"enabled": True}},
            "shadowsocks2022.enabled=true requires both Entry and Transit gateway roles",
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
            "interconnect.entryTransit.routerTransit.enabled=true requires the Transit gateway role",
        ),
        (
            {"interconnect": {"entryTransit": {"enabled": False, "routerTransit": {"enabled": True}}, "mieru": {"enabled": False}}},
            "router link-crypto profiles require interconnect.mieru.enabled=true",
        ),
        (
            {"experimentalProfiles": {"directTransitObfuscation": {"mieru": {"enabled": True}}}},
            "experimentalProfiles.enabled=false cannot enable V8/V9 lab surfaces",
        ),
        (
            {
                "experimentalProfiles": {
                    "enabled": True,
                    "directTransitObfuscation": {"enabled": False, "mieru": {"enabled": True}},
                }
            },
            "experimentalProfiles.directTransitObfuscation.enabled=false cannot enable V8 Mieru/RESTLS layers",
        ),
        (
            {"experimentalProfiles": {"enabled": True, "directTransitObfuscation": {"enabled": True}}},
            "experimentalProfiles.directTransitObfuscation.enabled=true requires mieru.enabled or restls.enabled",
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
            {"transportProfiles": {"clientNames": ["V1-VLESS-Reality-Direct", "MTProto-TCP443-Direct"]}},
            "transportProfiles.clientNames must include V1-VLESS-gRPC-TLS-Direct",
        ),
        (
            {
                "transportProfiles": {
                    "clientNames": [
                        "V1-VLESS-Reality-Direct",
                        "V1-VLESS-gRPC-TLS-Direct",
                        "V1-VLESS-WS-TLS-Direct",
                        "V2-VLESS-Reality-Chain",
                        "V3-Hysteria2-QUIC-Direct",
                        "V4-Hysteria2-QUIC-Chain",
                        "V5-Shadowsocks2022-ShadowTLS-Direct",
                        "V6-Shadowsocks2022-ShadowTLS-Chain",
                        "V7-WireGuard-WSTunnel-Direct",
                    ]
                }
            },
            "transportProfiles.clientNames must include MTProto-FakeTLS-Direct",
        ),
        (
            {
                "transportProfiles": {
                    "clientNames": [
                        *TRACEGATE21_CLIENT_PROFILES,
                        "V8-Mieru-TCP-Direct",
                    ]
                }
            },
            "transportProfiles.clientNames must not include lab-only profile V8-Mieru-TCP-Direct",
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
    assert "type: {{ $.Values.gateway.strategy }}" in gateways
    assert "maxUnavailable: {{ $.Values.gateway.rollingUpdate.maxUnavailable | quote }}" in gateways
    assert "maxSurge: {{ $.Values.gateway.rollingUpdate.maxSurge | quote }}" in gateways
    assert "progressDeadlineSeconds: {{ int $.Values.gateway.progressDeadlineSeconds }}" in gateways
    assert "checksum/users" not in gateways
    assert "checksum/secrets" not in gateways
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
    assert "DEFAULT_ENTRY_HOST" in gateways
    assert "DEFAULT_TRANSIT_HOST" in gateways
    assert "gateway.containerResources.agent" in gateways
    assert "gateway.containerResources.zapret2" in gateways
    assert "gateway.containerResources.wireguard" in gateways
    assert "gateway.containerResources.singbox" in gateways
    assert 'value: "/var/lib/tracegate/private"' in gateways
    assert "PRIVATE_ZAPRET_PROFILE_DIR" in gateways
    assert "PRIVATE_ZAPRET_PROFILE_ENTRY" in gateways
    assert "PRIVATE_ZAPRET_PROFILE_TRANSIT" in gateways
    assert "PRIVATE_MIERU_PROFILE_DIR" in gateways
    assert "PRIVATE_SHADOWTLS_PROFILE_DIR" in gateways
    assert "PRIVATE_SHADOWTLS_PROFILE_ENTRY" in gateways
    assert "PRIVATE_SHADOWTLS_PROFILE_TRANSIT" in gateways
    assert "PRIVATE_LINK_CRYPTO_ENABLED" in gateways
    assert "$roleLinkCryptoClientEnabled" in gateways
    assert "$roleLinkCryptoServerEnabled" in gateways
    assert "$roleLinkCryptoEnabled" in gateways
    assert "shutdown_mieru_profiles()" in gateways
    assert "start_mieru_profile" in gateways
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


def test_tracegate21_gateway_probes_are_local_only() -> None:
    gateways = (CHART_ROOT / "templates" / "gateways.yaml").read_text(encoding="utf-8")

    assert "startupProbe:" in gateways
    assert "readinessProbe:" in gateways
    assert "livenessProbe:" in gateways
    assert "path: /v1/live" in gateways
    assert "path: /v1/health" in gateways
    assert "port: agent" in gateways
    assert "tcpSocket:" in gateways
    assert "port: https" in gateways
    assert "test -s /usr/local/etc/haproxy/haproxy.cfg" in gateways
    assert "test -s /etc/nginx/nginx.conf" in gateways
    assert "test -s /etc/xray/config.json" in gateways
    assert "http://example" not in gateways
    assert "curl " not in gateways
    assert "wget " not in gateways


def test_tracegate21_templates_include_grpc_mtproto_and_mieru_surfaces() -> None:
    text = _chart_text()

    assert "vless-grpc-in" in text
    assert "grpc_pass grpc://127.0.0.1" in text
    assert "be_mtproto" in text
    assert "mieru run -c" in text
    assert "wstunnel server" in text
    assert "wstunnel-link-crypto" in text
    assert "wstunnel client -L" in text


def test_tracegate21_gateway_projects_private_profile_secret_paths() -> None:
    gateways = (CHART_ROOT / "templates" / "gateways.yaml").read_text(encoding="utf-8")
    configmaps = (CHART_ROOT / "templates" / "configmaps.yaml").read_text(encoding="utf-8")

    assert "items:" in gateways
    assert "secretKeys.mieruClient" in gateways
    assert "secretKeys.mieruServer" in gateways
    assert "path: {{ $.Values.privateProfiles.keys.mieruClient }}" in gateways
    assert "path: {{ $.Values.privateProfiles.keys.mieruServer }}" in gateways
    assert "--required-file" in gateways
    assert "--zapret-file" in gateways
    assert "keys.realityPrivateKeyEntry" in gateways
    assert "keys.realityPrivateKeyTransit" in gateways
    assert "keys.hysteriaAuthEntry" in gateways
    assert "keys.hysteriaAuthTransit" in gateways
    assert "keys.shadowsocks2022Entry" in gateways
    assert "keys.shadowsocks2022Transit" in gateways
    assert "secretKeys.shadowsocks2022Entry" in gateways
    assert "secretKeys.shadowsocks2022Transit" in gateways
    assert "keys.shadowtlsEntry" in gateways
    assert "keys.shadowtlsTransit" in gateways
    assert '(eq $roleName "transit") $.Values.shadowsocks2022.enabled' not in gateways
    assert "{{- if $.Values.shadowsocks2022.enabled }}" in gateways
    assert "ssserver -c {{ $.Values.privateProfiles.mountPath }}/{{ $roleShadowsocks2022Key }}" in gateways
    assert "shadow-tls --config {{ $.Values.privateProfiles.mountPath }}/{{ $roleShadowtlsKey }}" in gateways
    assert "keys.zapretInterconnect" in gateways
    assert 'start_zapret_profile "{{ $.Values.privateProfiles.mountPath }}/{{ $zapretProfileKey }}"' in gateways
    assert (
        'start_zapret_profile "{{ $.Values.privateProfiles.mountPath }}/{{ $.Values.privateProfiles.keys.zapretInterconnect }}"'
        in gateways
    )
    assert (
        'start_zapret_profile "{{ $.Values.privateProfiles.mountPath }}/{{ $.Values.privateProfiles.keys.zapretMtproto }}"'
        in gateways
    )
    assert '(eq $roleName "transit") $.Values.wireguard.enabled' in gateways
    assert '(eq $roleName "transit") $.Values.mtproto.enabled' in gateways
    assert "name: wireguard" in gateways
    assert "wg-quick up {{ $.Values.privateProfiles.mountPath }}/{{ $.Values.privateProfiles.keys.wireguard }}" in gateways
    assert "wstunnel-wireguard" in gateways
    assert "wstunnel-link-crypto" in gateways
    assert 'exec wstunnel client -L "tcp://127.0.0.1:{{ int $linkOuterCarrier.clientLocalPort }}:127.0.0.1:{{ int $.Values.interconnect.mieru.localSocks.transitPort }}"' in gateways
    assert 'exec wstunnel server "ws://127.0.0.1:{{ int $linkOuterCarrier.serverLocalPort }}"' in gateways
    assert '(eq $roleName "transit") $.Values.wireguard.enabled $.Values.wireguard.wstunnel.enabled' in gateways
    assert "location {{ $.Values.wireguard.wstunnel.publicPath }}" in configmaps
    assert "proxy_pass http://127.0.0.1:{{ int $.Values.wireguard.wstunnel.websocketPort }}" in configmaps
    assert "location {{ $linkOuterCarrier.publicPath }}" in configmaps
    assert "proxy_pass http://127.0.0.1:{{ int $linkOuterCarrier.serverLocalPort }}" in configmaps
    assert "bridge_wss_sni" in configmaps
    assert "until {{ $roleLinkCryptoReadyTest }}; do sleep 2; done" in gateways
    assert "start_mieru_profile" in gateways
    assert "until {{ $roleProfileReadyTest }}; do sleep 2; done; ssserver -c" in gateways
    assert "until {{ $roleProfileReadyTest }}; do sleep 2; done; shadow-tls --config" in gateways
    assert "until {{ $roleProfileReadyTest }}; do sleep 2; done; wstunnel server" in gateways
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
    assert "HYSTERIA_AUTH" in gateways
    assert "escape_sed_replacement()" in gateways
    assert "replace_literal REPLACE_REALITY_PRIVATE_KEY" in gateways
    assert "replace_literal REPLACE_HYSTERIA_AUTH" in gateways
    assert "REPLACE_REALITY_PRIVATE_KEY" in configmaps
    assert "REPLACE_HYSTERIA_AUTH" in configmaps
    assert "REPLACE_FROM_PRIVATE_SECRET" not in configmaps
