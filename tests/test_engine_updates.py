from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
from types import SimpleNamespace

import pytest

from tracegate.cli import engine_update as cli
from tracegate.services import engine_updates as eu
from tracegate.services.artifacts import ArtifactError, ArtifactStore, RegistryError, format_env, load_registry
from tracegate.services.engine_registry import (
    HttpResponse,
    RegistryClient,
    TagDigest,
    UpstreamError,
    select_semver,
    split_image,
)
from tracegate.services.engine_updates import (
    ROLE_ENGINE_UNITS,
    CheckResult,
    EngineUpdateSupervisor,
    Evidence,
    ProbePlan,
    UpdateError,
    metrics_snapshot,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

D_OLD = "sha256:" + "0" * 64
D_NEW = "sha256:" + "1" * 64
D_NEWER = "sha256:" + "2" * 64
D_LAST_GOOD = "sha256:" + "9" * 64

XRAY = "ghcr.io/example/xray"
SHADOWTLS = "ghcr.io/example/shadow-tls"
HYSTERIA = "docker.io/example/hysteria"
TELEMT = "ghcr.io/example/telemt"

REGISTRY = {
    "schema_version": 1,
    "components": {
        "xray": {
            "image": XRAY,
            "channel": "latest",
            "units": ["tracegate-xray@.service", "tracegate-xray-ss2022.service"],
            "container_prefixes": ["tracegate-xray-"],
            "update": {"track": "channel"},
            "policy": {"endpoint": "auto", "entry": "notify"},
        },
        "telemt": {
            "image": TELEMT,
            "channel": "latest",
            "units": ["tracegate-mtproto@.service"],
            "container_prefixes": ["tracegate-mtproto-"],
            "update": {"track": "channel"},
            "policy": {"endpoint": "notify", "entry": "notify"},
        },
        "shadowtls": {
            "image": SHADOWTLS,
            "channel": "latest",
            "units": [
                "tracegate-shadowtls-backhaul.service",
                "tracegate-shadowtls-backhaul2.service",
                "tracegate-shadowtls-entry.service",
                "tracegate-shadowtls-entry2.service",
            ],
            "container_prefixes": ["tracegate-shadowtls"],
            "update": {"track": "channel"},
            "policy": {"endpoint": "auto", "entry": "auto"},
        },
        "hysteria": {
            "image": HYSTERIA,
            "channel": "v2.13.0",
            "units": ["tracegate-hysteria@.service", "tracegate-hysteria-salamander.service"],
            "container_prefixes": ["tracegate-hysteria-"],
            "update": {"track": "semver", "allow": "v2.*"},
            "policy": {"endpoint": "auto", "entry": "notify"},
        },
    },
}


def _completed(argv: list[str], code: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=stderr)


class FakeHost:
    """Scripted docker + systemctl; no daemon, no network."""

    def __init__(self) -> None:
        self.images: dict[str, list[str]] = {}
        self.pullable: dict[str, str] = {}
        self.inactive: set[str] = set()
        self.restart_fail: set[str] = set()
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if argv[:2] == ["systemctl", "restart"]:
            return _completed(argv, 1 if argv[2] in self.restart_fail else 0, stderr="failed")
        if argv[:2] == ["systemctl", "is-active"]:
            return _completed(argv, 3 if argv[-1] in self.inactive else 0)
        args = argv[1:]
        if args[:1] == ["pull"]:
            ref = args[1]
            if ref not in self.pullable:
                return _completed(argv, 1, stderr="manifest unknown")
            self.images[ref] = [self.pullable[ref]]
            return _completed(argv, 0)
        if args[:2] == ["image", "inspect"]:
            ref = args[-1]
            if ref not in self.images:
                return _completed(argv, 1, stderr="no such image")
            if "--format" in args:
                return _completed(argv, 0, stdout=json.dumps(self.images[ref]) + "\n")
            return _completed(argv, 0, stdout="[{}]")
        return _completed(argv, 1, stderr=f"unexpected {argv}")

    def restarts(self) -> list[str]:
        return [call[2] for call in self.calls if call[:2] == ["systemctl", "restart"]]

    def pulls(self) -> list[str]:
        return [call[2] for call in self.calls if call[:2] == ["docker", "pull"]]


class FakeClient:
    def __init__(self) -> None:
        self.digests: dict[tuple[str, str], str] = {}
        self.tag_lists: dict[str, list[str]] = {}
        self.fail: set[str] = set()

    def tags(self, image: str) -> list[str]:
        if image in self.fail:
            raise UpstreamError("registry unreachable")
        return self.tag_lists.get(image, [])

    def resolve(self, image: str, tag: str, *, known_digest: str | None = None) -> TagDigest:
        if image in self.fail:
            raise UpstreamError("registry unreachable")
        return TagDigest(tag=tag, digest=self.digests[(image, tag)], media_type="index", platform_digest=None)


class FakeProber:
    def __init__(self) -> None:
        self.incomplete: dict[str, str] = {}
        self.check_status: dict[str, str] = {}
        # Static-check result for the currently active (D_OLD) image.
        self.active_check_status: dict[str, str] = {}
        self.fail_when = lambda context: False
        self.contexts: list[eu.ProbeContext] = []

    def plan(self, component: str) -> ProbePlan:
        reason = self.incomplete.get(component)
        return ProbePlan(reason is None, ("fake",), reason or "")

    def static_check(self, component: str, reference: str, units: tuple[str, ...]) -> CheckResult:
        if reference.endswith(D_OLD):
            status = self.active_check_status.get(component, "ok")
        else:
            status = self.check_status.get(component, "ok")
        return CheckResult(status, (Evidence("static", status == "ok", f"{status} for {reference}"),))

    def probe(self, context: eu.ProbeContext) -> list[Evidence]:
        self.contexts.append(context)
        ok = not self.fail_when(context)
        return [Evidence("fake-probe", ok, context.phase)]


class Clock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.t = start

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds

    def days(self, value: float) -> None:
        self.t += value * 86400


@pytest.fixture()
def env(tmp_path: Path):
    registry_path = tmp_path / "artifacts.json"
    registry_path.write_text(json.dumps(REGISTRY), encoding="utf-8")
    host = FakeHost()
    store = ArtifactStore(tmp_path / "store", load_registry(registry_path), runner=host)
    for name, spec in REGISTRY["components"].items():
        ref = f"{spec['image']}@{D_OLD}"
        (tmp_path / "store" / "active").mkdir(parents=True, exist_ok=True)
        (tmp_path / "store" / "active" / f"{name}.env").write_text(format_env(ref), encoding="utf-8")
        host.images[ref] = [ref]
        last_good = f"{spec['image']}@{D_LAST_GOOD}"
        (tmp_path / "store" / "last-good").mkdir(parents=True, exist_ok=True)
        (tmp_path / "store" / "last-good" / f"{name}.env").write_text(format_env(last_good), encoding="utf-8")
        host.images[last_good] = [last_good]
        for digest in (D_NEW, D_NEWER):
            host.pullable[f"{spec['image']}@{digest}"] = f"{spec['image']}@{digest}"
    client = FakeClient()
    for name, spec in REGISTRY["components"].items():
        client.digests[(spec["image"], "latest")] = D_OLD
        client.tag_lists[spec["image"]] = ["v2.13.0", "v2.14.0"]
        client.digests[(spec["image"], "v2.14.0")] = D_OLD
    prober = FakeProber()
    clock = Clock()

    def make(role: str = "endpoint", soak_days: float = 3) -> EngineUpdateSupervisor:
        return EngineUpdateSupervisor(
            store=store,
            role=role,
            client=client,  # type: ignore[arg-type]
            prober=prober,
            runner=host,
            soak_days=soak_days,
            now=clock.now,
            sleep=clock.sleep,
            settle_seconds=5,
            unit_active_timeout=30,
        )

    return SimpleNamespace(store=store, host=host, client=client, prober=prober, clock=clock, make=make, root=tmp_path / "store")


def _candidate(env, component: str, digest: str) -> dict:
    state = json.loads((env.root / "updates.json").read_text(encoding="utf-8"))
    return state["components"][component]["candidates"][digest]


def _actions(env) -> list[tuple[str, str]]:
    return [(entry["action"], entry["component"]) for entry in env.store.journal_entries()]


# -- registry file -----------------------------------------------------------------


def test_tracked_registry_declares_update_tracks_and_policies() -> None:
    registry = load_registry(REPO_ROOT / "deploy/host/artifacts.json")
    table = {
        name: (component.update.track, component.update.allow, component.policy_for("endpoint"), component.policy_for("entry"))
        for name, component in registry.components.items()
    }
    assert table == {
        "xray": ("channel", None, "auto", "notify"),
        "telemt": ("channel", None, "notify", "notify"),
        "shadowtls": ("channel", None, "auto", "auto"),
        "hysteria": ("semver", "v2.*", "auto", "notify"),
        "prometheus": ("semver", "v3.*", "auto", "notify"),
        "grafana": ("semver", "13.*", "auto", "notify"),
    }


@pytest.mark.parametrize(
    "update,policy",
    (
        ({"track": "nightly"}, None),
        ({"track": "semver"}, None),
        ({"track": "semver", "allow": "v2.1.*"}, None),
        ({"track": "semver", "allow": "*"}, None),
        ({"track": "channel", "allow": "v2.*"}, None),
        (None, {"endpoint": "always"}),
        (None, {"edge": "auto"}),
    ),
)
def test_registry_rejects_bad_update_or_policy_blocks(tmp_path: Path, update, policy) -> None:
    spec = {k: v for k, v in REGISTRY["components"]["xray"].items() if k not in {"update", "policy"}}
    if update is not None:
        spec["update"] = update
    if policy is not None:
        spec["policy"] = policy
    path = tmp_path / "artifacts.json"
    path.write_text(json.dumps({"schema_version": 1, "components": {"xray": spec}}), encoding="utf-8")
    with pytest.raises(RegistryError):
        load_registry(path)


def test_role_engine_units_match_host_deploy_role_units() -> None:
    script = (REPO_ROOT / "deploy/host/tracegate-host-deploy").read_text(encoding="utf-8")
    registry = load_registry(REPO_ROOT / "deploy/host/artifacts.json")
    for role in ("endpoint", "entry"):
        block = re.search(rf"(?ms)^\s+{role}\)\n.*?ROLE_UNITS=\((.*?)\)", script)
        assert block is not None
        units = block.group(1).split()
        engine_units: dict[str, list[str]] = {}
        for unit in units:
            component = registry.component_for_unit(unit)
            if component is not None:
                engine_units.setdefault(component.name, []).append(unit)
        expected = {name: sorted(values) for name, values in engine_units.items()}
        assert {name: sorted(values) for name, values in ROLE_ENGINE_UNITS[role].items()} == expected


# -- upstream registry client -----------------------------------------------------------------


def test_split_image_handles_ghcr_docker_hub_and_official_images() -> None:
    assert split_image("ghcr.io/xtls/xray-core") == ("ghcr.io", "xtls/xray-core")
    assert split_image("docker.io/tobyxdd/hysteria") == ("registry-1.docker.io", "tobyxdd/hysteria")
    assert split_image("prom/prometheus") == ("registry-1.docker.io", "prom/prometheus")
    assert split_image("alpine") == ("registry-1.docker.io", "library/alpine")


def _index(*platforms: tuple[str, str]) -> bytes:
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": "sha256:" + str(i) * 64, "platform": {"os": os_, "architecture": arch}}
                for i, (os_, arch) in enumerate(platforms, start=3)
            ],
        }
    ).encode()


class FakeTransport:
    def __init__(self, routes: dict[tuple[str, str], HttpResponse], *, realm: str) -> None:
        self.routes = routes
        self.realm = realm
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    def __call__(self, method: str, url: str, headers: dict[str, str]) -> HttpResponse:
        self.calls.append((method, url, dict(headers)))
        if url.startswith(self.realm):
            return HttpResponse(200, {}, json.dumps({"token": "anon-token"}).encode())
        if headers.get("Authorization") != "Bearer anon-token":
            return HttpResponse(
                401,
                {"www-authenticate": f'Bearer realm="{self.realm}",service="registry.example",scope="repository:x:pull"'},
                b"",
            )
        key = (method, url.split("?", 1)[0] if "tags/list" not in url else url)
        return self.routes.get(key, HttpResponse(404, {}, b""))


@pytest.mark.parametrize(
    "image,base,realm",
    (
        ("ghcr.io/example/xray", "https://ghcr.io/v2/example/xray", "https://ghcr.io/token"),
        ("docker.io/example/hysteria", "https://registry-1.docker.io/v2/example/hysteria", "https://auth.docker.io/token"),
    ),
)
def test_resolve_uses_token_flow_and_records_index_digest_for_amd64(image: str, base: str, realm: str) -> None:
    body = _index(("linux", "arm64"), ("linux", "amd64"))
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    headers = {"docker-content-digest": digest, "content-type": "application/vnd.oci.image.index.v1+json"}
    transport = FakeTransport(
        {
            ("HEAD", f"{base}/manifests/latest"): HttpResponse(200, headers, b""),
            ("GET", f"{base}/manifests/latest"): HttpResponse(200, headers, body),
        },
        realm=realm,
    )
    resolved = RegistryClient(transport).resolve(image, "latest")
    assert resolved.digest == digest
    assert resolved.platform_digest == "sha256:" + "4" * 64
    token_calls = [call for call in transport.calls if call[1].startswith(realm)]
    assert len(token_calls) == 1  # token cached per repository
    assert "scope=repository" in token_calls[0][1] and "service=registry.example" in token_calls[0][1]
    assert all("application/vnd.oci.image.index.v1+json" in call[2].get("Accept", "") for call in transport.calls if "manifests" in call[1])

    # A known digest on HEAD skips the manifest GET (gentle on rate limits).
    transport.calls.clear()
    RegistryClient(transport).resolve(image, "latest", known_digest=digest)
    assert [call[0] for call in transport.calls if "manifests" in call[1]] == ["HEAD", "HEAD"]


def test_resolve_refuses_index_without_amd64_and_digest_mismatch() -> None:
    base = "https://ghcr.io/v2/example/xray"
    body = _index(("linux", "arm64"))
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    headers = {"docker-content-digest": digest}
    transport = FakeTransport(
        {("HEAD", f"{base}/manifests/latest"): HttpResponse(200, headers, b""), ("GET", f"{base}/manifests/latest"): HttpResponse(200, headers, body)},
        realm="https://ghcr.io/token",
    )
    with pytest.raises(UpstreamError, match="amd64"):
        RegistryClient(transport).resolve("ghcr.io/example/xray", "latest")

    good = _index(("linux", "amd64"))
    lying = {"docker-content-digest": D_NEW}
    transport = FakeTransport(
        {("HEAD", f"{base}/manifests/latest"): HttpResponse(200, lying, b""), ("GET", f"{base}/manifests/latest"): HttpResponse(200, lying, good)},
        realm="https://ghcr.io/token",
    )
    with pytest.raises(UpstreamError, match="does not match"):
        RegistryClient(transport).resolve("ghcr.io/example/xray", "latest")


def test_tags_list_follows_link_pagination() -> None:
    base = "https://registry-1.docker.io/v2/prom/prometheus/tags/list"
    transport = FakeTransport(
        {
            ("GET", f"{base}?n=1000"): HttpResponse(
                200, {"link": '</v2/prom/prometheus/tags/list?last=v3.1.0&n=1000>; rel="next"'}, json.dumps({"tags": ["v3.0.0", "v3.1.0"]}).encode()
            ),
            ("GET", f"{base}?last=v3.1.0&n=1000"): HttpResponse(200, {}, json.dumps({"tags": ["v3.2.0", "latest"]}).encode()),
        },
        realm="https://auth.docker.io/token",
    )
    assert RegistryClient(transport).tags("prom/prometheus") == ["v3.0.0", "v3.1.0", "v3.2.0", "latest"]


def test_semver_selection_stays_in_major_and_skips_prereleases() -> None:
    tags = ["v2.6.1", "v2.13.0", "v2.14.0-rc.1", "v2.14.0", "v3.0.0", "app/v2.20.0", "v2.9.10", "latest"]
    assert select_semver(tags, "v2.*") == "v2.14.0"
    assert select_semver(["13.2.4", "13.10.0", "13.11.0-ubuntu", "14.0.0", "13.9.9"], "13.*") == "13.10.0"
    assert select_semver(["v4.0.0"], "v3.*") is None
    assert select_semver(["3.1.0"], "v3.*") is None


# -- stage by digest -----------------------------------------------------------------------------


def test_stage_by_digest_pulls_the_digest_and_verifies_repo_digest(env) -> None:
    ref = env.store.stage("xray", digest=D_NEW, tag="latest")
    assert ref == f"{XRAY}@{D_NEW}"
    assert env.host.pulls() == [f"{XRAY}@{D_NEW}"]
    env.host.pullable[f"{XRAY}@{D_NEWER}"] = f"{XRAY}@{D_NEW}"  # registry served something else
    with pytest.raises(ArtifactError, match="expected digest"):
        env.store.stage("xray", digest=D_NEWER)
    with pytest.raises(ArtifactError, match="invalid digest"):
        env.store.stage("xray", digest="sha256:abc")


def test_artifacts_cli_stage_accepts_a_digest(env, monkeypatch) -> None:
    from tracegate.cli import artifacts as artifacts_cli
    from tracegate.services import artifacts as artifacts_svc

    monkeypatch.setattr(artifacts_svc, "_default_runner", env.host)
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = artifacts_cli.main(
            ["--registry", str(env.root.parent / "artifacts.json"), "--root", str(env.root), "stage", "xray", "--digest", D_NEW, "--json"]
        )
    assert code == 0
    assert json.loads(stdout.getvalue())["reference"] == f"{XRAY}@{D_NEW}"
    assert env.host.pulls() == [f"{XRAY}@{D_NEW}"]


# -- supervisor ------------------------------------------------------------------------------------


def test_soak_gates_staging_and_state_file_is_private(env) -> None:
    env.client.digests[(SHADOWTLS, "latest")] = D_NEW
    sup = env.make()
    report = sup.run()
    assert report.ok
    assert _candidate(env, "shadowtls", D_NEW)["status"] == "discovered"
    assert env.host.pulls() == []
    assert stat.S_IMODE((env.root / "updates.json").stat().st_mode) == 0o600
    assert ("update-discovered", "shadowtls") in _actions(env)

    env.clock.days(2.9)
    sup.run()
    assert env.host.pulls() == []

    env.clock.days(0.2)
    report = sup.run()
    assert report.activated == ["shadowtls"]
    assert env.host.pulls() == [f"{SHADOWTLS}@{D_NEW}"]
    assert env.store.read_active("shadowtls") == f"{SHADOWTLS}@{D_NEW}"
    assert env.store.read_last_good("shadowtls") == f"{SHADOWTLS}@{D_OLD}"
    assert env.host.restarts() == ["tracegate-shadowtls-backhaul.service", "tracegate-shadowtls-backhaul2.service"]
    phases = [context.phase for context in env.prober.contexts]
    assert phases == [
        "baseline",
        "after tracegate-shadowtls-backhaul.service",
        "after tracegate-shadowtls-backhaul2.service",
    ]
    # Mid-sequence the second unit still runs the old digest.
    middle = env.prober.contexts[1].expected_digests
    assert middle == {"tracegate-shadowtls-backhaul.service": D_NEW, "tracegate-shadowtls-backhaul2.service": D_OLD}
    assert env.prober.contexts[1].client_image == f"{SHADOWTLS}@{D_NEW}"
    assert _candidate(env, "shadowtls", D_NEW)["status"] == "activated"

    # Idempotent: nothing more to do.
    env.host.calls.clear()
    report = sup.run()
    assert report.ok and env.host.restarts() == [] and env.host.pulls() == []


def test_replaced_or_withdrawn_digest_is_dropped_and_soak_restarts(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    sup = env.make()
    sup.run()
    env.clock.days(2)
    env.client.digests[(XRAY, "latest")] = D_NEWER
    sup.run()
    state = json.loads((env.root / "updates.json").read_text())
    assert set(state["components"]["xray"]["candidates"]) == {D_NEWER}
    assert ("update-dropped", "xray") in _actions(env)
    env.clock.days(2)
    sup.run()
    assert env.host.pulls() == []  # the new digest has its own soak


def test_semver_track_never_crosses_major(env) -> None:
    env.client.tag_lists[HYSTERIA] = ["v2.13.0", "v2.14.0", "v3.0.0"]
    env.client.digests[(HYSTERIA, "v2.14.0")] = D_NEW
    env.client.digests[(HYSTERIA, "v3.0.0")] = D_NEWER
    sup = env.make()
    sup.run()
    candidate = _candidate(env, "hysteria", D_NEW)
    assert candidate["tag"] == "v2.14.0"


def test_hold_freezes_automatic_activation(env) -> None:
    env.client.digests[(SHADOWTLS, "latest")] = D_NEW
    sup = env.make(soak_days=0)
    sup.set_hold(True)
    report = sup.run()
    assert report.pending == ["shadowtls"]
    candidate = _candidate(env, "shadowtls", D_NEW)
    assert candidate["status"] == "pending-approval" and "hold is on" in candidate["reason"]
    assert env.host.restarts() == []
    assert env.store.read_active("shadowtls") == f"{SHADOWTLS}@{D_OLD}"
    assert ("update-hold", "*") in _actions(env)

    sup.set_hold(False)
    report = sup.run()
    assert report.activated == ["shadowtls"]


def test_hold_set_between_baseline_and_switch_stops_activation(env) -> None:
    env.client.digests[(SHADOWTLS, "latest")] = D_NEW
    sup = env.make(soak_days=0)

    def baseline_sets_hold(context):
        if context.phase == "baseline":
            sup.set_hold(True, reason="operator during run")
        return False

    env.prober.fail_when = baseline_sets_hold
    sup.run()
    assert env.host.restarts() == []
    assert env.store.read_active("shadowtls") == f"{SHADOWTLS}@{D_OLD}"
    assert _candidate(env, "shadowtls", D_NEW)["status"] == "pending-approval"


def test_policy_auto_versus_notify_per_role(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.client.digests[(SHADOWTLS, "latest")] = D_NEW
    entry = env.make(role="entry", soak_days=0)
    report = entry.run()
    # Entry: xray is notify (staged + checked, queued); shadowtls is auto.
    assert _candidate(env, "xray", D_NEW)["status"] == "pending-approval"
    assert "policy is notify for entry" in _candidate(env, "xray", D_NEW)["reason"]
    assert report.activated == ["shadowtls"]
    assert env.host.restarts() == ["tracegate-shadowtls-entry.service", "tracegate-shadowtls-entry2.service"]
    assert f"{XRAY}@{D_NEW}" in env.host.pulls()  # staged for the operator
    assert env.store.read_active("xray") == f"{XRAY}@{D_OLD}"


def test_incomplete_probe_set_queues_even_with_auto_policy(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.prober.incomplete["xray"] = "Reality probe unavailable"
    sup = env.make(soak_days=0)
    report = sup.run()
    assert report.pending == ["xray"] and report.activated == []
    assert "probe set incomplete" in _candidate(env, "xray", D_NEW)["reason"]


def test_one_activation_per_run(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.client.digests[(SHADOWTLS, "latest")] = D_NEW
    sup = env.make(soak_days=0)
    report = sup.run()
    assert report.activated == ["xray"]
    assert _candidate(env, "shadowtls", D_NEW)["status"] == "checked"
    report = sup.run()
    assert report.activated == ["shadowtls"]


def test_static_check_failure_rejects_and_rejected_digest_is_never_restaged(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.prober.check_status["xray"] = "fail"
    sup = env.make(soak_days=0)
    report = sup.run()
    assert report.rejected == ["xray"]
    candidate = _candidate(env, "xray", D_NEW)
    assert candidate["status"] == "rejected" and "static check failed" in candidate["reason"]
    assert env.store.read_active("xray") == f"{XRAY}@{D_OLD}"

    env.host.calls.clear()
    env.prober.check_status["xray"] = "ok"
    env.clock.days(10)
    sup.run()
    assert env.host.pulls() == []
    assert _candidate(env, "xray", D_NEW)["status"] == "rejected"
    with pytest.raises(UpdateError, match="rejected"):
        sup.approve("xray", D_NEW, no_soak=True)


def test_static_check_failing_for_active_too_queues_instead_of_rejecting(env) -> None:
    # The same check failing for the running version points at the host,
    # not at the candidate: the candidate must not be rejected for good.
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.prober.check_status["xray"] = "fail"
    env.prober.active_check_status["xray"] = "fail"
    sup = env.make(soak_days=0)
    report = sup.run()
    candidate = _candidate(env, "xray", D_NEW)
    assert candidate["status"] == "pending-approval"
    assert "inconclusive" in candidate["reason"]
    assert report.rejected == []
    assert env.store.read_active("xray") == f"{XRAY}@{D_OLD}"


def test_static_check_error_keeps_candidate_staged_for_retry(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.prober.check_status["xray"] = "error"
    sup = env.make(soak_days=0)
    report = sup.run()
    assert not report.ok
    assert _candidate(env, "xray", D_NEW)["status"] == "staged"


def test_probe_failure_after_switch_rolls_back_restarts_and_rejects(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.prober.fail_when = lambda context: context.phase == "after tracegate-xray-ss2022.service"
    sup = env.make(soak_days=0)
    report = sup.run()
    assert report.rolled_back == ["xray"] and not report.ok
    assert env.store.read_active("xray") == f"{XRAY}@{D_OLD}"
    # last-good is restored, not left pointing at the rejected candidate
    assert env.store.read_last_good("xray") == f"{XRAY}@{D_LAST_GOOD}"
    assert env.host.restarts() == [
        "tracegate-xray@transit.service",
        "tracegate-xray-ss2022.service",
        "tracegate-xray@transit.service",
        "tracegate-xray-ss2022.service",
    ]
    rollback_context = env.prober.contexts[-1]
    assert rollback_context.phase == "after rollback"
    assert set(rollback_context.expected_digests.values()) == {D_OLD}
    assert rollback_context.client_image == f"{XRAY}@{D_OLD}"
    candidate = _candidate(env, "xray", D_NEW)
    assert candidate["status"] == "rejected" and "post-switch probe failed" in candidate["reason"]
    assert any(item["name"] == "fake-probe" and not item["ok"] for item in candidate["evidence"])
    actions = [action for action, component in _actions(env) if component == "xray"]
    assert actions.index("promote") < actions.index("rollback") < actions.index("update-rejected")
    assert not sup.hold_active()


def test_failed_restart_rolls_back_only_restarted_units(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.host.restart_fail.add("tracegate-xray@transit.service")
    sup = env.make(soak_days=0)
    sup.run()
    assert env.store.read_active("xray") == f"{XRAY}@{D_OLD}"
    assert _candidate(env, "xray", D_NEW)["status"] == "rejected"
    assert "tracegate-xray-ss2022.service" not in env.host.restarts()


def test_rollback_that_still_fails_sets_hold(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.prober.fail_when = lambda context: context.phase != "baseline"
    sup = env.make(soak_days=0)
    report = sup.run()
    assert sup.hold_active()
    assert any("on hold" in line for line in report.errors)


def test_baseline_failure_queues_without_switching(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.prober.fail_when = lambda context: context.phase == "baseline"
    sup = env.make(soak_days=0)
    sup.run()
    assert env.host.restarts() == []
    assert env.store.read_active("xray") == f"{XRAY}@{D_OLD}"
    assert "baseline" in _candidate(env, "xray", D_NEW)["reason"]


def test_approve_activates_notify_component_through_probe_path(env) -> None:
    env.client.digests[(TELEMT, "latest")] = D_NEW
    env.prober.incomplete["telemt"] = "no authenticated probe"
    sup = env.make()
    sup.run()
    with pytest.raises(UpdateError, match="soaking"):
        sup.approve("telemt", D_NEW)
    report = sup.approve("telemt", D_NEW, no_soak=True)
    assert report.activated == ["telemt"]
    assert env.store.read_active("telemt") == f"{TELEMT}@{D_NEW}"
    assert env.host.restarts() == ["tracegate-mtproto@transit.service"]
    candidate = _candidate(env, "telemt", D_NEW)
    assert candidate["approved"] and candidate["no_soak"]
    assert any("incomplete probe set" in item["detail"] for item in candidate["evidence"])
    assert ("update-approve", "telemt") in _actions(env)


def test_approve_and_reject_validate_inputs(env) -> None:
    sup = env.make(role="entry")
    with pytest.raises(UpdateError, match="not updated on a entry host"):
        sup.approve("telemt", D_NEW)
    with pytest.raises(UpdateError, match="not a known candidate"):
        sup.approve("xray", D_NEW)
    with pytest.raises(UpdateError, match="active artifact"):
        sup.reject("xray", D_OLD)
    sup.reject("xray", D_NEWER, reason="known bad")
    env.client.digests[(XRAY, "latest")] = D_NEWER
    env.make(role="entry", soak_days=0).run()
    assert _candidate(env, "xray", D_NEWER)["status"] == "rejected"
    assert f"{XRAY}@{D_NEWER}" not in env.host.pulls()


def test_discovery_failure_is_reported_and_blocks_progress(env) -> None:
    env.client.digests[(XRAY, "latest")] = D_NEW
    sup = env.make(soak_days=0)
    env.client.fail.add(XRAY)
    report = sup.run()
    assert not report.ok and any("discovery failed" in line for line in report.errors)
    state = json.loads((env.root / "updates.json").read_text())
    assert state["last_run_ok"] is False and state["last_success"] is None


def test_manual_rollback_of_activated_digest_is_not_reactivated(env) -> None:
    env.client.digests[(SHADOWTLS, "latest")] = D_NEW
    sup = env.make(soak_days=0)
    sup.run()
    env.store.rollback("shadowtls")
    env.host.calls.clear()
    sup.run()
    assert env.host.restarts() == []
    assert _candidate(env, "shadowtls", D_NEW)["status"] == "pending-approval"


# -- metrics and alerts ---------------------------------------------------------------------------


def test_metrics_snapshot_and_agent_gauges(env, monkeypatch) -> None:
    from tracegate.agent import metrics as agent_metrics

    assert metrics_snapshot(env.root)["present"] is False
    env.client.digests[(XRAY, "latest")] = D_NEW
    env.client.digests[(TELEMT, "latest")] = D_NEW
    env.prober.incomplete["telemt"] = "no probe"
    env.prober.check_status["xray"] = "fail"
    sup = env.make(soak_days=0)
    sup.run()
    sup.set_hold(True)
    snapshot = metrics_snapshot(env.root)
    assert snapshot["present"] and snapshot["hold"] and snapshot["role"] == "endpoint"
    assert snapshot["components"]["telemt"]["pending"] == 1
    assert snapshot["components"]["xray"]["rejected"] == 1
    assert snapshot["components"]["xray"]["last_rejected"] == env.clock.t

    class Recorder:
        def __init__(self, name, documentation, labels=None):  # noqa: ANN001
            self.name = name
            self.label_names = list(labels or [])
            self.rows = []

        def add_metric(self, values, value):  # noqa: ANN001
            self.rows.append((tuple(zip(self.label_names, values)), float(value)))

    # Other tests swap prometheus_client for fakes; record directly instead.
    monkeypatch.setattr(agent_metrics, "GaugeMetricFamily", Recorder)
    settings = SimpleNamespace(agent_engine_updates_dir=str(env.root), agent_role="TRANSIT")
    samples = {
        (family.name, tuple(sorted(labels))): value
        for family in agent_metrics._engine_update_metrics(settings)
        for labels, value in family.rows
    }
    assert samples[("tracegate_engine_update_pending", (("component", "telemt"), ("role", "endpoint")))] == 1
    assert samples[("tracegate_engine_update_rejected", (("component", "xray"), ("role", "endpoint")))] == 1
    assert samples[("tracegate_engine_update_hold", (("role", "endpoint"),))] == 1
    assert ("tracegate_engine_update_last_run_timestamp_seconds", (("role", "endpoint"),)) in samples
    assert all("sha256" not in str(key) for key in samples)


def test_engine_update_alert_rules_are_three_state_warnings() -> None:
    from tracegate.cli.grafana_bootstrap import _slo_alert_rules

    rules = {rule["uid"]: rule for rule in _slo_alert_rules("prom", folder_uid="tracegate-admin")}
    uids = ("tg-ops-engine-update-pending", "tg-ops-engine-update-rejected", "tg-ops-engine-update-stale")
    for uid in uids:
        rule = rules[uid]
        assert len(uid) <= 40
        assert rule["labels"]["severity"] == "warning"
        assert rule["labels"]["notify"] == "owner"
        assert rule["noDataState"] in {"OK", "NoData"}
        assert rule["execErrState"] == "Error"
        assert rule["ruleGroup"] == "tracegate-slo"
    assert "tracegate_engine_update_pending" in rules[uids[0]]["data"][0]["model"]["expr"]
    assert "tracegate_engine_update_last_rejected_timestamp_seconds" in rules[uids[1]]["data"][0]["model"]["expr"]
    assert "tracegate_engine_update_last_success_timestamp_seconds" in rules[uids[2]]["data"][0]["model"]["expr"]


def test_webhook_forwards_owner_notices_but_not_their_no_data_state() -> None:
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("grafana_router_for_engine_tests", REPO_ROOT / "src/tracegate/api/routers/grafana.py")
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    failed = {"alerts": [{"labels": {"severity": "warning", "notify": "owner", "slo_type": "engine_update_pending"}}]}
    assert module._grafana_alert_webhook_should_forward(failed) is True
    no_data = {"alerts": [{"labels": {"severity": "warning", "notify": "owner", "alertname": "DatasourceNoData"}}]}
    assert module._grafana_alert_webhook_should_forward(no_data) is False
    plain_warning = {"alerts": [{"labels": {"severity": "warning"}}]}
    assert module._grafana_alert_webhook_should_forward(plain_warning) is False


# -- systemd and CLI --------------------------------------------------------------------------------


def test_engine_update_units_are_oneshot_daily_and_never_run_docker_directly() -> None:
    service = (REPO_ROOT / "deploy/systemd/tracegate-engine-update.service").read_text(encoding="utf-8")
    timer = (REPO_ROOT / "deploy/systemd/tracegate-engine-update.timer").read_text(encoding="utf-8")
    assert "Type=oneshot" in service
    assert "ExecStart=/opt/tracegate/venv/bin/tracegate-engine-update run" in service
    assert "EnvironmentFile=/etc/tracegate/deploy.env" in service
    assert "docker run" not in service and "docker pull" not in service
    assert "NoNewPrivileges=yes" in service
    # Night window in UTC, so engine restarts never land in the daytime.
    assert re.search(r"(?m)^OnCalendar=\*-\*-\* 0[0-3]:\d\d:00 UTC$", timer)
    assert "Persistent=true" in timer and "RandomizedDelaySec=" in timer
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'tracegate-engine-update = "tracegate.cli.engine_update:main"' in pyproject


def _cli(env, monkeypatch, *argv: str) -> tuple[int, str, str]:
    registry_path = env.root.parent / "artifacts.json"
    sup_factory = env.make

    def fake_build(args):
        return sup_factory(role=args.role or "endpoint", soak_days=cli._soak_days(args))

    monkeypatch.setattr(cli, "build_supervisor", fake_build)
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(["--registry", str(registry_path), "--root", str(env.root), *argv])
    return code, stdout.getvalue(), stderr.getvalue()


def test_cli_run_status_hold_and_exit_codes(env, monkeypatch) -> None:
    code, out, _ = _cli(env, monkeypatch, "--role", "endpoint", "run")
    assert code == 0 and "up to date" in out

    env.client.digests[(SHADOWTLS, "latest")] = D_NEW
    code, out, _ = _cli(env, monkeypatch, "--role", "endpoint", "--soak-days", "0", "run", "--json")
    payload = json.loads(out)
    assert code == 0 and payload["activated"] == ["shadowtls"]

    code, out, _ = _cli(env, monkeypatch, "--role", "endpoint", "status", "--json")
    status = json.loads(out)
    assert code == 0 and status["components"]["shadowtls"]["policy"] == "auto"
    assert status["components"]["shadowtls"]["active"] == f"{SHADOWTLS}@{D_NEW}"

    code, out, _ = _cli(env, monkeypatch, "hold", "on")
    assert code == 0 and "hold is on" in out and (env.root / "updates.hold").exists()
    code, out, _ = _cli(env, monkeypatch, "hold", "off")
    assert code == 0 and not (env.root / "updates.hold").exists()

    code, _, err = _cli(env, monkeypatch, "--role", "endpoint", "approve", "xray", D_NEW)
    assert code == 1 and "not a known candidate" in err

    env.client.fail.add(XRAY)
    code, _, _ = _cli(env, monkeypatch, "--role", "endpoint", "run")
    assert code == 1

    code, _, err = _cli(env, monkeypatch, "--soak-days", "-1", "run")
    assert code == 2


def test_cli_requires_a_role(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("TRACEGATE_HOST_ROLE", raising=False)
    registry_path = tmp_path / "artifacts.json"
    registry_path.write_text(json.dumps(REGISTRY), encoding="utf-8")
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
        code = cli.main(["--registry", str(registry_path), "--root", str(tmp_path / "store"), "status"])
    assert code == 2 and "role" in stderr.getvalue()


def test_cli_registry_resolution_prefers_current_release(monkeypatch, tmp_path: Path) -> None:
    from tracegate.cli import artifacts as artifacts_cli

    installed = tmp_path / "current" / "artifacts.json"
    installed.parent.mkdir()
    installed.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(artifacts_cli, "_INSTALLED_REGISTRY", installed)
    monkeypatch.delenv("TRACEGATE_ARTIFACTS_REGISTRY", raising=False)
    args = SimpleNamespace(registry=None)
    assert cli._registry_path(args) == installed
    monkeypatch.setenv("TRACEGATE_ARTIFACTS_REGISTRY", str(tmp_path / "env.json"))
    assert cli._registry_path(args) == tmp_path / "env.json"


def test_probe_config_from_settings_uses_role_values(monkeypatch) -> None:
    monkeypatch.delenv("TRACEGATE_AGENT_HEALTH_URL", raising=False)
    monkeypatch.delenv("TRACEGATE_GRAFANA_URL", raising=False)
    settings = SimpleNamespace(
        agent_port=8070,
        agent_auth_token="agent-secret",
        grafana_internal_url="http://tracegate-grafana:3000",
        hysteria_server_name_transit="hy.example.com",
        hysteria_server_name_entry="",
        hysteria_endpoint_backhaul_auth_token=" backhaul ",
    )
    config = cli.probe_config_from_settings("endpoint", settings)
    assert config.agent_metrics_url == "http://127.0.0.1:8070/metrics"
    assert config.grafana_url == "http://127.0.0.1:3000"
    assert config.hysteria_backhaul_token == "backhaul"
    assert config.hysteria_server_name == "hy.example.com"
