from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import stat
import subprocess

import pytest

from tracegate.cli import artifacts as cli
from tracegate.services import artifacts as svc
from tracegate.services.artifacts import (
    ArtifactError,
    ArtifactStore,
    RegistryError,
    components_for_units,
    load_registry,
    parse_env,
    parse_reference,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64

XRAY_IMAGE = "ghcr.io/example/xray"
TELEMT_IMAGE = "ghcr.io/example/telemt"
WSTUNNEL_IMAGE = "ghcr.io/example/wstunnel"
HYSTERIA_IMAGE = "docker.io/example/hysteria"
HYSTERIA_FAMILIAR = "example/hysteria"

REGISTRY = {
    "schema_version": 1,
    "components": {
        "xray": {
            "image": XRAY_IMAGE,
            "channel": "latest",
            "units": ["tracegate-xray@.service", "tracegate-xray-ss2022.service"],
            "container_prefixes": ["tracegate-xray-"],
        },
        "telemt": {
            "image": TELEMT_IMAGE,
            "channel": "latest",
            "units": ["tracegate-mtproto@.service"],
            "container_prefixes": ["tracegate-mtproto-"],
        },
        "wstunnel": {
            "image": WSTUNNEL_IMAGE,
            "channel": "latest",
            "units": ["tracegate-wstunnel-wireguard.service"],
            "container_prefixes": ["tracegate-wstunnel-wireguard"],
        },
        "hysteria": {
            "image": HYSTERIA_IMAGE,
            "channel": "v2.13.0",
            "units": ["tracegate-hysteria@.service"],
            "container_prefixes": ["tracegate-hysteria-"],
        },
    },
}


def _completed(argv: list[str], returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


class FakeDocker:
    """Scripted docker runner; no daemon involved."""

    def __init__(self) -> None:
        self.containers: list[tuple[str, str]] = []  # (container id, name)
        self.container_image: dict[str, str] = {}  # container id -> image id
        self.repo_digests: dict[str, list[str]] = {}  # inspectable ref -> repo digests
        self.pull_results: dict[str, str] = {}  # tag ref -> repo digest served on pull
        self.docker_unavailable = False  # simulate a daemon that cannot be reached
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if not argv or argv[0] != "docker":
            return _completed(argv, 1, stderr=f"unexpected command: {argv}")
        args = argv[1:]
        if args[:2] == ["ps", "--no-trunc"]:
            if self.docker_unavailable:
                return _completed(argv, 1, stderr="Cannot connect to the Docker daemon")
            stdout = "".join(f"{container_id}\t{name}\n" for container_id, name in self.containers)
            return _completed(argv, 0, stdout=stdout)
        if args[:1] == ["inspect"]:
            container_id = args[-1]
            image = self.container_image.get(container_id)
            if image is None:
                return _completed(argv, 1, stderr=f"no such container: {container_id}")
            return _completed(argv, 0, stdout=image + "\n")
        if args[:2] == ["image", "inspect"]:
            reference = args[-1]
            digests = self.repo_digests.get(reference)
            if digests is None:
                return _completed(argv, 1, stderr=f"no such image: {reference}")
            if "--format" in args:
                return _completed(argv, 0, stdout=json.dumps(digests) + "\n")
            return _completed(argv, 0, stdout="[{}]")
        if args[:1] == ["pull"]:
            reference = args[-1]
            digest = self.pull_results.get(reference)
            if digest is None:
                return _completed(argv, 1, stderr=f"pull access denied: {reference}")
            self.repo_digests[reference] = [digest]
            self.repo_digests[digest] = [digest]
            return _completed(argv, 0, stdout=f"Status: Downloaded newer image: {reference}\n")
        return _completed(argv, 1, stderr=f"unexpected argv: {argv}")


def make_store(tmp_path: Path, docker: FakeDocker | None = None) -> tuple[ArtifactStore, FakeDocker]:
    registry_path = tmp_path / "artifacts.json"
    registry_path.write_text(json.dumps(REGISTRY), encoding="utf-8")
    registry = load_registry(registry_path)
    docker = docker if docker is not None else FakeDocker()
    store = ArtifactStore(tmp_path / "store", registry, runner=docker)
    return store, docker


def xray_running(docker: FakeDocker, digest: str = DIGEST_A, name: str = "tracegate-xray-transit") -> None:
    docker.containers.append(("c1", name))
    docker.container_image["c1"] = "img1"
    docker.repo_digests["img1"] = [f"{XRAY_IMAGE}@{digest}"]


def test_capture_from_running_container_records_exact_env_and_journal(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    xray_running(docker)

    result = store.capture("xray")

    assert result.noop is False
    assert result.reference == f"{XRAY_IMAGE}@{DIGEST_A}"
    env_file = tmp_path / "store" / "active" / "xray.env"
    assert env_file.read_text(encoding="utf-8") == f"TRACEGATE_IMAGE={XRAY_IMAGE}@{DIGEST_A}\n"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o644
    assert stat.S_IMODE(env_file.parent.stat().st_mode) == 0o755
    (entry,) = store.journal_entries()
    assert entry["action"] == "capture"
    assert entry["component"] == "xray"
    assert entry["reference"] == f"{XRAY_IMAGE}@{DIGEST_A}"
    assert set(entry) == {"time", "action", "component", "reference", "previous", "detail"}
    assert not list((tmp_path / "store").rglob("*.tmp*"))


def test_capture_refuses_divergent_running_digests_and_honours_from_container(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    docker.containers.extend([("c1", "tracegate-xray-transit"), ("c2", "tracegate-xray-entry")])
    docker.container_image["c1"] = "img1"
    docker.container_image["c2"] = "img2"
    docker.repo_digests["img1"] = [f"{XRAY_IMAGE}@{DIGEST_A}"]
    docker.repo_digests["img2"] = [f"{XRAY_IMAGE}@{DIGEST_B}"]

    with pytest.raises(ArtifactError) as excinfo:
        store.capture("xray")
    message = str(excinfo.value)
    assert "tracegate-xray-transit" in message and DIGEST_A in message
    assert "tracegate-xray-entry" in message and DIGEST_B in message
    assert "--from-container" in message

    with pytest.raises(ArtifactError):
        store.capture("xray", from_container="missing-container")

    result = store.capture("xray", from_container="tracegate-xray-entry")
    assert result.reference == f"{XRAY_IMAGE}@{DIGEST_B}"
    (entry,) = store.journal_entries()
    assert entry["detail"] == "from-container tracegate-xray-entry"


def test_capture_falls_back_to_local_channel_tag(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    docker.repo_digests[f"{XRAY_IMAGE}:latest"] = [f"{XRAY_IMAGE}@{DIGEST_C}"]

    result = store.capture("xray")

    assert result.reference == f"{XRAY_IMAGE}@{DIGEST_C}"
    assert store.read_active("xray") == f"{XRAY_IMAGE}@{DIGEST_C}"


def test_capture_is_noop_once_active_exists(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    xray_running(docker)
    store.capture("xray")
    calls_after_first_capture = len(docker.calls)

    result = store.capture("xray")

    assert result.noop is True
    assert result.reference == f"{XRAY_IMAGE}@{DIGEST_A}"
    assert len(docker.calls) == calls_after_first_capture
    assert len(store.journal_entries()) == 1


def test_capture_without_anything_local_fails_with_stage_hint(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)

    with pytest.raises(ArtifactError) as excinfo:
        store.capture("xray")

    assert "tracegate-artifacts stage xray" in str(excinfo.value)


def test_capture_fails_when_image_has_no_repo_digest(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    docker.containers.append(("c1", "tracegate-xray-transit"))
    docker.container_image["c1"] = "img1"
    docker.repo_digests["img1"] = [f"{TELEMT_IMAGE}@{DIGEST_A}"]

    with pytest.raises(ArtifactError):
        store.capture("xray")


def test_capture_from_container_without_running_containers_is_an_error(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    docker.repo_digests[f"{XRAY_IMAGE}:latest"] = [f"{XRAY_IMAGE}@{DIGEST_A}"]

    with pytest.raises(ArtifactError) as excinfo:
        store.capture("xray", from_container="tracegate-xray-transit")

    message = str(excinfo.value)
    assert "--from-container tracegate-xray-transit" in message
    assert "no container of xray is running" in message
    assert store.read_active("xray") is None


def test_docker_hub_familiar_spelling_resolves_in_capture_stage_promote_and_verify(tmp_path: Path) -> None:
    # Docker reports Docker Hub RepoDigests without the registry host; the
    # registry file keeps the docker.io spelling in everything stored.
    store, docker = make_store(tmp_path)
    familiar_a = f"{HYSTERIA_FAMILIAR}@{DIGEST_A}"
    familiar_b = f"{HYSTERIA_FAMILIAR}@{DIGEST_B}"

    # capture from a running container whose RepoDigests are in familiar form
    docker.containers.append(("h1", "tracegate-hysteria-transit"))
    docker.container_image["h1"] = "himg1"
    docker.repo_digests["himg1"] = [familiar_a]
    result = store.capture("hysteria")
    assert result.reference == f"{HYSTERIA_IMAGE}@{DIGEST_A}"
    assert store.read_active("hysteria") == f"{HYSTERIA_IMAGE}@{DIGEST_A}"

    # stage: the pull serves familiar-form RepoDigests
    docker.pull_results[f"{HYSTERIA_IMAGE}:v2.13.0"] = familiar_b
    reference = store.stage("hysteria")
    assert reference == f"{HYSTERIA_IMAGE}@{DIGEST_B}"

    # promote accepts the familiar spelling and still stores the registry spelling
    docker.repo_digests[f"{HYSTERIA_IMAGE}@{DIGEST_B}"] = [familiar_b]
    promote = store.promote("hysteria", familiar_b)
    assert promote.already_active is False
    assert store.read_active("hysteria") == f"{HYSTERIA_IMAGE}@{DIGEST_B}"
    assert store.read_last_good("hysteria") == f"{HYSTERIA_IMAGE}@{DIGEST_A}"

    # verify accepts both spellings of the same repo
    store._atomic_write(store._env_path("active", "hysteria"), f"TRACEGATE_IMAGE={familiar_a}\n")
    docker.repo_digests[familiar_a] = [familiar_a]
    docker.repo_digests[f"{HYSTERIA_IMAGE}@{DIGEST_A}"] = [familiar_a]
    assert [p.code for p in store.verify(["hysteria"])] == []

    # ... but still refuses a different repo
    store._atomic_write(store._env_path("active", "hysteria"), f"TRACEGATE_IMAGE=docker.io/other/image@{DIGEST_A}\n")
    (problem,) = store.verify(["hysteria"])
    assert problem.code == "repo-mismatch"
    with pytest.raises(ArtifactError):
        store.promote("hysteria", f"docker.io/other/image@{DIGEST_A}")


def test_docker_hub_channel_tag_fallback_with_familiar_spelling(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    docker.repo_digests[f"{HYSTERIA_IMAGE}:v2.13.0"] = [f"{HYSTERIA_FAMILIAR}@{DIGEST_C}"]

    result = store.capture("hysteria")

    assert result.reference == f"{HYSTERIA_IMAGE}@{DIGEST_C}"


def test_stage_adds_candidate_and_leaves_active_unchanged(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    docker.pull_results[f"{TELEMT_IMAGE}:latest"] = f"{TELEMT_IMAGE}@{DIGEST_B}"

    reference = store.stage("telemt")

    assert reference == f"{TELEMT_IMAGE}@{DIGEST_B}"
    assert store.read_active("telemt") is None
    candidates = json.loads((tmp_path / "store" / "candidates" / "telemt.json").read_text(encoding="utf-8"))
    assert len(candidates) == 1
    assert candidates[0]["reference"] == reference
    assert candidates[0]["tag"] == "latest"
    assert candidates[0]["staged_at"].endswith("Z")
    (entry,) = store.journal_entries()
    assert entry["action"] == "stage"
    assert entry["reference"] == reference


def test_stage_with_explicit_tag(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    docker.pull_results[f"{TELEMT_IMAGE}:v1.2.3"] = f"{TELEMT_IMAGE}@{DIGEST_A}"

    reference = store.stage("telemt", tag="v1.2.3")

    assert reference == f"{TELEMT_IMAGE}@{DIGEST_A}"
    with pytest.raises(ArtifactError):
        store.stage("telemt", tag="bad:tag")


def test_promote_moves_active_to_last_good_and_returns_units(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    xray_running(docker)
    store.capture("xray")
    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_B}"] = [f"{XRAY_IMAGE}@{DIGEST_B}"]

    result = store.promote("xray", DIGEST_B)

    assert result.already_active is False
    assert result.units == ["tracegate-xray@.service", "tracegate-xray-ss2022.service"]
    assert result.reference == f"{XRAY_IMAGE}@{DIGEST_B}"
    assert store.read_active("xray") == f"{XRAY_IMAGE}@{DIGEST_B}"
    assert store.read_last_good("xray") == f"{XRAY_IMAGE}@{DIGEST_A}"
    actions = [entry["action"] for entry in store.journal_entries()]
    assert actions == ["capture", "promote"]
    promote = store.journal_entries()[-1]
    assert promote["previous"] == f"{XRAY_IMAGE}@{DIGEST_A}"


def test_promote_already_active_reference_leaves_last_good_and_journal_untouched(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    xray_running(docker)
    store.capture("xray")
    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_A}"] = [f"{XRAY_IMAGE}@{DIGEST_A}"]
    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_B}"] = [f"{XRAY_IMAGE}@{DIGEST_B}"]
    store.promote("xray", DIGEST_B)
    store.rollback("xray")
    assert store.read_active("xray") == f"{XRAY_IMAGE}@{DIGEST_A}"
    assert store.read_last_good("xray") == f"{XRAY_IMAGE}@{DIGEST_B}"
    entries_before = store.journal_entries()

    result = store.promote("xray", DIGEST_A)

    assert result.already_active is True
    assert result.reference == f"{XRAY_IMAGE}@{DIGEST_A}"
    assert store.read_active("xray") == f"{XRAY_IMAGE}@{DIGEST_A}"
    assert store.read_last_good("xray") == f"{XRAY_IMAGE}@{DIGEST_B}"
    assert store.journal_entries() == entries_before


def test_promote_accepts_full_reference(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_A}"] = [f"{XRAY_IMAGE}@{DIGEST_A}"]

    store.promote("xray", f"{XRAY_IMAGE}@{DIGEST_A}")

    assert store.read_active("xray") == f"{XRAY_IMAGE}@{DIGEST_A}"


def test_promote_refuses_foreign_repo_tag_reference_and_absent_image(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    with pytest.raises(ArtifactError):
        store.promote("xray", f"{TELEMT_IMAGE}@{DIGEST_A}")
    with pytest.raises(ArtifactError):
        store.promote("xray", f"{XRAY_IMAGE}:latest")
    with pytest.raises(ArtifactError):
        store.promote("xray", "latest")
    with pytest.raises(ArtifactError) as excinfo:
        store.promote("xray", DIGEST_A)
    assert "tracegate-artifacts stage xray" in str(excinfo.value)


def test_rollback_swaps_active_and_last_good(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    xray_running(docker)
    store.capture("xray")
    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_A}"] = [f"{XRAY_IMAGE}@{DIGEST_A}"]
    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_B}"] = [f"{XRAY_IMAGE}@{DIGEST_B}"]
    store.promote("xray", DIGEST_B)

    active, last_good = store.rollback("xray")

    assert active == f"{XRAY_IMAGE}@{DIGEST_A}"
    assert last_good == f"{XRAY_IMAGE}@{DIGEST_B}"
    assert store.read_active("xray") == f"{XRAY_IMAGE}@{DIGEST_A}"
    assert store.read_last_good("xray") == f"{XRAY_IMAGE}@{DIGEST_B}"
    active, last_good = store.rollback("xray")
    assert active == f"{XRAY_IMAGE}@{DIGEST_B}"
    assert store.read_active("xray") == f"{XRAY_IMAGE}@{DIGEST_B}"


def test_rollback_refuses_without_last_good_or_absent_image(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    with pytest.raises(ArtifactError):
        store.rollback("xray")

    store2_root = tmp_path / "other"
    store2_root.mkdir()
    registry_path = store2_root / "artifacts.json"
    registry_path.write_text(json.dumps(REGISTRY), encoding="utf-8")
    docker = FakeDocker()
    store2 = ArtifactStore(store2_root / "store", load_registry(registry_path), runner=docker)
    store2._atomic_write(store2._env_path("active", "xray"), f"TRACEGATE_IMAGE={XRAY_IMAGE}@{DIGEST_A}\n")
    store2._atomic_write(store2._env_path("last-good", "xray"), f"TRACEGATE_IMAGE={XRAY_IMAGE}@{DIGEST_B}\n")
    with pytest.raises(ArtifactError):
        store2.rollback("xray")


def test_verify_reports_problem_codes(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)

    problems = store.verify(["xray"])
    assert [(p.component, p.code) for p in problems] == [("xray", "active-missing")]

    store._atomic_write(store._env_path("active", "xray"), "not an env file\n")
    (problem,) = store.verify(["xray"])
    assert problem.code == "active-format"

    store._atomic_write(store._env_path("active", "xray"), f"TRACEGATE_IMAGE={TELEMT_IMAGE}@{DIGEST_A}\n")
    (problem,) = store.verify(["xray"])
    assert problem.code == "repo-mismatch"

    store._atomic_write(store._env_path("active", "xray"), f"TRACEGATE_IMAGE={XRAY_IMAGE}@{DIGEST_A}\n")
    (problem,) = store.verify(["xray"])
    assert problem.code == "image-absent"

    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_A}"] = [f"{XRAY_IMAGE}@{DIGEST_A}"]
    assert store.verify(["xray"]) == []


def test_status_reports_running_digests_and_drift(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    xray_running(docker, digest=DIGEST_B)
    store._atomic_write(store._env_path("active", "xray"), f"TRACEGATE_IMAGE={XRAY_IMAGE}@{DIGEST_A}\n")

    (status,) = store.status(["xray"])

    assert status.active == f"{XRAY_IMAGE}@{DIGEST_A}"
    assert status.last_good is None
    assert status.candidates == ()
    assert [(c.name, c.digest) for c in status.running] == [("tracegate-xray-transit", DIGEST_B)]
    assert status.running_error is None
    assert status.drift is True

    xray_env = tmp_path / "store" / "active" / "xray.env"
    xray_env.write_text(f"TRACEGATE_IMAGE={XRAY_IMAGE}@{DIGEST_B}\n", encoding="utf-8")
    (status,) = store.status(["xray"])
    assert status.drift is False


def test_status_reports_unknown_running_state_and_drift_when_docker_fails(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    store._atomic_write(store._env_path("active", "xray"), f"TRACEGATE_IMAGE={XRAY_IMAGE}@{DIGEST_A}\n")
    docker.docker_unavailable = True

    (status,) = store.status(["xray"])

    assert status.running == ()
    assert status.running_error is not None
    assert "Docker daemon" in status.running_error
    assert status.drift is None


def test_components_for_units_maps_instances_to_templates() -> None:
    registry_path = Path(__file__).parent.parent / "deploy" / "host" / "artifacts.json"
    registry = load_registry(registry_path)

    assert components_for_units(
        registry,
        ["tracegate-xray@transit.service", "tracegate-mtproto@entry.service", "tracegate-api.service"],
    ) == ["xray", "telemt"]
    assert components_for_units(registry, ["tracegate-api.service"]) == []


def test_parse_reference_accepts_only_full_digest_references() -> None:
    repo, digest = parse_reference(f"{XRAY_IMAGE}@{DIGEST_A}")
    assert repo == XRAY_IMAGE and digest == DIGEST_A
    for bad in (
        XRAY_IMAGE,
        f"{XRAY_IMAGE}:latest",
        f"{XRAY_IMAGE}@sha256:xyz",
        f"{XRAY_IMAGE}@sha256:{'A' * 64}",
        f"@{DIGEST_A}",
    ):
        with pytest.raises(ArtifactError):
            parse_reference(bad)


def test_parse_env_requires_exact_single_line(tmp_path: Path) -> None:
    reference = f"{XRAY_IMAGE}@{DIGEST_A}"
    assert parse_env(f"TRACEGATE_IMAGE={reference}\n") == reference
    for bad in (
        f"TRACEGATE_IMAGE={reference}",
        f"TRACEGATE_IMAGE={reference}\nEXTRA=1\n",
        f"TRACEGATE_IMAGE ={reference}\n",
        "TRACEGATE_IMAGE=latest\n",
        f"TRACEGATE_IMAGE={XRAY_IMAGE}:latest\n",
    ):
        with pytest.raises(ArtifactError):
            parse_env(bad)


@pytest.mark.parametrize(
    "registry",
    (
        {"schema_version": 2, "components": {}},
        {"schema_version": 1},
        {"schema_version": 1, "components": {}, "extra": 1},
        {"schema_version": 1, "components": {"Xray": REGISTRY["components"]["xray"]}},
        {
            "schema_version": 1,
            "components": {"xray": {**REGISTRY["components"]["xray"], "image": f"{XRAY_IMAGE}:latest"}},
        },
        {
            "schema_version": 1,
            "components": {"xray": {**REGISTRY["components"]["xray"], "image": f"{XRAY_IMAGE}@{DIGEST_A}"}},
        },
        {
            "schema_version": 1,
            "components": {"xray": {k: v for k, v in REGISTRY["components"]["xray"].items() if k != "units"}},
        },
        {
            "schema_version": 1,
            "components": {"xray": {**REGISTRY["components"]["xray"], "units": []}},
        },
        {
            "schema_version": 1,
            "components": {"xray": {**REGISTRY["components"]["xray"], "container_prefixes": []}},
        },
        {
            "schema_version": 1,
            "components": {"xray": {**REGISTRY["components"]["xray"], "surprise": True}},
        },
    ),
)
def test_load_registry_rejects_malformed_registries(tmp_path: Path, registry: dict) -> None:
    path = tmp_path / "artifacts.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    with pytest.raises(RegistryError):
        load_registry(path)


def test_load_registry_rejects_missing_and_non_json_files(tmp_path: Path) -> None:
    with pytest.raises(RegistryError):
        load_registry(tmp_path / "missing.json")
    path = tmp_path / "artifacts.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RegistryError):
        load_registry(path)


def test_store_never_leaves_temp_files_behind(tmp_path: Path) -> None:
    store, docker = make_store(tmp_path)
    xray_running(docker)
    store.capture("xray")
    docker.pull_results[f"{TELEMT_IMAGE}:latest"] = f"{TELEMT_IMAGE}@{DIGEST_B}"
    store.stage("telemt")
    store.promote("telemt", DIGEST_B)

    leftovers = [p for p in (tmp_path / "store").rglob("*") if p.name.endswith(".tmp") or ".tmp" in p.name]
    assert leftovers == []


# -- CLI ---------------------------------------------------------------------


def _run_cli(tmp_path: Path, docker: FakeDocker, *argv: str) -> tuple[int, str, str]:
    registry_path = tmp_path / "artifacts.json"
    registry_path.write_text(json.dumps(REGISTRY), encoding="utf-8")
    stdout, stderr = io.StringIO(), io.StringIO()
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(svc, "_default_runner", docker)
        monkey.setenv("TRACEGATE_ARTIFACTS_DIR", str(tmp_path / "store"))
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["--registry", str(registry_path), *argv])
    finally:
        monkey.undo()
    return code, stdout.getvalue(), stderr.getvalue()


def test_cli_components_json_is_stable(tmp_path: Path) -> None:
    code, stdout, _ = _run_cli(tmp_path, FakeDocker(), "components", "--json")
    assert code == 0
    payload = json.loads(stdout)
    assert sorted(payload["components"]) == ["hysteria", "telemt", "wstunnel", "xray"]
    assert payload["components"]["xray"]["image"] == XRAY_IMAGE


def test_cli_verify_exit_codes_and_json(tmp_path: Path) -> None:
    docker = FakeDocker()
    code, stdout, _ = _run_cli(tmp_path, docker, "verify", "--all", "--json")
    assert code == 1
    problems = json.loads(stdout)["problems"]
    assert {p["code"] for p in problems} == {"active-missing"}

    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_A}"] = [f"{XRAY_IMAGE}@{DIGEST_A}"]
    store, _ = make_store(tmp_path, docker)
    store._atomic_write(store._env_path("active", "xray"), f"TRACEGATE_IMAGE={XRAY_IMAGE}@{DIGEST_A}\n")
    code, stdout, _ = _run_cli(tmp_path, docker, "verify", "xray", "--json")
    assert code == 0
    assert json.loads(stdout)["problems"] == []


def test_cli_capture_via_units_and_status_drift(tmp_path: Path) -> None:
    docker = FakeDocker()
    xray_running(docker)
    code, stdout, _ = _run_cli(tmp_path, docker, "capture", "--units", "tracegate-xray@transit.service", "--json")
    assert code == 0
    result = json.loads(stdout)["results"][0]
    assert result["reference"] == f"{XRAY_IMAGE}@{DIGEST_A}"
    assert result["noop"] is False

    code, stdout, _ = _run_cli(tmp_path, docker, "status", "xray", "--json")
    assert code == 0
    status = json.loads(stdout)["components"][0]
    assert status["drift"] is False
    assert status["active"] == f"{XRAY_IMAGE}@{DIGEST_A}"


def test_cli_stage_and_promote(tmp_path: Path) -> None:
    docker = FakeDocker()
    docker.pull_results[f"{WSTUNNEL_IMAGE}:latest"] = f"{WSTUNNEL_IMAGE}@{DIGEST_C}"
    code, stdout, _ = _run_cli(tmp_path, docker, "stage", "wstunnel", "--json")
    assert code == 0
    assert json.loads(stdout)["reference"] == f"{WSTUNNEL_IMAGE}@{DIGEST_C}"

    code, stdout, _ = _run_cli(tmp_path, docker, "promote", "wstunnel", DIGEST_C, "--json")
    assert code == 0
    payload = json.loads(stdout)
    assert payload["units"] == ["tracegate-wstunnel-wireguard.service"]
    assert payload["reference"] == f"{WSTUNNEL_IMAGE}@{DIGEST_C}"


def test_cli_exit_code_two_for_usage_errors(tmp_path: Path) -> None:
    docker = FakeDocker()
    code, _, stderr = _run_cli(tmp_path, docker, "capture")
    assert code == 2 and "component" in stderr
    code, _, stderr = _run_cli(tmp_path, docker, "verify", "nosuch")
    assert code == 2 and "unknown component" in stderr
    code, _, _ = _run_cli(tmp_path, docker, "capture", "--all", "xray")
    assert code == 2
    code, _, _ = _run_cli(tmp_path, docker, "promote", "xray", "latest")
    assert code == 1
    code, _, _ = _run_cli(tmp_path, docker, "stage", "nosuch")
    assert code == 2


def test_cli_rollback(tmp_path: Path) -> None:
    docker = FakeDocker()
    xray_running(docker)
    _run_cli(tmp_path, docker, "capture", "xray")
    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_A}"] = [f"{XRAY_IMAGE}@{DIGEST_A}"]
    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_B}"] = [f"{XRAY_IMAGE}@{DIGEST_B}"]
    _run_cli(tmp_path, docker, "promote", "xray", DIGEST_B)

    code, stdout, _ = _run_cli(tmp_path, docker, "rollback", "xray", "--json")
    assert code == 0
    payload = json.loads(stdout)
    assert payload["active"] == f"{XRAY_IMAGE}@{DIGEST_A}"


def test_cli_promote_already_active_exits_zero(tmp_path: Path) -> None:
    docker = FakeDocker()
    xray_running(docker)
    _run_cli(tmp_path, docker, "capture", "xray")
    docker.repo_digests[f"{XRAY_IMAGE}@{DIGEST_A}"] = [f"{XRAY_IMAGE}@{DIGEST_A}"]

    code, stdout, _ = _run_cli(tmp_path, docker, "promote", "xray", DIGEST_A, "--json")
    assert code == 0
    payload = json.loads(stdout)
    assert payload["already_active"] is True
    assert payload["reference"] == f"{XRAY_IMAGE}@{DIGEST_A}"

    code, stdout, _ = _run_cli(tmp_path, docker, "promote", "xray", DIGEST_A)
    assert code == 0
    assert "already active" in stdout


def test_cli_status_unknown_running_state_in_human_and_json(tmp_path: Path) -> None:
    docker = FakeDocker()
    docker.docker_unavailable = True

    code, stdout, _ = _run_cli(tmp_path, docker, "status", "xray", "--json")
    assert code == 0
    status = json.loads(stdout)["components"][0]
    assert status["running"] == []
    assert "Docker daemon" in status["running_error"]
    assert status["drift"] is None

    code, stdout, _ = _run_cli(tmp_path, docker, "status", "xray")
    assert code == 0
    assert "running: unknown" in stdout
    assert "drift: unknown" in stdout


def test_cli_human_output_names_next_step(tmp_path: Path) -> None:
    docker = FakeDocker()
    docker.pull_results[f"{WSTUNNEL_IMAGE}:latest"] = f"{WSTUNNEL_IMAGE}@{DIGEST_C}"
    code, stdout, stderr = _run_cli(tmp_path, docker, "stage", "wstunnel")
    assert code == 0, stderr
    assert "tracegate-artifacts promote wstunnel" in stdout


def test_normalize_repo_strips_docker_hub_host_and_official_library_prefix() -> None:
    from tracegate.services.artifacts import normalize_repo

    assert normalize_repo("docker.io/library/nginx") == "nginx"
    assert normalize_repo("library/nginx") == "nginx"
    assert normalize_repo("docker.io/tobyxdd/hysteria") == "tobyxdd/hysteria"
    assert normalize_repo("index.docker.io/prom/prometheus") == "prom/prometheus"
    assert normalize_repo("ghcr.io/xtls/xray-core") == "ghcr.io/xtls/xray-core"
    assert normalize_repo("library/team/app") == "library/team/app"
