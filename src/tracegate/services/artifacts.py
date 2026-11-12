"""Local artifact store for engine images.

Tracegate engine units never pull at start. Each component records its
active image by immutable digest in a local store; ``stage`` is the only
operation that pulls, run by the operator or by the engine update supervisor
(which pulls by digest after its soak period).

This module is standard-library only: it must import without the project's
third-party dependencies and must never call docker except through the
injected runner, so tests run without a docker daemon.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import re
import subprocess
from typing import Any, Protocol


DEFAULT_ROOT = Path("/var/lib/tracegate/artifacts")

_NAME_RE = re.compile(r"^[a-z0-9-]+$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ENV_PREFIX = "TRACEGATE_IMAGE="
# A repo reference may not carry a tag or digest; registries with an explicit
# port (host:5000/repo) are not used by any tracked component.
_REPO_RE = re.compile(r"^[a-z0-9]+(?:(?:[._-][a-z0-9]+)+)?(?:/[a-z0-9]+(?:(?:[._-][a-z0-9]+)+)?)*$")
_DOCKER_HUB_HOSTS = ("docker.io/", "index.docker.io/", "registry-1.docker.io/")


def normalize_repo(repo: str) -> str:
    """Canonical spelling used only for repo comparison.

    Docker reports Docker Hub RepoDigests in the familiar form (no registry
    host, and no ``library/`` prefix for official images) while pulls accept
    the ``docker.io/...`` spelling. Stored references always keep the registry
    file's spelling; two repos are equal when their normalised forms match.
    """
    normalized = repo
    for host in _DOCKER_HUB_HOSTS:
        if normalized.startswith(host):
            normalized = normalized[len(host):]
            break
    official = "library/"
    if normalized.startswith(official) and "/" not in normalized[len(official):]:
        normalized = normalized[len(official):]
    return normalized


class ArtifactError(RuntimeError):
    """An operation was refused or the store/docker state is unusable."""


class RegistryError(ArtifactError):
    """The registry file is malformed."""


class Runner(Protocol):
    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]: ...


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True)


UPDATE_TRACKS = ("channel", "semver")
UPDATE_POLICIES = ("auto", "notify")
HOST_ROLES = ("endpoint", "entry")
# A semver allow pattern pins one major version: "v2.*", "3.*".
_ALLOW_RE = re.compile(r"^(v?)(0|[1-9][0-9]*)\.\*$")


@dataclass(frozen=True)
class UpdateSpec:
    """How the engine update supervisor follows a component upstream."""

    track: str
    allow: str | None = None


@dataclass(frozen=True)
class Component:
    name: str
    image: str
    channel: str
    units: tuple[str, ...]
    container_prefixes: tuple[str, ...]
    update: UpdateSpec | None = None
    # (role, policy) pairs; a role without an entry is "notify".
    policy: tuple[tuple[str, str], ...] = ()

    def policy_for(self, role: str) -> str:
        for policy_role, value in self.policy:
            if policy_role == role:
                return value
        return "notify"


@dataclass(frozen=True)
class Registry:
    schema_version: int
    components: dict[str, Component]

    def component_for_unit(self, unit_name: str) -> Component | None:
        template = unit_name
        if "@" in unit_name:
            template = unit_name.split("@", 1)[0] + "@.service"
        for component in self.components.values():
            if template in component.units:
                return component
        return None


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RegistryError(message)


def _validate_repo(value: Any, *, label: str) -> str:
    _require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    _require("@" not in value, f"{label} must not contain a digest: {value}")
    last_segment = value.rsplit("/", 1)[-1]
    _require(":" not in last_segment, f"{label} must not contain a tag: {value}")
    _require(_REPO_RE.match(value) is not None, f"{label} is not a valid image repo: {value}")
    return value


def _validate_update(name: str, value: Any) -> UpdateSpec:
    _require(isinstance(value, dict), f"component {name} update must be an object")
    track = value.get("track")
    _require(track in UPDATE_TRACKS, f"component {name} update.track must be one of {', '.join(UPDATE_TRACKS)}")
    if track == "channel":
        _require(set(value) == {"track"}, f"component {name} update with track channel takes no other keys")
        return UpdateSpec(track="channel")
    _require(set(value) == {"track", "allow"}, f"component {name} update with track semver needs exactly track and allow")
    allow = value["allow"]
    _require(
        isinstance(allow, str) and _ALLOW_RE.match(allow) is not None,
        f"component {name} update.allow must pin one major version like v2.* or 13.*: {allow!r}",
    )
    return UpdateSpec(track="semver", allow=allow)


def _validate_policy(name: str, value: Any) -> tuple[tuple[str, str], ...]:
    _require(isinstance(value, dict), f"component {name} policy must be an object")
    pairs: list[tuple[str, str]] = []
    for role, policy in value.items():
        _require(role in HOST_ROLES, f"component {name} policy has an unknown role: {role!r}")
        _require(policy in UPDATE_POLICIES, f"component {name} policy for {role} must be auto or notify")
        pairs.append((role, policy))
    return tuple(pairs)


def load_registry(path: Path) -> Registry:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RegistryError(f"registry file not found: {path}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"registry file is not valid JSON: {path}: {exc}") from exc
    _require(isinstance(payload, dict), "registry root must be an object")
    _require(set(payload) == {"schema_version", "components"}, "registry must contain exactly schema_version and components")
    _require(payload["schema_version"] == 1, f"unsupported registry schema_version: {payload['schema_version']!r}")
    raw_components = payload["components"]
    _require(isinstance(raw_components, dict) and raw_components, "registry components must be a non-empty object")

    components: dict[str, Component] = {}
    for name, spec in raw_components.items():
        _require(isinstance(name, str) and _NAME_RE.match(name) is not None, f"invalid component name: {name!r}")
        _require(isinstance(spec, dict), f"component {name} must be an object")
        required_keys = {"image", "channel", "units", "container_prefixes"}
        _require(
            required_keys <= set(spec) <= required_keys | {"update", "policy"},
            f"component {name} must contain exactly image, channel, units and container_prefixes "
            "(plus optional update and policy)",
        )
        image = _validate_repo(spec["image"], label=f"component {name} image")
        _require(isinstance(spec["channel"], str) and spec["channel"], f"component {name} channel must be a non-empty string")
        units = spec["units"]
        _require(isinstance(units, list) and units, f"component {name} units must be a non-empty list")
        for unit in units:
            _require(isinstance(unit, str) and unit.endswith(".service"), f"component {name} has an invalid unit: {unit!r}")
        prefixes = spec["container_prefixes"]
        _require(
            isinstance(prefixes, list) and prefixes,
            f"component {name} container_prefixes must be a non-empty list",
        )
        for prefix in prefixes:
            _require(isinstance(prefix, str) and prefix, f"component {name} has an invalid container prefix: {prefix!r}")
        components[name] = Component(
            name=name,
            image=image,
            channel=spec["channel"],
            units=tuple(units),
            container_prefixes=tuple(prefixes),
            update=_validate_update(name, spec["update"]) if "update" in spec else None,
            policy=_validate_policy(name, spec["policy"]) if "policy" in spec else (),
        )
    return Registry(schema_version=1, components=components)


def parse_reference(reference: str, *, expected_repo: str | None = None) -> tuple[str, str]:
    """Validate a stored reference `<repo>@sha256:<64 hex>` and return (repo, digest)."""
    repo, separator, digest = reference.partition("@")
    if not separator or not repo or not digest.startswith("sha256:"):
        raise ArtifactError(f"not a digest reference (<repo>@sha256:<digest>): {reference}")
    hexdigits = digest[len("sha256:"):]
    if _DIGEST_RE.match(hexdigits) is None:
        raise ArtifactError(f"invalid sha256 digest in reference: {reference}")
    _validate_repo(repo, label="reference repo")
    if expected_repo is not None and normalize_repo(repo) != normalize_repo(expected_repo):
        raise ArtifactError(f"reference belongs to {repo}, expected {expected_repo}: {reference}")
    return repo, digest


def format_env(reference: str) -> str:
    parse_reference(reference)
    return f"{_ENV_PREFIX}{reference}\n"


def parse_env(text: str) -> str:
    """Return the reference from an env file body, or raise ArtifactError."""
    if not text.endswith("\n") or text.count("\n") != 1 or not text.startswith(_ENV_PREFIX):
        raise ArtifactError("env file must contain exactly one TRACEGATE_IMAGE=<repo>@sha256:<digest> line")
    reference = text[len(_ENV_PREFIX):-1]
    parse_reference(reference)
    return reference


def components_for_units(registry: Registry, unit_names: list[str]) -> list[str]:
    """Map unit names (instances included) to component names, in registry order."""
    selected: set[str] = set()
    for unit_name in unit_names:
        component = registry.component_for_unit(unit_name)
        if component is not None:
            selected.add(component.name)
    return [name for name in registry.components if name in selected]


@dataclass(frozen=True)
class Problem:
    component: str
    code: str
    message: str


@dataclass(frozen=True)
class CaptureResult:
    component: str
    reference: str | None
    noop: bool


@dataclass(frozen=True)
class RunningContainer:
    name: str
    digest: str


@dataclass(frozen=True)
class ComponentStatus:
    component: str
    active: str | None
    last_good: str | None
    candidates: tuple[dict[str, Any], ...]
    running: tuple[RunningContainer, ...]
    running_error: str | None
    drift: bool | None


@dataclass(frozen=True)
class PromoteResult:
    units: list[str]
    reference: str
    already_active: bool


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ArtifactStore:
    def __init__(
        self,
        root: Path,
        registry: Registry,
        runner: Runner | None = None,
    ) -> None:
        self.root = Path(root)
        self.registry = registry
        self.runner = runner if runner is not None else _default_runner

    # -- store layout ----------------------------------------------------

    def _component(self, name: str) -> Component:
        component = self.registry.components.get(name)
        if component is None:
            known = ", ".join(sorted(self.registry.components))
            raise ArtifactError(f"unknown component: {name} (known: {known})")
        return component

    def _env_path(self, section: str, component: str) -> Path:
        return self.root / section / f"{component}.env"

    def _candidates_path(self, component: str) -> Path:
        return self.root / "candidates" / f"{component}.json"

    def _ensure_dir(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o755)

    def _atomic_write(self, path: Path, content: str) -> None:
        self._ensure_dir(path.parent)
        temporary = path.with_name(f"{path.name}.tmp{os.getpid()}")
        try:
            temporary.write_text(content, encoding="utf-8")
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _journal(
        self,
        action: str,
        component: str,
        *,
        reference: str | None = None,
        previous: str | None = None,
        detail: str | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "time": _utc_now(),
            "action": action,
            "component": component,
            "reference": reference,
            "previous": previous,
            "detail": detail,
        }
        self._ensure_dir(self.root)
        with (self.root / "journal.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        os.chmod(self.root / "journal.jsonl", 0o644)

    def record(
        self,
        action: str,
        component: str,
        *,
        reference: str | None = None,
        previous: str | None = None,
        detail: str | None = None,
    ) -> None:
        """Append an entry to the artifact journal (used by the update supervisor).

        ``component`` "*" records a store-wide action such as an update hold.
        """
        name = component if component == "*" else self._component(component).name
        self._journal(action, name, reference=reference, previous=previous, detail=detail)

    def _read_env(self, section: str, component: str) -> str | None:
        path = self._env_path(section, component)
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        return parse_env(text)

    def read_active(self, component_name: str) -> str | None:
        """Return the active digest reference for a component, or None."""
        return self._read_env("active", self._component(component_name).name)

    def read_last_good(self, component_name: str) -> str | None:
        """Return the last-good digest reference for a component, or None."""
        return self._read_env("last-good", self._component(component_name).name)

    # -- docker helpers ---------------------------------------------------

    def _docker(self, argv: list[str], *, what: str) -> str:
        result = self.runner(["docker", *argv])
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            raise ArtifactError(f"docker {what} failed: {stderr or 'no output'}")
        return result.stdout

    def _repo_digest(self, image: str, repo: str) -> str:
        """Resolve the digest of a local image for the component repo."""
        output = self._docker(
            ["image", "inspect", "--format", "{{json .RepoDigests}}", image],
            what=f"image inspect {image}",
        ).strip()
        try:
            repo_digests = json.loads(output)
        except json.JSONDecodeError as exc:
            raise ArtifactError(f"could not parse RepoDigests for {image}: {output!r}") from exc
        if not isinstance(repo_digests, list):
            raise ArtifactError(f"unexpected RepoDigests for {image}: {output!r}")
        expected = normalize_repo(repo)
        for entry in repo_digests:
            if isinstance(entry, str) and "@" in entry:
                entry_repo, entry_digest = entry.rsplit("@", 1)
                if normalize_repo(entry_repo) == expected:
                    return entry
        raise ArtifactError(
            f"local image {image} has no repo digest for {repo}; "
            "the registry did not return a digest (image built locally?)"
        )

    def _has_repo_digest(self, image: str, repo: str, digest: str) -> bool:
        output = self._docker(
            ["image", "inspect", "--format", "{{json .RepoDigests}}", image],
            what=f"image inspect {image}",
        ).strip()
        try:
            repo_digests = json.loads(output)
        except json.JSONDecodeError as exc:
            raise ArtifactError(f"could not parse RepoDigests for {image}: {output!r}") from exc
        if not isinstance(repo_digests, list):
            raise ArtifactError(f"unexpected RepoDigests for {image}: {output!r}")
        expected = normalize_repo(repo)
        for entry in repo_digests:
            if isinstance(entry, str) and "@" in entry:
                entry_repo, entry_digest = entry.rsplit("@", 1)
                if normalize_repo(entry_repo) == expected and entry_digest == digest:
                    return True
        return False

    def _running_containers(self, component: Component) -> list[RunningContainer]:
        output = self._docker(
            ["ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"],
            what="ps",
        )
        containers: list[RunningContainer] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            container_id, separator, name = line.partition("\t")
            if not separator or not any(name.startswith(prefix) for prefix in component.container_prefixes):
                continue
            image_id = self._docker(
                ["inspect", "--format", "{{.Image}}", container_id.strip()],
                what=f"inspect {name}",
            ).strip()
            repo_digest = self._repo_digest(image_id, component.image)
            digest = repo_digest.split("@", 1)[1]
            containers.append(RunningContainer(name=name, digest=digest))
        return containers

    def _image_present(self, reference: str) -> bool:
        result = self.runner(["docker", "image", "inspect", reference])
        return result.returncode == 0

    # -- operations --------------------------------------------------------

    def capture(self, component_name: str, *, from_container: str | None = None) -> CaptureResult:
        """Record the digest of the currently running (or locally tagged) image as active."""
        component = self._component(component_name)
        existing = self._read_env("active", component.name)
        if existing is not None:
            return CaptureResult(component=component.name, reference=existing, noop=True)

        running = self._running_containers(component)
        detail: str | None = None
        if running:
            by_name = {container.name: container for container in running}
            if from_container is not None:
                chosen = by_name.get(from_container)
                if chosen is None:
                    known = ", ".join(sorted(by_name))
                    raise ArtifactError(
                        f"container {from_container} is not running for {component.name} (running: {known})"
                    )
                digest = chosen.digest
                detail = f"from-container {from_container}"
            else:
                digests = {container.digest for container in running}
                if len(digests) > 1:
                    lines = "\n".join(
                        f"  {container.name} -> {container.digest}" for container in running
                    )
                    raise ArtifactError(
                        f"running containers of {component.name} use different digests:\n{lines}\n"
                        f"choose one with: tracegate-artifacts capture {component.name} --from-container NAME"
                    )
                digest = digests.pop()
        else:
            if from_container is not None:
                raise ArtifactError(
                    f"--from-container {from_container} was given but no container of "
                    f"{component.name} is running"
                )
            tagged = f"{component.image}:{component.channel}"
            if not self._image_present(tagged):
                raise ArtifactError(
                    f"no running containers for {component.name} and {tagged} is not available locally; "
                    f"run: tracegate-artifacts stage {component.name}"
                )
            digest = self._repo_digest(tagged, component.image).split("@", 1)[1]

        reference = f"{component.image}@{digest}"
        self._atomic_write(self._env_path("active", component.name), format_env(reference))
        self._journal("capture", component.name, reference=reference, detail=detail)
        return CaptureResult(component=component.name, reference=reference, noop=False)

    def stage(self, component_name: str, *, tag: str | None = None, digest: str | None = None) -> str:
        """Fetch a candidate image. The only operation that pulls.

        With ``digest`` the image is pulled by that immutable digest (``tag``
        is then only recorded as a label) and the pulled image must report the
        same repo digest; otherwise the tag (default: the channel) is pulled.
        """
        component = self._component(component_name)
        if digest is not None:
            if not digest.startswith("sha256:") or _DIGEST_RE.match(digest[len("sha256:"):]) is None:
                raise ArtifactError(f"invalid digest for {component.name}: {digest!r}")
            if tag is not None and (not tag or any(char in tag for char in "@:")):
                raise ArtifactError(f"invalid tag for {component.name}: {tag!r}")
            reference = f"{component.image}@{digest}"
            self._docker(["pull", reference], what=f"pull {reference}")
            if not self._has_repo_digest(reference, component.image, digest):
                raise ArtifactError(
                    f"pulled image does not report the expected digest {digest} for {component.image}"
                )
            detail = f"digest {digest}" + (f" tag {tag}" if tag else "")
        else:
            tag = tag or component.channel
            if not tag or any(char in tag for char in "@:"):
                raise ArtifactError(f"invalid tag for {component.name}: {tag!r}")
            tagged = f"{component.image}:{tag}"
            self._docker(["pull", tagged], what=f"pull {tagged}")
            pulled = self._repo_digest(tagged, component.image).split("@", 1)[1]
            reference = f"{component.image}@{pulled}"
            detail = f"tag {tag}"

        path = self._candidates_path(component.name)
        try:
            candidates = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            candidates = []
        if not isinstance(candidates, list):
            raise ArtifactError(f"candidate store is corrupt: {path}")
        candidates.append({"reference": reference, "tag": tag, "staged_at": _utc_now()})
        self._atomic_write(path, json.dumps(candidates, indent=2) + "\n")
        self._journal("stage", component.name, reference=reference, detail=detail)
        return reference

    def image_present(self, reference: str) -> bool:
        return self._image_present(reference)

    def promote(self, component_name: str, reference: str) -> PromoteResult:
        """Make a digest reference active. Returns the component's unit names."""
        component = self._component(component_name)
        if reference.startswith("sha256:"):
            full = f"{component.image}@{reference}"
        elif "@" in reference:
            repo, digest = parse_reference(reference)
            if normalize_repo(repo) != normalize_repo(component.image):
                raise ArtifactError(
                    f"reference {reference} does not belong to {component.image}"
                )
            # Keep the registry file's spelling in everything we store.
            full = f"{component.image}@{digest}"
        else:
            raise ArtifactError(
                f"promote requires a digest reference (<repo>@sha256:<digest> or sha256:<digest>), got: {reference}"
            )
        parse_reference(full, expected_repo=component.image)
        if not self._image_present(full):
            raise ArtifactError(f"image is not present locally: {full}; run: tracegate-artifacts stage {component.name}")

        previous = self._read_env("active", component.name)
        if previous == full:
            return PromoteResult(units=list(component.units), reference=full, already_active=True)
        if previous is not None:
            self._atomic_write(self._env_path("last-good", component.name), format_env(previous))
        self._atomic_write(self._env_path("active", component.name), format_env(full))
        self._journal("promote", component.name, reference=full, previous=previous)
        return PromoteResult(units=list(component.units), reference=full, already_active=False)

    def rollback(self, component_name: str) -> tuple[str, str]:
        """Swap active and last-good. Returns (new active, new last-good)."""
        component = self._component(component_name)
        active = self._read_env("active", component.name)
        last_good = self._read_env("last-good", component.name)
        if last_good is None:
            raise ArtifactError(f"no last-good artifact recorded for {component.name}")
        if not self._image_present(last_good):
            raise ArtifactError(f"last-good image is not present locally: {last_good}")
        self._atomic_write(self._env_path("active", component.name), format_env(last_good))
        if active is not None:
            self._atomic_write(self._env_path("last-good", component.name), format_env(active))
        self._journal("rollback", component.name, reference=last_good, previous=active)
        return last_good, active if active is not None else last_good

    def restore_last_good(self, component_name: str, reference: str | None) -> None:
        """Rewrite last-good after an automatic rollback.

        ``rollback`` swaps active and last-good, which would leave a rejected
        candidate recorded as last-good. The update supervisor restores the
        last-good it saw before promoting (or removes it when there was none).
        """
        component = self._component(component_name)
        path = self._env_path("last-good", component.name)
        current = self._read_env("last-good", component.name)
        if reference is None:
            if path.exists():
                path.unlink()
        else:
            parse_reference(reference, expected_repo=component.image)
            self._atomic_write(path, format_env(reference))
        self._journal("restore-last-good", component.name, reference=reference, previous=current)

    def _verify_component(self, component: Component) -> list[Problem]:
        problems: list[Problem] = []
        path = self._env_path("active", component.name)
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            problems.append(
                Problem(
                    component.name,
                    "active-missing",
                    f"no active artifact recorded; run: tracegate-artifacts capture {component.name}",
                )
            )
            return problems
        try:
            reference = parse_env(text)
        except ArtifactError as exc:
            problems.append(Problem(component.name, "active-format", f"{path} is malformed: {exc}"))
            return problems
        repo, _ = parse_reference(reference)
        if normalize_repo(repo) != normalize_repo(component.image):
            problems.append(
                Problem(
                    component.name,
                    "repo-mismatch",
                    f"{path} records {repo}, expected {component.image}",
                )
            )
            return problems
        if not self._image_present(reference):
            problems.append(
                Problem(
                    component.name,
                    "image-absent",
                    f"active image is not present locally: {reference}",
                )
            )
        return problems

    def verify(self, component_names: list[str]) -> list[Problem]:
        problems: list[Problem] = []
        for name in component_names:
            problems.extend(self._verify_component(self._component(name)))
        return problems

    def status(self, component_names: list[str]) -> list[ComponentStatus]:
        statuses: list[ComponentStatus] = []
        for name in component_names:
            component = self._component(name)
            active = self._read_env("active", component.name)
            last_good = self._read_env("last-good", component.name)
            candidates_path = self._candidates_path(component.name)
            try:
                candidates = tuple(json.loads(candidates_path.read_text(encoding="utf-8")))
            except (FileNotFoundError, json.JSONDecodeError):
                candidates = ()
            try:
                running = tuple(self._running_containers(component))
                running_error = None
            except ArtifactError as exc:
                running = ()
                running_error = str(exc)
            active_digest = active.split("@", 1)[1] if active else None
            drift = None if running_error is not None else any(
                container.digest != active_digest for container in running
            )
            statuses.append(
                ComponentStatus(
                    component=component.name,
                    active=active,
                    last_good=last_good,
                    candidates=candidates,
                    running=running,
                    running_error=running_error,
                    drift=drift,
                )
            )
        return statuses

    def journal_entries(self) -> list[dict[str, Any]]:
        path = self.root / "journal.jsonl"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        entries: list[dict[str, Any]] = []
        for line in lines:
            if line.strip():
                entries.append(json.loads(line))
        return entries
