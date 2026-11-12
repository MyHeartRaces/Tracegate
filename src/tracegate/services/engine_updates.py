"""Engine update supervisor (Tracegate 4.1).

Discovers new upstream engine images without pulling, lets each candidate
soak, stages it by digest through the artifact store (still the only pull),
checks it statically against the live runtime config and activates it only
where a complete set of authenticated probes proves that issued connections
keep working. Everything else is queued for the operator.

Activation for one component on one host is the only way this module touches
a running service: promote -> restart one unit -> probe -> ... and, on any
failure, rollback -> restart -> re-probe -> reject.

This module is standard-library only (like ``artifacts``); probes, docker and
systemctl are injected so tests run without a daemon or network.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import time
from typing import Any, Callable, Iterator, Protocol

from tracegate.services.artifacts import ArtifactError, ArtifactStore, Runner
from tracegate.services.engine_registry import RegistryClient, UpstreamError, select_semver

STATE_FILE = "updates.json"
HOLD_FILE = "updates.hold"
LOCK_FILE = "updates.lock"
DEFAULT_SOAK_DAYS = 3.0
STATE_SCHEMA_VERSION = 1

STATUSES = ("discovered", "staged", "checked", "pending-approval", "activated", "rejected")
WAITING = ("discovered", "staged", "checked", "pending-approval")
_HISTORY_LIMIT = 10
_EVIDENCE_LIMIT = 60

# Engine units per host role. Mirrors the engine part of ROLE_UNITS in
# deploy/host/tracegate-host-deploy (a test keeps both in sync). Order is the
# restart order used during activation.
ROLE_ENGINE_UNITS: dict[str, dict[str, tuple[str, ...]]] = {
    "endpoint": {
        "xray": ("tracegate-xray@transit.service", "tracegate-xray-ss2022.service"),
        "hysteria": ("tracegate-hysteria@transit.service", "tracegate-hysteria-salamander.service"),
        "shadowtls": ("tracegate-shadowtls-backhaul.service", "tracegate-shadowtls-backhaul2.service"),
        "telemt": ("tracegate-mtproto@transit.service",),
        "prometheus": ("tracegate-prometheus.service",),
        "grafana": ("tracegate-grafana.service",),
    },
    "entry": {
        "xray": (
            "tracegate-xray@entry.service",
            "tracegate-backhaul-fragment@1.service",
            "tracegate-backhaul-fragment@2.service",
        ),
        "hysteria": ("tracegate-hysteria@entry.service",),
        "shadowtls": ("tracegate-shadowtls-entry.service", "tracegate-shadowtls-entry2.service"),
    },
}


class UpdateError(RuntimeError):
    """An update operation was refused."""


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


@dataclass(frozen=True)
class Evidence:
    name: str
    ok: bool
    detail: str
    at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "at": self.at}


@dataclass(frozen=True)
class ProbePlan:
    complete: bool
    probes: tuple[str, ...]
    reason: str = ""


@dataclass(frozen=True)
class CheckResult:
    """Static check outcome: ok, fail (the image rejects the live config) or error (could not run)."""

    status: str
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True)
class ProbeContext:
    component: str
    units: tuple[str, ...]
    # unit -> digest its running container must use right now
    expected_digests: dict[str, str]
    # image reference used for synthetic clients
    client_image: str
    # probe results must be newer than this (epoch seconds)
    since: float
    phase: str


class Prober(Protocol):
    def plan(self, component: str) -> ProbePlan: ...

    def static_check(self, component: str, reference: str, units: tuple[str, ...]) -> CheckResult: ...

    def probe(self, context: ProbeContext) -> list[Evidence]: ...


# -- state ------------------------------------------------------------------


def empty_state(role: str | None) -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "role": role,
        "last_run": None,
        "last_run_ok": None,
        "last_success": None,
        "components": {},
    }


def read_state(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        raise UpdateError(f"update state is not valid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != STATE_SCHEMA_VERSION:
        raise UpdateError(f"update state has an unsupported format: {path}")
    if not isinstance(payload.get("components"), dict):
        raise UpdateError(f"update state has no components object: {path}")
    return payload


def write_private_atomic(path: Path, content: str) -> None:
    """Write ``content`` atomically with mode 0600."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp{os.getpid()}")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def metrics_snapshot(root: Path) -> dict[str, Any]:
    """Numbers the agent exports from updates.json (no secrets, no digests)."""
    root = Path(root)
    snapshot: dict[str, Any] = {
        "present": False,
        "role": "",
        "hold": (root / HOLD_FILE).exists(),
        "last_run": None,
        "last_success": None,
        "components": {},
    }
    try:
        state = read_state(root / STATE_FILE)
    except (UpdateError, OSError):
        return snapshot
    if state is None:
        return snapshot
    snapshot["present"] = True
    snapshot["role"] = str(state.get("role") or "")
    snapshot["last_run"] = parse_iso(state.get("last_run"))
    snapshot["last_success"] = parse_iso(state.get("last_success"))
    for name, component in sorted(state["components"].items()):
        candidates = component.get("candidates") if isinstance(component, dict) else None
        if not isinstance(candidates, dict):
            continue
        pending = 0
        rejected = 0
        last_rejected: float | None = None
        for candidate in candidates.values():
            if not isinstance(candidate, dict):
                continue
            status = candidate.get("status")
            if status == "pending-approval":
                pending += 1
            elif status == "rejected":
                rejected += 1
                at = parse_iso(candidate.get("rejected_at"))
                if at is not None and (last_rejected is None or at > last_rejected):
                    last_rejected = at
        snapshot["components"][name] = {
            "pending": pending,
            "rejected": rejected,
            "last_rejected": last_rejected,
        }
    return snapshot


def set_update_hold(
    store: ArtifactStore,
    on: bool,
    *,
    reason: str = "operator",
    now: Callable[[], float] = time.time,
) -> bool:
    """Create or remove the hold file that freezes automatic activation."""
    path = store.root / HOLD_FILE
    if on:
        if path.exists():
            return False
        write_private_atomic(path, json.dumps({"since": utc_iso(now()), "reason": reason}) + "\n")
        store.record("update-hold", "*", detail=f"on: {reason}")
        return True
    if not path.exists():
        return False
    path.unlink()
    store.record("update-hold", "*", detail=f"off: {reason}")
    return True


# -- supervisor ---------------------------------------------------------------


@dataclass
class RunReport:
    lines: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    activated: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    rolled_back: list[str] = field(default_factory=list)

    def note(self, line: str) -> None:
        self.lines.append(line)

    def error(self, line: str) -> None:
        self.errors.append(line)
        self.lines.append(f"error: {line}")

    @property
    def ok(self) -> bool:
        return not self.errors and not self.rolled_back

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "lines": self.lines,
            "errors": self.errors,
            "activated": self.activated,
            "rejected": self.rejected,
            "pending": self.pending,
            "rolled_back": self.rolled_back,
        }


class EngineUpdateSupervisor:
    def __init__(
        self,
        *,
        store: ArtifactStore,
        role: str,
        client: RegistryClient,
        prober: Prober,
        runner: Runner,
        soak_days: float = DEFAULT_SOAK_DAYS,
        now: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        settle_seconds: float = 5.0,
        unit_active_timeout: float = 60.0,
    ) -> None:
        if role not in ROLE_ENGINE_UNITS:
            raise UpdateError(f"unknown host role: {role!r} (expected endpoint or entry)")
        if soak_days < 0:
            raise UpdateError("soak days must not be negative")
        self.store = store
        self.root = store.root
        self.role = role
        self.client = client
        self.prober = prober
        self.runner = runner
        self.soak_seconds = float(soak_days) * 86400.0
        self.now = now
        self.sleep = sleep
        self.settle_seconds = settle_seconds
        self.unit_active_timeout = unit_active_timeout

    # -- paths, lock, hold --------------------------------------------------

    @property
    def state_path(self) -> Path:
        return self.root / STATE_FILE

    @property
    def hold_path(self) -> Path:
        return self.root / HOLD_FILE

    @contextmanager
    def locked(self) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.root / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UpdateError("another engine update operation is running") from exc
            yield
        finally:
            os.close(fd)

    def hold_active(self) -> bool:
        return self.hold_path.exists()

    def set_hold(self, on: bool, *, reason: str = "operator") -> bool:
        """Turn the hold on or off. Returns True when the state changed."""
        return set_update_hold(self.store, on, reason=reason, now=self.now)

    def load_state(self) -> dict[str, Any]:
        state = read_state(self.state_path)
        if state is None:
            state = empty_state(self.role)
        state["role"] = self.role
        return state

    def save_state(self, state: dict[str, Any]) -> None:
        write_private_atomic(self.state_path, json.dumps(state, indent=2, sort_keys=True) + "\n")

    # -- host model -----------------------------------------------------------

    def components_on_host(self) -> list[str]:
        units = ROLE_ENGINE_UNITS[self.role]
        return [
            name
            for name, component in self.store.registry.components.items()
            if name in units and component.update is not None
        ]

    def host_units(self, component: str) -> tuple[str, ...]:
        return ROLE_ENGINE_UNITS[self.role].get(component, ())

    def _active_digest(self, component: str) -> str | None:
        active = self.store.read_active(component)
        return active.split("@", 1)[1] if active else None

    # -- helpers ----------------------------------------------------------------

    def _component_state(self, state: dict[str, Any], component: str) -> dict[str, Any]:
        entry = state["components"].setdefault(component, {})
        entry.setdefault("candidates", {})
        entry.setdefault("last_discovery", None)
        return entry

    def _evidence(self, candidate: dict[str, Any], items: list[Evidence] | tuple[Evidence, ...]) -> None:
        stamp = utc_iso(self.now())
        log = candidate.setdefault("evidence", [])
        for item in items:
            log.append({**item.as_dict(), "at": item.at or stamp})
        del log[:-_EVIDENCE_LIMIT]

    def _set_status(self, component: str, candidate: dict[str, Any], status: str, *, reason: str | None = None) -> None:
        changed = candidate.get("status") != status or candidate.get("reason") != reason
        candidate["status"] = status
        candidate["reason"] = reason
        candidate["updated_at"] = utc_iso(self.now())
        if status == "rejected":
            candidate["rejected_at"] = candidate["updated_at"]
        if status == "activated":
            candidate["activated_at"] = candidate["updated_at"]
        if changed:
            self.store.record(
                f"update-{status}",
                component,
                reference=candidate.get("reference"),
                detail=reason,
            )

    def _soak_remaining(self, candidate: dict[str, Any]) -> float:
        if candidate.get("no_soak"):
            return 0.0
        first_seen = parse_iso(candidate.get("first_seen"))
        if first_seen is None:
            return self.soak_seconds
        return max(0.0, first_seen + self.soak_seconds - self.now())

    def _trim_history(self, component_state: dict[str, Any]) -> None:
        activated = sorted(
            (
                (candidate.get("activated_at") or "", digest)
                for digest, candidate in component_state["candidates"].items()
                if candidate.get("status") == "activated"
            ),
        )
        for _, digest in activated[:-_HISTORY_LIMIT]:
            del component_state["candidates"][digest]

    # -- discovery --------------------------------------------------------------

    def discover(self, state: dict[str, Any], report: RunReport) -> dict[str, str]:
        """Observe the newest upstream digest per component. Returns {component: digest} observed now."""
        observed: dict[str, str] = {}
        for name in self.components_on_host():
            component = self.store.registry.components[name]
            spec = component.update
            assert spec is not None
            entry = self._component_state(state, name)
            candidates: dict[str, Any] = entry["candidates"]
            stamp = utc_iso(self.now())
            try:
                if spec.track == "channel":
                    tag = component.channel
                else:
                    assert spec.allow is not None
                    selected = select_semver(self.client.tags(component.image), spec.allow)
                    if selected is None:
                        raise UpstreamError(f"no stable tag of {component.image} matches {spec.allow}")
                    tag = selected
                known = next(
                    (digest for digest, cand in candidates.items() if cand.get("tag") == tag),
                    None,
                )
                resolved = self.client.resolve(component.image, tag, known_digest=known)
            except UpstreamError as exc:
                entry["last_discovery"] = {"at": stamp, "ok": False, "error": str(exc), "tag": None, "digest": None}
                report.error(f"{name}: discovery failed: {exc}")
                continue
            digest = resolved.digest
            entry["last_discovery"] = {"at": stamp, "ok": True, "error": None, "tag": tag, "digest": digest}
            observed[name] = digest

            # Anything still waiting that is no longer the newest was withdrawn
            # or replaced upstream: drop it (the soak restarts for the new one).
            for old_digest in [d for d, cand in candidates.items() if d != digest and cand.get("status") in WAITING]:
                dropped = candidates.pop(old_digest)
                self.store.record(
                    "update-dropped",
                    name,
                    reference=dropped.get("reference"),
                    detail=f"no longer the newest upstream ({tag} -> {digest})",
                )
                report.note(f"{name}: dropped {old_digest} (replaced or withdrawn upstream)")

            active_digest = self._active_digest(name)
            candidate = candidates.get(digest)
            if digest == active_digest:
                if candidate is not None and candidate.get("status") in WAITING:
                    self._set_status(name, candidate, "activated", reason="already active")
                report.note(f"{name}: up to date ({tag})")
                continue
            if candidate is None:
                candidates[digest] = {
                    "digest": digest,
                    "tag": tag,
                    "reference": f"{component.image}@{digest}",
                    "first_seen": stamp,
                    "last_seen": stamp,
                    "status": "discovered",
                    "reason": None,
                    "no_soak": False,
                    "approved": False,
                    "evidence": [],
                    "updated_at": stamp,
                }
                self.store.record(
                    "update-discovered", name, reference=f"{component.image}@{digest}", detail=f"tag {tag}"
                )
                report.note(f"{name}: discovered {digest} ({tag})")
                continue
            candidate["last_seen"] = stamp
            if candidate.get("status") == "rejected":
                report.note(f"{name}: newest upstream {digest} is rejected; waiting for a newer image")
            elif candidate.get("status") == "activated":
                # It was activated here before but is no longer active: someone
                # rolled back by hand. Never re-activate it automatically.
                candidate["manual_only"] = True
                self._set_status(
                    name,
                    candidate,
                    "pending-approval",
                    reason="previously activated but no longer active (manual rollback?)",
                )
        return observed

    # -- stage / check / activate -------------------------------------------------

    def _stage(self, name: str, candidate: dict[str, Any], report: RunReport) -> bool:
        try:
            reference = self.store.stage(name, digest=candidate["digest"], tag=candidate.get("tag"))
        except ArtifactError as exc:
            self._evidence(candidate, [Evidence("stage", False, str(exc))])
            report.error(f"{name}: staging {candidate['digest']} failed: {exc}")
            return False
        candidate["reference"] = reference
        self._evidence(candidate, [Evidence("stage", True, f"pulled by digest {candidate['digest']}")])
        self._set_status(name, candidate, "staged")
        report.note(f"{name}: staged {candidate['digest']}")
        return True

    def _check(self, name: str, candidate: dict[str, Any], report: RunReport) -> bool:
        result = self.prober.static_check(name, candidate["reference"], self.host_units(name))
        self._evidence(candidate, list(result.evidence))
        if result.status == "ok":
            self._set_status(name, candidate, "checked")
            report.note(f"{name}: static check passed for {candidate['digest']}")
            return True
        if result.status == "fail":
            failed = "; ".join(f"{item.name}: {item.detail}" for item in result.evidence if not item.ok)
            # A check that also fails for the running version points at the
            # host environment, not at the candidate: never reject on that.
            active = self.store.read_active(name)
            if active and active != candidate["reference"]:
                baseline = self.prober.static_check(name, active, self.host_units(name))
                if baseline.status != "ok":
                    self._evidence(
                        candidate,
                        [Evidence("static-check-baseline", False, "the same check fails for the active version")],
                    )
                    self._queue(name, candidate, f"static check inconclusive (fails for active too): {failed}", report)
                    return False
            self._set_status(name, candidate, "rejected", reason=f"static check failed: {failed}")
            report.rejected.append(name)
            report.note(f"{name}: rejected {candidate['digest']} (static check failed)")
            return False
        report.error(f"{name}: static check could not run for {candidate['digest']}; will retry")
        return False

    def _auto_blockers(self, name: str) -> list[str]:
        component = self.store.registry.components[name]
        blockers: list[str] = []
        if component.policy_for(self.role) != "auto":
            blockers.append(f"policy is notify for {self.role}")
        plan = self.prober.plan(name)
        if not plan.complete:
            blockers.append(f"probe set incomplete: {plan.reason}")
        if self.hold_active():
            blockers.append("hold is on")
        return blockers

    def _queue(self, name: str, candidate: dict[str, Any], reason: str, report: RunReport) -> None:
        self._set_status(name, candidate, "pending-approval", reason=reason)
        report.pending.append(name)
        report.note(f"{name}: {candidate['digest']} awaits operator approval ({reason})")

    def _advance(
        self,
        name: str,
        candidate: dict[str, Any],
        state: dict[str, Any],
        report: RunReport,
        *,
        may_activate: bool,
    ) -> str:
        """Move one candidate forward. Returns 'idle', 'activated', 'failed' or 'deferred'."""
        if candidate["status"] == "discovered":
            remaining = self._soak_remaining(candidate)
            if remaining > 0:
                report.note(f"{name}: {candidate['digest']} soaking, eligible at {utc_iso(self.now() + remaining)}")
                return "idle"
            if not self._stage(name, candidate, report):
                return "idle"
        if candidate["status"] == "staged":
            if not self._check(name, candidate, report):
                return "idle"
        if candidate["status"] not in ("checked", "pending-approval"):
            return "idle"
        blockers = self._auto_blockers(name)
        if candidate.get("manual_only"):
            blockers.insert(0, "operator approval required (previously activated, later rolled back by hand)")
        if blockers:
            self._queue(name, candidate, "; ".join(blockers), report)
            return "idle"
        if not may_activate:
            report.note(f"{name}: activation deferred to the next run (one activation per run)")
            return "deferred"
        return self._activate(name, candidate, state, report, by="auto")

    def _restart(self, unit: str) -> tuple[bool, str]:
        result = self.runner(["systemctl", "restart", unit])
        if result.returncode != 0:
            return False, (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
        deadline = self.now() + self.unit_active_timeout
        while True:
            active = self.runner(["systemctl", "is-active", "--quiet", unit])
            if active.returncode == 0:
                break
            if self.now() >= deadline:
                return False, f"{unit} not active within {self.unit_active_timeout:.0f}s"
            self.sleep(1.0)
        if self.settle_seconds > 0:
            self.sleep(self.settle_seconds)
        return True, "active"

    def _activate(
        self,
        name: str,
        candidate: dict[str, Any],
        state: dict[str, Any],
        report: RunReport,
        *,
        by: str,
    ) -> str:
        component = self.store.registry.components[name]
        units = self.host_units(name)
        digest = candidate["digest"]
        reference = f"{component.image}@{digest}"
        active_before = self.store.read_active(name)
        last_good_before = self.store.read_last_good(name)
        if active_before is None:
            self._queue(name, candidate, "no active artifact recorded to roll back to", report)
            return "idle"
        old_digest = active_before.split("@", 1)[1]
        if not self.store.image_present(reference):
            self._evidence(candidate, [Evidence("stage", False, "staged image is no longer present locally")])
            self._set_status(name, candidate, "discovered", reason="staged image missing; re-stage")
            report.error(f"{name}: staged image {digest} is missing locally")
            return "idle"

        # Baseline: the probe set must pass before anything is switched, so a
        # post-switch failure can be attributed to the candidate.
        baseline = self.prober.probe(
            ProbeContext(
                component=name,
                units=units,
                expected_digests={unit: old_digest for unit in units},
                client_image=reference,
                since=self.now(),
                phase="baseline",
            )
        )
        self._evidence(candidate, [Evidence(f"baseline:{item.name}", item.ok, item.detail, item.at) for item in baseline])
        if not baseline or not all(item.ok for item in baseline):
            self._queue(name, candidate, "baseline probes failed before switching; nothing changed", report)
            return "idle"

        # Re-check hold and state immediately before the switch.
        if by == "auto" and self.hold_active():
            self._queue(name, candidate, "hold is on", report)
            return "idle"
        fresh = read_state(self.state_path) or empty_state(self.role)
        fresh_candidate = fresh["components"].get(name, {}).get("candidates", {}).get(digest)
        if fresh_candidate is not None and fresh_candidate.get("status") == "rejected":
            self._set_status(name, candidate, "rejected", reason=fresh_candidate.get("reason") or "rejected by operator")
            return "idle"
        if self.store.read_active(name) != active_before:
            self._queue(name, candidate, "active artifact changed during the run", report)
            return "idle"

        self.store.promote(name, reference)
        self.store.record("update-switch", name, reference=reference, previous=active_before, detail=f"by {by}")
        restarted: list[str] = []
        for unit in units:
            since = self.now()
            restarted.append(unit)
            ok, detail = self._restart(unit)
            self.store.record("update-restart", name, reference=reference, detail=f"{unit}: {detail}")
            results = [Evidence(f"restart:{unit}", ok, detail)]
            if ok:
                results.extend(
                    self.prober.probe(
                        ProbeContext(
                            component=name,
                            units=units,
                            expected_digests={u: (digest if u in restarted else old_digest) for u in units},
                            client_image=reference,
                            since=since,
                            phase=f"after {unit}",
                        )
                    )
                )
            self._evidence(candidate, results)
            failed = [item for item in results if not item.ok]
            if failed:
                reason = "; ".join(f"{item.name}: {item.detail}" for item in failed)
                self._rollback(name, candidate, restarted, active_before, last_good_before, reason, report)
                return "failed"

        self._set_status(name, candidate, "activated", reason=f"activated by {by} after passing probes")
        report.activated.append(name)
        report.note(f"{name}: activated {digest}")
        self._trim_history(self._component_state(state, name))
        return "activated"

    def _rollback(
        self,
        name: str,
        candidate: dict[str, Any],
        restarted: list[str],
        active_before: str,
        last_good_before: str | None,
        reason: str,
        report: RunReport,
    ) -> None:
        units = self.host_units(name)
        old_digest = active_before.split("@", 1)[1]
        report.rolled_back.append(name)
        report.note(f"{name}: post-switch probe failed, rolling back: {reason}")
        recovered = True
        try:
            self.store.rollback(name)
            self.store.restore_last_good(name, last_good_before)
        except ArtifactError as exc:
            recovered = False
            self._evidence(candidate, [Evidence("rollback", False, str(exc))])
        results: list[Evidence] = []
        if recovered:
            for unit in restarted:
                ok, detail = self._restart(unit)
                self.store.record("update-restart", name, reference=active_before, detail=f"rollback {unit}: {detail}")
                results.append(Evidence(f"rollback-restart:{unit}", ok, detail))
            results.extend(
                self.prober.probe(
                    ProbeContext(
                        component=name,
                        units=units,
                        expected_digests={unit: old_digest for unit in units},
                        client_image=active_before,
                        since=self.now(),
                        phase="after rollback",
                    )
                )
            )
            self._evidence(candidate, [Evidence(f"after-rollback:{item.name}", item.ok, item.detail, item.at) for item in results])
            recovered = all(item.ok for item in results)
        self._set_status(name, candidate, "rejected", reason=f"post-switch probe failed: {reason}")
        report.rejected.append(name)
        if not recovered:
            # The previous image does not pass either: freeze everything
            # automatic until the operator has looked at the host.
            self.set_hold(True, reason=f"{name}: probes still failing after rollback")
            report.error(f"{name}: probes still fail after rollback; automatic activation is now on hold")
        else:
            report.error(f"{name}: rolled back to {active_before}")

    # -- entry points -------------------------------------------------------------

    def run(self) -> RunReport:
        report = RunReport()
        with self.locked():
            state = self.load_state()
            state["last_run"] = utc_iso(self.now())
            observed = self.discover(state, report)
            may_activate = True
            for name in self.components_on_host():
                digest = observed.get(name)
                if digest is None:
                    continue
                candidate = self._component_state(state, name)["candidates"].get(digest)
                if candidate is None or candidate.get("status") not in WAITING:
                    continue
                outcome = self._advance(name, candidate, state, report, may_activate=may_activate)
                if outcome in ("activated", "failed"):
                    may_activate = False
                self.save_state(state)
            state["last_run_ok"] = report.ok
            if report.ok:
                state["last_success"] = state["last_run"]
            self.save_state(state)
        if not report.lines:
            report.note("nothing to do")
        return report

    def discover_only(self) -> RunReport:
        report = RunReport()
        with self.locked():
            state = self.load_state()
            self.discover(state, report)
            self.save_state(state)
        return report

    def _find_candidate(self, state: dict[str, Any], name: str, digest: str) -> tuple[str, dict[str, Any] | None]:
        if name not in self.store.registry.components:
            raise UpdateError(f"unknown component: {name}")
        if name not in self.components_on_host():
            raise UpdateError(f"{name} is not updated on a {self.role} host")
        if not digest.startswith("sha256:"):
            digest = f"sha256:{digest}"
        return digest, self._component_state(state, name)["candidates"].get(digest)

    def approve(self, name: str, digest: str, *, no_soak: bool = False) -> RunReport:
        report = RunReport()
        with self.locked():
            state = self.load_state()
            digest, candidate = self._find_candidate(state, name, digest)
            if candidate is None:
                raise UpdateError(f"{name}: {digest} is not a known candidate; run: tracegate-engine-update discover")
            if candidate.get("status") == "rejected":
                raise UpdateError(f"{name}: {digest} is rejected and is never activated")
            if candidate.get("status") == "activated" and self._active_digest(name) == digest:
                report.note(f"{name}: {digest} is already active")
                return report
            if not no_soak and self._soak_remaining(candidate) > 0:
                raise UpdateError(
                    f"{name}: {digest} is still soaking until "
                    f"{utc_iso(self.now() + self._soak_remaining(candidate))}; use --no-soak to override"
                )
            candidate["approved"] = True
            if no_soak:
                candidate["no_soak"] = True
            self.store.record("update-approve", name, reference=candidate.get("reference"), detail="no-soak" if no_soak else None)
            if candidate.get("status") == "activated":
                candidate["status"] = "checked"
            if candidate["status"] == "discovered" and not self._stage(name, candidate, report):
                self.save_state(state)
                return report
            if candidate["status"] == "staged" and not self._check(name, candidate, report):
                self.save_state(state)
                return report
            plan = self.prober.plan(name)
            if not plan.complete:
                self._evidence(
                    candidate,
                    [Evidence("approval", True, f"operator approval with an incomplete probe set: {plan.reason}")],
                )
                report.note(f"{name}: warning: activating with an incomplete probe set ({plan.reason})")
            self._activate(name, candidate, state, report, by="operator")
            self.save_state(state)
        return report

    def reject(self, name: str, digest: str, *, reason: str = "rejected by operator") -> RunReport:
        report = RunReport()
        with self.locked():
            state = self.load_state()
            digest, candidate = self._find_candidate(state, name, digest)
            if self._active_digest(name) == digest:
                raise UpdateError(
                    f"{name}: {digest} is the active artifact; roll it back with tracegate-artifacts first"
                )
            component = self.store.registry.components[name]
            if candidate is None:
                stamp = utc_iso(self.now())
                candidate = {
                    "digest": digest,
                    "tag": None,
                    "reference": f"{component.image}@{digest}",
                    "first_seen": stamp,
                    "last_seen": stamp,
                    "status": "discovered",
                    "reason": None,
                    "no_soak": False,
                    "approved": False,
                    "evidence": [],
                }
                self._component_state(state, name)["candidates"][digest] = candidate
            self._evidence(candidate, [Evidence("operator", False, reason)])
            self._set_status(name, candidate, "rejected", reason=reason)
            report.rejected.append(name)
            report.note(f"{name}: rejected {digest}")
            self.save_state(state)
        return report

    def status(self) -> dict[str, Any]:
        state = read_state(self.state_path) or empty_state(self.role)
        components: dict[str, Any] = {}
        for name in self.components_on_host():
            component = self.store.registry.components[name]
            entry = state["components"].get(name) or {}
            try:
                plan = self.prober.plan(name)
                plan_payload = {"complete": plan.complete, "probes": list(plan.probes), "reason": plan.reason}
            except Exception as exc:  # noqa: BLE001 - status must always render
                plan_payload = {"complete": False, "probes": [], "reason": f"plan unavailable: {exc}"}
            candidates = []
            for digest, candidate in sorted((entry.get("candidates") or {}).items()):
                row = {key: value for key, value in candidate.items() if key != "evidence"}
                row["evidence"] = candidate.get("evidence", [])[-10:]
                if candidate.get("status") == "discovered":
                    row["soak_remaining_seconds"] = round(self._soak_remaining(candidate))
                candidates.append(row)
            components[name] = {
                "active": self.store.read_active(name),
                "policy": component.policy_for(self.role),
                "track": component.update.track if component.update else None,
                "allow": component.update.allow if component.update else None,
                "units": list(self.host_units(name)),
                "probe_plan": plan_payload,
                "last_discovery": entry.get("last_discovery"),
                "candidates": candidates,
            }
        return {
            "role": self.role,
            "hold": self.hold_active(),
            "soak_days": self.soak_seconds / 86400.0,
            "last_run": state.get("last_run"),
            "last_run_ok": state.get("last_run_ok"),
            "last_success": state.get("last_success"),
            "components": components,
        }
