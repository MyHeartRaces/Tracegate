"""Engine update supervisor CLI (`tracegate-engine-update`).

`run` is the daily timer entry point: discover -> soak -> stage -> check ->
activate (only with policy auto, no hold and a complete passing probe set)
or queue for the operator. It is idempotent and exits 0 when nothing needs
doing. Discovery never pulls; staging pulls by digest through the artifact
store, which stays the only pull.

Exit codes: 0 success or nothing to do, 1 refused/failed (including a
rollback or an unreachable registry), 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit

from tracegate.cli.artifacts import _registry_path
from tracegate.services.artifacts import DEFAULT_ROOT, ArtifactError, ArtifactStore, RegistryError, load_registry
from tracegate.services.engine_probes import HostProber, ProbeConfig
from tracegate.services.engine_registry import RegistryClient
from tracegate.services.engine_updates import (
    DEFAULT_SOAK_DAYS,
    ROLE_ENGINE_UNITS,
    EngineUpdateSupervisor,
    RunReport,
    UpdateError,
    set_update_hold,
)

_PROG = "tracegate-engine-update"
_ROLE_ENV_FILES = {
    "endpoint": ("TRACEGATE_RUNTIME_ENV", "/etc/tracegate/tracegate.env"),
    "entry": ("TRACEGATE_ENTRY_RUNTIME_ENV", "/etc/tracegate/tracegate-entry.env"),
}
_COMPOSE_GRAFANA_URL = "http://tracegate-grafana:3000"
_DEFAULT_GRAFANA_URL = "http://127.0.0.1:3000"
_DEFAULT_PROMETHEUS_URL = "http://127.0.0.1:9090"


class UsageError(UpdateError):
    pass


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, stdout="", stderr="timed out")


def _role(args: argparse.Namespace) -> str:
    role = (args.role or os.environ.get("TRACEGATE_HOST_ROLE") or "").strip().lower()
    if role not in ROLE_ENGINE_UNITS:
        raise UsageError("host role unknown: pass --role endpoint|entry or set TRACEGATE_HOST_ROLE")
    return role


def _soak_days(args: argparse.Namespace) -> float:
    raw = args.soak_days if args.soak_days is not None else os.environ.get("TRACEGATE_ENGINE_UPDATE_SOAK_DAYS")
    if raw is None or raw == "":
        return DEFAULT_SOAK_DAYS
    try:
        value = float(raw)
    except ValueError as exc:
        raise UsageError(f"invalid soak days: {raw!r}") from exc
    if value < 0:
        raise UsageError("soak days must not be negative")
    return value


def _load_settings(role: str):  # noqa: ANN202 - Settings is imported lazily
    """Role runtime settings, read from the role's runtime env file like the agent unit does."""
    from tracegate.settings import Settings

    variable, default = _ROLE_ENV_FILES[role]
    env_file = Path(os.environ.get(variable) or default)
    if env_file.is_file():
        return Settings(_env_file=str(env_file))
    return Settings()


def probe_config_from_settings(role: str, settings) -> ProbeConfig:  # noqa: ANN001
    health_url = os.environ.get("TRACEGATE_AGENT_HEALTH_URL") or f"http://127.0.0.1:{int(settings.agent_port)}/v1/health"
    parts = urlsplit(health_url)
    metrics_url = urlunsplit((parts.scheme, parts.netloc, "/metrics", "", ""))
    grafana_url = os.environ.get("TRACEGATE_GRAFANA_URL") or str(settings.grafana_internal_url or "")
    if grafana_url.rstrip("/") == _COMPOSE_GRAFANA_URL:
        grafana_url = _DEFAULT_GRAFANA_URL
    server_name = settings.hysteria_server_name_transit if role == "endpoint" else settings.hysteria_server_name_entry
    return ProbeConfig(
        role=role,
        agent_health_url=health_url,
        agent_metrics_url=metrics_url,
        agent_token=str(settings.agent_auth_token or ""),
        prometheus_url=os.environ.get("TRACEGATE_PROMETHEUS_URL") or _DEFAULT_PROMETHEUS_URL,
        grafana_url=grafana_url,
        hysteria_backhaul_token=str(settings.hysteria_endpoint_backhaul_auth_token or "").strip(),
        hysteria_server_name=str(server_name or "").strip(),
        reality_public_key=str(
            getattr(settings, "reality_public_key_transit", "") or getattr(settings, "reality_public_key", "") or ""
        ).strip(),
    )


def build_supervisor(args: argparse.Namespace) -> EngineUpdateSupervisor:
    role = _role(args)
    registry = load_registry(_registry_path(args))
    runner = _default_runner
    store = ArtifactStore(args.root, registry, runner=runner)
    config = probe_config_from_settings(role, _load_settings(role))
    prober = HostProber(
        config=config,
        store=store,
        runner=runner,
        units_for=lambda component: ROLE_ENGINE_UNITS[role].get(component, ()),
    )
    return EngineUpdateSupervisor(
        store=store,
        role=role,
        client=RegistryClient(),
        prober=prober,
        runner=runner,
        soak_days=_soak_days(args),
    )


def _print_report(args: argparse.Namespace, report: RunReport) -> None:
    if args.json:
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
        return
    for line in report.lines:
        print(line)


def _cmd_discover(args: argparse.Namespace) -> int:
    report = build_supervisor(args).discover_only()
    _print_report(args, report)
    return 0 if report.ok else 1


def _cmd_run(args: argparse.Namespace) -> int:
    report = build_supervisor(args).run()
    _print_report(args, report)
    return 0 if report.ok else 1


def _cmd_status(args: argparse.Namespace) -> int:
    payload = build_supervisor(args).status()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(f"role: {payload['role']}  hold: {'on' if payload['hold'] else 'off'}  soak: {payload['soak_days']:g} day(s)")
    print(f"last run: {payload['last_run'] or 'never'} (ok: {payload['last_run_ok']})")
    for name, component in payload["components"].items():
        plan = component["probe_plan"]
        track = component["track"] + (f" {component['allow']}" if component["allow"] else "")
        print(f"{name}: policy {component['policy']}, track {track}")
        print(f"  active: {component['active'] or 'none'}")
        if plan["complete"]:
            print(f"  probes: complete ({', '.join(plan['probes'])})")
        else:
            print(f"  probes: incomplete ({plan['reason']})")
        discovery = component["last_discovery"]
        if discovery:
            if discovery.get("ok"):
                print(f"  upstream: {discovery.get('tag')} {discovery.get('digest')} at {discovery.get('at')}")
            else:
                print(f"  upstream: discovery failed at {discovery.get('at')}: {discovery.get('error')}")
        for candidate in component["candidates"]:
            line = f"  candidate {candidate['digest']} ({candidate.get('tag') or '-'}): {candidate['status']}"
            if candidate.get("reason"):
                line += f" - {candidate['reason']}"
            if "soak_remaining_seconds" in candidate:
                line += f" (soak {candidate['soak_remaining_seconds'] / 3600:.1f} h left)"
            print(line)
    return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    supervisor = build_supervisor(args)
    report = supervisor.approve(args.component, args.digest, no_soak=args.no_soak)
    _print_report(args, report)
    return 0 if report.ok and (report.activated or any("already active" in line for line in report.lines)) else 1


def _cmd_reject(args: argparse.Namespace) -> int:
    report = build_supervisor(args).reject(args.component, args.digest, reason=args.reason)
    _print_report(args, report)
    return 0


def _cmd_hold(args: argparse.Namespace) -> int:
    store = ArtifactStore(args.root, load_registry(_registry_path(args)), runner=_default_runner)
    changed = set_update_hold(store, args.state == "on", reason=args.reason)
    if args.json:
        print(json.dumps({"hold": args.state == "on", "changed": changed}, sort_keys=True))
    else:
        print(f"engine update hold is {args.state}" + ("" if changed else " (unchanged)"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", type=Path, default=argparse.SUPPRESS, help="artifact store root")
    common.add_argument("--registry", type=Path, default=argparse.SUPPRESS, help="registry JSON path")
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output")
    common.add_argument("--role", default=argparse.SUPPRESS, help="host role (default: TRACEGATE_HOST_ROLE)")
    common.add_argument(
        "--soak-days",
        default=argparse.SUPPRESS,
        help=f"soak period (default: TRACEGATE_ENGINE_UPDATE_SOAK_DAYS or {DEFAULT_SOAK_DAYS:g})",
    )

    parser = argparse.ArgumentParser(
        prog=_PROG,
        description="Discover, soak, stage, check and (only where probes prove it safe) activate engine images",
        epilog="Exit codes: 0 success or nothing to do, 1 refused or failed, 2 usage error.",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("discover", parents=[common], help="record the newest upstream digests (never pulls)").set_defaults(
        func=_cmd_discover
    )
    sub.add_parser("run", parents=[common], help="timer entry point: discover, soak, stage, check, activate or queue").set_defaults(
        func=_cmd_run
    )
    sub.add_parser("status", parents=[common], help="show candidates, policies, probe plans and hold").set_defaults(
        func=_cmd_status
    )
    approve = sub.add_parser("approve", parents=[common], help="operator activation through the probe/rollback path")
    approve.add_argument("component")
    approve.add_argument("digest", help="sha256:<digest> of a known candidate")
    approve.add_argument("--no-soak", action="store_true", help="skip the remaining soak period")
    approve.set_defaults(func=_cmd_approve)
    reject = sub.add_parser("reject", parents=[common], help="never activate this digest")
    reject.add_argument("component")
    reject.add_argument("digest")
    reject.add_argument("--reason", default="rejected by operator")
    reject.set_defaults(func=_cmd_reject)
    hold = sub.add_parser("hold", parents=[common], help="freeze (on) or allow (off) automatic activation")
    hold.add_argument("state", choices=("on", "off"))
    hold.add_argument("--reason", default="operator")
    hold.set_defaults(func=_cmd_hold)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "root", None):
        args.root = Path(os.environ.get("TRACEGATE_ARTIFACTS_DIR", str(DEFAULT_ROOT)))
    for name, default in (("registry", None), ("json", False), ("role", None), ("soak_days", None)):
        if not hasattr(args, name):
            setattr(args, name, default)
    try:
        return int(args.func(args))
    except UsageError as exc:
        print(f"{_PROG}: {exc}", file=sys.stderr)
        return 2
    except (UpdateError, ArtifactError, RegistryError) as exc:
        print(f"{_PROG}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
