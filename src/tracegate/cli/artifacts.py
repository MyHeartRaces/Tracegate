"""Operator CLI for the local engine artifact store.

Engine units never pull at start: they run the image recorded by immutable
digest in the local store. This CLI records, promotes, rolls back and checks
those digests. ``stage`` is the only subcommand that contacts a registry.

Exit codes: 0 success, 1 problems found or operation refused, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from tracegate.services.artifacts import (
    DEFAULT_ROOT,
    ArtifactError,
    ArtifactStore,
    RegistryError,
    components_for_units,
    load_registry,
)

_INSTALLED_REGISTRY = Path("/opt/tracegate/current/deploy/host/artifacts.json")
_REPO_REGISTRY = Path(__file__).resolve().parents[3] / "deploy" / "host" / "artifacts.json"


class UsageError(ArtifactError):
    pass


def _default_root() -> Path:
    return Path(os.environ.get("TRACEGATE_ARTIFACTS_DIR", str(DEFAULT_ROOT)))


def _registry_path(args: argparse.Namespace) -> Path:
    if args.registry:
        return Path(args.registry)
    env_value = os.environ.get("TRACEGATE_ARTIFACTS_REGISTRY")
    if env_value:
        return Path(env_value)
    if _INSTALLED_REGISTRY.is_file():
        return _INSTALLED_REGISTRY
    return _REPO_REGISTRY


def _build_store(args: argparse.Namespace) -> ArtifactStore:
    registry = load_registry(_registry_path(args))
    return ArtifactStore(args.root, registry)


def _select_components(args: argparse.Namespace, store: ArtifactStore, positional: list[str]) -> list[str]:
    registry = store.registry
    if args.all and (positional or args.units):
        raise UsageError("--all cannot be combined with positional components or --units")
    if positional and args.units:
        raise UsageError("positional components and --units cannot be combined")
    if args.all:
        return list(registry.components)
    if args.units:
        selected = components_for_units(registry, list(args.units))
        if not selected:
            raise UsageError("no registry component owns the given units")
        return selected
    if positional:
        unknown = [name for name in positional if name not in registry.components]
        if unknown:
            raise UsageError(f"unknown component(s): {', '.join(unknown)}")
        return list(positional)
    raise UsageError("give component names, --all, or --units")


def _emit(args: argparse.Namespace, payload: dict, human: str) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(human)


def _cmd_components(args: argparse.Namespace) -> int:
    store = _build_store(args)
    components = store.registry.components
    if args.json:
        print(
            json.dumps(
                {
                    "registry": str(_registry_path(args)),
                    "components": {
                        name: {
                            "image": component.image,
                            "channel": component.channel,
                            "units": list(component.units),
                            "container_prefixes": list(component.container_prefixes),
                        }
                        for name, component in components.items()
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"registry: {_registry_path(args)}")
        for name, component in components.items():
            units = " ".join(component.units)
            print(f"{name}: {component.image} (channel {component.channel})")
            print(f"  units: {units}")
    return 0


def _cmd_capture(args: argparse.Namespace) -> int:
    store = _build_store(args)
    positional = [args.component] if args.component else []
    names = _select_components(args, store, positional)
    results = []
    for name in names:
        result = store.capture(name, from_container=args.from_container)
        results.append({"component": name, "reference": result.reference, "noop": result.noop})
        if args.json:
            continue
        if result.noop:
            print(f"{name}: active artifact already recorded, nothing to do")
        else:
            print(f"{name}: captured {result.reference}")
    if args.json:
        print(json.dumps({"results": results}, indent=2, sort_keys=True))
    elif any(not result["noop"] for result in results):
        print("restart the listed units to apply captured artifacts (one at a time, probe after each)")
    return 0


def _cmd_stage(args: argparse.Namespace) -> int:
    store = _build_store(args)
    component = store.registry.components.get(args.component)
    if component is None:
        raise UsageError(f"unknown component: {args.component}")
    reference = store.stage(args.component, tag=args.tag)
    _emit(
        args,
        {"component": args.component, "reference": reference, "tag": args.tag or component.channel},
        f"{args.component}: staged {reference}\n"
        f"next: probe it, then tracegate-artifacts promote {args.component} {reference}",
    )
    return 0


def _cmd_promote(args: argparse.Namespace) -> int:
    store = _build_store(args)
    result = store.promote(args.component, args.reference)
    if result.already_active:
        _emit(
            args,
            {"component": args.component, "reference": result.reference, "units": result.units, "already_active": True},
            f"{args.component}: {result.reference} is already active; nothing to do",
        )
        return 0
    _emit(
        args,
        {
            "component": args.component,
            "reference": result.reference,
            "units": result.units,
            "already_active": False,
        },
        f"{args.component}: promoted {result.reference}\n"
        f"restart one of these units to apply, then probe: {' '.join(result.units)}",
    )
    return 0


def _cmd_rollback(args: argparse.Namespace) -> int:
    store = _build_store(args)
    active, last_good = store.rollback(args.component)
    units = list(store.registry.components[args.component].units)
    _emit(
        args,
        {"component": args.component, "active": active, "last_good": last_good, "units": units},
        f"{args.component}: rolled back to {active}\nrestart one of these units to apply, then probe: {' '.join(units)}",
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    store = _build_store(args)
    names = _select_components(args, store, list(args.components))
    problems = store.verify(names)
    if args.json:
        print(
            json.dumps(
                {
                    "problems": [
                        {"component": problem.component, "code": problem.code, "message": problem.message}
                        for problem in problems
                    ]
                },
                indent=2,
                sort_keys=True,
            )
        )
    elif problems:
        for problem in problems:
            print(f"{problem.component}: {problem.code}: {problem.message}")
    else:
        print("artifact store verified: every active image is present by digest")
    return 1 if problems else 0


def _status_payload(store: ArtifactStore, names: list[str]) -> dict:
    statuses = store.status(names)
    return {
        "root": str(store.root),
        "components": [
            {
                "component": status.component,
                "active": status.active,
                "last_good": status.last_good,
                "candidates": list(status.candidates),
                "running": [
                    {"name": container.name, "digest": container.digest} for container in status.running
                ],
                "running_error": status.running_error,
                "drift": status.drift,
            }
            for status in statuses
        ],
    }


def _cmd_status(args: argparse.Namespace) -> int:
    store = _build_store(args)
    names = _select_components(args, store, list(args.components))
    payload = _status_payload(store, names)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for component in payload["components"]:
            print(f"{component['component']}:")
            print(f"  active: {component['active'] or 'none'}")
            print(f"  last-good: {component['last_good'] or 'none'}")
            print(f"  candidates: {len(component['candidates'])}")
            if component["running_error"] is not None:
                print(f"  running: unknown ({component['running_error']})")
            else:
                for container in component["running"]:
                    print(f"  running: {container['name']} {container['digest']}")
            if component["drift"] is None:
                print("  drift: unknown")
            elif component["drift"]:
                print("  drift: a running container digest differs from active")
    return 0


def _add_selection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--all", action="store_true", help="select every registry component")
    parser.add_argument(
        "--units",
        nargs="+",
        metavar="UNIT",
        help="select components owning the given systemd unit names",
    )


def build_parser() -> argparse.ArgumentParser:
    # SUPPRESS defaults so a subparser does not reset a value given before the
    # subcommand (both `--root X status` and `status --root X` work).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", type=Path, default=argparse.SUPPRESS, help="artifact store root")
    common.add_argument("--registry", type=Path, default=argparse.SUPPRESS, help="registry JSON path")
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output")

    parser = argparse.ArgumentParser(
        prog="tracegate-artifacts",
        description="Manage the local engine artifact store (engine units never pull at start)",
        epilog="Exit codes: 0 success, 1 problems found or operation refused, 2 usage error.",
        parents=[common],
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("components", parents=[common], help="list registry components")

    capture = subparsers.add_parser(
        "capture", parents=[common, _selection_parent()], help="record the running image digest as active"
    )
    capture.add_argument("component", nargs="?", help="component name")
    capture.add_argument("--from-container", metavar="NAME", help="choose this container on digest divergence")

    stage = subparsers.add_parser("stage", parents=[common], help="pull a candidate image (the only pull)")
    stage.add_argument("component", help="component name")
    stage.add_argument("--tag", help="upstream tag to pull (default: the registry channel)")

    promote = subparsers.add_parser("promote", parents=[common], help="make a digest reference active")
    promote.add_argument("component", help="component name")
    promote.add_argument("reference", help="<repo>@sha256:<digest> or sha256:<digest>")

    rollback = subparsers.add_parser("rollback", parents=[common], help="restore the last-good artifact")
    rollback.add_argument("component", help="component name")

    verify = subparsers.add_parser(
        "verify", parents=[common, _selection_parent()], help="check active artifacts against the store"
    )
    verify.add_argument("components", nargs="*", help="component names")
    status = subparsers.add_parser(
        "status", parents=[common, _selection_parent()], help="show active/last-good/candidates/drift"
    )
    status.add_argument("components", nargs="*", help="component names")

    parser.set_defaults(func=None)
    subparsers.choices["components"].set_defaults(func=_cmd_components)
    capture.set_defaults(func=_cmd_capture)
    stage.set_defaults(func=_cmd_stage)
    promote.set_defaults(func=_cmd_promote)
    rollback.set_defaults(func=_cmd_rollback)
    verify.set_defaults(func=_cmd_verify)
    status.set_defaults(func=_cmd_status)
    return parser


def _selection_parent() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    _add_selection_arguments(parent)
    return parent


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "root", None):
        args.root = _default_root()
    if not getattr(args, "registry", None):
        args.registry = None
    if not getattr(args, "json", False):
        args.json = False
    try:
        return int(args.func(args))
    except UsageError as exc:
        print(f"tracegate-artifacts: {exc}", file=sys.stderr)
        return 2
    except (ArtifactError, RegistryError) as exc:
        print(f"tracegate-artifacts: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
