from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from tracegate.services.link_crypto_runner import (
    LinkCryptoRunnerError,
    LinkCryptoRunnerPaths,
    apply_link_crypto_runner_plan,
    build_link_crypto_runner_plan,
    write_link_crypto_runner_plan,
)
from tracegate.services.runtime_preflight import RuntimePreflightError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracegate-link-crypto-runner",
        description="Validate and operate Tracegate private link-crypto Mieru/Hysteria2 runner plans.",
    )
    parser.add_argument("action", choices=["plan", "validate", "start", "reload", "stop"])
    parser.add_argument("--role", required=True, choices=["ENTRY", "TRANSIT", "entry", "transit"])
    parser.add_argument("--state-json", required=True, help="link-crypto desired-state.json")
    parser.add_argument("--runtime-contract", default="", help="runtime-contract.json override")
    parser.add_argument("--runtime-dir", default="/var/lib/tracegate/private/link-crypto/runtime")
    parser.add_argument("--plan-file", default="", help="runner plan output path")
    parser.add_argument("--mieru-bin", default="mieru")
    parser.add_argument("--hysteria-bin", default="hysteria")
    parser.add_argument("--paired-obfs-runner", default="")
    parser.add_argument("--only-udp", action="store_true", help="operate only UDP Hysteria2/paired-obfs processes")
    parser.add_argument("--only-mieru", action="store_true", help="operate only Mieru processes")
    parser.add_argument("--json", action="store_true", help="print JSON result")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.only_udp and args.only_mieru:
        raise SystemExit("--only-udp and --only-mieru are mutually exclusive")
    runtime_dir = Path(args.runtime_dir)
    plan_file = Path(args.plan_file) if args.plan_file else runtime_dir / f"{args.role.lower()}-runner-plan.json"
    try:
        plan = build_link_crypto_runner_plan(
            action=args.action,
            role=args.role,
            paths=LinkCryptoRunnerPaths(
                state_json=Path(args.state_json),
                runtime_dir=runtime_dir,
                plan_file=plan_file,
                runtime_contract=Path(args.runtime_contract) if args.runtime_contract else None,
            ),
            mieru_bin=args.mieru_bin,
            hysteria_bin=args.hysteria_bin,
            paired_obfs_runner=args.paired_obfs_runner,
            include_mieru=not args.only_udp,
            include_udp=not args.only_mieru,
        )
        write_link_crypto_runner_plan(plan, plan_file)
        result = apply_link_crypto_runner_plan(plan)
    except (LinkCryptoRunnerError, RuntimePreflightError) as exc:
        raise SystemExit(str(exc)) from exc

    if args.json:
        sys.stdout.write(json.dumps({"planFile": str(plan_file), **result}, ensure_ascii=True, indent=2) + "\n")
        return
    sys.stdout.write(
        "OK link-crypto runner "
        f"action={plan['action']} "
        f"role={plan['role']} "
        f"processes={len(plan['processes'])} "
        f"plan={plan_file}\n"
    )
