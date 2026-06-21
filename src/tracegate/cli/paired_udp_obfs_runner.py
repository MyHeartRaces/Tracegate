from __future__ import annotations

import argparse
import sys

from tracegate.services.paired_udp_obfs_runner import (
    PairedUdpObfsRunnerError,
    build_paired_udp_obfs_runner_plan,
    exec_paired_udp_obfs,
    plan_to_json,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracegate-paired-udp-obfs-runner",
        description="Validate and run Tracegate paired UDP obfuscation profiles.",
    )
    parser.add_argument("action", choices=["plan", "validate", "start", "reload", "stop"])
    parser.add_argument("profile", help="paired-obfs.env profile")
    parser.add_argument("--udp2raw-bin", default="", help="udp2raw binary override")
    parser.add_argument("--json", action="store_true", help="print JSON result")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        plan = build_paired_udp_obfs_runner_plan(
            action=args.action,
            profile_path=args.profile,
            udp2raw_bin=args.udp2raw_bin,
        )
        if plan["action"] == "start":
            exec_paired_udp_obfs(args.profile, udp2raw_bin=args.udp2raw_bin)
            return
    except PairedUdpObfsRunnerError as exc:
        raise SystemExit(str(exc)) from exc

    if args.json:
        sys.stdout.write(plan_to_json(plan))
        return
    sys.stdout.write(
        "OK paired UDP obfs "
        f"action={plan['action']} "
        f"mode={plan['mode']} "
        f"side={plan['side']} "
        f"profile={plan['profile']}\n"
    )


if __name__ == "__main__":  # pragma: no cover
    main()
