#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import collections
import json
import logging
from pathlib import Path
import sys
import time


def _normalize_random_padding_secret(raw: str) -> str:
    normalized = "".join(ch for ch in str(raw or "").strip().lower() if ch in "0123456789abcdef")
    if normalized.startswith("dd") and len(normalized) == 34:
        normalized = normalized[2:]
    if len(normalized) != 32:
        raise ValueError("MTProxy random-padding secret must contain exactly 16 bytes in hex")
    return normalized


def _read_secret(*, secret_file: str, secret_stdin: bool) -> str:
    if secret_stdin:
        raw = sys.stdin.read()
    else:
        raw = Path(secret_file).read_text(encoding="utf-8")
    return _normalize_random_padding_secret(raw)


async def _probe_once(args: argparse.Namespace, secret: str) -> dict[str, object]:
    try:
        from telethon.network.authenticator import do_authentication
        from telethon.network.connection.tcpmtproxy import ConnectionTcpMTProxyRandomizedIntermediate
        from telethon.network.mtprotoplainsender import MTProtoPlainSender
    except ImportError as exc:  # pragma: no cover - depends on the operator environment
        raise RuntimeError(
            "Telethon is required; run with `uv run --with 'telethon>=1.36,<2'` or install it explicitly"
        ) from exc

    logger = logging.getLogger("tracegate.mtproto_probe")
    loggers = collections.defaultdict(lambda: logger)
    connection = ConnectionTcpMTProxyRandomizedIntermediate(
        args.dc_ip,
        int(args.dc_port),
        int(args.dc_id),
        loggers=loggers,
        proxy=(args.server, int(args.port), f"dd{secret}"),
    )
    started = time.monotonic()
    try:
        await asyncio.wait_for(connection.connect(timeout=args.connect_timeout), timeout=args.connect_timeout + 5)
        sender = MTProtoPlainSender(connection, loggers=loggers)
        auth_key, time_offset = await asyncio.wait_for(do_authentication(sender), timeout=args.auth_timeout)
        return {
            "ok": True,
            "auth_key_bytes": len(auth_key.key),
            "time_offset_seconds": int(time_offset),
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    except Exception as exc:  # noqa: BLE001 - probe reports a stable error class, not secret-bearing details
        return {
            "ok": False,
            "error": type(exc).__name__,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    finally:
        await connection.disconnect()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a Telegram auth key through a random-padding MTProxy without logging its secret."
    )
    parser.add_argument("--server", required=True, help="Public MTProxy hostname or address")
    parser.add_argument("--port", type=int, default=443)
    secret = parser.add_mutually_exclusive_group(required=True)
    secret.add_argument("--secret-file", help="File containing the raw or dd-prefixed 16-byte hex secret")
    secret.add_argument("--secret-stdin", action="store_true", help="Read the secret from standard input")
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between attempts in seconds")
    parser.add_argument("--connect-timeout", type=float, default=10.0)
    parser.add_argument("--auth-timeout", type=float, default=30.0)
    parser.add_argument("--dc-id", type=int, default=2)
    # TcpMTProxy connects to proxy=(server, port) and routes by dc_id; this
    # positional address is ignored by Telethon's MTProxy implementation.
    parser.add_argument("--dc-ip", default="192.0.2.1")
    parser.add_argument("--dc-port", type=int, default=443)
    return parser


async def _run(args: argparse.Namespace, secret: str) -> int:
    if args.attempts < 1:
        raise ValueError("--attempts must be positive")
    results: list[dict[str, object]] = []
    for attempt in range(1, args.attempts + 1):
        result = await _probe_once(args, secret)
        result["attempt"] = attempt
        results.append(result)
        print(json.dumps(result, sort_keys=True), flush=True)
        if attempt < args.attempts and args.delay > 0:
            await asyncio.sleep(args.delay)

    successful = sum(1 for result in results if result.get("ok") is True)
    print(
        json.dumps(
            {
                "summary": True,
                "attempts": len(results),
                "successful": successful,
                "failed": len(results) - successful,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0 if successful == len(results) else 1


def main() -> int:
    args = _parser().parse_args()
    try:
        secret = _read_secret(secret_file=str(args.secret_file or ""), secret_stdin=bool(args.secret_stdin))
        return asyncio.run(_run(args, secret))
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__, "detail": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
