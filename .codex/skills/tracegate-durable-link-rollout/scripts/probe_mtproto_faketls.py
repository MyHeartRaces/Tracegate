#!/usr/bin/env python3
"""Verify an authenticated MTProxy FakeTLS ServerHello without logging secrets."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import socket
import sys
import time


def _build_client_hello(secret: bytes, sni: str) -> tuple[bytes, bytes]:
    session_id = os.urandom(32)
    host = sni.encode("ascii")

    sni_payload = len(host + b"\x00\x00\x00").to_bytes(2, "big")
    sni_payload += b"\x00" + len(host).to_bytes(2, "big") + host
    extensions = b"\x00\x00" + len(sni_payload).to_bytes(2, "big") + sni_payload

    key = os.urandom(32)
    key_share = b"\x00\x1d" + len(key).to_bytes(2, "big") + key
    key_share_payload = len(key_share).to_bytes(2, "big") + key_share
    extensions += b"\x00\x33" + len(key_share_payload).to_bytes(2, "big") + key_share_payload

    alpn_list = b"\x02h2\x08http/1.1"
    alpn_payload = len(alpn_list).to_bytes(2, "big") + alpn_list
    extensions += b"\x00\x10" + len(alpn_payload).to_bytes(2, "big") + alpn_payload

    body = b"\x03\x03" + os.urandom(32)
    body += bytes([len(session_id)]) + session_id
    body += b"\x00\x02\x13\x01\x01\x00"
    body += len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\x01" + len(body).to_bytes(4, "big")[1:] + body
    record = bytearray(b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake)

    record[11:43] = b"\x00" * 32
    digest = bytearray(hmac.new(secret, bytes(record), hashlib.sha256).digest())
    timestamp = int(time.time()).to_bytes(4, "little")
    for index in range(4):
        digest[28 + index] ^= timestamp[index]
    record[11:43] = digest
    return bytes(record), bytes(digest)


def _read_secret() -> bytes:
    normalized = "".join(
        character
        for character in sys.stdin.read().strip().lower()
        if character in "0123456789abcdef"
    )
    if normalized.startswith(("dd", "ee")):
        normalized = normalized[2:34]
    else:
        normalized = normalized[:32]
    secret = bytes.fromhex(normalized)
    if len(secret) != 16:
        raise ValueError("stdin must contain a 16-byte MTProxy secret")
    return secret


def _probe_once(server: str, port: int, sni: str, secret: bytes) -> tuple[bool, int]:
    started = time.monotonic()
    with socket.create_connection((server, port), timeout=8) as connection:
        connection.settimeout(8)
        hello, client_digest = _build_client_hello(secret, sni)
        connection.sendall(hello)
        response = bytearray(connection.recv(65_536))
        connection.settimeout(0.25)
        while True:
            try:
                chunk = connection.recv(65_536)
            except TimeoutError:
                break
            if not chunk:
                break
            response.extend(chunk)

    response_digest = bytes(response[11:43]) if len(response) >= 43 else b""
    if len(response) >= 43:
        response[11:43] = b"\x00" * 32
    expected = hmac.new(secret, client_digest + bytes(response), hashlib.sha256).digest()
    valid = (
        len(response) >= 43
        and response[0] == 0x16
        and response[5] == 0x02
        and hmac.compare_digest(response_digest, expected)
    )
    return valid, round((time.monotonic() - started) * 1000)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--sni", required=True)
    parser.add_argument("--attempts", type=int, default=3)
    args = parser.parse_args()
    if args.attempts < 1:
        parser.error("--attempts must be positive")

    try:
        secret = _read_secret()
    except ValueError as error:
        parser.error(str(error))

    failures = 0
    for attempt in range(1, args.attempts + 1):
        try:
            valid, latency_ms = _probe_once(args.server, args.port, args.sni, secret)
            print(f"attempt={attempt} authenticated={str(valid).lower()} latency_ms={latency_ms}")
            failures += int(not valid)
        except Exception as error:  # noqa: BLE001 - report only the stable error type.
            print(f"attempt={attempt} authenticated=false error={type(error).__name__}")
            failures += 1
    print(f"summary attempts={args.attempts} successful={args.attempts - failures} failed={failures}")
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())
