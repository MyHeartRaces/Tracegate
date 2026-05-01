from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


@dataclass(frozen=True)
class WireGuardKeyPair:
    private_key: str
    public_key: str


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode_key(value: str, *, field_name: str) -> bytes:
    try:
        raw = base64.b64decode(str(value).strip(), validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} must be a base64-encoded WireGuard key") from exc
    if len(raw) != 32:
        raise ValueError(f"{field_name} must decode to 32 bytes")
    return raw


def _new_private_key_bytes() -> bytes:
    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return bytes(raw)


def derive_wireguard_public_key(private_key: str) -> str:
    private_raw = _b64decode_key(private_key, field_name="wireguard.private_key")
    key = x25519.X25519PrivateKey.from_private_bytes(private_raw)
    public_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64encode(public_raw)


def generate_wireguard_keypair() -> WireGuardKeyPair:
    private_key = _b64encode(_new_private_key_bytes())
    return WireGuardKeyPair(
        private_key=private_key,
        public_key=derive_wireguard_public_key(private_key),
    )


def generate_wireguard_preshared_key() -> str:
    return _b64encode(os.urandom(32))


def derive_wireguard_client_address(connection_id: UUID | str) -> str:
    digest = hashlib.sha256(str(connection_id).encode("ascii", errors="ignore")).digest()
    host_index = int.from_bytes(digest[:2], byteorder="big") % (253 * 254)
    third_octet = (host_index // 254) + 1
    fourth_octet = (host_index % 254) + 1
    return f"10.70.{third_octet}.{fourth_octet}/32"
