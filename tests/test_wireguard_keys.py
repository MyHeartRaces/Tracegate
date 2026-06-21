import base64
from uuid import UUID

from tracegate.services.wireguard_keys import (
    derive_wireguard_client_address,
    derive_wireguard_public_key,
    generate_wireguard_keypair,
    generate_wireguard_preshared_key,
)


def test_generate_wireguard_keypair_and_preshared_key_are_wireguard_sized() -> None:
    keypair = generate_wireguard_keypair()
    assert len(base64.b64decode(keypair.private_key, validate=True)) == 32
    assert len(base64.b64decode(keypair.public_key, validate=True)) == 32
    assert derive_wireguard_public_key(keypair.private_key) == keypair.public_key
    assert len(base64.b64decode(generate_wireguard_preshared_key(), validate=True)) == 32


def test_derive_wireguard_client_address_is_stable_host_route() -> None:
    connection_id = UUID("00000000-0000-4000-8000-000000000123")
    first = derive_wireguard_client_address(connection_id)
    second = derive_wireguard_client_address(str(connection_id))
    assert first == second
    assert first.startswith("10.70.")
    assert first.endswith("/32")
    octets = first.removesuffix("/32").split(".")
    assert 1 <= int(octets[2]) <= 253
    assert 1 <= int(octets[3]) <= 254
