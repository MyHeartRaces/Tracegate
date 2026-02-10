from __future__ import annotations

import subprocess


class WireguardKeygenError(RuntimeError):
    pass


def generate_keypair() -> tuple[str, str]:
    """
    Returns (private_key, public_key) in WireGuard base64 format.
    Requires `wg` binary in the runtime image.
    """
    try:
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
    except FileNotFoundError as exc:
        raise WireguardKeygenError("wg binary not found") from exc
    except subprocess.CalledProcessError as exc:
        raise WireguardKeygenError(exc.stderr.strip() or "wg genkey failed") from exc

    try:
        pub = subprocess.run(["wg", "pubkey"], input=priv + "\n", capture_output=True, text=True, check=True).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise WireguardKeygenError(exc.stderr.strip() or "wg pubkey failed") from exc

    if not priv or not pub:
        raise WireguardKeygenError("wireguard keygen returned empty output")
    return priv, pub

