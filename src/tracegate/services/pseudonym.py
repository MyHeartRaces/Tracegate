from __future__ import annotations

import hashlib
import hmac

from tracegate.settings import Settings


class PseudonymError(RuntimeError):
    pass


def _secret(settings: Settings) -> str:
    # Prefer a dedicated secret, but keep backward compatibility for existing installs.
    secret = (settings.pseudonym_secret or "").strip()
    if secret:
        return secret
    secret = (settings.grafana_cookie_secret or "").strip()
    if secret:
        return secret
    secret = (settings.api_internal_token or "").strip()
    if secret:
        return secret
    raise PseudonymError("PSEUDONYM_SECRET is not set (and no fallback secret is available)")


def pseudo_id(*, settings: Settings, kind: str, raw: str, length: int = 20) -> str:
    """
    Derive a stable pseudo-ID (base64url) from raw identifiers.

    This is used to avoid leaking real identifiers (e.g. Telegram ID) into node artifacts / Prometheus labels,
    while keeping per-user scoping stable in Grafana.
    """
    kind_s = str(kind or "").strip()
    raw_s = str(raw or "").strip()
    if not kind_s:
        raise PseudonymError("pseudo_id kind is required")
    if not raw_s:
        raise PseudonymError("pseudo_id raw is required")
    if length < 8:
        raise PseudonymError("pseudo_id length must be >= 8")

    msg = f"{kind_s}:{raw_s}".encode("utf-8")
    digest = hmac.new(_secret(settings).encode("utf-8"), msg, hashlib.sha256).digest()
    # Use hex to keep IDs Grafana/login-safe (alnum only) and Prometheus-label-safe.
    return digest.hex()[: int(length)]


def user_pid(settings: Settings, telegram_id: int) -> str:
    return pseudo_id(settings=settings, kind="user", raw=str(int(telegram_id)))


def device_pid(settings: Settings, device_id: str) -> str:
    return pseudo_id(settings=settings, kind="device", raw=str(device_id))


def connection_pid(settings: Settings, connection_id: str) -> str:
    return pseudo_id(settings=settings, kind="connection", raw=str(connection_id))
