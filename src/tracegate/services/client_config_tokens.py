from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from tracegate.settings import Settings

_PURPOSE = "tracegate-client-config"


class ClientConfigTokenError(ValueError):
    pass


def client_config_token_secret(settings: Settings) -> str:
    return str(settings.pseudonym_secret or settings.api_internal_token or "").strip()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode((value + pad).encode("ascii"))
    except Exception as exc:
        raise ClientConfigTokenError("invalid client config token encoding") from exc


def build_client_config_token(*, subject_type: str, subject_id: str, secret: str) -> str:
    normalized_subject_type = str(subject_type or "").strip().lower()
    normalized_subject_id = str(subject_id or "").strip()
    normalized_secret = str(secret or "").strip()
    if normalized_subject_type not in {"device", "revision"}:
        raise ClientConfigTokenError("client config token subject_type must be device or revision")
    if not normalized_subject_id:
        raise ClientConfigTokenError("client config token subject_id is required")
    if not normalized_secret:
        raise ClientConfigTokenError("client config token secret is required")

    payload = {
        "v": 1,
        "purpose": _PURPOSE,
        "subjectType": normalized_subject_type,
        "subjectId": normalized_subject_id,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(normalized_secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    return f"{_b64url(payload_bytes)}.{_b64url(sig)}"


def parse_client_config_token(token: str, *, secret: str) -> dict[str, Any]:
    normalized_secret = str(secret or "").strip()
    if not normalized_secret:
        raise ClientConfigTokenError("client config token secret is required")
    data_b64, sep, sig_b64 = str(token or "").strip().partition(".")
    if not sep or not data_b64 or not sig_b64:
        raise ClientConfigTokenError("invalid client config token")
    payload_bytes = _b64url_decode(data_b64)
    sig = _b64url_decode(sig_b64)
    expected = hmac.new(normalized_secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise ClientConfigTokenError("invalid client config token signature")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientConfigTokenError("invalid client config token payload") from exc
    if not isinstance(payload, dict) or payload.get("purpose") != _PURPOSE or int(payload.get("v") or 0) != 1:
        raise ClientConfigTokenError("unsupported client config token")
    subject_type = str(payload.get("subjectType") or "").strip().lower()
    subject_id = str(payload.get("subjectId") or "").strip()
    if subject_type not in {"device", "revision"} or not subject_id:
        raise ClientConfigTokenError("invalid client config token subject")
    return {"subject_type": subject_type, "subject_id": subject_id}
