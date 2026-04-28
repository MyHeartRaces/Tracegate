from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from tracegate.services.mtproto import MTPROTO_FAKE_TLS_PROFILE_NAME
from tracegate.settings import Settings, effective_mtproto_public_profile_file


class DecoyAuthConfigError(RuntimeError):
    pass


_GITHUB_FRAME_CACHE: dict[str, tuple[float, str]] = {}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _sign(payload: dict[str, Any], secret: str) -> str:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).digest()
    return f"{_b64url(data)}.{_b64url(sig)}"


def _verify(token: str, secret: str) -> dict[str, Any] | None:
    try:
        data_b64, sig_b64 = token.split(".", 1)
        data = _b64url_decode(data_b64)
        sig = _b64url_decode(sig_b64)
    except Exception:
        return None
    expected = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def decoy_auth_is_configured(settings: Settings) -> bool:
    return bool(str(settings.transit_decoy_auth_login or "").strip() and str(settings.transit_decoy_auth_password or ""))


def verify_decoy_credentials(settings: Settings, *, login: str, password: str) -> bool:
    expected_login = str(settings.transit_decoy_auth_login or "").strip()
    expected_password = str(settings.transit_decoy_auth_password or "")
    if not expected_login or not expected_password:
        return False
    return hmac.compare_digest(str(login or "").strip(), expected_login) and hmac.compare_digest(
        str(password or ""),
        expected_password,
    )


def decoy_cookie_secret(settings: Settings) -> str:
    for raw in (
        settings.pseudonym_secret,
        settings.grafana_cookie_secret,
        settings.api_internal_token,
        settings.agent_auth_token,
    ):
        value = str(raw or "").strip()
        if value:
            return value
    raise DecoyAuthConfigError("no secret available to sign decoy session cookies")


def build_decoy_session_cookie(settings: Settings) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "login": str(settings.transit_decoy_auth_login or "").strip(),
        "exp": now + int(settings.transit_decoy_auth_session_ttl_seconds),
    }
    return _sign(payload, decoy_cookie_secret(settings))


def load_decoy_session(settings: Settings, raw_cookie: str) -> dict[str, Any] | None:
    raw = str(raw_cookie or "").strip()
    if not raw:
        return None
    payload = _verify(raw, decoy_cookie_secret(settings))
    if not payload:
        return None
    try:
        exp = int(payload.get("exp") or 0)
    except Exception:
        return None
    if exp <= int(datetime.now(timezone.utc).timestamp()):
        return None
    login = str(payload.get("login") or "").strip()
    if not login or login != str(settings.transit_decoy_auth_login or "").strip():
        return None
    return payload


def load_mtproto_public_profile(settings: Settings) -> dict[str, Any]:
    path = Path(effective_mtproto_public_profile_file(settings))
    if not path.is_file():
        raise FileNotFoundError(path)

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DecoyAuthConfigError(f"invalid mtproto public profile json: {path}") from exc

    if not isinstance(raw, dict):
        raise DecoyAuthConfigError(f"invalid mtproto public profile payload: {path}")

    protocol = str(raw.get("protocol") or "").strip().lower()
    server = str(raw.get("server") or "").strip()
    transport = str(raw.get("transport") or "").strip().lower()
    client_secret_hex = str(raw.get("clientSecretHex") or "").strip()
    tg_uri = str(raw.get("tgUri") or "").strip()
    https_url = str(raw.get("httpsUrl") or "").strip()
    domain = str(raw.get("domain") or "").strip()
    profile = str(raw.get("profile") or MTPROTO_FAKE_TLS_PROFILE_NAME).strip() or MTPROTO_FAKE_TLS_PROFILE_NAME

    try:
        port = int(raw.get("port") or 0)
    except (TypeError, ValueError) as exc:
        raise DecoyAuthConfigError(f"invalid mtproto public profile port: {path}") from exc

    if protocol != "mtproto":
        raise DecoyAuthConfigError(f"unexpected protocol in mtproto public profile: {path}")
    if not server or port <= 0 or not transport or not client_secret_hex or not tg_uri or not https_url:
        raise DecoyAuthConfigError(f"incomplete mtproto public profile payload: {path}")

    return {
        "protocol": "mtproto",
        "server": server,
        "port": port,
        "transport": transport,
        "profile": profile,
        "domain": domain or server,
        "clientSecretHex": client_secret_hex,
        "tgUri": tg_uri,
        "httpsUrl": https_url,
    }


def _github_click_script(repo_url: str) -> str:
    safe_repo_url = json.dumps(str(repo_url or "").strip() or "https://github.com/")
    return (
        "<script>"
        "(function(){"
        "var target=" + safe_repo_url + ";"
        "document.addEventListener('click',function(event){"
        "var anchor=event.target&&event.target.closest?event.target.closest('a[href]'):null;"
        "if(anchor){event.preventDefault();window.top.location.href=anchor.href;return;}"
        "event.preventDefault();window.top.location.href=target;"
        "},true);"
        "})();"
        "</script>"
    )


def sanitize_github_repo_html(raw_html: str, *, repo_url: str) -> str:
    html = str(raw_html or "")
    if not html.strip():
        raise DecoyAuthConfigError("github repo html is empty")

    html = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"<meta\b[^>]+http-equiv=[\"']?Content-Security-Policy[\"']?[^>]*>", "", html, flags=re.IGNORECASE)
    html = re.sub(r"<meta\b[^>]+http-equiv=[\"']?X-Frame-Options[\"']?[^>]*>", "", html, flags=re.IGNORECASE)
    html = re.sub(r'data-color-mode="[^"]*"', 'data-color-mode="light"', html, flags=re.IGNORECASE)
    html = re.sub(r"data-color-mode='[^']*'", "data-color-mode='light'", html, flags=re.IGNORECASE)
    html = re.sub(r'data-dark-theme="[^"]*"', 'data-dark-theme="light"', html, flags=re.IGNORECASE)
    html = re.sub(r"data-dark-theme='[^']*'", "data-dark-theme='light'", html, flags=re.IGNORECASE)

    if "<head" in html.lower():
        html = re.sub(
            r"<head([^>]*)>",
            (
                "<head\\1>"
                "<base href=\"https://github.com/\" />"
                "<style>"
                ":root{color-scheme:light!important;}"
                "html,body{background:#ffffff!important;color:#1f2328!important;overflow:auto!important;}"
                "body{min-height:100vh;margin:0!important;}"
                "a{cursor:pointer!important;}"
                "</style>"
            ),
            html,
            count=1,
            flags=re.IGNORECASE,
        )
    else:
        html = (
            "<!doctype html><html data-color-mode=\"light\" data-dark-theme=\"light\"><head>"
            "<base href=\"https://github.com/\" />"
            "<style>:root{color-scheme:light!important;}html,body{background:#ffffff!important;color:#1f2328!important;overflow:auto!important;}body{min-height:100vh;margin:0!important;}a{cursor:pointer!important;}</style>"
            "</head><body>"
            + html
            + "</body></html>"
        )

    if "</body>" in html.lower():
        html = re.sub(r"</body>", _github_click_script(repo_url) + "</body>", html, count=1, flags=re.IGNORECASE)
    else:
        html += _github_click_script(repo_url)
    return html


async def load_github_repo_frame_html(settings: Settings) -> str:
    repo_url = str(settings.transit_decoy_github_repo_url or "").strip() or "https://github.com/MyHeartRaces/Tracegate"
    ttl = max(30, int(settings.transit_decoy_github_cache_ttl_seconds or 300))
    now = time.time()
    cached = _GITHUB_FRAME_CACHE.get(repo_url)
    if cached and (now - cached[0]) < ttl:
        return cached[1]

    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        response = await client.get(
            repo_url,
            headers={
                "User-Agent": "Tracegate-Decoy/2.0",
                "Accept": "text/html,application/xhtml+xml",
            },
        )
        response.raise_for_status()
        sanitized = sanitize_github_repo_html(response.text, repo_url=repo_url)

    _GITHUB_FRAME_CACHE[repo_url] = (now, sanitized)
    return sanitized
