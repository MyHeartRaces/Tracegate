from __future__ import annotations

import base64
import hashlib
import html as html_lib
import hmac
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from tracegate.services.mtproto import MTPROTO_FAKE_TLS_PROFILE_NAME
from tracegate.settings import Settings, effective_mtproto_public_profile_file


class DecoyAuthConfigError(RuntimeError):
    pass


_GITHUB_FRAME_CACHE: dict[str, tuple[float, str]] = {}
_GITHUB_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


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
    secret_policy = str(raw.get("secretPolicy") or "").strip()

    try:
        port = int(raw.get("port") or 0)
    except (TypeError, ValueError) as exc:
        raise DecoyAuthConfigError(f"invalid mtproto public profile port: {path}") from exc

    if protocol != "mtproto":
        raise DecoyAuthConfigError(f"unexpected protocol in mtproto public profile: {path}")
    if not server or port <= 0 or not transport or not client_secret_hex or not tg_uri or not https_url:
        raise DecoyAuthConfigError(f"incomplete mtproto public profile payload: {path}")

    payload = {
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
    if secret_policy:
        payload["secretPolicy"] = secret_policy
    return payload


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


def _escape_html(value: object) -> str:
    return html_lib.escape(str(value or ""), quote=True)


def _github_repo_parts(repo_url: str) -> tuple[str, str] | None:
    parsed = urlparse(str(repo_url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        return None
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None
    owner = parts[0]
    repo = parts[1].removesuffix(".git")
    if not _GITHUB_REPO_NAME_RE.fullmatch(owner) or not _GITHUB_REPO_NAME_RE.fullmatch(repo):
        return None
    return owner, repo


def _github_api_headers() -> dict[str, str]:
    return {
        "User-Agent": "Tracegate-Decoy/2.0",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _format_github_count(value: object) -> str:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        return "0"
    if number >= 1_000_000:
        return f"{number / 1_000_000:.1f}m"
    if number >= 1_000:
        return f"{number / 1_000:.1f}k"
    return str(number)


def _render_github_file_rows(contents: list[dict[str, Any]], *, repo_url: str, branch: str) -> str:
    if not contents:
        return (
            "<div class=\"empty-state\">"
            "Repository contents are available on GitHub. "
            f"<a href=\"{_escape_html(repo_url)}\" target=\"_top\" rel=\"noreferrer\">Open repository</a>."
            "</div>"
        )

    branch_path = quote(branch or "main", safe="")
    rows = []
    for item in contents[:80]:
        name = str(item.get("name") or item.get("path") or "").strip()
        path = str(item.get("path") or name).strip()
        item_type = str(item.get("type") or "file").strip().lower()
        if item_type not in {"dir", "file", "submodule", "symlink"}:
            item_type = "file"
        if not name or not path:
            continue
        kind = "tree" if item_type == "dir" else "blob"
        icon = "DIR" if item_type == "dir" else "FILE"
        url = str(item.get("html_url") or f"{repo_url}/{kind}/{branch_path}/{quote(path, safe='/')}")
        rows.append(
            "<a class=\"file-row\" target=\"_top\" rel=\"noreferrer\" "
            f"href=\"{_escape_html(url)}\">"
            f"<span class=\"file-icon {item_type}\">{icon}</span>"
            f"<span class=\"file-name\">{_escape_html(name)}</span>"
            f"<span class=\"file-kind\">{_escape_html(item_type or 'file')}</span>"
            "</a>"
        )
    return "".join(rows)


def render_github_repo_mirror_html(
    repo_payload: dict[str, Any],
    contents_payload: list[dict[str, Any]],
    *,
    repo_url: str,
) -> str:
    full_name = str(repo_payload.get("full_name") or "").strip()
    if "/" in full_name:
        owner, repo = (full_name.split("/", 1) + [""])[:2]
    else:
        owner, repo = ("MyHeartRaces", "Tracegate")
    html_url = str(repo_payload.get("html_url") or repo_url).strip() or repo_url
    owner_url = html_url.rsplit("/", 1)[0] if "/" in html_url else html_url
    branch = str(repo_payload.get("default_branch") or "main").strip() or "main"
    description = str(repo_payload.get("description") or "Tracegate public source mirror.").strip()
    visibility = str(repo_payload.get("visibility") or "public").strip() or "public"
    license_payload = repo_payload.get("license") if isinstance(repo_payload.get("license"), dict) else {}
    license_name = str(license_payload.get("spdx_id") or license_payload.get("name") or "License").strip()
    updated_at = str(repo_payload.get("pushed_at") or repo_payload.get("updated_at") or "").strip()
    file_rows = _render_github_file_rows(contents_payload, repo_url=html_url, branch=branch)

    return f"""<!doctype html>
<html lang="en" data-color-mode="light">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <base target="_top" />
    <title>{_escape_html(full_name or "Tracegate")}</title>
    <style>
      :root {{
        color-scheme: light;
        --bg: #ffffff;
        --ink: #1f2328;
        --muted: #57606a;
        --line: #d0d7de;
        --soft: #f6f8fa;
        --link: #0969da;
        --green: #1a7f37;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        background: var(--bg);
        color: var(--ink);
        font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }}
      a {{ color: var(--link); text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}
      .repo-shell {{ min-height: 100vh; background: var(--bg); }}
      .repo-header {{
        padding: 20px 28px 14px;
        border-bottom: 1px solid var(--line);
        background: var(--soft);
      }}
      .crumb {{
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 7px;
        font-size: 20px;
      }}
      .crumb strong {{ font-weight: 600; }}
      .visibility {{
        display: inline-flex;
        align-items: center;
        min-height: 22px;
        padding: 0 8px;
        border: 1px solid var(--line);
        border-radius: 999px;
        color: var(--muted);
        font-size: 12px;
        font-weight: 600;
      }}
      .description {{
        max-width: 920px;
        margin: 10px 0 0;
        color: var(--muted);
      }}
      .repo-meta {{
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 14px;
        color: var(--muted);
        font-size: 13px;
      }}
      .repo-meta span {{
        display: inline-flex;
        align-items: center;
        min-height: 26px;
        padding: 0 10px;
        border: 1px solid var(--line);
        border-radius: 999px;
        background: #fff;
      }}
      .tabs {{
        display: flex;
        gap: 6px;
        padding: 0 28px;
        border-bottom: 1px solid var(--line);
        background: var(--bg);
      }}
      .tab {{
        min-height: 48px;
        display: inline-flex;
        align-items: center;
        padding: 0 10px;
        border-bottom: 2px solid transparent;
        color: var(--muted);
        font-weight: 600;
      }}
      .tab.active {{
        color: var(--ink);
        border-bottom-color: #fd8c73;
      }}
      .content {{
        width: min(1160px, calc(100% - 32px));
        margin: 18px auto 32px;
      }}
      .toolbar {{
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
        margin-bottom: 10px;
      }}
      .branch {{
        display: inline-flex;
        align-items: center;
        min-height: 34px;
        padding: 0 12px;
        border: 1px solid var(--line);
        border-radius: 6px;
        background: var(--soft);
        color: var(--ink);
        font-weight: 600;
      }}
      .open-link {{
        display: inline-flex;
        align-items: center;
        min-height: 34px;
        padding: 0 12px;
        border: 1px solid rgba(26, 127, 55, 0.3);
        border-radius: 6px;
        background: #dafbe1;
        color: var(--green);
        font-weight: 700;
      }}
      .file-list {{
        overflow: hidden;
        border: 1px solid var(--line);
        border-radius: 6px;
        background: #fff;
      }}
      .file-row {{
        display: grid;
        grid-template-columns: 68px minmax(0, 1fr) 90px;
        gap: 12px;
        align-items: center;
        min-height: 44px;
        padding: 0 16px;
        color: var(--ink);
        border-top: 1px solid var(--line);
      }}
      .file-row:first-child {{ border-top: 0; }}
      .file-row:hover {{ background: var(--soft); text-decoration: none; }}
      .file-icon {{
        color: var(--muted);
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 11px;
        font-weight: 700;
      }}
      .file-icon.dir {{ color: var(--link); }}
      .file-name {{
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        font-weight: 600;
      }}
      .file-kind {{
        justify-self: end;
        color: var(--muted);
        font-size: 12px;
      }}
      .readme {{
        margin-top: 18px;
        border: 1px solid var(--line);
        border-radius: 6px;
        background: #fff;
      }}
      .readme-title {{
        padding: 12px 16px;
        border-bottom: 1px solid var(--line);
        font-weight: 700;
      }}
      .readme-body {{
        padding: 20px 16px;
        color: var(--muted);
      }}
      .empty-state {{
        padding: 18px 16px;
        color: var(--muted);
      }}
      @media (max-width: 720px) {{
        .repo-header {{ padding: 16px; }}
        .tabs {{ padding: 0 16px; overflow-x: auto; }}
        .content {{ width: min(100% - 20px, 1160px); }}
        .toolbar {{ align-items: stretch; flex-direction: column; }}
        .file-row {{ grid-template-columns: 48px minmax(0, 1fr); }}
        .file-kind {{ display: none; }}
      }}
    </style>
  </head>
  <body>
    <main class="repo-shell">
      <header class="repo-header">
        <div class="crumb">
          <a href="{_escape_html(owner_url)}" rel="noreferrer">{_escape_html(owner)}</a>
          <span>/</span>
          <a href="{_escape_html(html_url)}" rel="noreferrer"><strong>{_escape_html(repo)}</strong></a>
          <span class="visibility">{_escape_html(visibility)}</span>
        </div>
        <p class="description">{_escape_html(description)}</p>
        <div class="repo-meta" aria-label="Repository metadata">
          <span>Branch: {_escape_html(branch)}</span>
          <span>Stars: {_format_github_count(repo_payload.get("stargazers_count"))}</span>
          <span>Forks: {_format_github_count(repo_payload.get("forks_count"))}</span>
          <span>License: {_escape_html(license_name)}</span>
          <span>Updated: {_escape_html(updated_at[:10] or "unknown")}</span>
        </div>
      </header>
      <nav class="tabs" aria-label="Repository navigation">
        <a class="tab active" href="{_escape_html(html_url)}" rel="noreferrer">Code</a>
        <a class="tab" href="{_escape_html(html_url)}/issues" rel="noreferrer">Issues</a>
        <a class="tab" href="{_escape_html(html_url)}/pulls" rel="noreferrer">Pull requests</a>
        <a class="tab" href="{_escape_html(html_url)}/actions" rel="noreferrer">Actions</a>
      </nav>
      <section class="content" aria-label="Repository files">
        <div class="toolbar">
          <span class="branch">{_escape_html(branch)}</span>
          <a class="open-link" href="{_escape_html(html_url)}" rel="noreferrer">Open on GitHub</a>
        </div>
        <div class="file-list">{file_rows}</div>
        <article class="readme">
          <div class="readme-title">README.md</div>
          <div class="readme-body">
            This frame is a lightweight live mirror built from GitHub repository metadata. Open the
            repository on GitHub for the full README, history and source browser.
          </div>
        </article>
      </section>
    </main>
  </body>
</html>"""


def render_github_repo_fallback_html(*, repo_url: str) -> str:
    owner_repo = _github_repo_parts(repo_url)
    if owner_repo is None:
        owner, repo = ("MyHeartRaces", "Tracegate")
    else:
        owner, repo = owner_repo
    safe_repo_url = f"https://github.com/{owner}/{repo}"
    payload = {
        "full_name": f"{owner}/{repo}",
        "html_url": safe_repo_url,
        "default_branch": "main",
        "description": "Tracegate public source mirror.",
        "visibility": "public",
        "license": {"spdx_id": "GPL-3.0-only"},
    }
    return render_github_repo_mirror_html(payload, [], repo_url=safe_repo_url)


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

    repo_parts = _github_repo_parts(repo_url)
    if repo_parts is None:
        html = render_github_repo_fallback_html(repo_url=repo_url)
        _GITHUB_FRAME_CACHE[repo_url] = (now, html)
        return html

    owner, repo = repo_parts
    api_base = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        timeout = httpx.Timeout(5.0, connect=3.0)
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            repo_response = await client.get(api_base, headers=_github_api_headers())
            repo_response.raise_for_status()
            repo_payload = repo_response.json()
            if not isinstance(repo_payload, dict):
                raise DecoyAuthConfigError("github repository payload is not an object")

            branch = str(repo_payload.get("default_branch") or "main").strip() or "main"
            contents_response = await client.get(
                f"{api_base}/contents",
                headers=_github_api_headers(),
                params={"ref": branch},
            )
            contents_response.raise_for_status()
            contents_payload = contents_response.json()
            if not isinstance(contents_payload, list):
                contents_payload = []

        html = render_github_repo_mirror_html(repo_payload, contents_payload, repo_url=repo_url)
    except Exception:
        html = render_github_repo_fallback_html(repo_url=repo_url)

    _GITHUB_FRAME_CACHE[repo_url] = (now, html)
    return html
