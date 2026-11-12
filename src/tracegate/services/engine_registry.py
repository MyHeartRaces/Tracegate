"""Anonymous, read-only upstream registry client for engine update discovery.

Discovery never pulls: it reads manifest digests and tag lists over the
Docker Registry HTTP API v2 with the standard library only. Proxies follow
the process environment (``HTTPS_PROXY`` / ``no_proxy``) through urllib's
default proxy handling.

The digest recorded for a tag is the one ``docker pull`` reports in
RepoDigests: the manifest-list / OCI-index digest when the tag is
multi-platform, otherwise the image manifest digest. A multi-platform tag is
only accepted when the index lists a linux/amd64 image.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
import urllib.request


INDEX_MEDIA_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
MANIFEST_MEDIA_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
_ACCEPT = ", ".join((*INDEX_MEDIA_TYPES, *MANIFEST_MEDIA_TYPES))
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DOCKER_HUB_API = "registry-1.docker.io"
_DOCKER_HUB_HOSTS = {"docker.io", "index.docker.io", "registry-1.docker.io"}
_MAX_TAG_PAGES = 50
_USER_AGENT = "tracegate-engine-update"


class UpstreamError(RuntimeError):
    """The upstream registry could not answer a discovery question."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]  # lower-case header names
    body: bytes


class Transport(Protocol):
    def __call__(self, method: str, url: str, headers: dict[str, str]) -> HttpResponse: ...


def urllib_transport(timeout: float = 20.0) -> Transport:
    """Real transport: urllib with environment proxies; HTTP errors are returned, not raised."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler())

    def fetch(method: str, url: str, headers: dict[str, str]) -> HttpResponse:
        request = urllib.request.Request(url, method=method, headers={"User-Agent": _USER_AGENT, **headers})
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read() if method != "HEAD" else b""
                return HttpResponse(
                    status=int(response.status),
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=body,
                )
        except HTTPError as exc:
            try:
                body = exc.read() if method != "HEAD" else b""
            except Exception:  # noqa: BLE001
                body = b""
            return HttpResponse(
                status=int(exc.code),
                headers={key.lower(): value for key, value in (exc.headers or {}).items()},
                body=body,
            )
        except (URLError, OSError, TimeoutError) as exc:
            raise UpstreamError(f"{method} {url}: {exc}") from exc

    return fetch


def split_image(image: str) -> tuple[str, str]:
    """Return (registry API host, repository path) for a registry-file image repo."""
    first, _, rest = image.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = "docker.io", image
    if host in _DOCKER_HUB_HOSTS:
        host = _DOCKER_HUB_API
        if "/" not in path:
            path = f"library/{path}"
    return host, path


def _parse_www_authenticate(value: str) -> dict[str, str]:
    scheme, _, params = value.strip().partition(" ")
    if scheme.lower() != "bearer":
        return {}
    return {key.lower(): val for key, val in re.findall(r'(\w+)="([^"]*)"', params)}


@dataclass(frozen=True)
class TagDigest:
    tag: str
    digest: str
    media_type: str
    platform_digest: str | None


class RegistryClient:
    """Anonymous registry client; one instance caches tokens per repository."""

    def __init__(self, transport: Transport | None = None) -> None:
        self.transport = transport if transport is not None else urllib_transport()
        self._tokens: dict[tuple[str, str], str] = {}

    def _request(self, method: str, host: str, path: str, url: str, headers: dict[str, str]) -> HttpResponse:
        key = (host, path)
        sent = dict(headers)
        token = self._tokens.get(key)
        if token:
            sent["Authorization"] = f"Bearer {token}"
        response = self.transport(method, url, sent)
        if response.status != 401:
            return response
        challenge = _parse_www_authenticate(response.headers.get("www-authenticate", ""))
        realm = challenge.get("realm")
        if not realm:
            raise UpstreamError(f"{host}/{path}: 401 without a bearer challenge")
        query = {"scope": challenge.get("scope") or f"repository:{path}:pull"}
        if challenge.get("service"):
            query["service"] = challenge["service"]
        token_response = self.transport("GET", f"{realm}?{urlencode(query)}", {})
        if token_response.status != 200:
            raise UpstreamError(f"{host}/{path}: token endpoint answered {token_response.status}")
        try:
            payload = json.loads(token_response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpstreamError(f"{host}/{path}: token endpoint returned invalid JSON") from exc
        token = str(payload.get("token") or payload.get("access_token") or "")
        if not token:
            raise UpstreamError(f"{host}/{path}: token endpoint returned no token")
        self._tokens[key] = token
        sent["Authorization"] = f"Bearer {token}"
        response = self.transport(method, url, sent)
        if response.status == 401:
            raise UpstreamError(f"{host}/{path}: anonymous pull access denied")
        return response

    def resolve(self, image: str, tag: str, *, known_digest: str | None = None) -> TagDigest:
        """Digest of ``image:tag`` as docker RepoDigests reports it (index digest for multi-platform tags).

        ``known_digest``: when HEAD reports this digest, the manifest body is
        not fetched again (it was validated on an earlier run).
        """
        host, path = split_image(image)
        url = f"https://{host}/v2/{path}/manifests/{tag}"
        headers = {"Accept": _ACCEPT}
        head = self._request("HEAD", host, path, url, headers)
        if head.status == 404:
            raise UpstreamError(f"{image}:{tag} does not exist upstream")
        head_digest = head.headers.get("docker-content-digest", "") if head.status == 200 else ""
        if head_digest and head_digest == known_digest:
            return TagDigest(tag=tag, digest=head_digest, media_type=head.headers.get("content-type", ""), platform_digest=None)

        response = self._request("GET", host, path, url, headers)
        if response.status == 404:
            raise UpstreamError(f"{image}:{tag} does not exist upstream")
        if response.status != 200:
            raise UpstreamError(f"{image}:{tag}: manifest request answered {response.status}")
        computed = "sha256:" + hashlib.sha256(response.body).hexdigest()
        reported = response.headers.get("docker-content-digest", "")
        if reported and reported != computed:
            raise UpstreamError(f"{image}:{tag}: manifest digest header does not match its body")
        if head_digest and head_digest != computed:
            raise UpstreamError(f"{image}:{tag}: tag moved between HEAD and GET; retry later")
        try:
            manifest = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpstreamError(f"{image}:{tag}: manifest is not valid JSON") from exc
        media_type = str(manifest.get("mediaType") or response.headers.get("content-type", "")).split(";")[0].strip()
        platform_digest: str | None = None
        if media_type in INDEX_MEDIA_TYPES or isinstance(manifest.get("manifests"), list):
            for entry in manifest.get("manifests") or []:
                platform = entry.get("platform") if isinstance(entry, dict) else None
                if (
                    isinstance(platform, dict)
                    and platform.get("os") == "linux"
                    and platform.get("architecture") == "amd64"
                    and _DIGEST_RE.match(str(entry.get("digest") or ""))
                ):
                    platform_digest = str(entry["digest"])
                    break
            if platform_digest is None:
                raise UpstreamError(f"{image}:{tag}: the index has no linux/amd64 image")
        elif media_type not in MANIFEST_MEDIA_TYPES:
            raise UpstreamError(f"{image}:{tag}: unsupported manifest media type {media_type!r}")
        return TagDigest(tag=tag, digest=computed, media_type=media_type, platform_digest=platform_digest)

    def tags(self, image: str) -> list[str]:
        host, path = split_image(image)
        url = f"https://{host}/v2/{path}/tags/list?n=1000"
        collected: list[str] = []
        for _ in range(_MAX_TAG_PAGES):
            response = self._request("GET", host, path, url, {"Accept": "application/json"})
            if response.status != 200:
                raise UpstreamError(f"{image}: tags list answered {response.status}")
            try:
                payload = json.loads(response.body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise UpstreamError(f"{image}: tags list is not valid JSON") from exc
            collected.extend(str(tag) for tag in (payload.get("tags") or []) if isinstance(tag, str))
            link = response.headers.get("link", "")
            match = re.search(r"<([^>]+)>\s*;\s*rel=\"?next\"?", link)
            if not match:
                return collected
            url = urljoin(f"https://{host}/", match.group(1))
        raise UpstreamError(f"{image}: tags list has more than {_MAX_TAG_PAGES} pages")


def _allow_regex(allow: str) -> re.Pattern[str]:
    match = re.match(r"^(v?)(0|[1-9][0-9]*)\.\*$", allow)
    if match is None:
        raise UpstreamError(f"unsupported allow pattern: {allow!r}")
    prefix, major = match.groups()
    # Stable releases only: MAJOR.MINOR.PATCH, no pre-release or build suffix.
    return re.compile(rf"^{re.escape(prefix)}{major}\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def select_semver(tags: list[str], allow: str) -> str | None:
    """Highest stable tag within the allowed major, or None."""
    pattern = _allow_regex(allow)
    best: tuple[int, int] | None = None
    best_tag: str | None = None
    for tag in tags:
        match = pattern.match(tag)
        if match is None:
            continue
        key = (int(match.group(1)), int(match.group(2)))
        if best is None or key > best:
            best, best_tag = key, tag
    return best_tag


def semver_key(tag: str, allow: str) -> tuple[int, int] | None:
    match = _allow_regex(allow).match(tag)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))
