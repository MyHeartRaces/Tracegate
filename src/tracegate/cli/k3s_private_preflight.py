from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any

import yaml


class K3sPrivatePreflightError(RuntimeError):
    pass


_PLACEHOLDER_RE = re.compile(r"\b(?:REPLACE_[A-Z0-9_]+|CHANGE_ME|TODO|TBD)\b")
_TRUE_VALUES = {"1", "true", "yes", "y", "on", "enabled"}
_HOST_WIDE_KEYS = {
    "HOST_WIDE_INTERCEPTION",
    "TRACEGATE_HOST_WIDE_INTERCEPTION",
    "TRACEGATE_ZAPRET_HOST_WIDE_INTERCEPTION",
    "TRACEGATE_ZAPRET_HOSTWIDE",
    "ZAPRET_HOSTWIDE",
}
_NFQUEUE_KEYS = {
    "NFQUEUE",
    "TRACEGATE_NFQUEUE",
    "TRACEGATE_ZAPRET_NFQUEUE",
    "ZAPRET_NFQUEUE",
}
_HOST_WIDE_SCOPES = {"all", "all-host-traffic", "host", "host-wide", "hostwide", "system", "global"}
_BROAD_TARGET_VALUES = _HOST_WIDE_SCOPES | {"*", "any", "everything"}
_ZAPRET_TARGET_KEYS = {
    "APPLY_TO",
    "TRACEGATE_ZAPRET_APPLY_TO",
    "TRACEGATE_ZAPRET_TARGET_PROTOCOLS",
    "TRACEGATE_ZAPRET_TARGET_SURFACES",
    "ZAPRET_APPLY_TO",
    "ZAPRET_TARGET_PROTOCOLS",
    "ZAPRET_TARGET_SURFACES",
}
_ZAPRET_APPLY_MODE_KEYS = {
    "APPLY_MODE",
    "TRACEGATE_ZAPRET_APPLY_MODE",
    "ZAPRET_APPLY_MODE",
}
_BROAD_APPLY_MODES = {"all", "all-flows", "host-wide", "hostwide", "transparent-all"}
_WIREGUARD_FORBIDDEN_HOOK_KEYS = {"preup", "postup", "predown", "postdown"}
_WIREGUARD_FORBIDDEN_INTERFACE_KEYS = _WIREGUARD_FORBIDDEN_HOOK_KEYS | {"dns", "saveconfig"}
_SHADOWSOCKS2022_SECRET_KEYS = {"password", "psk", "key", "server_key", "user_key"}
_MTPROTO_RAW_SECRET_RE = re.compile(r"[0-9a-fA-F]{32}")
_MIERU_SECRET_KEYS = {"password", "pass", "secret", "token", "credential", "credentials", "key"}
_MIERU_AUTH_MODE_KEYS = {"auth", "authentication", "authmode", "auth_mode"}
_MIERU_ANONYMOUS_AUTH_VALUES = {"none", "noauth", "no-auth", "anonymous", "disabled", "off", "false"}
_MIERU_ANONYMOUS_BOOL_KEYS = {"allowanonymous", "allow_anonymous", "anonymous", "noauth", "no_auth", "disableauth", "disable_auth"}
_RESTLS_SECRET_KEYS = {"password", "secret", "token", "private_key", "key", "cert", "certificate", "tls_key"}
_RESTLS_INSECURE_TLS_KEYS = {
    "insecure",
    "allow_insecure",
    "skip_cert_verify",
    "skip_certificate_verify",
    "tls_insecure",
    "disable_certificate_verification",
}
_TUIC_SECRET_KEYS = {"uuid", "password", "token", "secret", "shared_secret", "private_key"}
_TUIC_ZERO_RTT_KEYS = {"0rtt", "0_rtt", "zero_rtt", "zerortt", "zero_rtt_handshake", "enable_0rtt", "enable_0_rtt"}


def _is_true(value: object) -> bool:
    return str(value or "").strip().strip("\"'").lower() in _TRUE_VALUES


def _resolve_private_child(root: Path, rel_path: str) -> Path:
    raw = str(rel_path or "").strip()
    if not raw:
        raise K3sPrivatePreflightError("empty private file path")
    child = Path(raw)
    if child.is_absolute() or ".." in child.parts:
        raise K3sPrivatePreflightError(f"private file path must stay under private root: {raw}")
    root_resolved = root.resolve()
    candidate = (root / child).resolve()
    if not candidate.is_relative_to(root_resolved):
        raise K3sPrivatePreflightError(f"private file path escapes private root: {raw}")
    return candidate


def _read_required_text(path: Path, *, label: str) -> str:
    try:
        stat = path.stat()
    except FileNotFoundError as exc:
        raise K3sPrivatePreflightError(f"{label} private file is missing: {path}") from exc
    if not path.is_file():
        raise K3sPrivatePreflightError(f"{label} private path is not a file: {path}")
    if stat.st_size <= 0:
        raise K3sPrivatePreflightError(f"{label} private file is empty: {path}")
    if stat.st_mode & 0o007:
        raise K3sPrivatePreflightError(f"{label} private file must not be accessible by world permissions: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def _reject_placeholders(content: str, *, label: str, path: Path) -> None:
    if _PLACEHOLDER_RE.search(content):
        raise K3sPrivatePreflightError(f"{label} private file still contains placeholder markers: {path}")


def _validate_structured_file(path: Path, content: str, *, label: str) -> Any | None:
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise K3sPrivatePreflightError(f"{label} private JSON is invalid: {path}") from exc
        if not isinstance(parsed, (dict, list)):
            raise K3sPrivatePreflightError(f"{label} private JSON must be an object or list: {path}")
        return parsed
    if suffix in {".yaml", ".yml"}:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise K3sPrivatePreflightError(f"{label} private YAML is invalid: {path}") from exc
    return None


def _path_has_part(path: Path, name: str) -> bool:
    return name.strip().lower() in {part.lower() for part in path.parts}


def _key_values(value: Any, key: str) -> list[Any]:
    target = key.strip().lower()
    values: list[Any] = []
    if isinstance(value, dict):
        for raw_key, child in value.items():
            if str(raw_key).strip().lower() == target:
                values.append(child)
            values.extend(_key_values(child, target))
    elif isinstance(value, list):
        for child in value:
            values.extend(_key_values(child, target))
    return values


def _has_key(value: Any, key: str) -> bool:
    target = key.strip().lower()
    if isinstance(value, dict):
        return any(str(raw_key).strip().lower() == target or _has_key(child, target) for raw_key, child in value.items())
    if isinstance(value, list):
        return any(_has_key(child, target) for child in value)
    return False


def _has_nonempty_value(value: Any, keys: set[str]) -> bool:
    normalized_keys = {key.strip().lower() for key in keys}
    if isinstance(value, dict):
        for raw_key, child in value.items():
            if str(raw_key).strip().lower() in normalized_keys and str(child or "").strip():
                return True
            if _has_nonempty_value(child, normalized_keys):
                return True
    elif isinstance(value, list):
        return any(_has_nonempty_value(child, normalized_keys) for child in value)
    return False


def _normalized_key(value: object) -> str:
    return str(value or "").strip().lower().replace("-", "").replace("_", "")


def _has_forbidden_mieru_auth_mode(value: Any) -> bool:
    auth_mode_keys = {_normalized_key(key) for key in _MIERU_AUTH_MODE_KEYS}
    anonymous_bool_keys = {_normalized_key(key) for key in _MIERU_ANONYMOUS_BOOL_KEYS}
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = _normalized_key(raw_key)
            if key in auth_mode_keys and not isinstance(child, (dict, list)):
                if str(child or "").strip().strip("\"'").lower() in _MIERU_ANONYMOUS_AUTH_VALUES:
                    return True
            if key in anonymous_bool_keys and _is_true(child):
                return True
            if _has_forbidden_mieru_auth_mode(child):
                return True
    elif isinstance(value, list):
        return any(_has_forbidden_mieru_auth_mode(child) for child in value)
    return False


def _has_true_normalized_key(value: Any, keys: set[str]) -> bool:
    normalized_keys = {_normalized_key(key) for key in keys}
    if isinstance(value, dict):
        for raw_key, child in value.items():
            if _normalized_key(raw_key) in normalized_keys and _is_true(child):
                return True
            if _has_true_normalized_key(child, normalized_keys):
                return True
    elif isinstance(value, list):
        return any(_has_true_normalized_key(child, normalized_keys) for child in value)
    return False


def _looks_mieru_config(path: Path) -> bool:
    return _path_has_part(path, "mieru") or "mieru" in path.name.lower()


def _validate_mieru_config(path: Path, parsed: Any | None, *, label: str) -> None:
    if not _looks_mieru_config(path):
        return
    if not isinstance(parsed, (dict, list)):
        raise K3sPrivatePreflightError(f"{label} Mieru config must be a JSON/YAML object or list: {path}")
    if not _has_nonempty_value(parsed, _MIERU_SECRET_KEYS):
        raise K3sPrivatePreflightError(f"{label} Mieru config is missing private credential material: {path}")
    if _has_forbidden_mieru_auth_mode(parsed):
        raise K3sPrivatePreflightError(f"{label} Mieru config must not allow anonymous/no-auth mode: {path}")


def _looks_tuic_config(path: Path) -> bool:
    return _path_has_part(path, "tuic") or "tuic" in path.name.lower()


def _looks_restls_config(path: Path) -> bool:
    return _path_has_part(path, "restls") or "restls" in path.name.lower()


def _validate_restls_config(path: Path, parsed: Any | None, *, label: str) -> None:
    if not _looks_restls_config(path):
        return
    if not isinstance(parsed, (dict, list)):
        raise K3sPrivatePreflightError(f"{label} RESTLS config must be a JSON/YAML object or list: {path}")
    if not _has_nonempty_value(parsed, _RESTLS_SECRET_KEYS):
        raise K3sPrivatePreflightError(f"{label} RESTLS config is missing private credential material: {path}")
    if _has_true_normalized_key(parsed, _RESTLS_INSECURE_TLS_KEYS):
        raise K3sPrivatePreflightError(f"{label} RESTLS lab config must not disable TLS verification: {path}")


def _validate_tuic_config(path: Path, parsed: Any | None, *, label: str) -> None:
    if not _looks_tuic_config(path):
        return
    if not isinstance(parsed, (dict, list)):
        raise K3sPrivatePreflightError(f"{label} TUIC config must be a JSON/YAML object or list: {path}")
    if not _has_nonempty_value(parsed, _TUIC_SECRET_KEYS):
        raise K3sPrivatePreflightError(f"{label} TUIC config is missing private credential material: {path}")
    if _has_true_normalized_key(parsed, _TUIC_ZERO_RTT_KEYS):
        raise K3sPrivatePreflightError(f"{label} TUIC lab config must keep 0-RTT disabled: {path}")


def _looks_shadowsocks2022_config(path: Path) -> bool:
    return _path_has_part(path, "shadowsocks2022") or path.name.lower() in {"ss2022.json", "shadowsocks2022.json"}


def _validate_shadowsocks2022_config(path: Path, parsed: Any | None, *, label: str) -> None:
    if not _looks_shadowsocks2022_config(path):
        return
    if not isinstance(parsed, dict):
        raise K3sPrivatePreflightError(f"{label} Shadowsocks-2022 config must be a JSON object: {path}")

    methods = [str(value or "").strip().lower() for value in _key_values(parsed, "method")]
    if not methods or not any(method.startswith("2022-") for method in methods):
        raise K3sPrivatePreflightError(f"{label} Shadowsocks config must use a 2022-* method: {path}")
    if not _has_nonempty_value(parsed, _SHADOWSOCKS2022_SECRET_KEYS):
        raise K3sPrivatePreflightError(f"{label} Shadowsocks-2022 config is missing private key/password material: {path}")


def _looks_shadowtls_config(path: Path) -> bool:
    return _path_has_part(path, "shadowtls") or path.name.lower() in {"shadowtls.yaml", "shadowtls.yml", "shadowtls.json"}


def _validate_shadowtls_config(path: Path, parsed: Any | None, *, label: str) -> None:
    if not _looks_shadowtls_config(path):
        return
    if not isinstance(parsed, dict):
        raise K3sPrivatePreflightError(f"{label} ShadowTLS config must be a YAML/JSON object: {path}")

    versions = [str(value or "").strip().lower() for value in _key_values(parsed, "version")]
    has_v3_section = _has_key(parsed, "v3")
    if not has_v3_section and not any(version == "3" or version == "v3" for version in versions):
        raise K3sPrivatePreflightError(f"{label} ShadowTLS config must declare version 3: {path}")
    if not _has_nonempty_value(parsed, {"password"}):
        raise K3sPrivatePreflightError(f"{label} ShadowTLS v3 config is missing password material: {path}")


def _looks_mtproto_secret(path: Path) -> bool:
    return _path_has_part(path, "mtproto") or path.name.lower() in {"mtproto-secret", "mtproto-secret.txt"}


def _validate_mtproto_secret(path: Path, content: str, *, label: str) -> None:
    if not _looks_mtproto_secret(path):
        return
    values = [line.split("#", 1)[0].strip() for line in content.splitlines()]
    values = [value for value in values if value]
    if len(values) != 1 or _MTPROTO_RAW_SECRET_RE.fullmatch(values[0]) is None:
        raise K3sPrivatePreflightError(
            f"{label} MTProto secret must contain exactly one raw 32-hex-character server secret: {path}"
        )


def _parse_wireguard_sections(content: str) -> dict[str, set[str]]:
    sections: dict[str, set[str]] = {}
    current_section = ""
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip().lower()
            if current_section:
                sections.setdefault(current_section, set())
            continue
        if "=" not in line:
            continue
        key, _value = line.split("=", 1)
        key_normalized = key.strip().lower()
        if current_section and key_normalized:
            sections.setdefault(current_section, set()).add(key_normalized)
    return sections


def _parse_wireguard_values(content: str) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current_section = ""
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip().lower()
            if current_section:
                sections.setdefault(current_section, {})
            continue
        if "=" not in line or not current_section:
            continue
        key, value = line.split("=", 1)
        key_normalized = key.strip().lower()
        value_normalized = value.strip()
        if key_normalized and value_normalized:
            sections.setdefault(current_section, {}).setdefault(key_normalized, []).append(value_normalized)
    return sections


def _looks_wireguard_config(path: Path) -> bool:
    normalized_parts = {part.lower() for part in path.parts}
    return "wireguard" in normalized_parts or path.name.lower() in {"wg.conf", "wg0.conf"}


def _validate_wireguard_allowed_ips(values: list[str], *, label: str, path: Path) -> None:
    for value in values:
        for token in re.split(r"[\s,]+", value):
            if not token:
                continue
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise K3sPrivatePreflightError(f"{label} WireGuard AllowedIPs entry is invalid: {token}") from exc
            if (network.version == 4 and network.prefixlen <= 1) or (
                network.version == 6 and network.prefixlen <= 1
            ):
                raise K3sPrivatePreflightError(
                    f"{label} WireGuard config must not install default or split-default routes via AllowedIPs: {path}"
                )


def _validate_wireguard_mtu(values: list[str], *, label: str) -> None:
    for value in values:
        try:
            mtu = int(value)
        except ValueError as exc:
            raise K3sPrivatePreflightError(f"{label} WireGuard Interface MTU must be an integer") from exc
        if mtu < 1200 or mtu > 1420:
            raise K3sPrivatePreflightError(f"{label} WireGuard Interface MTU must stay within 1200..1420")


def _validate_wireguard_keepalive(values: list[str], *, label: str) -> None:
    for value in values:
        try:
            keepalive = int(value)
        except ValueError as exc:
            raise K3sPrivatePreflightError(f"{label} WireGuard PersistentKeepalive must be an integer") from exc
        if keepalive < 0 or keepalive > 60:
            raise K3sPrivatePreflightError(f"{label} WireGuard PersistentKeepalive must stay within 0..60")


def _validate_wireguard_config(path: Path, content: str, *, label: str) -> None:
    if not _looks_wireguard_config(path):
        return
    sections = _parse_wireguard_sections(content)
    values = _parse_wireguard_values(content)
    interface_keys = sections.get("interface", set())
    if not interface_keys:
        raise K3sPrivatePreflightError(f"{label} WireGuard config is missing [Interface]: {path}")
    if "privatekey" not in interface_keys:
        raise K3sPrivatePreflightError(f"{label} WireGuard config is missing Interface PrivateKey: {path}")
    if not {"address", "listenport"}.intersection(interface_keys):
        raise K3sPrivatePreflightError(f"{label} WireGuard config must declare Interface Address or ListenPort: {path}")
    forbidden = sorted(interface_keys.intersection(_WIREGUARD_FORBIDDEN_INTERFACE_KEYS))
    if forbidden:
        raise K3sPrivatePreflightError(
            f"{label} WireGuard config contains wg-quick host-network side effects: {', '.join(forbidden)}"
        )
    _validate_wireguard_mtu(values.get("interface", {}).get("mtu", []), label=label)
    for peer_values in [section for section_name, section in values.items() if section_name == "peer"]:
        _validate_wireguard_allowed_ips(peer_values.get("allowedips", []), label=label, path=path)
        _validate_wireguard_keepalive(peer_values.get("persistentkeepalive", []), label=label)


def _parse_env(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        values[key] = value.strip().strip("\"'")
    return values


def _env_list_tokens(value: object) -> set[str]:
    raw = str(value or "").strip().lower()
    if not raw:
        return set()
    return {token for token in re.split(r"[\s,;:]+", raw) if token}


def _validate_zapret_profile(
    path: Path,
    content: str,
    *,
    allow_host_wide_interception: bool,
    allow_nfqueue: bool,
) -> None:
    values = _parse_env(content)
    if not allow_host_wide_interception:
        scope = str(
            values.get("TRACEGATE_ZAPRET_SCOPE")
            or values.get("ZAPRET_SCOPE")
            or values.get("SCOPE")
            or ""
        ).strip().lower()
        if scope in _HOST_WIDE_SCOPES:
            raise K3sPrivatePreflightError(f"zapret2 profile uses forbidden host-wide scope: {path}")
        for key in _HOST_WIDE_KEYS:
            if _is_true(values.get(key)):
                raise K3sPrivatePreflightError(f"zapret2 profile enables host-wide interception via {key}: {path}")
        for key in _ZAPRET_TARGET_KEYS:
            tokens = _env_list_tokens(values.get(key))
            if tokens.intersection(_BROAD_TARGET_VALUES):
                raise K3sPrivatePreflightError(f"zapret2 profile targets broad host traffic via {key}: {path}")
        for key in _ZAPRET_APPLY_MODE_KEYS:
            mode = str(values.get(key) or "").strip().lower()
            if mode in _BROAD_APPLY_MODES:
                raise K3sPrivatePreflightError(f"zapret2 profile applies to broad host traffic via {key}: {path}")
    if not allow_nfqueue:
        for key in _NFQUEUE_KEYS:
            if _is_true(values.get(key)):
                raise K3sPrivatePreflightError(f"zapret2 profile enables broad NFQUEUE via {key}: {path}")


def validate_private_mount(
    *,
    root: Path,
    role: str,
    required_files: list[str],
    zapret_files: list[str],
    forbid_placeholders: bool = True,
    allow_host_wide_interception: bool = False,
    allow_nfqueue: bool = False,
) -> dict[str, int | str]:
    role_upper = str(role or "").strip().upper()
    if role_upper not in {"ENTRY", "TRANSIT"}:
        raise K3sPrivatePreflightError(f"role must be ENTRY or TRANSIT, got: {role}")

    if not root.exists() or not root.is_dir():
        raise K3sPrivatePreflightError(f"private root is missing or not a directory: {root}")

    seen: set[str] = set()
    checked_required = 0
    for rel_path in required_files:
        normalized = str(rel_path or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        path = _resolve_private_child(root, normalized)
        content = _read_required_text(path, label=normalized)
        if forbid_placeholders:
            _reject_placeholders(content, label=normalized, path=path)
        parsed = _validate_structured_file(path, content, label=normalized)
        _validate_mieru_config(path, parsed, label=normalized)
        _validate_restls_config(path, parsed, label=normalized)
        _validate_tuic_config(path, parsed, label=normalized)
        _validate_shadowsocks2022_config(path, parsed, label=normalized)
        _validate_shadowtls_config(path, parsed, label=normalized)
        _validate_mtproto_secret(path, content, label=normalized)
        _validate_wireguard_config(path, content, label=normalized)
        checked_required += 1

    checked_zapret = 0
    for rel_path in zapret_files:
        normalized = str(rel_path or "").strip()
        if not normalized:
            continue
        path = _resolve_private_child(root, normalized)
        content = _read_required_text(path, label=normalized)
        if forbid_placeholders:
            _reject_placeholders(content, label=normalized, path=path)
        _validate_zapret_profile(
            path,
            content,
            allow_host_wide_interception=allow_host_wide_interception,
            allow_nfqueue=allow_nfqueue,
        )
        checked_zapret += 1

    return {
        "role": role_upper,
        "requiredFiles": checked_required,
        "zapretFiles": checked_zapret,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracegate-k3s-private-preflight",
        description="Validate mounted Tracegate private profile Secret files before starting a k3s gateway pod.",
    )
    parser.add_argument("--root", default="/etc/tracegate/private", help="Mounted private Secret root")
    parser.add_argument("--role", required=True, choices=["ENTRY", "TRANSIT", "entry", "transit"], help="Gateway role")
    parser.add_argument("--required-file", action="append", default=[], help="Private file path relative to --root")
    parser.add_argument("--zapret-file", action="append", default=[], help="zapret2 env file path relative to --root")
    parser.add_argument("--allow-placeholders", action="store_true", help="Allow REPLACE_/TODO placeholders")
    parser.add_argument("--allow-host-wide-interception", action="store_true", help="Allow host-wide zapret2 scopes")
    parser.add_argument("--allow-nfqueue", action="store_true", help="Allow broad NFQUEUE zapret2 settings")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = validate_private_mount(
            root=Path(args.root),
            role=args.role,
            required_files=args.required_file,
            zapret_files=args.zapret_file,
            forbid_placeholders=not args.allow_placeholders,
            allow_host_wide_interception=args.allow_host_wide_interception,
            allow_nfqueue=args.allow_nfqueue,
        )
    except K3sPrivatePreflightError as exc:
        raise SystemExit(str(exc)) from exc

    sys.stdout.write(
        "OK k3s private preflight "
        f"role={report['role']} "
        f"required_files={report['requiredFiles']} "
        f"zapret_files={report['zapretFiles']}\n"
    )


if __name__ == "__main__":
    main()
