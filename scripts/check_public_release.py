from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import re
import subprocess


_SKIPPED_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build"}
_ALLOWED_EMAIL_DOMAINS = {"example.com", "example.net", "example.org", "users.noreply.github.com"}
_ALLOWED_PUBLIC_TEST_IPS = {
    "1.0.0.1",
    "1.0.0.2",
    "8.8.4.4",
    "8.8.8.8",
    "9.9.9.9",
    "103.21.244.0",
    "128.0.0.0",
}
_SECRET_PATTERNS = {
    "GitHub token": re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "Telegram bot token": re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{30,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "credential URL": re.compile(r"\b(?:postgres(?:ql)?|redis|mongodb)://[^\s/:@]+:[^\s@]+@", re.IGNORECASE),
}
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_SYSTEMD_INSTANCE_PATTERN = re.compile(r"\b[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+\.(?:service|socket|timer)\b")
_IPV4_PATTERN = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_HOME_PATH_PATTERN = re.compile(r"/(?:Users|home)/(?!app(?:/|$)|runner(?:/|$))[A-Za-z0-9._-]+/")


def _blocked_needles() -> tuple[str, ...]:
    live_domain = "".join(("trace", "gate", ".", "su"))
    main_domain = "".join(("my", "heart", "races", ".", "online"))
    return (
        live_domain,
        main_domain,
        live_domain.encode("utf-8").hex(),
        main_domain.encode("utf-8").hex(),
        "".join(("@", "sengoku", "batsu")),
        "".join(("255", "761", "416")),
        ".".join(("178", "250", "243")) + ".",
        ".".join(("2", "59", "219")) + ".",
        ".".join(("79", "137", "195")) + ".",
    )


def _tracked_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        # Release archives intentionally contain no Git metadata. Treat the
        # extracted tree as the complete release input instead of making the
        # privacy gate unusable outside a checkout.
        return _all_files(root)
    return [root / value.decode("utf-8") for value in result.stdout.split(b"\0") if value]


def _all_files(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file() and not any(part in _SKIPPED_PARTS for part in path.relative_to(root).parts)
    ]


def _is_allowed_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_unspecified
        or address.is_link_local
        or address in ipaddress.ip_network("192.0.2.0/24")
        or address in ipaddress.ip_network("198.51.100.0/24")
        or address in ipaddress.ip_network("203.0.113.0/24")
        or address == ipaddress.ip_address("1.1.1.1")
        or address in ipaddress.ip_network("173.245.48.0/20")
        or value in _ALLOWED_PUBLIC_TEST_IPS
    )


def scan_release_tree(root: Path, *, all_files: bool = False) -> list[str]:
    findings: list[str] = []
    paths = _all_files(root) if all_files else _tracked_files(root)
    blocked_needles = _blocked_needles()

    for path in paths:
        relative = path.relative_to(root).as_posix()
        if path.name == ".env" or path.suffix.lower() in {".key", ".pem", ".p12", ".pfx", ".kubeconfig"}:
            findings.append(f"{relative}: private file type")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        lowered = text.lower()
        for needle in blocked_needles:
            if needle.lower() in lowered:
                findings.append(f"{relative}: live deployment identifier")
                break
        for label, pattern in _SECRET_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{relative}: {label}")
        if _HOME_PATH_PATTERN.search(text):
            findings.append(f"{relative}: local home path")
        email_scan_text = _SYSTEMD_INSTANCE_PATTERN.sub("", text)
        for match in _EMAIL_PATTERN.finditer(email_scan_text):
            domain = match.group(1).lower()
            if not domain.endswith(".test") and not any(
                domain == allowed or domain.endswith(f".{allowed}") for allowed in _ALLOWED_EMAIL_DOMAINS
            ):
                findings.append(f"{relative}: non-example email address")
                break
        for value in _IPV4_PATTERN.findall(text):
            if not _is_allowed_ip(value):
                findings.append(f"{relative}: non-reserved public IPv4 address")
                break

    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser(description="Reject private material from public Tracegate release inputs")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--all-files", action="store_true", help="scan every file under an extracted release tree")
    args = parser.parse_args()

    root = args.root.resolve()
    findings = scan_release_tree(root, all_files=args.all_files)
    if findings:
        print("public release privacy check failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print(f"public release privacy check passed ({root})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
