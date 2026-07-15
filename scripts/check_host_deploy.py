from __future__ import annotations

import argparse
from pathlib import Path
import subprocess


def _require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def check(root: Path, *, compose_runtime: bool = False) -> None:
    if compose_runtime:
        raise RuntimeError("Docker Compose host runtime is retired")

    deploy_path = root / "deploy/host/tracegate-host-deploy"
    install_path = root / "deploy/host/tracegate-host-install"
    backup_path = root / "deploy/host/tracegate-db-backup"
    env_path = root / "deploy/host/deploy.env.example"
    for path in (deploy_path, install_path, backup_path, env_path):
        _require(path.is_file(), f"missing host deployment file: {path.relative_to(root)}")
    _require(not (root / "deploy/host/compose.yaml").exists(), "retired Compose file is still present")
    _require(not (root / "deploy/host/tracegate-host.service").exists(), "retired Compose unit is still present")

    deploy = deploy_path.read_text()
    for token in (
        "TRACEGATE_HOST_ROLE",
        "tracegate-entry.env",
        "tracegate-host-private-preflight",
        "capture_previous_state",
        "PREVIOUS_CURRENT",
        "PREVIOUS_VENV",
        "switch_release",
        "restore_previous",
        "tracegate-migrate-db",
        "TRACEGATE_BACKUP_COMMAND",
        "wait_healthy",
        "database migrations were not downgraded",
    ):
        _require(token in deploy, f"host deploy script is missing contract: {token}")
    for forbidden in ("docker compose", "TRACEGATE_IMAGE", "POSTGRES_IMAGE", "deploy.env.previous"):
        _require(forbidden not in deploy, f"host deploy script still contains retired contract: {forbidden}")

    installer = install_path.read_text()
    for token in (
        "packages/tracegate-${VERSION}-*.whl",
        '"${PYTHON}" -m venv',
        "/releases/",
        "check_host_runtime.py",
        "check_host_deploy.py",
        "90-tracegate-quic.conf",
        "systemctl",
    ):
        _require(token in installer, f"host installer is missing contract: {token}")
    _require("current.new" not in installer, "installer must stage without switching the active release")

    units = {
        "tracegate-api.service": "/opt/tracegate/venv/bin/tracegate-api",
        "tracegate-bot.service": "/opt/tracegate/venv/bin/tracegate-bot",
        "tracegate-dispatcher.service": "/opt/tracegate/venv/bin/tracegate-dispatcher",
        "tracegate-agent.service": "EnvironmentFile=/etc/tracegate/tracegate.env",
        "tracegate-agent-entry.service": "EnvironmentFile=/etc/tracegate/tracegate-entry.env",
        "tracegate-entry-firewall.service": "ConditionPathExists=/etc/tracegate/entry-origin.nft",
        "tracegate-db-backup.service": "/usr/local/sbin/tracegate-db-backup",
        "tracegate-db-backup.timer": "Persistent=true",
    }
    for name, token in units.items():
        text = (root / "deploy/systemd" / name).read_text()
        _require(token in text, f"{name} is missing native host contract: {token}")
        _require("k3s" not in text.lower(), f"{name} references retired k3s runtime")

    env = env_path.read_text()
    _require("TRACEGATE_HOST_ROLE=endpoint" in env, "native host role is not documented")
    _require("TRACEGATE_RUNTIME_ENV=/etc/tracegate/tracegate.env" in env, "Endpoint env path is not documented")
    _require("TRACEGATE_ENTRY_RUNTIME_ENV=/etc/tracegate/tracegate-entry.env" in env, "Entry env path is not documented")
    for forbidden in ("TRACEGATE_IMAGE", "POSTGRES_IMAGE", "TRACEGATE_COMPOSE_PROFILES"):
        _require(forbidden not in env, f"deployment example still contains Compose field: {forbidden}")

    for script in (deploy_path, install_path, backup_path):
        subprocess.run(["bash", "-n", str(script)], check=True)

    dockerfile_path = root / "Dockerfile"
    if dockerfile_path.exists():
        dockerfile = dockerfile_path.read_text()
        _require("FROM ghcr.io/xtls/xray-core:latest AS xray-runtime" in dockerfile, "Xray runtime must track latest")
        _require("@sha256:" not in dockerfile, "Dockerfile must not lock runtime images by digest")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the native host production deployment contract")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--compose-runtime", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    check(root, compose_runtime=args.compose_runtime)
    print(f"native host deployment check passed ({root})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
