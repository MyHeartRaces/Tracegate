from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess

import yaml


def _require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def check(root: Path, *, compose_runtime: bool = False) -> None:
    compose_path = root / "deploy/host/compose.yaml"
    deploy_script_path = root / "deploy/host/tracegate-host-deploy"
    install_path = root / "deploy/host/tracegate-host-install"
    unit_path = root / "deploy/host/tracegate-host.service"
    env_example_path = root / "deploy/host/deploy.env.example"
    for path in (compose_path, deploy_script_path, install_path, unit_path, env_example_path):
        _require(path.is_file(), f"missing host deployment file: {path.relative_to(root)}")

    compose_text = compose_path.read_text()
    compose = yaml.safe_load(compose_text)
    services = compose.get("services", {})
    _require(
        {"postgres", "migrate", "api", "dispatcher", "bot", "agent", "wireguard-sync"}.issubset(services),
        "host compose is missing required services",
    )
    _require("TRACEGATE_IMAGE:?" in compose_text, "host compose must require an application image")
    _require("POSTGRES_IMAGE:?" in compose_text, "host compose must require a PostgreSQL image")
    _require(services["migrate"].get("command") == "tracegate-migrate-db", "migration gate is not configured")
    for service_name in ("postgres", "migrate", "api", "dispatcher", "bot"):
        _require("control" in services[service_name].get("profiles", []), f"{service_name} must be control-only")
    api_dependencies = services["api"].get("depends_on", {})
    _require(
        api_dependencies.get("migrate", {}).get("condition") == "service_completed_successfully",
        "API must wait for successful migrations",
    )
    api_ports = services["api"].get("ports", [])
    _require(any(str(port).startswith("127.0.0.1:") for port in api_ports), "API must bind to loopback")
    _require("/ready" in str(services["api"].get("healthcheck", {})), "API readiness healthcheck is missing")
    _require("gateway" in services["agent"].get("profiles", []), "agent must remain an explicit gateway profile")
    _require(services["agent"].get("network_mode") == "host", "gateway agent must use host networking")
    _require("gateway" in services["wireguard-sync"].get("profiles", []), "WireGuard sync must be a gateway profile")
    _require("NET_ADMIN" in services["wireguard-sync"].get("cap_add", []), "WireGuard sync needs NET_ADMIN")
    _require("tracegate-wireguard-sync-runner" in services["wireguard-sync"].get("command", ""), "WireGuard sync command is missing")

    deploy_script = deploy_script_path.read_text()
    for token in (
        "compose config --quiet",
        "tracegate-host-private-preflight",
        "TRACEGATE_COMPOSE_PROFILES",
        "TRACEGATE_AGENT_HEALTH_URL",
        "TRACEGATE_BACKUP_COMMAND",
        "compose run --rm migrate",
        "compose pull",
        "rollback",
        "deploy.env.previous",
        "@sha256:",
    ):
        _require(token in deploy_script, f"host deploy script is missing contract: {token}")
    _require("database migrations are not downgraded" in deploy_script, "rollback migration warning is missing")

    unit = unit_path.read_text()
    _require("EnvironmentFile=/etc/tracegate/deploy.env" in unit, "systemd unit must use external deploy env")
    _require("tracegate-host-deploy up" in unit, "systemd unit start command is missing")

    installer = install_path.read_text()
    for token in ("check_host_runtime.py", "check_host_deploy.py", "/releases/", "current.new", "systemctl daemon-reload"):
        _require(token in installer, f"host installer is missing contract: {token}")

    env_example = env_example_path.read_text()
    _require("REPLACE_ME" not in env_example, "deployment example uses a forbidden secret placeholder")
    _require(
        len(re.findall(r"@sha256:REPLACE_WITH_64_HEX_DIGEST", env_example)) == 2,
        "deployment example must document both immutable image pins",
    )

    if compose_runtime:
        subprocess.run(
            ["docker", "compose", "--env-file", str(env_example_path), "-f", str(compose_path), "config", "--quiet"],
            check=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the host-based production deployment contract")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--compose-runtime", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    check(root, compose_runtime=args.compose_runtime)
    print(f"host deployment check passed ({root})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
