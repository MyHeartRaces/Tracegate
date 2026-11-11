from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess


def _executable(path: Path, text: str = "#!/bin/sh\nexit 0\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _release(root: Path, version: str) -> Path:
    release = root / "releases" / version
    runtime = release / "runtime"
    venv = release / "venv"
    (runtime / "scripts").mkdir(parents=True)
    (runtime / "deploy/systemd").mkdir(parents=True)
    (runtime / "deploy/host").mkdir(parents=True)
    (runtime / "deploy/systemd/example.service").write_text("[Service]\nExecStart=/bin/true\n")
    (runtime / "deploy/systemd/example.timer").write_text("[Timer]\nOnBootSec=1\n")
    (runtime / "deploy/host/90-tracegate-quic.conf").write_text("net.core.rmem_max = 16777216\n")
    _executable(runtime / "deploy/systemd/tracegate-shadowtls-env")
    _executable(runtime / "deploy/systemd/tracegate-telemt-permissions")
    _executable(runtime / "deploy/systemd/tracegate-artifact-verify")
    _executable(runtime / "deploy/host/tracegate-db-backup")
    _executable(runtime / "deploy/host/tracegate-network-qdisc")
    _executable(runtime / "deploy/host/tracegate-certbot-deploy-hook")
    (runtime / "scripts/check_host_runtime.py").write_text("raise SystemExit(0)\n")
    (runtime / "scripts/check_host_deploy.py").write_text("raise SystemExit(0)\n")
    for command in ("python", "tracegate-api", "tracegate-migrate-db", "tracegate-host-private-preflight"):
        _executable(venv / "bin" / command)
    _executable(
        venv / "bin" / "tracegate-artifacts",
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "${TRACEGATE_ARTIFACTS_LOG}"\n'
        "exit 0\n",
    )
    return release


def test_native_deploy_and_rollback_switch_real_release_targets(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    install_root = tmp_path / "opt/tracegate"
    old = _release(install_root, "3.1.4")
    new = _release(install_root, "3.1.5")
    install_root.mkdir(parents=True, exist_ok=True)
    (install_root / "current").symlink_to(old / "runtime")
    (install_root / "app").symlink_to(old / "runtime")
    (install_root / "venv").symlink_to(old / "venv")

    etc = tmp_path / "etc/tracegate"
    etc.mkdir(parents=True)
    runtime_env = etc / "tracegate.env"
    runtime_env.write_text("DATABASE_URL=postgresql+asyncpg://localhost/tracegate\n")
    runtime_env.chmod(0o600)
    deploy_env = etc / "deploy.env"
    deploy_env.write_text(
        "TRACEGATE_HOST_ROLE=endpoint\n"
        f"TRACEGATE_RUNTIME_ENV={runtime_env}\n"
        "TRACEGATE_BACKUP_COMMAND=true\n"
    )
    deploy_env.chmod(0o600)

    fake_bin = tmp_path / "bin"
    for command in ("systemctl", "curl", "sysctl"):
        _executable(fake_bin / command)

    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "TRACEGATE_INSTALL_ROOT": str(install_root),
        "TRACEGATE_ETC_DIR": str(etc),
        "TRACEGATE_DEPLOY_ENV": str(deploy_env),
        "TRACEGATE_STATE_DIR": str(tmp_path / "state"),
        "TRACEGATE_SYSTEMD_DIR": str(tmp_path / "systemd"),
        "TRACEGATE_SYSCTL_DIR": str(tmp_path / "sysctl.d"),
        "TRACEGATE_LOCAL_SBIN_DIR": str(tmp_path / "sbin"),
        "TRACEGATE_LETSENCRYPT_DEPLOY_HOOK_DIR": str(tmp_path / "letsencrypt-hooks"),
        "TRACEGATE_SYSTEMCTL": str(fake_bin / "systemctl"),
        "TRACEGATE_CURL": str(fake_bin / "curl"),
        "TRACEGATE_SYSCTL": str(fake_bin / "sysctl"),
        "TRACEGATE_HEALTH_ATTEMPTS": "1",
        "TRACEGATE_HEALTH_DELAY_SECONDS": "0",
        "TRACEGATE_ARTIFACTS_LOG": str(tmp_path / "artifacts.log"),
    }
    script = project_root / "deploy/host/tracegate-host-deploy"
    subprocess.run([str(script), "deploy", "3.1.5"], env=env, check=True)
    assert (install_root / "current").resolve() == new / "runtime"
    assert (install_root / "venv").resolve() == new / "venv"

    artifact_calls = (tmp_path / "artifacts.log").read_text(encoding="utf-8")
    capture_at = artifact_calls.index("capture --units")
    verify_at = artifact_calls.index("verify --units")
    assert capture_at < verify_at
    assert (tmp_path / "sbin" / "tracegate-artifact-verify").is_file()

    subprocess.run([str(script), "rollback"], env=env, check=True)
    assert (install_root / "current").resolve() == old / "runtime"
    assert (install_root / "app").resolve() == old / "runtime"
    assert (install_root / "venv").resolve() == old / "venv"


def test_failed_native_restart_restores_previous_release(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    install_root = tmp_path / "opt/tracegate"
    old = _release(install_root, "3.1.4")
    _release(install_root, "3.1.5")
    (install_root / "current").symlink_to(old / "runtime")
    (install_root / "app").symlink_to(old / "runtime")
    (install_root / "venv").symlink_to(old / "venv")

    etc = tmp_path / "etc/tracegate"
    etc.mkdir(parents=True)
    runtime_env = etc / "tracegate.env"
    runtime_env.write_text("DATABASE_URL=postgresql+asyncpg://localhost/tracegate\n")
    runtime_env.chmod(0o600)
    deploy_env = etc / "deploy.env"
    deploy_env.write_text(
        "TRACEGATE_HOST_ROLE=endpoint\n"
        f"TRACEGATE_RUNTIME_ENV={runtime_env}\n"
        "TRACEGATE_BACKUP_COMMAND=true\n"
    )
    deploy_env.chmod(0o600)

    fake_bin = tmp_path / "bin"
    fail_marker = tmp_path / "restart-failed-once"
    _executable(
        fake_bin / "systemctl",
        "#!/bin/sh\n"
        'if [ "$1" = restart ] && [ ! -e "$TRACEGATE_TEST_FAIL_MARKER" ]; then\n'
        '  touch "$TRACEGATE_TEST_FAIL_MARKER"\n'
        "  exit 1\n"
        "fi\n"
        "exit 0\n",
    )
    for command in ("curl", "sysctl"):
        _executable(fake_bin / command)

    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "TRACEGATE_INSTALL_ROOT": str(install_root),
        "TRACEGATE_ETC_DIR": str(etc),
        "TRACEGATE_DEPLOY_ENV": str(deploy_env),
        "TRACEGATE_STATE_DIR": str(tmp_path / "state"),
        "TRACEGATE_SYSTEMD_DIR": str(tmp_path / "systemd"),
        "TRACEGATE_SYSCTL_DIR": str(tmp_path / "sysctl.d"),
        "TRACEGATE_LOCAL_SBIN_DIR": str(tmp_path / "sbin"),
        "TRACEGATE_LETSENCRYPT_DEPLOY_HOOK_DIR": str(tmp_path / "letsencrypt-hooks"),
        "TRACEGATE_SYSTEMCTL": str(fake_bin / "systemctl"),
        "TRACEGATE_CURL": str(fake_bin / "curl"),
        "TRACEGATE_SYSCTL": str(fake_bin / "sysctl"),
        "TRACEGATE_HEALTH_ATTEMPTS": "1",
        "TRACEGATE_HEALTH_DELAY_SECONDS": "0",
        "TRACEGATE_TEST_FAIL_MARKER": str(fail_marker),
    }
    script = project_root / "deploy/host/tracegate-host-deploy"
    result = subprocess.run([str(script), "deploy", "3.1.5"], env=env, check=False)
    assert result.returncode != 0
    assert fail_marker.exists()
    assert (install_root / "current").resolve() == old / "runtime"
    assert (install_root / "app").resolve() == old / "runtime"
    assert (install_root / "venv").resolve() == old / "venv"


def test_native_deploy_aborts_before_any_state_change_when_artifacts_unverified(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    install_root = tmp_path / "opt/tracegate"
    old = _release(install_root, "3.1.4")
    new = _release(install_root, "3.1.5")
    _executable(
        new / "venv/bin/tracegate-artifacts",
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "${TRACEGATE_ARTIFACTS_LOG}"\n'
        'if [ "$1" = "verify" ]; then exit 1; fi\n'
        "exit 0\n",
    )
    (install_root / "current").symlink_to(old / "runtime")
    (install_root / "app").symlink_to(old / "runtime")
    (install_root / "venv").symlink_to(old / "venv")

    etc = tmp_path / "etc/tracegate"
    etc.mkdir(parents=True)
    runtime_env = etc / "tracegate.env"
    runtime_env.write_text("DATABASE_URL=postgresql+asyncpg://localhost/tracegate\n")
    runtime_env.chmod(0o600)
    deploy_env = etc / "deploy.env"
    deploy_env.write_text(
        "TRACEGATE_HOST_ROLE=endpoint\n"
        f"TRACEGATE_RUNTIME_ENV={runtime_env}\n"
        "TRACEGATE_BACKUP_COMMAND=true\n"
    )
    deploy_env.chmod(0o600)

    fake_bin = tmp_path / "bin"
    for command in ("systemctl", "curl", "sysctl"):
        _executable(fake_bin / command)

    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "TRACEGATE_INSTALL_ROOT": str(install_root),
        "TRACEGATE_ETC_DIR": str(etc),
        "TRACEGATE_DEPLOY_ENV": str(deploy_env),
        "TRACEGATE_STATE_DIR": str(tmp_path / "state"),
        "TRACEGATE_SYSTEMD_DIR": str(tmp_path / "systemd"),
        "TRACEGATE_SYSCTL_DIR": str(tmp_path / "sysctl.d"),
        "TRACEGATE_LOCAL_SBIN_DIR": str(tmp_path / "sbin"),
        "TRACEGATE_LETSENCRYPT_DEPLOY_HOOK_DIR": str(tmp_path / "letsencrypt-hooks"),
        "TRACEGATE_SYSTEMCTL": str(fake_bin / "systemctl"),
        "TRACEGATE_CURL": str(fake_bin / "curl"),
        "TRACEGATE_SYSCTL": str(fake_bin / "sysctl"),
        "TRACEGATE_HEALTH_ATTEMPTS": "1",
        "TRACEGATE_HEALTH_DELAY_SECONDS": "0",
        "TRACEGATE_ARTIFACTS_LOG": str(tmp_path / "artifacts.log"),
    }
    script = project_root / "deploy/host/tracegate-host-deploy"
    result = subprocess.run([str(script), "deploy", "3.1.5"], env=env, check=False)
    assert result.returncode != 0
    assert (install_root / "current").resolve() == old / "runtime"
    assert not (tmp_path / "state" / "previous.env").exists()
    assert not (tmp_path / "systemd" / "example.service").exists()
    artifact_calls = (tmp_path / "artifacts.log").read_text(encoding="utf-8")
    assert "capture --units" in artifact_calls
    assert "verify --units" in artifact_calls


def _endpoint_deploy_env(tmp_path: Path, runtime_env_text: str) -> tuple[Path, dict[str, str], Path]:
    project_root = Path(__file__).resolve().parents[1]
    install_root = tmp_path / "opt/tracegate"
    old = _release(install_root, "3.1.4")
    _release(install_root, "3.1.5")
    (install_root / "current").symlink_to(old / "runtime")
    (install_root / "app").symlink_to(old / "runtime")
    (install_root / "venv").symlink_to(old / "venv")
    etc = tmp_path / "etc/tracegate"
    etc.mkdir(parents=True)
    runtime_env = etc / "tracegate.env"
    runtime_env.write_text(runtime_env_text)
    runtime_env.chmod(0o600)
    deploy_env = etc / "deploy.env"
    deploy_env.write_text(
        "TRACEGATE_HOST_ROLE=endpoint\n"
        f"TRACEGATE_RUNTIME_ENV={runtime_env}\n"
        "TRACEGATE_BACKUP_COMMAND=true\n"
    )
    fake_bin = tmp_path / "bin"
    for command in ("systemctl", "curl", "sysctl"):
        _executable(fake_bin / command)
    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "TRACEGATE_INSTALL_ROOT": str(install_root),
        "TRACEGATE_ETC_DIR": str(etc),
        "TRACEGATE_DEPLOY_ENV": str(deploy_env),
        "TRACEGATE_STATE_DIR": str(tmp_path / "state"),
        "TRACEGATE_SYSTEMD_DIR": str(tmp_path / "systemd"),
        "TRACEGATE_SYSCTL_DIR": str(tmp_path / "sysctl.d"),
        "TRACEGATE_LOCAL_SBIN_DIR": str(tmp_path / "sbin"),
        "TRACEGATE_LETSENCRYPT_DEPLOY_HOOK_DIR": str(tmp_path / "letsencrypt-hooks"),
        "TRACEGATE_SYSTEMCTL": str(fake_bin / "systemctl"),
        "TRACEGATE_CURL": str(fake_bin / "curl"),
        "TRACEGATE_SYSCTL": str(fake_bin / "sysctl"),
        "TRACEGATE_HEALTH_ATTEMPTS": "1",
        "TRACEGATE_HEALTH_DELAY_SECONDS": "0",
        "TRACEGATE_ARTIFACTS_LOG": str(tmp_path / "artifacts.log"),
    }
    return project_root / "deploy/host/tracegate-host-deploy", env, runtime_env


def _hop_values(runtime_env: Path) -> dict[str, tuple[int, int]]:
    values: dict[str, tuple[int, int]] = {}
    for line in runtime_env.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.endswith("_HOP_PORTS") and value:
            lo, hi = value.split("-")
            values[key] = (int(lo), int(hi))
    return values


def test_endpoint_deploy_generates_private_hop_ranges_once(tmp_path: Path) -> None:
    script, env, runtime_env = _endpoint_deploy_env(tmp_path, "DATABASE_URL=postgresql+asyncpg://localhost/tracegate\n")

    subprocess.run([str(script), "deploy", "3.1.5"], env=env, check=True)
    first = _hop_values(runtime_env)
    gecko_lo, gecko_hi = first["HYSTERIA_GECKO_HOP_PORTS"]
    salamander_lo, salamander_hi = first["HYSTERIA_SALAMANDER_HOP_PORTS"]
    assert 20000 <= gecko_lo <= 23000 and gecko_hi == gecko_lo + 2999
    assert 26000 <= salamander_lo <= 29000 and salamander_hi == salamander_lo + 2999
    assert stat.S_IMODE(runtime_env.stat().st_mode) == 0o600

    subprocess.run([str(script), "deploy", "3.1.5"], env=env, check=True)
    assert _hop_values(runtime_env) == first
    assert runtime_env.read_text(encoding="utf-8").count("HOP_PORTS=") == 2


def test_endpoint_deploy_keeps_operator_hop_settings(tmp_path: Path) -> None:
    script, env, runtime_env = _endpoint_deploy_env(
        tmp_path,
        "DATABASE_URL=postgresql+asyncpg://localhost/tracegate\n"
        "HYSTERIA_GECKO_HOP_PORTS=\n"
        "export HYSTERIA_SALAMANDER_HOP_PORTS=30000-30999\n",
    )
    before = runtime_env.read_text(encoding="utf-8")

    subprocess.run([str(script), "deploy", "3.1.5"], env=env, check=True)

    assert runtime_env.read_text(encoding="utf-8") == before
