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
    _executable(runtime / "deploy/host/tracegate-db-backup")
    (runtime / "scripts/check_host_runtime.py").write_text("raise SystemExit(0)\n")
    (runtime / "scripts/check_host_deploy.py").write_text("raise SystemExit(0)\n")
    for command in ("python", "tracegate-api", "tracegate-migrate-db", "tracegate-host-private-preflight"):
        _executable(venv / "bin" / command)
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
        "TRACEGATE_SYSTEMCTL": str(fake_bin / "systemctl"),
        "TRACEGATE_CURL": str(fake_bin / "curl"),
        "TRACEGATE_SYSCTL": str(fake_bin / "sysctl"),
        "TRACEGATE_HEALTH_ATTEMPTS": "1",
        "TRACEGATE_HEALTH_DELAY_SECONDS": "0",
    }
    script = project_root / "deploy/host/tracegate-host-deploy"
    subprocess.run([str(script), "deploy", "3.1.5"], env=env, check=True)
    assert (install_root / "current").resolve() == new / "runtime"
    assert (install_root / "venv").resolve() == new / "venv"

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
