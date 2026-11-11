from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

DIGEST = "sha256:" + "a" * 64
IMAGE = f"ghcr.io/example/xray@{DIGEST}"
VERIFY = Path(__file__).resolve().parents[1] / "deploy" / "systemd" / "tracegate-artifact-verify"


def _fake_docker(bin_dir: Path, present_file: Path) -> Path:
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then\n'
        "  for last do :; done\n"
        f'  grep -Fxq "$last" "{present_file}" && exit 0\n'
        "  exit 1\n"
        "fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    return docker


def _run(tmp_path: Path, component: str = "xray", env_content: str | None = None, present: tuple[str, ...] = ()) -> subprocess.CompletedProcess[str]:
    artifacts_dir = tmp_path / "artifacts"
    active = artifacts_dir / "active"
    active.mkdir(parents=True, exist_ok=True)
    present_file = tmp_path / "present.txt"
    present_file.write_text("".join(f"{ref}\n" for ref in present), encoding="utf-8")
    if env_content is not None:
        (active / f"{component}.env").write_text(env_content, encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    _fake_docker(bin_dir, present_file)
    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "TRACEGATE_ARTIFACTS_DIR": str(artifacts_dir),
    }
    return subprocess.run(
        ["bash", str(VERIFY), component],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_verifier_passes_for_present_digest(tmp_path: Path) -> None:
    result = _run(tmp_path, env_content=f"TRACEGATE_IMAGE={IMAGE}\n", present=(IMAGE,))
    assert result.returncode == 0
    assert result.stderr == ""


def test_verifier_fails_for_missing_env_file_with_actionable_message(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "tracegate-artifacts capture xray" in result.stderr
    assert result.stderr.count("\n") == 1


def test_verifier_fails_for_malformed_env_file(tmp_path: Path) -> None:
    result = _run(tmp_path, env_content="TRACEGATE_IMAGE=ghcr.io/example/xray:latest\n", present=(IMAGE,))
    assert result.returncode == 1
    assert "tracegate-artifacts capture xray" in result.stderr

    result = _run(tmp_path, env_content=f"TRACEGATE_IMAGE={IMAGE}\nEXTRA=1\n", present=(IMAGE,))
    assert result.returncode == 1

    result = _run(tmp_path, env_content=f"TRACEGATE_IMAGE={IMAGE}", present=(IMAGE,))
    assert result.returncode == 1


def test_verifier_fails_when_image_is_absent_and_never_pulls(tmp_path: Path) -> None:
    result = _run(tmp_path, env_content=f"TRACEGATE_IMAGE={IMAGE}\n", present=())
    assert result.returncode == 1
    assert "tracegate-artifacts stage xray" in result.stderr


def test_verifier_rejects_bad_component_without_touching_docker(tmp_path: Path) -> None:
    result = _run(tmp_path, component="Bad_Name", env_content=None)
    assert result.returncode == 2
    assert "usage" in result.stderr
