from pathlib import Path
import subprocess
import sys

from scripts.check_host_runtime import check_host_runtime


def test_tracked_host_runtime_contract_is_complete() -> None:
    check_host_runtime(Path(__file__).resolve().parents[1])


def test_host_release_preserves_quic_socket_buffer_tuning() -> None:
    root = Path(__file__).resolve().parents[1]
    profile = (root / "deploy/host/90-tracegate-quic.conf").read_text(encoding="utf-8")
    assert profile.count("= 16777216") == 4

    installer = (root / "deploy/host/tracegate-host-install").read_text(encoding="utf-8")
    assert '"${SYSCTL}" -p "${SYSCTL_DIR}/90-tracegate-quic.conf"' in installer


def test_host_runtime_check_cli_succeeds() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "scripts/check_host_runtime.py"), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "host runtime check passed" in result.stdout
