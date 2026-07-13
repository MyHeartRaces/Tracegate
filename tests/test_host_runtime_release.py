from pathlib import Path
import subprocess
import sys

from scripts.check_host_runtime import check_host_runtime


def test_tracked_host_runtime_contract_is_complete() -> None:
    check_host_runtime(Path(__file__).resolve().parents[1])


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
