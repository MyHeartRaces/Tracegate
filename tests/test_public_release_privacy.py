from pathlib import Path
import subprocess
import sys


def test_tracked_tree_passes_public_release_privacy_gate() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(repo_root / "scripts/check_public_release.py"), "--root", str(repo_root)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
