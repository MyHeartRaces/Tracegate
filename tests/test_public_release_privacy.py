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


def test_extracted_tree_without_git_metadata_passes_privacy_gate(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    (tmp_path / "README.md").write_text("example release\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(repo_root / "scripts/check_public_release.py"), "--root", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
