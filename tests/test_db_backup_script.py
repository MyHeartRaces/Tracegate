from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess


def _executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_backup_guard_consumes_the_complete_restore_toc(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _executable(
        fake_bin / "runuser",
        "#!/bin/sh\n"
        "printf 'valid-custom-archive\\n'\n",
    )
    _executable(
        fake_bin / "pg_restore",
        "#!/bin/sh\n"
        "i=0\n"
        "while [ \"$i\" -lt 10000 ]; do\n"
        "  printf '%s; TABLE public item_%s postgres\\n' \"$i\" \"$i\"\n"
        "  i=$((i + 1))\n"
        "done\n",
    )
    backup_dir = tmp_path / "backups"
    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "TRACEGATE_BACKUP_DIR": str(backup_dir),
        "TRACEGATE_DB_NAME": "tracegate",
        "TRACEGATE_BACKUP_RETENTION_DAYS": "30",
    }

    result = subprocess.run(
        [str(repo_root / "deploy/host/tracegate-db-backup")],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    backups = list(backup_dir.glob("tracegate-*.dump"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "valid-custom-archive\n"
    assert backups[0].stat().st_mode & 0o777 == 0o600
    assert not list(backup_dir.glob("*.tmp"))
