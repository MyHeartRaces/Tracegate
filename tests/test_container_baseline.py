from __future__ import annotations

import json
from pathlib import Path
import re


def test_dockerfile_does_not_embed_retired_mtg_runtime() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "nineseconds/mtg" not in dockerfile
    assert "COPY --from=mtg-runtime" not in dockerfile


def test_engine_units_start_recorded_digests_and_never_pull() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    registry = json.loads((repo_root / "deploy" / "host" / "artifacts.json").read_text(encoding="utf-8"))
    units_dir = repo_root / "deploy" / "systemd"

    units = sorted({unit for spec in registry["components"].values() for unit in spec["units"]})
    assert len(units) == 12

    for component, spec in sorted(registry["components"].items()):
        image = spec["image"]
        for unit_name in spec["units"]:
            unit = (units_dir / unit_name).read_text(encoding="utf-8")
            assert "docker pull" not in unit
            assert f"EnvironmentFile=/var/lib/tracegate/artifacts/active/{component}.env" in unit
            verifier = f"ExecStartPre=/usr/local/sbin/tracegate-artifact-verify {component}"
            exec_start_pre = re.findall(r"(?m)^ExecStartPre=.*$", unit)
            assert exec_start_pre and exec_start_pre[0] == verifier
            exec_start_match = re.search(r"(?m)^ExecStart=(?P<cmd>.*)$", unit)
            assert exec_start_match is not None
            exec_start = exec_start_match.group("cmd")
            assert "${TRACEGATE_IMAGE}" in exec_start
            assert image not in exec_start
            assert ":latest" not in exec_start
            assert "@sha256:" not in exec_start
            assert "SuccessExitStatus=143" in unit

    covered = {unit for spec in registry["components"].values() for unit in spec["units"]}
    for unit_path in sorted(units_dir.glob("*.service")):
        text = unit_path.read_text(encoding="utf-8")
        if "docker run" in text:
            assert unit_path.name in covered, f"{unit_path.name} runs docker but is not in the artifact registry"
