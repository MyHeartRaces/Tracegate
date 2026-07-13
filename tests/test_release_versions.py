from pathlib import Path
import re
import tomllib

import yaml


def test_release_versions_are_kept_in_sync() -> None:
    repo_root = Path(__file__).resolve().parents[1]

    pyproject = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    package_version = pyproject["project"]["version"]

    init_text = (repo_root / "src/tracegate/__init__.py").read_text(encoding="utf-8")
    init_match = re.search(r'__version__ = "([^"]+)"', init_text)
    assert init_match is not None
    assert init_match.group(1) == package_version

    bundle_manifest = yaml.safe_load((repo_root / "bundles/manifest.yaml").read_text(encoding="utf-8"))

    assert bundle_manifest["metadata"]["version"] == package_version
    assert bundle_manifest["spec"]["runtimeProfile"] == "tracegate-3"
    assert {row["canonicalRole"] for row in bundle_manifest["spec"]["bundles"]} == {"Entry", "Endpoint"}
