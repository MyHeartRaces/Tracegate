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

    chart = yaml.safe_load((repo_root / "deploy/k3s/tracegate/Chart.yaml").read_text(encoding="utf-8"))
    assert chart["version"] == package_version

    expected_app_version = ".".join(package_version.split(".")[:2])
    assert chart["appVersion"] == expected_app_version

    values = yaml.safe_load((repo_root / "deploy/k3s/tracegate/values.yaml").read_text(encoding="utf-8"))
    example_values = yaml.safe_load((repo_root / "deploy/k3s/values-prod.example.yaml").read_text(encoding="utf-8"))

    assert values["controlPlane"]["image"]["tag"] == expected_app_version
    assert values["gateway"]["agentImage"]["tag"] == expected_app_version
    assert example_values["controlPlane"]["image"]["tag"] == expected_app_version
    assert example_values["gateway"]["agentImage"]["tag"] == expected_app_version

    assert values["gateway"]["vpsT"]["wireguard"]["image"].endswith(f":{expected_app_version}")
    assert example_values["gateway"]["vpsT"]["wireguard"]["image"].endswith(f":{expected_app_version}")
