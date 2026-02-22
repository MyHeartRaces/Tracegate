import sys
import types
from pathlib import Path

import pytest

# Importing tracegate.api.routers.dispatch executes routers package __init__, which imports metrics router.
sys.modules.setdefault(
    "prometheus_client",
    types.SimpleNamespace(CONTENT_TYPE_LATEST="text/plain", generate_latest=lambda: b""),
)

from tracegate.api.routers import dispatch
from tracegate.settings import Settings


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_load_bundle_files_uses_repo_bundle_when_no_materialized_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "bundles"
    _write(repo_root / "base-vps-t" / "nftables.conf", "flush ruleset\n")
    _write(repo_root / "base-vps-t" / "xray.json", '{"log":"repo"}')

    monkeypatch.setattr(
        dispatch,
        "get_settings",
        lambda: Settings(bundle_root=str(repo_root), bundle_materialized_root=""),
    )

    files = dispatch._load_bundle_files("base-vps-t")

    assert files == {
        "nftables.conf": "flush ruleset\n",
        "xray.json": '{"log":"repo"}',
    }


def test_load_bundle_files_overlays_materialized_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "bundles"
    materialized_root = tmp_path / "materialized"
    _write(repo_root / "base-vps-e" / "nftables.conf", "repo-firewall\n")
    _write(repo_root / "base-vps-e" / "xray.json", '{"privateKey":"REPLACE_PRIVATE_KEY"}')
    _write(repo_root / "base-vps-e" / "hysteria.yaml", "acme:\n  domains: [example.com]\n")

    _write(materialized_root / "base-vps-e" / "xray.json", '{"privateKey":"real-key"}')
    _write(materialized_root / "base-vps-e" / "hysteria.yaml", "listen: :443\n")

    monkeypatch.setattr(
        dispatch,
        "get_settings",
        lambda: Settings(bundle_root=str(repo_root), bundle_materialized_root=str(materialized_root)),
    )

    files = dispatch._load_bundle_files("base-vps-e")

    assert files["nftables.conf"] == "repo-firewall\n"
    assert files["xray.json"] == '{"privateKey":"real-key"}'
    assert files["hysteria.yaml"] == "listen: :443\n"


def test_load_bundle_files_ignores_missing_materialized_bundle_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo_root = tmp_path / "bundles"
    _write(repo_root / "base-vps-t" / "wg0.conf", "[Interface]\n")

    monkeypatch.setattr(
        dispatch,
        "get_settings",
        lambda: Settings(
            bundle_root=str(repo_root),
            bundle_materialized_root=str(tmp_path / "materialized"),
        ),
    )

    files = dispatch._load_bundle_files("base-vps-t")

    assert files == {"wg0.conf": "[Interface]\n"}
