from pathlib import Path


def test_public_repo_does_not_ship_decoy_html_surfaces() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    for root in (
        repo_root / "bundles/base-entry/decoy",
        repo_root / "bundles/base-transit/decoy",
    ):
        assert not any(path.is_file() for path in root.rglob("*"))


def test_readme_stays_high_level() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    assert "Tracegate 2.2 is a managed privacy-gateway stack" in readme
    assert "## Connection Surfaces" in readme
    assert "## Core Features" in readme
    assert "Security and private data" not in readme
    assert "Do not commit" not in readme
    assert "Current runtime note" not in readme
    assert "decoy HTML/CSS/JS assets" not in readme
    assert "/etc/tracegate/private" not in readme
    assert "local SOCKS" not in readme


def test_public_repo_does_not_ship_bot_copy() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assert not (repo_root / "bundles/bot/guide.md").exists()
    public_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            repo_root / "deploy/k3s/tracegate/values.yaml",
            repo_root / "deploy/k3s/values-prod.example.yaml",
        )
    )
    assert "tracegate-bot-guide" in public_text
    assert ("Короткий " + "гайд") not in public_text
