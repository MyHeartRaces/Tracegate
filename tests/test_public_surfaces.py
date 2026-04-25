from pathlib import Path


def test_public_repo_does_not_ship_decoy_html_surfaces() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    for root in (
        repo_root / "bundles/base-entry/decoy",
        repo_root / "bundles/base-transit/decoy",
    ):
        assert not any(path.is_file() for path in root.rglob("*"))


def test_readme_declares_private_static_surface_boundary() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    assert "optional host-local static/auth surfaces on `Transit`, staged outside Git" in readme
    assert "keep optional decoy HTML/CSS/JS assets out of the public repository" in readme
    assert "decoy HTML/CSS/JS assets" in readme


def test_public_repo_does_not_ship_bot_copy() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assert not (repo_root / "bundles/bot/guide.md").exists()
    public_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            repo_root / "deploy/k3s/tracegate/values.yaml",
            repo_root / "deploy/systemd/tracegate.env.example",
        )
    )
    assert "[TRACEGATE_BOT_GUIDE_PLACEHOLDER]" in public_text
    assert ("Короткий " + "гайд") not in public_text
