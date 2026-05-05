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
    assert "Tracegate is a managed privacy-gateway control plane" in readme
    assert "## Repository Boundary" in readme
    assert "## Capabilities" in readme
    assert "real domains, public addresses, ports" in readme
    assert "/etc/tracegate/private" not in readme
    assert "tracegate.su" not in readme
    assert "deploy-ready-check.sh" not in readme
    assert "deploy-prod.sh" not in readme


def test_public_docs_do_not_expose_live_tracegate_domains_or_ips() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    scanned_roots = (repo_root / "README.md", repo_root / "docs", repo_root / "deploy/k3s/README.md")
    needles = (
        "tracegate.su",
        "entry.tracegate.su",
        "transit.tracegate.su",
        "grafana.tracegate.su",
        "176.124.",
        "178.250.",
        "79.137.",
        "46.226.165.23",
        "138.124.29.105",
        "185.105.108.109",
        "myheartraces.space",
    )
    texts: list[str] = []
    for root in scanned_roots:
        if root.is_file():
            texts.append(root.read_text(encoding="utf-8"))
        else:
            texts.extend(path.read_text(encoding="utf-8") for path in root.rglob("*.md"))
    public_text = "\n".join(texts)
    for needle in needles:
        assert needle not in public_text


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
