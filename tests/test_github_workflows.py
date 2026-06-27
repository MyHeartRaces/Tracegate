from pathlib import Path


def test_images_workflow_matches_tracegate3_surface() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "images.yml").read_text(encoding="utf-8")

    assert "tracegate-wireguard" not in workflow
    assert "./deploy/images/wireguard/Dockerfile" not in workflow
    assert "tracegate-systemd-bundle" not in workflow
    assert "actions/upload-artifact@v4" not in workflow
    assert "DOCKER_BUILD_RECORD_UPLOAD: false" in workflow
    assert "tracegate-naiveproxy-caddy" not in workflow
    assert "./deploy/images/naiveproxy-caddy/Dockerfile" not in workflow
    assert "build-naiveproxy-caddy" not in (root / "Makefile").read_text(encoding="utf-8")
    assert not (root / "deploy" / "images" / "naiveproxy-caddy").joinpath("Dockerfile").exists()


def test_legacy_transit_node_replacement_workflow_is_removed() -> None:
    workflow_path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "transit-node-replacement.yml"

    assert not workflow_path.exists()
