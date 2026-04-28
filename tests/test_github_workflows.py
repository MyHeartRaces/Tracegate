from pathlib import Path


def test_images_workflow_matches_tracegate2_surface() -> None:
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "images.yml"
    ).read_text(encoding="utf-8")

    assert "tracegate-wireguard" not in workflow
    assert "./deploy/images/wireguard/Dockerfile" not in workflow
    assert "tracegate-systemd-bundle" not in workflow
    assert "actions/upload-artifact@v4" not in workflow
    assert "DOCKER_BUILD_RECORD_UPLOAD: false" in workflow


def test_legacy_transit_node_replacement_workflow_is_removed() -> None:
    workflow_path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "transit-node-replacement.yml"

    assert not workflow_path.exists()
