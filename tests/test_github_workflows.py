from pathlib import Path


def test_images_workflow_matches_tracegate2_surface() -> None:
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "images.yml"
    ).read_text(encoding="utf-8")

    assert "tracegate-wireguard" not in workflow
    assert "./deploy/images/wireguard/Dockerfile" not in workflow
    assert "${{ runner.temp }}/tracegate-systemd-bundle.tar.gz" in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert "DOCKER_BUILD_RECORD_UPLOAD: false" in workflow
    assert "retention-days: 7" in workflow


def test_transit_node_replacement_workflow_exists() -> None:
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "transit-node-replacement.yml"
    ).read_text(encoding="utf-8")

    assert "workflow_dispatch" in workflow
    assert "TRACEGATE_TRANSIT_SSH_KEY" in workflow
    assert "TRACEGATE_TRANSIT_SINGLE_ENV" in workflow
    assert "replace-transit-node.sh" in workflow
    assert "scp -P" in workflow
    assert "ssh -p" in workflow
