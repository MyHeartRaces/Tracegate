from pathlib import Path


def test_dockerfile_tracks_latest_xray_and_includes_wireguard_sync_tools() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM ghcr.io/xtls/xray-core:latest AS xray-runtime" in dockerfile
    assert "@sha256:" not in dockerfile
    assert "ARG XRAY_VERSION=" not in dockerfile
    assert "wireguard-tools" in dockerfile


def test_dockerfile_does_not_embed_retired_mtg_runtime() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "nineseconds/mtg" not in dockerfile
    assert "COPY --from=mtg-runtime" not in dockerfile
