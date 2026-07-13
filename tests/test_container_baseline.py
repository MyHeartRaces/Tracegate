from pathlib import Path


def test_dockerfile_pins_xray_release_and_wireguard_sync_tools() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG XRAY_VERSION=v" in dockerfile
    assert "ARG XRAY_SHA256=" in dockerfile
    assert "sha256sum -c -" in dockerfile
    assert 'https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip' in dockerfile
    assert "api.github.com/repos/XTLS/Xray-core/releases/latest" not in dockerfile
    assert "wireguard-tools" in dockerfile


def test_dockerfile_embeds_pinned_mtg_runtime() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM nineseconds/mtg@sha256:" in dockerfile
    assert " AS mtg-runtime" in dockerfile
    assert "COPY --from=mtg-runtime /mtg /mtg" in dockerfile
