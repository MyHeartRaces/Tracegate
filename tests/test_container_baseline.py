from pathlib import Path


def test_dockerfile_uses_latest_xray_release_and_wireguard_sync_tools() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG XRAY_VERSION=latest" in dockerfile
    assert "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip" in dockerfile
    assert 'https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip' in dockerfile
    assert "api.github.com/repos/XTLS/Xray-core/releases/latest" not in dockerfile
    assert "wireguard-tools" in dockerfile
