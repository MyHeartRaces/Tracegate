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


def test_compatibility_checked_runtime_versions_are_pinned() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    expected_images = {
        "tracegate-hysteria@.service": "docker.io/tobyxdd/hysteria:v2.12.2",
        "tracegate-hysteria-salamander.service": "docker.io/tobyxdd/hysteria:v2.12.2",
        "tracegate-prometheus.service": "prom/prometheus:v3.14.0",
        "tracegate-grafana.service": "grafana/grafana:13.2.0",
    }

    for unit_name, image in expected_images.items():
        unit = (repo_root / "deploy" / "systemd" / unit_name).read_text(encoding="utf-8")
        assert f"docker pull {image}" in unit
        assert image in unit
