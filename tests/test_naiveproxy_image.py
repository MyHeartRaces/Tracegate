from pathlib import Path


def test_naiveproxy_caddy_image_is_removed_from_tracegate3() -> None:
    image_root = Path(__file__).resolve().parents[1] / "deploy/images/naiveproxy-caddy"

    assert not (image_root / "Dockerfile").exists()
    assert not (image_root / "README.md").exists()
