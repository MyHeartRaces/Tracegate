from pathlib import Path

import yaml


def test_hysteria_images_are_pinned_and_consistent_between_gateways() -> None:
    values = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "deploy/k3s/tracegate/values.yaml").read_text(encoding="utf-8")
    )
    gateway = values["gateway"]
    vps_t_image = gateway["vpsT"]["hysteria"]["image"]
    vps_e_image = gateway["vpsE"]["hysteria"]["image"]

    assert vps_t_image == vps_e_image
    assert "@sha256:" in vps_t_image
    assert not vps_t_image.split("@", 1)[0].endswith(":v2")
