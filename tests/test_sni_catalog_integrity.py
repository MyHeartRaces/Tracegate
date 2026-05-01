from pathlib import Path

import pytest
import yaml

from tracegate.services.sni_catalog import load_catalog


def test_sni_catalog_integrity() -> None:
    rows = load_catalog()
    assert rows, "static SNI catalog must not be empty"

    # IDs are the stable reference used by revisions; keep ordering stable.
    ids = [r.id for r in rows]
    assert ids == sorted(ids)
    assert all(i > 0 for i in ids)

    allowed_providers = {"mts", "megafon", "t2", "tmobile", "rtk", "yota"}
    for r in rows:
        assert r.fqdn and r.fqdn.strip() == r.fqdn
        assert "." in r.fqdn
        for p in r.providers or []:
            assert p == p.lower().strip()
            assert p in allowed_providers


def test_private_k3s_values_have_reality_inbound_for_each_bot_sni() -> None:
    private_values = Path("deploy/k3s/values-tracegate.private.yaml")
    if not private_values.exists():
        pytest.skip("private production values are intentionally kept outside the public checkout")
    values = yaml.safe_load(private_values.read_text(encoding="utf-8"))
    groups = values["gateway"]["realityMultiInboundGroups"]
    grouped_snis = {sni for group in groups for sni in group["snis"]}
    enabled_snis = {row.fqdn for row in load_catalog() if row.enabled}

    assert grouped_snis == enabled_snis
