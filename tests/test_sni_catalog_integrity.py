from pathlib import Path

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


def test_reality_multi_inbound_groups_reference_enabled_catalog_entries() -> None:
    catalog_fqdns = {row.fqdn.strip().lower() for row in load_catalog() if row.enabled}
    values_path = Path(__file__).resolve().parents[1] / "deploy/k3s/tracegate/values.yaml"
    values = yaml.safe_load(values_path.read_text(encoding="utf-8")) or {}
    groups = (((values.get("gateway") or {}).get("realityMultiInbound") or {}).get("groups") or [])
    assert groups

    for group in groups:
        assert isinstance(group, dict)
        for sni in group.get("snis") or []:
            assert str(sni).strip().lower() in catalog_fqdns
