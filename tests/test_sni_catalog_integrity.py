from tracegate.services.sni_catalog import load_catalog


def test_sni_catalog_integrity() -> None:
    rows = load_catalog()
    assert rows, "static SNI catalog must not be empty"

    # IDs are the stable reference used by revisions; keep ordering stable.
    ids = [r.id for r in rows]
    assert ids == sorted(ids)
    assert all(i > 0 for i in ids)

    allowed_providers = {"mts", "megafon", "t2", "tmobile", "rtk", "yota", "beeline"}
    for r in rows:
        assert r.fqdn and r.fqdn.strip() == r.fqdn
        assert "." in r.fqdn
        for p in r.providers or []:
            assert p == p.lower().strip()
            assert p in allowed_providers

