from pathlib import Path

import pytest
import yaml

from tracegate.services.sni_catalog import is_blocked_sni, load_catalog, sni_root_domain


def test_sni_catalog_integrity() -> None:
    rows = load_catalog()
    assert rows, "static SNI catalog must not be empty"
    enabled = [row for row in rows if row.enabled]

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

    assert len(enabled) == 10
    assert all(row.fqdn.endswith(".ru") for row in enabled)
    assert all(not row.providers for row in enabled)
    assert all(not is_blocked_sni(row.fqdn) for row in enabled)
    assert len({sni_root_domain(row.fqdn) for row in enabled}) == len(enabled)
    assert not {"old-forbidden.tracegate-sni.ru", "old-mtproto-a.tracegate-sni.ru", "reserved-86.tracegate-sni.ru", "reserved-50.tracegate-sni.ru", "reserved-97.tracegate-sni.ru"} & {
        row.fqdn for row in enabled
    }


def test_private_k3s_values_have_reality_inbound_for_each_bot_sni() -> None:
    private_values = Path("deploy/k3s/values-tracegate.private.yaml")
    if not private_values.exists():
        pytest.skip("private production values are intentionally kept outside the public checkout")
    values = yaml.safe_load(private_values.read_text(encoding="utf-8"))
    groups = values["gateway"]["realityMultiInboundGroups"]
    grouped_snis = {sni for group in groups for sni in group["snis"]}
    enabled_snis = {row.fqdn for row in load_catalog() if row.enabled}

    # Private production overlays may retain disabled legacy SNI groups while
    # previously issued revisions drain.
    assert enabled_snis <= grouped_snis


def test_chart_shadowtls_server_names_avoid_forbidden_faketls_domains() -> None:
    """Default ShadowTLS camouflage SNIs must never reuse a domain the project
    marks as a forbidden MTProto FakeTLS front or an enabled Reality lease
    pool domain. They must also stay in .ru zones for production SNI policy.

    Regression guard for the audit finding where the chart shipped
    ``serverNameTransit: old-mtproto-a.tracegate-sni.ru`` -- a domain listed in the same file's
    ``mtproto.stealth.forbiddenTlsDomains`` and called out in the release
    checklist as forbidden in active SNI fields. (ShadowTLS fronts are
    intentionally kept *out* of the enabled Reality lease pool to avoid an SNI
    demux collision, so they are not required to be catalog-``enabled``.)
    """
    values = yaml.safe_load(Path("deploy/k3s/tracegate/values.yaml").read_text(encoding="utf-8"))
    shadowtls = values["shadowsocks2022"]["shadowtls"]
    server_names = {
        str(shadowtls.get("serverNameEntry") or "").strip(),
        str(shadowtls.get("serverNameTransit") or "").strip(),
    }
    forbidden = {str(d).strip() for d in values["mtproto"]["stealth"].get("forbiddenTlsDomains", [])}
    enabled_reality_snis = {row.fqdn for row in load_catalog() if row.enabled}

    for name in server_names:
        assert name, "ShadowTLS serverName defaults must be set"
        assert name.endswith(".ru"), f"ShadowTLS serverName {name!r} must stay in .ru zones"
        assert name not in forbidden, f"ShadowTLS serverName {name!r} is a forbidden MTProto FakeTLS domain"
        assert name not in enabled_reality_snis, f"ShadowTLS serverName {name!r} must not reuse an enabled Reality SNI"
