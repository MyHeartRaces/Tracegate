"""Rendered port model: Endpoint TCP/8443, optional Entry MTProto 8443, Hysteria hop table."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tracegate.services.materialized_bundles import (
    MaterializedBundleRenderContext,
    MaterializedBundleRenderError,
    render_materialized_bundles,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    env = {
        "BUNDLE_SOURCE_ROOT": str(REPO_ROOT / "bundles"),
        "BUNDLE_MATERIALIZED_ROOT": str(tmp_path / "materialized"),
        "DEFAULT_ENTRY_HOST": "entry.tracegate.test",
        "DEFAULT_TRANSIT_HOST": "transit.tracegate.test",
        "HYSTERIA_GECKO_PASSWORD_ENTRY": "entry-gecko-secret",
        "HYSTERIA_GECKO_PASSWORD_TRANSIT": "transit-gecko-secret",
        "HYSTERIA_STATS_SECRET_ENTRY": "entry-stats-secret",
        "HYSTERIA_STATS_SECRET_TRANSIT": "transit-stats-secret",
        "HYSTERIA_LISTEN_HOST_ENTRY": "192.0.2.10",
        "HYSTERIA_LISTEN_HOST_TRANSIT": "192.0.2.20",
        "REALITY_PUBLIC_KEY_TRANSIT": "transit-public-key",
        "REALITY_SHORT_ID_ENTRY": "entry-short-id",
        "REALITY_SHORT_ID_TRANSIT": "transit-short-id",
        "REALITY_PRIVATE_KEY_ENTRY": "entry-private-key",
        "REALITY_PRIVATE_KEY_TRANSIT": "transit-private-key",
        "REALITY_DEST_ENTRY": "origin-entry.example:443",
        "REALITY_DEST_TRANSIT": "origin-transit.example:443",
        "ENTRY_TLS_SERVER_NAME": "tls-entry.example",
        "TRANSIT_TLS_SERVER_NAME": "tls-transit.example",
        "MTPROTO_DOMAIN": "proxied.tracegate.test",
        "MTPROTO_DIRECT_BACKUP_HOST": "192.0.2.30",
    }
    env.update(overrides)
    return env


def _render(tmp_path: Path, **overrides: str) -> dict[str, str]:
    ctx = MaterializedBundleRenderContext.from_environ(_env(tmp_path, **overrides))
    render_materialized_bundles(ctx)
    root = ctx.materialized_root
    return {
        "entry_haproxy": (root / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8"),
        "entry_nft": (root / "base-entry" / "nftables.conf").read_text(encoding="utf-8"),
        "transit_haproxy": (root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8"),
        "transit_nft": (root / "base-transit" / "nftables.conf").read_text(encoding="utf-8"),
    }


def _frontend(haproxy: str, name: str) -> list[str]:
    lines = haproxy.splitlines()
    start = lines.index(f"frontend {name}")
    block: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line.startswith(" "):
            break
        block.append(line)
    return [line for line in block if line.strip() and not line.strip().startswith("#")]


def test_transit_haproxy_binds_443_and_8443_with_identical_dispatch(tmp_path: Path) -> None:
    rendered = _render(tmp_path)
    block = _frontend(rendered["transit_haproxy"], "fe_tracegate_transit_tls")

    binds = [line.strip() for line in block if line.strip().startswith("bind ")]
    assert binds == ["bind :443", "bind :8443"]
    # Both binds share one frontend, so every ACL/route applies to both ports.
    stripped = [line.strip() for line in block]
    assert "use_backend be_transit_mtproto if mtproto_tls_sni { dst_port 443 }" in stripped
    assert "use_backend be_transit_ws_tls if ws_tls_sni" in stripped
    assert stripped[-1] == "default_backend be_transit_reality"
    assert rendered["transit_haproxy"].count("frontend ") == 2


def test_transit_nftables_accepts_tcp_8443_and_still_drops_udp_8443(tmp_path: Path) -> None:
    nft = _render(tmp_path)["transit_nft"]
    assert "tcp dport { 80, 443, 8443 } accept" in nft
    assert "udp dport 8443 drop" in nft
    assert nft.index("udp dport 8443 drop") < nft.index("udp dport { 443, 4443, 8444 } accept")
    assert not re.search(r"tcp dport [^\n]*8443[^\n]* drop", nft)
    assert "tracegate_hysteria_hop" not in nft


def test_entry_keeps_tcp_8443_closed_by_default(tmp_path: Path) -> None:
    rendered = _render(tmp_path)
    assert "tcp dport { 4443, 8443 } drop" in rendered["entry_nft"]
    assert "tcp dport 443 accept" in rendered["entry_nft"]
    assert ":8443" not in rendered["entry_haproxy"]
    template = (REPO_ROOT / "bundles" / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8")
    assert rendered["entry_haproxy"].count("frontend ") == template.count("frontend ")


def test_entry_never_renders_tcp_8443_even_with_legacy_alt_port_env(tmp_path: Path) -> None:
    # The optional Entry alternative port was removed: a stale env key must not
    # open Entry TCP/8443 or add a frontend there.
    default = _render(tmp_path / "default")
    stale = _render(tmp_path / "stale", MTPROTO_ALT_PUBLIC_PORT="8443")
    assert stale == default
    assert ":8443" not in stale["entry_haproxy"]


def test_transit_serves_mtproto_only_on_443(tmp_path: Path) -> None:
    # Telegram is delivered only through Entry. Endpoint keeps routing the
    # FakeTLS SNI on TCP/443 for links saved earlier, never on TCP/8443.
    block = _frontend(_render(tmp_path)["transit_haproxy"], "fe_tracegate_transit_tls")
    routes = [line.strip() for line in block if "be_transit_mtproto" in line]
    assert routes == ["use_backend be_transit_mtproto if mtproto_tls_sni { dst_port 443 }"]


def test_hysteria_hop_table_is_not_rendered_without_ranges(tmp_path: Path) -> None:
    default = _render(tmp_path / "default")
    empty = _render(tmp_path / "empty", HYSTERIA_GECKO_HOP_PORTS="", HYSTERIA_SALAMANDER_HOP_PORTS="")
    assert default == empty
    assert "tracegate_hysteria_hop" not in default["transit_nft"]
    assert "tracegate_hysteria_hop" not in default["entry_nft"]


def test_hysteria_hop_table_redirects_both_families_for_wildcard_listener(tmp_path: Path) -> None:
    link = "192.0.2.21:9445"
    default = _render(tmp_path / "default", HYSTERIA_LISTEN_HOST_TRANSIT="", MTPROTO_ENTRY_LINK_UPSTREAM=link)
    rendered = _render(
        tmp_path / "hop",
        HYSTERIA_LISTEN_HOST_TRANSIT="",
        MTPROTO_ENTRY_LINK_UPSTREAM=link,
        HYSTERIA_GECKO_HOP_PORTS="20000-29999",
        HYSTERIA_SALAMANDER_HOP_PORTS="30000-39999",
    )
    nft = rendered["transit_nft"]

    assert nft.startswith(default["transit_nft"])
    assert "table inet tracegate_hysteria_hop {" in nft
    assert "type nat hook prerouting priority dstnat; policy accept;" in nft
    assert "meta nfproto ipv4 udp dport 20000-29999 redirect to :443" in nft
    assert "meta nfproto ipv6 udp dport 20000-29999 redirect to :443" in nft
    assert "meta nfproto ipv4 udp dport 30000-39999 redirect to :8444" in nft
    assert "meta nfproto ipv6 udp dport 30000-39999 redirect to :8444" in nft
    # Hop ranges never get their own input accept: prerouting rewrites them first.
    assert "udp dport 20000-29999 accept" not in nft
    assert "tracegate_hysteria_hop" not in rendered["entry_nft"]
    assert rendered["entry_nft"] == default["entry_nft"]


def test_hysteria_hop_table_dnats_to_bound_listener_address(tmp_path: Path) -> None:
    nft = _render(
        tmp_path,
        HYSTERIA_GECKO_HOP_PORTS="20000-29999",
        HYSTERIA_SALAMANDER_LISTEN_HOST_TRANSIT="2001:db8::20",
        HYSTERIA_SALAMANDER_HOP_PORTS="30000-39999",
    )["transit_nft"]
    assert "ip daddr 192.0.2.20 udp dport 20000-29999 dnat ip to 192.0.2.20:443" in nft
    assert "ip6 daddr 2001:db8::20 udp dport 30000-39999 dnat ip6 to [2001:db8::20]:8444" in nft
    assert "redirect" not in nft.split("tracegate_hysteria_hop", 1)[1]


def test_hysteria_hop_table_survives_private_nftables_overlay(tmp_path: Path) -> None:
    overlay = tmp_path / "overlay" / "transit"
    overlay.mkdir(parents=True)
    template = (REPO_ROOT / "bundles" / "base-transit" / "nftables.conf").read_text(encoding="utf-8")
    (overlay / "nftables.conf").write_text(template, encoding="utf-8")
    nft = _render(
        tmp_path / "out",
        BUNDLE_PRIVATE_OVERLAY_ROOT=str(tmp_path / "overlay"),
        HYSTERIA_GECKO_HOP_PORTS="20000-29999",
    )["transit_nft"]
    assert nft.count("table inet tracegate_hysteria_hop {") == 1


def test_hysteria_hop_requires_input_accept_for_listener_port(tmp_path: Path) -> None:
    overlay = tmp_path / "overlay" / "transit"
    overlay.mkdir(parents=True)
    template = (REPO_ROOT / "bundles" / "base-transit" / "nftables.conf").read_text(encoding="utf-8")
    (overlay / "nftables.conf").write_text(
        template.replace("udp dport { 443, 4443, 8444 } accept", "udp dport { 443, 4443 } accept"),
        encoding="utf-8",
    )
    with pytest.raises(MaterializedBundleRenderError, match="udp/8444"):
        _render(
            tmp_path / "out",
            BUNDLE_PRIVATE_OVERLAY_ROOT=str(tmp_path / "overlay"),
            HYSTERIA_SALAMANDER_HOP_PORTS="30000-39999",
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"HYSTERIA_GECKO_HOP_PORTS": "8000-9000"},
        {"HYSTERIA_GECKO_HOP_PORTS": "20000-30000", "HYSTERIA_SALAMANDER_HOP_PORTS": "30000-31000"},
        {"HYSTERIA_GECKO_HOP_PORTS": "100-2000"},
        {"HYSTERIA_GECKO_HOP_PORTS": "20000-60000"},
    ],
)
def test_hysteria_hop_ranges_are_validated_by_the_materializer(tmp_path: Path, overrides: dict[str, str]) -> None:
    with pytest.raises(MaterializedBundleRenderError):
        MaterializedBundleRenderContext.from_environ(_env(tmp_path, **overrides))
