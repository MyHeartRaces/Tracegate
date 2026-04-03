from pathlib import Path


def test_vps_t_wg_nat_is_interface_agnostic() -> None:
    conf = Path("bundles/base-vps-t/nftables.conf").read_text(encoding="utf-8")
    assert 'oifname != "wg0" ip saddr 10.70.0.0/24 masquerade' in conf
    assert 'oifname "eth0" ip saddr 10.70.0.0/24 masquerade' not in conf


def test_vps_e_opens_udp_443_for_hysteria_chain_entry() -> None:
    conf = Path("bundles/base-vps-e/nftables.conf").read_text(encoding="utf-8")
    assert "udp dport 443 accept" in conf


def test_vps_interconnect_wireguard_backplane_is_allowed_only_between_nodes() -> None:
    conf_t = Path("bundles/base-vps-t/nftables.conf").read_text(encoding="utf-8")
    conf_e = Path("bundles/base-vps-e/nftables.conf").read_text(encoding="utf-8")
    assert "ip saddr 178.250.243.46 udp dport 51821 accept" in conf_t
    assert "ip saddr 176.124.198.228 udp dport 51821 accept" in conf_e


def test_vps_t_accepts_hysteria_backplane_only_from_vps_e() -> None:
    conf_t = Path("bundles/base-vps-t/nftables.conf").read_text(encoding="utf-8")
    assert "ip saddr 178.250.243.46 udp dport 15445 accept" in conf_t
    assert "ip saddr 178.250.243.46 tcp dport 15446 accept" in conf_t
