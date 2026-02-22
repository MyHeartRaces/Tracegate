from pathlib import Path


def test_vps_t_wg_nat_is_interface_agnostic() -> None:
    conf = Path("bundles/base-vps-t/nftables.conf").read_text(encoding="utf-8")
    assert 'oifname != "wg0" ip saddr 10.70.0.0/24 masquerade' in conf
    assert 'oifname "eth0" ip saddr 10.70.0.0/24 masquerade' not in conf


def test_vps_e_opens_udp_443_for_hysteria_chain_entry() -> None:
    conf = Path("bundles/base-vps-e/nftables.conf").read_text(encoding="utf-8")
    assert "udp dport 443 accept" in conf
