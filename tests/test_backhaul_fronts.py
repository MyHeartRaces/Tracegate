from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from tracegate.cli import backhaul_fronts


def test_common_prefix_bits_prioritizes_entry_neighbors() -> None:
    entry = ipaddress.IPv4Address("192.0.2.10")
    assert backhaul_fronts._common_prefix_bits(entry, ipaddress.IPv4Address("192.0.2.200")) == 24
    assert backhaul_fronts._common_prefix_bits(
        entry, ipaddress.IPv4Address("198.51.100.10")
    ) < 24


def test_neighbor_scan_is_bounded_and_must_contain_entry() -> None:
    entry = ipaddress.IPv4Address("192.0.2.10")
    assert str(backhaul_fronts._neighbor_network(entry, None)) == "192.0.2.0/24"
    with pytest.raises(ValueError, match="at most 256"):
        backhaul_fronts._neighbor_network(entry, "192.0.2.0/23")
    with pytest.raises(ValueError, match="contain"):
        backhaul_fronts._neighbor_network(entry, "198.51.100.0/24")


def test_update_env_changes_only_selected_keys(tmp_path: Path) -> None:
    path = tmp_path / "runtime.env"
    path.write_text("SECRET=keep\nSHADOWTLS_BACKHAUL_SNI=old.example\n", encoding="utf-8")
    path.chmod(0o600)

    backhaul_fronts._update_env(
        path,
        {
            "SHADOWTLS_BACKHAUL_SNI": "new.example",
            "SHADOWTLS_BACKHAUL_FRAGMENT1_LENGTH": "2-6",
        },
    )

    assert path.read_text(encoding="utf-8") == (
        "SECRET=keep\n"
        "SHADOWTLS_BACKHAUL_SNI=new.example\n\n"
        "SHADOWTLS_BACKHAUL_FRAGMENT1_LENGTH=2-6\n"
    )
    assert path.stat().st_mode & 0o777 == 0o600


def test_catalog_candidates_reads_only_enabled_yaml_rows(tmp_path: Path) -> None:
    path = tmp_path / "catalog.yaml"
    path.write_text(
        "- fqdn: a.example.com\n  enabled: true\n"
        "- fqdn: b.example.com\n  enabled: false\n",
        encoding="utf-8",
    )
    assert backhaul_fronts._catalog_candidates(path) == {"a.example.com"}


def test_independent_slicing_ranges_are_validated() -> None:
    assert backhaul_fronts._bounded_range("2-6", label="length", minimum=1, maximum=512) == "2-6"
    with pytest.raises(ValueError, match="within"):
        backhaul_fronts._bounded_range("0-6", label="length", minimum=1, maximum=512)


def test_ssh_target_rejects_option_injection() -> None:
    assert backhaul_fronts._ssh_target("root@example.net") == "root@example.net"
    assert backhaul_fronts._ssh_target("root@[2001:db8::1]") == "root@[2001:db8::1]"
    with pytest.raises(ValueError):
        backhaul_fronts._ssh_target("-oProxyCommand=evil")
    with pytest.raises(ValueError):
        backhaul_fronts._ssh_target("root@example.net;evil")
