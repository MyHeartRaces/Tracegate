import pytest

from tracegate.constants import TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, TRACEGATE_PUBLIC_UDP_PORT
from tracegate.services.runtime_contract import (
    RuntimeContractError,
    TRACEGATE21_CLIENT_PROFILES,
    TRACEGATE22_CLIENT_PROFILES,
    normalize_runtime_profile_name,
    resolve_runtime_contract,
    tcp8443_is_public_listener,
)


def test_resolve_current_runtime_contract_and_aliases() -> None:
    contract = resolve_runtime_contract("xray-hysteria")
    alias_contract = resolve_runtime_contract("split")

    assert normalize_runtime_profile_name("split") == "xray-centric"
    assert contract == alias_contract
    assert contract.manages_component("xray") is True
    assert contract.manages_component("hysteria") is False
    assert contract.hysteria_auth_mode == "token"
    assert contract.hysteria_metrics_source == "xray_stats"
    assert contract.xray_backhaul_allowed is True
    assert contract.expected_ports("ENTRY") == (
        ("tcp", 443, "listen tcp/443"),
        ("udp", TRACEGATE_PUBLIC_UDP_PORT, f"listen udp/{TRACEGATE_PUBLIC_UDP_PORT}"),
    )
    assert contract.forbidden_ports("ENTRY") == (
        ("tcp", 8443, "blocked tcp/8443"),
        ("udp", TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, f"blocked udp/{TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT}"),
    )
    assert contract.expected_ports("TRANSIT") == (
        ("tcp", 443, "listen tcp/443"),
        ("tcp", 8443, "listen tcp/8443"),
        ("udp", TRACEGATE_PUBLIC_UDP_PORT, f"listen udp/{TRACEGATE_PUBLIC_UDP_PORT}"),
    )
    assert contract.forbidden_ports("TRANSIT") == (
        ("udp", TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, f"blocked udp/{TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT}"),
    )
    assert contract.requires_transit_stats_secret("ENTRY") is False
    assert contract.requires_transit_stats_secret("TRANSIT") is False


def test_tracegate22_runtime_contract_is_default_profile() -> None:
    contract = resolve_runtime_contract("tracegate-3")
    alias_contract = resolve_runtime_contract("default")

    assert normalize_runtime_profile_name("") == "tracegate-3"
    assert normalize_runtime_profile_name("host") == "tracegate-3"
    assert alias_contract == contract
    assert contract.manages_component("xray") is True
    assert contract.manages_component("hysteria") is True
    assert contract.hysteria_auth_mode == "userpass"
    assert contract.hysteria_metrics_source == "hysteria_stats"
    assert contract.xray_backhaul_allowed is True
    assert contract.client_profiles == TRACEGATE22_CLIENT_PROFILES
    assert contract.requires_transit_stats_secret("ENTRY") is False
    assert contract.requires_transit_stats_secret("TRANSIT") is True
    assert any(row.name == "process hysteria" for row in contract.process_checks("ENTRY"))
    assert any(row.name == "process hysteria" for row in contract.process_checks("TRANSIT"))
    assert contract.expected_ports("ENTRY") == (
        ("tcp", 443, "listen tcp/443"),
        ("udp", TRACEGATE_PUBLIC_UDP_PORT, f"listen udp/{TRACEGATE_PUBLIC_UDP_PORT}"),
    )
    assert contract.forbidden_ports("ENTRY") == (
        ("tcp", 8443, "blocked tcp/8443"),
        ("udp", TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, f"blocked udp/{TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT}"),
    )


def test_xray_centric_runtime_contract_is_legacy_profile() -> None:
    contract = resolve_runtime_contract("xray-centric")
    alias_contract = resolve_runtime_contract("xray-unified")

    assert alias_contract == contract
    assert contract.manages_component("xray") is True
    assert contract.manages_component("hysteria") is False
    assert contract.hysteria_auth_mode == "token"
    assert contract.hysteria_metrics_source == "xray_stats"
    assert contract.requires_transit_stats_secret("TRANSIT") is False
    assert contract.expected_ports("ENTRY") == (
        ("tcp", 443, "listen tcp/443"),
        ("udp", TRACEGATE_PUBLIC_UDP_PORT, f"listen udp/{TRACEGATE_PUBLIC_UDP_PORT}"),
    )
    assert contract.forbidden_ports("ENTRY") == (
        ("tcp", 8443, "blocked tcp/8443"),
        ("udp", TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, f"blocked udp/{TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT}"),
    )


def test_tracegate21_runtime_contract_has_no_xray_backhaul() -> None:
    contract = resolve_runtime_contract("tracegate-2.1")

    assert normalize_runtime_profile_name("tracegate2.1") == "tracegate-2.1"
    assert contract.manages_component("xray") is True
    assert contract.manages_component("hysteria") is False
    assert contract.hysteria_auth_mode == "token"
    assert contract.hysteria_metrics_source == "xray_stats"
    assert contract.xray_backhaul_allowed is False
    assert contract.client_profiles == TRACEGATE21_CLIENT_PROFILES
    assert "MTProto-FakeTLS-Direct" in contract.client_profiles
    assert contract.local_socks_auth_required is True
    assert contract.allow_anonymous_local_socks is False
    assert contract.requires_transit_stats_secret("TRANSIT") is False
    assert contract.expected_ports("TRANSIT") == (
        ("tcp", 443, "listen tcp/443"),
        ("tcp", 8443, "listen tcp/8443"),
        ("udp", TRACEGATE_PUBLIC_UDP_PORT, f"listen udp/{TRACEGATE_PUBLIC_UDP_PORT}"),
    )
    assert contract.forbidden_ports("TRANSIT") == (
        ("udp", TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, f"blocked udp/{TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT}"),
    )


def test_unknown_runtime_profile_is_rejected() -> None:
    with pytest.raises(RuntimeContractError, match="unsupported runtime profile"):
        resolve_runtime_contract("totally-custom")


@pytest.mark.parametrize("profile", ["tracegate-3", "xray-centric", "tracegate-2.1"])
def test_transit_declares_tcp8443_listener_and_entry_keeps_it_blocked(profile: str) -> None:
    contract = resolve_runtime_contract(profile)

    assert ("tcp", 8443, "listen tcp/8443") in contract.expected_ports("TRANSIT")
    assert all(not (row[0] == "tcp" and row[1] == 8443) for row in contract.forbidden_ports("TRANSIT"))
    assert ("udp", 8443, "blocked udp/8443") in contract.forbidden_ports("TRANSIT")
    assert ("tcp", 8443, "blocked tcp/8443") in contract.forbidden_ports("ENTRY")
    assert ("udp", 8443, "blocked udp/8443") in contract.forbidden_ports("ENTRY")
    assert all(row[1] != 8443 for row in contract.expected_ports("ENTRY"))


def test_tcp8443_public_listener_helper() -> None:
    assert tcp8443_is_public_listener(role="TRANSIT") is True
    assert tcp8443_is_public_listener(role="ENTRY") is False
    assert (
        tcp8443_is_public_listener(
            role="ENTRY", mtproto_public_port=8443, mtproto_route_mode="entry-transit-endpoint"
        )
        is True
    )
    assert (
        tcp8443_is_public_listener(role="ENTRY", mtproto_public_port=8443, mtproto_route_mode="endpoint-direct")
        is False
    )
