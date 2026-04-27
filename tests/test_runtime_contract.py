import pytest

from tracegate.services.runtime_contract import (
    RuntimeContractError,
    TRACEGATE21_CLIENT_PROFILES,
    TRACEGATE22_CLIENT_PROFILES,
    normalize_runtime_profile_name,
    resolve_runtime_contract,
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
        ("udp", 8443, "listen udp/8443"),
    )
    assert contract.forbidden_ports("ENTRY") == (
        ("udp", 443, "blocked udp/443"),
        ("tcp", 8443, "blocked tcp/8443"),
    )
    assert contract.expected_ports("TRANSIT") == (
        ("tcp", 443, "listen tcp/443"),
        ("udp", 8443, "listen udp/8443"),
    )
    assert contract.forbidden_ports("TRANSIT") == (
        ("udp", 443, "blocked udp/443"),
        ("tcp", 8443, "blocked tcp/8443"),
    )
    assert contract.requires_transit_stats_secret("ENTRY") is False
    assert contract.requires_transit_stats_secret("TRANSIT") is False


def test_tracegate22_runtime_contract_is_default_profile() -> None:
    contract = resolve_runtime_contract("tracegate-2.2")
    alias_contract = resolve_runtime_contract("default")

    assert normalize_runtime_profile_name("") == "tracegate-2.2"
    assert normalize_runtime_profile_name("k3s") == "tracegate-2.2"
    assert alias_contract == contract
    assert contract.manages_component("xray") is True
    assert contract.manages_component("hysteria") is True
    assert contract.hysteria_auth_mode == "userpass"
    assert contract.hysteria_metrics_source == "hysteria_stats"
    assert contract.xray_backhaul_allowed is False
    assert contract.client_profiles == TRACEGATE22_CLIENT_PROFILES
    assert contract.requires_transit_stats_secret("ENTRY") is False
    assert contract.requires_transit_stats_secret("TRANSIT") is True
    assert any(row.name == "process hysteria" for row in contract.process_checks("ENTRY"))
    assert any(row.name == "process hysteria" for row in contract.process_checks("TRANSIT"))
    assert contract.expected_ports("ENTRY") == (
        ("tcp", 443, "listen tcp/443"),
        ("udp", 8443, "listen udp/8443"),
    )
    assert contract.forbidden_ports("ENTRY") == (
        ("udp", 443, "blocked udp/443"),
        ("tcp", 8443, "blocked tcp/8443"),
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
        ("udp", 8443, "listen udp/8443"),
    )
    assert contract.forbidden_ports("ENTRY") == (
        ("udp", 443, "blocked udp/443"),
        ("tcp", 8443, "blocked tcp/8443"),
    )


def test_tracegate21_runtime_contract_is_k3s_profile_without_xray_backhaul() -> None:
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
        ("udp", 8443, "listen udp/8443"),
    )
    assert contract.forbidden_ports("TRANSIT") == (
        ("udp", 443, "blocked udp/443"),
        ("tcp", 8443, "blocked tcp/8443"),
    )


def test_unknown_runtime_profile_is_rejected() -> None:
    with pytest.raises(RuntimeContractError, match="unsupported runtime profile"):
        resolve_runtime_contract("totally-custom")
