from tracegate.enums import ConnectionProtocol, ConnectionVariant, NodeRole
from tracegate.services.role_targeting import target_roles_for_connection


def test_chain_targets_entry_and_transit() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_REALITY, ConnectionVariant.V2)
    assert roles == [NodeRole.ENTRY, NodeRole.TRANSIT]


def test_direct_targets_only_transit() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_REALITY, ConnectionVariant.V1)
    assert roles == [NodeRole.TRANSIT]


def test_ws_tls_targets_only_transit_for_v1() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_WS_TLS, ConnectionVariant.V1)
    assert roles == [NodeRole.TRANSIT]


def test_grpc_tls_targets_only_transit_for_v1() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_GRPC_TLS, ConnectionVariant.V1)
    assert roles == [NodeRole.TRANSIT]


def test_hysteria_chain_v4_targets_entry_and_transit() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.HYSTERIA2, ConnectionVariant.V4)
    assert roles == [NodeRole.ENTRY, NodeRole.TRANSIT]


def test_shadowsocks_chain_v6_targets_entry_and_transit() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionVariant.V6)
    assert roles == [NodeRole.ENTRY, NodeRole.TRANSIT]


def test_wireguard_wstunnel_v7_targets_only_transit() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.WIREGUARD_WSTUNNEL, ConnectionVariant.V7)
    assert roles == [NodeRole.TRANSIT]
