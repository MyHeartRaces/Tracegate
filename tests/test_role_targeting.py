from tracegate.enums import ConnectionProtocol, ConnectionVariant, NodeRole
from tracegate.services.role_targeting import target_roles_for_connection


def test_chain_targets_vps_e_and_vps_t() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_REALITY, ConnectionVariant.B2)
    assert roles == [NodeRole.VPS_E, NodeRole.VPS_T]


def test_wireguard_targets_only_vps_t() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.WIREGUARD, ConnectionVariant.B5)
    assert roles == [NodeRole.VPS_T]


def test_direct_targets_only_vps_t() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_REALITY, ConnectionVariant.B1)
    assert roles == [NodeRole.VPS_T]


def test_ws_tls_targets_only_vps_t_for_b1() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_WS_TLS, ConnectionVariant.B1)
    assert roles == [NodeRole.VPS_T]
