import sys
import types

import pytest

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant
from tracegate.services.connection_profiles import connection_profile_sort_key

_prom_stub = types.ModuleType("prometheus_client")
_prom_stub.CONTENT_TYPE_LATEST = "text/plain"
_prom_stub.generate_latest = lambda: b""
_orig_prometheus_client = sys.modules.get("prometheus_client")
sys.modules["prometheus_client"] = _prom_stub
try:
    from tracegate.api.routers.connections import ConnectionValidationError, validate_variant  # noqa: E402
finally:
    if _orig_prometheus_client is None:
        sys.modules.pop("prometheus_client", None)
    else:
        sys.modules["prometheus_client"] = _orig_prometheus_client


def test_tracegate22_connection_variants_are_validated() -> None:
    validate_variant(
        ConnectionProtocol.VLESS_REALITY,
        ConnectionMode.DIRECT,
        ConnectionVariant.V1,
    )
    validate_variant(
        ConnectionProtocol.VLESS_REALITY,
        ConnectionMode.CHAIN,
        ConnectionVariant.V1,
    )
    validate_variant(
        ConnectionProtocol.VLESS_GRPC_TLS,
        ConnectionMode.DIRECT,
        ConnectionVariant.V0,
    )
    validate_variant(
        ConnectionProtocol.HYSTERIA2,
        ConnectionMode.CHAIN,
        ConnectionVariant.V2,
    )
    validate_variant(
        ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        ConnectionMode.DIRECT,
        ConnectionVariant.V3,
    )
    validate_variant(
        ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        ConnectionMode.CHAIN,
        ConnectionVariant.V3,
    )
    validate_variant(
        ConnectionProtocol.WIREGUARD_WSTUNNEL,
        ConnectionMode.DIRECT,
        ConnectionVariant.V0,
    )


def test_wireguard_wstunnel_chain_is_rejected() -> None:
    with pytest.raises(ConnectionValidationError):
        validate_variant(
            ConnectionProtocol.WIREGUARD_WSTUNNEL,
            ConnectionMode.CHAIN,
            ConnectionVariant.V0,
        )


def test_disabled_connection_profile_is_rejected() -> None:
    validate_variant(
        ConnectionProtocol.VLESS_REALITY,
        ConnectionMode.DIRECT,
        ConnectionVariant.V1,
        enabled_client_profiles=["v1-direct-reality-vless"],
    )

    with pytest.raises(ConnectionValidationError, match="disabled"):
        validate_variant(
            ConnectionProtocol.VLESS_REALITY,
            ConnectionMode.CHAIN,
            ConnectionVariant.V1,
            enabled_client_profiles=["v1-direct-reality-vless"],
        )


def test_connection_profile_sort_key_groups_created_connections_by_product_order() -> None:
    shuffled = [
        (ConnectionProtocol.HYSTERIA2, ConnectionMode.CHAIN, ConnectionVariant.V2),
        (ConnectionProtocol.VLESS_GRPC_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
        (ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionMode.DIRECT, ConnectionVariant.V3),
        (ConnectionProtocol.VLESS_REALITY, ConnectionMode.DIRECT, ConnectionVariant.V1),
        (ConnectionProtocol.HYSTERIA2, ConnectionMode.DIRECT, ConnectionVariant.V2),
        (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
        (ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionMode.CHAIN, ConnectionVariant.V3),
        (ConnectionProtocol.VLESS_REALITY, ConnectionMode.CHAIN, ConnectionVariant.V1),
    ]

    ordered = sorted(shuffled, key=lambda item: connection_profile_sort_key(*item))

    assert ordered == [
        (ConnectionProtocol.VLESS_REALITY, ConnectionMode.DIRECT, ConnectionVariant.V1),
        (ConnectionProtocol.HYSTERIA2, ConnectionMode.DIRECT, ConnectionVariant.V2),
        (ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionMode.DIRECT, ConnectionVariant.V3),
        (ConnectionProtocol.VLESS_REALITY, ConnectionMode.CHAIN, ConnectionVariant.V1),
        (ConnectionProtocol.HYSTERIA2, ConnectionMode.CHAIN, ConnectionVariant.V2),
        (ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionMode.CHAIN, ConnectionVariant.V3),
        (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
        (ConnectionProtocol.VLESS_GRPC_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
    ]
