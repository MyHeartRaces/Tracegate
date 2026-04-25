import sys
import types

import pytest

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant

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


def test_tracegate21_connection_variants_are_validated() -> None:
    validate_variant(
        ConnectionProtocol.VLESS_GRPC_TLS,
        ConnectionMode.DIRECT,
        ConnectionVariant.V1,
    )
    validate_variant(
        ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        ConnectionMode.DIRECT,
        ConnectionVariant.V5,
    )
    validate_variant(
        ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        ConnectionMode.CHAIN,
        ConnectionVariant.V6,
    )
    validate_variant(
        ConnectionProtocol.WIREGUARD_WSTUNNEL,
        ConnectionMode.DIRECT,
        ConnectionVariant.V7,
    )


def test_wireguard_wstunnel_chain_is_rejected() -> None:
    with pytest.raises(ConnectionValidationError):
        validate_variant(
            ConnectionProtocol.WIREGUARD_WSTUNNEL,
            ConnectionMode.CHAIN,
            ConnectionVariant.V7,
        )
