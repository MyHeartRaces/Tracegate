import pytest

from tracegate.enums import ConnectionProtocol
from tracegate.services.overrides import OverrideValidationError, validate_overrides


def test_vless_overrides_whitelist() -> None:
    result = validate_overrides(
        ConnectionProtocol.VLESS_REALITY,
        {
            "camouflage_sni_id": 1,
            "connect_timeout_ms": 5000,
            "local_socks_port": 1080,
        },
    )
    assert result["camouflage_sni_id"] == 1


def test_vless_port_override_rejected() -> None:
    with pytest.raises(OverrideValidationError):
        validate_overrides(ConnectionProtocol.VLESS_REALITY, {"port": 8443})


def test_hysteria_security_override_rejected() -> None:
    with pytest.raises(OverrideValidationError):
        validate_overrides(ConnectionProtocol.HYSTERIA2, {"traffic_stats_secret": "bad"})


def test_wireguard_endpoint_override_rejected() -> None:
    with pytest.raises(OverrideValidationError):
        validate_overrides(ConnectionProtocol.WIREGUARD, {"endpoint_port": 12345})
