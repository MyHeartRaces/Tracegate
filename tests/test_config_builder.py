from datetime import datetime, timezone
from uuid import uuid4

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, EntitlementStatus, RecordStatus
from tracegate.models import Connection, Device, User
from tracegate.services.config_builder import EndpointSet, build_effective_config
from tracegate.services.sni_catalog import SniCatalogEntry


def _user() -> User:
    return User(
        telegram_id=1,
        devices_max=5,
        entitlement_status=EntitlementStatus.ACTIVE,
        grace_ends_at=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _device(user_id):
    return Device(id=uuid4(), user_id=user_id, name="phone", status=RecordStatus.ACTIVE)


def test_chain_sni_same_on_both_legs() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.B2,
        profile_name="B2",
        custom_overrides_json={"local_socks_port": 1080},
        status=RecordStatus.ACTIVE,
    )
    sni = SniCatalogEntry(id=1, fqdn="google.com", enabled=True, is_test=False, providers=[], note=None)

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=sni,
        endpoints=EndpointSet(
            vps_t_host="vps-t.example.com",
            vps_e_host="vps-e.example.com",
            reality_public_key="pub",
            reality_short_id="abcd1234",
        ),
    )

    assert cfg["sni"] == "google.com"
    assert cfg["server"] == "vps-e.example.com"
    assert cfg["chain"]["type"] == "tcp_forward"
    assert cfg["chain"]["upstream"] == "vps-t.example.com"


def test_wireguard_uses_fixed_port_51820() -> None:
    user = _user()
    device = _device(user.telegram_id)
    conn = Connection(
        id=uuid4(),
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=ConnectionProtocol.WIREGUARD,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.B5,
        profile_name="B5",
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )

    cfg = build_effective_config(
        user=user,
        device=device,
        connection=conn,
        selected_sni=None,
        endpoints=EndpointSet(vps_t_host="vps-t.example.com", vps_e_host="vps-e.example.com", wireguard_server_public_key="wgpub"),
    )

    assert cfg["endpoint"].endswith(":51820")
