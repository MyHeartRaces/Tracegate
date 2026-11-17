"""Retired client families (4.1.1): VLESS over WebSocket-TLS and VLESS over gRPC-TLS.

Covers the Direct "Backup" profiles (v0-ws-vless, v0-grpc-vless) and the legacy
Chain variants (v5-entry-ws, v5-universal-entry). Nothing can be issued,
re-issued, activated, pushed or exported any more, but existing rows must
still load, display and be revocable, and every other family keeps working.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import re
import sys
from types import ModuleType, SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, NodeRole, OutboxEventType, RecordStatus
from tracegate.models import Connection, ConnectionRevision, Device, User
from tracegate.schemas import ConnectionCreate
from tracegate.services import connections as connections_service
from tracegate.services import revisions as revisions_service
from tracegate.services.connection_profiles import (
    RETIRED_CLIENT_PROTOCOLS,
    connection_profile_display_label,
    connection_profile_label,
    enabled_profile_keys,
    is_retired_client_protocol,
    is_supported_profile,
    profile_key_for,
    supported_profile_specs,
)
from tracegate.services.materialized_bundles import MaterializedBundleRenderContext, render_materialized_bundles
from tracegate.services.role_targeting import target_roles_for_connection

REPO_ROOT = Path(__file__).resolve().parents[1]
RETIRED_MESSAGE = "retired in Tracegate 4.1.1"

RETIRED = (
    (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
    (ConnectionProtocol.VLESS_GRPC_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
    (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.CHAIN, ConnectionVariant.V5),
    (ConnectionProtocol.VLESS_GRPC_TLS, ConnectionMode.CHAIN, ConnectionVariant.V5),
)


def _import_with_stubs(module_name: str):
    stubs = {
        "prometheus_client": {
            "CONTENT_TYPE_LATEST": "text/plain",
            "generate_latest": lambda *args, **kwargs: b"",
            "Counter": lambda *args, **kwargs: None,
            "Gauge": lambda *args, **kwargs: None,
            "Histogram": lambda *args, **kwargs: None,
            "start_http_server": lambda *args, **kwargs: None,
        },
        "qrcode": {"QRCode": object, "constants": SimpleNamespace(ERROR_CORRECT_M=0)},
    }
    originals = {name: sys.modules.get(name) for name in stubs}
    for name, attrs in stubs.items():
        stub = ModuleType(name)
        for key, value in attrs.items():
            setattr(stub, key, value)
        sys.modules[name] = stub
    try:
        __import__(module_name)
        return sys.modules[module_name]
    finally:
        for name, original in originals.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


# --- migration -----------------------------------------------------------------


def _migration_path() -> Path:
    return REPO_ROOT / "alembic" / "versions" / "d4b6f0e2a315_revoke_retired_vless_ws_grpc_connections.py"


def test_migration_sql_revokes_exactly_the_retired_vless_protocols() -> None:
    text = _migration_path().read_text(encoding="utf-8")
    sql = "\n".join(re.findall(r'"""(.*?)"""', text, flags=re.S)[1:])

    assert 'revision: str = "d4b6f0e2a315"' in text
    assert 'down_revision: Union[str, Sequence[str], None] = "c3a5e9d1f204"' in text
    assert set(re.findall(r"'([A-Z0-9_]+)'", sql)) == {"REVOKED", "VLESS_WS_TLS", "VLESS_GRPC_TLS"}
    assert "UPDATE connection_revision" in sql
    assert "UPDATE connection\n" in sql
    for forbidden in ("DROP", "ALTER TYPE", "DELETE", "VLESS_REALITY", "HYSTERIA2"):
        assert forbidden not in sql.upper()
    # Downgrade is a no-op.
    downgrade = text[text.index("def downgrade()") :]
    assert "op." not in downgrade


def test_migration_is_in_the_single_alembic_history() -> None:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(Config(str(REPO_ROOT / "alembic.ini")))
    heads = script.get_heads()
    assert len(heads) == 1
    # Later migrations (4.1.2 Chain Hysteria revocation) build on top of it.
    assert "d4b6f0e2a315" in {rev.revision for rev in script.walk_revisions(base="base", head=heads[0])}
    assert script.get_revision("d4b6f0e2a315").down_revision == "c3a5e9d1f204"


# --- profile catalogue ----------------------------------------------------------


@pytest.mark.parametrize(("protocol", "mode", "variant"), RETIRED)
def test_retired_profiles_are_not_issuable(protocol, mode, variant) -> None:
    assert is_retired_client_protocol(protocol)
    assert is_retired_client_protocol(protocol.value)
    assert not is_supported_profile(protocol, mode, variant)
    assert profile_key_for(protocol, mode, variant) is None
    assert (protocol, mode, variant) not in set(supported_profile_specs().values())


def test_supported_profiles_are_exactly_reality_hysteria_and_chain() -> None:
    assert supported_profile_specs() == {
        "reality": (ConnectionProtocol.VLESS_REALITY, ConnectionMode.DIRECT, ConnectionVariant.V1),
        "hysteria": (ConnectionProtocol.HYSTERIA2, ConnectionMode.DIRECT, ConnectionVariant.V2),
        "entry": (ConnectionProtocol.VLESS_REALITY, ConnectionMode.CHAIN, ConnectionVariant.V1),
    }
    assert RETIRED_CLIENT_PROTOCOLS == {ConnectionProtocol.VLESS_WS_TLS, ConnectionProtocol.VLESS_GRPC_TLS}
    assert not is_retired_client_protocol(ConnectionProtocol.VLESS_REALITY)
    assert not is_retired_client_protocol(ConnectionProtocol.HYSTERIA2)
    assert not is_retired_client_protocol("not-a-protocol")


def test_old_enabled_profile_names_no_longer_enable_anything() -> None:
    assert enabled_profile_keys(["backup-ws", "backup-grpc", "entry-ws-legacy", "v0-ws-vless", "v5-entry-ws"]) == set()
    assert enabled_profile_keys(["reality", "backup-ws"]) == {"reality"}


def test_retired_enum_members_and_labels_remain_for_existing_rows() -> None:
    assert ConnectionProtocol("vless_ws_tls") is ConnectionProtocol.VLESS_WS_TLS
    assert ConnectionProtocol("vless_grpc_tls") is ConnectionProtocol.VLESS_GRPC_TLS
    ws_direct, grpc_direct, ws_chain, grpc_chain = RETIRED
    assert connection_profile_label(*ws_direct) == "v0-ws-vless"
    assert connection_profile_label(*grpc_direct) == "v0-grpc-vless"
    assert connection_profile_label(*ws_chain) == "v5-entry-ws"
    assert connection_profile_label(*grpc_chain) == "v5-universal-entry"
    assert connection_profile_display_label(*ws_direct) == "Tracegate-Backup(WebSocket)"
    assert connection_profile_display_label(*grpc_direct) == "Tracegate-Backup(gRPC)"


# --- API ------------------------------------------------------------------------


class _CreateSession:
    def __init__(self, *, user: User, device: Device) -> None:
        self.user = user
        self.device = device
        self.added: list[object] = []
        self.commits = 0

    async def get(self, model, key):  # noqa: ANN001
        if model is User and key == self.user.telegram_id:
            return self.user
        if model is Device and key == self.device.id:
            return self.device
        return None

    async def scalar(self, _query):  # noqa: ANN001
        return 0

    def add(self, row: object) -> None:
        self.added.append(row)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        pass

    async def refresh(self, _row: object) -> None:
        pass


@pytest.mark.parametrize(("protocol", "mode", "variant"), RETIRED)
def test_api_refuses_to_create_retired_connections(protocol, mode, variant) -> None:
    create_connection = _import_with_stubs("tracegate.api.routers.connections").create_connection
    user = User(telegram_id=1001, devices_max=5)
    device = Device(id=uuid4(), user_id=user.telegram_id, name="phone", status=RecordStatus.ACTIVE)
    session = _CreateSession(user=user, device=device)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            create_connection(
                ConnectionCreate(
                    user_id=user.telegram_id,
                    device_id=device.id,
                    protocol=protocol,
                    mode=mode,
                    variant=variant,
                    profile_name=connection_profile_label(protocol, mode, variant),
                ),
                session=session,  # type: ignore[arg-type]
            )
        )

    assert exc_info.value.status_code == 400
    assert RETIRED_MESSAGE in str(exc_info.value.detail)
    assert session.added == []
    assert session.commits == 0


# --- revisions (re-issue / activation) -------------------------------------------


def _active_retired_connection(protocol, mode, variant) -> Connection:
    connection = Connection(
        id=uuid4(),
        user_id=1001,
        device_id=uuid4(),
        protocol=protocol,
        mode=mode,
        variant=variant,
        profile_name=connection_profile_label(protocol, mode, variant),
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    connection.revisions = []
    return connection


@pytest.mark.parametrize(("protocol", "mode", "variant"), RETIRED)
def test_reissue_of_retired_connection_is_refused(monkeypatch, protocol, mode, variant) -> None:
    # Even a row that is still ACTIVE (database not yet migrated) is refused.
    connection = _active_retired_connection(protocol, mode, variant)
    emitted: list[object] = []

    async def _load_connection(_session, _connection_id):
        return connection

    async def _emit(*args, **kwargs) -> None:
        emitted.append((args, kwargs))

    monkeypatch.setattr(revisions_service, "_load_connection", _load_connection)
    monkeypatch.setattr(revisions_service, "_emit_apply_for_revision", _emit)

    with pytest.raises(revisions_service.RevisionError, match=RETIRED_MESSAGE):
        asyncio.run(
            revisions_service.create_revision(
                SimpleNamespace(), connection_id=connection.id, camouflage_sni_id=None, force=True
            )
        )
    assert connection.revisions == []
    assert emitted == []


@pytest.mark.parametrize(("protocol", "mode", "variant"), RETIRED)
def test_activation_of_stored_retired_revision_is_refused(monkeypatch, protocol, mode, variant) -> None:
    connection = _active_retired_connection(protocol, mode, variant)
    revision = ConnectionRevision(
        id=uuid4(),
        connection_id=connection.id,
        slot=1,
        status=RecordStatus.ACTIVE,
        effective_config_json={"protocol": "vless", "transport": "ws_tls"},
    )
    connection.revisions.append(revision)

    class _Session:
        async def get(self, _model, key):
            return revision if key == revision.id else None

    async def _load_connection(_session, _connection_id):
        return connection

    monkeypatch.setattr(revisions_service, "_load_connection", _load_connection)

    with pytest.raises(revisions_service.RevisionError, match=RETIRED_MESSAGE):
        asyncio.run(revisions_service.activate_revision(_Session(), revision.id))
    assert revision.slot == 1


def test_dispatch_reissue_never_pushes_retired_connections(monkeypatch) -> None:
    dispatch = _import_with_stubs("tracegate.api.routers.dispatch")
    retired = _active_retired_connection(ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0)
    kept = Connection(
        id=uuid4(),
        user_id=1001,
        device_id=uuid4(),
        protocol=ConnectionProtocol.VLESS_REALITY,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V1,
        status=RecordStatus.ACTIVE,
    )
    pushed: list[str] = []

    class _Result:
        def scalars(self):
            return self

        def all(self):
            return [retired, kept]

    class _Session:
        async def execute(self, _query):
            return _Result()

        async def get(self, _model, _key):
            return None

        async def scalar(self, _query):
            from datetime import datetime, timezone

            return SimpleNamespace(id=uuid4(), created_at=datetime.now(timezone.utc), effective_config_json={})

        async def commit(self) -> None:
            pass

        async def refresh(self, _row) -> None:
            pass

    async def _fake_outbox(_session, **kwargs):
        pushed.append(kwargs["aggregate_id"])
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(dispatch, "create_outbox_event", _fake_outbox)
    monkeypatch.setattr(dispatch.OutboxEventRead, "model_validate", staticmethod(lambda event, **_kwargs: event))

    asyncio.run(dispatch.reissue_current_revisions(dispatch.ReissueRequest(), session=_Session()))

    assert str(retired.id) not in pushed
    assert pushed == [str(kept.id)]


# --- overrides and config builder ------------------------------------------------


@pytest.mark.parametrize("protocol", sorted(RETIRED_CLIENT_PROTOCOLS, key=lambda item: item.value))
def test_override_validation_reports_retired(protocol) -> None:
    from tracegate.services.overrides import OverrideValidationError, validate_overrides

    with pytest.raises(OverrideValidationError, match=RETIRED_MESSAGE):
        validate_overrides(protocol, {})


# --- legacy rows can still be revoked --------------------------------------------


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _RevokeSession:
    def __init__(self, connection, revisions):
        self.connection = connection
        self.revisions = revisions

    async def get(self, _model, key):
        return self.connection if key == self.connection.id else None

    async def execute(self, _statement):
        return _FakeResult(self.revisions)


@pytest.mark.parametrize(("protocol", "mode", "variant"), RETIRED)
def test_legacy_rows_can_still_be_revoked(monkeypatch, protocol, mode, variant) -> None:
    events: list[dict] = []

    async def _fake_outbox(_session, **kwargs):
        events.append(kwargs)

    monkeypatch.setattr(connections_service, "create_outbox_event", _fake_outbox)
    connection = SimpleNamespace(
        id=uuid4(),
        user_id=101,
        device_id=uuid4(),
        protocol=protocol,
        mode=mode,
        variant=variant,
        status=RecordStatus.ACTIVE,
    )
    revision = SimpleNamespace(status=RecordStatus.ACTIVE)

    asyncio.run(connections_service.revoke_connection(_RevokeSession(connection, [revision]), connection.id))

    assert connection.status == RecordStatus.REVOKED
    assert revision.status == RecordStatus.REVOKED
    assert [event["role_target"] for event in events] == target_roles_for_connection(protocol, variant, mode)
    assert all(event["event_type"] == OutboxEventType.REVOKE_CONNECTION for event in events)
    assert NodeRole.TRANSIT in {event["role_target"] for event in events}


# --- bot ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec", ["backup-ws", "backup-grpc", "entry-ws-legacy", "v0ws", "v0grpc", "v0-ws-vless", "v5-universal-entry"]
)
def test_bot_refuses_old_backup_buttons_with_retired_message(spec: str) -> None:
    bot = _import_with_stubs("tracegate.bot.main")

    with pytest.raises(ValueError, match=RETIRED_MESSAGE):
        bot._profile_key(spec)
    with pytest.raises(ValueError, match=RETIRED_MESSAGE):
        bot._profile(spec)


def test_bot_enabled_specs_and_guide_have_no_backup_profiles(monkeypatch) -> None:
    bot = _import_with_stubs("tracegate.bot.main")
    from tracegate.settings import Settings

    monkeypatch.setattr(bot.settings, "enabled_client_profiles", ["reality", "backup-ws", "backup-grpc", "v5-entry-ws"])
    assert bot._enabled_profile_specs() == {"reality"}
    assert bot._profile_key("reality") == "reality"

    guide = str(Settings.model_fields["bot_guide_message"].default)
    for needle in ("Backup", "gRPC", "WebSocket"):
        assert needle not in guide


# --- rendered server templates ---------------------------------------------------


def _render_env(tmp_path: Path) -> dict[str, str]:
    return {
        "BUNDLE_SOURCE_ROOT": str(REPO_ROOT / "bundles"),
        "BUNDLE_MATERIALIZED_ROOT": str(tmp_path / "materialized"),
        "DEFAULT_ENTRY_HOST": "entry.tracegate.test",
        "DEFAULT_TRANSIT_HOST": "transit.tracegate.test",
        "HYSTERIA_GECKO_PASSWORD_ENTRY": "entry-gecko-secret",
        "HYSTERIA_GECKO_PASSWORD_TRANSIT": "transit-gecko-secret",
        "HYSTERIA_STATS_SECRET_ENTRY": "entry-stats-secret",
        "HYSTERIA_STATS_SECRET_TRANSIT": "transit-stats-secret",
        "HYSTERIA_LISTEN_HOST_ENTRY": "192.0.2.10",
        "HYSTERIA_LISTEN_HOST_TRANSIT": "192.0.2.20",
        "REALITY_PUBLIC_KEY_TRANSIT": "transit-public-key",
        "REALITY_SHORT_ID_ENTRY": "entry-short-id",
        "REALITY_SHORT_ID_TRANSIT": "transit-short-id",
        "REALITY_PRIVATE_KEY_ENTRY": "entry-private-key",
        "REALITY_PRIVATE_KEY_TRANSIT": "transit-private-key",
        "REALITY_DEST_ENTRY": "origin-entry.example:443",
        "REALITY_DEST_TRANSIT": "origin-transit.example:443",
        "ENTRY_TLS_SERVER_NAME": "tls-entry.example",
        "TRANSIT_TLS_SERVER_NAME": "tls-transit.example",
        "GRAFANA_PUBLIC_BASE_URL": "https://grafana.tracegate.test",
        "SHADOWSOCKS2022_BACKHAUL_KEY": "backhaul-256-key",
        "SHADOWTLS_BACKHAUL2_SNI": "leg2-front.example",
        "REALITY_BACKHAUL_SNI": "backhaul-front.example",
        "MTPROTO_DOMAIN": "proxied.tracegate.test",
        "XRAY_CENTRIC_DECOY_DIR": "/srv/decoy",
    }


def _render(tmp_path: Path, **extra: str) -> dict[str, str]:
    ctx = MaterializedBundleRenderContext.from_environ({**_render_env(tmp_path), **extra})
    render_materialized_bundles(ctx)
    root = ctx.materialized_root
    return {
        name: (root / name).read_text(encoding="utf-8")
        for name in (
            "base-entry/nginx.conf",
            "base-entry/haproxy.cfg",
            "base-entry/xray.json",
            "base-transit/nginx.conf",
            "base-transit/haproxy.cfg",
            "base-transit/xray.json",
            "base-transit/xray-ss2022.json",
        )
    }


def test_rendered_templates_drop_client_ws_grpc_but_keep_cover_site_grafana_and_bridge(tmp_path: Path) -> None:
    rendered = _render(tmp_path)
    entry_nginx = rendered["base-entry/nginx.conf"]
    transit_nginx = rendered["base-transit/nginx.conf"]
    entry_haproxy = rendered["base-entry/haproxy.cfg"]
    transit_haproxy = rendered["base-transit/haproxy.cfg"]
    entry_xray = json.loads(rendered["base-entry/xray.json"])
    transit_xray = json.loads(rendered["base-transit/xray.json"])
    transit_ss2022 = json.loads(rendered["base-transit/xray-ss2022.json"])

    # Retired client surfaces are gone from the web layer.
    for nginx_conf in (entry_nginx, transit_nginx):
        assert "grpc_pass" not in nginx_conf
        assert "tracegate.v1.Edge" not in nginx_conf
    assert "location /ws" not in entry_nginx
    assert "127.0.0.1:10000" not in entry_nginx
    assert "vless-grpc-in" not in {inbound["tag"] for inbound in transit_xray["inbounds"]}
    assert all("vless-grpc-in" not in (rule.get("inboundTag") or []) for rule in transit_xray["routing"]["rules"])

    # Own-domain TLS termination and the cover/decoy site stay on both roles.
    for nginx_conf, server_name in ((entry_nginx, "tls-entry.example"), (transit_nginx, "tls-transit.example")):
        assert "listen 127.0.0.1:10443 ssl;" in nginx_conf
        assert server_name in nginx_conf
        assert "root /srv/decoy;" in nginx_conf
        assert "try_files $uri $uri/ =404;" in nginx_conf
        assert "error_page 404 /404.html;" in nginx_conf
    assert "listen 127.0.0.1:443 ssl;" in entry_nginx
    assert "listen 192.0.2.10:10444 ssl;" in entry_nginx

    # Grafana routing stays on Endpoint.
    assert "location ^~ /grafana/" in transit_nginx
    assert "proxy_pass http://127.0.0.1:18080;" in transit_nginx
    assert "server_name tls-transit.example grafana.tracegate.test;" in transit_nginx

    # HAProxy still routes the own-domain SNI to the web layer on both roles.
    assert "use_backend be_entry_ws_tls if ws_tls_sni" in entry_haproxy
    assert "server entry_ws_tls 127.0.0.1:10443 check" in entry_haproxy
    assert "use_backend be_transit_ws_tls if ws_tls_sni" in transit_haproxy
    assert "server transit_ws_tls 127.0.0.1:10443 check" in transit_haproxy

    # Entry <-> Endpoint bridge: SS2022+ShadowTLS pool, REALITY backhaul leg,
    # Endpoint backhaul inbound and the source-gated REALITY terminator.
    outbound_tags = {outbound["tag"] for outbound in entry_xray["outbounds"]}
    assert {"to-transit", "to-transit-ss"} <= outbound_tags
    assert entry_xray["routing"]["balancers"][0]["tag"] == "backhaul-balancer"
    assert "ss2022-backhaul-in" in {inbound["tag"] for inbound in transit_ss2022["inbounds"]}
    assert "frontend fe_transit_reality_backhaul" in transit_haproxy
    assert "acl mtproto_tls_sni req.ssl_sni -i proxied.tracegate.test" in entry_haproxy

    # Reality stays on both roles.
    assert "entry-in" in {inbound["tag"] for inbound in entry_xray["inbounds"]}
    assert "vless-reality-in" in {inbound["tag"] for inbound in transit_xray["inbounds"]}


def test_endpoint_ws_inbound_survives_only_as_mtproto_egress_carrier(tmp_path: Path) -> None:
    rendered = _render(
        tmp_path,
        MTPROTO_ROUTE_MODE="entry-local-endpoint-egress",
        MTPROTO_ENTRY_BACKHAUL_UUID="00000000-0000-4000-8000-0000000000aa",
    )
    transit_xray = json.loads(rendered["base-transit/xray.json"])
    entry_xray = json.loads(rendered["base-entry/xray.json"])
    transit_ws = next(inbound for inbound in transit_xray["inbounds"] if inbound["tag"] == "vless-ws-in")

    assert transit_ws["settings"]["clients"] == [
        {"id": "00000000-0000-4000-8000-0000000000aa", "email": "mtproto-entry-egress"}
    ]
    assert "mtproto-egress-endpoint-ws" in {outbound["tag"] for outbound in entry_xray["outbounds"]}
    assert "proxy_pass http://127.0.0.1:10000;" in rendered["base-transit/nginx.conf"]
