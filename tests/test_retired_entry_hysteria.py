"""Entry Hysteria / Chain Hysteria retired in Tracegate 4.1.2.

Entry no longer runs Hysteria: Chain is issued only as VLESS Reality. Covers:

- Entry health without Hysteria (a deploy health gate must pass on an Entry
  that has no UDP/443 listener and no Hysteria process), Endpoint unchanged;
- HYSTERIA2 in Chain mode refused like the 4.1.1 retired families: API 400,
  revision create/activate refused, re-issue dispatch skips it, export raises;
- the migration revokes HYSTERIA2 + CHAIN only;
- the host deploy disables ``tracegate-hysteria@entry.service`` on Entry only;
- the Entry agent never renders, reloads or reports Hysteria.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import ModuleType, SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from tracegate.agent import system
from tracegate.agent.reconcile import reconcile_all
from tracegate.client_export.config import ClientConfigExportError, export_client_config
from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, RecordStatus
from tracegate.models import Connection, ConnectionRevision, Device, User
from tracegate.schemas import ConnectionCreate
from tracegate.services import revisions as revisions_service
from tracegate.services.connection_profiles import (
    RETIRED_CLIENT_PROFILES,
    connection_profile_label,
    is_retired_client_profile,
    is_retired_client_protocol,
    is_supported_profile,
    retired_client_profile_message,
)
from tracegate.services.engine_updates import ROLE_ENGINE_UNITS
from tracegate.settings import Settings

REPO_ROOT = Path(__file__).resolve().parents[1]
RETIRED_MESSAGE = "retired in Tracegate 4.1.2"
MIGRATION = REPO_ROOT / "alembic" / "versions" / "a8c3e5f17b42_revoke_retired_hysteria_chain_connections.py"


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


# --- Entry health without Hysteria ------------------------------------------------


def _entry_host_without_hysteria(protocol: str, port: int) -> tuple[bool, str]:
    # A live Entry after the retirement: TCP/443 (HAProxy) listens, nothing on UDP.
    return (protocol == "tcp" and port == 443), f"{protocol}/{port}"


@pytest.mark.parametrize("profile", ["tracegate-3", "xray-centric", "tracegate-2.1"])
def test_entry_is_healthy_without_hysteria(monkeypatch, profile: str) -> None:
    monkeypatch.setattr(system, "check_port", _entry_host_without_hysteria)
    monkeypatch.setattr(system, "check_process", lambda name: (name != "hysteria", name))

    async def _stats(_url, _secret):  # pragma: no cover - Entry never queries Hysteria stats
        raise AssertionError("Entry must not query the Hysteria stats API")

    monkeypatch.setattr(system, "check_hysteria_stats_secret", _stats)

    rows = asyncio.run(system.gather_health_checks("http://127.0.0.1:9999/traffic", "", "ENTRY", "systemd", profile))
    names = [row["name"] for row in rows]

    assert all(row["ok"] for row in rows), rows
    assert "listen tcp/443" in names
    assert "listen udp/443" not in names
    assert "process hysteria" not in names
    assert "process xray" in names
    assert "process haproxy" in names


def test_endpoint_health_still_requires_hysteria(monkeypatch) -> None:
    monkeypatch.setattr(system, "check_port", lambda protocol, port: (True, f"{protocol}/{port}"))
    monkeypatch.setattr(system, "check_port_blocked", lambda protocol, port: (True, f"{protocol}/{port}"))
    monkeypatch.setattr(system, "check_process", lambda name: (True, name))

    async def _stats(_url, _secret):
        return True, "auth=200"

    monkeypatch.setattr(system, "check_hysteria_stats_secret", _stats)

    rows = asyncio.run(
        system.gather_health_checks("http://127.0.0.1:9999/traffic", "secret", "TRANSIT", "systemd", "tracegate-3")
    )
    names = [row["name"] for row in rows]

    assert "listen udp/443" in names
    assert "process hysteria" in names
    assert "hysteria stats API auth" in names


# --- profile catalogue ------------------------------------------------------------


def test_chain_hysteria_is_a_retired_profile_and_direct_hysteria_is_not() -> None:
    assert RETIRED_CLIENT_PROFILES == {(ConnectionProtocol.HYSTERIA2, ConnectionMode.CHAIN)}
    assert is_retired_client_profile(ConnectionProtocol.HYSTERIA2, ConnectionMode.CHAIN)
    assert is_retired_client_profile("hysteria2", "chain")
    assert not is_retired_client_protocol(ConnectionProtocol.HYSTERIA2)
    assert not is_retired_client_profile(ConnectionProtocol.HYSTERIA2, ConnectionMode.DIRECT)
    assert not is_retired_client_profile(ConnectionProtocol.VLESS_REALITY, ConnectionMode.CHAIN)
    assert not is_retired_client_profile("not-a-protocol", "chain")
    assert is_supported_profile(ConnectionProtocol.HYSTERIA2, ConnectionMode.DIRECT, ConnectionVariant.V2)
    assert RETIRED_MESSAGE in retired_client_profile_message(ConnectionProtocol.HYSTERIA2, ConnectionMode.CHAIN)
    assert "4.1.1" in retired_client_profile_message(ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT)


# --- API ----------------------------------------------------------------------------


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


@pytest.mark.parametrize("variant", [ConnectionVariant.V2, ConnectionVariant.V4])
def test_api_refuses_to_create_chain_hysteria(variant) -> None:
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
                    protocol=ConnectionProtocol.HYSTERIA2,
                    mode=ConnectionMode.CHAIN,
                    variant=variant,
                    profile_name="v2-chain-quic-hysteria",
                ),
                session=session,  # type: ignore[arg-type]
            )
        )

    assert exc_info.value.status_code == 400
    assert RETIRED_MESSAGE in str(exc_info.value.detail)
    assert session.added == []
    assert session.commits == 0


# --- revisions (re-issue / activation) and dispatch ------------------------------------


def _active_chain_hysteria() -> Connection:
    connection = Connection(
        id=uuid4(),
        user_id=1001,
        device_id=uuid4(),
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.CHAIN,
        variant=ConnectionVariant.V2,
        profile_name=connection_profile_label(ConnectionProtocol.HYSTERIA2, ConnectionMode.CHAIN, ConnectionVariant.V2),
        custom_overrides_json={},
        status=RecordStatus.ACTIVE,
    )
    connection.revisions = []
    return connection


def test_reissue_of_chain_hysteria_is_refused(monkeypatch) -> None:
    # Refused even while the row is still ACTIVE (database not yet migrated).
    connection = _active_chain_hysteria()
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


def test_activation_of_stored_chain_hysteria_revision_is_refused(monkeypatch) -> None:
    connection = _active_chain_hysteria()
    revision = ConnectionRevision(
        id=uuid4(),
        connection_id=connection.id,
        slot=1,
        status=RecordStatus.ACTIVE,
        effective_config_json={"protocol": "hysteria2", "profile": "v2-chain-quic-hysteria"},
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


def test_dispatch_reissue_never_pushes_chain_hysteria(monkeypatch) -> None:
    dispatch = _import_with_stubs("tracegate.api.routers.dispatch")
    retired = _active_chain_hysteria()
    direct_hysteria = Connection(
        id=uuid4(),
        user_id=1001,
        device_id=uuid4(),
        protocol=ConnectionProtocol.HYSTERIA2,
        mode=ConnectionMode.DIRECT,
        variant=ConnectionVariant.V2,
        status=RecordStatus.ACTIVE,
    )
    pushed: list[str] = []

    class _Result:
        def scalars(self):
            return self

        def all(self):
            return [retired, direct_hysteria]

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
    assert pushed == [str(direct_hysteria.id)]


# --- export ---------------------------------------------------------------------


def _stored_hysteria(profile: str, **extra) -> dict:
    return {
        "protocol": "hysteria2",
        "server": "entry.example.test",
        "port": 443,
        "auth": {"type": "userpass", "username": "u", "password": "p"},
        "obfs": {"type": "gecko", "password": "obfs-secret"},
        "tls": {"server_name": "entry.example.test", "insecure": False, "alpn": ["h3"]},
        "profile": profile,
        **extra,
    }


@pytest.mark.parametrize(
    "effective",
    [
        _stored_hysteria("v2-chain-quic-hysteria", chain={"type": "entry_transit_private_relay"}),
        _stored_hysteria("v2-chain-quic-hysteria"),
        _stored_hysteria("custom", mode="chain"),
    ],
)
def test_export_of_stored_chain_hysteria_revision_is_refused(effective: dict) -> None:
    with pytest.raises(ClientConfigExportError, match=RETIRED_MESSAGE):
        export_client_config(effective)


def test_direct_hysteria_still_exports() -> None:
    exported = export_client_config(_stored_hysteria("v2-direct-quic-hysteria", server="endpoint.example.test"))
    assert exported.content.startswith("hysteria2://")


# --- migration ------------------------------------------------------------------


def test_migration_revokes_only_hysteria2_chain() -> None:
    text = MIGRATION.read_text(encoding="utf-8")
    sql = "\n".join(re.findall(r'"""(.*?)"""', text, flags=re.S)[1:])

    assert 'revision: str = "a8c3e5f17b42"' in text
    assert 'down_revision: Union[str, Sequence[str], None] = "d4b6f0e2a315"' in text
    # Enum names (uppercase) as stored in the database.
    assert set(re.findall(r"'([A-Z0-9_]+)'", sql)) == {"REVOKED", "HYSTERIA2", "CHAIN"}
    assert sql.count("protocol = 'HYSTERIA2'") == 2
    assert sql.count("mode = 'CHAIN'") == 2
    assert "UPDATE connection_revision" in sql
    assert "UPDATE connection\n" in sql
    # Idempotent: already revoked rows are left untouched.
    assert sql.count("status <> 'REVOKED'") == 2
    for forbidden in ("DROP", "ALTER", "DELETE", "DIRECT", "VLESS_REALITY", "INSERT"):
        assert forbidden not in sql.upper()
    downgrade = text[text.index("def downgrade()") :]
    assert "op." not in downgrade


def test_migration_is_the_single_alembic_head() -> None:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(Config(str(REPO_ROOT / "alembic.ini")))
    assert script.get_heads() == ["a8c3e5f17b42"]
    assert script.get_revision("a8c3e5f17b42").down_revision == "d4b6f0e2a315"


def test_migration_upgrade_sql_revokes_chain_hysteria_only_and_is_idempotent() -> None:
    sqlite3 = pytest.importorskip("sqlite3")
    namespace: dict = {}
    executed: list[str] = []

    class _Op:
        @staticmethod
        def execute(statement: str) -> None:
            executed.append(statement)

    # Load the repository-owned migration and capture the SQL its upgrade runs.
    exec(compile(MIGRATION.read_text(encoding="utf-8"), str(MIGRATION), "exec"), namespace)  # noqa: S102
    namespace["op"] = _Op
    namespace["upgrade"]()
    assert len(executed) == 2

    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE connection (id TEXT PRIMARY KEY, protocol TEXT, mode TEXT, status TEXT)")
    db.execute("CREATE TABLE connection_revision (id TEXT PRIMARY KEY, connection_id TEXT, status TEXT)")
    rows = {
        "chain-hy": ("HYSTERIA2", "CHAIN", "ACTIVE"),
        "direct-hy": ("HYSTERIA2", "DIRECT", "ACTIVE"),
        "chain-reality": ("VLESS_REALITY", "CHAIN", "ACTIVE"),
        "chain-hy-revoked": ("HYSTERIA2", "CHAIN", "REVOKED"),
    }
    for row_id, (protocol, mode, status) in rows.items():
        db.execute("INSERT INTO connection VALUES (?, ?, ?, ?)", (row_id, protocol, mode, status))
        db.execute("INSERT INTO connection_revision VALUES (?, ?, ?)", (f"rev-{row_id}", row_id, status))
    for _ in range(2):  # idempotent
        for statement in executed:
            db.execute(statement)

    connection_status = dict(db.execute("SELECT id, status FROM connection"))
    revision_status = dict(db.execute("SELECT connection_id, status FROM connection_revision"))
    assert connection_status == {
        "chain-hy": "REVOKED",
        "direct-hy": "ACTIVE",
        "chain-reality": "ACTIVE",
        "chain-hy-revoked": "REVOKED",
    }
    assert revision_status == connection_status


# --- host deploy ------------------------------------------------------------------


def _executable(path: Path, text: str = "#!/bin/sh\nexit 0\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _release(root: Path, version: str, *, deploy_script: str | None = None) -> Path:
    release = root / "releases" / version
    runtime = release / "runtime"
    venv = release / "venv"
    (runtime / "scripts").mkdir(parents=True)
    (runtime / "deploy/systemd").mkdir(parents=True)
    (runtime / "deploy/host").mkdir(parents=True)
    (runtime / "deploy/systemd/example.service").write_text("[Service]\nExecStart=/bin/true\n")
    (runtime / "deploy/systemd/example.timer").write_text("[Timer]\nOnBootSec=1\n")
    (runtime / "scripts/check_host_runtime.py").write_text("raise SystemExit(0)\n")
    (runtime / "scripts/check_host_deploy.py").write_text("raise SystemExit(0)\n")
    if deploy_script is not None:
        (runtime / "deploy/host/tracegate-host-deploy").write_text(deploy_script, encoding="utf-8")
    for command in ("python", "tracegate-api", "tracegate-migrate-db", "tracegate-host-private-preflight"):
        _executable(venv / "bin" / command)
    _executable(
        venv / "bin" / "tracegate-artifacts",
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "${TRACEGATE_ARTIFACTS_LOG}"\nexit 0\n',
    )
    return release


def _deploy_env(
    tmp_path: Path,
    role: str,
    *,
    systemctl: str,
    old_deploy_script: str | None = None,
) -> tuple[Path, dict[str, str], Path, Path]:
    install_root = tmp_path / "opt/tracegate"
    old = _release(install_root, "4.1.1", deploy_script=old_deploy_script)
    _release(install_root, "4.1.2")
    (install_root / "current").symlink_to(old / "runtime")
    (install_root / "app").symlink_to(old / "runtime")
    (install_root / "venv").symlink_to(old / "venv")
    etc = tmp_path / "etc/tracegate"
    etc.mkdir(parents=True)
    runtime_env = etc / ("tracegate-entry.env" if role == "entry" else "tracegate.env")
    runtime_env.write_text("AGENT_ROLE=placeholder-free\n" if role == "entry" else "HYSTERIA_GECKO_HOP_PORTS=\n")
    runtime_env.chmod(0o600)
    deploy_env = etc / "deploy.env"
    deploy_env.write_text(f"TRACEGATE_HOST_ROLE={role}\nTRACEGATE_BACKUP_COMMAND=true\n")
    fake_bin = tmp_path / "bin"
    log = tmp_path / "systemctl.log"
    _executable(fake_bin / "systemctl", systemctl.replace("@LOG@", str(log)))
    for command in ("curl", "sysctl"):
        _executable(fake_bin / command)
    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "TRACEGATE_INSTALL_ROOT": str(install_root),
        "TRACEGATE_ETC_DIR": str(etc),
        "TRACEGATE_DEPLOY_ENV": str(deploy_env),
        "TRACEGATE_STATE_DIR": str(tmp_path / "state"),
        "TRACEGATE_SYSTEMD_DIR": str(tmp_path / "systemd"),
        "TRACEGATE_SYSCTL_DIR": str(tmp_path / "sysctl.d"),
        "TRACEGATE_LOCAL_SBIN_DIR": str(tmp_path / "sbin"),
        "TRACEGATE_LETSENCRYPT_DEPLOY_HOOK_DIR": str(tmp_path / "letsencrypt-hooks"),
        "TRACEGATE_SYSTEMCTL": str(fake_bin / "systemctl"),
        "TRACEGATE_CURL": str(fake_bin / "curl"),
        "TRACEGATE_SYSCTL": str(fake_bin / "sysctl"),
        "TRACEGATE_HEALTH_ATTEMPTS": "1",
        "TRACEGATE_HEALTH_DELAY_SECONDS": "0",
        "TRACEGATE_ARTIFACTS_LOG": str(tmp_path / "artifacts.log"),
        "TRACEGATE_HYSTERIA_HOP_APPLY": str(fake_bin / "missing-hop-apply"),
    }
    return REPO_ROOT / "deploy/host/tracegate-host-deploy", env, log, install_root


_LOGGING_SYSTEMCTL = '#!/bin/sh\necho "$*" >> "@LOG@"\nexit 0\n'


def test_entry_deploy_disables_entry_hysteria_before_restarting_the_role(tmp_path: Path) -> None:
    script, env, log, install_root = _deploy_env(tmp_path, "entry", systemctl=_LOGGING_SYSTEMCTL)

    subprocess.run([str(script), "deploy", "4.1.2"], env=env, check=True)

    calls = log.read_text(encoding="utf-8").splitlines()
    disable = "disable --now tracegate-hysteria@entry.service"
    assert calls.count(disable) == 1
    first_restart = next(index for index, call in enumerate(calls) if call.startswith("restart "))
    assert calls.index(disable) < first_restart
    # The unit is never enabled or restarted again, and is not part of the role.
    assert not any("tracegate-hysteria@entry.service" in call for call in calls if call != disable)
    artifacts = (tmp_path / "artifacts.log").read_text(encoding="utf-8")
    assert "tracegate-hysteria@" not in artifacts
    # Bridge, firewall and qdisc units still restart on Entry.
    for unit in (
        "tracegate-network-qdisc.service",
        "tracegate-entry-firewall.service",
        "tracegate-xray@entry.service",
        "tracegate-haproxy@entry.service",
        "tracegate-backhaul-fragment@1.service",
        "tracegate-backhaul-fragment@2.service",
        "tracegate-shadowtls-entry.service",
        "tracegate-shadowtls-entry2.service",
    ):
        assert f"restart {unit}" in calls
    assert (install_root / "current").resolve().name == "runtime"
    assert (install_root / "current").resolve().parent.name == "4.1.2"


def test_entry_deploy_tolerates_an_absent_entry_hysteria_unit(tmp_path: Path) -> None:
    systemctl = (
        "#!/bin/sh\n"
        'echo "$*" >> "@LOG@"\n'
        'if [ "$1" = disable ]; then echo "Unit $3 does not exist" >&2; exit 5; fi\n'
        "exit 0\n"
    )
    script, env, log, install_root = _deploy_env(tmp_path, "entry", systemctl=systemctl)

    subprocess.run([str(script), "deploy", "4.1.2"], env=env, check=True)

    assert "disable --now tracegate-hysteria@entry.service" in log.read_text(encoding="utf-8")
    assert (install_root / "current").resolve().parent.name == "4.1.2"


def test_endpoint_deploy_never_touches_entry_hysteria(tmp_path: Path) -> None:
    script, env, log, _install_root = _deploy_env(tmp_path, "endpoint", systemctl=_LOGGING_SYSTEMCTL)

    subprocess.run([str(script), "deploy", "4.1.2"], env=env, check=True)

    calls = log.read_text(encoding="utf-8").splitlines()
    assert not any("tracegate-hysteria@entry" in call for call in calls)
    assert not any(call.startswith("disable --now tracegate-hysteria") for call in calls)
    assert "restart tracegate-hysteria@transit.service" in calls
    assert "restart tracegate-hysteria-salamander.service" in calls


_FAIL_FIRST_RESTART_SYSTEMCTL = (
    "#!/bin/sh\n"
    'echo "$*" >> "@LOG@"\n'
    'if [ "$1" = restart ] && [ ! -e "@LOG@.failed" ]; then touch "@LOG@.failed"; exit 1; fi\n'
    "exit 0\n"
)


def test_entry_rollback_to_a_release_that_ran_entry_hysteria_starts_it_again(tmp_path: Path) -> None:
    # The previous release lists the unit in its ROLE_UNITS (one unit per line).
    old_script = "ROLE_UNITS=(\n        tracegate-xray@entry.service\n        tracegate-hysteria@entry.service\n)\n"
    script, env, log, install_root = _deploy_env(
        tmp_path, "entry", systemctl=_FAIL_FIRST_RESTART_SYSTEMCTL, old_deploy_script=old_script
    )

    result = subprocess.run([str(script), "deploy", "4.1.2"], env=env, check=False)

    assert result.returncode != 0
    calls = log.read_text(encoding="utf-8").splitlines()
    assert calls.index("disable --now tracegate-hysteria@entry.service") < calls.index(
        "enable --now tracegate-hysteria@entry.service"
    )
    assert (install_root / "current").resolve().parent.name == "4.1.1"


def test_entry_rollback_to_a_release_without_entry_hysteria_keeps_it_off(tmp_path: Path) -> None:
    # A release from 4.1.2 on only names the unit in RETIRED_ROLE_UNITS.
    newer_script = (REPO_ROOT / "deploy/host/tracegate-host-deploy").read_text(encoding="utf-8")
    script, env, log, _install_root = _deploy_env(
        tmp_path, "entry", systemctl=_FAIL_FIRST_RESTART_SYSTEMCTL, old_deploy_script=newer_script
    )

    result = subprocess.run([str(script), "deploy", "4.1.2"], env=env, check=False)

    assert result.returncode != 0
    assert "enable --now tracegate-hysteria@entry.service" not in log.read_text(encoding="utf-8")


def test_deploy_script_role_units_and_engine_units_drop_entry_hysteria() -> None:
    deploy = (REPO_ROOT / "deploy/host/tracegate-host-deploy").read_text(encoding="utf-8")
    entry_block = deploy[deploy.index("    entry)\n") : deploy.index("    *) die")]
    role_units = entry_block[entry_block.index("ROLE_UNITS=(") : entry_block.index(")\n", entry_block.index("ROLE_UNITS=("))]
    assert "tracegate-hysteria" not in role_units
    assert "RETIRED_ROLE_UNITS=(tracegate-hysteria@entry.service)" in entry_block
    endpoint_block = deploy[deploy.index("    endpoint)\n") : deploy.index("    entry)\n")]
    assert "tracegate-hysteria@transit.service" in endpoint_block
    assert "RETIRED_ROLE_UNITS" not in endpoint_block
    # The template unit stays for Endpoint.
    assert (REPO_ROOT / "deploy/systemd/tracegate-hysteria@.service").is_file()

    assert "hysteria" not in ROLE_ENGINE_UNITS["entry"]
    assert ROLE_ENGINE_UNITS["endpoint"]["hysteria"] == (
        "tracegate-hysteria@transit.service",
        "tracegate-hysteria-salamander.service",
    )
    registry = json.loads((REPO_ROOT / "deploy/host/artifacts.json").read_text(encoding="utf-8"))
    assert registry["components"]["hysteria"]["policy"] == {"endpoint": "auto"}


# --- Entry agent --------------------------------------------------------------------


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_entry_agent_never_renders_reloads_or_reports_hysteria(tmp_path: Path) -> None:
    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="ENTRY",
        agent_runtime_profile="tracegate-3",
        default_entry_host="entry.tracegate.test",
        default_transit_host="transit.tracegate.test",
    )
    # A hand-managed / pre-4.1.2 Entry base that still carries Hysteria.
    _write(
        tmp_path / "base/xray/config.json",
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "entry-in",
                        "listen": "127.0.0.1",
                        "port": 2443,
                        "protocol": "vless",
                        "settings": {"clients": [], "decryption": "none"},
                        "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {}},
                    },
                    {"tag": "hy2-in", "listen": "0.0.0.0", "port": 443, "protocol": "hysteria", "settings": {"clients": []}},
                ],
                "outbounds": [{"tag": "to-transit", "protocol": "freedom"}],
                "routing": {
                    "rules": [
                        {"type": "field", "inboundTag": ["hy2-in"], "outboundTag": "to-transit"},
                        {"type": "field", "inboundTag": ["entry-in", "hy2-in"], "outboundTag": "to-transit"},
                    ]
                },
            }
        ),
    )
    _write(tmp_path / "base/hysteria/server.yaml", 'listen: ":443"\n')
    _write(tmp_path / "base/nginx/nginx.conf", "events {}\nhttp { server { root /srv/decoy; } }\n")
    _write(tmp_path / "base/haproxy/haproxy.cfg", "frontend fe\n  bind :443\n")
    _write(tmp_path / "runtime/hysteria/server.yaml", 'listen: ":443"\n')
    # An old Chain Hysteria artifact left in the Entry index.
    _write(
        tmp_path / "users/u1/connection-c9.json",
        json.dumps(
            {
                "user_id": "u1",
                "device_id": "d1",
                "connection_id": "c9",
                "revision_id": "r9",
                "protocol": "hysteria2",
                "mode": "chain",
                "variant": "V2",
                "config": {"auth": {"type": "userpass", "username": "u1", "password": "d1"}},
            }
        ),
    )

    changed = reconcile_all(settings)

    assert "hysteria" not in changed
    assert not (tmp_path / "runtime/hysteria").exists()
    runtime_xray = json.loads((tmp_path / "runtime/xray/config.json").read_text(encoding="utf-8"))
    assert [inbound["tag"] for inbound in runtime_xray["inbounds"]] == ["entry-in"]
    for rule in runtime_xray["routing"]["rules"]:
        assert "hy2-in" not in (rule.get("inboundTag") or [])

    contract = json.loads((tmp_path / "runtime/runtime-contract.json").read_text(encoding="utf-8"))
    assert "hysteria" not in contract["contract"]["managedComponents"]
    assert "hysteria" not in contract["contract"]["runtimeDirs"]
    assert {"protocol": "udp", "port": 443, "name": "listen udp/443"} not in contract["contract"]["expectedPorts"]
    assert contract["fronting"]["publicUdpOwner"] == ""
    assert contract["decoy"]["splitHysteriaMasqueradeDirs"] == []
    assert contract["xray"]["hysteriaInboundTags"] == []
    shaping = contract["trafficShaping"]
    assert "chainClient" not in shaping
    assert "entryChainIgnoreClientBandwidth" not in shaping["hysteria"]
    # The host-wide Entry cap stays.
    assert shaping["entry"]["maxMbit"] == 65
    assert shaping["entry"]["scope"] == "host-public-interface"
