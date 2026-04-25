import importlib
import json
import os
import sys
import tempfile
import types
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("AGENT_AUTH_TOKEN", "test-agent-token")
os.environ.setdefault("AGENT_DATA_ROOT", tempfile.mkdtemp(prefix="tracegate-agent-main-test-"))
os.environ.setdefault("AGENT_DRY_RUN", "true")

from tracegate.services.mtproto_access import load_mtproto_access_entries
from tracegate.settings import Settings, get_settings


orig_observability = sys.modules.get("tracegate.observability")
fake_observability = types.ModuleType("tracegate.observability")
fake_observability.configure_logging = lambda _level: None
fake_observability.install_http_observability = lambda _app, **_kwargs: None
sys.modules["tracegate.observability"] = fake_observability

orig_agent_metrics = sys.modules.get("tracegate.agent.metrics")
fake_agent_metrics = types.ModuleType("tracegate.agent.metrics")
fake_agent_metrics.register_agent_metrics = lambda _settings: None
sys.modules["tracegate.agent.metrics"] = fake_agent_metrics

fake_prometheus = types.ModuleType("prometheus_client")
fake_prometheus.CONTENT_TYPE_LATEST = "text/plain"
fake_prometheus.generate_latest = lambda: b""
sys.modules["prometheus_client"] = fake_prometheus
get_settings.cache_clear()
try:
    agent_main = importlib.import_module("tracegate.agent.main")
finally:
    sys.modules.pop("prometheus_client", None)
    if orig_agent_metrics is None:
        sys.modules.pop("tracegate.agent.metrics", None)
    else:
        sys.modules["tracegate.agent.metrics"] = orig_agent_metrics
    if orig_observability is None:
        sys.modules.pop("tracegate.observability", None)
    else:
        sys.modules["tracegate.observability"] = orig_observability


def _write_profile(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "protocol": "mtproto",
                "server": "proxied.tracegate.su",
                "port": 443,
                "transport": "tls",
                "domain": "proxied.tracegate.su",
                "clientSecretHex": "ee00112233445566778899aabbccddeeff70726f786965642e7472616365676174652e7375",
                "tgUri": "tg://proxy?server=proxied.tracegate.su&port=443&secret=ee0011",
                "httpsUrl": "https://t.me/proxy?server=proxied.tracegate.su&port=443&secret=ee0011",
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        agent_auth_token="test-agent-token",
        agent_data_root=str(tmp_path / "agent"),
        transit_decoy_auth_login="vault-operator",
        transit_decoy_auth_password="vault-passphrase",
        transit_decoy_secret_path="/vault/mtproto/",
        mtproto_public_profile_file=str(tmp_path / "mtproto" / "public-profile.json"),
        mtproto_issued_state_file=str(tmp_path / "mtproto" / "issued.json"),
    )


def test_agent_live_endpoint_is_lightweight() -> None:
    with TestClient(agent_main.app) as client:
        response = client.get("/v1/live")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["role"] == agent_main.settings.agent_role


def test_agent_health_endpoint_marks_degraded_readiness(monkeypatch) -> None:
    async def _checks(*_args, **_kwargs):
        return [{"name": "listen tcp/443", "ok": False, "details": "not listening"}]

    monkeypatch.setattr(agent_main, "gather_health_checks", _checks)

    with TestClient(agent_main.app) as client:
        response = client.get("/v1/health")

    assert response.status_code == 503
    assert response.json()["overall_ok"] is False


def test_decoy_login_session_and_mtproto_fetch(monkeypatch, tmp_path) -> None:
    settings = _settings(tmp_path)
    _write_profile(Path(settings.mtproto_public_profile_file))

    monkeypatch.setattr(agent_main, "settings", settings)
    monkeypatch.setattr(agent_main, "_is_loopback_host", lambda _host: True)

    with TestClient(agent_main.app) as client:
        login = client.post(
            "/v1/decoy/login",
            json={"login": "vault-operator", "password": "vault-passphrase"},
        )
        assert login.status_code == 200
        assert login.json() == {"ok": True, "redirect": "/vault/mtproto/"}
        assert settings.transit_decoy_auth_cookie_name in login.cookies

        session = client.get("/v1/decoy/session")
        assert session.status_code == 200
        assert session.json() == {"ok": True, "redirect": "/vault/mtproto/"}

        profile = client.get("/v1/decoy/mtproto")
        assert profile.status_code == 200
        payload = profile.json()
        assert payload["ok"] is True
        assert payload["profile"]["protocol"] == "mtproto"
        assert payload["profile"]["server"] == "proxied.tracegate.su"


def test_agent_mtproto_access_issue_persists_user_bound_profile(monkeypatch, tmp_path) -> None:
    settings = _settings(tmp_path)
    _write_profile(Path(settings.mtproto_public_profile_file))
    reload_calls: list[str] = []

    monkeypatch.setattr(agent_main, "settings", settings)
    monkeypatch.setattr(agent_main, "_apply_mtproto_reload", lambda: reload_calls.append("reload"))

    with TestClient(agent_main.app) as client:
        response = client.post(
            "/v1/mtproto/access/issue",
            headers={"x-agent-token": "test-agent-token"},
            json={"telegram_id": 101, "label": "@user101", "issued_by": "bot"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["changed"] is True
    assert payload["profile"]["telegramId"] == 101
    assert payload["profile"]["ephemeral"] is False
    assert reload_calls == ["reload"]
    entries = load_mtproto_access_entries(settings)
    assert len(entries) == 1
    assert entries[0]["telegramId"] == 101
    assert entries[0]["label"] == "@user101"


def test_agent_mtproto_access_issue_rolls_back_when_reload_fails(monkeypatch, tmp_path) -> None:
    settings = _settings(tmp_path)
    _write_profile(Path(settings.mtproto_public_profile_file))
    reload_calls: list[str] = []

    def _fail_reload() -> None:
        reload_calls.append("reload")
        raise HTTPException(status_code=500, detail="reload failed")

    monkeypatch.setattr(agent_main, "settings", settings)
    monkeypatch.setattr(agent_main, "_apply_mtproto_reload", _fail_reload)

    with TestClient(agent_main.app) as client:
        response = client.post(
            "/v1/mtproto/access/issue",
            headers={"x-agent-token": "test-agent-token"},
            json={"telegram_id": 101, "issued_by": "bot"},
        )

    assert response.status_code == 500
    assert response.json()["detail"] == "reload failed"
    assert reload_calls == ["reload", "reload"]
    assert load_mtproto_access_entries(settings) == []


def test_agent_mtproto_access_revoke_removes_profile(monkeypatch, tmp_path) -> None:
    settings = _settings(tmp_path)
    _write_profile(Path(settings.mtproto_public_profile_file))
    reload_calls: list[str] = []

    monkeypatch.setattr(agent_main, "settings", settings)
    monkeypatch.setattr(agent_main, "_apply_mtproto_reload", lambda: reload_calls.append("reload"))

    with TestClient(agent_main.app) as client:
        issue = client.post(
            "/v1/mtproto/access/issue",
            headers={"x-agent-token": "test-agent-token"},
            json={"telegram_id": 101},
        )
        assert issue.status_code == 200

        listing = client.get("/v1/mtproto/access", headers={"x-agent-token": "test-agent-token"})
        assert listing.status_code == 200
        assert listing.json()["entries"] == [
            {
                "telegramId": 101,
                "issuedAt": listing.json()["entries"][0]["issuedAt"],
                "updatedAt": listing.json()["entries"][0]["updatedAt"],
            }
        ]

        revoke = client.delete("/v1/mtproto/access/101", headers={"x-agent-token": "test-agent-token"})

    assert revoke.status_code == 200
    assert revoke.json() == {"ok": True, "removed": True}
    assert reload_calls == ["reload", "reload"]
    assert load_mtproto_access_entries(settings) == []
