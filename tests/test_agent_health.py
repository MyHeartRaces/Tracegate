import pytest

from tracegate.agent import system


@pytest.mark.asyncio
async def test_check_hysteria_stats_secret_auth_only(monkeypatch):
    calls = []

    class _Resp:
        def __init__(self, status_code: int):
            self.status_code = status_code

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None, timeout=0):
            calls.append((url, headers, timeout))
            return _Resp(200)

    monkeypatch.setattr(system.httpx, "AsyncClient", lambda: _Client())

    ok, details = await system.check_hysteria_stats_secret("http://127.0.0.1:9999/traffic", "secret")
    assert ok is True
    assert details == "auth=200"
    assert calls == [("http://127.0.0.1:9999/traffic", {"Authorization": "secret"}, 5)]


@pytest.mark.asyncio
async def test_check_hysteria_stats_secret_empty_secret_short_circuit(monkeypatch):
    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None, timeout=0):  # pragma: no cover - should never be called
            raise AssertionError("network call must not happen for empty secret")

    monkeypatch.setattr(system.httpx, "AsyncClient", lambda: _Client())

    ok, details = await system.check_hysteria_stats_secret("http://127.0.0.1:9999/traffic", "")
    assert ok is False
    assert details == "stats secret is empty"


@pytest.mark.asyncio
async def test_gather_health_checks_vps_e_kubernetes(monkeypatch):
    monkeypatch.setattr(system, "check_port", lambda protocol, port: (True, f"{protocol}:{port}"))
    monkeypatch.setattr(system, "check_process", lambda name: (True, name))
    monkeypatch.setattr(system, "check_systemd", lambda name: (False, name))
    monkeypatch.setattr(system, "check_wg_listen_port", lambda interface, expected: (True, "wg"))

    async def _stats(url, secret):
        return True, "stats-ok"

    monkeypatch.setattr(system, "check_hysteria_stats_secret", _stats)

    checks = await system.gather_health_checks(
        "http://127.0.0.1:9999/traffic",
        "secret",
        "wg0",
        51820,
        "VPS_E",
        "kubernetes",
    )

    names = [row["name"] for row in checks]
    assert "listen tcp/443" in names
    assert "listen udp/443" not in names
    assert "process entry" in names
    assert all(not name.startswith("systemd ") for name in names)
    assert "wireguard listen-port policy" not in names


@pytest.mark.asyncio
async def test_gather_health_checks_vps_t_kubernetes(monkeypatch):
    monkeypatch.setattr(system, "check_port", lambda protocol, port: (True, f"{protocol}:{port}"))
    monkeypatch.setattr(system, "check_process", lambda name: (True, name))
    monkeypatch.setattr(system, "check_systemd", lambda name: (False, name))
    monkeypatch.setattr(system, "check_wg_listen_port", lambda interface, expected: (True, "wg"))

    async def _stats(url, secret):
        return True, "stats-ok"

    monkeypatch.setattr(system, "check_hysteria_stats_secret", _stats)

    checks = await system.gather_health_checks(
        "http://127.0.0.1:9999/traffic",
        "secret",
        "wg0",
        51820,
        "VPS_T",
        "kubernetes",
    )

    names = [row["name"] for row in checks]
    assert "listen tcp/443" in names
    assert "listen udp/443" in names
    assert "listen udp/51820" in names
    assert "process xray" in names
    assert "process hysteria" in names
    assert "hysteria stats API auth" in names
    assert "wireguard listen-port policy" in names
