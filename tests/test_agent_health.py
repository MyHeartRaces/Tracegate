import pytest

from tracegate.agent import system


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
