import pytest

from tracegate.agent import system


def _write_proc_net_table(path, rows: list[str]) -> None:
    path.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        + "\n".join(rows)
        + "\n",
        encoding="utf-8",
    )


def test_proc_net_has_tcp_listener(tmp_path):
    _write_proc_net_table(
        tmp_path / "tcp",
        ["   0: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1"],
    )

    ok, details = system._proc_net_has_listener("tcp", 443, proc_net_root=tmp_path)

    assert ok is True
    assert "/proc/net/tcp port=443 state=0A" in details


def test_proc_net_rejects_non_listening_tcp_state(tmp_path):
    _write_proc_net_table(
        tmp_path / "tcp",
        ["   0: 0100007F:01BB 00000000:0000 01 00000000:00000000 00:00000000 00000000 0 0 1"],
    )

    ok, details = system._proc_net_has_listener("tcp", 443, proc_net_root=tmp_path)

    assert ok is False
    assert "tcp/443 is not listening" in details


def test_proc_net_has_udp_bound_port(tmp_path):
    _write_proc_net_table(
        tmp_path / "udp6",
        ["   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 1"],
    )

    ok, details = system._proc_net_has_listener("udp", 443, proc_net_root=tmp_path)

    assert ok is True
    assert "/proc/net/udp6 port=443 state=07" in details


def test_check_port_falls_back_to_proc_net_when_ss_missing(monkeypatch, tmp_path):
    _write_proc_net_table(
        tmp_path / "tcp",
        ["   0: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1"],
    )

    def _missing(*_args, **_kwargs):
        raise FileNotFoundError

    original_proc_fallback = system._proc_net_has_listener
    monkeypatch.setattr(system.subprocess, "run", _missing)
    monkeypatch.setattr(
        system,
        "_proc_net_has_listener",
        lambda protocol, port: original_proc_fallback(protocol, port, proc_net_root=tmp_path),
    )

    ok, details = system.check_port("tcp", 443)

    assert ok is True
    assert "/proc/net/tcp port=443" in details


def test_proc_has_process_from_comm(tmp_path):
    proc = tmp_path / "123"
    proc.mkdir()
    (proc / "comm").write_text("xray\n", encoding="utf-8")
    (proc / "cmdline").write_bytes(b"")

    ok, details = system._proc_has_process("xray", proc_root=tmp_path)

    assert ok is True
    assert "pid=123" in details


def test_proc_has_process_from_cmdline(tmp_path):
    proc = tmp_path / "456"
    proc.mkdir()
    (proc / "comm").write_text("python\n", encoding="utf-8")
    (proc / "cmdline").write_bytes(b"/usr/local/bin/haproxy\x00-W\x00-db")

    ok, details = system._proc_has_process("haproxy", proc_root=tmp_path)

    assert ok is True
    assert "/usr/local/bin/haproxy -W -db" in details


def test_check_process_falls_back_to_proc_when_pgrep_missing(monkeypatch, tmp_path):
    proc = tmp_path / "789"
    proc.mkdir()
    (proc / "comm").write_text("haproxy\n", encoding="utf-8")
    (proc / "cmdline").write_bytes(b"")

    def _missing(*_args, **_kwargs):
        raise FileNotFoundError

    original_proc_fallback = system._proc_has_process
    monkeypatch.setattr(system.subprocess, "run", _missing)
    monkeypatch.setattr(
        system,
        "_proc_has_process",
        lambda name: original_proc_fallback(name, proc_root=tmp_path),
    )

    ok, details = system.check_process("haproxy")

    assert ok is True
    assert "pid=789" in details


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
async def test_gather_health_checks_entry_legacy_container_runtime(monkeypatch):
    monkeypatch.setattr(system, "check_port", lambda protocol, port: (True, f"{protocol}:{port}"))
    monkeypatch.setattr(system, "check_process", lambda name: (True, name))
    monkeypatch.setattr(system, "check_systemd", lambda name: (False, name))

    async def _stats(url, secret):  # pragma: no cover - should never be called in xray-centric profile
        raise AssertionError("hysteria stats API must not be queried in xray-centric profile")

    monkeypatch.setattr(system, "check_hysteria_stats_secret", _stats)

    checks = await system.gather_health_checks(
        "http://127.0.0.1:9999/traffic",
        "secret",
        "ENTRY",
        "kubernetes",
    )

    names = [row["name"] for row in checks]
    assert "listen tcp/443" in names
    assert "listen udp/443" in names
    assert "process xray" in names
    assert "process haproxy" in names
    assert "hysteria stats API auth" not in names
    assert all(not name.startswith("systemd ") for name in names)
    assert "wireguard listen-port policy" not in names


@pytest.mark.asyncio
async def test_gather_health_checks_transit_legacy_container_runtime(monkeypatch):
    monkeypatch.setattr(system, "check_port", lambda protocol, port: (True, f"{protocol}:{port}"))
    monkeypatch.setattr(system, "check_process", lambda name: (True, name))
    monkeypatch.setattr(system, "check_systemd", lambda name: (False, name))

    async def _stats(url, secret):  # pragma: no cover - should never be called in xray-centric profile
        raise AssertionError("hysteria stats API must not be queried in xray-centric profile")

    monkeypatch.setattr(system, "check_hysteria_stats_secret", _stats)

    checks = await system.gather_health_checks(
        "http://127.0.0.1:9999/traffic",
        "secret",
        "TRANSIT",
        "kubernetes",
    )

    names = [row["name"] for row in checks]
    assert "listen tcp/443" in names
    assert "listen udp/443" in names
    assert "process xray" in names
    assert "process haproxy" in names
    assert "process hysteria" not in names
    assert "hysteria stats API auth" not in names


@pytest.mark.asyncio
async def test_gather_health_checks_transit_xray_centric_profile_skips_hysteria_process_and_stats(monkeypatch):
    monkeypatch.setattr(system, "check_port", lambda protocol, port: (True, f"{protocol}:{port}"))
    monkeypatch.setattr(system, "check_process", lambda name: (True, name))
    monkeypatch.setattr(system, "check_systemd", lambda name: (False, name))

    async def _stats(url, secret):  # pragma: no cover - should never be called in xray-centric profile
        raise AssertionError("hysteria stats API must not be queried for xray-centric profile")

    monkeypatch.setattr(system, "check_hysteria_stats_secret", _stats)

    checks = await system.gather_health_checks(
        "http://127.0.0.1:9999/traffic",
        "",
        "TRANSIT",
        "systemd",
        "xray-centric",
    )

    names = [row["name"] for row in checks]
    assert "listen tcp/443" in names
    assert "listen udp/443" in names
    assert "process xray" in names
    assert "process haproxy" in names
    assert "process hysteria" not in names
    assert "hysteria stats API auth" not in names
