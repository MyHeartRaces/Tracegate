import logging
import time

import pytest

from tracegate.transit_selector import (
    ListenerSelector,
    TransitListenerConfig,
    TransitPathConfig,
    TransitSelectorRuntimeConfig,
    _probe_path,
    parse_listener_configs,
)


def _listener(*paths: TransitPathConfig) -> TransitListenerConfig:
    return TransitListenerConfig(
        name="main",
        bind_host="127.0.0.1",
        bind_port=15443,
        idle_timeout_seconds=3600,
        paths=paths,
    )


@pytest.mark.asyncio
async def test_selector_switches_to_better_healthy_path() -> None:
    selector = ListenerSelector(
        _listener(
            TransitPathConfig(name="public_ipv4", host="1.1.1.1", port=443),
            TransitPathConfig(name="wg_backplane", host="10.200.0.1", port=443),
        ),
        TransitSelectorRuntimeConfig(
            switch_cooldown_seconds=0,
            switch_margin_ms=10,
            failure_stale_seconds=30,
        ),
        logger=logging.getLogger("test.selector"),
    )

    assert (await selector.active_path()).name == "public_ipv4"
    await selector.register_probe_result("public_ipv4", latency_ms=90, error=None)
    await selector.register_probe_result("wg_backplane", latency_ms=25, error=None)

    assert (await selector.active_path()).name == "wg_backplane"


@pytest.mark.asyncio
async def test_selector_holds_current_path_when_improvement_is_too_small() -> None:
    selector = ListenerSelector(
        _listener(
            TransitPathConfig(name="public_ipv4", host="1.1.1.1", port=443),
            TransitPathConfig(name="fqdn", host="tracegate.su", port=443),
        ),
        TransitSelectorRuntimeConfig(
            switch_cooldown_seconds=0,
            switch_margin_ms=15,
            failure_stale_seconds=30,
        ),
        logger=logging.getLogger("test.selector"),
    )

    await selector.register_probe_result("public_ipv4", latency_ms=31, error=None)
    await selector.register_probe_result("fqdn", latency_ms=24, error=None)

    assert (await selector.active_path()).name == "public_ipv4"


@pytest.mark.asyncio
async def test_selector_switches_when_current_path_becomes_unhealthy() -> None:
    selector = ListenerSelector(
        _listener(
            TransitPathConfig(name="public_ipv4", host="1.1.1.1", port=443),
            TransitPathConfig(name="wg_backplane", host="10.200.0.1", port=443),
        ),
        TransitSelectorRuntimeConfig(
            switch_cooldown_seconds=999,
            switch_margin_ms=100,
            failure_stale_seconds=0.01,
        ),
        logger=logging.getLogger("test.selector"),
    )

    await selector.register_probe_result("public_ipv4", latency_ms=20, error=None)
    await selector.register_probe_result("wg_backplane", latency_ms=25, error=None)
    assert (await selector.active_path()).name == "public_ipv4"

    time.sleep(0.02)
    await selector.register_probe_result("wg_backplane", latency_ms=28, error=None)

    assert (await selector.active_path()).name == "wg_backplane"


def test_parse_listener_configs_accepts_multiple_paths() -> None:
    listeners = parse_listener_configs(
        """
        [
          {
            "name": "transit-443",
            "bind_host": "127.0.0.1",
            "bind_port": 15443,
            "idle_timeout_seconds": 120,
            "paths": [
              {"name": "public_ipv4", "host": "176.124.198.228", "port": 443},
              {"name": "wg_backplane", "host": "10.200.0.1", "port": 443, "priority": 10}
            ]
          }
        ]
        """
    )

    assert len(listeners) == 1
    assert listeners[0].name == "transit-443"
    assert [path.name for path in listeners[0].paths] == ["public_ipv4", "wg_backplane"]
    assert listeners[0].paths[1].priority == 10


def test_parse_listener_configs_preserves_probe_overrides() -> None:
    listeners = parse_listener_configs(
        """
        [
          {
            "name": "transit-443",
            "bind_host": "127.0.0.1",
            "bind_port": 15443,
            "idle_timeout_seconds": 120,
            "paths": [
              {
                "name": "custom_probe",
                "host": "tracegate-vps-t",
                "port": 443,
                "probe_host": "10.200.0.1",
                "probe_port": 8443
              }
            ]
          }
        ]
        """
    )

    assert listeners[0].paths[0].connect_target() == ("tracegate-vps-t", 443)
    assert listeners[0].paths[0].probe_target() == ("10.200.0.1", 8443)


def test_parse_listener_configs_preserves_probe_tls_server_name() -> None:
    listeners = parse_listener_configs(
        """
        [
          {
            "name": "transit-443",
            "bind_host": "127.0.0.1",
            "bind_port": 15443,
            "idle_timeout_seconds": 120,
            "paths": [
              {
                "name": "hysteria_backplane",
                "host": "127.0.0.1",
                "port": 16443,
                "probe_host": "127.0.0.1",
                "probe_port": 16443,
                "probe_tls_server_name": "tracegate.su"
              }
            ]
          }
        ]
        """
    )

    assert listeners[0].paths[0].probe_tls_server_name == "tracegate.su"


@pytest.mark.asyncio
async def test_probe_path_uses_tls_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    class _Writer:
        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def _open_connection(host: str, port: int, **kwargs: object) -> tuple[object, _Writer]:
        calls.append({"host": host, "port": port, **kwargs})
        return object(), _Writer()

    monkeypatch.setattr("tracegate.transit_selector.asyncio.open_connection", _open_connection)

    latency_ms, error = await _probe_path(
        TransitPathConfig(
            name="hysteria_backplane",
            host="127.0.0.1",
            port=16443,
            probe_host="127.0.0.1",
            probe_port=16443,
            probe_tls_server_name="tracegate.su",
        ),
        timeout_seconds=1.0,
    )

    assert latency_ms is not None
    assert error is None
    assert len(calls) == 1
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 16443
    assert calls[0]["server_hostname"] == "tracegate.su"
    assert calls[0]["ssl"] is not None
