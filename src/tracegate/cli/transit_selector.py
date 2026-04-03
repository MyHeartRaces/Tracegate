from __future__ import annotations

import asyncio
import logging

from prometheus_client import start_http_server

from tracegate.observability import configure_logging
from tracegate.settings import get_settings
from tracegate.transit_selector import TransitSelectorRuntimeConfig, TransitSelectorService, parse_listener_configs


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)

    listeners = parse_listener_configs(settings.transit_selector_listeners_json)
    runtime = TransitSelectorRuntimeConfig(
        probe_interval_seconds=float(settings.transit_selector_probe_interval_seconds),
        probe_timeout_seconds=float(settings.transit_selector_probe_timeout_seconds),
        connect_timeout_seconds=float(settings.transit_selector_connect_timeout_seconds),
        failure_stale_seconds=float(settings.transit_selector_failure_stale_seconds),
        switch_cooldown_seconds=float(settings.transit_selector_switch_cooldown_seconds),
        switch_margin_ms=float(settings.transit_selector_switch_margin_ms),
    )

    if settings.transit_selector_metrics_enabled:
        start_http_server(
            int(settings.transit_selector_metrics_port),
            addr=str(settings.transit_selector_metrics_host),
        )

    asyncio.run(
        TransitSelectorService(
            listeners,
            runtime,
            logger=logging.getLogger("tracegate.transit_selector"),
        ).run()
    )
