from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any

try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover - local test env fallback
    class _NullMetric:
        def labels(self, *args: object, **kwargs: object) -> "_NullMetric":
            return self

        def inc(self, amount: float = 1.0) -> None:
            return None

        def set(self, value: float) -> None:
            return None

    def Counter(*args: object, **kwargs: object) -> _NullMetric:  # type: ignore[misc]
        return _NullMetric()

    def Gauge(*args: object, **kwargs: object) -> _NullMetric:  # type: ignore[misc]
        return _NullMetric()

_PATH_UP = Gauge(
    "tracegate_transit_selector_path_up",
    "Whether a selector path is currently considered healthy",
    labelnames=["listener", "path"],
)
_PATH_LATENCY_SECONDS = Gauge(
    "tracegate_transit_selector_path_latency_seconds",
    "EWMA latency of selector path probes",
    labelnames=["listener", "path"],
)
_ACTIVE_PATH = Gauge(
    "tracegate_transit_selector_active_path",
    "Whether a selector path is currently active for new connections",
    labelnames=["listener", "path"],
)
_CONNECTIONS_TOTAL = Counter(
    "tracegate_transit_selector_connections_total",
    "TCP connections handled by the selector",
    labelnames=["listener", "path", "result"],
)
_PATH_SWITCHES_TOTAL = Counter(
    "tracegate_transit_selector_path_switches_total",
    "Number of active path switches performed by the selector",
    labelnames=["listener", "from_path", "to_path", "reason"],
)


@dataclass(slots=True, frozen=True)
class TransitPathConfig:
    name: str
    host: str
    port: int
    priority: int = 0
    probe_host: str | None = None
    probe_port: int | None = None
    probe_tls_server_name: str | None = None

    def connect_target(self) -> tuple[str, int]:
        return self.host, int(self.port)

    def probe_target(self) -> tuple[str, int]:
        return (self.probe_host or self.host), int(self.probe_port or self.port)


@dataclass(slots=True, frozen=True)
class TransitListenerConfig:
    name: str
    bind_host: str
    bind_port: int
    idle_timeout_seconds: float
    paths: tuple[TransitPathConfig, ...]


@dataclass(slots=True)
class TransitSelectorRuntimeConfig:
    probe_interval_seconds: float = 5.0
    probe_timeout_seconds: float = 2.0
    connect_timeout_seconds: float = 5.0
    failure_stale_seconds: float = 15.0
    switch_cooldown_seconds: float = 15.0
    switch_margin_ms: float = 20.0
    latency_ewma_alpha: float = 0.35
    unknown_latency_ms: float = 10_000.0


@dataclass(slots=True)
class PathState:
    ewma_latency_ms: float | None = None
    last_probe_monotonic: float = 0.0
    last_success_monotonic: float = 0.0
    consecutive_failures: int = 0
    last_error: str | None = None
    total_successes: int = 0
    total_failures: int = 0

    def register_success(self, *, latency_ms: float, now: float, alpha: float) -> None:
        self.last_probe_monotonic = now
        self.last_success_monotonic = now
        self.consecutive_failures = 0
        self.last_error = None
        self.total_successes += 1
        if self.ewma_latency_ms is None:
            self.ewma_latency_ms = latency_ms
        else:
            self.ewma_latency_ms = (alpha * latency_ms) + ((1.0 - alpha) * self.ewma_latency_ms)

    def register_failure(self, *, now: float, error: str | None) -> None:
        self.last_probe_monotonic = now
        self.consecutive_failures += 1
        self.last_error = error or "probe_failed"
        self.total_failures += 1

    def is_healthy(self, *, now: float, stale_seconds: float) -> bool:
        if self.last_success_monotonic <= 0:
            return False
        return (now - self.last_success_monotonic) <= stale_seconds


@dataclass(slots=True)
class ChosenPath:
    path: TransitPathConfig
    state: PathState
    healthy: bool
    score_ms: float


def parse_listener_configs(raw: str) -> list[TransitListenerConfig]:
    data = json.loads(raw or "[]")
    if not isinstance(data, list):
        raise ValueError("transit selector config must be a JSON list")

    listeners: list[TransitListenerConfig] = []
    seen_listener_names: set[str] = set()
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"listener #{idx + 1} must be an object")
        name = str(item.get("name") or "").strip()
        bind_host = str(item.get("bind_host") or "127.0.0.1").strip()
        bind_port = int(item.get("bind_port") or 0)
        idle_timeout_seconds = float(item.get("idle_timeout_seconds") or 3600.0)
        raw_paths = item.get("paths")
        if not name:
            raise ValueError(f"listener #{idx + 1} is missing name")
        if name in seen_listener_names:
            raise ValueError(f"duplicate listener name: {name}")
        if bind_port <= 0:
            raise ValueError(f"listener {name} has invalid bind_port")
        if idle_timeout_seconds <= 0:
            raise ValueError(f"listener {name} has invalid idle_timeout_seconds")
        if not isinstance(raw_paths, list) or not raw_paths:
            raise ValueError(f"listener {name} must define at least one path")

        seen_listener_names.add(name)
        seen_path_names: set[str] = set()
        paths: list[TransitPathConfig] = []
        for path_idx, raw_path in enumerate(raw_paths):
            if not isinstance(raw_path, dict):
                raise ValueError(f"listener {name} path #{path_idx + 1} must be an object")
            path_name = str(raw_path.get("name") or "").strip()
            host = str(raw_path.get("host") or "").strip()
            port = int(raw_path.get("port") or 0)
            priority = int(raw_path.get("priority") or 0)
            probe_host = str(raw_path.get("probe_host") or "").strip() or None
            probe_port_raw = raw_path.get("probe_port")
            probe_port = int(probe_port_raw) if probe_port_raw not in (None, "") else None
            probe_tls_server_name = str(raw_path.get("probe_tls_server_name") or "").strip() or None
            if not path_name:
                raise ValueError(f"listener {name} path #{path_idx + 1} is missing name")
            if path_name in seen_path_names:
                raise ValueError(f"listener {name} has duplicate path name: {path_name}")
            if not host or port <= 0:
                raise ValueError(f"listener {name} path {path_name} has invalid host/port")
            seen_path_names.add(path_name)
            paths.append(
                TransitPathConfig(
                    name=path_name,
                    host=host,
                    port=port,
                    priority=priority,
                    probe_host=probe_host,
                    probe_port=probe_port,
                    probe_tls_server_name=probe_tls_server_name,
                )
            )

        listeners.append(
            TransitListenerConfig(
                name=name,
                bind_host=bind_host,
                bind_port=bind_port,
                idle_timeout_seconds=idle_timeout_seconds,
                paths=tuple(paths),
            )
        )
    return listeners


class ListenerSelector:
    def __init__(
        self,
        config: TransitListenerConfig,
        runtime: TransitSelectorRuntimeConfig,
        *,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.runtime = runtime
        self.logger = logger
        self._path_index = {path.name: idx for idx, path in enumerate(config.paths)}
        self._states = {path.name: PathState() for path in config.paths}
        self._active_path_name: str = config.paths[0].name
        self._last_switch_monotonic = 0.0
        self._lock = asyncio.Lock()
        self._refresh_metrics(time.monotonic())

    def states(self) -> dict[str, PathState]:
        return self._states

    def ordered_candidates(self, now: float | None = None) -> list[ChosenPath]:
        when = time.monotonic() if now is None else now
        ordered: list[ChosenPath] = []
        for path in self.config.paths:
            state = self._states[path.name]
            healthy = state.is_healthy(now=when, stale_seconds=self.runtime.failure_stale_seconds)
            latency = state.ewma_latency_ms if state.ewma_latency_ms is not None else self.runtime.unknown_latency_ms
            ordered.append(
                ChosenPath(
                    path=path,
                    state=state,
                    healthy=healthy,
                    score_ms=latency,
                )
            )
        ordered.sort(
            key=lambda row: (
                0 if row.healthy else 1,
                row.score_ms,
                -int(row.path.priority),
                self._path_index[row.path.name],
            )
        )
        return ordered

    async def register_probe_result(self, path_name: str, *, latency_ms: float | None, error: str | None) -> None:
        now = time.monotonic()
        async with self._lock:
            state = self._states[path_name]
            if latency_ms is None:
                state.register_failure(now=now, error=error)
            else:
                state.register_success(latency_ms=latency_ms, now=now, alpha=self.runtime.latency_ewma_alpha)
            self._maybe_switch(now)
            self._refresh_metrics(now)

    async def note_connect_failure(self, path_name: str, *, error: str | None) -> None:
        now = time.monotonic()
        async with self._lock:
            state = self._states[path_name]
            state.register_failure(now=now, error=error)
            self._maybe_switch(now)
            self._refresh_metrics(now)

    async def active_path(self) -> TransitPathConfig:
        async with self._lock:
            return self._active_path_locked()

    def _active_path_locked(self) -> TransitPathConfig:
        for path in self.config.paths:
            if path.name == self._active_path_name:
                return path
        return self.config.paths[0]

    def _maybe_switch(self, now: float) -> None:
        candidates = self.ordered_candidates(now)
        if not candidates:
            return
        current = next((item for item in candidates if item.path.name == self._active_path_name), None)
        best = candidates[0]
        if current is None:
            self._switch(best.path.name, now=now, reason="bootstrap")
            return
        if best.path.name == current.path.name:
            return
        if not current.healthy and best.healthy:
            self._switch(best.path.name, now=now, reason="current_unhealthy")
            return
        if not best.healthy:
            return
        if current.healthy:
            if (now - self._last_switch_monotonic) < self.runtime.switch_cooldown_seconds:
                return
            improvement = current.score_ms - best.score_ms
            if improvement < self.runtime.switch_margin_ms:
                return
        self._switch(best.path.name, now=now, reason="better_path")

    def _switch(self, new_path_name: str, *, now: float, reason: str) -> None:
        previous = self._active_path_name
        if new_path_name == previous:
            return
        self._active_path_name = new_path_name
        self._last_switch_monotonic = now
        _PATH_SWITCHES_TOTAL.labels(self.config.name, previous, new_path_name, reason).inc()
        self.logger.info(
            "selector_path_switch listener=%s from=%s to=%s reason=%s",
            self.config.name,
            previous,
            new_path_name,
            reason,
        )

    def _refresh_metrics(self, now: float) -> None:
        active_name = self._active_path_name
        for path in self.config.paths:
            state = self._states[path.name]
            _PATH_UP.labels(self.config.name, path.name).set(
                1.0 if state.is_healthy(now=now, stale_seconds=self.runtime.failure_stale_seconds) else 0.0
            )
            _PATH_LATENCY_SECONDS.labels(self.config.name, path.name).set(
                max(0.0, (state.ewma_latency_ms or self.runtime.unknown_latency_ms) / 1000.0)
            )
            _ACTIVE_PATH.labels(self.config.name, path.name).set(1.0 if path.name == active_name else 0.0)


class TransitListenerServer:
    def __init__(
        self,
        config: TransitListenerConfig,
        runtime: TransitSelectorRuntimeConfig,
        *,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.runtime = runtime
        self.logger = logger
        self.selector = ListenerSelector(config, runtime, logger=logger)
        self._server: asyncio.base_events.Server | None = None
        self._tasks: list[asyncio.Task[Any]] = []

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.config.bind_host,
            port=self.config.bind_port,
        )
        sockets = self._server.sockets or []
        socket_labels = ", ".join(self._format_socket(sock) for sock in sockets)
        self.logger.info(
            "selector_listener_started listener=%s bind=%s paths=%s",
            self.config.name,
            socket_labels or f"{self.config.bind_host}:{self.config.bind_port}",
            ",".join(path.name for path in self.config.paths),
        )
        for path in self.config.paths:
            self._tasks.append(asyncio.create_task(self._probe_loop(path), name=f"selector-probe-{self.config.name}-{path.name}"))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("listener server is not started")
        async with self._server:
            await self._server.serve_forever()

    async def _probe_loop(self, path: TransitPathConfig) -> None:
        jitter = (self.selector._path_index[path.name] % 5) * 0.15
        await asyncio.sleep(jitter)
        while True:
            latency_ms, error = await _probe_path(path, timeout_seconds=self.runtime.probe_timeout_seconds)
            await self.selector.register_probe_result(path.name, latency_ms=latency_ms, error=error)
            await asyncio.sleep(max(0.5, self.runtime.probe_interval_seconds))

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        ordered = self.selector.ordered_candidates()
        chosen_path: TransitPathConfig | None = None
        upstream_reader: asyncio.StreamReader | None = None
        upstream_writer: asyncio.StreamWriter | None = None
        last_error = "no_paths"

        for candidate in ordered:
            chosen_path = candidate.path
            connect_host, connect_port = chosen_path.connect_target()
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_host, connect_port),
                    timeout=self.runtime.connect_timeout_seconds,
                )
                break
            except Exception as exc:  # noqa: BLE001
                last_error = type(exc).__name__
                await self.selector.note_connect_failure(chosen_path.name, error=last_error)
                _CONNECTIONS_TOTAL.labels(self.config.name, chosen_path.name, "connect_error").inc()
                chosen_path = None

        if chosen_path is None or upstream_reader is None or upstream_writer is None:
            self.logger.warning(
                "selector_connect_failed listener=%s error=%s remote=%s",
                self.config.name,
                last_error,
                _peername(client_writer),
            )
            client_writer.close()
            with contextlib.suppress(Exception):
                await client_writer.wait_closed()
            return

        _CONNECTIONS_TOTAL.labels(self.config.name, chosen_path.name, "accepted").inc()
        self.logger.info(
            "selector_connection listener=%s path=%s remote=%s upstream=%s:%s",
            self.config.name,
            chosen_path.name,
            _peername(client_writer),
            chosen_path.host,
            chosen_path.port,
        )

        client_to_up = asyncio.create_task(
            _pipe_stream(
                client_reader,
                upstream_writer,
                idle_timeout_seconds=self.config.idle_timeout_seconds,
            ),
            name=f"selector-pipe-up-{self.config.name}-{chosen_path.name}",
        )
        up_to_client = asyncio.create_task(
            _pipe_stream(
                upstream_reader,
                client_writer,
                idle_timeout_seconds=self.config.idle_timeout_seconds,
            ),
            name=f"selector-pipe-down-{self.config.name}-{chosen_path.name}",
        )

        done, pending = await asyncio.wait({client_to_up, up_to_client}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for task in done:
            with contextlib.suppress(Exception):
                await task

        upstream_writer.close()
        client_writer.close()
        with contextlib.suppress(Exception):
            await upstream_writer.wait_closed()
        with contextlib.suppress(Exception):
            await client_writer.wait_closed()
        _CONNECTIONS_TOTAL.labels(self.config.name, chosen_path.name, "closed").inc()

    @staticmethod
    def _format_socket(sock: socket.socket) -> str:
        addr = sock.getsockname()
        if isinstance(addr, tuple):
            return f"{addr[0]}:{addr[1]}"
        return str(addr)


class TransitSelectorService:
    def __init__(
        self,
        listeners: list[TransitListenerConfig],
        runtime: TransitSelectorRuntimeConfig,
        *,
        logger: logging.Logger,
    ) -> None:
        if not listeners:
            raise ValueError("at least one transit selector listener is required")
        self.listeners = [
            TransitListenerServer(listener, runtime, logger=logger.getChild(listener.name))
            for listener in listeners
        ]
        self.logger = logger

    async def run(self) -> None:
        for listener in self.listeners:
            await listener.start()
        self.logger.info("transit_selector_ready listeners=%s", ",".join(listener.config.name for listener in self.listeners))
        try:
            await asyncio.gather(*(listener.serve_forever() for listener in self.listeners))
        finally:
            for listener in self.listeners:
                with contextlib.suppress(Exception):
                    await listener.stop()


async def _probe_path(
    path: TransitPathConfig,
    *,
    timeout_seconds: float,
) -> tuple[float | None, str | None]:
    latency_ms: float | None = None
    error: str | None = None
    started = time.perf_counter()
    probe_host, probe_port = path.probe_target()
    ssl_context: ssl.SSLContext | None = None
    server_hostname: str | None = None

    if path.probe_tls_server_name:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        server_hostname = path.probe_tls_server_name

    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                probe_host,
                probe_port,
                ssl=ssl_context,
                server_hostname=server_hostname,
            ),
            timeout=timeout_seconds,
        )
        latency_ms = max(0.0, (time.perf_counter() - started) * 1000.0)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    except Exception as exc:  # noqa: BLE001
        error = type(exc).__name__

    return latency_ms, error


async def _pipe_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    idle_timeout_seconds: float,
) -> None:
    while True:
        chunk = await asyncio.wait_for(reader.read(64 * 1024), timeout=idle_timeout_seconds)
        if not chunk:
            break
        writer.write(chunk)
        await writer.drain()


def _peername(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple):
        return f"{peer[0]}:{peer[1]}"
    return str(peer or "unknown")
