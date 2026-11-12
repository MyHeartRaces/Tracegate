"""Static checks and authenticated post-switch probes for engine updates.

Every probe is read-only towards the live runtime: configs are mounted
read-only into short-lived containers, synthetic clients run the candidate
image itself and only use the internal backhaul identities (never a real
user's credentials). Secrets read from runtime configs or settings are never
written to evidence, logs or the journal.

Standard library only, with docker/systemctl, HTTP and the SOCKS fetch
injected so tests need neither a daemon nor network.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import ssl
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
import urllib.request

from tracegate.services.artifacts import ArtifactError, ArtifactStore, Runner
from tracegate.services.engine_updates import CheckResult, Evidence, ProbeContext, ProbePlan

PROBE_URL = "https://www.gstatic.com/generate_204"
REALITY_INBOUND_TAG = "vless-reality-in"
REALITY_BACKHAUL_EMAIL = "entry-transit"
REALITY_PROBE_PORT = 443
BACKHAUL_CHANNELS = ("shadowtls-primary-a", "shadowtls-primary-b", "reality-fallback")
_SUCCESS_METRIC = "tracegate_backhaul_egress_probe_success"
_LAST_TRY_METRIC = "tracegate_backhaul_egress_probe_last_try_timestamp_seconds"
_DOCKER_RUN_ERRORS = {125, 126, 127}

HttpGet = Callable[[str, dict[str, str], float], tuple[int, bytes]]
SocksFetch = Callable[[int, str, float], int]


def urllib_http_get(url: str, headers: dict[str, str], timeout: float) -> tuple[int, bytes]:
    """Loopback HTTP GET without proxies; HTTP errors return their status."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(response.status), response.read()
    except HTTPError as exc:
        try:
            body = exc.read()
        except Exception:  # noqa: BLE001
            body = b""
        return int(exc.code), body
    except (URLError, OSError, TimeoutError) as exc:
        raise ConnectionError(str(exc)) from exc


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("SOCKS proxy closed the connection")
        data += chunk
    return data


def socks5_https_status(port: int, url: str, timeout: float) -> int:
    """HTTPS GET through a loopback SOCKS5 proxy (remote DNS); returns the HTTP status."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    target_port = parts.port or 443
    path = parts.path or "/"
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
        raw.sendall(b"\x05\x01\x00")
        if _recv_exact(raw, 2) != b"\x05\x00":
            raise ConnectionError("SOCKS proxy refused the no-auth method")
        encoded = host.encode("idna")
        raw.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + target_port.to_bytes(2, "big"))
        header = _recv_exact(raw, 4)
        if header[1] != 0:
            raise ConnectionError(f"SOCKS CONNECT failed with code {header[1]}")
        atyp = header[3]
        if atyp == 1:
            _recv_exact(raw, 4 + 2)
        elif atyp == 4:
            _recv_exact(raw, 16 + 2)
        elif atyp == 3:
            _recv_exact(raw, _recv_exact(raw, 1)[0] + 2)
        else:
            raise ConnectionError("SOCKS reply has an unknown address type")
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tracegate-engine-probe\r\n"
                "Connection: close\r\n\r\n".encode("ascii")
            )
            status_line = b""
            while b"\r\n" not in status_line and len(status_line) < 1024:
                chunk = tls.recv(256)
                if not chunk:
                    break
                status_line += chunk
        fields = status_line.split(b"\r\n", 1)[0].split()
        if len(fields) < 2 or not fields[1].isdigit():
            raise ConnectionError("no HTTP status line through the SOCKS proxy")
        return int(fields[1])


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass(frozen=True)
class ProbeConfig:
    role: str
    state_root: Path = Path("/var/lib/tracegate")
    units_dir: Path = Path("/etc/systemd/system")
    agent_health_url: str = "http://127.0.0.1:8070/v1/health"
    agent_metrics_url: str = "http://127.0.0.1:8070/metrics"
    agent_token: str = ""
    prometheus_url: str = "http://127.0.0.1:9090"
    grafana_url: str = ""
    hysteria_backhaul_token: str = ""
    hysteria_server_name: str = ""
    # Endpoint REALITY public key from settings. The probe never derives it
    # from the private key, so the private key never leaves the config file.
    reality_public_key: str = ""
    probe_url: str = PROBE_URL
    sustain_samples: int = 5
    sustain_interval: float = 3.0
    ready_timeout: float = 60.0
    ready_interval: float = 2.0
    fresh_timeout: float = 300.0
    request_timeout: float = 10.0

    def __post_init__(self) -> None:
        if self.sustain_samples < 2 or self.sustain_interval * (self.sustain_samples - 1) < 10:
            raise ValueError("sustained probes need several samples spanning at least 10 seconds")


@dataclass(frozen=True)
class UnitSpec:
    container: str
    mounts: dict[str, str]  # container path -> host path


def parse_unit(text: str, instance: str | None) -> UnitSpec:
    match = re.search(r"(?m)^ExecStart=(?P<cmd>.*)$", text)
    if match is None:
        raise ValueError("unit has no ExecStart")
    command = match.group("cmd")
    if instance is not None:
        command = command.replace("%i", instance)
    argv = shlex.split(command)
    container = ""
    mounts: dict[str, str] = {}
    for index, token in enumerate(argv):
        if token == "--name" and index + 1 < len(argv):
            container = argv[index + 1]
        if token == "-v" and index + 1 < len(argv):
            pieces = argv[index + 1].split(":")
            if len(pieces) >= 2:
                mounts[pieces[1]] = pieces[0]
    if not container:
        raise ValueError("unit ExecStart has no --name")
    return UnitSpec(container=container, mounts=mounts)


def _yaml_load(path: Path) -> dict[str, Any]:
    import yaml  # project dependency; imported lazily to keep the module light

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} is not a mapping")
    return payload


def _first_dns_san(cert_path: Path) -> str:
    """First DNS SAN of a PEM certificate (Hysteria sniGuard dns-san matches it)."""
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        )
    except Exception:  # noqa: BLE001
        return ""
    for name in names:
        if name and not name.startswith("*."):
            return str(name)
    return ""


def _parse_prom_text(text: str, metric: str) -> dict[str, float]:
    """{channel: value} for one metric family from Prometheus text exposition."""
    values: dict[str, float] = {}
    pattern = re.compile(rf"^{re.escape(metric)}\{{(?P<labels>[^}}]*)\}}\s+(?P<value>\S+)")
    for line in text.splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        labels = dict(re.findall(r'(\w+)="([^"]*)"', match.group("labels")))
        channel = labels.get("channel")
        if not channel:
            continue
        try:
            value = float(match.group("value"))
        except ValueError:
            continue
        values[channel] = min(values.get(channel, value), value)
    return values


class HostProber:
    def __init__(
        self,
        *,
        config: ProbeConfig,
        store: ArtifactStore,
        runner: Runner,
        units_for: Callable[[str], tuple[str, ...]],
        http_get: HttpGet = urllib_http_get,
        socks_fetch: SocksFetch = socks5_https_status,
        free_port: Callable[[], int] = free_loopback_port,
        now: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.role = config.role
        self.store = store
        self.runner = runner
        self.units_for = units_for
        self.http_get = http_get
        self.socks_fetch = socks_fetch
        self.free_port = free_port
        self.now = now
        self.sleep = sleep

    # -- unit model -------------------------------------------------------------

    def unit_spec(self, unit: str) -> UnitSpec:
        instance: str | None = None
        template = unit
        if "@" in unit:
            prefix, rest = unit.split("@", 1)
            instance = rest[: -len(".service")] if rest.endswith(".service") else rest
            template = f"{prefix}@.service"
        path = self.config.units_dir / template
        return parse_unit(path.read_text(encoding="utf-8"), instance)

    def _mount(self, unit: str, container_path: str) -> Path | None:
        try:
            source = self.unit_spec(unit).mounts.get(container_path)
        except (OSError, ValueError):
            return None
        return Path(source) if source else None

    # -- plan ----------------------------------------------------------------------

    def plan(self, component: str) -> ProbePlan:
        common = ("units-active", "container-digests", "agent-health")
        if self.role == "endpoint":
            if component == "xray":
                try:
                    self._reality_params(client_image=None)
                except ValueError as exc:
                    return ProbePlan(False, common, f"Reality probe unavailable: {exc}")
                if not str(self.config.reality_public_key or "").strip():
                    return ProbePlan(False, common, "Reality probe unavailable: REALITY public key is not configured")
                return ProbePlan(True, (*common, "reality-client", "backhaul-prometheus"))
            if component == "hysteria":
                if not self.config.hysteria_backhaul_token:
                    return ProbePlan(False, common, "the Hysteria backhaul auth token is not set")
                try:
                    self._hysteria_targets()
                except ValueError as exc:
                    return ProbePlan(False, common, f"Hysteria probe unavailable: {exc}")
                return ProbePlan(True, (*common, "hysteria-client"))
            if component == "shadowtls":
                return ProbePlan(True, (*common, "backhaul-prometheus"))
            if component == "prometheus":
                return ProbePlan(True, (*common, "prometheus-ready"))
            if component == "grafana":
                if not self.config.grafana_url:
                    return ProbePlan(False, common, "the Grafana URL is not set")
                return ProbePlan(True, (*common, "grafana-health"))
        if self.role == "entry" and component == "shadowtls":
            if not self.config.agent_token:
                return ProbePlan(False, common, "the agent token is not set")
            return ProbePlan(True, (*common, "backhaul-agent"))
        return ProbePlan(False, common, f"no authenticated probe for {component} on {self.role}")

    # -- static check ------------------------------------------------------------------

    def static_check(self, component: str, reference: str, units: tuple[str, ...]) -> CheckResult:
        if component == "xray":
            return self._check_each(
                units,
                "/etc/xray/config.json",
                lambda source: [
                    "docker", "run", "--rm", "--network", "none", "--read-only", "--user", "0:0",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                    "-v", f"{source}:/etc/xray/config.json:ro",
                    reference, "run", "-test", "-c", "/etc/xray/config.json",
                ],
                "xray-test",
            )
        if component == "prometheus":
            return self._check_each(
                units,
                "/etc/prometheus/prometheus.yml",
                lambda source: [
                    "docker", "run", "--rm", "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                    "--entrypoint", "/bin/promtool",
                    "-v", f"{source}:/etc/prometheus/prometheus.yml:ro",
                    reference, "check", "config", "/etc/prometheus/prometheus.yml",
                ],
                "promtool-check",
            )
        return CheckResult("ok", (Evidence("static-check", True, f"no static check for {component}"),))

    def _check_each(
        self,
        units: tuple[str, ...],
        container_path: str,
        build: Callable[[Path], list[str]],
        name: str,
    ) -> CheckResult:
        evidence: list[Evidence] = []
        status = "ok"
        sources: list[Path] = []
        for unit in units:
            source = self._mount(unit, container_path)
            if source is None:
                evidence.append(Evidence(name, False, f"{unit}: config mount not found in the installed unit"))
                status = "error"
                continue
            if source not in sources:
                sources.append(source)
        for source in sources:
            if not source.is_file():
                evidence.append(Evidence(name, False, f"{source} is missing"))
                status = "error"
                continue
            result = self.runner(build(source))
            if result.returncode == 0:
                evidence.append(Evidence(name, True, f"{source} accepted"))
                continue
            tail = ((result.stderr or "") + (result.stdout or "")).strip().splitlines()[-3:]
            detail = f"{source}: exit {result.returncode}: {' | '.join(tail)}"[:500]
            evidence.append(Evidence(name, False, detail))
            if result.returncode in _DOCKER_RUN_ERRORS:
                status = "error" if status == "ok" else status
            else:
                status = "fail"
        if not evidence:
            return CheckResult("error", (Evidence(name, False, "no runtime config to check"),))
        return CheckResult(status, tuple(evidence))

    # -- probes ----------------------------------------------------------------------------

    def probe(self, context: ProbeContext) -> list[Evidence]:
        plan = self.plan(context.component)
        results: list[Evidence] = [self._units_active(context), self._container_digests(context)]
        results.append(self._sustain("agent-health", self._agent_health_once))
        if not all(item.ok for item in results):
            return results
        for name in plan.probes:
            if name == "reality-client":
                results.append(self._reality_probe(context))
            elif name == "hysteria-client":
                results.extend(self._hysteria_probes(context))
            elif name == "backhaul-prometheus":
                results.append(self._backhaul_probe(context, self._backhaul_from_prometheus, "backhaul-prometheus"))
            elif name == "backhaul-agent":
                results.append(self._backhaul_probe(context, self._backhaul_from_agent, "backhaul-agent"))
            elif name == "prometheus-ready":
                results.append(self._sustain("prometheus-ready", self._prometheus_ready_once))
            elif name == "grafana-health":
                results.append(self._sustain("grafana-health", self._grafana_health_once))
            if not results[-1].ok:
                break
        return results

    def _sustain(self, name: str, check: Callable[[], tuple[bool, str]]) -> Evidence:
        """Wait until the check first passes, then require every sample of a >=10 s window to pass."""
        cfg = self.config
        deadline = self.now() + cfg.ready_timeout
        while True:
            ok, detail = self._safe(check)
            if ok:
                break
            if self.now() >= deadline:
                return Evidence(name, False, f"not ready within {cfg.ready_timeout:.0f}s: {detail}")
            self.sleep(cfg.ready_interval)
        started = self.now()
        for index in range(1, cfg.sustain_samples):
            self.sleep(cfg.sustain_interval)
            ok, detail = self._safe(check)
            if not ok:
                return Evidence(name, False, f"sample {index + 1}/{cfg.sustain_samples} failed: {detail}")
        return Evidence(name, True, f"{cfg.sustain_samples} samples passed over {self.now() - started:.0f}s")

    @staticmethod
    def _safe(check: Callable[[], tuple[bool, str]]) -> tuple[bool, str]:
        try:
            return check()
        except Exception as exc:  # noqa: BLE001 - a probe error is a failed sample
            return False, f"{type(exc).__name__}: {exc}"[:300]

    def _units_active(self, context: ProbeContext) -> Evidence:
        inactive = [
            unit
            for unit in context.units
            if self.runner(["systemctl", "is-active", "--quiet", unit]).returncode != 0
        ]
        if inactive:
            return Evidence("units-active", False, f"not active: {', '.join(inactive)}")
        return Evidence("units-active", True, f"{len(context.units)} unit(s) active")

    def _container_digests(self, context: ProbeContext) -> Evidence:
        try:
            status = self.store.status([context.component])[0]
        except ArtifactError as exc:
            return Evidence("container-digests", False, str(exc))
        if status.running_error is not None:
            return Evidence("container-digests", False, status.running_error)
        running = {container.name: container.digest for container in status.running}
        problems: list[str] = []
        for unit in context.units:
            try:
                container = self.unit_spec(unit).container
            except (OSError, ValueError) as exc:
                problems.append(f"{unit}: {exc}")
                continue
            expected = context.expected_digests.get(unit)
            actual = running.get(container)
            if actual is None:
                problems.append(f"{container} is not running")
            elif expected is not None and actual != expected:
                problems.append(f"{container} runs {actual}, expected {expected}")
        if problems:
            return Evidence("container-digests", False, "; ".join(problems))
        return Evidence("container-digests", True, "running containers use the expected digests")

    def _agent_health_once(self) -> tuple[bool, str]:
        status, body = self.http_get(self.config.agent_health_url, {}, self.config.request_timeout)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, f"HTTP {status}, unparseable body"
        if payload.get("overall_ok") is True:
            return True, "overall_ok"
        failed = [
            str(check.get("name"))
            for check in payload.get("checks") or []
            if isinstance(check, dict) and not check.get("ok")
        ]
        return False, f"HTTP {status}, failing checks: {', '.join(failed) or 'unknown'}"

    def _prometheus_ready_once(self) -> tuple[bool, str]:
        status, _ = self.http_get(f"{self.config.prometheus_url.rstrip('/')}/-/ready", {}, self.config.request_timeout)
        return status == 200, f"HTTP {status}"

    def _grafana_health_once(self) -> tuple[bool, str]:
        status, body = self.http_get(f"{self.config.grafana_url.rstrip('/')}/api/health", {}, self.config.request_timeout)
        if status != 200:
            return False, f"HTTP {status}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, "unparseable body"
        database = str(payload.get("database") or "")
        return database == "ok", f"database {database or 'unknown'}"

    # -- backhaul freshness ------------------------------------------------------------------

    def _prom_query(self, query: str) -> dict[str, float]:
        url = f"{self.config.prometheus_url.rstrip('/')}/api/v1/query?{urlencode({'query': query})}"
        status, body = self.http_get(url, {}, self.config.request_timeout)
        if status != 200:
            raise ConnectionError(f"Prometheus answered HTTP {status}")
        payload = json.loads(body.decode("utf-8"))
        values: dict[str, float] = {}
        for row in payload.get("data", {}).get("result", []):
            channel = row.get("metric", {}).get("channel")
            if channel:
                values[str(channel)] = float(row["value"][1])
        return values

    def _backhaul_from_prometheus(self) -> tuple[dict[str, float], dict[str, float]]:
        success = self._prom_query(f"min by (channel) ({_SUCCESS_METRIC})")
        last_try = self._prom_query(f"min by (channel) ({_LAST_TRY_METRIC})")
        return success, last_try

    def _backhaul_from_agent(self) -> tuple[dict[str, float], dict[str, float]]:
        status, body = self.http_get(
            self.config.agent_metrics_url,
            {"X-Agent-Token": self.config.agent_token},
            self.config.request_timeout,
        )
        if status != 200:
            raise ConnectionError(f"agent /metrics answered HTTP {status}")
        text = body.decode("utf-8", errors="replace")
        return _parse_prom_text(text, _SUCCESS_METRIC), _parse_prom_text(text, _LAST_TRY_METRIC)

    def _backhaul_probe(
        self,
        context: ProbeContext,
        source: Callable[[], tuple[dict[str, float], dict[str, float]]],
        name: str,
    ) -> Evidence:
        def once() -> tuple[bool, str]:
            success, last_try = source()
            problems: list[str] = []
            for channel in BACKHAUL_CHANNELS:
                if channel not in success or channel not in last_try:
                    problems.append(f"{channel} missing")
                elif last_try[channel] <= context.since:
                    problems.append(f"{channel} not probed since the switch")
                elif success[channel] != 1:
                    problems.append(f"{channel} failing")
            return (not problems), ("; ".join(problems) or "all channels fresh and passing")

        # Fresh results may take a few observatory and scrape intervals; until
        # then (or until a channel recovers after the restart) keep polling.
        cfg = self.config
        deadline = self.now() + cfg.fresh_timeout
        while True:
            ok, detail = self._safe(once)
            if ok:
                break
            if self.now() >= deadline:
                return Evidence(name, False, f"no fresh passing results within {cfg.fresh_timeout:.0f}s: {detail}")
            self.sleep(cfg.ready_interval)
        return self._sustain(name, once)

    # -- synthetic clients -----------------------------------------------------------------------

    def _probe_dir(self) -> Path:
        base = self.store.root / "probe"
        base.mkdir(parents=True, exist_ok=True)
        os.chmod(base, 0o700)
        path = base / secrets.token_hex(6)
        path.mkdir(mode=0o700)
        return path

    def _run_client(self, name: str, image: str, config_text: str, config_target: str, args: list[str], socks_port: int) -> Evidence:
        workdir = self._probe_dir()
        container = f"tracegate-engine-probe-{name}-{secrets.token_hex(4)}"
        try:
            config_path = workdir / Path(config_target).name
            fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(config_text)
            started = self.runner(
                [
                    "docker", "run", "-d", "--rm", "--name", container, "--network", "host",
                    "--read-only", "--user", "0:0", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp",
                    "-v", f"{config_path}:{config_target}:ro", image, *args,
                ]
            )
            if started.returncode != 0:
                return Evidence(name, False, f"client did not start (exit {started.returncode})")

            def once() -> tuple[bool, str]:
                code = self.socks_fetch(socks_port, self.config.probe_url, self.config.request_timeout)
                return code == 204, f"HTTP {code}"

            return self._sustain(name, once)
        finally:
            self.runner(["docker", "rm", "-f", container])
            shutil.rmtree(workdir, ignore_errors=True)

    def _runtime_root(self) -> Path:
        agent = "agent-transit" if self.role == "endpoint" else "agent-entry"
        return self.config.state_root / agent / "runtime"

    def _reality_params(self, client_image: str | None) -> dict[str, Any]:
        path = self._runtime_root() / "xray" / "config.json"
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read the Endpoint Xray runtime config: {exc}") from exc
        inbound = next(
            (row for row in config.get("inbounds") or [] if isinstance(row, dict) and row.get("tag") == REALITY_INBOUND_TAG),
            None,
        )
        if inbound is None:
            raise ValueError(f"inbound {REALITY_INBOUND_TAG} not found")
        settings = inbound.get("settings") or {}
        if str(settings.get("decryption") or "none") != "none":
            raise ValueError("the Reality inbound uses VLESS encryption; the probe cannot derive client parameters")
        client = next(
            (row for row in settings.get("clients") or [] if isinstance(row, dict) and row.get("email") == REALITY_BACKHAUL_EMAIL),
            None,
        )
        if client is None or not client.get("id"):
            raise ValueError(f"backhaul client {REALITY_BACKHAUL_EMAIL} not found")
        stream = inbound.get("streamSettings") or {}
        reality = stream.get("realitySettings") or {}
        server_names = reality.get("serverNames") or []
        short_ids = reality.get("shortIds") or []
        private_key = str(reality.get("privateKey") or "")
        if not server_names or not isinstance(short_ids, list) or not short_ids or not private_key:
            raise ValueError("Reality settings lack serverNames, shortIds or privateKey")
        params = {
            "id": str(client["id"]),
            "flow": str(client.get("flow") or ""),
            "network": str(stream.get("network") or "raw"),
            "server_name": str(server_names[0]),
            "short_id": str(short_ids[0]),
        }
        if client_image is not None:
            public_key = str(self.config.reality_public_key or "").strip()
            if not public_key:
                raise ValueError("REALITY_PUBLIC_KEY_TRANSIT / REALITY_PUBLIC_KEY is not set; the probe cannot build a client")
            params["public_key"] = public_key
        return params

    def _reality_probe(self, context: ProbeContext) -> Evidence:
        try:
            params = self._reality_params(client_image=context.client_image)
        except ValueError as exc:
            return Evidence("reality-client", False, str(exc))
        socks_port = self.free_port()
        user = {"id": params["id"], "encryption": "none"}
        if params["flow"]:
            user["flow"] = params["flow"]
        client_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": False}}
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "127.0.0.1", "port": REALITY_PROBE_PORT, "users": [user]}]},
                    "streamSettings": {
                        "network": params["network"],
                        "security": "reality",
                        "realitySettings": {
                            "serverName": params["server_name"],
                            "fingerprint": "chrome",
                            "publicKey": params["public_key"],
                            "shortId": params["short_id"],
                            "spiderX": "/",
                        },
                    },
                }
            ],
        }
        return self._run_client(
            "reality-client",
            context.client_image,
            json.dumps(client_config),
            "/etc/xray/config.json",
            ["run", "-c", "/etc/xray/config.json"],
            socks_port,
        )

    def _hysteria_targets(self) -> list[dict[str, Any]]:
        targets: list[dict[str, Any]] = []
        for unit in self.units_for("hysteria"):
            source = self._mount(unit, "/etc/hysteria/server.yaml")
            if source is None:
                raise ValueError(f"{unit}: server config mount not found")
            try:
                server = _yaml_load(source)
            except (OSError, ValueError) as exc:
                raise ValueError(f"cannot read {source.name}: {exc}") from exc
            listen = str(server.get("listen") or "")
            host, _, port = listen.rpartition(":")
            if not port.isdigit():
                raise ValueError(f"{source.name}: unsupported listen value")
            host = host.strip("[]")
            if host in {"", "0.0.0.0", "::"}:
                host = "127.0.0.1"
            dial = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            obfs = server.get("obfs")
            if not isinstance(obfs, dict) or not obfs.get("type"):
                raise ValueError(f"{source.name}: no obfs block")
            tls = server.get("tls") if isinstance(server.get("tls"), dict) else {}
            sni = self.config.hysteria_server_name or _first_dns_san(Path(str(tls.get("cert") or "")))
            if not sni:
                raise ValueError(f"{source.name}: no SNI (set the Hysteria server name or a DNS SAN certificate)")
            targets.append({"unit": unit, "server": dial, "obfs": obfs, "sni": sni})
        if not targets:
            raise ValueError("no Hysteria units on this host")
        return targets

    def _hysteria_probes(self, context: ProbeContext) -> list[Evidence]:
        try:
            targets = self._hysteria_targets()
        except ValueError as exc:
            return [Evidence("hysteria-client", False, str(exc))]
        results: list[Evidence] = []
        for target in targets:
            socks_port = self.free_port()
            client_config = {
                "server": target["server"],
                "auth": self.config.hysteria_backhaul_token,
                "tls": {"sni": target["sni"], "insecure": False},
                "obfs": target["obfs"],
                "socks5": {"listen": f"127.0.0.1:{socks_port}"},
            }
            name = f"hysteria-client:{target['unit']}"
            evidence = self._run_client(
                "hysteria-client",
                context.client_image,
                json.dumps(client_config),
                "/etc/hysteria/client.yaml",
                ["client", "-c", "/etc/hysteria/client.yaml"],
                socks_port,
            )
            results.append(Evidence(name, evidence.ok, evidence.detail, evidence.at))
            if not evidence.ok:
                break
        return results
