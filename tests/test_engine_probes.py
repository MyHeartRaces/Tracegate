from __future__ import annotations

import json
from pathlib import Path
import subprocess
from urllib.parse import parse_qs, urlsplit

import pytest

from tracegate.services.artifacts import ArtifactStore, load_registry
from tracegate.services.engine_probes import HostProber, ProbeConfig, parse_unit
from tracegate.services.engine_updates import ROLE_ENGINE_UNITS, ProbeContext

REPO_ROOT = Path(__file__).resolve().parents[1]
XRAY = "ghcr.io/xtls/xray-core"
HYSTERIA = "docker.io/tobyxdd/hysteria"
D_OLD = "sha256:" + "0" * 64
D_NEW = "sha256:" + "1" * 64
PRIVATE_KEY = "PRIVATE-KEY-MUST-NOT-LEAK"
BACKHAUL_TOKEN = "BACKHAUL-TOKEN-MUST-NOT-LEAK"


def _completed(argv, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=stderr)


class Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.inactive: set[str] = set()
        self.check_exit = 0
        self.containers: dict[str, str] = {}  # container name -> repo digest reference
        self.client_configs: list[dict] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if argv[:2] == ["systemctl", "is-active"]:
            return _completed(argv, 3 if argv[-1] in self.inactive else 0)
        if argv[:1] != ["docker"]:
            return _completed(argv, 1)
        args = argv[1:]
        if args[:2] == ["ps", "--no-trunc"]:
            return _completed(argv, 0, "".join(f"id-{name}\t{name}\n" for name in self.containers))
        if args[:1] == ["inspect"]:
            return _completed(argv, 0, f"img-{args[-1][3:]}\n")
        if args[:2] == ["image", "inspect"]:
            name = args[-1][4:]
            return _completed(argv, 0, json.dumps([self.containers[name]]))
        if args[:1] == ["run"] and "x25519" in args:
            raise AssertionError("the probe must never pass the private key to a command line")
        if args[:2] == ["run", "-d"]:
            mount = args[args.index("-v") + 1]
            source = mount.split(":")[0]
            self.client_configs.append(json.loads(Path(source).read_text(encoding="utf-8")))
            return _completed(argv, 0, "container-id\n")
        if args[:1] == ["run"]:
            return _completed(argv, self.check_exit, "", "config error line" if self.check_exit else "")
        if args[:2] == ["rm", "-f"]:
            return _completed(argv, 0)
        return _completed(argv, 1, stderr=f"unexpected {argv}")


@pytest.fixture()
def host(tmp_path: Path):
    state_root = tmp_path / "var-lib-tracegate"
    units_dir = tmp_path / "units"
    units_dir.mkdir()
    for unit in (REPO_ROOT / "deploy/systemd").glob("*.service"):
        text = unit.read_text(encoding="utf-8").replace("/var/lib/tracegate", str(state_root))
        text = text.replace("/etc/tracegate/prometheus", str(tmp_path / "etc-prometheus"))
        (units_dir / unit.name).write_text(text, encoding="utf-8")
    runtime = state_root / "agent-transit" / "runtime"
    (runtime / "xray").mkdir(parents=True)
    (runtime / "xray-ss2022").mkdir(parents=True)
    (runtime / "hysteria").mkdir(parents=True)
    (runtime / "xray" / "config.json").write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "tag": "vless-reality-in",
                        "settings": {
                            "clients": [
                                {"id": "user-uuid", "email": "someone-else"},
                                {"id": "backhaul-uuid", "email": "entry-transit", "flow": "xtls-rprx-vision"},
                            ],
                            "decryption": "none",
                        },
                        "streamSettings": {
                            "network": "raw",
                            "security": "reality",
                            "realitySettings": {
                                "serverNames": ["front.example.com", "other.example.com"],
                                "shortIds": ["abcd", "ef01"],
                                "privateKey": PRIVATE_KEY,
                            },
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (runtime / "xray-ss2022" / "config.json").write_text("{}", encoding="utf-8")
    for name, obfs in (("server.yaml", "gecko"), ("salamander-server.yaml", "salamander")):
        (runtime / "hysteria" / name).write_text(
            f"listen: \":443\"\ntls:\n  cert: /nonexistent.pem\nobfs:\n  type: {obfs}\n  {obfs}:\n    password: obfs-pass\n",
            encoding="utf-8",
        )
    (tmp_path / "etc-prometheus").mkdir()
    (tmp_path / "etc-prometheus" / "prometheus.yml").write_text("global: {}\n", encoding="utf-8")

    registry = load_registry(REPO_ROOT / "deploy/host/artifacts.json")
    runner = FakeRunner()
    store = ArtifactStore(tmp_path / "store", registry, runner=runner)
    clock = Clock()
    http_calls: list[tuple[str, dict]] = []
    http_responses: dict[str, object] = {}

    def http_get(url: str, headers: dict, timeout: float):
        http_calls.append((url, headers))
        for prefix, response in http_responses.items():
            if url.startswith(prefix):
                return response(url) if callable(response) else response
        raise ConnectionError("refused")

    socks_results: list[int] = []

    def socks_fetch(port: int, url: str, timeout: float) -> int:
        assert url == "https://www.gstatic.com/generate_204"
        return socks_results.pop(0) if socks_results else 204

    def make(role: str = "endpoint", **overrides) -> HostProber:
        values = {
            "role": role,
            "state_root": state_root,
            "units_dir": units_dir,
            "agent_token": "agent-token",
            "grafana_url": "http://127.0.0.1:3000",
            "hysteria_backhaul_token": BACKHAUL_TOKEN,
            "hysteria_server_name": "hy.example.com",
            "reality_public_key": "PUBLIC-KEY",
        }
        values.update(overrides)
        return HostProber(
            config=ProbeConfig(**values),
            store=store,
            runner=runner,
            units_for=lambda component: ROLE_ENGINE_UNITS[role].get(component, ()),
            http_get=http_get,
            socks_fetch=socks_fetch,
            free_port=lambda: 41000,
            now=clock.now,
            sleep=clock.sleep,
        )

    http_responses["http://127.0.0.1:8070/v1/health"] = (200, json.dumps({"overall_ok": True, "checks": []}).encode())
    return type(
        "Host",
        (),
        {
            "make": staticmethod(make),
            "runner": runner,
            "store": store,
            "clock": clock,
            "http_calls": http_calls,
            "http": http_responses,
            "socks": socks_results,
            "runtime": runtime,
            "root": tmp_path,
        },
    )


def _context(component: str, role: str = "endpoint", image: str = f"{XRAY}@{D_NEW}", digest: str = D_NEW, since: float = 0.0):
    units = ROLE_ENGINE_UNITS[role][component]
    return ProbeContext(
        component=component,
        units=units,
        expected_digests={unit: digest for unit in units},
        client_image=image,
        since=since,
        phase="test",
    )


def test_parse_tracked_units_for_container_names_and_config_mounts() -> None:
    xray = parse_unit((REPO_ROOT / "deploy/systemd/tracegate-xray@.service").read_text(), "transit")
    assert xray.container == "tracegate-xray-transit"
    assert xray.mounts["/etc/xray/config.json"] == "/var/lib/tracegate/agent-transit/runtime/xray/config.json"
    salamander = parse_unit((REPO_ROOT / "deploy/systemd/tracegate-hysteria-salamander.service").read_text(), None)
    assert salamander.container == "tracegate-hysteria-salamander-transit"
    assert salamander.mounts["/etc/hysteria/server.yaml"].endswith("/hysteria/salamander-server.yaml")
    fragment = parse_unit((REPO_ROOT / "deploy/systemd/tracegate-backhaul-fragment@.service").read_text(), "2")
    assert fragment.container == "tracegate-backhaul-fragment-2"


def test_xray_static_check_runs_each_live_config_offline_and_read_only(host) -> None:
    prober = host.make()
    result = prober.static_check("xray", f"{XRAY}@{D_NEW}", ROLE_ENGINE_UNITS["endpoint"]["xray"])
    assert result.status == "ok"
    runs = [call for call in host.runner.calls if call[:2] == ["docker", "run"]]
    assert len(runs) == 2
    for call in runs:
        assert call[call.index("--network") + 1] == "none"
        assert "--rm" in call and "--read-only" in call
        assert call[call.index("-v") + 1].endswith(":/etc/xray/config.json:ro")
        assert call[-4:] == ["run", "-test", "-c", "/etc/xray/config.json"]

    host.runner.check_exit = 23
    assert prober.static_check("xray", f"{XRAY}@{D_NEW}", ROLE_ENGINE_UNITS["endpoint"]["xray"]).status == "fail"
    host.runner.check_exit = 125
    assert prober.static_check("xray", f"{XRAY}@{D_NEW}", ROLE_ENGINE_UNITS["endpoint"]["xray"]).status == "error"
    host.runner.check_exit = 0
    (host.runtime / "xray-ss2022" / "config.json").unlink()
    assert prober.static_check("xray", f"{XRAY}@{D_NEW}", ROLE_ENGINE_UNITS["endpoint"]["xray"]).status == "error"


def test_prometheus_static_check_uses_promtool_and_others_record_no_check(host) -> None:
    prober = host.make()
    result = prober.static_check("prometheus", "prom/prometheus@" + D_NEW, ("tracegate-prometheus.service",))
    assert result.status == "ok"
    call = host.runner.calls[-1]
    assert call[call.index("--entrypoint") + 1] == "/bin/promtool"
    assert call[-3:] == ["check", "config", "/etc/prometheus/prometheus.yml"]
    other = prober.static_check("shadowtls", "x@" + D_NEW, ())
    assert other.status == "ok" and "no static check" in other.evidence[0].detail


def test_probe_plans_per_role(host) -> None:
    endpoint = host.make()
    assert endpoint.plan("xray").complete
    assert endpoint.plan("hysteria").complete
    assert endpoint.plan("shadowtls").complete
    assert endpoint.plan("prometheus").complete
    assert endpoint.plan("grafana").complete
    assert not endpoint.plan("telemt").complete
    assert not host.make(hysteria_backhaul_token="").plan("hysteria").complete
    assert "token" in host.make(hysteria_backhaul_token="").plan("hysteria").reason
    assert not host.make(hysteria_server_name="").plan("hysteria").complete  # no SNI and no readable certificate
    entry = host.make(role="entry")
    assert entry.plan("shadowtls").complete
    assert not host.make(role="entry", agent_token="").plan("shadowtls").complete
    for component in ("xray", "hysteria"):
        assert not entry.plan(component).complete
    (host.runtime / "xray" / "config.json").write_text("{}", encoding="utf-8")
    assert not endpoint.plan("xray").complete


def _running(host, component: str, image: str, digest: str, role: str = "endpoint") -> None:
    prober = host.make(role=role)
    for unit in ROLE_ENGINE_UNITS[role][component]:
        host.runner.containers[prober.unit_spec(unit).container] = f"{image}@{digest}"


def _backhaul_prometheus(fresh_at: float, success: float = 1):
    def respond(url: str):
        query = parse_qs(urlsplit(url).query)["query"][0]
        value = success if "success" in query else fresh_at
        result = [
            {"metric": {"channel": channel}, "value": [0, str(value)]}
            for channel in ("shadowtls-primary-a", "shadowtls-primary-b", "reality-fallback")
        ]
        return 200, json.dumps({"status": "success", "data": {"result": result}}).encode()

    return respond


def test_reality_probe_uses_backhaul_identity_and_never_leaks_the_private_key(host) -> None:
    _running(host, "xray", XRAY, D_NEW)
    since = host.clock.t
    host.http["http://127.0.0.1:9090/api/v1/query"] = _backhaul_prometheus(fresh_at=since + 5)
    prober = host.make()
    results = prober.probe(_context("xray", since=since))
    assert [item.name for item in results] == [
        "units-active",
        "container-digests",
        "agent-health",
        "reality-client",
        "backhaul-prometheus",
    ]
    assert all(item.ok for item in results), results
    config = host.runner.client_configs[0]
    outbound = config["outbounds"][0]
    user = outbound["settings"]["vnext"][0]["users"][0]
    assert user == {"id": "backhaul-uuid", "encryption": "none", "flow": "xtls-rprx-vision"}
    assert outbound["settings"]["vnext"][0]["address"] == "127.0.0.1"
    assert outbound["settings"]["vnext"][0]["port"] == 443
    reality = outbound["streamSettings"]["realitySettings"]
    assert reality == {
        "serverName": "front.example.com",
        "fingerprint": "chrome",
        "publicKey": "PUBLIC-KEY",
        "shortId": "abcd",
        "spiderX": "/",
    }
    assert config["inbounds"][0]["listen"] == "127.0.0.1"
    start = next(call for call in host.runner.calls if call[:3] == ["docker", "run", "-d"])
    assert f"{XRAY}@{D_NEW}" in start and "--network" in start and start[start.index("--network") + 1] == "host"
    assert ["docker", "rm", "-f"] == next(call for call in host.runner.calls if call[:2] == ["docker", "rm"])[:3]
    assert PRIVATE_KEY not in json.dumps([item.as_dict() for item in results])
    assert PRIVATE_KEY not in json.dumps(config)
    assert not any((host.store.root / "probe").iterdir())  # temporary configs removed
    sustained = results[3].detail
    assert "5 samples" in sustained and int(sustained.split("over ")[1].rstrip("s")) >= 10


def test_sustained_probe_fails_on_any_bad_sample(host) -> None:
    _running(host, "xray", XRAY, D_NEW)
    host.socks.extend([204, 204, 502])
    results = host.make().probe(_context("xray"))
    reality = next(item for item in results if item.name == "reality-client")
    assert not reality.ok and "HTTP 502" in reality.detail


def test_backhaul_results_must_be_newer_than_the_switch(host) -> None:
    _running(host, "shadowtls", "ghcr.io/ihciah/shadow-tls", D_NEW)
    since = host.clock.t
    host.http["http://127.0.0.1:9090/api/v1/query"] = _backhaul_prometheus(fresh_at=since - 1)
    results = host.make().probe(_context("shadowtls", image="x", since=since))
    assert not results[-1].ok and "not probed since the switch" in results[-1].detail

    host.http["http://127.0.0.1:9090/api/v1/query"] = _backhaul_prometheus(fresh_at=host.clock.t + 1000, success=0)
    results = host.make().probe(_context("shadowtls", image="x", since=host.clock.t))
    assert not results[-1].ok and "failing" in results[-1].detail


def test_entry_shadowtls_probe_reads_agent_metrics_with_token(host) -> None:
    _running(host, "shadowtls", "ghcr.io/ihciah/shadow-tls", D_NEW, role="entry")
    since = host.clock.t
    lines = []
    for channel, tag in (("shadowtls-primary-a", "to-transit-ss"), ("shadowtls-primary-b", "to-transit-ss2"), ("reality-fallback", "to-transit")):
        lines.append(f'tracegate_backhaul_egress_probe_success{{channel="{channel}",outbound_tag="{tag}"}} 1.0')
        lines.append(
            f'tracegate_backhaul_egress_probe_last_try_timestamp_seconds{{channel="{channel}",outbound_tag="{tag}"}} {since + 3}'
        )
    host.http["http://127.0.0.1:8070/metrics"] = (200, "\n".join(lines).encode())
    results = host.make(role="entry").probe(_context("shadowtls", role="entry", image="x", since=since))
    assert all(item.ok for item in results), results
    metrics_calls = [headers for url, headers in host.http_calls if url.endswith("/metrics")]
    assert metrics_calls and all(headers == {"X-Agent-Token": "agent-token"} for headers in metrics_calls)


def test_hysteria_probe_targets_each_listener_with_backhaul_token(host) -> None:
    _running(host, "hysteria", HYSTERIA, D_NEW)
    results = host.make().probe(_context("hysteria", image=f"{HYSTERIA}@{D_NEW}"))
    assert all(item.ok for item in results), results
    assert [item.name for item in results][-2:] == [
        "hysteria-client:tracegate-hysteria@transit.service",
        "hysteria-client:tracegate-hysteria-salamander.service",
    ]
    gecko, salamander = host.runner.client_configs
    assert gecko["server"] == "127.0.0.1:443"
    assert gecko["auth"] == BACKHAUL_TOKEN
    assert gecko["tls"] == {"sni": "hy.example.com", "insecure": False}
    assert gecko["obfs"]["type"] == "gecko" and salamander["obfs"]["type"] == "salamander"
    assert gecko["socks5"] == {"listen": "127.0.0.1:41000"}
    assert BACKHAUL_TOKEN not in json.dumps([item.as_dict() for item in results])


def test_common_probes_catch_inactive_units_wrong_digests_and_unhealthy_agent(host) -> None:
    _running(host, "prometheus", "prom/prometheus", D_OLD)
    host.http["http://127.0.0.1:9090/-/ready"] = (200, b"ok")
    results = host.make().probe(_context("prometheus", image="x"))
    digests = next(item for item in results if item.name == "container-digests")
    assert not digests.ok and "expected" in digests.detail

    _running(host, "prometheus", "prom/prometheus", D_NEW)
    host.runner.inactive.add("tracegate-prometheus.service")
    assert not host.make().probe(_context("prometheus", image="x"))[0].ok
    host.runner.inactive.clear()

    host.http["http://127.0.0.1:8070/v1/health"] = (
        503,
        json.dumps({"overall_ok": False, "checks": [{"name": "xray", "ok": False}]}).encode(),
    )
    results = host.make().probe(_context("prometheus", image="x"))
    health = next(item for item in results if item.name == "agent-health")
    assert not health.ok and "xray" in health.detail

    host.http["http://127.0.0.1:8070/v1/health"] = (200, json.dumps({"overall_ok": True}).encode())
    results = host.make().probe(_context("prometheus", image="x"))
    assert all(item.ok for item in results) and results[-1].name == "prometheus-ready"


def test_grafana_probe_requires_database_ok(host) -> None:
    _running(host, "grafana", "grafana/grafana", D_NEW)
    host.http["http://127.0.0.1:3000/api/health"] = (200, json.dumps({"database": "failing"}).encode())
    results = host.make().probe(_context("grafana", image="x"))
    assert not results[-1].ok and "database failing" in results[-1].detail
    host.http["http://127.0.0.1:3000/api/health"] = (200, json.dumps({"database": "ok"}).encode())
    assert all(item.ok for item in host.make().probe(_context("grafana", image="x")))


def test_probe_config_requires_a_sustained_window() -> None:
    with pytest.raises(ValueError):
        ProbeConfig(role="endpoint", sustain_samples=3, sustain_interval=2)



def test_reality_plan_is_incomplete_without_configured_public_key(host) -> None:
    plan = host.make(reality_public_key="").plan("xray")
    assert plan.complete is False
    assert "public key" in plan.reason
