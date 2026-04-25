from __future__ import annotations

from dataclasses import dataclass

from tracegate.services.mtproto import MTPROTO_FAKE_TLS_PROFILE_NAME


class RuntimeContractError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeProcessCheck:
    name: str
    mode: str  # "all" | "any"
    process_names: tuple[str, ...]


@dataclass(frozen=True)
class AgentRuntimeContract:
    name: str
    aliases: tuple[str, ...]
    managed_components: tuple[str, ...]
    runtime_dirs: tuple[str, ...]
    hysteria_auth_mode: str
    hysteria_metrics_source: str | None
    expected_ports_entry: tuple[tuple[str, int, str], ...]
    expected_ports_transit: tuple[tuple[str, int, str], ...]
    process_checks_entry: tuple[RuntimeProcessCheck, ...]
    process_checks_transit: tuple[RuntimeProcessCheck, ...]
    transit_stats_provider: str | None = None
    xray_backhaul_allowed: bool = True
    client_profiles: tuple[str, ...] = ()
    local_socks_auth_required: bool = True
    allow_anonymous_local_socks: bool = False

    def manages_component(self, component: str) -> bool:
        return str(component or "").strip() in set(self.managed_components)

    def expected_ports(self, role: str) -> tuple[tuple[str, int, str], ...]:
        return self.expected_ports_entry if str(role or "").strip().upper() == "ENTRY" else self.expected_ports_transit

    def process_checks(self, role: str) -> tuple[RuntimeProcessCheck, ...]:
        return self.process_checks_entry if str(role or "").strip().upper() == "ENTRY" else self.process_checks_transit

    def requires_transit_stats_secret(self, role: str) -> bool:
        return str(role or "").strip().upper() == "TRANSIT" and self.transit_stats_provider is not None


XRAY_CENTRIC_CLIENT_PROFILES = (
    "V1-VLESS-Reality-Direct",
    "V1-VLESS-gRPC-TLS-Direct",
    "V1-VLESS-WS-TLS-Direct",
    "V2-VLESS-Reality-Chain",
    "V3-Hysteria2-QUIC-Direct",
    "V4-Hysteria2-QUIC-Chain",
    "V5-Shadowsocks2022-ShadowTLS-Direct",
    "V6-Shadowsocks2022-ShadowTLS-Chain",
    "V7-WireGuard-WSTunnel-Direct",
    MTPROTO_FAKE_TLS_PROFILE_NAME,
)

TRACEGATE21_CLIENT_PROFILES = (
    "V1-VLESS-Reality-Direct",
    "V1-VLESS-gRPC-TLS-Direct",
    "V1-VLESS-WS-TLS-Direct",
    "V2-VLESS-Reality-Chain",
    "V3-Hysteria2-QUIC-Direct",
    "V4-Hysteria2-QUIC-Chain",
    "V5-Shadowsocks2022-ShadowTLS-Direct",
    "V6-Shadowsocks2022-ShadowTLS-Chain",
    "V7-WireGuard-WSTunnel-Direct",
    MTPROTO_FAKE_TLS_PROFILE_NAME,
)


_XRAY_CENTRIC_CONTRACT = AgentRuntimeContract(
    name="xray-centric",
    aliases=("default", "xray-unified", "split", "xray-hysteria"),
    managed_components=("xray", "haproxy", "nginx"),
    runtime_dirs=("xray", "haproxy", "nginx", "xray-v2"),
    hysteria_auth_mode="token",
    hysteria_metrics_source="xray_stats",
    expected_ports_entry=(("tcp", 443, "listen tcp/443"), ("udp", 443, "listen udp/443")),
    expected_ports_transit=(("tcp", 443, "listen tcp/443"), ("udp", 443, "listen udp/443")),
    process_checks_entry=(
        RuntimeProcessCheck(name="process xray", mode="all", process_names=("xray",)),
        RuntimeProcessCheck(name="process haproxy", mode="all", process_names=("haproxy",)),
    ),
    process_checks_transit=(
        RuntimeProcessCheck(name="process xray", mode="all", process_names=("xray",)),
        RuntimeProcessCheck(name="process haproxy", mode="all", process_names=("haproxy",)),
    ),
    transit_stats_provider=None,
    client_profiles=XRAY_CENTRIC_CLIENT_PROFILES,
)


_TRACEGATE21_CONTRACT = AgentRuntimeContract(
    name="tracegate-2.1",
    aliases=("tracegate2.1", "k3s", "helm"),
    managed_components=("xray", "haproxy", "nginx"),
    runtime_dirs=("xray", "haproxy", "nginx", "xray-v2"),
    hysteria_auth_mode="token",
    hysteria_metrics_source="xray_stats",
    expected_ports_entry=(("tcp", 443, "listen tcp/443"), ("udp", 443, "listen udp/443")),
    expected_ports_transit=(("tcp", 443, "listen tcp/443"), ("udp", 443, "listen udp/443")),
    process_checks_entry=(
        RuntimeProcessCheck(name="process xray", mode="all", process_names=("xray",)),
        RuntimeProcessCheck(name="process haproxy", mode="all", process_names=("haproxy",)),
    ),
    process_checks_transit=(
        RuntimeProcessCheck(name="process xray", mode="all", process_names=("xray",)),
        RuntimeProcessCheck(name="process haproxy", mode="all", process_names=("haproxy",)),
    ),
    transit_stats_provider=None,
    xray_backhaul_allowed=False,
    client_profiles=TRACEGATE21_CLIENT_PROFILES,
)


_CONTRACTS: dict[str, AgentRuntimeContract] = {
    _XRAY_CENTRIC_CONTRACT.name: _XRAY_CENTRIC_CONTRACT,
    _TRACEGATE21_CONTRACT.name: _TRACEGATE21_CONTRACT,
}
_PROFILE_ALIASES: dict[str, str] = {}
for _contract in _CONTRACTS.values():
    _PROFILE_ALIASES[_contract.name] = _contract.name
    for _alias in _contract.aliases:
        _PROFILE_ALIASES[_alias] = _contract.name


def normalize_runtime_profile_name(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return _XRAY_CENTRIC_CONTRACT.name
    if raw in _PROFILE_ALIASES:
        return _PROFILE_ALIASES[raw]
    raise RuntimeContractError(f"unsupported runtime profile: {raw}")


def resolve_runtime_contract(profile_name: str | None) -> AgentRuntimeContract:
    return _CONTRACTS[normalize_runtime_profile_name(profile_name)]
