"""Bridge render invariance characterization test.

Renders the materialized bundles for both roles with representative synthetic
settings and extracts every bridge-relevant artifact (Entry->Endpoint
SS2022+ShadowTLS backhaul pool, Telemt link, REALITY backhaul leg, bridge
units and env helpers). The extracted JSON is compared against a golden file
generated from the pre-change code; it must keep passing unchanged while the
client-facing WGWS and SS2022-ShadowTLS families are removed.
"""

from __future__ import annotations

import json
from pathlib import Path

from tracegate.services.materialized_bundles import (
    MaterializedBundleRenderContext,
    render_materialized_bundles,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_PATH = Path(__file__).resolve().parent / "fixtures" / "bridge_render_golden.json"

_BRIDGE_UNIT_FILES = (
    "tracegate-xray-ss2022.service",
    "tracegate-shadowtls-backhaul.service",
    "tracegate-shadowtls-backhaul2.service",
    "tracegate-shadowtls-entry.service",
    "tracegate-shadowtls-entry2.service",
    "tracegate-backhaul-fragment@.service",
)

_BRIDGE_ENV_HELPERS = (
    "tracegate-shadowtls-backhaul-env",
    "tracegate-shadowtls-backhaul2-env",
    "tracegate-shadowtls-entry-env",
    "tracegate-shadowtls-entry2-env",
    "tracegate-backhaul-fragment-config",
)


def _base_env(tmp_path: Path) -> dict[str, str]:
    return {
        "BUNDLE_SOURCE_ROOT": str(REPO_ROOT / "bundles"),
        "BUNDLE_MATERIALIZED_ROOT": str(tmp_path / "materialized"),
        "DEFAULT_ENTRY_HOST": "entry.tracegate.test",
        "DEFAULT_TRANSIT_HOST": "transit.tracegate.test",
        "VLESS_WS_PATH": "/stealth/ws",
        "HYSTERIA_BOOTSTRAP_PASSWORD": "bootstrap-secret",
        "HYSTERIA_GECKO_PASSWORD_ENTRY": "entry-gecko-secret",
        "HYSTERIA_GECKO_PASSWORD_TRANSIT": "transit-gecko-secret",
        "HYSTERIA_STATS_SECRET_ENTRY": "entry-stats-secret",
        "HYSTERIA_STATS_SECRET_TRANSIT": "transit-stats-secret",
        "HYSTERIA_LISTEN_HOST_ENTRY": "192.0.2.10",
        "HYSTERIA_LISTEN_HOST_TRANSIT": "192.0.2.20",
        "HYSTERIA_TLS_CERT_FILE_ENTRY": "/etc/tls/entry.crt",
        "HYSTERIA_TLS_KEY_FILE_ENTRY": "/etc/tls/entry.key",
        "HYSTERIA_TLS_CERT_FILE_TRANSIT": "/etc/tls/transit.crt",
        "HYSTERIA_TLS_KEY_FILE_TRANSIT": "/etc/tls/transit.key",
        "REALITY_PUBLIC_KEY_TRANSIT": "transit-public-key",
        "REALITY_SHORT_ID_ENTRY": "entry-short-id",
        "REALITY_SHORT_ID_TRANSIT": "transit-short-id",
        "REALITY_PRIVATE_KEY_ENTRY": "entry-private-key",
        "REALITY_PRIVATE_KEY_TRANSIT": "transit-private-key",
        "REALITY_DEST_ENTRY": "origin-entry.example:443",
        "REALITY_DEST_TRANSIT": "origin-transit.example:443",
        "ENTRY_TLS_SERVER_NAME": "tls-entry.example",
        "TRANSIT_TLS_SERVER_NAME": "tls-transit.example",
        "GRAFANA_PUBLIC_BASE_URL": "https://grafana.tracegate.test",
        "SHADOWTLS_SERVER_NAME_TRANSIT": "shadowtls.example",
        "SHADOWSOCKS2022_PASSWORD_TRANSIT": "ss2022-server-key",
        "SHADOWSOCKS2022_BACKHAUL_KEY": "backhaul-256-key",
        "SHADOWTLS_BACKHAUL2_SNI": "leg2-front.example",
        "REALITY_BACKHAUL_SNI": "backhaul-front.example",
        "MTPROTO_DOMAIN": "proxied.tracegate.test",
        "MTPROTO_DIRECT_BACKUP_HOST": "192.0.2.30",
        "XRAY_CENTRIC_DECOY_DIR": "/srv/decoy",
    }


def _rules_without_ss2022_in(payload: dict) -> list:
    rules = []
    for rule in payload.get("routing", {}).get("rules", []):
        if not isinstance(rule, dict):
            rules.append(rule)
            continue
        inbound_tags = rule.get("inboundTag")
        if not isinstance(inbound_tags, list):
            rules.append(rule)
            continue
        remaining = [tag for tag in inbound_tags if tag != "ss2022-in"]
        if not remaining:
            continue
        rule = dict(rule)
        rule["inboundTag"] = remaining
        rules.append(rule)
    return rules


def _entry_mtproto_haproxy_section(haproxy: str) -> list[str]:
    lines = haproxy.splitlines()
    section: list[str] = []
    in_backend = False
    for line in lines:
        if line.startswith("backend be_mtproto_tls"):
            in_backend = True
        elif in_backend and line.startswith("backend "):
            in_backend = False
        if "mtproto" in line or in_backend:
            section.append(line)
    return section


def _transit_link_nftables_block(nftables: str) -> list[str]:
    lines = nftables.splitlines()
    block: list[str] = []
    in_block = False
    for line in lines:
        if "# BEGIN tracegate-managed-entry-link-firewall" in line:
            in_block = True
        if in_block:
            block.append(line)
        if "# END tracegate-managed-entry-link-firewall" in line:
            in_block = False
    return block


def extract_bridge_render(tmp_path: Path) -> dict:
    ctx = MaterializedBundleRenderContext.from_environ(_base_env(tmp_path))
    render_materialized_bundles(ctx)

    transit_ss2022 = json.loads(
        (ctx.materialized_root / "base-transit" / "xray-ss2022.json").read_text(encoding="utf-8")
    )
    entry_xray = json.loads((ctx.materialized_root / "base-entry" / "xray.json").read_text(encoding="utf-8"))
    entry_haproxy = (ctx.materialized_root / "base-entry" / "haproxy.cfg").read_text(encoding="utf-8")
    transit_haproxy = (ctx.materialized_root / "base-transit" / "haproxy.cfg").read_text(encoding="utf-8")
    transit_nftables = (ctx.materialized_root / "base-transit" / "nftables.conf").read_text(encoding="utf-8")

    transit_inbounds = {
        str(inbound.get("tag")): inbound
        for inbound in transit_ss2022.get("inbounds", [])
        if isinstance(inbound, dict)
    }
    fe_reality_backhaul = transit_haproxy[transit_haproxy.index("frontend fe_transit_reality_backhaul") :]

    extracted = {
        "transit_xray_ss2022": {
            "api_inbound": transit_inbounds["api"],
            "ss2022_backhaul_in_inbound": transit_inbounds["ss2022-backhaul-in"],
            "outbounds": transit_ss2022.get("outbounds", []),
            "routing_rules": _rules_without_ss2022_in(transit_ss2022),
        },
        "entry_xray": entry_xray,
        "entry_haproxy_mtproto_section": _entry_mtproto_haproxy_section(entry_haproxy),
        "transit_haproxy_fe_reality_backhaul": fe_reality_backhaul,
        "transit_nftables_link_block": _transit_link_nftables_block(transit_nftables),
        "bridge_unit_files": {
            name: (REPO_ROOT / "deploy" / "systemd" / name).read_text(encoding="utf-8")
            for name in _BRIDGE_UNIT_FILES
        },
        "bridge_env_helpers": {
            name: (REPO_ROOT / "deploy" / "systemd" / name).read_text(encoding="utf-8")
            for name in _BRIDGE_ENV_HELPERS
        },
    }
    return extracted


def test_bridge_render_invariance(tmp_path: Path) -> None:
    extracted = extract_bridge_render(tmp_path)

    assert GOLDEN_PATH.exists(), f"golden file is missing: {GOLDEN_PATH}"
    golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    assert extracted == golden
