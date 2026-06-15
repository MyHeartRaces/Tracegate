from pathlib import Path
import runpy

import pytest
import yaml


def _module() -> dict:
    return runpy.run_path("deploy/k3s/universal-entry-origin-firewall.py")


def _endpoint_backhaul_module() -> dict:
    return runpy.run_path("deploy/k3s/universal-entry-endpoint-backhaul-firewall.py")


def _values() -> dict:
    return {
        "architecture": {
            "universalEntry": {
                "enabled": True,
                "originFirewall": {
                    "required": True,
                    "denyDirectAccess": True,
                    "allowedSourceCidrs": ["173.245.48.0/20", "103.21.244.0/22"],
                },
            }
        },
        "interconnect": {
            "endpointBackhaul": {
                "enabled": True,
                "hysteria2": {
                    "enabled": True,
                    "endpointPort": 4443,
                    "allowedSources": ["8.8.4.4"],
                },
            }
        },
        "topology": {"servers": {"entry": {"publicIp": "8.8.4.4"}, "endpoint": {"publicIp": "9.9.9.9"}}},
        "gateway": {"roles": {"entry": {"ports": {"publicTcp": 443}}}},
    }


def test_universal_entry_origin_firewall_script_is_executable() -> None:
    path = Path("deploy/k3s/universal-entry-origin-firewall.py")

    assert path.stat().st_mode & 0o111
    assert "tracegate_universal_entry_origin" in path.read_text(encoding="utf-8")
    assert yaml.safe_load(Path("deploy/k3s/tracegate/values.yaml").read_text(encoding="utf-8"))["architecture"]["universalEntry"]["originFirewall"]["required"] is True

    endpoint_path = Path("deploy/k3s/universal-entry-endpoint-backhaul-firewall.py")
    assert endpoint_path.stat().st_mode & 0o111
    assert "tracegate_universal_entry_endpoint_backhaul" in endpoint_path.read_text(encoding="utf-8")


def test_universal_entry_origin_firewall_allows_cloudflare_then_rejects_direct() -> None:
    rendered = _module()["render"](_values())

    assert "ip daddr 8.8.4.4 tcp dport 443 ip saddr { 103.21.244.0/22, 173.245.48.0/20 } accept" in rendered
    assert "ip daddr 8.8.4.4 tcp dport 443 reject with tcp reset" in rendered


def test_universal_entry_origin_firewall_rejects_private_source_cidr() -> None:
    values = _values()
    values["architecture"]["universalEntry"]["originFirewall"]["allowedSourceCidrs"] = ["10.0.0.0/8"]

    with pytest.raises(SystemExit, match="public IPv4 CIDRs"):
        _module()["render"](values)


def test_universal_entry_endpoint_backhaul_firewall_allows_entry_then_rejects_other_udp() -> None:
    rendered = _endpoint_backhaul_module()["render"](_values())

    assert "ip daddr 9.9.9.9 udp dport 4443 ip saddr { 8.8.4.4 } accept" in rendered
    assert "ip daddr 9.9.9.9 udp dport 4443 reject with icmp type port-unreachable" in rendered
