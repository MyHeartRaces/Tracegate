import json
from pathlib import Path

from tracegate.services.xray_centric import render_xray_centric_xray_config


def _load_bundle_xray(bundle_name: str) -> dict:
    root = Path(__file__).resolve().parents[1] / "bundles" / bundle_name / "xray.json"
    return json.loads(root.read_text(encoding="utf-8"))


def test_render_xray_centric_entry_keeps_xray_native_hysteria_inbound() -> None:
    rendered = render_xray_centric_xray_config(
        _load_bundle_xray("base-entry"),
        role="ENTRY",
        bootstrap_auth="entry-bootstrap",
    )

    tags = [str(row.get("tag") or "") for row in rendered["inbounds"] if isinstance(row, dict)]
    assert "hy2-in" in tags

    hy2_in = next(row for row in rendered["inbounds"] if isinstance(row, dict) and row.get("tag") == "hy2-in")
    assert hy2_in["protocol"] == "hysteria"
    assert hy2_in["listen"] == "0.0.0.0"
    assert hy2_in["port"] == 443
    assert hy2_in["settings"]["version"] == 2
    assert hy2_in["settings"]["clients"] == []
    assert hy2_in["streamSettings"]["security"] == "tls"
    assert hy2_in["streamSettings"]["tlsSettings"]["certificates"] == [
        {"certificateFile": "/etc/tracegate/tls/ws.crt", "keyFile": "/etc/tracegate/tls/ws.key"}
    ]
    assert hy2_in["streamSettings"]["tlsSettings"]["alpn"] == ["h3"]
    assert hy2_in["streamSettings"]["hysteriaSettings"]["auth"] == "entry-bootstrap"
    assert hy2_in["streamSettings"]["hysteriaSettings"]["masquerade"]["dir"] == "/var/www/decoy"

    hy2_rule = next(
        row
        for row in rendered["routing"]["rules"]
        if isinstance(row, dict) and row.get("inboundTag") == ["hy2-in"]
    )
    assert hy2_rule["outboundTag"] == "to-transit"


def test_render_xray_centric_transit_adds_direct_hysteria_rule() -> None:
    rendered = render_xray_centric_xray_config(
        _load_bundle_xray("base-transit"),
        role="TRANSIT",
        bootstrap_auth="transit-bootstrap",
    )

    hy2_in = next(row for row in rendered["inbounds"] if isinstance(row, dict) and row.get("tag") == "hy2-in")
    assert hy2_in["protocol"] == "hysteria"
    assert hy2_in["streamSettings"]["security"] == "tls"
    assert hy2_in["streamSettings"]["tlsSettings"]["alpn"] == ["h3"]
    assert hy2_in["streamSettings"]["hysteriaSettings"]["auth"] == "transit-bootstrap"

    hy2_rule = next(
        row
        for row in rendered["routing"]["rules"]
        if isinstance(row, dict) and row.get("inboundTag") == ["hy2-in"]
    )
    assert hy2_rule["outboundTag"] == "direct"


def test_render_xray_centric_replaces_existing_legacy_hysteria_inbound() -> None:
    rendered = render_xray_centric_xray_config(
        {
            "inbounds": [
                {
                    "tag": "hy2-in",
                    "protocol": "hysteria",
                    "settings": {"clients": []},
                    "streamSettings": {
                        "network": "hysteria",
                        "security": "none",
                        "hysteriaSettings": {"version": 2, "auth": "legacy"},
                    },
                }
            ],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": []},
        },
        role="TRANSIT",
        bootstrap_auth="fresh-bootstrap",
        decoy_dir="/srv/decoy",
        tls_cert_file="/etc/tracegate/tls/hy2.crt",
        tls_key_file="/etc/tracegate/tls/hy2.key",
        finalmask={"udp": [{"type": "sudoku", "settings": {"pad": 2}}]},
        ech_server_keys="ech-server-key",
    )

    hy2_in = next(row for row in rendered["inbounds"] if isinstance(row, dict) and row.get("tag") == "hy2-in")
    assert hy2_in["settings"]["version"] == 2
    assert hy2_in["streamSettings"]["security"] == "tls"
    assert hy2_in["streamSettings"]["tlsSettings"]["certificates"] == [
        {"certificateFile": "/etc/tracegate/tls/hy2.crt", "keyFile": "/etc/tracegate/tls/hy2.key"}
    ]
    assert hy2_in["streamSettings"]["tlsSettings"]["alpn"] == ["h3"]
    assert hy2_in["streamSettings"]["tlsSettings"]["echServerKeys"] == "ech-server-key"
    assert hy2_in["streamSettings"]["hysteriaSettings"]["auth"] == "fresh-bootstrap"
    assert hy2_in["streamSettings"]["hysteriaSettings"]["masquerade"]["dir"] == "/srv/decoy"
    assert hy2_in["streamSettings"]["finalmask"] == {"udp": [{"type": "sudoku", "settings": {"pad": 2}}]}
