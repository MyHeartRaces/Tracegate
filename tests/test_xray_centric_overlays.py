import json
from pathlib import Path

from tracegate.services.xray_centric import XrayCentricOverlayRenderContext, render_xray_centric_private_overlays


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def test_render_xray_centric_private_overlays_prefers_materialized_root(tmp_path: Path) -> None:
    source_root = tmp_path / "bundles"
    materialized_root = tmp_path / "materialized"
    overlay_root = tmp_path / "private-overlays"

    source_entry = {
        "inbounds": [{"tag": "api", "protocol": "dokodemo-door"}],
        "outbounds": [],
        "routing": {"rules": []},
    }
    source_transit = {
        "inbounds": [{"tag": "api", "protocol": "dokodemo-door"}],
        "outbounds": [],
        "routing": {"rules": []},
    }
    materialized_entry = {
        "inbounds": [
            {"tag": "api", "protocol": "dokodemo-door"},
        ],
        "outbounds": [{"tag": "to-transit", "protocol": "vless"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "to-transit"}]},
    }
    materialized_transit = {
        "inbounds": [{"tag": "api", "protocol": "dokodemo-door"}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "direct"}]},
    }

    _write(source_root / "base-entry" / "xray.json", source_entry)
    _write(source_root / "base-transit" / "xray.json", source_transit)
    _write(materialized_root / "base-entry" / "xray.json", materialized_entry)
    _write(materialized_root / "base-transit" / "xray.json", materialized_transit)

    ctx = XrayCentricOverlayRenderContext(
        source_root=source_root,
        materialized_root=materialized_root,
        overlay_root=overlay_root,
        bootstrap_auth="bootstrap-secret",
        decoy_dir="/srv/decoy",
        entry_finalmask={"udp": [{"type": "fragment", "settings": {"packets": "1-2"}}]},
        transit_ech_server_keys="transit-ech-key",
    )

    render_xray_centric_private_overlays(ctx)

    entry_overlay = json.loads((overlay_root / "entry" / "xray.json").read_text(encoding="utf-8"))
    transit_overlay = json.loads((overlay_root / "transit" / "xray.json").read_text(encoding="utf-8"))
    manifest = json.loads((overlay_root / ".tracegate-overlay-manifest.json").read_text(encoding="utf-8"))
    overlays = {row["role"]: row for row in manifest["overlays"]}

    entry_tags = [row.get("tag") for row in entry_overlay["inbounds"] if isinstance(row, dict)]
    assert "hy2-in" in entry_tags

    entry_hy2 = next(row for row in entry_overlay["inbounds"] if isinstance(row, dict) and row.get("tag") == "hy2-in")
    assert entry_hy2["streamSettings"]["hysteriaSettings"]["auth"] == "bootstrap-secret"
    assert entry_hy2["streamSettings"]["hysteriaSettings"]["masquerade"]["dir"] == "/srv/decoy"
    assert entry_hy2["streamSettings"]["tlsSettings"]["certificates"] == [
        {"certificateFile": "/etc/tracegate/tls/ws.crt", "keyFile": "/etc/tracegate/tls/ws.key"}
    ]
    assert entry_hy2["streamSettings"]["tlsSettings"]["alpn"] == ["h3"]
    assert entry_hy2["streamSettings"]["finalmask"] == {"udp": [{"type": "fragment", "settings": {"packets": "1-2"}}]}

    transit_hy2 = next(
        row for row in transit_overlay["inbounds"] if isinstance(row, dict) and row.get("tag") == "hy2-in"
    )
    assert transit_hy2["streamSettings"]["hysteriaSettings"]["auth"] == "bootstrap-secret"
    assert transit_hy2["streamSettings"]["tlsSettings"]["alpn"] == ["h3"]
    assert transit_hy2["streamSettings"]["tlsSettings"]["echServerKeys"] == "transit-ech-key"
    assert manifest["runtimeProfile"] == "xray-centric"
    assert overlays["ENTRY"]["sourcePath"] == str(materialized_root / "base-entry" / "xray.json")
    assert overlays["TRANSIT"]["sourcePath"] == str(materialized_root / "base-transit" / "xray.json")
    assert overlays["ENTRY"]["targetUnit"] == "tracegate-xray@entry"
    assert overlays["ENTRY"]["features"]["finalMaskEnabled"] is True
    assert overlays["TRANSIT"]["features"]["echEnabled"] is True


def test_render_xray_centric_private_overlays_falls_back_to_source_root(tmp_path: Path) -> None:
    source_root = tmp_path / "bundles"
    overlay_root = tmp_path / "private-overlays"

    base_entry = {
        "inbounds": [{"tag": "api", "protocol": "dokodemo-door"}],
        "outbounds": [],
        "routing": {"rules": []},
    }
    base_transit = {
        "inbounds": [{"tag": "api", "protocol": "dokodemo-door"}],
        "outbounds": [],
        "routing": {"rules": []},
    }
    _write(source_root / "base-entry" / "xray.json", base_entry)
    _write(source_root / "base-transit" / "xray.json", base_transit)

    ctx = XrayCentricOverlayRenderContext(
        source_root=source_root,
        materialized_root=None,
        overlay_root=overlay_root,
        bootstrap_auth="fallback-bootstrap",
        decoy_dir="/srv/decoy",
    )

    render_xray_centric_private_overlays(ctx)

    assert (overlay_root / "entry" / "xray.json").exists()
    assert (overlay_root / "transit" / "xray.json").exists()
    manifest = json.loads((overlay_root / ".tracegate-overlay-manifest.json").read_text(encoding="utf-8"))
    overlays = {row["role"]: row for row in manifest["overlays"]}
    assert overlays["ENTRY"]["sourcePath"] == str(source_root / "base-entry" / "xray.json")
    assert overlays["TRANSIT"]["sourcePath"] == str(source_root / "base-transit" / "xray.json")


def test_overlay_context_loads_private_hysteria_feature_files(tmp_path: Path) -> None:
    source_root = tmp_path / "bundles"
    overlay_root = tmp_path / "private-overlays"
    finalmask_path = tmp_path / "entry-finalmask.json"
    ech_path = tmp_path / "transit-ech.txt"

    finalmask_path.write_text('{"udp":[{"type":"sudoku","settings":{"pad":4}}]}\n', encoding="utf-8")
    ech_path.write_text("transit-ech-server-key\n", encoding="utf-8")

    ctx = XrayCentricOverlayRenderContext.from_environ(
        {
            "BUNDLE_SOURCE_ROOT": str(source_root),
            "BUNDLE_PRIVATE_OVERLAY_ROOT": str(overlay_root),
            "HYSTERIA_BOOTSTRAP_PASSWORD": "bootstrap-secret",
            "XRAY_HYSTERIA_FINALMASK_ENTRY_FILE": str(finalmask_path),
            "XRAY_HYSTERIA_ECH_SERVER_KEYS_TRANSIT_FILE": str(ech_path),
        }
    )

    assert ctx.entry_finalmask == {"udp": [{"type": "sudoku", "settings": {"pad": 4}}]}
    assert ctx.transit_ech_server_keys == "transit-ech-server-key"
