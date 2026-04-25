import sys
import types
from pathlib import Path

import pytest

# Importing tracegate.api.routers.dispatch executes routers package __init__, which imports metrics router.
_prom_stub = types.ModuleType("prometheus_client")
_prom_stub.CONTENT_TYPE_LATEST = "text/plain"
_prom_stub.generate_latest = lambda: b""
_orig_prometheus_client = sys.modules.get("prometheus_client")
sys.modules["prometheus_client"] = _prom_stub
try:
    from tracegate.api.routers import dispatch  # noqa: E402
    from tracegate.settings import Settings  # noqa: E402
finally:
    if _orig_prometheus_client is None:
        sys.modules.pop("prometheus_client", None)
    else:
        sys.modules["prometheus_client"] = _orig_prometheus_client


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def test_load_bundle_files_uses_repo_bundle_when_no_materialized_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "bundles"
    _write(repo_root / "base-transit" / "nftables.conf", "flush ruleset\n")
    _write(repo_root / "base-transit" / "xray.json", '{"log":"repo"}')

    monkeypatch.setattr(
        dispatch,
        "get_settings",
        lambda: Settings(bundle_root=str(repo_root), bundle_materialized_root=""),
    )

    files = dispatch._load_bundle_files("base-transit")

    assert files == {
        "nftables.conf": "flush ruleset\n",
        "xray.json": '{"log":"repo"}',
    }


def test_load_bundle_files_overlays_materialized_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "bundles"
    materialized_root = tmp_path / "materialized"
    _write(repo_root / "base-entry" / "nftables.conf", "repo-firewall\n")
    _write(repo_root / "base-entry" / "xray.json", '{"privateKey":"REPLACE_PRIVATE_KEY"}')
    _write(repo_root / "base-entry" / "haproxy.cfg", "frontend repo_entry\n  bind :443\n")

    _write(materialized_root / "base-entry" / "xray.json", '{"privateKey":"real-key"}')
    _write(materialized_root / "base-entry" / "haproxy.cfg", "frontend materialized_entry\n  bind :443\n")

    monkeypatch.setattr(
        dispatch,
        "get_settings",
        lambda: Settings(bundle_root=str(repo_root), bundle_materialized_root=str(materialized_root)),
    )

    files = dispatch._load_bundle_files("base-entry")

    assert files["nftables.conf"] == "repo-firewall\n"
    assert files["xray.json"] == '{"privateKey":"real-key"}'
    assert files["haproxy.cfg"] == "frontend materialized_entry\n  bind :443\n"


def test_load_bundle_files_overlays_proxy_materialized_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "bundles"
    materialized_root = tmp_path / "materialized"
    _write(repo_root / "base-entry" / "haproxy.cfg", "acl ws_tls_sni req.ssl_sni -i REPLACE_TLS_SERVER_NAME\n")
    _write(repo_root / "base-entry" / "nginx.conf", "server_name REPLACE_TLS_SERVER_NAME;\n")
    _write(materialized_root / "base-entry" / "haproxy.cfg", "acl ws_tls_sni req.ssl_sni -i entry.tracegate.test\n")
    _write(materialized_root / "base-entry" / "nginx.conf", "server_name entry.tracegate.test;\n")

    monkeypatch.setattr(
        dispatch,
        "get_settings",
        lambda: Settings(bundle_root=str(repo_root), bundle_materialized_root=str(materialized_root)),
    )

    files = dispatch._load_bundle_files("base-entry")

    assert files["haproxy.cfg"] == "acl ws_tls_sni req.ssl_sni -i entry.tracegate.test\n"
    assert files["nginx.conf"] == "server_name entry.tracegate.test;\n"


def test_load_bundle_files_ignores_missing_materialized_bundle_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo_root = tmp_path / "bundles"
    _write(repo_root / "base-transit" / "xray.json", '{"log":"repo"}')

    monkeypatch.setattr(
        dispatch,
        "get_settings",
        lambda: Settings(
            bundle_root=str(repo_root),
            bundle_materialized_root=str(tmp_path / "materialized"),
        ),
    )

    files = dispatch._load_bundle_files("base-transit")

    assert files == {"xray.json": '{"log":"repo"}'}


def test_load_bundle_files_base64_encodes_binary_assets(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "bundles"
    binary_payload = b"\xff\xd8\xfftracegate-jpeg"
    _write_bytes(repo_root / "base-transit" / "decoy" / "assets" / "great-wave.jpg", binary_payload)

    monkeypatch.setattr(
        dispatch,
        "get_settings",
        lambda: Settings(bundle_root=str(repo_root), bundle_materialized_root=""),
    )

    files = dispatch._load_bundle_files("base-transit")

    assert files["decoy/assets/great-wave.jpg"] == {
        "encoding": "base64",
        "content": "/9j/dHJhY2VnYXRlLWpwZWc=",
    }
