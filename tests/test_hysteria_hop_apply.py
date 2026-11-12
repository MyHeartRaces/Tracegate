"""tracegate-hysteria-hop-apply: renders and loads only the hop table, with a fake nft."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/host/tracegate-hysteria-hop-apply"


def _setup(tmp_path: Path, env_text: str, *, gecko_listen: str = '"192.0.2.20:443"',
           salamander_listen: str = "192.0.2.20:8444", nft_conf: str | None = "flush ruleset\n",
           nft_check_fails_for_conf: bool = False) -> tuple[dict[str, str], Path]:
    runtime = tmp_path / "runtime/hysteria"
    runtime.mkdir(parents=True)
    (runtime / "server.yaml").write_text(f"listen: {gecko_listen}\ntrafficStats:\n  listen: 127.0.0.1:9999\n")
    (runtime / "salamander-server.yaml").write_text(f"listen: {salamander_listen}\n")
    env_file = tmp_path / "tracegate.env"
    env_file.write_text(env_text)
    log = tmp_path / "nft.log"
    fake = tmp_path / "nft"
    conf = tmp_path / "nftables.conf"
    fail_line = f'[ "$1 $2 $3" = "-c -f {conf}" ] && exit 1\n' if nft_check_fails_for_conf else ""
    fake.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{log}"\n'
        f"{fail_line}"
        '[ "$1 $2 $3" = "list table inet" ] && exit 1\n'
        "exit 0\n"
    )
    fake.chmod(0o755)
    if nft_conf is not None:
        conf.write_text(nft_conf)
    env = os.environ | {
        "TRACEGATE_HYSTERIA_RUNTIME_DIR": str(runtime),
        "TRACEGATE_HYSTERIA_HOP_FILE": str(tmp_path / "hysteria-hop.nft"),
        "TRACEGATE_NFTABLES_CONF": str(conf),
        "TRACEGATE_NFT": str(fake),
    }
    return env, env_file


def _run(env: dict[str, str], env_file: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(SCRIPT), str(env_file)], env=env, capture_output=True, text=True)


def test_renders_address_bound_dnat_rules_and_persists(tmp_path: Path) -> None:
    env, env_file = _setup(
        tmp_path,
        "HYSTERIA_GECKO_HOP_PORTS=21000-23999\nexport HYSTERIA_SALAMANDER_HOP_PORTS=\"26000-28999\"\n",
    )
    result = _run(env, env_file)
    assert result.returncode == 0, result.stderr

    table = (tmp_path / "hysteria-hop.nft").read_text()
    assert "table inet tracegate_hysteria_hop {" in table
    assert "type nat hook prerouting priority dstnat; policy accept;" in table
    assert "ip daddr 192.0.2.20 udp dport 21000-23999 dnat ip to 192.0.2.20:443" in table
    assert "ip daddr 192.0.2.20 udp dport 26000-28999 dnat ip to 192.0.2.20:8444" in table
    assert oct((tmp_path / "hysteria-hop.nft").stat().st_mode & 0o777) == "0o600"

    calls = (tmp_path / "nft.log").read_text().splitlines()
    # Checked before loading; only the hop table is ever deleted or loaded.
    assert calls[0].startswith("-c -f ")
    assert any(call.startswith("-f ") for call in calls)
    assert not any("flush" in call for call in calls)
    assert all("delete" not in call or "tracegate_hysteria_hop" in call for call in calls)

    conf = (tmp_path / "nftables.conf").read_text()
    assert conf.count(f'include "{tmp_path / "hysteria-hop.nft"}"') == 1

    # Idempotent: a second run does not add a second include.
    assert _run(env, env_file).returncode == 0
    assert (tmp_path / "nftables.conf").read_text().count("hysteria-hop.nft") == 1


def test_wildcard_listener_uses_redirect_for_both_families(tmp_path: Path) -> None:
    env, env_file = _setup(tmp_path, "HYSTERIA_GECKO_HOP_PORTS=21000-23999\n", gecko_listen=":443")
    assert _run(env, env_file).returncode == 0
    table = (tmp_path / "hysteria-hop.nft").read_text()
    assert "meta nfproto ipv4 udp dport 21000-23999 redirect to :443" in table
    assert "meta nfproto ipv6 udp dport 21000-23999 redirect to :443" in table
    assert "8444" not in table


def test_empty_ranges_load_an_empty_table(tmp_path: Path) -> None:
    env, env_file = _setup(tmp_path, "HYSTERIA_GECKO_HOP_PORTS=\n")
    assert _run(env, env_file).returncode == 0
    table = (tmp_path / "hysteria-hop.nft").read_text()
    assert "dport" not in table


def test_invalid_range_is_refused_before_touching_nft(tmp_path: Path) -> None:
    env, env_file = _setup(tmp_path, "HYSTERIA_GECKO_HOP_PORTS=30000-20000\n")
    result = _run(env, env_file)
    assert result.returncode != 0
    assert "invalid hop range" in result.stderr
    assert not (tmp_path / "nft.log").exists()


def test_failed_persistence_check_restores_nftables_conf(tmp_path: Path) -> None:
    env, env_file = _setup(tmp_path, "HYSTERIA_GECKO_HOP_PORTS=21000-23999\n", nft_check_fails_for_conf=True)
    result = _run(env, env_file)
    assert result.returncode != 0
    assert (tmp_path / "nftables.conf").read_text() == "flush ruleset\n"
    # The live table was still loaded before persistence was attempted.
    assert (tmp_path / "hysteria-hop.nft").is_file()


def test_no_nftables_conf_skips_persistence(tmp_path: Path) -> None:
    env, env_file = _setup(tmp_path, "HYSTERIA_GECKO_HOP_PORTS=21000-23999\n", nft_conf=None)
    assert _run(env, env_file).returncode == 0
    assert not (tmp_path / "nftables.conf").exists()
