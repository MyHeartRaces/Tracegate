import os
import subprocess
import sys
from pathlib import Path

from scripts.check_host_runtime import check_host_runtime


def test_tracked_host_runtime_contract_is_complete() -> None:
    check_host_runtime(Path(__file__).resolve().parents[1])


def test_host_release_preserves_quic_socket_buffer_tuning() -> None:
    root = Path(__file__).resolve().parents[1]
    profile = (root / "deploy/host/90-tracegate-quic.conf").read_text(encoding="utf-8")
    assert profile.count("= 16777216") == 4

    installer = (root / "deploy/host/tracegate-host-install").read_text(encoding="utf-8")
    assert '"${SYSCTL}" -p "${SYSCTL_DIR}/90-tracegate-quic.conf"' in installer
    assert "tracegate-network-qdisc.service" in installer


def test_host_runtime_reapplies_fq_after_the_default_interface_exists() -> None:
    root = Path(__file__).resolve().parents[1]
    helper = (root / "deploy/host/tracegate-network-qdisc").read_text(encoding="utf-8")
    unit = (root / "deploy/systemd/tracegate-network-qdisc.service").read_text(encoding="utf-8")

    assert 'qdisc replace dev "${interface}" root fq' in helper
    assert "After=network-online.target" in unit
    assert "WantedBy=multi-user.target" in unit


def test_host_qdisc_helper_detects_the_default_route_interface(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    fake_ip = tmp_path / "ip"
    fake_tc = tmp_path / "tc"
    calls = tmp_path / "tc.calls"
    fake_ip.write_text(
        "#!/bin/sh\n"
        'if [ "$1 $2 $3" = "-o route show" ]; then echo "default via 192.0.2.1 dev ens3"; exit 0; fi\n'
        'if [ "$1 $2 $3" = "link show dev" ] && [ "$4" = ens3 ]; then exit 0; fi\n'
        "exit 2\n",
        encoding="utf-8",
    )
    fake_tc.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {calls}\n", encoding="utf-8")
    fake_ip.chmod(0o755)
    fake_tc.chmod(0o755)

    subprocess.run(
        [str(root / "deploy/host/tracegate-network-qdisc")],
        env=os.environ
        | {
            "TRACEGATE_IP": str(fake_ip),
            "TRACEGATE_TC": str(fake_tc),
            "TRACEGATE_DEPLOY_ENV": str(tmp_path / "absent.env"),
        },
        check=True,
    )

    assert calls.read_text(encoding="utf-8") == "qdisc replace dev ens3 root fq\n"


def _run_qdisc(
    tmp_path: Path, deploy_env: str, entry_env: str | None = None, root_qdisc: str = ""
) -> tuple[subprocess.CompletedProcess, list[str]]:
    root = Path(__file__).resolve().parents[1]
    fake_ip = tmp_path / "ip"
    fake_tc = tmp_path / "tc"
    calls = tmp_path / "tc.calls"
    fake_ip.write_text(
        "#!/bin/sh\n"
        'if [ "$1 $2 $3" = "-o route show" ]; then echo "default via 192.0.2.1 dev ens3"; exit 0; fi\n'
        'if [ "$1 $2 $3" = "link show dev" ]; then exit 0; fi\n'
        "exit 2\n",
        encoding="utf-8",
    )
    # Behaves like the kernel: "qdisc show ... root" prints the current root, and
    # replacing an existing htb 1: root is a "change", which HTB does not support.
    state = tmp_path / "root.qdisc"
    state.write_text(root_qdisc, encoding="utf-8")
    fake_tc.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {calls}\n"
        f'if [ "$1 $2" = "qdisc show" ]; then cat {state}; exit 0; fi\n'
        'case "$*" in "qdisc replace dev ens3 root handle 1: htb"*)\n'
        f"  if grep -q '^qdisc htb 1: root' {state}; then\n"
        '    echo "Error: Change operation not supported by specified qdisc." >&2; exit 2; fi;;\n'
        "esac\n",
        encoding="utf-8",
    )
    fake_ip.chmod(0o755)
    fake_tc.chmod(0o755)
    deploy = tmp_path / "deploy.env"
    deploy.write_text(deploy_env, encoding="utf-8")
    entry = tmp_path / "entry.env"
    entry.write_text(entry_env or "", encoding="utf-8")
    result = subprocess.run(
        [str(root / "deploy/host/tracegate-network-qdisc")],
        env={
            "PATH": os.environ["PATH"],
            "TRACEGATE_IP": str(fake_ip),
            "TRACEGATE_TC": str(fake_tc),
            "TRACEGATE_DEPLOY_ENV": str(deploy),
            "TRACEGATE_ENTRY_RUNTIME_ENV": str(entry),
        },
        check=False,
        capture_output=True,
        text=True,
    )
    lines = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return result, lines


def test_entry_qdisc_applies_the_host_wide_cap_by_default(tmp_path: Path) -> None:
    result, lines = _run_qdisc(tmp_path, "TRACEGATE_HOST_ROLE=entry\n")

    assert result.returncode == 0, result.stderr
    assert lines == [
        "qdisc show dev ens3 root",
        "qdisc replace dev ens3 root handle 1: htb default 10",
        "class replace dev ens3 parent 1: classid 1:10 htb rate 65mbit ceil 65mbit burst 64k cburst 64k quantum 60000",
        "qdisc replace dev ens3 parent 1:10 handle 10: fq",
        "qdisc del dev ens3 ingress",
        "qdisc add dev ens3 handle ffff: ingress",
        "filter add dev ens3 parent ffff: protocol all prio 1 matchall action police rate 65mbit burst 1024000 conform-exceed drop",
    ]
    assert "cap 65 Mbit/s (tx=1 rx=1)" in result.stdout


def test_entry_qdisc_reads_rate_interface_and_directions_from_the_entry_env(tmp_path: Path) -> None:
    result, lines = _run_qdisc(
        tmp_path,
        "TRACEGATE_HOST_ROLE=entry\n",
        "AGENT_ENTRY_TRAFFIC_SHAPING_MAX_MBIT=40\n"
        "AGENT_ENTRY_TRAFFIC_SHAPING_INTERFACE=eth9\n"
        "AGENT_ENTRY_TRAFFIC_SHAPING_APPLY_INGRESS_POLICING=false\n",
    )

    assert result.returncode == 0, result.stderr
    assert lines[:2] == ["qdisc show dev eth9 root", "qdisc replace dev eth9 root handle 1: htb default 10"]
    assert "rate 40mbit ceil 40mbit" in lines[2]
    assert lines[-1] == "qdisc del dev eth9 ingress"
    assert not any("police" in line for line in lines)


def test_entry_qdisc_disabled_falls_back_to_fq_and_removes_the_policer(tmp_path: Path) -> None:
    result, lines = _run_qdisc(tmp_path, "TRACEGATE_HOST_ROLE=entry\n", "AGENT_ENTRY_TRAFFIC_SHAPING_ENABLED=false\n")

    assert result.returncode == 0, result.stderr
    assert lines == ["qdisc replace dev ens3 root fq", "qdisc del dev ens3 ingress"]


def test_endpoint_qdisc_is_never_shaped(tmp_path: Path) -> None:
    result, lines = _run_qdisc(
        tmp_path, "TRACEGATE_HOST_ROLE=endpoint\n", "AGENT_ENTRY_TRAFFIC_SHAPING_MAX_MBIT=40\n"
    )

    assert result.returncode == 0, result.stderr
    assert lines == ["qdisc replace dev ens3 root fq"]


def test_entry_qdisc_rejects_an_invalid_rate(tmp_path: Path) -> None:
    result, lines = _run_qdisc(tmp_path, "TRACEGATE_HOST_ROLE=entry\n", "AGENT_ENTRY_TRAFFIC_SHAPING_MAX_MBIT=fast\n")

    assert result.returncode == 2
    assert "invalid AGENT_ENTRY_TRAFFIC_SHAPING_MAX_MBIT" in result.stderr
    assert lines == []


def test_installer_creates_venv_at_final_release_path() -> None:
    root = Path(__file__).resolve().parents[1]
    installer = (root / "deploy/host/tracegate-host-install").read_text(encoding="utf-8")
    assert '"${PYTHON}" -m venv "${venv}"' in installer
    assert '"${PYTHON}" -m venv "${temporary}/venv"' not in installer


def test_host_runtime_check_cli_succeeds() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "scripts/check_host_runtime.py"), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "host runtime check passed" in result.stdout


_HTB_ROOT = "qdisc htb 1: root refcnt 2 r2q 10 default 0x10 direct_packets_stat 0 direct_qlen 1000\n"


def test_entry_qdisc_rerun_keeps_an_existing_matching_htb_root(tmp_path: Path) -> None:
    # Regression: the 4.1.4 Entry deploy failed because every run after the
    # first tried "qdisc replace" on the existing htb 1: root.
    result, lines = _run_qdisc(tmp_path, "TRACEGATE_HOST_ROLE=entry\n", root_qdisc=_HTB_ROOT)

    assert result.returncode == 0, result.stderr
    assert not any(line.startswith("qdisc replace dev ens3 root") for line in lines)
    assert "class replace dev ens3 parent 1: classid 1:10 htb rate 65mbit ceil 65mbit burst 64k cburst 64k quantum 60000" in lines
    assert "cap 65 Mbit/s (tx=1 rx=1)" in result.stdout


def test_entry_qdisc_recreates_an_htb_root_with_other_parameters(tmp_path: Path) -> None:
    other = "qdisc htb 1: root refcnt 2 r2q 10 default 0x20 direct_packets_stat 0\n"
    result, lines = _run_qdisc(tmp_path, "TRACEGATE_HOST_ROLE=entry\n", root_qdisc=other)

    assert result.returncode == 0, result.stderr
    assert lines[1:3] == ["qdisc del dev ens3 root", "qdisc add dev ens3 root handle 1: htb default 10"]


def test_entry_qdisc_disable_after_shaping_returns_to_fq(tmp_path: Path) -> None:
    result, lines = _run_qdisc(
        tmp_path,
        "TRACEGATE_HOST_ROLE=entry\n",
        "AGENT_ENTRY_TRAFFIC_SHAPING_ENABLED=false\n",
        root_qdisc=_HTB_ROOT,
    )

    assert result.returncode == 0, result.stderr
    assert lines == ["qdisc replace dev ens3 root fq", "qdisc del dev ens3 ingress"]
