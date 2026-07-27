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
        env=os.environ | {"TRACEGATE_IP": str(fake_ip), "TRACEGATE_TC": str(fake_tc)},
        check=True,
    )

    assert calls.read_text(encoding="utf-8") == "qdisc replace dev ens3 root fq\n"


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
