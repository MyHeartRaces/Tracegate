from pathlib import Path

from scripts.check_host_deploy import check


def test_host_deployment_contract() -> None:
    check(Path(__file__).resolve().parents[1])
