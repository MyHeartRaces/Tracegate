from tracegate.models import IpamPool
from tracegate.services.ipam import iter_candidate_ips


def test_iter_candidate_ips_skips_gateway() -> None:
    pool = IpamPool(cidr="10.70.0.0/30", gateway="10.70.0.1", quarantine_seconds=30)
    ips = iter_candidate_ips(pool)
    assert "10.70.0.1" not in ips
    assert ips == ["10.70.0.2"]
