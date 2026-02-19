from uuid import uuid4

from tracegate.enums import RecordStatus
from tracegate.models import WireguardPeer
from tracegate.services.revisions import _select_wireguard_peer_candidate


def _peer(*, device_id, lease_id) -> WireguardPeer:
    return WireguardPeer(
        id=uuid4(),
        user_id=1,
        device_id=device_id,
        peer_public_key=f"pk-{uuid4()}",
        lease_id=lease_id,
        preshared_key=None,
        allowed_ips=["0.0.0.0/0"],
        status=RecordStatus.REVOKED,
    )


def test_select_wireguard_peer_candidate_prefers_device_row_and_marks_stale() -> None:
    device_id = uuid4()
    lease_id = uuid4()
    device_row = _peer(device_id=device_id, lease_id=uuid4())
    lease_row = _peer(device_id=uuid4(), lease_id=lease_id)

    primary, stale = _select_wireguard_peer_candidate(
        [device_row, lease_row],
        device_id=device_id,
        lease_id=lease_id,
    )

    assert primary is device_row
    assert stale == [lease_row]


def test_select_wireguard_peer_candidate_falls_back_to_lease_row() -> None:
    device_id = uuid4()
    lease_id = uuid4()
    lease_row = _peer(device_id=uuid4(), lease_id=lease_id)

    primary, stale = _select_wireguard_peer_candidate(
        [lease_row],
        device_id=device_id,
        lease_id=lease_id,
    )

    assert primary is lease_row
    assert stale == []
