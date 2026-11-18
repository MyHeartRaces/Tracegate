from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from tracegate.enums import RecordStatus
from tracegate.services.revisions import active_reality_snis


def _rev(slot: int, sni: str | None, status: RecordStatus = RecordStatus.ACTIVE, age_s: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        slot=slot,
        status=status,
        effective_config_json={"sni": sni} if sni is not None else {},
        created_at=datetime(2026, 11, 18, tzinfo=timezone.utc) - timedelta(seconds=age_s),
    )


def test_active_reality_snis_lists_current_then_previous_active_revisions() -> None:
    revisions = [
        _rev(1, "www.old.example"),
        _rev(0, "new.example"),
        _rev(1, "revoked.example", status=RecordStatus.REVOKED),
    ]
    assert active_reality_snis("New.Example.", revisions) == ["new.example", "www.old.example"]


def test_active_reality_snis_deduplicates_and_skips_missing_values() -> None:
    revisions = [_rev(0, "same.example"), _rev(1, "same.example"), _rev(1, None)]
    assert active_reality_snis("same.example", revisions) == ["same.example"]
    assert active_reality_snis(None, []) == []
