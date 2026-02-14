from __future__ import annotations


def test_xray_stats_query_uses_prefix_pattern(monkeypatch) -> None:
    """
    Xray QueryStatsRequest.pattern is a prefix, not a glob:
      - good: "user>>>"
      - bad:  "user>>>*>>>traffic>>>*"
    """
    from tracegate.agent import xray_api
    from tracegate.settings import Settings

    class _DummyChannel:
        def close(self) -> None:
            pass

    class _DummyResp:
        stat: list = []

    class _DummyStub:
        last_req = None
        last_timeout = None

        def QueryStats(self, req, timeout=None):  # noqa: ANN001, N802
            self.last_req = req
            self.last_timeout = timeout
            return _DummyResp()

    stub = _DummyStub()

    def _fake_stats_stub(_settings: Settings):  # noqa: ANN001
        return _DummyChannel(), stub

    monkeypatch.setattr(xray_api, "_stats_stub", _fake_stats_stub)

    xray_api.query_user_traffic_bytes(Settings(), reset=False)

    assert stub.last_req is not None
    assert stub.last_req.pattern == "user>>>"
    assert stub.last_req.reset is False

