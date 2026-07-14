from tracegate.agent import metrics
from tracegate.settings import Settings


def test_xray_user_traffic_merges_isolated_ss2022_stats(monkeypatch) -> None:
    targets: list[str] = []

    def _query(settings: Settings, *, reset: bool):
        assert reset is False
        targets.append(settings.agent_xray_api_server)
        if settings.agent_xray_api_server.endswith(":10086"):
            return {"V3 - 1 - ss": {"uplink": 30, "downlink": 40}}
        return {"V1 - 1 - reality": {"uplink": 10, "downlink": 20}}

    monkeypatch.setattr("tracegate.agent.xray_api.query_user_traffic_bytes", _query)
    settings = Settings(
        agent_role="TRANSIT",
        agent_xray_api_server="127.0.0.1:8080",
        agent_xray_ss2022_api_server="127.0.0.1:10086",
    )

    assert metrics._query_xray_user_traffic_bytes(settings) == {
        "V1 - 1 - reality": {"uplink": 10, "downlink": 20},
        "V3 - 1 - ss": {"uplink": 30, "downlink": 40},
    }
    assert targets == ["127.0.0.1:8080", "127.0.0.1:10086"]
