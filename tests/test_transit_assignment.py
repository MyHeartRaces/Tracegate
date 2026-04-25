from tracegate.agent.transit_assignment import assign_sticky_transit_if_needed
from tracegate.settings import Settings


def test_assign_sticky_transit_uses_default_transit_for_new_v2_connection() -> None:
    settings = Settings(agent_role="ENTRY", default_transit_host="transit.example.com")
    payload = {
        "user_id": "u1",
        "connection_id": "c1",
        "revision_id": "r1",
        "protocol": "vless_reality",
        "variant": "V2",
        "config": {"uuid": "c1", "sni": "splitter.wb.ru"},
    }

    out = assign_sticky_transit_if_needed(settings, payload)

    assert out["config"]["transit"]["mode"] == "fixed"
    assert out["config"]["transit"]["scope"] == "connection"
    assert out["config"]["transit"]["selected_path"]["name"] == "transit"
    assert out["config"]["transit"]["selected_path"]["host"] == "transit.example.com"
    assert out["config"]["transit"]["selected_path"]["port"] == 443


def test_assign_sticky_transit_keeps_existing_path_without_overwrite() -> None:
    settings = Settings(agent_role="ENTRY", default_transit_host="transit.example.com")
    existing = {
        "config": {
            "transit": {
                "selected_path": {
                    "name": "manual",
                    "host": "manual.example.com",
                    "port": 443,
                }
            }
        }
    }
    payload = {
        "protocol": "vless_reality",
        "variant": "V2",
        "config": {"uuid": "c1", "sni": "splitter.wb.ru"},
    }

    out = assign_sticky_transit_if_needed(settings, payload, existing_payload=existing)

    assert out["config"]["transit"]["selected_path"]["name"] == "manual"
    assert out["config"]["transit"]["selected_path"]["host"] == "manual.example.com"
