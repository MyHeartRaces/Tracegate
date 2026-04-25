from tracegate.settings import (
    Settings,
    effective_mtproto_issued_state_file,
    effective_mtproto_public_profile_file,
    effective_private_runtime_root,
)


def test_settings_accept_new_entry_transit_field_names() -> None:
    settings = Settings(
        default_entry_host="entry.tracegate.test",
        default_transit_host="transit.tracegate.test",
        agent_runtime_profile="xray-hysteria",
        reality_public_key_entry="entry-pbk",
        reality_short_id_entry="entry-sid",
        reality_public_key_transit="transit-pbk",
        reality_short_id_transit="transit-sid",
        agent_entry_v2_split_backend_enabled=True,
        mtproto_domain="proxied.tracegate.test",
        mtproto_fronting_mode="dedicated-dns-only",
        mtproto_public_profile_file="/var/lib/tracegate/private/mtproto/public-profile.json",
        agent_reload_fronting_cmd="reload-fronting",
        transit_decoy_auth_login="operator",
        transit_decoy_auth_password="secret-pass",
        fronting_touch_udp_443=False,
    )

    assert settings.default_entry_host == "entry.tracegate.test"
    assert settings.default_transit_host == "transit.tracegate.test"
    assert settings.agent_runtime_profile == "xray-centric"
    assert settings.reality_public_key_entry == "entry-pbk"
    assert settings.reality_short_id_entry == "entry-sid"
    assert settings.reality_public_key_transit == "transit-pbk"
    assert settings.reality_short_id_transit == "transit-sid"
    assert settings.agent_entry_v2_split_backend_enabled is True
    assert settings.mtproto_domain == "proxied.tracegate.test"
    assert settings.mtproto_fronting_mode == "dedicated-dns-only"
    assert settings.mtproto_public_profile_file == "/var/lib/tracegate/private/mtproto/public-profile.json"
    assert settings.agent_reload_fronting_cmd == "reload-fronting"
    assert settings.transit_decoy_auth_login == "operator"
    assert settings.transit_decoy_auth_password == "secret-pass"
    assert settings.fronting_touch_udp_443 is False


def test_settings_keep_legacy_property_aliases() -> None:
    settings = Settings(
        default_entry_host="entry.tracegate.test",
        default_transit_host="transit.tracegate.test",
        agent_runtime_profile="xray-hysteria",
        reality_public_key_entry="entry-pbk",
        reality_short_id_entry="entry-sid",
        reality_public_key_transit="transit-pbk",
        reality_short_id_transit="transit-sid",
        agent_entry_v2_split_backend_enabled=True,
    )

    assert settings.default_vps_e_host == "entry.tracegate.test"
    assert settings.default_vps_t_host == "transit.tracegate.test"
    assert settings.reality_public_key_vps_e == "entry-pbk"
    assert settings.reality_short_id_vps_e == "entry-sid"
    assert settings.reality_public_key_vps_t == "transit-pbk"
    assert settings.reality_short_id_vps_t == "transit-sid"
    assert settings.agent_vps_e_v2_split_backend_enabled is True


def test_settings_accept_legacy_env_aliases(monkeypatch) -> None:
    monkeypatch.setenv("DEFAULT_VPS_E_HOST", "entry.legacy.test")
    monkeypatch.setenv("DEFAULT_VPS_T_HOST", "transit.legacy.test")
    monkeypatch.setenv("AGENT_RUNTIME_PROFILE", "split")
    monkeypatch.setenv("REALITY_PUBLIC_KEY_VPS_E", "entry-pbk")
    monkeypatch.setenv("REALITY_SHORT_ID_VPS_E", "entry-sid")
    monkeypatch.setenv("REALITY_PUBLIC_KEY_VPS_T", "transit-pbk")
    monkeypatch.setenv("REALITY_SHORT_ID_VPS_T", "transit-sid")
    monkeypatch.setenv("AGENT_VPS_E_V2_SPLIT_BACKEND_ENABLED", "true")

    settings = Settings()

    assert settings.default_entry_host == "entry.legacy.test"
    assert settings.default_transit_host == "transit.legacy.test"
    assert settings.agent_runtime_profile == "xray-centric"
    assert settings.reality_public_key_entry == "entry-pbk"
    assert settings.reality_short_id_entry == "entry-sid"
    assert settings.reality_public_key_transit == "transit-pbk"
    assert settings.reality_short_id_transit == "transit-sid"
    assert settings.agent_entry_v2_split_backend_enabled is True


def test_settings_keep_tracegate21_profile_distinct_from_xray_centric() -> None:
    settings = Settings(agent_runtime_profile="tracegate-2.1")
    alias_settings = Settings(agent_runtime_profile="k3s")

    assert settings.agent_runtime_profile == "tracegate-2.1"
    assert alias_settings.agent_runtime_profile == "tracegate-2.1"


def test_effective_private_paths_follow_agent_data_root_outside_systemd_layout() -> None:
    settings = Settings(agent_data_root="/tmp/tracegate-agent")

    assert effective_private_runtime_root(settings) == "/tmp/tracegate-agent/private"
    assert effective_mtproto_public_profile_file(settings) == "/tmp/tracegate-agent/private/mtproto/public-profile.json"
    assert effective_mtproto_issued_state_file(settings) == "/tmp/tracegate-agent/private/mtproto/issued.json"


def test_effective_private_paths_follow_tracegate_parent_for_systemd_layout() -> None:
    settings = Settings(agent_data_root="/var/lib/tracegate/agent-transit")

    assert effective_private_runtime_root(settings) == "/var/lib/tracegate/private"
    assert effective_mtproto_public_profile_file(settings) == "/var/lib/tracegate/private/mtproto/public-profile.json"
    assert effective_mtproto_issued_state_file(settings) == "/var/lib/tracegate/private/mtproto/issued.json"
