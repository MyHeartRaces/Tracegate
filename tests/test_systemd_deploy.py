from pathlib import Path


def test_systemd_units_exist_for_tracegate2_runtime() -> None:
    root = Path(__file__).resolve().parents[1] / "deploy/systemd"
    expected = {
        "README.md",
        "entry.env.example",
        "install.sh",
        "install-runtime.sh",
        "replace-transit-node.sh",
        "private-example",
        "render-materialized-bundles.sh",
        "render-xray-centric-overlays.sh",
        "validate-runtime-contracts.sh",
        "tracegate-haproxy@.service",
        "tracegate-nginx@.service",
        "tracegate.env.example",
        "tracegate-api.service",
        "tracegate-dispatcher.service",
        "tracegate-bot.service",
        "tracegate-agent-entry.service",
        "tracegate-agent-transit.service",
        "tracegate-hysteria@.service",
        "tracegate-xray@.service",
        "transit-single.env.example",
        "transit.env.example",
    }
    assert {path.name for path in root.iterdir()} == expected


def test_agent_units_are_role_specific() -> None:
    root = Path(__file__).resolve().parents[1] / "deploy/systemd"
    entry = (root / "tracegate-agent-entry.service").read_text(encoding="utf-8")
    transit = (root / "tracegate-agent-transit.service").read_text(encoding="utf-8")

    assert "AGENT_RUNTIME_MODE=systemd" in entry
    assert "AGENT_ROLE=ENTRY" in entry
    assert "tracegate-agent" in entry

    assert "AGENT_RUNTIME_MODE=systemd" in transit
    assert "AGENT_ROLE=TRANSIT" in transit
    assert "tracegate-agent" in transit

    for unit in (entry, transit):
        assert "StateDirectory=tracegate" in unit
        assert "ConfigurationDirectory=tracegate" in unit
        assert "RuntimeDirectory=tracegate" in unit
        assert "UMask=0077" in unit


def test_systemd_templates_cover_shared_and_role_specific_envs() -> None:
    root = Path(__file__).resolve().parents[1] / "deploy/systemd"
    private_example_root = root / "private-example"
    private_systemd_root = private_example_root / "systemd"
    private_fronting_root = private_example_root / "fronting"
    private_profiles_root = private_example_root / "profiles"
    private_link_crypto_root = private_example_root / "link-crypto"
    private_zapret_root = private_example_root / "zapret"
    private_mtproto_root = private_example_root / "mtproto"
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    deploy_readme = (root / "README.md").read_text(encoding="utf-8")
    shared = (root / "tracegate.env.example").read_text(encoding="utf-8")
    transit_single = (root / "transit-single.env.example").read_text(encoding="utf-8")
    entry = (root / "entry.env.example").read_text(encoding="utf-8")
    transit = (root / "transit.env.example").read_text(encoding="utf-8")
    install_script = (root / "install.sh").read_text(encoding="utf-8")
    runtime_install_script = (root / "install-runtime.sh").read_text(encoding="utf-8")
    replace_transit_script = (root / "replace-transit-node.sh").read_text(encoding="utf-8")
    render_script = (root / "render-materialized-bundles.sh").read_text(encoding="utf-8")
    render_xray_centric_script = (root / "render-xray-centric-overlays.sh").read_text(encoding="utf-8")
    validate_runtime_script = (root / "validate-runtime-contracts.sh").read_text(encoding="utf-8")
    private_readme = (private_example_root / "README.md").read_text(encoding="utf-8")
    private_hook = (private_example_root / "render-hook.sh.example").read_text(encoding="utf-8")
    private_systemd_readme = (private_systemd_root / "README.md").read_text(encoding="utf-8")
    private_systemd_env = (private_systemd_root / "obfuscation.env.example").read_text(encoding="utf-8")
    private_systemd_runner = (private_systemd_root / "run-obfuscation.sh.example").read_text(encoding="utf-8")
    private_systemd_unit = (private_systemd_root / "tracegate-obfuscation@.service.example").read_text(encoding="utf-8")
    private_fronting_readme = (private_fronting_root / "README.md").read_text(encoding="utf-8")
    private_fronting_env = (private_fronting_root / "fronting.env.example").read_text(encoding="utf-8")
    private_fronting_runner = (private_fronting_root / "run-fronting.sh.example").read_text(encoding="utf-8")
    private_fronting_unit = (private_fronting_root / "tracegate-fronting@.service.example").read_text(encoding="utf-8")
    private_profiles_readme = (private_profiles_root / "README.md").read_text(encoding="utf-8")
    private_profiles_env = (private_profiles_root / "profiles.env.example").read_text(encoding="utf-8")
    private_profiles_runner = (private_profiles_root / "run-profiles.sh.example").read_text(encoding="utf-8")
    private_profiles_unit = (private_profiles_root / "tracegate-profiles@.service.example").read_text(encoding="utf-8")
    private_link_crypto_readme = (private_link_crypto_root / "README.md").read_text(encoding="utf-8")
    private_link_crypto_env = (private_link_crypto_root / "link-crypto.env.example").read_text(encoding="utf-8")
    private_link_crypto_runner = (private_link_crypto_root / "run-link-crypto.sh.example").read_text(encoding="utf-8")
    private_paired_obfs_env = (private_link_crypto_root / "paired-obfs.env.example").read_text(encoding="utf-8")
    private_link_crypto_unit = (private_link_crypto_root / "tracegate-link-crypto@.service.example").read_text(encoding="utf-8")
    private_zapret_readme = (private_zapret_root / "README.md").read_text(encoding="utf-8")
    private_zapret_entry = (private_zapret_root / "entry-lite.env.example").read_text(encoding="utf-8")
    private_zapret_transit = (private_zapret_root / "transit-lite.env.example").read_text(encoding="utf-8")
    private_zapret_interconnect = (private_zapret_root / "entry-transit-stealth.env.example").read_text(encoding="utf-8")
    private_zapret_mtproto = (private_zapret_root / "mtproto-extra.env.example").read_text(encoding="utf-8")
    private_mtproto_readme = (private_mtproto_root / "README.md").read_text(encoding="utf-8")
    private_mtproto_env = (private_mtproto_root / "mtproto.env.example").read_text(encoding="utf-8")
    private_mtproto_fronting = (private_mtproto_root / "fronting-transit.env.example").read_text(encoding="utf-8")
    private_mtproto_runner = (private_mtproto_root / "run-mtproto.sh.example").read_text(encoding="utf-8")
    private_mtproto_unit = (private_mtproto_root / "tracegate-mtproto@.service.example").read_text(encoding="utf-8")
    haproxy_unit = (root / "tracegate-haproxy@.service").read_text(encoding="utf-8")
    xray_unit = (root / "tracegate-xray@.service").read_text(encoding="utf-8")
    hysteria_unit = (root / "tracegate-hysteria@.service").read_text(encoding="utf-8")
    nginx_unit = (root / "tracegate-nginx@.service").read_text(encoding="utf-8")

    assert "DEFAULT_ENTRY_HOST=" in shared
    assert "DEFAULT_TRANSIT_HOST=" in shared
    assert "AGENT_RUNTIME_PROFILE=tracegate-2.2" in shared
    assert "BUNDLE_PRIVATE_OVERLAY_ROOT=/etc/tracegate/private/overlays" in shared
    assert "TRACEGATE_PRIVATE_RENDER_HOOK=/etc/tracegate/private/render-hook.sh" in shared
    assert "AGENT_XRAY_API_ENABLED=true" in entry
    assert "AGENT_XRAY_API_ENABLED=true" in transit
    assert "Transit-only node replacement profile." in transit_single
    assert "TRACEGATE_REPLACE_API_URL=http://127.0.0.1:18080" in transit_single
    assert "TRACEGATE_REPLACE_REISSUE_CURRENT_REVISIONS=true" in transit_single
    assert "INSTALL_COMPONENTS=xray,hysteria,mtproto" in transit_single
    assert "XRAY_INSTALL_POLICY=if-missing" in transit_single
    assert "HYSTERIA_INSTALL_POLICY=if-missing" in transit_single
    assert "MTPROTO_INSTALL_POLICY=if-missing" in transit_single
    assert "MTPROTO_REFRESH_BOOTSTRAP=if-missing" in transit_single
    assert "REALITY_PRIVATE_KEY_ENTRY=REPLACE_ENTRY_PLACEHOLDER_PRIVATE_KEY" in transit_single
    assert "AGENT_DATA_ROOT=/var/lib/tracegate/agent-transit" in transit_single
    assert "MTPROTO_DOMAIN=mtproto.example.com" in transit_single
    assert "# PRIVATE_RUNTIME_ROOT=/var/lib/tracegate/private" in entry
    assert "# PRIVATE_RUNTIME_ROOT=/var/lib/tracegate/private" in transit
    assert "XRAY_CENTRIC_DECOY_DIR=/var/www/decoy" in shared
    assert "XRAY_CENTRIC_TLS_CERT_FILE=/etc/tracegate/tls/ws.crt" in shared
    assert "XRAY_CENTRIC_TLS_KEY_FILE=/etc/tracegate/tls/ws.key" in shared
    assert "Shared decoy root for nginx and standalone Hysteria2 masquerade." in shared
    assert "REALITY_PRIVATE_KEY_ENTRY=" in shared
    assert "REALITY_PRIVATE_KEY_TRANSIT=" in shared
    assert "REALITY_MULTI_INBOUND_GROUPS=" in shared
    assert "HYSTERIA_UDP_PORT=8443" in shared
    assert "HYSTERIA_SALAMANDER_PASSWORD_ENTRY=REPLACE_ME" in shared
    assert "HYSTERIA_SALAMANDER_PASSWORD_TRANSIT=REPLACE_ME" in shared
    assert "HYSTERIA_STATS_SECRET_ENTRY=REPLACE_ME" in shared
    assert "HYSTERIA_STATS_SECRET_TRANSIT=REPLACE_ME" in shared
    assert "HYSTERIA_BOOTSTRAP_PASSWORD=" in shared
    assert "AGENT_XRAY_API_SERVER=127.0.0.1:8080" in entry
    assert "AGENT_XRAY_API_SERVER=127.0.0.1:8080" in transit
    assert "Hysteria2 metrics are sourced from the standalone Hysteria traffic stats API." in entry
    assert "Hysteria2 metrics are sourced from the standalone Hysteria traffic stats API." in transit
    assert "AGENT_HOST=0.0.0.0" in entry
    assert "AGENT_PORT=8070" in entry
    assert "PRIVATE_OBFUSCATION_BACKEND=zapret2" in entry
    assert "PRIVATE_ENTRY_INTERFACE=eth0" in entry
    assert "AGENT_RELOAD_HAPROXY_CMD=systemctl restart tracegate-haproxy@entry" in entry
    assert "AGENT_RELOAD_XRAY_CMD=systemctl restart tracegate-xray@entry" in entry
    assert "AGENT_RELOAD_HYSTERIA_CMD=systemctl reload tracegate-hysteria@entry || systemctl restart tracegate-hysteria@entry" in entry
    assert "AGENT_RELOAD_NGINX_CMD=systemctl reload tracegate-nginx@entry || systemctl restart tracegate-nginx@entry" in entry
    assert "AGENT_RELOAD_OBFUSCATION_CMD=systemctl reload tracegate-obfuscation@entry || systemctl restart tracegate-obfuscation@entry" in entry
    assert "Private helpers are safe no-ops until their private env files enable them." in entry
    assert "AGENT_RELOAD_PROFILES_CMD=systemctl reload tracegate-profiles@entry || systemctl restart tracegate-profiles@entry" in entry
    assert "AGENT_RELOAD_LINK_CRYPTO_CMD=systemctl reload tracegate-link-crypto@entry || systemctl restart tracegate-link-crypto@entry" in entry
    assert "PRIVATE_MIERU_PROFILE_DIR=/etc/tracegate/private/mieru" in entry
    assert "PRIVATE_LINK_CRYPTO_ENABLED=true" in entry
    assert "PRIVATE_LINK_CRYPTO_GENERATION=1" in entry
    assert "PRIVATE_LINK_CRYPTO_BIND_HOST=127.0.0.1" in entry
    assert "PRIVATE_LINK_CRYPTO_ENTRY_PORT=10881" in entry
    assert "PRIVATE_LINK_CRYPTO_REMOTE_PORT=443" in entry
    assert "PRIVATE_LINK_CRYPTO_ROUTER_ENTRY_ENABLED=false" in entry
    assert "PRIVATE_LINK_CRYPTO_ROUTER_ENTRY_PORT=10883" in entry
    assert "PRIVATE_UDP_LINK_ENABLED=true" in entry
    assert "PRIVATE_UDP_LINK_ENTRY_PORT=14481" in entry
    assert "PRIVATE_UDP_LINK_REMOTE_PORT=8443" in entry
    assert "PRIVATE_UDP_LINK_OBFS_PROFILE=salamander.env" in entry
    assert "PRIVATE_UDP_LINK_HARDENING_ENABLED=true" in entry
    assert "PRIVATE_UDP_LINK_ANTI_REPLAY_ENABLED=true" in entry
    assert "PRIVATE_UDP_LINK_REPLAY_WINDOW_PACKETS=4096" in entry
    assert "PRIVATE_UDP_LINK_ANTI_AMPLIFICATION_ENABLED=true" in entry
    assert "PRIVATE_UDP_LINK_MAX_UNVALIDATED_BYTES=1200" in entry
    assert "PRIVATE_UDP_LINK_RATE_LIMIT_ENABLED=true" in entry
    assert "PRIVATE_UDP_LINK_MTU_MODE=clamp" in entry
    assert "PRIVATE_UDP_LINK_MTU_MAX_PACKET_SIZE=1252" in entry
    assert "PRIVATE_UDP_LINK_KEY_ROTATION_ENABLED=true" in entry
    assert "PRIVATE_UDP_LINK_SOURCE_VALIDATION_ENABLED=true" in entry
    assert "PRIVATE_UDP_LINK_SOURCE_VALIDATION_MODE=profile-bound-remote" in entry
    assert "PRIVATE_UDP_LINK_ROUTER_ENTRY_ENABLED=false" in entry
    assert "FRONTING_TOUCH_UDP_443=false" in entry
    assert "AGENT_HOST=0.0.0.0" in transit
    assert "AGENT_PORT=8070" in transit
    assert "PRIVATE_OBFUSCATION_BACKEND=zapret2" in transit
    assert "PRIVATE_TRANSIT_INTERFACE=eth0" in transit
    assert "PRIVATE_ZAPRET_PROFILE_DIR=/etc/tracegate/private/zapret" in transit
    assert "PRIVATE_ZAPRET_STATE_DIR=/var/lib/tracegate/private/zapret" in transit
    assert "PRIVATE_ZAPRET_PROFILE_INTERCONNECT=entry-transit-stealth.env" in transit
    assert "AGENT_RELOAD_HAPROXY_CMD=systemctl restart tracegate-haproxy@transit" in transit
    assert "AGENT_RELOAD_XRAY_CMD=systemctl restart tracegate-xray@transit" in transit
    assert "AGENT_RELOAD_HYSTERIA_CMD=systemctl reload tracegate-hysteria@transit || systemctl restart tracegate-hysteria@transit" in transit
    assert "AGENT_RELOAD_NGINX_CMD=systemctl reload tracegate-nginx@transit || systemctl restart tracegate-nginx@transit" in transit
    assert "AGENT_RELOAD_OBFUSCATION_CMD=systemctl reload tracegate-obfuscation@transit || systemctl restart tracegate-obfuscation@transit" in transit
    assert "AGENT_RELOAD_FRONTING_CMD=systemctl reload tracegate-fronting@transit || systemctl restart tracegate-fronting@transit" in transit
    assert "Private helpers are safe no-ops until their private env files enable them." in transit
    assert "AGENT_RELOAD_PROFILES_CMD=systemctl reload tracegate-profiles@transit || systemctl restart tracegate-profiles@transit" in transit
    assert "AGENT_RELOAD_LINK_CRYPTO_CMD=systemctl reload tracegate-link-crypto@transit || systemctl restart tracegate-link-crypto@transit" in transit
    assert "PRIVATE_MIERU_PROFILE_DIR=/etc/tracegate/private/mieru" in transit
    assert "PRIVATE_LINK_CRYPTO_ENABLED=true" in transit
    assert "PRIVATE_LINK_CRYPTO_GENERATION=1" in transit
    assert "PRIVATE_LINK_CRYPTO_BIND_HOST=127.0.0.1" in transit
    assert "PRIVATE_LINK_CRYPTO_TRANSIT_PORT=10882" in transit
    assert "PRIVATE_LINK_CRYPTO_REMOTE_PORT=443" in transit
    assert "PRIVATE_LINK_CRYPTO_ROUTER_TRANSIT_ENABLED=false" in transit
    assert "PRIVATE_LINK_CRYPTO_ROUTER_TRANSIT_PORT=10884" in transit
    assert "PRIVATE_UDP_LINK_ENABLED=true" in transit
    assert "PRIVATE_UDP_LINK_TRANSIT_PORT=14482" in transit
    assert "PRIVATE_UDP_LINK_REMOTE_PORT=8443" in transit
    assert "PRIVATE_UDP_LINK_OBFS_PROFILE=salamander.env" in transit
    assert "PRIVATE_UDP_LINK_HARDENING_ENABLED=true" in transit
    assert "PRIVATE_UDP_LINK_ANTI_REPLAY_ENABLED=true" in transit
    assert "PRIVATE_UDP_LINK_REPLAY_WINDOW_PACKETS=4096" in transit
    assert "PRIVATE_UDP_LINK_ANTI_AMPLIFICATION_ENABLED=true" in transit
    assert "PRIVATE_UDP_LINK_MAX_UNVALIDATED_BYTES=1200" in transit
    assert "PRIVATE_UDP_LINK_RATE_LIMIT_ENABLED=true" in transit
    assert "PRIVATE_UDP_LINK_MTU_MODE=clamp" in transit
    assert "PRIVATE_UDP_LINK_MTU_MAX_PACKET_SIZE=1252" in transit
    assert "PRIVATE_UDP_LINK_KEY_ROTATION_ENABLED=true" in transit
    assert "PRIVATE_UDP_LINK_SOURCE_VALIDATION_ENABLED=true" in transit
    assert "PRIVATE_UDP_LINK_SOURCE_VALIDATION_MODE=profile-bound-remote" in transit
    assert "PRIVATE_UDP_LINK_ROUTER_TRANSIT_ENABLED=false" in transit
    assert "PRIVATE_FRONTING_LISTEN_ADDR=127.0.0.1:10443" in transit
    assert "PRIVATE_FRONTING_REALITY_UPSTREAM=127.0.0.1:2443" in transit
    assert "PRIVATE_FRONTING_MTPROTO_UPSTREAM=127.0.0.1:9443" in transit
    assert "PRIVATE_MTPROTO_BACKEND=private" in transit
    assert "PRIVATE_MTPROTO_SECRET_FILE=/etc/tracegate/private/mtproto/secret.txt" in transit
    assert "MTPROTO_DOMAIN=mtproto.example.com" in transit
    assert "MTPROTO_PUBLIC_PORT=443" in transit
    assert "MTPROTO_FRONTING_MODE=dedicated-dns-only" in transit
    assert "MTPROTO_HAPROXY_UPSTREAM=127.0.0.1:9443" in transit
    assert "MTPROTO_PUBLIC_PROFILE_FILE=/var/lib/tracegate/private/mtproto/public-profile.json" in transit
    assert "TRANSIT_DECOY_AUTH_LOGIN=" in transit
    assert "TRANSIT_DECOY_AUTH_PASSWORD=" in transit
    assert "TRANSIT_DECOY_SECRET_PATH=/vault/mtproto/" in transit
    assert "TRANSIT_DECOY_GITHUB_REPO_URL=https://github.com/MyHeartRaces/Tracegate" in transit
    assert "FRONTING_TOUCH_UDP_443=false" in transit
    assert "AGENT_HOST=0.0.0.0" in transit_single
    assert "AGENT_PORT=8070" in transit_single
    assert "PRIVATE_RUNTIME_ROOT=/var/lib/tracegate/private" in transit_single
    assert "PRIVATE_TRANSIT_INTERFACE=eth0" in transit_single
    assert "AGENT_RELOAD_PROFILES_CMD=systemctl reload tracegate-profiles@transit || systemctl restart tracegate-profiles@transit" in transit_single
    assert "AGENT_RELOAD_HYSTERIA_CMD=systemctl reload tracegate-hysteria@transit || systemctl restart tracegate-hysteria@transit" in transit_single
    assert "AGENT_RELOAD_LINK_CRYPTO_CMD=systemctl reload tracegate-link-crypto@transit || systemctl restart tracegate-link-crypto@transit" in transit_single
    assert "PRIVATE_MIERU_PROFILE_DIR=/etc/tracegate/private/mieru" in transit_single
    assert "PRIVATE_MIERU_SERVER_PROFILE=server.json" in transit_single
    assert "PRIVATE_LINK_CRYPTO_ENABLED=true" in transit_single
    assert "PRIVATE_LINK_CRYPTO_TRANSIT_PORT=10882" in transit_single
    assert "PRIVATE_LINK_CRYPTO_ROUTER_TRANSIT_ENABLED=false" in transit_single
    assert "PRIVATE_LINK_CRYPTO_ROUTER_TRANSIT_PORT=10884" in transit_single
    assert "PRIVATE_LINK_CRYPTO_ZAPRET2_ENABLED=false" in transit_single
    assert "PRIVATE_UDP_LINK_ENABLED=true" in transit_single
    assert "PRIVATE_UDP_LINK_TRANSIT_PORT=14482" in transit_single
    assert "PRIVATE_UDP_LINK_REMOTE_PORT=8443" in transit_single
    assert "PRIVATE_UDP_LINK_MTU_MODE=clamp" in transit_single
    assert "PRIVATE_UDP_LINK_SOURCE_VALIDATION_MODE=profile-bound-remote" in transit_single
    assert "PRIVATE_UDP_LINK_ROUTER_TRANSIT_ENABLED=false" in transit_single
    assert "PRIVATE_FRONTING_WS_SNI=transit.example.com" in transit_single
    assert "PRIVATE_MTPROTO_UPSTREAM_PORT=9443" in transit_single
    assert "tracegate-xray@entry" in entry
    assert "tracegate-hysteria@entry" in entry
    assert "tracegate-xray@transit" in transit
    assert "tracegate-hysteria@transit" in transit
    assert 'CONFIG_DIR="${CONFIG_DIR:-/etc/tracegate}"' in install_script
    assert "tracegate.env" in install_script
    assert "install-runtime.sh" in install_script
    assert "validate-runtime-contracts.sh" in install_script
    assert "render-materialized-bundles.sh" in install_script
    assert "render-xray-centric-overlays.sh" in install_script
    assert "systemctl daemon-reload" in install_script
    assert 'LOG_DIR="${LOG_DIR:-/var/log/tracegate}"' in install_script
    assert 'TRACEGATE_INSTALL_ROLE="${TRACEGATE_INSTALL_ROLE:-all}"' in install_script
    assert 'TRACEGATE_SINGLE_ENV_ONLY="${TRACEGATE_SINGLE_ENV_ONLY:-false}"' in install_script
    assert 'install -d -m 0755 -o root -g root "${LOG_DIR}"' in install_script
    assert '"${STATE_DIR}/private"' in install_script
    assert '"${STATE_DIR}/private/obfuscation/entry"' in install_script
    assert '"${STATE_DIR}/private/obfuscation/transit"' in install_script
    assert '"${STATE_DIR}/private/fronting/runtime"' in install_script
    assert '"${STATE_DIR}/private/mtproto/runtime"' in install_script
    assert '"${STATE_DIR}/private/profiles/entry"' in install_script
    assert '"${STATE_DIR}/private/profiles/transit"' in install_script
    assert '"${STATE_DIR}/private/profiles/runtime"' in install_script
    assert '"${STATE_DIR}/private/link-crypto/entry"' in install_script
    assert '"${STATE_DIR}/private/link-crypto/transit"' in install_script
    assert '"${STATE_DIR}/private/zapret"' in install_script
    assert 'seed_if_missing() {' in install_script
    assert 'RUNTIME_PROFILE="$(normalize_runtime_profile "$(read_env_assignment "${CONFIG_DIR}/tracegate.env" "AGENT_RUNTIME_PROFILE")")"' in install_script
    assert 'TRACEGATE_INSTALL_ROLE="$(normalize_install_role "${TRACEGATE_INSTALL_ROLE}")"' in install_script
    assert 'tracegate_env_source="${ROOT_DIR}/deploy/systemd/transit-single.env.example"' in install_script
    assert 'DECOY_ROOT="$(read_env_assignment "${CONFIG_DIR}/tracegate.env" "XRAY_CENTRIC_DECOY_DIR")"' in install_script
    assert 'DECOY_ROOT="${DECOY_ROOT:-/var/www/decoy}"' in install_script
    assert 'install -d -m 0755 -o root -g root "${DECOY_ROOT}"' in install_script
    assert 'ENTRY_RUNTIME_UNITS="$(runtime_units_for_role entry "${RUNTIME_PROFILE}")"' in install_script
    assert 'TRANSIT_RUNTIME_UNITS="$(runtime_units_for_role transit "${RUNTIME_PROFILE}")"' in install_script
    assert "INSTALL_COMPONENTS=auto follows AGENT_RUNTIME_PROFILE=" in install_script
    assert 'systemctl enable --now ${ENTRY_RUNTIME_UNITS}' in install_script
    assert 'systemctl enable --now ${TRANSIT_RUNTIME_UNITS}' in install_script
    assert "deploy/systemd/private-example/README.md" in install_script
    assert "deploy/systemd/private-example/render-hook.sh.example" in install_script
    assert '"${CONFIG_DIR}/private/systemd"' in install_script
    assert '"${CONFIG_DIR}/private/fronting"' in install_script
    assert '"${CONFIG_DIR}/private/profiles"' in install_script
    assert '"${CONFIG_DIR}/private/link-crypto"' in install_script
    assert '"${CONFIG_DIR}/private/mtproto"' in install_script
    assert '"${CONFIG_DIR}/private/mieru"' in install_script
    assert '"${CONFIG_DIR}/private/zapret"' in install_script
    assert "tracegate-obfuscation@.service.example" in install_script
    assert "tracegate-fronting@.service.example" in install_script
    assert "tracegate-profiles@.service.example" in install_script
    assert "tracegate-link-crypto@.service.example" in install_script
    assert "entry-lite.env.example" in install_script
    assert "transit-lite.env.example" in install_script
    assert "entry-transit-stealth.env.example" in install_script
    assert "mtproto-extra.env.example" in install_script
    assert "tracegate-mtproto@.service.example" in install_script
    assert '"/etc/systemd/system/tracegate-obfuscation@.service"' in install_script
    assert '"/etc/systemd/system/tracegate-fronting@.service"' in install_script
    assert '"/etc/systemd/system/tracegate-profiles@.service"' in install_script
    assert '"/etc/systemd/system/tracegate-link-crypto@.service"' in install_script
    assert '"/etc/systemd/system/tracegate-mtproto@.service"' in install_script
    assert '"${CONFIG_DIR}/private/render-hook.sh"' in install_script
    assert '"${private_systemd_target_dir}/obfuscation.env"' in install_script
    assert '"${private_systemd_target_dir}/run-obfuscation.sh"' in install_script
    assert '"${private_fronting_target_dir}/fronting.env"' in install_script
    assert '"${private_fronting_target_dir}/run-fronting.sh"' in install_script
    assert '"${private_profiles_target_dir}/profiles.env"' in install_script
    assert '"${private_profiles_target_dir}/run-profiles.sh"' in install_script
    assert '"${private_link_crypto_target_dir}/link-crypto.env"' in install_script
    assert '"${private_link_crypto_target_dir}/run-link-crypto.sh"' in install_script
    assert '"${private_mtproto_target_dir}/mtproto.env"' in install_script
    assert '"${private_mtproto_target_dir}/run-mtproto.sh"' in install_script
    assert '"${private_zapret_target_dir}/transit-lite.env"' in install_script
    assert '"${private_zapret_target_dir}/entry-transit-stealth.env"' in install_script
    assert '"${private_zapret_target_dir}/mtproto-extra.env"' in install_script
    assert "run-fronting.sh.example" in install_script
    assert "fronting.env.example" in install_script
    assert "run-profiles.sh.example" in install_script
    assert "profiles.env.example" in install_script
    assert "run-link-crypto.sh.example" in install_script
    assert "link-crypto.env.example" in install_script
    assert "run-mtproto.sh.example" in install_script
    assert "mtproto.env.example" in install_script
    assert "fronting-transit.env.example" in install_script
    assert '"${CONFIG_DIR}/private/overlays/entry"' in install_script
    assert '"${CONFIG_DIR}/private/overlays/transit"' in install_script
    assert "INSTALL_COMPONENTS=xray,hysteria,mtproto" in install_script
    assert 'TRACEGATE_ENV_FILE="${TRACEGATE_ENV_FILE:-${CONFIG_DIR}/tracegate.env}"' in replace_transit_script
    assert 'TRACEGATE_SINGLE_ENV_ONLY="${TRACEGATE_SINGLE_ENV_ONLY:-true}"' in replace_transit_script
    assert 'TRACEGATE_INSTALL_ROLE="${TRACEGATE_INSTALL_ROLE:-transit}"' in replace_transit_script
    assert "apt-get install -y --no-install-recommends ca-certificates curl rsync python3 python3-venv" in replace_transit_script
    assert '"${ROOT_DIR}/deploy/systemd/install.sh"' in replace_transit_script
    assert '"${INSTALL_DIR}/deploy/systemd/install-runtime.sh"' in replace_transit_script
    assert '"${INSTALL_DIR}/deploy/systemd/render-materialized-bundles.sh"' in replace_transit_script
    assert '"${INSTALL_DIR}/deploy/systemd/validate-runtime-contracts.sh"' in replace_transit_script
    assert 'wait_for_http_ok() {' in replace_transit_script
    assert 'wait_for_file() {' in replace_transit_script
    assert 'resolve_api_url() {' in replace_transit_script
    assert 'enable_transit_runtime_units() {' in replace_transit_script
    assert 'tracegate-hysteria@transit' in replace_transit_script
    assert 'TRACEGATE_REPLACE_RUNTIME_CONTRACT="${TRACEGATE_REPLACE_RUNTIME_CONTRACT:-${AGENT_DATA_ROOT:-/var/lib/tracegate/agent-transit}/runtime/runtime-contract.json}"' in replace_transit_script
    assert 'TRACEGATE_REPLACE_API_URL="$(resolve_api_url)"' in replace_transit_script
    assert 'tracegate-obfuscation@transit tracegate-fronting@transit tracegate-mtproto@transit' in replace_transit_script
    assert 'wait_for_http_ok "${TRACEGATE_REPLACE_API_URL%/}/health" 60 1' in replace_transit_script
    assert 'wait_for_file "${TRACEGATE_REPLACE_RUNTIME_CONTRACT}" 60 1' in replace_transit_script
    assert "dispatch_post \"/dispatch/reapply-base\" '{\"role\":\"TRANSIT\"}'" in replace_transit_script
    assert "dispatch_post \"/dispatch/reissue-current-revisions\" '{}'" in replace_transit_script
    assert 'XRAY_VERSION="${XRAY_VERSION:-latest}"' in runtime_install_script
    assert 'XRAY_INSTALL_POLICY="${XRAY_INSTALL_POLICY:-if-missing}"' in runtime_install_script
    assert 'HYSTERIA_VERSION="${HYSTERIA_VERSION:-latest}"' in runtime_install_script
    assert 'HYSTERIA_INSTALL_POLICY="${HYSTERIA_INSTALL_POLICY:-if-missing}"' in runtime_install_script
    assert 'TRACEGATE_ENV_FILE="${TRACEGATE_ENV_FILE:-/etc/tracegate/tracegate.env}"' in runtime_install_script
    assert 'MTPROTO_GIT_REPO="${MTPROTO_GIT_REPO:-https://github.com/TelegramMessenger/MTProxy.git}"' in runtime_install_script
    assert 'MTPROTO_GIT_REF="${MTPROTO_GIT_REF:-master}"' in runtime_install_script
    assert 'MTPROTO_INSTALL_POLICY="${MTPROTO_INSTALL_POLICY:-if-missing}"' in runtime_install_script
    assert 'MTPROTO_INSTALL_ROOT="${MTPROTO_INSTALL_ROOT:-/opt/MTProxy}"' in runtime_install_script
    assert 'MTPROTO_SECRET_FILE="${MTPROTO_SECRET_FILE:-/etc/tracegate/private/mtproto/secret.txt}"' in runtime_install_script
    assert 'MTPROTO_ISSUED_STATE_FILE="${MTPROTO_ISSUED_STATE_FILE:-${MTPROTO_STATE_DIR}/issued.json}"' in runtime_install_script
    assert 'MTPROTO_PROXY_SECRET_FILE="${MTPROTO_PROXY_SECRET_FILE:-${MTPROTO_RUNTIME_DIR}/proxy-secret}"' in runtime_install_script
    assert 'MTPROTO_PROXY_CONFIG_FILE="${MTPROTO_PROXY_CONFIG_FILE:-${MTPROTO_RUNTIME_DIR}/proxy-multi.conf}"' in runtime_install_script
    assert 'MTPROTO_REFRESH_BOOTSTRAP="${MTPROTO_REFRESH_BOOTSTRAP:-if-missing}"' in runtime_install_script
    assert '"https://github.com/${repo}/releases/latest"' in runtime_install_script
    assert '"https://github.com/${repo}/releases/latest/download/${asset_name}"' in runtime_install_script
    assert '"https://github.com/${repo}/releases/download/${version}/${asset_name}"' in runtime_install_script
    assert '"XTLS/Xray-core"' in runtime_install_script
    assert 'INSTALL_COMPONENTS="${INSTALL_COMPONENTS:-auto}"' in runtime_install_script
    assert 'INSTALL_PROXY_STACK="${INSTALL_PROXY_STACK:-true}"' in runtime_install_script
    assert 'INSTALL_COMPONENTS_RESOLVED="$(resolve_install_components)"' in runtime_install_script
    assert 'XRAY_INSTALL_POLICY="$(normalize_install_policy "${XRAY_INSTALL_POLICY}")"' in runtime_install_script
    assert 'HYSTERIA_INSTALL_POLICY="$(normalize_install_policy "${HYSTERIA_INSTALL_POLICY}")"' in runtime_install_script
    assert 'MTPROTO_INSTALL_POLICY="$(normalize_install_policy "${MTPROTO_INSTALL_POLICY}")"' in runtime_install_script
    assert 'MTPROTO_REFRESH_BOOTSTRAP="$(normalize_refresh_policy "${MTPROTO_REFRESH_BOOTSTRAP}")"' in runtime_install_script
    assert 'runtime_profile="$(read_env_assignment "${TRACEGATE_ENV_FILE}" "AGENT_RUNTIME_PROFILE")"' in runtime_install_script
    assert 'runtime_profile="$(normalize_runtime_profile "${runtime_profile}")"' in runtime_install_script
    assert "tracegate-2.1" in install_script
    assert "tracegate2.1" in install_script
    assert "tracegate-2.1" in runtime_install_script
    assert "tracegate2.1" in runtime_install_script
    assert 'echo "xray"' in runtime_install_script
    assert 'normalize_install_component() {' in runtime_install_script
    assert 'normalize_install_policy() {' in runtime_install_script
    assert 'normalize_refresh_policy() {' in runtime_install_script
    assert 'component_enabled() {' in runtime_install_script
    assert 'xray_install_required() {' in runtime_install_script
    assert 'hysteria_install_required() {' in runtime_install_script
    assert 'mtproto_install_required() {' in runtime_install_script
    assert "components: ${INSTALL_COMPONENTS_RESOLVED}" in runtime_install_script
    assert "apt-get install -y --no-install-recommends haproxy nginx" in runtime_install_script
    assert "apt-get install -y --no-install-recommends git build-essential libssl-dev zlib1g-dev" in runtime_install_script
    assert 'ensure_mtproto_secret_file() {' in runtime_install_script
    assert 'ensure_mtproto_issued_state_file() {' in runtime_install_script
    assert 'refresh_mtproto_bootstrap() {' in runtime_install_script
    assert 'ensure_mtproto_bootstrap_file() {' in runtime_install_script
    assert 'install_mtproto_binary() {' in runtime_install_script
    assert 'install_mtproto() {' in runtime_install_script
    assert 'install_hysteria() {' in runtime_install_script
    assert 'hysteria-linux-amd64' in runtime_install_script
    assert 'https://download.hysteria.network/app' in runtime_install_script
    assert 'git clone --depth 1 "${MTPROTO_GIT_REPO}" "${source_dir}"' in runtime_install_script
    assert 'git -C "${source_dir}" fetch --depth 1 origin "${MTPROTO_GIT_REF}"' in runtime_install_script
    assert 'make -C "${source_dir}" >/dev/null' in runtime_install_script
    assert 'install -m 0755 "${source_dir}/objs/bin/mtproto-proxy" "${target_binary}"' in runtime_install_script
    assert 'echo "mtproto_binary=${MTPROTO_INSTALL_ROOT}/objs/bin/mtproto-proxy"' in runtime_install_script
    assert 'BUNDLE_MATERIALIZED_ROOT="${BUNDLE_MATERIALIZED_ROOT:-/var/lib/tracegate/materialized-bundles}"' in render_script
    assert 'PYTHON_BIN="${PYTHON_BIN:-${INSTALL_DIR}/.venv/bin/python}"' in render_script
    assert 'PRIVATE_RENDER_HOOK="${TRACEGATE_PRIVATE_RENDER_HOOK:-${CONFIG_DIR}/private/render-hook.sh}"' in render_script
    assert 'load_env_file() {' in render_script
    assert 'load_env_file "${CONFIG_DIR}/tracegate.env"' in render_script
    assert 'load_env_file "${CONFIG_DIR}/entry.env"' in render_script
    assert 'load_env_file "${CONFIG_DIR}/transit.env"' in render_script
    assert '"${PYTHON_BIN}" -m tracegate.cli.render_materialized_bundles' in render_script
    assert 'private render hook is not executable' in render_script
    assert 'tracegate-render-materialized-bundles = "tracegate.cli.render_materialized_bundles:main"' in pyproject
    assert 'BUNDLE_PRIVATE_OVERLAY_ROOT="${BUNDLE_PRIVATE_OVERLAY_ROOT:-${CONFIG_DIR}/private/overlays}"' in render_xray_centric_script
    assert 'load_env_file "${CONFIG_DIR}/tracegate.env"' in render_xray_centric_script
    assert '"${PYTHON_BIN}" -m tracegate.cli.render_xray_centric_overlays' in render_xray_centric_script
    assert 'tracegate-render-xray-centric-overlays = "tracegate.cli.render_xray_centric_overlays:main"' in pyproject
    assert 'CONFIG_DIR="${CONFIG_DIR:-/etc/tracegate}"' in validate_runtime_script
    assert 'load_env_file() {' in validate_runtime_script
    assert 'load_env_file "${CONFIG_DIR}/tracegate.env"' in validate_runtime_script
    assert 'load_env_file "${CONFIG_DIR}/entry.env"' in validate_runtime_script
    assert 'load_env_file "${CONFIG_DIR}/transit.env"' in validate_runtime_script
    assert '"${PYTHON_BIN}" -m tracegate.cli.validate_runtime_contracts' in validate_runtime_script
    assert 'ZAPRET_PROFILE_ROOT="${ZAPRET_PROFILE_ROOT:-/etc/tracegate/private/zapret}"' in validate_runtime_script
    assert 'PREFLIGHT_MODE="${PREFLIGHT_MODE:-auto}"' in validate_runtime_script
    assert 'derive_private_runtime_root() {' in validate_runtime_script
    assert 'detect_preflight_mode() {' in validate_runtime_script
    assert 'PRIVATE_RUNTIME_ROOT="${PRIVATE_RUNTIME_ROOT:-}"' in validate_runtime_script
    assert 'PRIVATE_RUNTIME_ROOT="$(derive_private_runtime_root "${ENTRY_RUNTIME_CONTRACT}" || true)"' in validate_runtime_script
    assert 'PRIVATE_RUNTIME_ROOT="$(derive_private_runtime_root "${TRANSIT_RUNTIME_CONTRACT}" || true)"' in validate_runtime_script
    assert 'PRIVATE_RUNTIME_ROOT="${PRIVATE_RUNTIME_ROOT:-/var/lib/tracegate/private}"' in validate_runtime_script
    assert 'OBFUSCATION_STATE_ROOT="${OBFUSCATION_STATE_ROOT:-${PRIVATE_RUNTIME_ROOT}/obfuscation}"' in validate_runtime_script
    assert 'OBFUSCATION_ENV="${OBFUSCATION_ENV:-/etc/tracegate/private/systemd/obfuscation.env}"' in validate_runtime_script
    assert 'ENTRY_RUNTIME_STATE="${ENTRY_RUNTIME_STATE:-${OBFUSCATION_STATE_ROOT}/entry/runtime-state.json}"' in validate_runtime_script
    assert 'TRANSIT_RUNTIME_STATE="${TRANSIT_RUNTIME_STATE:-${OBFUSCATION_STATE_ROOT}/transit/runtime-state.json}"' in validate_runtime_script
    assert 'ENTRY_RUNTIME_ENV="${ENTRY_RUNTIME_ENV:-${OBFUSCATION_STATE_ROOT}/entry/runtime-state.env}"' in validate_runtime_script
    assert 'TRANSIT_RUNTIME_ENV="${TRANSIT_RUNTIME_ENV:-${OBFUSCATION_STATE_ROOT}/transit/runtime-state.env}"' in validate_runtime_script
    assert 'PROFILE_STATE_ROOT="${PROFILE_STATE_ROOT:-${PRIVATE_RUNTIME_ROOT}/profiles}"' in validate_runtime_script
    assert 'ENTRY_PROFILE_STATE="${ENTRY_PROFILE_STATE:-${PROFILE_STATE_ROOT}/entry/desired-state.json}"' in validate_runtime_script
    assert 'TRANSIT_PROFILE_STATE="${TRANSIT_PROFILE_STATE:-${PROFILE_STATE_ROOT}/transit/desired-state.json}"' in validate_runtime_script
    assert 'ENTRY_PROFILE_ENV="${ENTRY_PROFILE_ENV:-${PROFILE_STATE_ROOT}/entry/desired-state.env}"' in validate_runtime_script
    assert 'TRANSIT_PROFILE_ENV="${TRANSIT_PROFILE_ENV:-${PROFILE_STATE_ROOT}/transit/desired-state.env}"' in validate_runtime_script
    assert 'PROFILES_UNIT="${PROFILES_UNIT:-/etc/systemd/system/tracegate-profiles@.service}"' in validate_runtime_script
    assert 'LINK_CRYPTO_STATE_ROOT="${LINK_CRYPTO_STATE_ROOT:-${PRIVATE_RUNTIME_ROOT}/link-crypto}"' in validate_runtime_script
    assert 'ENTRY_LINK_CRYPTO_STATE="${ENTRY_LINK_CRYPTO_STATE:-${LINK_CRYPTO_STATE_ROOT}/entry/desired-state.json}"' in validate_runtime_script
    assert 'TRANSIT_LINK_CRYPTO_STATE="${TRANSIT_LINK_CRYPTO_STATE:-${LINK_CRYPTO_STATE_ROOT}/transit/desired-state.json}"' in validate_runtime_script
    assert 'ENTRY_LINK_CRYPTO_ENV="${ENTRY_LINK_CRYPTO_ENV:-${LINK_CRYPTO_STATE_ROOT}/entry/desired-state.env}"' in validate_runtime_script
    assert 'TRANSIT_LINK_CRYPTO_ENV="${TRANSIT_LINK_CRYPTO_ENV:-${LINK_CRYPTO_STATE_ROOT}/transit/desired-state.env}"' in validate_runtime_script
    assert 'LINK_CRYPTO_UNIT="${LINK_CRYPTO_UNIT:-/etc/systemd/system/tracegate-link-crypto@.service}"' in validate_runtime_script
    assert 'ROUTER_HANDOFF_STATE_ROOT="${ROUTER_HANDOFF_STATE_ROOT:-${PRIVATE_RUNTIME_ROOT}/router}"' in validate_runtime_script
    assert 'ENTRY_ROUTER_STATE="${ENTRY_ROUTER_STATE:-${ROUTER_HANDOFF_STATE_ROOT}/entry/desired-state.json}"' in validate_runtime_script
    assert 'TRANSIT_ROUTER_STATE="${TRANSIT_ROUTER_STATE:-${ROUTER_HANDOFF_STATE_ROOT}/transit/desired-state.json}"' in validate_runtime_script
    assert 'ENTRY_ROUTER_ENV="${ENTRY_ROUTER_ENV:-${ROUTER_HANDOFF_STATE_ROOT}/entry/desired-state.env}"' in validate_runtime_script
    assert 'TRANSIT_ROUTER_ENV="${TRANSIT_ROUTER_ENV:-${ROUTER_HANDOFF_STATE_ROOT}/transit/desired-state.env}"' in validate_runtime_script
    assert 'ENTRY_ROUTER_CLIENT_BUNDLE="${ENTRY_ROUTER_CLIENT_BUNDLE:-${ROUTER_HANDOFF_STATE_ROOT}/entry/client-bundle.json}"' in validate_runtime_script
    assert 'TRANSIT_ROUTER_CLIENT_BUNDLE="${TRANSIT_ROUTER_CLIENT_BUNDLE:-${ROUTER_HANDOFF_STATE_ROOT}/transit/client-bundle.json}"' in validate_runtime_script
    assert 'ENTRY_ROUTER_CLIENT_ENV="${ENTRY_ROUTER_CLIENT_ENV:-${ROUTER_HANDOFF_STATE_ROOT}/entry/client-bundle.env}"' in validate_runtime_script
    assert 'TRANSIT_ROUTER_CLIENT_ENV="${TRANSIT_ROUTER_CLIENT_ENV:-${ROUTER_HANDOFF_STATE_ROOT}/transit/client-bundle.env}"' in validate_runtime_script
    assert 'FRONTING_STATE="${FRONTING_STATE:-${PRIVATE_RUNTIME_ROOT}/fronting/last-action.json}"' in validate_runtime_script
    assert 'FRONTING_ENV="${FRONTING_ENV:-/etc/tracegate/private/fronting/fronting.env}"' in validate_runtime_script
    assert 'MTPROTO_STATE="${MTPROTO_STATE:-${PRIVATE_RUNTIME_ROOT}/mtproto/last-action.json}"' in validate_runtime_script
    assert 'MTPROTO_ENV="${MTPROTO_ENV:-/etc/tracegate/private/mtproto/mtproto.env}"' in validate_runtime_script
    assert 'MTPROTO_PUBLIC_PROFILE="${MTPROTO_PUBLIC_PROFILE:-${PRIVATE_RUNTIME_ROOT}/mtproto/public-profile.json}"' in validate_runtime_script
    assert 'PREFLIGHT_MODE_RESOLVED="$(detect_preflight_mode)"' in validate_runtime_script
    assert '--mode "${PREFLIGHT_MODE_RESOLVED}"' in validate_runtime_script
    assert 'args+=(--entry "${ENTRY_RUNTIME_CONTRACT}" --transit "${TRANSIT_RUNTIME_CONTRACT}")' in validate_runtime_script
    assert 'args+=(--entry "${ENTRY_RUNTIME_CONTRACT}")' in validate_runtime_script
    assert 'args+=(--transit "${TRANSIT_RUNTIME_CONTRACT}")' in validate_runtime_script
    assert 'args+=(--zapret-root "${ZAPRET_PROFILE_ROOT}")' in validate_runtime_script
    assert 'args+=(--obfuscation-env "${OBFUSCATION_ENV}")' in validate_runtime_script
    assert 'args+=(--profiles-unit "${PROFILES_UNIT}")' in validate_runtime_script
    assert 'args+=(--link-crypto-unit "${LINK_CRYPTO_UNIT}")' in validate_runtime_script
    assert 'args+=(--entry-runtime-state "${ENTRY_RUNTIME_STATE}" --transit-runtime-state "${TRANSIT_RUNTIME_STATE}")' in validate_runtime_script
    assert 'args+=(--entry-runtime-env "${ENTRY_RUNTIME_ENV}" --transit-runtime-env "${TRANSIT_RUNTIME_ENV}")' in validate_runtime_script
    assert 'args+=(--entry-runtime-state "${ENTRY_RUNTIME_STATE}")' in validate_runtime_script
    assert 'args+=(--transit-runtime-state "${TRANSIT_RUNTIME_STATE}")' in validate_runtime_script
    assert 'args+=(--entry-runtime-env "${ENTRY_RUNTIME_ENV}")' in validate_runtime_script
    assert 'args+=(--transit-runtime-env "${TRANSIT_RUNTIME_ENV}")' in validate_runtime_script
    assert 'args+=(--entry-profile-state "${ENTRY_PROFILE_STATE}" --transit-profile-state "${TRANSIT_PROFILE_STATE}")' in validate_runtime_script
    assert 'args+=(--entry-profile-env "${ENTRY_PROFILE_ENV}" --transit-profile-env "${TRANSIT_PROFILE_ENV}")' in validate_runtime_script
    assert 'args+=(--entry-link-crypto-state "${ENTRY_LINK_CRYPTO_STATE}" --transit-link-crypto-state "${TRANSIT_LINK_CRYPTO_STATE}")' in validate_runtime_script
    assert 'args+=(--entry-link-crypto-env "${ENTRY_LINK_CRYPTO_ENV}" --transit-link-crypto-env "${TRANSIT_LINK_CRYPTO_ENV}")' in validate_runtime_script
    assert 'args+=(--entry-router-state "${ENTRY_ROUTER_STATE}" --transit-router-state "${TRANSIT_ROUTER_STATE}")' in validate_runtime_script
    assert 'args+=(--entry-router-env "${ENTRY_ROUTER_ENV}" --transit-router-env "${TRANSIT_ROUTER_ENV}")' in validate_runtime_script
    assert (
        'args+=(--entry-router-client-bundle "${ENTRY_ROUTER_CLIENT_BUNDLE}" '
        '--transit-router-client-bundle "${TRANSIT_ROUTER_CLIENT_BUNDLE}")'
    ) in validate_runtime_script
    assert 'args+=(--entry-router-client-env "${ENTRY_ROUTER_CLIENT_ENV}" --transit-router-client-env "${TRANSIT_ROUTER_CLIENT_ENV}")' in validate_runtime_script
    assert 'args+=(--entry-profile-state "${ENTRY_PROFILE_STATE}")' in validate_runtime_script
    assert 'args+=(--transit-profile-state "${TRANSIT_PROFILE_STATE}")' in validate_runtime_script
    assert 'args+=(--entry-profile-env "${ENTRY_PROFILE_ENV}")' in validate_runtime_script
    assert 'args+=(--transit-profile-env "${TRANSIT_PROFILE_ENV}")' in validate_runtime_script
    assert 'args+=(--entry-link-crypto-state "${ENTRY_LINK_CRYPTO_STATE}")' in validate_runtime_script
    assert 'args+=(--transit-link-crypto-state "${TRANSIT_LINK_CRYPTO_STATE}")' in validate_runtime_script
    assert 'args+=(--entry-link-crypto-env "${ENTRY_LINK_CRYPTO_ENV}")' in validate_runtime_script
    assert 'args+=(--transit-link-crypto-env "${TRANSIT_LINK_CRYPTO_ENV}")' in validate_runtime_script
    assert 'args+=(--entry-router-state "${ENTRY_ROUTER_STATE}")' in validate_runtime_script
    assert 'args+=(--transit-router-state "${TRANSIT_ROUTER_STATE}")' in validate_runtime_script
    assert 'args+=(--entry-router-env "${ENTRY_ROUTER_ENV}")' in validate_runtime_script
    assert 'args+=(--transit-router-env "${TRANSIT_ROUTER_ENV}")' in validate_runtime_script
    assert 'args+=(--entry-router-client-bundle "${ENTRY_ROUTER_CLIENT_BUNDLE}")' in validate_runtime_script
    assert 'args+=(--transit-router-client-bundle "${TRANSIT_ROUTER_CLIENT_BUNDLE}")' in validate_runtime_script
    assert 'args+=(--entry-router-client-env "${ENTRY_ROUTER_CLIENT_ENV}")' in validate_runtime_script
    assert 'args+=(--transit-router-client-env "${TRANSIT_ROUTER_CLIENT_ENV}")' in validate_runtime_script
    assert 'args+=(--fronting-state "${FRONTING_STATE}")' in validate_runtime_script
    assert 'args+=(--fronting-env "${FRONTING_ENV}")' in validate_runtime_script
    assert 'args+=(--mtproto-state "${MTPROTO_STATE}")' in validate_runtime_script
    assert 'args+=(--mtproto-env "${MTPROTO_ENV}")' in validate_runtime_script
    assert 'args+=(--mtproto-public-profile "${MTPROTO_PUBLIC_PROFILE}")' in validate_runtime_script
    assert 'tracegate-validate-runtime-contracts = "tracegate.cli.validate_runtime_contracts:main"' in pyproject
    assert "private overlays" in private_readme
    assert "/etc/tracegate/private/systemd" in private_readme
    assert "/etc/tracegate/private/fronting" in private_readme
    assert "/etc/tracegate/private/profiles" in private_readme
    assert "/etc/tracegate/private/link-crypto" in private_readme
    assert "/etc/tracegate/private/zapret" in private_readme
    assert "/etc/tracegate/private/mtproto" in private_readme
    assert "/etc/tracegate/private/render-hook.sh" in private_readme
    assert "/var/lib/tracegate/agent-entry/runtime/runtime-contract.json" in private_readme
    assert "render-xray-centric-overlays.sh" in private_readme
    assert "tracegate private render hook placeholder" in private_hook
    assert "single-node testbeds" in deploy_readme
    assert "PREFLIGHT_MODE=entry|transit|pair" in deploy_readme
    assert "transit-single.env.example" in deploy_readme
    assert "replace-transit-node.sh" in deploy_readme
    assert "TRACEGATE_TRANSIT_SINGLE_ENV" in deploy_readme
    assert "private systemd helpers" in private_systemd_readme
    assert "tracegate-obfuscation@.service.example" in private_systemd_readme
    assert "../zapret/*.env.example" in private_systemd_readme
    assert "runtime-contract.json" in private_systemd_readme
    assert "TRACEGATE_ZAPRET_PROFILE_FILE" in private_systemd_readme
    assert "Keep `Entry` narrower than `Transit`" in private_systemd_readme
    assert "private TCP/443 fronting scaffold" in private_fronting_readme
    assert "own only `TCP/443`; do not claim public `UDP/8443`" in private_fronting_readme
    assert "tracegate-fronting@.service.example" in private_fronting_readme
    assert "TRACEGATE_FRONTING_ENABLED=false" in private_fronting_env
    assert "TRACEGATE_PRIVATE_RUNTIME_DIR=/var/lib/tracegate/private" in private_fronting_env
    assert "TRACEGATE_FRONTING_RUNTIME_STATE_JSON=/var/lib/tracegate/private/obfuscation/transit/runtime-state.json" in private_fronting_env
    assert "TRACEGATE_FRONTING_LISTEN_ADDR=127.0.0.1:10443" in private_fronting_env
    assert "TRACEGATE_FRONTING_MTPROTO_UPSTREAM=127.0.0.1:9443" in private_fronting_env
    assert "TRACEGATE_FRONTING_HAPROXY_BIN=/usr/sbin/haproxy" in private_fronting_env
    assert "TRACEGATE_FRONTING_WS_SNI=nlconn.tracegate.su" in private_fronting_env
    assert "TRACEGATE_FRONTING_TOUCH_UDP_443=false" in private_fronting_env
    assert 'TRACEGATE_PRIVATE_RUNTIME_DIR="${TRACEGATE_PRIVATE_RUNTIME_DIR:-/var/lib/tracegate/private}"' in private_fronting_runner
    assert 'TRACEGATE_FRONTING_RUNTIME_STATE_JSON="${TRACEGATE_FRONTING_RUNTIME_STATE_JSON:-${TRACEGATE_PRIVATE_RUNTIME_DIR}/obfuscation/${ROLE}/runtime-state.json}"' in private_fronting_runner
    assert 'TRACEGATE_FRONTING_LISTEN_ADDR="${TRACEGATE_FRONTING_LISTEN_ADDR:-127.0.0.1:10443}"' in private_fronting_runner
    assert 'TRACEGATE_FRONTING_HAPROXY_BIN="${TRACEGATE_FRONTING_HAPROXY_BIN:-/usr/sbin/haproxy}"' in private_fronting_runner
    assert 'TRACEGATE_FRONTING_STATE_DIR="${TRACEGATE_FRONTING_STATE_DIR:-${TRACEGATE_PRIVATE_RUNTIME_DIR}/fronting}"' in private_fronting_runner
    assert 'TRACEGATE_FRONTING_CFG_FILE="${TRACEGATE_FRONTING_CFG_FILE:-${TRACEGATE_FRONTING_RUNTIME_DIR}/haproxy.cfg}"' in private_fronting_runner
    assert '"backend": str(sys.argv[16]).strip().lower()' in private_fronting_runner
    assert "tracegate fronting disabled" in private_fronting_runner
    assert "tracegate fronting must not claim public udp/8443" in private_fronting_runner
    assert "tracegate fronting haproxy not installed" in private_fronting_runner
    assert "tracegate fronting started" in private_fronting_runner
    assert "tracegate fronting reloaded" in private_fronting_runner
    assert "ConditionPathExists=/etc/tracegate/private/fronting/run-fronting.sh" in private_fronting_unit
    assert "ExecStart=/usr/bin/env bash /etc/tracegate/private/fronting/run-fronting.sh start %i" in private_fronting_unit
    assert "Type=oneshot" in private_fronting_unit
    assert "RemainAfterExit=yes" in private_fronting_unit
    assert "private profile adapter scaffold" in private_profiles_readme
    assert "required local SOCKS5 auth" in private_profiles_readme
    assert "transportProfiles.localSocks.auth=required" in private_profiles_readme
    assert "TRACEGATE_PROFILES_ENABLED=false" in private_profiles_env
    assert "TRACEGATE_PROFILES_BACKEND=private" in private_profiles_env
    assert "TRACEGATE_PROFILES_STATE_JSON=/var/lib/tracegate/private/profiles/transit/desired-state.json" in private_profiles_env
    assert "TRACEGATE_PROFILES_NO_ANONYMOUS_SOCKS=true" in private_profiles_env
    assert "TRACEGATE_PROFILES_NO_HOST_WIDE_INTERCEPTION=true" in private_profiles_env
    assert "TRACEGATE_PROFILES_RESTART_EXISTING=false" in private_profiles_env
    assert 'TRACEGATE_PROFILES_STATE_JSON="${TRACEGATE_PROFILES_STATE_JSON:-${TRACEGATE_PRIVATE_RUNTIME_DIR}/profiles/${ROLE_LOWER}/desired-state.json}"' in private_profiles_runner
    assert "tracegate profiles desired-state must stay private and contain secret material" in private_profiles_runner
    assert "tracegate profiles transportProfiles local SOCKS5 auth must stay required" in private_profiles_runner
    assert "tracegate profiles transportProfiles must not allow anonymous localhost SOCKS5" in private_profiles_runner
    assert "profile name is not present in transportProfiles.clientNames" in private_profiles_runner
    assert "tracegate profiles refuses anonymous SOCKS mode" in private_profiles_runner
    assert "tracegate profiles refuses host-wide interception" in private_profiles_runner
    assert "tracegate profiles refuses restart-existing mode" in private_profiles_runner
    assert "redacted" in private_profiles_runner
    assert "TRACEGATE_PROFILES_MANIFEST" in private_profiles_runner
    assert "ConditionPathExists=/etc/tracegate/private/profiles/run-profiles.sh" in private_profiles_unit
    assert "ExecStart=/usr/bin/env bash /etc/tracegate/private/profiles/run-profiles.sh start %i" in private_profiles_unit
    assert "Type=oneshot" in private_profiles_unit
    assert "RemainAfterExit=yes" in private_profiles_unit
    assert "private link-crypto scaffold" in private_link_crypto_readme
    assert "Mieru" in private_link_crypto_readme
    assert "never to all host traffic" in private_link_crypto_readme
    assert "transportProfiles.localSocks.auth=required" in private_link_crypto_readme
    assert "TRACEGATE_UDP_OBFS_AUTO_FIREWALL=false" in private_link_crypto_readme
    assert "TRACEGATE_LINK_CRYPTO_ENABLED=false" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_BACKEND=mieru" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_STATE_JSON=/var/lib/tracegate/private/link-crypto/transit/desired-state.json" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_UDP_RUNNER=tracegate-link-crypto-runner" in private_link_crypto_env
    assert "TRACEGATE_HYSTERIA_BIN=/usr/local/bin/hysteria" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_PAIRED_OBFS_RUNNER=tracegate-paired-udp-obfs-runner" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_UDP_PLAN_FILE=/var/lib/tracegate/private/link-crypto/runtime/transit-udp-runner-plan.json" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_NO_HOST_WIDE_INTERCEPTION=true" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_NO_NFQUEUE=true" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_RESTART_EXISTING=false" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_OUTER_WSS_SPKI_PINNING_REQUIRED=true" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_OUTER_WSS_ADMISSION_REQUIRED=true" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_TCP_DPI_RESISTANCE_REQUIRED=true" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_TCP_TRAFFIC_SHAPING_REQUIRED=true" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_PROMOTION_PREFLIGHT_REQUIRED=true" in private_link_crypto_env
    assert "TRACEGATE_LINK_CRYPTO_ZAPRET2_REQUIRED=true" in private_link_crypto_env
    assert 'TRACEGATE_LINK_CRYPTO_STATE_JSON="${TRACEGATE_LINK_CRYPTO_STATE_JSON:-${TRACEGATE_PRIVATE_RUNTIME_DIR}/link-crypto/${ROLE_LOWER}/desired-state.json}"' in private_link_crypto_runner
    assert 'TRACEGATE_LINK_CRYPTO_UDP_RUNNER="${TRACEGATE_LINK_CRYPTO_UDP_RUNNER:-$(command -v tracegate-link-crypto-runner || true)}"' in private_link_crypto_runner
    assert 'TRACEGATE_LINK_CRYPTO_PAIRED_OBFS_RUNNER="${TRACEGATE_LINK_CRYPTO_PAIRED_OBFS_RUNNER:-$(command -v tracegate-paired-udp-obfs-runner || true)}"' in private_link_crypto_runner
    assert 'TRACEGATE_HYSTERIA_BIN="${TRACEGATE_HYSTERIA_BIN:-$(command -v hysteria || true)}"' in private_link_crypto_runner
    assert "run_udp_link_runner() {" in private_link_crypto_runner
    assert "python3 -m tracegate.cli.link_crypto_runner" in private_link_crypto_runner
    assert "--only-udp" in private_link_crypto_runner
    assert "tracegate link-crypto udp runner not installed" in private_link_crypto_runner
    assert 'TRACEGATE_LINK_CRYPTO_NO_HOST_WIDE_INTERCEPTION="${TRACEGATE_LINK_CRYPTO_NO_HOST_WIDE_INTERCEPTION:-true}"' in private_link_crypto_runner
    assert 'TRACEGATE_LINK_CRYPTO_NO_NFQUEUE="${TRACEGATE_LINK_CRYPTO_NO_NFQUEUE:-true}"' in private_link_crypto_runner
    assert 'TRACEGATE_LINK_CRYPTO_RESTART_EXISTING="${TRACEGATE_LINK_CRYPTO_RESTART_EXISTING:-false}"' in private_link_crypto_runner
    assert 'TRACEGATE_LINK_CRYPTO_TCP_DPI_RESISTANCE_REQUIRED="${TRACEGATE_LINK_CRYPTO_TCP_DPI_RESISTANCE_REQUIRED:-true}"' in private_link_crypto_runner
    assert "tracegate link-crypto desired-state must not contain secrets" in private_link_crypto_runner
    assert "tracegate link-crypto transportProfiles local SOCKS5 auth must stay required" in private_link_crypto_runner
    assert "tracegate link-crypto transportProfiles must not allow anonymous localhost SOCKS5" in private_link_crypto_runner
    assert "local listen must stay loopback-bound" in private_link_crypto_runner
    assert "local auth mode must be private-profile" in private_link_crypto_runner
    assert "selectedProfiles are not present in runtime-contract transportProfiles" in private_link_crypto_runner
    assert "tracegate link-crypto {link_class} must be managed by link-crypto" in private_link_crypto_runner
    assert "tracegate link-crypto {link_class} must stay outside Xray backhaul" in private_link_crypto_runner
    assert "outer carrier must require SPKI pinning" in private_link_crypto_runner
    assert "outer carrier must require HMAC admission" in private_link_crypto_runner
    assert "TCP traffic shaping must be required" in private_link_crypto_runner
    assert "promotion preflight must be required and fail closed" in private_link_crypto_runner
    assert "tracegate link-crypto refuses host-wide interception" in private_link_crypto_runner
    assert "tracegate link-crypto refuses broad NFQUEUE" in private_link_crypto_runner
    assert "tracegate link-crypto refuses restart-existing mode" in private_link_crypto_runner
    assert "tracegate link-crypto refuses to run without TCP DPI resistance" in private_link_crypto_runner
    assert "tracegate link-crypto refuses to run without scoped zapret2" in private_link_crypto_runner
    assert '"${TRACEGATE_MIERU_BIN}" run -c "${profile}"' in private_link_crypto_runner
    assert "already running profile=${profile}" in private_link_crypto_runner
    assert 'tracegate-link-crypto-runner = "tracegate.cli.link_crypto_runner:main"' in pyproject
    assert 'tracegate-paired-udp-obfs-runner = "tracegate.cli.paired_udp_obfs_runner:main"' in pyproject
    assert "TRACEGATE_UDP_OBFS_BACKEND=udp2raw" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_MODE=udp2raw-faketcp" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_TARGET=127.0.0.1:14482" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_CIPHER_MODE=aes128cbc" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_REQUIRES_BOTH_SIDES=true" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_FAIL_CLOSED=true" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_NO_HOST_WIDE_INTERCEPTION=true" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_NO_NFQUEUE=true" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_PUBLIC_UDP_PORT=8443" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_FORBID_UDP_443=true" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_FORBID_TCP_8443=true" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_DPI_MODE=salamander-plus-scoped-paired-obfs" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_PACKET_SHAPE=bounded-profile" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_MTU_MODE=clamp" in private_paired_obfs_env
    assert "TRACEGATE_UDP_OBFS_MAX_PACKET_SIZE=1252" in private_paired_obfs_env
    assert "ConditionPathExists=/etc/tracegate/private/link-crypto/run-link-crypto.sh" in private_link_crypto_unit
    assert "ExecStart=/usr/bin/env bash /etc/tracegate/private/link-crypto/run-link-crypto.sh start %i" in private_link_crypto_unit
    assert "Type=oneshot" in private_link_crypto_unit
    assert "RemainAfterExit=yes" in private_link_crypto_unit
    assert "role-specific profile selectors for `Entry` and `Transit`" in private_zapret_readme
    assert "Entry` to `Transit` interconnect profile" in private_zapret_readme
    assert "MTProto" in private_zapret_readme
    assert "TRACEGATE_ZAPRET_PROFILE_NAME=entry-lite" in private_zapret_entry
    assert "TRACEGATE_ZAPRET_TARGET_PROTOCOLS=v2,v4" in private_zapret_entry
    assert "TRACEGATE_ZAPRET_PROFILE_NAME=transit-lite" in private_zapret_transit
    assert "TRACEGATE_ZAPRET_TARGET_PROTOCOLS=v1,v3" in private_zapret_transit
    assert "TRACEGATE_ZAPRET_PROFILE_NAME=entry-transit-stealth" in private_zapret_interconnect
    assert "TRACEGATE_ZAPRET_SCOPE=entry-transit" in private_zapret_interconnect
    assert "TRACEGATE_ZAPRET_PROFILE_NAME=mtproto-extra" in private_zapret_mtproto
    assert "Telegram-recognizable framing" in private_zapret_mtproto
    assert "private MTProto gateway" in private_mtproto_readme
    assert "official Telegram `MTProxy` binary" in private_mtproto_readme
    assert "openssl s_client` is not a valid health check" in private_mtproto_readme
    assert "public-profile.json" in private_mtproto_readme
    assert "fronting-transit.env.example" in private_mtproto_readme
    assert "INSTALL_COMPONENTS=xray,hysteria,mtproto" in private_mtproto_readme
    assert "TRACEGATE_MTPROTO_ENABLED=false" in private_mtproto_env
    assert "TRACEGATE_PRIVATE_RUNTIME_DIR=/var/lib/tracegate/private" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_PROFILE_FILE=/etc/tracegate/private/zapret/mtproto-extra.env" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_ISSUED_STATE_FILE=/var/lib/tracegate/private/mtproto/issued.json" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_RUNNER=/opt/mtproto-private/tracegate-mtproto-gateway" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_FORCE_OFFICIAL=false" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_BINARY=/opt/MTProxy/objs/bin/mtproto-proxy" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_RUNTIME_DIR=/var/lib/tracegate/private/mtproto/runtime" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_STATS_PORT=9888" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_WORKERS=0" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_PID_NAMESPACE=auto" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_FETCH_SECRET_URL=https://core.telegram.org/getProxySecret" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_FETCH_CONFIG_URL=https://core.telegram.org/getProxyConfig" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_BOOTSTRAP_MAX_AGE_SECONDS=86400" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_PROXY_SECRET_FILE=/var/lib/tracegate/private/mtproto/runtime/proxy-secret" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_PROXY_CONFIG_FILE=/var/lib/tracegate/private/mtproto/runtime/proxy-multi.conf" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_PID_FILE=/var/lib/tracegate/private/mtproto/runtime/mtproto-proxy.pid" in private_mtproto_env
    assert "TRACEGATE_MTPROTO_LOG_FILE=/var/lib/tracegate/private/mtproto/runtime/mtproto-proxy.log" in private_mtproto_env
    assert "TRACEGATE_FRONTING_ENABLED=false" in private_mtproto_fronting
    assert "TRACEGATE_FRONTING_BACKEND=private" in private_mtproto_fronting
    assert "TRACEGATE_PRIVATE_RUNTIME_DIR=/var/lib/tracegate/private" in private_mtproto_fronting
    assert "TRACEGATE_FRONTING_MTPROTO_UPSTREAM=127.0.0.1:9443" in private_mtproto_fronting
    assert "TRACEGATE_FRONTING_TOUCH_UDP_443=false" in private_mtproto_fronting
    assert 'TRACEGATE_PRIVATE_RUNTIME_DIR="${TRACEGATE_PRIVATE_RUNTIME_DIR:-/var/lib/tracegate/private}"' in private_mtproto_runner
    assert 'TRACEGATE_APP_ROOT="${TRACEGATE_APP_ROOT:-/opt/tracegate}"' in private_mtproto_runner
    assert 'TRACEGATE_MTPROTO_RUNTIME_STATE_JSON="${TRACEGATE_MTPROTO_RUNTIME_STATE_JSON:-${TRACEGATE_PRIVATE_RUNTIME_DIR}/obfuscation/${ROLE}/runtime-state.json}"' in private_mtproto_runner
    assert 'TRACEGATE_MTPROTO_STATE_DIR="${TRACEGATE_MTPROTO_STATE_DIR:-${TRACEGATE_PRIVATE_RUNTIME_DIR}/mtproto}"' in private_mtproto_runner
    assert 'TRACEGATE_MTPROTO_PUBLIC_PROFILE_FILE="${TRACEGATE_MTPROTO_PUBLIC_PROFILE_FILE:-${TRACEGATE_MTPROTO_STATE_DIR}/public-profile.json}"' in private_mtproto_runner
    assert 'TRACEGATE_MTPROTO_ISSUED_STATE_FILE="${TRACEGATE_MTPROTO_ISSUED_STATE_FILE:-${TRACEGATE_MTPROTO_STATE_DIR}/issued.json}"' in private_mtproto_runner
    assert 'TRACEGATE_MTPROTO_FORCE_OFFICIAL="${TRACEGATE_MTPROTO_FORCE_OFFICIAL:-false}"' in private_mtproto_runner
    assert "use_private_runner() {" in private_mtproto_runner
    assert 'TRACEGATE_MTPROTO_PROXY_SECRET_FILE="${TRACEGATE_MTPROTO_PROXY_SECRET_FILE:-${TRACEGATE_MTPROTO_RUNTIME_DIR}/proxy-secret}"' in private_mtproto_runner
    assert 'TRACEGATE_MTPROTO_PROXY_CONFIG_FILE="${TRACEGATE_MTPROTO_PROXY_CONFIG_FILE:-${TRACEGATE_MTPROTO_RUNTIME_DIR}/proxy-multi.conf}"' in private_mtproto_runner
    assert 'TRACEGATE_MTPROTO_PID_FILE="${TRACEGATE_MTPROTO_PID_FILE:-${TRACEGATE_MTPROTO_RUNTIME_DIR}/mtproto-proxy.pid}"' in private_mtproto_runner
    assert 'TRACEGATE_PYTHON_BIN="${TRACEGATE_PYTHON_BIN:-${TRACEGATE_APP_ROOT}/.venv/bin/python}"' in private_mtproto_runner
    assert 'TRACEGATE_PYTHON_BIN="$(command -v python3 || true)"' in private_mtproto_runner
    assert 'tracegate mtproto cannot find python interpreter' in private_mtproto_runner
    assert '"backend": sys.argv[10].strip().lower()' in private_mtproto_runner
    assert '"publicProfileFile": sys.argv[11]' in private_mtproto_runner
    assert '"issuedStateFile": sys.argv[12]' in private_mtproto_runner
    assert '"${TRACEGATE_PYTHON_BIN}" - "${TRACEGATE_MTPROTO_PUBLIC_PROFILE_FILE}"' in private_mtproto_runner
    assert '"${TRACEGATE_PYTHON_BIN}" - \\' in private_mtproto_runner
    assert 'write_public_profile() {' in private_mtproto_runner
    assert 'build_mtproto_share_links' in private_mtproto_runner
    assert 'load_mtproto_server_secret' in private_mtproto_runner
    assert 'build_mtproto_official_proxy_command' in private_mtproto_runner
    assert 'load_mtproto_issued_secret_hexes' in private_mtproto_runner
    assert 'TRACEGATE_MTPROTO_PID_NAMESPACE="${TRACEGATE_MTPROTO_PID_NAMESPACE:-auto}"' in private_mtproto_runner
    assert "find_mtproto_listener_pids() {" in private_mtproto_runner
    assert 'ss -lntp "( sport = :${port} )"' in private_mtproto_runner
    assert "find_mtproto_process_pids() {" in private_mtproto_runner
    assert "find_mtproto_pids() {" in private_mtproto_runner
    assert "Official MTProxy stores the process id in a 16-bit field" in private_mtproto_runner
    assert 'launch_cmd=(unshare --pid --fork --mount-proc "${cmd[@]}")' in private_mtproto_runner
    assert 'mapfile -t listener_pids < <(find_mtproto_listener_pids)' in private_mtproto_runner
    assert 'nohup "${launch_cmd[@]}" >>"${TRACEGATE_MTPROTO_LOG_FILE}" 2>&1 &' in private_mtproto_runner
    assert 'tracegate mtproto started' in private_mtproto_runner
    assert 'tracegate mtproto reloaded' in private_mtproto_runner
    assert 'tracegate mtproto stopped' in private_mtproto_runner
    assert 'tracegate mtproto disabled' in private_mtproto_runner
    assert 'tracegate mtproto official binary not installed' in private_mtproto_runner
    assert "ConditionPathExists=/etc/tracegate/private/mtproto/run-mtproto.sh" in private_mtproto_unit
    assert "ExecStart=/usr/bin/env bash /etc/tracegate/private/mtproto/run-mtproto.sh start %i" in private_mtproto_unit
    assert "Type=oneshot" in private_mtproto_unit
    assert "RemainAfterExit=yes" in private_mtproto_unit
    assert "TRACEGATE_OBFUSCATION_ENABLED=false" in private_systemd_env
    assert "TRACEGATE_OBFUSCATION_BACKEND=zapret2" in private_systemd_env
    assert "TRACEGATE_ZAPRET_RUNNER=/opt/zapret2-private/tracegate-zapret-wrapper" in private_systemd_env
    assert "TRACEGATE_ZAPRET_POLICY_DIR=/etc/tracegate/private/zapret" in private_systemd_env
    assert "TRACEGATE_ZAPRET_STATE_DIR=/var/lib/tracegate/private/zapret" in private_systemd_env
    assert "TRACEGATE_ZAPRET_PROFILE_DIR=/etc/tracegate/private/zapret" in private_systemd_env
    assert "TRACEGATE_ZAPRET_PROFILE_ENTRY=entry-lite.env" in private_systemd_env
    assert "TRACEGATE_ZAPRET_PROFILE_TRANSIT=transit-lite.env" in private_systemd_env
    assert "TRACEGATE_ZAPRET_PROFILE_INTERCONNECT=entry-transit-stealth.env" in private_systemd_env
    assert "TRACEGATE_ZAPRET_PROFILE_MTPROTO=mtproto-extra.env" in private_systemd_env
    assert "TRACEGATE_ENTRY_RUNTIME_CONTRACT=/var/lib/tracegate/agent-entry/runtime/runtime-contract.json" in private_systemd_env
    assert "TRACEGATE_TRANSIT_RUNTIME_CONTRACT=/var/lib/tracegate/agent-transit/runtime/runtime-contract.json" in private_systemd_env
    assert 'TRACEGATE_OBFUSCATION_ENABLED="${TRACEGATE_OBFUSCATION_ENABLED:-false}"' in private_systemd_runner
    assert 'TRACEGATE_ZAPRET_RUNNER="${TRACEGATE_ZAPRET_RUNNER:-${TRACEGATE_ZAPRET_ROOT}/tracegate-zapret-wrapper}"' in private_systemd_runner
    assert 'TRACEGATE_ZAPRET_PROFILE_DIR="${TRACEGATE_ZAPRET_PROFILE_DIR:-${CONFIG_DIR}/private/zapret}"' in private_systemd_runner
    assert 'TRACEGATE_ZAPRET_PROFILE_ENTRY="${TRACEGATE_ZAPRET_PROFILE_ENTRY:-entry-lite.env}"' in private_systemd_runner
    assert 'TRACEGATE_ZAPRET_PROFILE_TRANSIT="${TRACEGATE_ZAPRET_PROFILE_TRANSIT:-transit-lite.env}"' in private_systemd_runner
    assert 'TRACEGATE_ZAPRET_PROFILE_MTPROTO="${TRACEGATE_ZAPRET_PROFILE_MTPROTO:-mtproto-extra.env}"' in private_systemd_runner
    assert 'RUNTIME_STATE_JSON="${ROLE_STATE_DIR}/runtime-state.json"' in private_systemd_runner
    assert '. "${RUNTIME_STATE_ENV}"' in private_systemd_runner
    assert '"backend": backend' in private_systemd_runner
    assert '"public": {' in private_systemd_runner
    assert '"zapretProfileFile": zapret_profile_file' in private_systemd_runner
    assert '"zapretMtprotoProfileFile": zapret_mtproto_profile_file' in private_systemd_runner
    assert 'TRACEGATE_OBFUSCATION_BACKEND={shell_quote(payload[\'backend\'])}' in private_systemd_runner
    assert 'TRACEGATE_ZAPRET_PROFILE_FILE={shell_quote(payload[\'public\'][\'zapretProfileFile\'])}' in private_systemd_runner
    assert 'TRACEGATE_ZAPRET_MTPROTO_PROFILE_FILE={shell_quote(payload[\'public\'][\'zapretMtprotoProfileFile\'])}' in private_systemd_runner
    assert "TRACEGATE_TCP_443_OWNER" in private_systemd_runner
    assert "TRACEGATE_PUBLIC_UDP_PORT" in private_systemd_runner
    assert "TRACEGATE_PUBLIC_UDP_OWNER" in private_systemd_runner
    assert "TRACEGATE_UDP_443_OWNER" in private_systemd_runner
    assert "TRACEGATE_TOUCH_UDP_443" in private_systemd_runner
    assert "TRACEGATE_MTPROTO_DOMAIN" in private_systemd_runner
    assert "TRACEGATE_MTPROTO_FRONTING_MODE" in private_systemd_runner
    assert 'tracegate obfuscation disabled' in private_systemd_runner
    assert 'tracegate zapret2 runner not installed' in private_systemd_runner
    assert "runtime_contract=${TRACEGATE_RUNTIME_CONTRACT}" in private_systemd_runner
    assert "runtime_state_json=${RUNTIME_STATE_JSON}" in private_systemd_runner
    assert "ExecStart=/usr/bin/env bash /etc/tracegate/private/systemd/run-obfuscation.sh start %i" in private_systemd_unit
    assert "ExecReload=/usr/bin/env bash /etc/tracegate/private/systemd/run-obfuscation.sh reload %i" in private_systemd_unit
    assert "ConditionPathExists=/etc/tracegate/private/systemd/run-obfuscation.sh" in private_systemd_unit
    assert "Type=oneshot" in private_systemd_unit
    assert "RemainAfterExit=yes" in private_systemd_unit
    assert "`INSTALL_COMPONENTS=auto` follows `AGENT_RUNTIME_PROFILE`" in deploy_readme
    assert "/etc/tracegate/private/systemd" in deploy_readme
    assert "/etc/tracegate/private/fronting" in deploy_readme
    assert "/etc/tracegate/private/profiles" in deploy_readme
    assert "/etc/tracegate/private/link-crypto" in deploy_readme
    assert "/etc/tracegate/private/zapret" in deploy_readme
    assert "/etc/tracegate/private/mtproto" in deploy_readme
    assert "INSTALL_COMPONENTS=xray,hysteria,mtproto" in deploy_readme
    assert "XRAY_INSTALL_POLICY=if-missing" in deploy_readme
    assert "MTPROTO_INSTALL_POLICY=if-missing" in deploy_readme
    assert "MTPROTO_REFRESH_BOOTSTRAP=if-missing" in deploy_readme
    assert "TRANSIT_DECOY_AUTH_LOGIN" in deploy_readme
    assert "TRANSIT_DECOY_SECRET_PATH" in deploy_readme
    assert "optional private static/auth content copied into the active decoy root when present" in deploy_readme
    assert "validate-runtime-contracts.sh" in deploy_readme
    assert "wait for the local or configured API `/health` endpoint" in deploy_readme
    assert "wait for the Transit `runtime-contract.json` emitted by the agent" in deploy_readme
    assert "non-production testbed" in deploy_readme
    assert "/etc/tracegate/private/systemd/obfuscation.env" in deploy_readme
    assert "PRIVATE_RUNTIME_ROOT" in deploy_readme
    assert "${CONFIG_DIR:-/etc/tracegate}/tracegate.env" in deploy_readme
    assert "JSON/ENV" in deploy_readme
    assert "handoff surfaces still describe the same runtime state" in deploy_readme
    assert "<private-runtime-root>/obfuscation/<role>/runtime-state.json" in deploy_readme
    assert "<private-runtime-root>/profiles/<role>/desired-state.json" in private_readme
    assert "<private-runtime-root>/link-crypto/<role>/desired-state.json" in private_readme
    assert "`XRAY_CENTRIC_DECOY_DIR` is the shared decoy root used by:" in deploy_readme
    assert "standalone Hysteria2 masquerade directories in `tracegate-2.2`" in deploy_readme
    assert "Xray-native `Hysteria` masquerade directories in the legacy `xray-centric` overlay generator" in deploy_readme
    assert "`AGENT_RUNTIME_PROFILE=tracegate-2.1` keeps the no-Xray-backhaul contract" in deploy_readme
    assert "The public repository does not ship decoy HTML assets." in deploy_readme
    assert "/var/lib/tracegate/agent-{entry,transit}/runtime/runtime-contract.json" in deploy_readme
    assert "`AGENT_RELOAD_OBFUSCATION_CMD` for an optional host-local wrapper reload when `runtime-contract.json` changes" in deploy_readme
    assert "AGENT_RELOAD_FRONTING_CMD" in deploy_readme
    assert "AGENT_RELOAD_MTPROTO_CMD" in deploy_readme
    assert "AGENT_RELOAD_PROFILES_CMD" in deploy_readme
    assert "AGENT_RELOAD_LINK_CRYPTO_CMD" in deploy_readme
    assert "sha256sum -c -" in runtime_install_script
    assert "Xray-linux-64" in runtime_install_script
    assert "ConditionPathExists=/usr/sbin/haproxy" in haproxy_unit
    assert "/usr/sbin/haproxy -W -db -f /var/lib/tracegate/agent-%i/runtime/haproxy/haproxy.cfg" in haproxy_unit
    assert "ConditionPathExists=/usr/sbin/nginx" in nginx_unit
    assert "/usr/sbin/nginx -g 'daemon off;' -c /var/lib/tracegate/agent-%i/runtime/nginx/nginx.conf" in nginx_unit
    assert "/var/www/decoy" not in nginx_unit
    assert "ConditionPathExists=/usr/local/bin/xray" in xray_unit
    assert "ConditionPathExists=/var/lib/tracegate/agent-%i/runtime/xray/config.json" in xray_unit
    assert "ExecReload=/bin/kill -HUP $MAINPID" in xray_unit
    assert "/usr/local/bin/xray run -config /var/lib/tracegate/agent-%i/runtime/xray/config.json" in xray_unit
    assert "ConditionPathExists=/usr/local/bin/hysteria" in hysteria_unit
    assert "ConditionPathExists=/var/lib/tracegate/agent-%i/runtime/hysteria/server.yaml" in hysteria_unit
    assert "/usr/local/bin/hysteria server -c /var/lib/tracegate/agent-%i/runtime/hysteria/server.yaml" in hysteria_unit
