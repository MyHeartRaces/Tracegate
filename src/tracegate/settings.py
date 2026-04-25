from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from tracegate.services.runtime_contract import normalize_runtime_profile_name, resolve_runtime_contract

_DEFAULT_MTPROTO_PUBLIC_PROFILE_FILE = "/var/lib/tracegate/private/mtproto/public-profile.json"
_DEFAULT_MTPROTO_ISSUED_STATE_FILE = "/var/lib/tracegate/private/mtproto/issued.json"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    app_env: str = "dev"
    log_level: str = "INFO"

    # Telegram role bootstrap. Roles are persisted in DB, but we need an initial superadmin.
    superadmin_telegram_ids: list[int] = Field(default_factory=list)

    # Secrets must not be hardcoded in repo files; provide via `.env` (not committed).
    database_url: str = ""

    # Runtime filesystem roots (container image includes ./bundles).
    bundle_root: str = "bundles"
    # Optional root with materialized bundle files (e.g. mounted from deployment secrets).
    # When set, /dispatch/reapply-base overlays files from this root on top of repo bundles.
    bundle_materialized_root: str = ""

    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_internal_token: str = ""

    # Public URL of the control-plane (used by bot links, e.g. Grafana OTP login).
    public_base_url: str = ""

    dispatcher_host: str = "0.0.0.0"
    dispatcher_port: int = 8090
    dispatcher_poll_seconds: int = 3
    dispatcher_batch_size: int = 50
    dispatcher_lock_ttl_seconds: int = 60
    dispatcher_max_attempts: int = 25
    dispatcher_concurrency: int = 10
    dispatcher_metrics_enabled: bool = True
    dispatcher_metrics_host: str = "0.0.0.0"
    dispatcher_metrics_port: int = 9091
    dispatcher_client_cert: str | None = None
    dispatcher_client_key: str | None = None
    dispatcher_ca_cert: str | None = None
    # Dispatcher periodic ops checks (Telegram alerts + retention purge).
    dispatcher_ops_alerts_enabled: bool = False
    dispatcher_ops_alerts_poll_seconds: int = 60
    dispatcher_ops_alerts_repeat_seconds: int = 1800
    dispatcher_ops_alerts_send_resolved: bool = True
    dispatcher_ops_alerts_suppress_initial: bool = True
    dispatcher_ops_alerts_http_timeout_seconds: int = 5
    dispatcher_ops_alerts_prometheus_url: str = "http://tracegate-prometheus:9090"
    dispatcher_ops_alerts_disk_enabled: bool = True
    dispatcher_ops_alerts_disk_threshold_percent: float = 80.0
    dispatcher_ops_alerts_outbox_dead_enabled: bool = True
    dispatcher_ops_alerts_outbox_dead_threshold: int = 0
    dispatcher_outbox_retention_enabled: bool = True
    dispatcher_outbox_retention_interval_seconds: int = 3600
    dispatcher_outbox_retention_sent_days: int = 14
    dispatcher_outbox_retention_failed_days: int = 30
    dispatcher_outbox_retention_batch_size: int = 500
    dispatcher_outbox_retention_max_batches_per_run: int = 20

    bot_token: str = ""
    bot_api_base_url: str = "http://localhost:8080"
    bot_api_token: str = ""
    # Telegram bot can run either in polling mode (default) or via webhooks.
    # Webhooks avoid "Conflict: terminated by other getUpdates request" if a stray poller exists elsewhere.
    bot_mode: str = "polling"  # "polling" | "webhook"
    bot_webhook_listen_host: str = "0.0.0.0"
    bot_webhook_listen_port: int = 8443
    bot_webhook_path: str = "/"
    bot_webhook_secret_token: str = ""  # used for X-Telegram-Bot-Api-Secret-Token validation
    bot_webhook_public_url: str = ""  # full URL; if empty, computed from bot_webhook_public_base_url + bot_webhook_path
    bot_webhook_public_base_url: str = ""  # e.g. "https://t.example.com:8443"
    bot_webhook_tls_cert: str = "/etc/tracegate/bot-webhook/tls.crt"
    bot_webhook_tls_key: str = "/etc/tracegate/bot-webhook/tls.key"
    bot_webhook_upload_cert: bool = True  # upload cert to Telegram (required for self-signed)
    bot_metrics_enabled: bool = True
    bot_metrics_host: str = "0.0.0.0"
    bot_metrics_port: int = 9092
    # Optional external text/markdown served by /guide. Production copy must
    # come from private runtime storage or a Kubernetes Secret, not from Git.
    bot_guide_path: str = ""
    bot_guide_message: str = "[TRACEGATE_BOT_GUIDE_PLACEHOLDER]"
    # Production warning shown before the normal /start flow. Keep the real
    # copy in private env/Secrets; the repository default is a placeholder.
    bot_welcome_required: bool = True
    bot_welcome_version: str = "tracegate-2.1-client-safety-v1"
    bot_welcome_message: str = "[TRACEGATE_BOT_WELCOME_MESSAGE_PLACEHOLDER]"
    bot_welcome_message_file: str = ""
    # /clear command tries to delete last N messages in chat (best-effort).
    bot_clean_max_messages: int = 150
    # Auto-prune regular users with no devices and no connections when listing users.
    users_auto_prune_empty: bool = True

    # Observability (Grafana is optional; can be deployed via Helm).
    grafana_enabled: bool = False
    grafana_internal_url: str = "http://tracegate-grafana:3000"
    grafana_admin_user: str = "admin"
    grafana_admin_password: str = ""
    grafana_cookie_secret: str = ""
    grafana_otp_ttl_seconds: int = 300
    grafana_session_ttl_seconds: int = 3600
    # Internal webhook (Grafana Alerting -> Tracegate API -> Telegram admins/superadmins).
    grafana_alerts_webhook_url: str = ""
    grafana_alerts_webhook_token: str = ""
    # Secret used to derive stable pseudo-IDs (e.g. for Grafana auth-proxy login and metrics labels).
    # If empty, falls back to grafana_cookie_secret, then api_internal_token.
    pseudonym_secret: str = ""

    agent_host: str = "0.0.0.0"
    agent_port: int = 8070
    agent_role: str = "TRANSIT"
    agent_auth_token: str = ""
    agent_data_root: str = "/tmp/tracegate-agent"
    agent_stats_url: str = "http://127.0.0.1:9999/traffic"
    agent_stats_secret: str = ""
    agent_dry_run: bool = True
    # Tracegate 2 defaults to systemd on plain Linux hosts.
    # The "kubernetes" mode is retained only as a compatibility bridge for legacy container deployments.
    agent_runtime_mode: str = "systemd"
    # Canonical runtime profile boundary. Tracegate 2 runs only the Xray-centric runtime.
    # Legacy profile names are normalized into the same Xray-native execution path.
    agent_runtime_profile: str = "xray-centric"
    # Kubernetes rollout invariants exposed through runtime-contract.json so preflight can
    # verify that Tracegate 2.1 upgrades cannot drop the only Entry/Transit gateway pod.
    agent_gateway_strategy: str = "RollingUpdate"
    agent_gateway_allow_recreate_strategy: bool = False
    agent_gateway_max_unavailable: str = "0"
    agent_gateway_max_surge: str = "1"
    agent_gateway_progress_deadline_seconds: int = 600
    agent_gateway_pdb_min_available: str = "1"
    agent_gateway_probes_enabled: bool = True
    agent_gateway_private_preflight_enabled: bool = True
    agent_gateway_private_preflight_forbid_placeholders: bool = True
    # When enabled, the agent uses Xray gRPC API (HandlerService) to add/remove users without restarting Xray.
    # This is required for true "zero-downtime" connection issuance/revocation.
    agent_xray_api_enabled: bool = False
    agent_xray_api_server: str = "127.0.0.1:8080"
    agent_xray_api_timeout_seconds: int = 3
    # Run Entry REALITY inbounds on a dedicated in-pod Xray sidecar built from
    # the Tracegate image when the upstream Xray image misbehaves on xhttp+REALITY.
    agent_entry_v2_split_backend_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "AGENT_ENTRY_V2_SPLIT_BACKEND_ENABLED",
            "AGENT_VPS_E_V2_SPLIT_BACKEND_ENABLED",
        ),
    )
    # Coalesce bursty outbox events into a single reload while still applying the latest runtime config.
    agent_reload_xray_cmd: str = (
        "sh -lc '(flock 9; sleep 1; pkill -HUP xray || true) 9>/tmp/xray-reload.lock'"
    )
    # Optional managed fronting layer for server-side TCP mux / TLS termination.
    agent_reload_haproxy_cmd: str = ""
    agent_reload_nginx_cmd: str = ""
    # Optional host-local obfuscation helper reload, for example a private systemd wrapper
    # that reacts to runtime-contract.json changes and refreshes zapret2 / FinalMask glue.
    agent_reload_obfuscation_cmd: str = ""
    # Optional private TCP/443 demux helper reload used by the Transit fronting wrapper.
    agent_reload_fronting_cmd: str = ""
    # Optional MTProto gateway reload hook used when account-bound MTProto grants rotate.
    agent_reload_mtproto_cmd: str = ""
    # Optional private profile adapter reload hook used by sing-box / WSTunnel / WireGuard wrappers.
    agent_reload_profiles_cmd: str = ""
    # Optional private link-crypto reload hook used by Mieru / router relay wrappers.
    agent_reload_link_crypto_cmd: str = ""
    # Optional private handoff roots/state used by host-local wrappers.
    private_runtime_root: str = ""
    private_obfuscation_backend: str = "zapret2"
    private_entry_interface: str = "eth0"
    private_transit_interface: str = "eth0"
    private_zapret_profile_dir: str = "/etc/tracegate/private/zapret"
    private_zapret_policy_dir: str = "/etc/tracegate/private/zapret"
    private_zapret_state_dir: str = ""
    private_zapret_profile_entry: str = "entry-lite.env"
    private_zapret_profile_transit: str = "transit-lite.env"
    private_zapret_profile_interconnect: str = "entry-transit-stealth.env"
    private_zapret_profile_mtproto: str = "mtproto-extra.env"
    private_mieru_profile_dir: str = "/etc/tracegate/private/mieru"
    private_mieru_client_profile: str = "client.json"
    private_mieru_server_profile: str = "server.json"
    private_shadowtls_profile_dir: str = "/etc/tracegate/private/shadowtls"
    private_shadowtls_profile_entry: str = "entry-config.yaml"
    private_shadowtls_profile_transit: str = "transit-config.yaml"
    private_link_crypto_enabled: bool = True
    private_link_crypto_generation: int = 1
    private_link_crypto_bind_host: str = "127.0.0.1"
    private_link_crypto_entry_port: int = 10881
    private_link_crypto_transit_port: int = 10882
    private_link_crypto_router_entry_enabled: bool = False
    private_link_crypto_router_transit_enabled: bool = False
    private_link_crypto_router_entry_port: int = 10883
    private_link_crypto_router_transit_port: int = 10884
    private_link_crypto_remote_port: int = 443
    private_link_crypto_zapret2_enabled: bool = False
    private_fronting_listen_addr: str = "127.0.0.1:10443"
    private_fronting_protocol: str = "tcp"
    private_fronting_reality_upstream: str = "127.0.0.1:2443"
    private_fronting_ws_tls_upstream: str = "127.0.0.1:4443"
    private_fronting_mtproto_upstream: str = "127.0.0.1:9443"
    private_fronting_ws_sni: str = ""
    private_fronting_mtproto_domain_override: str = ""
    private_mtproto_backend: str = "private"
    private_mtproto_upstream_host: str = "127.0.0.1"
    private_mtproto_upstream_port: int = 9443
    private_mtproto_secret_file: str = "/etc/tracegate/private/mtproto/secret.txt"
    # Future private MTProto/fronting hints exposed via runtime-contract.json for host-local wrappers.
    # Keep MTProto on a dedicated real domain and avoid claiming UDP/443 in the private TCP demux layer.
    mtproto_domain: str = ""
    mtproto_public_port: int = 443
    mtproto_fronting_mode: str = "dedicated-dns-only"
    mtproto_public_profile_file: str = _DEFAULT_MTPROTO_PUBLIC_PROFILE_FILE
    mtproto_issued_state_file: str = _DEFAULT_MTPROTO_ISSUED_STATE_FILE
    transit_decoy_auth_login: str = ""
    transit_decoy_auth_password: str = ""
    transit_decoy_auth_cookie_name: str = "tg_decoy_session"
    transit_decoy_auth_session_ttl_seconds: int = 7200
    transit_decoy_secret_path: str = "/vault/mtproto/"
    transit_decoy_github_repo_url: str = "https://github.com/MyHeartRaces/Tracegate"
    transit_decoy_github_cache_ttl_seconds: int = 300
    fronting_touch_udp_443: bool = False
    agent_server_cert: str | None = None
    agent_server_key: str | None = None
    agent_ca_cert: str | None = None

    default_transit_host: str = Field(
        default="transit.example.com",
        validation_alias=AliasChoices("DEFAULT_TRANSIT_HOST", "DEFAULT_VPS_T_HOST"),
    )
    default_entry_host: str = Field(
        default="entry.example.com",
        validation_alias=AliasChoices("DEFAULT_ENTRY_HOST", "DEFAULT_VPS_E_HOST"),
    )

    # Material required to build working client configs.
    # For direct mode this is Transit key.
    # For chain mode with Entry splitter, this can be reused as transit REALITY public key unless overridden in Helm values.
    reality_public_key: str = ""
    reality_short_id: str = ""
    # Optional per-role REALITY keys. When set, they override reality_public_key/reality_short_id for that node.
    # This is required when V1 (direct) and V2 (chain) terminate REALITY on different nodes with different keys.
    reality_public_key_transit: str = Field(
        default="",
        validation_alias=AliasChoices("REALITY_PUBLIC_KEY_TRANSIT", "REALITY_PUBLIC_KEY_VPS_T"),
    )
    reality_short_id_transit: str = Field(
        default="",
        validation_alias=AliasChoices("REALITY_SHORT_ID_TRANSIT", "REALITY_SHORT_ID_VPS_T"),
    )
    reality_public_key_entry: str = Field(
        default="",
        validation_alias=AliasChoices("REALITY_PUBLIC_KEY_ENTRY", "REALITY_PUBLIC_KEY_VPS_E"),
    )
    reality_short_id_entry: str = Field(
        default="",
        validation_alias=AliasChoices("REALITY_SHORT_ID_ENTRY", "REALITY_SHORT_ID_VPS_E"),
    )
    # REALITY "dest" is a single upstream used for the mimic handshake.
    # Default to a commonly reachable whitelist-friendly dest (operator can override).
    reality_dest: str = "splitter.wb.ru:443"
    # Optional SNI compatibility filter (used by the API/bot).
    # If empty, all enabled SNIs from DB are allowed.
    reality_sni_allow_suffixes: list[str] = Field(default_factory=list)
    # Pre-seeded SNI allow-list for REALITY inbounds. Keep it minimal to avoid
    # advertising unrelated camouflage targets by default.
    sni_seed: list[str] = Field(default_factory=lambda: ["splitter.wb.ru"])
    # Optional REALITY multi-inbound mapping.
    # Each row is an object with:
    # - id: stable slug (used in generated inbound tag)
    # - port: local Xray listen port (entry-mux upstream target)
    # - dest: REALITY dest host (port is forced to 443 by reconciler)
    # - snis: list of client SNI values routed to this inbound
    # Example:
    # [
    #   {"id": "shared-a", "port": 2501, "dest": "splitter.wb.ru", "snis": ["splitter.wb.ru"]}
    # ]
    reality_multi_inbound_groups: list[dict] = Field(default_factory=list)

    # Optional VLESS over WebSocket+TLS settings (operator-controlled; must match Xray inbound settings).
    vless_ws_path: str = "/ws"
    vless_ws_tls_port: int = 443
    # Optional Hysteria/ECH hints exposed to client effective configs.
    hysteria_ech_config_list_entry: str = Field(
        default="",
        validation_alias=AliasChoices("HYSTERIA_ECH_CONFIG_LIST_ENTRY", "HYSTERIA_ECH_CONFIG_LIST"),
    )
    hysteria_ech_config_list_transit: str = Field(
        default="",
        validation_alias=AliasChoices("HYSTERIA_ECH_CONFIG_LIST_TRANSIT", "HYSTERIA_ECH_CONFIG_LIST"),
    )
    hysteria_ech_force_query_entry: str = Field(
        default="",
        validation_alias=AliasChoices("HYSTERIA_ECH_FORCE_QUERY_ENTRY", "HYSTERIA_ECH_FORCE_QUERY"),
    )
    hysteria_ech_force_query_transit: str = Field(
        default="",
        validation_alias=AliasChoices("HYSTERIA_ECH_FORCE_QUERY_TRANSIT", "HYSTERIA_ECH_FORCE_QUERY"),
    )

    @field_validator("agent_runtime_profile", mode="before")
    @classmethod
    def _normalize_agent_runtime_profile(cls, value: object) -> str:
        return normalize_runtime_profile_name(str(value or ""))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


Settings.default_vps_t_host = property(lambda self: self.default_transit_host)  # type: ignore[attr-defined]
Settings.default_vps_e_host = property(lambda self: self.default_entry_host)  # type: ignore[attr-defined]
Settings.reality_public_key_vps_t = property(lambda self: self.reality_public_key_transit)  # type: ignore[attr-defined]
Settings.reality_short_id_vps_t = property(lambda self: self.reality_short_id_transit)  # type: ignore[attr-defined]
Settings.reality_public_key_vps_e = property(lambda self: self.reality_public_key_entry)  # type: ignore[attr-defined]
Settings.reality_short_id_vps_e = property(lambda self: self.reality_short_id_entry)  # type: ignore[attr-defined]
Settings.agent_vps_e_v2_split_backend_enabled = property(  # type: ignore[attr-defined]
    lambda self: self.agent_entry_v2_split_backend_enabled
)

def effective_mtproto_reload_cmd(settings: Settings) -> str:
    configured = str(settings.agent_reload_mtproto_cmd or "").strip()
    if configured:
        return configured

    role = str(settings.agent_role or "").strip().lower()
    if role:
        return f"systemctl reload tracegate-mtproto@{role}"
    return ""


def effective_private_runtime_root(settings: Settings) -> str:
    configured = str(settings.private_runtime_root or "").strip()
    if configured:
        return configured

    agent_root = Path(settings.agent_data_root)
    if agent_root.name.startswith("agent-"):
        return str(agent_root.parent / "private")
    return str(agent_root / "private")


def effective_zapret_state_dir(settings: Settings) -> str:
    configured = str(settings.private_zapret_state_dir or "").strip()
    if configured:
        return configured
    return str(Path(effective_private_runtime_root(settings)) / "zapret")


def effective_mtproto_public_profile_file(settings: Settings) -> str:
    configured = str(settings.mtproto_public_profile_file or "").strip()
    if configured and configured != _DEFAULT_MTPROTO_PUBLIC_PROFILE_FILE:
        return configured
    return str(Path(effective_private_runtime_root(settings)) / "mtproto" / "public-profile.json")


def effective_mtproto_issued_state_file(settings: Settings) -> str:
    configured = str(settings.mtproto_issued_state_file or "").strip()
    if configured and configured != _DEFAULT_MTPROTO_ISSUED_STATE_FILE:
        return configured
    return str(Path(effective_private_runtime_root(settings)) / "mtproto" / "issued.json")


def ensure_agent_dirs(settings: Settings) -> None:
    root = Path(settings.agent_data_root)
    contract = resolve_runtime_contract(settings.agent_runtime_profile)
    (root / "events").mkdir(parents=True, exist_ok=True)
    (root / "bundles").mkdir(parents=True, exist_ok=True)
    (root / "users").mkdir(parents=True, exist_ok=True)
    (root / "base").mkdir(parents=True, exist_ok=True)
    (root / "runtime").mkdir(parents=True, exist_ok=True)
    for component in contract.runtime_dirs:
        (root / "runtime" / component).mkdir(parents=True, exist_ok=True)
