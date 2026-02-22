from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "dev"
    log_level: str = "INFO"

    # Telegram role bootstrap. Roles are persisted in DB, but we need an initial superadmin.
    superadmin_telegram_ids: list[int] = Field(default_factory=list)

    # Secrets must not be hardcoded in repo files; provide via `.env` (not committed).
    database_url: str = ""

    # Runtime filesystem roots (container image includes ./bundles).
    bundle_root: str = "bundles"
    # Optional root with materialized bundle files (e.g. mounted from k8s Secrets).
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
    # Optional: path to a text/markdown file served by /guide.
    # If empty, defaults to "{bundle_root}/bot/guide.md".
    bot_guide_path: str = ""
    # /clean command tries to delete last N messages in chat (best-effort).
    bot_clean_max_messages: int = 150

    # Observability (Grafana is optional; can be deployed via Helm).
    grafana_enabled: bool = False
    grafana_internal_url: str = "http://tracegate-grafana:3000"
    grafana_admin_user: str = "admin"
    grafana_admin_password: str = ""
    grafana_cookie_secret: str = ""
    grafana_otp_ttl_seconds: int = 300
    grafana_session_ttl_seconds: int = 3600
    # Secret used to derive stable pseudo-IDs (e.g. for Grafana auth-proxy login and metrics labels).
    # If empty, falls back to grafana_cookie_secret, then api_internal_token.
    pseudonym_secret: str = ""

    agent_host: str = "0.0.0.0"
    agent_port: int = 8070
    agent_role: str = "VPS_T"
    agent_auth_token: str = ""
    agent_data_root: str = "/tmp/tracegate-agent"
    agent_stats_url: str = "http://127.0.0.1:9999/traffic"
    agent_stats_secret: str = ""
    agent_wg_interface: str = "wg0"
    agent_wg_expected_port: int = 51820
    agent_dry_run: bool = True
    agent_runtime_mode: str = "kubernetes"
    # When enabled, the agent uses Xray gRPC API (HandlerService) to add/remove users without restarting Xray.
    # This is required for true "zero-downtime" connection issuance/revocation.
    agent_xray_api_enabled: bool = False
    agent_xray_api_server: str = "127.0.0.1:8080"
    agent_xray_api_timeout_seconds: int = 3
    # In k3s pipeline prefer graceful signal where supported.
    # Coalesce bursty outbox events into a single reload to avoid xray CrashLoopBackOff
    # while still applying the latest runtime config.
    agent_reload_xray_cmd: str = (
        "sh -lc '(flock 9; sleep 1; pkill -HUP xray || true) 9>/tmp/xray-reload.lock'"
    )
    # Leave disabled by default: some Hysteria v2 builds exit on SIGHUP, which causes pod restarts.
    # Operators can override with a verified safe reload command for their exact image/version.
    agent_reload_hysteria_cmd: str = ""
    agent_reload_wg_cmd: str = "wg syncconf wg0 /etc/wireguard/wg0.conf"
    agent_server_cert: str | None = None
    agent_server_key: str | None = None
    agent_ca_cert: str | None = None

    default_vps_t_host: str = "vps-t.example.com"
    default_vps_e_host: str = "vps-e.example.com"

    # Material required to build working client configs.
    # For direct mode this is VPS-T key.
    # For chain mode with VPS-E splitter, this can be reused as transit REALITY public key unless overridden in Helm values.
    reality_public_key: str = ""
    reality_short_id: str = ""
    # Optional per-role REALITY keys. When set, they override reality_public_key/reality_short_id for that node.
    # This is required when B1 (direct) and B2 (chain) terminate REALITY on different nodes with different keys.
    reality_public_key_vps_t: str = ""
    reality_short_id_vps_t: str = ""
    reality_public_key_vps_e: str = ""
    reality_short_id_vps_e: str = ""
    # REALITY "dest" is a single upstream used for the mimic handshake.
    # Default to a commonly reachable whitelist-friendly dest (operator can override).
    reality_dest: str = "splitter.wb.ru:443"
    # Optional SNI compatibility filter (used by the API/bot).
    # If empty, all enabled SNIs from DB are allowed.
    reality_sni_allow_suffixes: list[str] = Field(default_factory=list)
    wireguard_server_public_key: str = ""

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def ensure_agent_dirs(settings: Settings) -> None:
    root = Path(settings.agent_data_root)
    (root / "events").mkdir(parents=True, exist_ok=True)
    (root / "bundles").mkdir(parents=True, exist_ok=True)
    (root / "users").mkdir(parents=True, exist_ok=True)
    (root / "wg-peers").mkdir(parents=True, exist_ok=True)
    (root / "base").mkdir(parents=True, exist_ok=True)
    (root / "runtime").mkdir(parents=True, exist_ok=True)
