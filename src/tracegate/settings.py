from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "dev"
    log_level: str = "INFO"

    # Telegram role bootstrap. Roles are persisted in DB, but we need an initial superadmin.
    superadmin_telegram_ids: list[int] = Field(default_factory=lambda: [255761416])

    # Secrets must not be hardcoded in repo files; provide via `.env` (not committed).
    database_url: str = ""

    # Runtime filesystem roots (container image includes ./bundles).
    bundle_root: str = "bundles"

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

    # Observability (Grafana is optional; can be deployed via Helm).
    grafana_enabled: bool = False
    grafana_internal_url: str = "http://tracegate-grafana:3000"
    grafana_admin_user: str = "admin"
    grafana_admin_password: str = ""
    grafana_cookie_secret: str = ""
    grafana_otp_ttl_seconds: int = 300
    grafana_session_ttl_seconds: int = 3600

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
    # In k3s pipeline prefer graceful signal where supported.
    agent_reload_xray_cmd: str = "pkill -HUP xray || true"
    # Hysteria supports graceful SIGHUP reload in current production build.
    # It avoids full container restart and minimizes active session interruption.
    agent_reload_hysteria_cmd: str = "pkill -HUP hysteria || true"
    agent_reload_wg_cmd: str = "wg syncconf wg0 /etc/wireguard/wg0.conf"
    agent_server_cert: str | None = None
    agent_server_key: str | None = None
    agent_ca_cert: str | None = None

    default_vps_t_host: str = "vps-t.example.com"
    default_vps_e_host: str = "vps-e.example.com"

    # Material required to build working client configs.
    # For v0.1 we treat REALITY handshake as terminating on VPS-T even in chain mode (VPS-E may be L4 forwarder).
    reality_public_key: str = ""
    reality_short_id: str = ""
    # REALITY "dest" is a single upstream used for the mimic handshake.
    # Default to a VK dest because it is commonly reachable on RU mobile ISPs.
    reality_dest: str = "vk.com:443"
    # Optional SNI compatibility filter (used by the API/bot).
    # If empty, all enabled SNIs from DB are allowed.
    reality_sni_allow_suffixes: list[str] = Field(default_factory=list)
    wireguard_server_public_key: str = ""

    sni_seed: list[str] = Field(default_factory=lambda: ["google.com", "yandex.ru", "microsoft.com", "twitch.tv"])

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
