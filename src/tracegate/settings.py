from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "dev"
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://tracegate:tracegate@localhost:5432/tracegate"

    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_internal_token: str = "change-me"

    dispatcher_host: str = "0.0.0.0"
    dispatcher_port: int = 8090
    dispatcher_poll_seconds: int = 3
    dispatcher_batch_size: int = 50
    dispatcher_client_cert: str | None = None
    dispatcher_client_key: str | None = None
    dispatcher_ca_cert: str | None = None

    bot_token: str = ""
    bot_api_base_url: str = "http://localhost:8080"
    bot_api_token: str = "change-me"

    agent_host: str = "0.0.0.0"
    agent_port: int = 8070
    agent_role: str = "VPS_T"
    agent_auth_token: str = "change-me"
    agent_data_root: str = "/tmp/tracegate-agent"
    agent_stats_url: str = "http://127.0.0.1:9999/traffic"
    agent_stats_secret: str = "change-me"
    agent_wg_interface: str = "wg0"
    agent_wg_expected_port: int = 51820
    agent_dry_run: bool = True
    agent_runtime_mode: str = "systemd"
    agent_reload_xray_cmd: str = "systemctl reload xray"
    agent_reload_hysteria_cmd: str = "systemctl reload hysteria-server"
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
    wireguard_server_public_key: str = ""

    sni_seed: list[str] = Field(default_factory=lambda: ["google.com", "yandex.ru", "microsoft.com", "twitch.tv"])


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
