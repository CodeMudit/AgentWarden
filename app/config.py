"""Application settings loaded from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AgentWarden"
    app_version: str = "0.1.0"
    debug: bool = False
    demo_mode: bool = True

    secret_key: str = "dev-secret-change-me-in-production-32chars"
    ledger_checkpoint_key: str = "dev-ledger-hmac-key-change-me"

    database_url: str = "sqlite:///./agentwarden.db"

    approval_sla_seconds: int = 900

    host: str = "0.0.0.0"
    port: int = 8000

    # Optional Anthropic (app works fully without these)
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-20250514"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()
