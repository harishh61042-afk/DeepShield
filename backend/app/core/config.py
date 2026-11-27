from functools import lru_cache

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    app_name: str = "DepShield"
    app_env: str = "development"
    frontend_url: str = "http://localhost:5173"
    backend_url: str = "http://localhost:8000"
    database_url: str = "postgresql+psycopg://depshield:change-me@localhost:5432/depshield"
    app_secret: str = ""
    session_ttl_hours: int = 12
    cookie_secure: bool = False
    allowed_origins: str = "http://localhost:5173"
    max_upload_bytes: int = 10 * 1024 * 1024
    max_archive_entries: int = 2000
    max_extracted_bytes: int = 50 * 1024 * 1024
    scan_timeout_seconds: int = 180
    worker_poll_seconds: float = 2
    osv_base_url: str = "https://api.osv.dev"
    osv_timeout_seconds: float = 15
    nvd_api_key: str | None = None
    nvd_enabled: bool = True
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    intelligence_cache_hours: int = 12
    ollama_enabled: bool = False
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    ollama_timeout_seconds: float = 45
    smtp_host: str | None = None
    smtp_port: int = 1025
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "depshield@localhost"
    reset_token_ttl_minutes: int = 30
    data_retention_days: int = 365
    support_email: str | None = None

    @field_validator("app_env", mode="before")
    @classmethod
    def normalize_app_env(cls, value):
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("app_secret")
    @classmethod
    def validate_secret(cls, value: str, info):
        env = info.data.get("app_env", "development")
        if env == "production" and len(value) < 32:
            raise ValueError("APP_SECRET must contain at least 32 characters in production")
        return value

    @model_validator(mode="after")
    def validate_production_settings(self):
        if "*" in self.cors_origins:
            raise ValueError("ALLOWED_ORIGINS must list explicit origins when credentialed requests are enabled")
        if self.app_env == "production":
            if not self.cors_origins:
                raise ValueError("ALLOWED_ORIGINS must include the production frontend origin")
            if not self.cookie_secure:
                raise ValueError("COOKIE_SECURE must be true in production")
            if not self.frontend_url.startswith("https://"):
                raise ValueError("FRONTEND_URL must use HTTPS in production")
            if "change-me" in self.database_url or "localhost" in self.database_url:
                raise ValueError("Set a non-default production PostgreSQL URL")
        return self

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
