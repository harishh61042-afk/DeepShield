import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_production_settings_reject_credentialed_wildcard_cors():
    with pytest.raises(ValidationError, match="explicit origins"):
        Settings(
            app_env="production",
            app_secret="s" * 40,
            cookie_secure=True,
            frontend_url="https://depshield.example.com",
            database_url="postgresql+psycopg://app:secret@db.example.com/depshield",
            allowed_origins="*",
        )


def test_app_environment_is_normalized_before_production_validation():
    with pytest.raises(ValidationError, match="COOKIE_SECURE must be true"):
        Settings(
            app_env="Production",
            app_secret="s" * 40,
            cookie_secure=False,
            frontend_url="https://depshield.example.com",
            database_url="postgresql+psycopg://app:secret@db.example.com/depshield",
            allowed_origins="https://depshield.example.com",
        )


def test_development_settings_allow_explicit_local_frontend_origin():
    settings = Settings(app_env="development", allowed_origins="http://localhost:5173")
    assert settings.cors_origins == ["http://localhost:5173"]
