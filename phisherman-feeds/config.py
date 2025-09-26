"""Configuración específica para el microservicio de feeds."""


from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class FeedsSettings(BaseSettings):
    """Configuración del microservicio de feeds."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
        env_prefix="FEEDS_",
    )

    # Application
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    api_prefix: str = Field(default="/feeds/v1")
    secret_key: str = Field(default="feeds-service-secret")
    allowed_internal_hosts: list[str] = Field(default=["api", "localhost", "127.0.0.1"])

    # Database (compartida con API principal)
    database_url: str = Field(
        default="postgresql+psycopg://phisherman:password@localhost:5432/phisherman"
    )

    # Redis (compartido)
    redis_url: str = Field(default="redis://localhost:6379")

    # Network
    http_timeout: int = Field(default=30)
    user_agent: str = Field(
        default="PhishermanFeeds/1.0 (+https://github.com/yourusername/phisherman)"
    )

    # API Keys
    google_safebrowsing_api_key: str = Field(default="")
    virustotal_api_key: str = Field(default="")

    # Feed refresh intervals (minutes)
    phishtank_refresh_interval: int = Field(default=15)
    openphish_refresh_interval: int = Field(default=15)
    urlhaus_refresh_interval: int = Field(default=30)
    safebrowsing_refresh_interval: int = Field(default=60)

    # Cache settings
    cache_ttl_seconds: int = Field(default=300)  # 5 minutes

    # Service port
    port: int = Field(default=8001)

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"


# Global settings instance
feeds_settings = FeedsSettings()
