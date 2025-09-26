"""Application configuration using pydantic-settings for 12-factor app compliance."""

from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    api_prefix: str = Field(default="/api/v1")
    secret_key: str = Field(default="change-me-in-production")
    allowed_hosts: list[str] = Field(default=["localhost", "127.0.0.1"])

    # Database
    database_url: str = Field(
        default="postgresql+psycopg://phisherman:password@localhost:5432/phisherman",
        description="PostgreSQL database URL",
    )
    database_pool_size: int = Field(
        default=10, description="Database connection pool size"
    )
    database_max_overflow: int = Field(
        default=20, description="Database pool max overflow"
    )

    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379", description="Redis connection URL"
    )
    redis_max_connections: int = Field(default=10, description="Redis max connections")

    # Celery
    celery_broker_url: str = Field(
        default="redis://localhost:6379", description="Celery broker URL"
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379", description="Celery result backend URL"
    )
    celery_task_serializer: str = Field(default="json")
    celery_result_serializer: str = Field(default="json")

    # Rate Limiting
    rate_limit_requests_per_minute: int = Field(default=100)
    rate_limit_burst_size: int = Field(default=20)

    # Network Configuration
    http_timeout: int = Field(default=10)
    dns_timeout: int = Field(default=5)
    whois_timeout: int = Field(default=10)
    max_retries: int = Field(default=3)
    user_agent: str = Field(
        default="Phisherman/1.0 (+https://github.com/yourusername/phisherman)"
    )

    # External APIs
    virustotal_api_key: str = Field(default="")
    shodan_api_key: str = Field(default="")
    abuse_ch_api_key: str = Field(default="")

    # Internal Services
    feeds_service_url: str = Field(
        default="http://localhost:8001", description="URL del microservicio de feeds"
    )

    # Feed Configuration
    phishtank_refresh_interval: int = Field(default=15)
    openphish_refresh_interval: int = Field(default=15)
    urlhaus_refresh_interval: int = Field(default=15)

    # Observability
    prometheus_port: int = Field(default=9090)
    metrics_endpoint: str = Field(default="/metrics")
    otel_service_name: str = Field(default="phisherman")
    otel_exporter_jaeger_endpoint: str = Field(
        default="http://localhost:14268/api/traces"
    )

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v: Any) -> list[str]:
        """Parse allowed hosts from string or list."""
        if isinstance(v, str):
            # Handle JSON-like string format
            v = v.strip('[]"')
            return [host.strip(" \"'") for host in v.split(",") if host.strip()]
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"

    @property
    def celery_config(self) -> dict[str, Any]:
        """Get Celery configuration dictionary."""
        return {
            "broker_url": self.celery_broker_url,
            "result_backend": self.celery_result_backend,
            "task_serializer": self.celery_task_serializer,
            "result_serializer": self.celery_result_serializer,
            "accept_content": ["json"],
            "timezone": "UTC",
            "enable_utc": True,
            "task_track_started": True,
            "task_time_limit": 300,  # 5 minutes
            "task_soft_time_limit": 240,  # 4 minutes
            "worker_prefetch_multiplier": 1,
            "task_acks_late": True,
            "worker_max_tasks_per_child": 1000,
        }


# Global settings instance
settings = Settings()
