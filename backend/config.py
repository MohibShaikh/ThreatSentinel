"""
ThreatSentinel SOC Agent Backend Configuration

Pydantic v2 settings loaded from environment variables and ``.env``.
Field names map to upper-case env vars (``secret_key`` -> ``SECRET_KEY``).
"""

import json
import os
import re
from functools import lru_cache
from typing import Annotated, Any, List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_PLACEHOLDER_RE = re.compile(
    r"^(your[_\-].*|.*_here|changeme|change[_\-]me|placeholder|xxx+|none|null|todo|<.*>)$",
    re.IGNORECASE,
)
KNOWN_WEAK_SECRETS = {
    "dev-secret-key", "secret", "changeme", "change-me", "your_secret_key_here",
    "your-secret-key", "supersecret", "password", "admin", "test", "default",
}
MIN_SECRET_LENGTH = 32


def _is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and (not value.strip() or bool(_PLACEHOLDER_RE.match(value.strip())))


class Settings(BaseSettings):
    """Application settings with environment variable support"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # API
    app_name: str = "ThreatSentinel SOC Agent API"
    version: str = "2.1.0"
    environment: str = "development"
    debug: bool = False

    # Server
    host: str = "127.0.0.1"
    port: int = 8000

    # Security
    # Development default only: validate_security_posture() refuses it unless DEBUG=true
    secret_key: str = "dev-secret-key"  # noqa: S105
    access_token_expire_minutes: int = 30

    # External threat intel API keys (all optional)
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    urlvoid_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    enable_keyless_intel: bool = True

    # LLM (hosted providers need a key; ollama/lmstudio/vllm/local do not)
    llm_provider: Optional[str] = None
    llm_api_key: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_temperature: float = 0.3
    llm_max_tokens: int = 2048
    llm_redact_secrets: bool = True
    # Read-only tool calls the LLM may make per investigation (0 disables, capped at 10)
    llm_max_tool_steps: int = Field(default=5, ge=0, le=10)

    # Agent
    confidence_threshold: float = 0.7
    emergency_threshold: float = 0.8
    max_investigation_time: int = 300

    # Storage
    data_dir: str = "data"
    reports_dir: str = "reports"
    memory_dir: str = "data/memory"
    logs_dir: str = "logs"
    auto_save_reports: bool = True

    # Integrations: JSON object of the form {"integrations": {"palo_alto": {...}}}
    integrations_config: str = "{}"

    database_url: Optional[str] = None
    redis_url: Optional[str] = None

    # Logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Rate limiting (per client IP)
    rate_limit_requests: int = 100
    rate_limit_window: int = 60

    # CORS
    cors_origins: Annotated[List[str], NoDecode] = [
        "http://localhost:3000", "http://localhost:5173", "http://localhost:8080"]

    # Investigation limits
    max_concurrent_investigations: int = 10
    investigation_timeout: int = 600
    task_queue_workers: int = 2

    # Monitoring
    health_check_interval: int = 60
    metrics_enabled: bool = True

    @field_validator("virustotal_api_key", "abuseipdb_api_key", "urlvoid_api_key", "shodan_api_key",
                     "llm_api_key", "llm_model", "llm_base_url", "llm_provider", "database_url", "redis_url",
                     mode="before")
    @classmethod
    def _drop_placeholders(cls, value: Any) -> Any:
        """Template values like 'your_api_key_here' mean 'not configured'."""
        if value is None or _is_placeholder(value):
            return None
        return value.strip() if isinstance(value, str) else value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_origins(cls, value: Any) -> Any:
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("["):
                return json.loads(text)
            return [o.strip() for o in text.split(",") if o.strip()]
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper_level(cls, value: Any) -> Any:
        return str(value).upper() if value else "INFO"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        for path in (self.data_dir, self.reports_dir, self.memory_dir, self.logs_dir):
            os.makedirs(path, exist_ok=True)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("production", "prod")

    @property
    def has_threat_intel_keys(self) -> bool:
        return bool(self.configured_apis)

    @property
    def configured_apis(self) -> List[str]:
        names = {
            "virustotal": self.virustotal_api_key,
            "abuseipdb": self.abuseipdb_api_key,
            "urlvoid": self.urlvoid_api_key,
            "shodan": self.shodan_api_key,
        }
        return [name for name, key in names.items() if key]

    def security_posture_errors(self) -> List[str]:
        """Problems that make this configuration unsafe outside debug mode."""
        errors = []
        key = (self.secret_key or "").strip()
        if key.lower() in KNOWN_WEAK_SECRETS or _is_placeholder(key):
            errors.append("SECRET_KEY is a known default/placeholder value")
        if len(key) < MIN_SECRET_LENGTH:
            errors.append(f"SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters")
        if "*" in self.cors_origins:
            errors.append("CORS_ORIGINS must not contain '*' (credentials are allowed)")
        return errors

    def validate_security_posture(self) -> None:
        """Fail closed: refuse to start a non-debug server with a weak secret."""
        if self.debug:
            return
        errors = self.security_posture_errors()
        if errors:
            raise RuntimeError(
                "Insecure configuration: " + "; ".join(errors)
                + ". Generate a key with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance"""
    return Settings()


class DevelopmentSettings(Settings):
    model_config = SettingsConfigDict(env_file=".env.dev", env_file_encoding="utf-8",
                                      case_sensitive=False, extra="ignore")
    debug: bool = True
    log_level: str = "DEBUG"


class ProductionSettings(Settings):
    model_config = SettingsConfigDict(env_file=".env.prod", env_file_encoding="utf-8",
                                      case_sensitive=False, extra="ignore")
    debug: bool = False
    environment: str = "production"
    log_level: str = "WARNING"


def get_settings_for_environment(environment: Optional[str] = None) -> Settings:
    environment = (environment or os.getenv("ENVIRONMENT", "development")).lower()
    if environment == "production":
        return ProductionSettings()
    if environment == "development":
        return DevelopmentSettings()
    return Settings()
