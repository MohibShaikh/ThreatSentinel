"""
AITIA SOC Agent Backend Configuration

Configuration management using Pydantic settings with environment variable support.
"""

import os
from typing import Optional
from pydantic import BaseSettings, Field
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # API Configuration
    app_name: str = "AITIA SOC Agent API"
    version: str = "2.0.0"
    debug: bool = Field(default=False, env="DEBUG")
    
    # Server Configuration
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    
    # Security
    secret_key: str = Field(default="dev-secret-key", env="SECRET_KEY")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # External API Keys
    virustotal_api_key: Optional[str] = Field(default=None, env="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, env="ABUSEIPDB_API_KEY")
    urlvoid_api_key: Optional[str] = Field(default=None, env="URLVOID_API_KEY")
    shodan_api_key: Optional[str] = Field(default=None, env="SHODAN_API_KEY")
    
    # Agent Configuration
    confidence_threshold: float = Field(default=0.7, env="CONFIDENCE_THRESHOLD")
    emergency_threshold: float = Field(default=0.8, env="EMERGENCY_THRESHOLD")
    max_investigation_time: int = Field(default=300, env="MAX_INVESTIGATION_TIME")  # seconds
    
    # Storage Paths
    data_dir: str = Field(default="data", env="DATA_DIR")
    reports_dir: str = Field(default="reports", env="REPORTS_DIR")
    memory_dir: str = Field(default="data/memory", env="MEMORY_DIR")
    logs_dir: str = Field(default="logs", env="LOGS_DIR")
    
    # Database (future)
    database_url: Optional[str] = Field(default=None, env="DATABASE_URL")
    
    # Redis (future)
    redis_url: Optional[str] = Field(default=None, env="REDIS_URL")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        env="LOG_FORMAT"
    )
    
    # Rate Limiting
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_window: int = Field(default=3600, env="RATE_LIMIT_WINDOW")  # seconds
    
    # CORS
    cors_origins: list = Field(default=["*"], env="CORS_ORIGINS")
    
    # Investigation Limits
    max_concurrent_investigations: int = Field(default=10, env="MAX_CONCURRENT_INVESTIGATIONS")
    investigation_timeout: int = Field(default=600, env="INVESTIGATION_TIMEOUT")  # seconds
    
    # Monitoring
    health_check_interval: int = Field(default=60, env="HEALTH_CHECK_INTERVAL")  # seconds
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Create directories if they don't exist
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.memory_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
    
    @property
    def has_threat_intel_keys(self) -> bool:
        """Check if any threat intelligence API keys are configured"""
        return any([
            self.virustotal_api_key,
            self.abuseipdb_api_key,
            self.urlvoid_api_key,
            self.shodan_api_key
        ])
    
    @property
    def configured_apis(self) -> list[str]:
        """Get list of configured API sources"""
        apis = []
        if self.virustotal_api_key:
            apis.append("virustotal")
        if self.abuseipdb_api_key:
            apis.append("abuseipdb")
        if self.urlvoid_api_key:
            apis.append("urlvoid")
        if self.shodan_api_key:
            apis.append("shodan")
        return apis


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


# Development settings
class DevelopmentSettings(Settings):
    """Development-specific settings"""
    debug: bool = True
    log_level: str = "DEBUG"
    
    class Config:
        env_file = ".env.dev"


# Production settings
class ProductionSettings(Settings):
    """Production-specific settings"""
    debug: bool = False
    log_level: str = "WARNING"
    
    class Config:
        env_file = ".env.prod"


def get_settings_for_environment(environment: str = None) -> Settings:
    """Get settings based on environment"""
    if environment is None:
        environment = os.getenv("ENVIRONMENT", "development")
    
    if environment.lower() == "production":
        return ProductionSettings()
    elif environment.lower() == "development":
        return DevelopmentSettings()
    else:
        return Settings() 