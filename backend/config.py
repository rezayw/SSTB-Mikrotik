from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import Optional
import secrets


class Settings(BaseSettings):
    # App Security — MUST be set via environment variable
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database
    DATABASE_URL: str

    # Redis / Celery
    REDIS_URL: str = "redis://redis:6379"

    # MikroTik — MUST be set via environment variable
    MIKROTIK_API_URL: str
    MIKROTIK_API_USER: str
    MIKROTIK_API_PASSWORD: str

    # Threat Intelligence APIs — optional, features degrade gracefully if missing
    NVD_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ALIENVAULT_API_KEY: Optional[str] = None
    THREAT_FOX_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    # Threat scoring
    THREAT_SCORE_THRESHOLD: float = 5.0
    AUTO_BLOCK_ENABLED: bool = True

    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_must_be_strong(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    class Config:
        env_file = ".env.local"
        extra = "ignore"


settings = Settings()
