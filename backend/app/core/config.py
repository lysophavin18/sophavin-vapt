"""
Kouprey Security Configuration
Environment-based settings management
"""

from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import List
import secrets


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=False, env="DEBUG")
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    
    # Security
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_hex(32), env="SECRET_KEY")
    JWT_SECRET: str = Field(default_factory=lambda: secrets.token_hex(32), env="JWT_SECRET")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    
    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://kouprey:password@localhost:5432/kouprey_vapt",
        env="DATABASE_URL"
    )
    
    # Redis
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    
    # CORS
    ALLOWED_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:80"],
        env="ALLOWED_ORIGINS"
    )
    
    @validator("ALLOWED_ORIGINS", pre=True)
    def parse_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    # Rate Limiting
    RATE_LIMIT_SCANS: int = Field(default=10, env="RATE_LIMIT_SCANS")
    RATE_LIMIT_WINDOW: int = Field(default=3600, env="RATE_LIMIT_WINDOW")  # seconds
    
    # Scan Settings
    SCAN_TIMEOUT: int = Field(default=7200, env="SCAN_TIMEOUT")  # 2 hours
    MAX_CPU_PERCENT: int = Field(default=80, env="MAX_CPU_PERCENT")
    MAX_RAM_PERCENT: int = Field(default=85, env="MAX_RAM_PERCENT")
    
    # OpenVAS Configuration
    OPENVAS_HOST: str = Field(default="openvas", env="OPENVAS_HOST")
    OPENVAS_PORT: int = Field(default=9392, env="OPENVAS_PORT")
    OPENVAS_USER: str = Field(default="admin", env="OPENVAS_USER")
    OPENVAS_PASSWORD: str = Field(default="", env="OPENVAS_PASSWORD")
    
    # ZAP Configuration
    ZAP_HOST: str = Field(default="zap", env="ZAP_HOST")
    ZAP_PORT: int = Field(default=8080, env="ZAP_PORT")
    ZAP_API_KEY: str = Field(default="", env="ZAP_API_KEY")
    
    # File Paths
    RESULTS_DIR: str = "/app/results"
    REPORTS_DIR: str = "/app/reports"
    
    # AI Configuration
    AI_PROVIDER: str = Field(default="openai", env="AI_PROVIDER")  # openai, anthropic, ollama
    OPENAI_API_KEY: str = Field(default="", env="OPENAI_API_KEY")
    OPENAI_MODEL: str = Field(default="gpt-4o", env="OPENAI_MODEL")
    ANTHROPIC_API_KEY: str = Field(default="", env="ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL: str = Field(default="claude-sonnet-4-20250514", env="ANTHROPIC_MODEL")
    OLLAMA_HOST: str = Field(default="http://localhost:11434", env="OLLAMA_HOST")
    OLLAMA_MODEL: str = Field(default="llama3.2", env="OLLAMA_MODEL")
    AI_MAX_TOKENS: int = Field(default=4096, env="AI_MAX_TOKENS")
    AI_TEMPERATURE: float = Field(default=0.3, env="AI_TEMPERATURE")
    
    # CVE Database Configuration
    NVD_API_KEY: str = Field(default="", env="NVD_API_KEY")  # Optional but recommended for higher rate limits
    CVE_CACHE_TTL: int = Field(default=86400, env="CVE_CACHE_TTL")  # 24 hours in seconds
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
