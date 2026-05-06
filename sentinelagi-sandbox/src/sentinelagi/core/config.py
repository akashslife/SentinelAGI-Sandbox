"""
SentinelAGI Configuration Management

Centralized configuration using Pydantic Settings with environment variable
support and validation.
"""

import os
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SandboxConfig(BaseSettings):
    """Docker/gVisor sandbox configuration."""
    model_config = SettingsConfigDict(env_prefix="SANDBOX_")
    
    runtime: str = Field(default="runsc", description="Container runtime: runsc (gVisor) or runc")
    image: str = Field(default="sentinelagi/agent-sandbox:latest")
    network_mode: str = Field(default="none")
    cpu_quota: float = Field(default=1.0, description="CPU cores limit")
    memory_limit: str = Field(default="512m")
    storage_limit: str = Field(default="1g")
    max_execution_time: int = Field(default=300, description="Max execution time in seconds")
    enable_seccomp: bool = Field(default=True)
    enable_apparmor: bool = Field(default=True)
    read_only_rootfs: bool = Field(default=True)
    no_new_privileges: bool = Field(default=True)
    drop_capabilities: List[str] = Field(default_factory=lambda: [
        "ALL"
    ])
    add_capabilities: List[str] = Field(default_factory=list)
    allowed_mounts: List[str] = Field(default_factory=list)
    env_allowlist: List[str] = Field(default_factory=lambda: [
        "PATH", "PYTHONPATH", "LANG", "LC_ALL"
    ])


class RedisConfig(BaseSettings):
    """Redis connection and stream configuration."""
    model_config = SettingsConfigDict(env_prefix="REDIS_")
    
    host: str = Field(default="localhost")
    port: int = Field(default=6379)
    db: int = Field(default=0)
    password: Optional[str] = Field(default=None)
    ssl: bool = Field(default=False)
    stream_maxlen: int = Field(default=100000, description="Max audit stream length")
    stream_ttl: int = Field(default=86400 * 7, description="Stream entry TTL in seconds")
    alert_channel: str = Field(default="sentinelagi:alerts")
    audit_stream: str = Field(default="sentinelagi:audit")
    metrics_key_prefix: str = Field(default="sentinelagi:metrics")


class SecurityConfig(BaseSettings):
    """Security and permission configuration."""
    model_config = SettingsConfigDict(env_prefix="SECURITY_")
    
    secret_key: str = Field(default="change-me-in-production")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expiry_hours: int = Field(default=24)
    max_tool_calls_per_minute: int = Field(default=60)
    max_concurrent_agents: int = Field(default=10)
    enable_constitutional_ai: bool = Field(default=True)
    enable_mitre_atlas_mapping: bool = Field(default=True)
    privilege_escalation_threshold: int = Field(default=3, description="Alerts after N violations")
    auto_kill_on_violation: bool = Field(default=False)
    audit_all_actions: bool = Field(default=True)


class AgentConfig(BaseSettings):
    """Agent behavior and orchestration configuration."""
    model_config = SettingsConfigDict(env_prefix="AGENT_")
    
    max_planning_steps: int = Field(default=20)
    max_correction_attempts: int = Field(default=3)
    enable_self_correction: bool = Field(default=True)
    long_horizon_threshold: int = Field(default=5, description="Steps before considered long-horizon")
    critic_model: str = Field(default="gpt-4")
    executor_model: str = Field(default="gpt-4")
    planner_model: str = Field(default="gpt-4")
    temperature: float = Field(default=0.1)


class Settings(BaseSettings):
    """Global application settings."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )
    
    app_name: str = Field(default="SentinelAGI Sandbox")
    app_version: str = Field(default="1.0.0")
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    
    # Sub-configs
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    
    # OpenAI
    openai_api_key: Optional[str] = Field(default=None)
    openai_base_url: Optional[str] = Field(default=None)
    
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production", "testing"}
        if v.lower() not in allowed:
            raise ValueError(f"environment must be one of {allowed}")
        return v.lower()


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings."""
    return settings
