"""Configuration management for the analyzer service."""

from enum import Enum
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class ObfuscationLevel(str, Enum):
    """Obfuscation levels for sensitive data."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    PARANOID = "paranoid"


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Server settings
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8080, description="Server port")
    debug: bool = Field(default=False, description="Debug mode")
    
    # Obfuscation settings
    obfuscation_level: ObfuscationLevel = Field(
        default=ObfuscationLevel.STANDARD,
        description="Level of data obfuscation"
    )
    
    # LLM settings
    llm_provider: LLMProvider = Field(
        default=LLMProvider.OLLAMA,
        description="LLM provider to use"
    )
    llm_model: str = Field(
        default="llama3.2",
        description="Model name to use"
    )
    llm_temperature: float = Field(
        default=0.1,
        description="Temperature for LLM responses"
    )
    llm_max_tokens: int = Field(
        default=2048,
        description="Maximum tokens in response"
    )
    
    # Provider-specific settings
    ollama_url: str = Field(
        default="http://localhost:11434",
        description="Ollama API URL"
    )
    openai_api_key: Optional[str] = Field(
        default=None,
        description="OpenAI API key"
    )
    openai_base_url: Optional[str] = Field(
        default=None,
        description="OpenAI API base URL (for Azure or compatible APIs)"
    )
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API key"
    )
    
    # Cache settings
    cache_enabled: bool = Field(
        default=True,
        description="Enable response caching"
    )
    cache_ttl: int = Field(
        default=3600,
        description="Cache TTL in seconds"
    )
    cache_max_size: int = Field(
        default=1000,
        description="Maximum cache entries"
    )
    
    # Loki settings
    loki_url: Optional[str] = Field(
        default=None,
        description="Loki push URL for logging"
    )
    
    class Config:
        env_prefix = "ANALYZER_"
        case_sensitive = False


settings = Settings()
