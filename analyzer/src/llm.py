"""LLM provider abstraction for security analysis."""

from abc import ABC, abstractmethod
from typing import Optional

import httpx
import structlog

from .config import LLMProvider, settings

logger = structlog.get_logger()


class BaseLLMProvider(ABC):
    """Base class for LLM providers."""
    
    @abstractmethod
    async def analyze(self, prompt: str) -> str:
        """Send prompt to LLM and return response."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the provider is available."""
        pass


class OllamaProvider(BaseLLMProvider):
    """Ollama LLM provider for local/self-hosted models."""
    
    def __init__(self):
        self.base_url = settings.ollama_url
        self.model = settings.llm_model
        self.client = httpx.AsyncClient(timeout=120.0)
    
    async def analyze(self, prompt: str) -> str:
        """Send prompt to Ollama and return response."""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": settings.llm_temperature,
                        "num_predict": settings.llm_max_tokens,
                    }
                }
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            logger.error("Ollama request failed", error=str(e))
            raise
    
    async def health_check(self) -> bool:
        """Check if Ollama is available."""
        try:
            response = await self.client.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except Exception:
            return False


class OpenAIProvider(BaseLLMProvider):
    """OpenAI/Azure OpenAI provider."""
    
    def __init__(self):
        from openai import AsyncOpenAI
        
        self.model = settings.llm_model
        self.client = AsyncOpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
        )
    
    async def analyze(self, prompt: str) -> str:
        """Send prompt to OpenAI and return response."""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Kubernetes security analyst specializing in runtime threat detection and incident response."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=settings.llm_temperature,
                max_tokens=settings.llm_max_tokens,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error("OpenAI request failed", error=str(e))
            raise
    
    async def health_check(self) -> bool:
        """Check if OpenAI is available."""
        try:
            await self.client.models.list()
            return True
        except Exception:
            return False


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude provider."""
    
    def __init__(self):
        from anthropic import AsyncAnthropic
        
        self.model = settings.llm_model
        self.client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    
    async def analyze(self, prompt: str) -> str:
        """Send prompt to Anthropic and return response."""
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=settings.llm_max_tokens,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                system="You are a Kubernetes security analyst specializing in runtime threat detection and incident response.",
            )
            return response.content[0].text
        except Exception as e:
            logger.error("Anthropic request failed", error=str(e))
            raise
    
    async def health_check(self) -> bool:
        """Check if Anthropic is available."""
        try:
            # Simple validation - Anthropic doesn't have a models endpoint
            return settings.anthropic_api_key is not None
        except Exception:
            return False


def get_llm_provider() -> BaseLLMProvider:
    """Factory function to get configured LLM provider."""
    provider_map = {
        LLMProvider.OLLAMA: OllamaProvider,
        LLMProvider.OPENAI: OpenAIProvider,
        LLMProvider.ANTHROPIC: AnthropicProvider,
    }
    
    provider_class = provider_map.get(settings.llm_provider)
    if not provider_class:
        raise ValueError(f"Unknown LLM provider: {settings.llm_provider}")
    
    return provider_class()


# Global provider instance (lazy initialization)
_provider: Optional[BaseLLMProvider] = None


def get_provider() -> BaseLLMProvider:
    """Get or create the global LLM provider instance."""
    global _provider
    if _provider is None:
        _provider = get_llm_provider()
    return _provider
