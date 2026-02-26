"""Configuration management for the Ransomware Intelligence MCP Server.

Loads settings from environment variables with sensible defaults.
All config is centralized here so tool modules don't read env vars directly.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Ransomware.live API
    ransomware_live_api_base: str = "https://api.ransomware.live"
    ransomware_live_pro_key: str = ""

    # Ollama (embeddings + local LLM)
    ollama_base_url: str = "http://localhost:11434"
    ollama_embed_model: str = "nomic-embed-text"
    ollama_model: str = "llama3"

    # LLM backend for LangGraph agent
    llm_backend: str = "claude"
    anthropic_api_key: str = ""

    # Agent behavior
    confidence_threshold: float = 0.65
    default_output_format: str = "markdown"

    # Rate limiting
    api_rate_limit_per_second: float = 2.0
    api_max_retries: int = 3
    api_timeout_seconds: float = 30.0

    # Vector store
    chroma_persist_dir: str = "chroma_data"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @property
    def has_pro_api(self) -> bool:
        """Check if a PRO API key is configured."""
        return bool(self.ransomware_live_pro_key)

    @property
    def has_anthropic(self) -> bool:
        """Check if an Anthropic API key is configured."""
        return bool(self.anthropic_api_key)


# Singleton instance — import this in other modules
settings = Settings()
