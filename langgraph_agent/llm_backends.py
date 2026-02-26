"""LLM backend abstraction for the LangGraph agent.

Supports both Ollama (local models) and Claude API as reasoning backends.
Switches based on the LLM_BACKEND environment variable.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("ransomware_intel.agent.llm")


def get_llm(
    backend: str | None = None,
    temperature: float = 0.0,
    **kwargs: Any,
) -> Any:
    """Get an LLM instance based on the configured backend.

    Args:
        backend: "claude" or "ollama". Defaults to LLM_BACKEND env var.
        temperature: LLM temperature (default 0.0 for deterministic output).
        **kwargs: Additional keyword arguments passed to the LLM constructor.

    Returns:
        A LangChain-compatible LLM instance.

    Raises:
        ImportError: If the required LangChain package is not installed.
        ValueError: If the backend is not recognized.
    """
    backend = backend or os.getenv("LLM_BACKEND", "claude")

    if backend == "claude":
        return _get_claude_llm(temperature, **kwargs)
    elif backend == "ollama":
        return _get_ollama_llm(temperature, **kwargs)
    else:
        raise ValueError(
            f"Unknown LLM backend: {backend}. Use 'claude' or 'ollama'."
        )


def _get_claude_llm(temperature: float, **kwargs: Any) -> Any:
    """Create a Claude API LLM via langchain-anthropic."""
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError as exc:
        raise ImportError(
            "langchain-anthropic is required for Claude backend. "
            "Install with: pip install langchain-anthropic"
        ) from exc

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not set — Claude API calls will fail")

    model = kwargs.pop("model", "claude-sonnet-4-20250514")

    return ChatAnthropic(
        model=model,
        temperature=temperature,
        api_key=api_key,
        max_tokens=4096,
        **kwargs,
    )


def _get_ollama_llm(temperature: float, **kwargs: Any) -> Any:
    """Create a local Ollama LLM via langchain-ollama."""
    try:
        from langchain_ollama import ChatOllama
    except ImportError as exc:
        raise ImportError(
            "langchain-ollama is required for Ollama backend. "
            "Install with: pip install langchain-ollama"
        ) from exc

    model = kwargs.pop("model", os.getenv("OLLAMA_MODEL", "llama3"))
    base_url = kwargs.pop("base_url", os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))

    return ChatOllama(
        model=model,
        temperature=temperature,
        base_url=base_url,
        **kwargs,
    )
