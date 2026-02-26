"""Configuration for the LangGraph agent."""

from __future__ import annotations

import os


class AgentConfig:
    """Configuration for the LangGraph ransomware intelligence agent."""

    def __init__(
        self,
        llm_backend: str | None = None,
        confidence_threshold: float | None = None,
        output_format: str | None = None,
    ) -> None:
        self.llm_backend = llm_backend or os.getenv("LLM_BACKEND", "claude")
        self.confidence_threshold = confidence_threshold or float(
            os.getenv("CONFIDENCE_THRESHOLD", "0.65")
        )
        self.output_format = output_format or os.getenv(
            "DEFAULT_OUTPUT_FORMAT", "markdown"
        )
