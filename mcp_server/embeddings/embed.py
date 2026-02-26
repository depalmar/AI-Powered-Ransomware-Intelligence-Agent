"""Ollama embedding integration for ransom note similarity matching.

Uses nomic-embed-text via Ollama to generate embeddings. Falls back
gracefully if Ollama is not running — the agent continues to work
with keyword-based matching instead.
"""

from __future__ import annotations

import logging
import re
from typing import Sequence

from mcp_server.config import settings

logger = logging.getLogger("ransomware_intel.embeddings")


async def generate_embedding(text: str) -> list[float] | None:
    """Generate an embedding vector for the given text using Ollama.

    Args:
        text: Text to embed.

    Returns:
        Embedding vector as a list of floats, or None if Ollama is unavailable.
    """
    try:
        import ollama as ollama_client

        response = ollama_client.embed(
            model=settings.ollama_embed_model,
            input=text,
        )
        # ollama.embed returns {"embeddings": [[...]]}
        embeddings = response.get("embeddings", [])
        if embeddings:
            return embeddings[0]
        return None
    except ImportError:
        logger.warning("ollama package not installed — embedding unavailable")
        return None
    except Exception as exc:
        logger.warning("Ollama embedding failed (is Ollama running?): %s", exc)
        return None


async def generate_embeddings_batch(texts: Sequence[str]) -> list[list[float] | None]:
    """Generate embeddings for multiple texts.

    Args:
        texts: Sequence of texts to embed.

    Returns:
        List of embedding vectors (None for any that failed).
    """
    results: list[list[float] | None] = []
    for text in texts:
        vec = await generate_embedding(text)
        results.append(vec)
    return results


def cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """Compute cosine similarity between two vectors.

    Args:
        vec_a: First vector.
        vec_b: Second vector.

    Returns:
        Cosine similarity score between -1.0 and 1.0.
    """
    if len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = sum(a * a for a in vec_a) ** 0.5
    norm_b = sum(b * b for b in vec_b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Keyword-based fallback matching
# ---------------------------------------------------------------------------

# Common patterns found in ransom notes, mapped to groups they're associated with
_GROUP_KEYWORDS: dict[str, list[str]] = {
    "lockbit": [
        "lockbit", "lockbit 3.0", "lockbit3", "lb3", "restore-my-files",
        "lockbit-decryptor", "lockbit ransomware",
    ],
    "alphv": [
        "alphv", "blackcat", "recover-files", "access key",
        "alphv-decryptor",
    ],
    "clop": [
        "clop", "cl0p", "clop ransomware", "moveit",
    ],
    "blackbasta": [
        "black basta", "blackbasta", "basta", "instructions_read_me",
    ],
    "royal": [
        "royal", "royal ransomware", ".royal",
    ],
    "akira": [
        "akira", "akira_readme", "akira ransomware",
    ],
    "play": [
        "play ransomware", "play news", ".play",
    ],
    "rhysida": [
        "rhysida", "rhysida ransomware", "criticaldataexfiltration",
    ],
    "medusa": [
        "medusa", "medusa ransomware", "medusalocker",
    ],
    "bianlian": [
        "bianlian", "bian lian", "look at this instruction",
    ],
    "hunters": [
        "hunters international", "hunters", "huntersinternational",
    ],
    "ransomhub": [
        "ransomhub", "ransom hub",
    ],
    "inc": [
        "inc ransom", "inc ransomware", "inc.",
    ],
    "8base": [
        "8base", "8 base",
    ],
}


def keyword_match(note_text: str) -> list[tuple[str, float]]:
    """Fall back to keyword/regex matching when embeddings are unavailable.

    Scans the ransom note text for known group-associated keywords and
    returns ranked matches with a rough confidence score.

    Args:
        note_text: Full text of the ransom note.

    Returns:
        List of (group_name, score) tuples sorted by score descending.
        Scores are rough estimates between 0.0 and 1.0.
    """
    text_lower = note_text.lower()
    scores: dict[str, float] = {}

    for group, keywords in _GROUP_KEYWORDS.items():
        hits = 0
        for kw in keywords:
            if kw.lower() in text_lower:
                hits += 1
            # Also try regex word-boundary match
            elif re.search(rf"\b{re.escape(kw)}\b", text_lower, re.IGNORECASE):
                hits += 0.5
        if hits > 0:
            # Normalize: more keyword hits = higher confidence, cap at 0.85
            scores[group] = min(hits / len(keywords), 0.85)

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return ranked
