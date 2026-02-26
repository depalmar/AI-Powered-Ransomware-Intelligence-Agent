"""match_ransom_note tool — compares submitted ransom note text against
known notes using embedding similarity, with keyword fallback.

Returns top 3 candidate groups with confidence scores.
"""

from __future__ import annotations

import logging

from mcp_server.api.client import APIClient
from mcp_server.api.pro_api import ProAPI
from mcp_server.embeddings.embed import (
    cosine_similarity,
    generate_embedding,
    keyword_match,
)
from mcp_server.embeddings.vector_store import RansomNoteVectorStore
from mcp_server.models import RansomNoteMatch

logger = logging.getLogger("ransomware_intel.tools.ransom_note")


async def match_ransom_note(
    note_text: str,
    top_k: int = 3,
) -> list[RansomNoteMatch]:
    """Match a ransom note against known ransomware group notes.

    Attempts embedding-based similarity search first (via Ollama +
    ChromaDB). If embeddings are unavailable, falls back to keyword
    matching.

    Args:
        note_text: Full text content of the ransom note.
        top_k: Number of top matches to return.

    Returns:
        List of RansomNoteMatch objects ranked by similarity.
    """
    if not note_text.strip():
        logger.warning("Empty ransom note text provided")
        return []

    # Try embedding-based matching first
    matches = await _embedding_match(note_text, top_k)
    if matches:
        logger.info(
            "Embedding match found %d candidates, top: %s (%.2f)",
            len(matches),
            matches[0].group_name,
            matches[0].similarity_score,
        )
        return matches

    # Fall back to keyword matching
    logger.info("Falling back to keyword-based matching")
    return _keyword_fallback(note_text, top_k)


async def _embedding_match(note_text: str, top_k: int) -> list[RansomNoteMatch]:
    """Try to match using embedding similarity via the vector store."""
    # Generate embedding for the submitted note
    query_embedding = await generate_embedding(note_text)
    if query_embedding is None:
        logger.info("Embedding generation unavailable — skipping vector search")
        return []

    # Query the vector store
    store = RansomNoteVectorStore()
    if store.count() == 0:
        logger.info("Vector store is empty — attempting direct API comparison")
        return await _direct_api_comparison(note_text, query_embedding, top_k)

    results = store.query_similar(query_embedding, top_k=top_k)
    return [
        RansomNoteMatch(
            group_name=r["group"],
            similarity_score=r["score"],
            matched_note_preview=r.get("preview", ""),
            match_method="embedding",
        )
        for r in results
    ]


async def _direct_api_comparison(
    note_text: str,
    query_embedding: list[float],
    top_k: int,
) -> list[RansomNoteMatch]:
    """If the vector store is empty, try comparing directly against API notes.

    This is slower but works without pre-indexing.
    """
    try:
        async with APIClient() as client:
            pro = ProAPI(client)
            known_notes = await pro.get_all_ransom_notes()
    except Exception as exc:
        logger.warning("Failed to fetch notes from API: %s", exc)
        return []

    if not known_notes:
        return []

    # Embed and compare each known note
    scored: list[RansomNoteMatch] = []
    for group_name, known_text in known_notes.items():
        if not known_text.strip():
            continue

        known_embedding = await generate_embedding(known_text)
        if known_embedding is None:
            continue

        score = cosine_similarity(query_embedding, known_embedding)
        scored.append(
            RansomNoteMatch(
                group_name=group_name,
                similarity_score=round(score, 4),
                matched_note_preview=known_text[:200],
                match_method="embedding",
            )
        )

    scored.sort(key=lambda m: m.similarity_score, reverse=True)
    return scored[:top_k]


def _keyword_fallback(note_text: str, top_k: int) -> list[RansomNoteMatch]:
    """Fall back to keyword-based matching."""
    kw_results = keyword_match(note_text)
    return [
        RansomNoteMatch(
            group_name=group,
            similarity_score=round(score, 4),
            matched_note_preview="",
            match_method="keyword",
        )
        for group, score in kw_results[:top_k]
    ]
