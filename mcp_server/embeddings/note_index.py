"""Ransom note pre-indexing module.

Fetches all known ransom notes from the PRO API, generates embeddings
via Ollama, and stores them in the vector store for similarity search.
"""

from __future__ import annotations

import logging

from mcp_server.api.client import APIClient
from mcp_server.api.pro_api import ProAPI
from mcp_server.embeddings.embed import generate_embedding
from mcp_server.embeddings.vector_store import RansomNoteVectorStore

logger = logging.getLogger("ransomware_intel.embeddings.index")


async def build_note_index(
    vector_store: RansomNoteVectorStore | None = None,
    force_rebuild: bool = False,
) -> int:
    """Fetch all ransom notes from the API and index them.

    This is a setup step — run it once after deployment, or periodically
    to pick up new notes. Skips groups that are already indexed unless
    force_rebuild is True.

    Args:
        vector_store: Optional pre-configured store. Creates one if not provided.
        force_rebuild: If True, re-index everything from scratch.

    Returns:
        Number of notes indexed.
    """
    store = vector_store or RansomNoteVectorStore()

    if force_rebuild:
        logger.info("Rebuilding ransom note index from scratch")
        store.clear()

    existing_count = store.count()
    if existing_count > 0 and not force_rebuild:
        logger.info(
            "Ransom note index already has %d entries. "
            "Use force_rebuild=True to rebuild.",
            existing_count,
        )
        return existing_count

    # Fetch all ransom notes from the PRO API
    async with APIClient() as client:
        pro = ProAPI(client)
        notes = await pro.get_all_ransom_notes()

    if not notes:
        logger.warning(
            "No ransom notes fetched — is the PRO API key configured?"
        )
        return 0

    logger.info("Fetched %d ransom notes, generating embeddings...", len(notes))

    # Generate embeddings and store them
    indexed = 0
    batch: dict[str, tuple[str, list[float]]] = {}

    for group_name, note_text in notes.items():
        if not note_text.strip():
            continue

        embedding = await generate_embedding(note_text)
        if embedding is None:
            logger.warning("Skipping %s — embedding generation failed", group_name)
            continue

        batch[group_name] = (note_text, embedding)

        # Flush in batches of 50
        if len(batch) >= 50:
            count = store.add_notes_batch(batch)
            indexed += count
            batch.clear()

    # Flush remaining
    if batch:
        count = store.add_notes_batch(batch)
        indexed += count

    logger.info("Indexed %d ransom notes into vector store", indexed)
    return indexed
