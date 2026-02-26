"""Vector store management for ransom note embeddings.

Uses ChromaDB to persist pre-embedded ransom notes. Supports adding,
querying, and rebuilding the index.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from mcp_server.config import settings

logger = logging.getLogger("ransomware_intel.embeddings.store")


class RansomNoteVectorStore:
    """ChromaDB-backed vector store for ransom note similarity search.

    Stores pre-embedded ransom notes keyed by group name. Supports
    querying by embedding vector to find similar notes.
    """

    COLLECTION_NAME = "ransom_notes"

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = persist_dir or settings.chroma_persist_dir
        self._client: Any = None
        self._collection: Any = None

    def _ensure_store(self) -> Any:
        """Lazily initialize the ChromaDB client and collection."""
        if self._collection is not None:
            return self._collection

        try:
            import chromadb

            persist_path = Path(self._persist_dir)
            persist_path.mkdir(parents=True, exist_ok=True)

            self._client = chromadb.PersistentClient(path=str(persist_path))
            self._collection = self._client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            logger.info(
                "ChromaDB collection '%s' ready (%d documents)",
                self.COLLECTION_NAME,
                self._collection.count(),
            )
            return self._collection
        except ImportError:
            logger.warning("chromadb not installed — vector store unavailable")
            return None
        except Exception as exc:
            logger.warning("Failed to initialize ChromaDB: %s", exc)
            return None

    def add_note(
        self,
        group_name: str,
        note_text: str,
        embedding: list[float],
    ) -> bool:
        """Add a ransom note to the vector store.

        Args:
            group_name: Ransomware group name (used as document ID).
            note_text: Full ransom note text.
            embedding: Pre-computed embedding vector.

        Returns:
            True if successfully added, False otherwise.
        """
        collection = self._ensure_store()
        if collection is None:
            return False

        try:
            collection.upsert(
                ids=[group_name],
                embeddings=[embedding],
                documents=[note_text],
                metadatas=[{"group": group_name}],
            )
            return True
        except Exception as exc:
            logger.error("Failed to add note for %s: %s", group_name, exc)
            return False

    def add_notes_batch(
        self,
        notes: dict[str, tuple[str, list[float]]],
    ) -> int:
        """Add multiple ransom notes to the store.

        Args:
            notes: Dict mapping group_name → (note_text, embedding).

        Returns:
            Number of notes successfully added.
        """
        collection = self._ensure_store()
        if collection is None:
            return 0

        ids = []
        embeddings = []
        documents = []
        metadatas = []

        for group_name, (note_text, embedding) in notes.items():
            ids.append(group_name)
            embeddings.append(embedding)
            documents.append(note_text)
            metadatas.append({"group": group_name})

        if not ids:
            return 0

        try:
            collection.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas,
            )
            return len(ids)
        except Exception as exc:
            logger.error("Failed to batch-add notes: %s", exc)
            return 0

    def query_similar(
        self,
        embedding: list[float],
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """Find the most similar ransom notes to the given embedding.

        Args:
            embedding: Query embedding vector.
            top_k: Number of results to return.

        Returns:
            List of dicts with keys: group, score, preview.
        """
        collection = self._ensure_store()
        if collection is None:
            return []

        try:
            results = collection.query(
                query_embeddings=[embedding],
                n_results=min(top_k, max(collection.count(), 1)),
                include=["documents", "metadatas", "distances"],
            )
        except Exception as exc:
            logger.error("Vector store query failed: %s", exc)
            return []

        matches: list[dict[str, Any]] = []
        if not results or not results.get("ids"):
            return matches

        ids = results["ids"][0]
        distances = results.get("distances", [[]])[0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]

        for i, doc_id in enumerate(ids):
            # ChromaDB cosine distance = 1 - similarity
            distance = distances[i] if i < len(distances) else 1.0
            similarity = 1.0 - distance
            doc_text = documents[i] if i < len(documents) else ""
            meta = metadatas[i] if i < len(metadatas) else {}

            matches.append({
                "group": meta.get("group", doc_id),
                "score": round(similarity, 4),
                "preview": doc_text[:200] if doc_text else "",
            })

        return matches

    def count(self) -> int:
        """Get the number of notes in the store."""
        collection = self._ensure_store()
        if collection is None:
            return 0
        return collection.count()

    def clear(self) -> None:
        """Delete all notes from the store."""
        collection = self._ensure_store()
        if collection is None:
            return
        try:
            if self._client:
                self._client.delete_collection(self.COLLECTION_NAME)
                self._collection = None
        except Exception as exc:
            logger.error("Failed to clear vector store: %s", exc)
