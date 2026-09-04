"""Chunk node text, embed with a pluggable encoder, write to node_chunks.

The encoder is a protocol — tests inject a deterministic stub, production uses
SentenceTransformer. This module never imports SentenceTransformer directly;
load_encoder() is the only place that touches real weights.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable
from typing import Protocol

from sqlalchemy.engine import Connection

from threatlens.graph.store import (
    delete_node_chunks,
    nodes_with_descriptions,
    upsert_node_chunks,
)

logger = logging.getLogger(__name__)

MODEL_NAME = "BAAI/bge-small-en-v1.5"
EMBEDDING_DIM = 384
MAX_CHUNK_WORDS = 300
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


class Encoder(Protocol):
    """Anything that turns a list of strings into a list of float vectors."""

    def encode(self, texts: list[str]) -> list[list[float]]: ...


def load_encoder() -> Encoder:
    """Load the real SentenceTransformer model (CPU only).

    Expensive — call once and pass the result around. Never called in unit tests.
    """
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(MODEL_NAME, device="cpu")

    class _Wrapper:
        def encode(self, texts: list[str]) -> list[list[float]]:
            return model.encode(texts, show_progress_bar=False, convert_to_numpy=True).tolist()

    return _Wrapper()


class StubEncoder:
    """Deterministic fake encoder for unit tests.

    Produces a 384-dim vector derived from the SHA-256 of the input. Same input
    always yields the same vector; different inputs yield different vectors.
    """

    def encode(self, texts: list[str]) -> list[list[float]]:
        return [self._hash_to_vector(t) for t in texts]

    @staticmethod
    def _hash_to_vector(text: str) -> list[float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        raw = list(digest) * (EMBEDDING_DIM // len(digest) + 1)
        vec = [b / 255.0 for b in raw[:EMBEDDING_DIM]]
        return vec


def chunk_text(text: str) -> list[str]:
    """Split text into chunks of roughly MAX_CHUNK_WORDS words.

    Splits on sentence boundaries first, then accumulates sentences until the
    chunk would exceed the word budget. Adjacent chunks overlap by one sentence
    so cross-boundary context is preserved.

    Returns an empty list for empty or whitespace-only text.
    """
    if not text or not text.strip():
        return []

    sentences = [s.strip() for s in SENTENCE_SPLIT.split(text) if s.strip()]
    if not sentences:
        return [text.strip()]

    chunks: list[str] = []
    current_sentences: list[str] = []
    current_words = 0

    for sentence in sentences:
        word_count = len(sentence.split())

        if current_words + word_count > MAX_CHUNK_WORDS and current_sentences:
            chunks.append(" ".join(current_sentences))
            # overlap: keep the last sentence for context continuity
            last = current_sentences[-1]
            current_sentences = [last]
            current_words = len(last.split())

        current_sentences.append(sentence)
        current_words += word_count

    if current_sentences:
        chunks.append(" ".join(current_sentences))

    return chunks


def embed_nodes(
    conn: Connection,
    encoder: Encoder,
    *,
    batch_size: int = 256,
    progress_callback: Callable[[int, int], None] | None = None,
) -> tuple[int, int]:
    """Read nodes, chunk descriptions, embed, write to node_chunks.

    Returns (nodes_processed, chunks_written).
    """
    nodes = nodes_with_descriptions(conn)
    total_nodes = len(nodes)
    total_chunks = 0

    if not nodes:
        return 0, 0

    # Build all (node_id, chunk_ix, text) triples first
    all_pending: list[tuple[str, int, str]] = []
    for node in nodes:
        chunks = chunk_text(node.description or "")
        if not chunks:
            continue
        for ix, chunk_text_str in enumerate(chunks):
            # Prefix with node name for better embedding context
            prefixed = f"{node.name}: {chunk_text_str}"
            all_pending.append((node.id, ix, prefixed))

    if not all_pending:
        return total_nodes, 0

    # Batch-encode all chunk texts
    all_texts = [t for _, _, t in all_pending]
    all_embeddings: list[list[float]] = []

    for i in range(0, len(all_texts), batch_size):
        batch_texts = all_texts[i : i + batch_size]
        batch_embeddings = encoder.encode(batch_texts)
        all_embeddings.extend(batch_embeddings)

    # Delete old chunks and insert new ones, grouped by node
    nodes_seen: set[str] = set()
    chunk_rows: list[dict] = []

    for idx, (node_id, chunk_ix, text_val) in enumerate(all_pending):
        if node_id not in nodes_seen:
            delete_node_chunks(conn, node_id)
            nodes_seen.add(node_id)

        embedding_str = "[" + ",".join(str(v) for v in all_embeddings[idx]) + "]"
        chunk_rows.append(
            {
                "node_id": node_id,
                "chunk_ix": chunk_ix,
                "text": text_val,
                "embedding": embedding_str,
            }
        )

    total_chunks = upsert_node_chunks(conn, chunk_rows)

    if progress_callback:
        progress_callback(total_nodes, total_nodes)

    logger.info("Embedded %d nodes → %d chunks", len(nodes_seen), total_chunks)
    return len(nodes_seen), total_chunks
