"""Tests for retrieval/embed.py — chunking, encoding, and embed_nodes.

Every test uses StubEncoder — a deterministic fake that derives a 384-dim vector
from the SHA-256 of the input string. Real weights are never loaded in this file.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from threatlens.models import Node
from threatlens.retrieval.embed import (
    EMBEDDING_DIM,
    StubEncoder,
    chunk_text,
    embed_nodes,
)

# ── chunk_text ──────────────────────────────────────────────────────────────


class TestChunkShortText:
    """Text under the word budget stays as a single chunk."""

    def test_single_chunk(self):
        text = "This is a short description of a technique."
        chunks = chunk_text(text)
        assert len(chunks) == 1
        assert chunks[0] == text

    def test_two_sentences_under_budget(self):
        text = "First sentence. Second sentence."
        chunks = chunk_text(text)
        assert len(chunks) == 1


class TestChunkLongText:
    """Text exceeding ~300 words produces multiple chunks with overlap."""

    def test_splits_on_sentence_boundary(self):
        # Build a text with many sentences, each ~10 words, totaling >600 words
        sentences = [f"Sentence number {i} has enough words to count properly." for i in range(80)]
        text = " ".join(sentences)
        chunks = chunk_text(text)
        assert len(chunks) > 1
        # Each chunk should be under the word budget (with some tolerance for overlap)
        for chunk in chunks:
            word_count = len(chunk.split())
            # Allow some slack for the overlap sentence
            assert word_count <= 400, f"Chunk has {word_count} words, expected <= 400"

    def test_overlap_preserves_context(self):
        """Adjacent chunks share at least one sentence."""
        sentences = [
            f"Unique sentence {i} with several words in it for testing." for i in range(80)
        ]
        text = " ".join(sentences)
        chunks = chunk_text(text)
        assert len(chunks) >= 2

        # The last sentence of chunk N should appear at the start of chunk N+1
        for i in range(len(chunks) - 1):
            # Extract the last sentence-like portion from chunk i
            chunk_i_words = chunks[i].split()
            chunk_next_words = chunks[i + 1].split()
            # There should be word overlap between the end of chunk i and start of chunk i+1
            overlap = set(chunk_i_words[-10:]) & set(chunk_next_words[:10])
            assert overlap, f"No overlap found between chunk {i} and {i + 1}"


class TestChunkEmptyText:
    """Empty or None input produces no chunks."""

    def test_empty_string(self):
        assert chunk_text("") == []

    def test_whitespace_only(self):
        assert chunk_text("   \n\n  ") == []

    def test_none_description(self):
        assert chunk_text(None) == []


# ── StubEncoder ─────────────────────────────────────────────────────────────


class TestStubEncoder:
    """The stub produces deterministic vectors of the correct dimension."""

    def test_correct_dimension(self):
        enc = StubEncoder()
        vecs = enc.encode(["hello world"])
        assert len(vecs) == 1
        assert len(vecs[0]) == EMBEDDING_DIM

    def test_deterministic(self):
        enc = StubEncoder()
        v1 = enc.encode(["test input"])[0]
        v2 = enc.encode(["test input"])[0]
        assert v1 == v2

    def test_different_inputs_different_vectors(self):
        enc = StubEncoder()
        v1 = enc.encode(["input A"])[0]
        v2 = enc.encode(["input B"])[0]
        assert v1 != v2

    def test_batch_encoding(self):
        enc = StubEncoder()
        vecs = enc.encode(["a", "b", "c"])
        assert len(vecs) == 3
        assert all(len(v) == EMBEDDING_DIM for v in vecs)

    def test_values_normalized(self):
        enc = StubEncoder()
        vec = enc.encode(["normalize check"])[0]
        assert all(0.0 <= v <= 1.0 for v in vec)


# ── embed_nodes ─────────────────────────────────────────────────────────────


def _make_node(node_id: str, description: str | None = None) -> Node:
    return Node(
        id=node_id,
        kind="technique",
        external_id=node_id.split(":")[-1],
        name=f"Name of {node_id}",
        source_url="https://example.com",
        description=description,
    )


class TestEmbedNodes:
    """embed_nodes reads nodes, chunks, encodes, and writes to the DB."""

    def test_writes_chunks(self):
        """Verify embed_nodes calls upsert_node_chunks with correct structure."""
        encoder = StubEncoder()
        mock_conn = MagicMock()
        nodes = [
            _make_node("technique:T0001", "A short technique description."),
            _make_node("technique:T0002", "Another technique with a description."),
        ]

        with (
            patch("threatlens.retrieval.embed.nodes_with_descriptions", return_value=nodes),
            patch("threatlens.retrieval.embed.delete_node_chunks", return_value=0) as mock_delete,
            patch(
                "threatlens.retrieval.embed.upsert_node_chunks",
                side_effect=lambda conn, chunks: len(list(chunks)),
            ) as mock_upsert,
        ):
            n_nodes, n_chunks = embed_nodes(mock_conn, encoder)

        assert n_nodes == 2
        assert n_chunks == 2
        assert mock_delete.call_count == 2
        assert mock_upsert.call_count == 1

        # Verify the chunk dicts have the right keys
        call_args = mock_upsert.call_args
        chunk_rows = call_args[0][1]  # second positional arg
        for row in chunk_rows:
            assert "node_id" in row
            assert "chunk_ix" in row
            assert "text" in row
            assert "embedding" in row

    def test_no_nodes_returns_zero(self):
        """No nodes with descriptions → (0, 0)."""
        encoder = StubEncoder()
        mock_conn = MagicMock()

        with patch("threatlens.retrieval.embed.nodes_with_descriptions", return_value=[]):
            n_nodes, n_chunks = embed_nodes(mock_conn, encoder)

        assert n_nodes == 0
        assert n_chunks == 0

    def test_skips_nodes_without_description(self):
        """Nodes with None/empty description produce no chunks."""
        encoder = StubEncoder()
        mock_conn = MagicMock()
        nodes = [
            _make_node("technique:T0001", None),
            _make_node("technique:T0002", ""),
        ]

        with (
            patch("threatlens.retrieval.embed.nodes_with_descriptions", return_value=nodes),
            patch("threatlens.retrieval.embed.delete_node_chunks", return_value=0),
            patch(
                "threatlens.retrieval.embed.upsert_node_chunks",
                side_effect=lambda conn, chunks: len(list(chunks)),
            ),
        ):
            n_nodes, n_chunks = embed_nodes(mock_conn, encoder)

        # nodes_with_descriptions returned them, but chunk_text returns [] for both
        assert n_chunks == 0

    def test_idempotent_rerun(self):
        """Running embed_nodes twice produces the same chunk count."""
        encoder = StubEncoder()
        mock_conn = MagicMock()
        nodes = [_make_node("technique:T0001", "A real description here.")]

        with (
            patch("threatlens.retrieval.embed.nodes_with_descriptions", return_value=nodes),
            patch("threatlens.retrieval.embed.delete_node_chunks", return_value=0) as mock_delete,
            patch(
                "threatlens.retrieval.embed.upsert_node_chunks",
                side_effect=lambda conn, chunks: len(list(chunks)),
            ),
        ):
            _, n1 = embed_nodes(mock_conn, encoder)
            _, n2 = embed_nodes(mock_conn, encoder)

        assert n1 == n2
        # delete_node_chunks should have been called each time
        assert mock_delete.call_count == 2

    def test_long_description_produces_multiple_chunks(self):
        """A description exceeding 300 words gets split into multiple chunks."""
        encoder = StubEncoder()
        mock_conn = MagicMock()
        long_desc = " ".join(
            [f"Sentence {i} with enough words to make this quite long." for i in range(80)]
        )
        nodes = [_make_node("technique:T0001", long_desc)]

        captured_chunks: list[list[dict]] = []

        def _capture_upsert(conn, chunks):
            rows = list(chunks)
            captured_chunks.append(rows)
            return len(rows)

        with (
            patch("threatlens.retrieval.embed.nodes_with_descriptions", return_value=nodes),
            patch("threatlens.retrieval.embed.delete_node_chunks", return_value=0),
            patch(
                "threatlens.retrieval.embed.upsert_node_chunks",
                side_effect=_capture_upsert,
            ),
        ):
            n_nodes, n_chunks = embed_nodes(mock_conn, encoder)

        assert n_nodes == 1
        assert n_chunks > 1
        # chunk_ix should be sequential starting from 0
        ixs = [row["chunk_ix"] for row in captured_chunks[0]]
        assert ixs == list(range(len(ixs)))


# ── Architecture ────────────────────────────────────────────────────────────


class TestNoLangchainImport:
    """retrieval/ must not import LangChain."""

    def test_no_langchain_in_retrieval(self):
        import importlib
        import sys

        # Ensure the module is loaded
        importlib.import_module("threatlens.retrieval.embed")

        langchain_modules = [name for name in sys.modules if "langchain" in name.lower()]
        assert langchain_modules == [], (
            f"retrieval/ imported LangChain modules: {langchain_modules}"
        )
