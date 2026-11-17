"""Properties of the mappings parser that must hold for any input, not just chosen examples.

The example-based tests pin known cases. These generate hundreds of cells and files — every
separator, spacing, case, and duplicate arrangement — and check the rules that must survive
all of them. Upstream already surprised this parser twice (a byte-order mark, then compound
cells); the next surprise is more likely to be caught here than by a hand-picked example.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from threatlens.ingest.mappings import _technique_ids, parse_mappings_csv

TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

technique_ids = st.builds(
    lambda n, sub: f"T{n:04d}" + ("" if sub is None else f".{sub:03d}"),
    st.integers(0, 9999),
    st.none() | st.integers(0, 999),
)
separators = st.sampled_from([";", ",", "; ", " ;", " , ", ";  ", ",\t"])
padding = st.sampled_from(["", " ", "  ", "\t"])

# A token that is clearly not a technique id and cannot be mistaken for a separator.
junk_tokens = st.text(
    alphabet=st.characters(categories=["L", "N"], include_characters="-_.()"), min_size=1
).filter(lambda t: not TECHNIQUE.match(t.strip().upper()))


@st.composite
def cells(draw, tokens):
    """Join tokens the way upstream might: any separator, any padding, any letter case."""
    parts = []
    for token in tokens:
        cased = token.lower() if draw(st.booleans()) else token
        parts.append(draw(padding) + cased + draw(padding))
    out = parts[0]
    for part in parts[1:]:
        out += draw(separators) + part
    return out


@given(st.data(), st.lists(technique_ids, min_size=1, max_size=8))
def test_any_cell_of_valid_ids_splits_back_into_exactly_those_ids(data, ids):
    cell = data.draw(cells(ids))
    assert _technique_ids(cell) == ([i.upper() for i in ids], 0)


@given(st.data(), st.lists(technique_ids | junk_tokens, min_size=1, max_size=10))
def test_every_token_is_either_kept_or_counted_never_both_never_neither(data, tokens):
    """The ignored-versus-lost rule as an invariant: each non-empty token lands in exactly one
    bucket, and valid ones keep their order."""
    cell = data.draw(cells(tokens))
    valid, invalid = _technique_ids(cell)
    expected_valid = [t.upper() for t in tokens if TECHNIQUE.match(t.upper())]
    assert valid == expected_valid
    assert invalid == len(tokens) - len(expected_valid)


rows = st.lists(
    st.tuples(
        st.integers(1, 30),
        st.lists(technique_ids, max_size=3),
        st.lists(technique_ids, max_size=3),
    ),
    min_size=1,
    max_size=25,
)


@given(rows, st.booleans())
def test_each_pair_appears_once_at_its_strongest_weight(rows, bom):
    """Whatever the duplication and ordering across rows and columns, the result is one edge
    per (CVE, technique) pair, at the highest weight it was listed with."""
    expected: dict[tuple[str, str], float] = {}
    lines = ["CVE ID,Primary Impact,Secondary Impact,Exploitation Technique,Uncategorized,Phase"]
    for cve_n, primary, secondary in rows:
        cve = f"CVE-2020-{cve_n:04d}"
        lines.append(f'{cve},"{"; ".join(primary)}","{"; ".join(secondary)}",,,')
        for ids, weight in ((primary, 1.0), (secondary, 0.5)):
            for tid in ids:
                key = (f"cve:{cve}", f"technique:{tid}")
                expected[key] = max(expected.get(key, 0.0), weight)

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "mappings.csv"
        path.write_bytes((b"\xef\xbb\xbf" if bom else b"") + "\r\n".join(lines).encode())

        if not expected:
            with pytest.raises(ValueError, match="no usable"):
                parse_mappings_csv(path)
            return

        edges, skipped = parse_mappings_csv(path)

    assert {(e.src, e.dst): e.weight for e in edges} == expected
    assert len(edges) == len(expected), "a pair appeared twice"
    assert skipped == 0
    assert all(TECHNIQUE.match(e.dst.removeprefix("technique:")) for e in edges)
