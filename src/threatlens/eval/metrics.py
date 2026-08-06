"""Retrieval and grounding metrics.

Pure functions — no pipeline, no LLM, no I/O. They exist before any retrieval
code so that the naive baseline and the full system are scored by the exact same
functions. A baseline measured with throwaway code and compared against harness
output later is not a comparison, and the headline claim rests on that comparison
being real.

Every function here is deliberately deterministic: the ablation table must be
reproducible without an API call.
"""

from __future__ import annotations


def recall_at_k(predicted: list[str], gold: set[str], k: int) -> float:
    """1.0 if any gold item appears in the top-k predictions, else 0.0.

    This is a per-query binary: did the system surface a correct answer
    within its top k? The ablation table averages this over the holdout.
    """
    if not gold:
        return 0.0
    return 1.0 if set(predicted[:k]) & gold else 0.0


def mrr(predicted: list[str], gold: set[str]) -> float:
    """Mean Reciprocal Rank: 1/rank of the first correct prediction.

    Returns 0.0 if no prediction matches any gold item.
    """
    for index, item in enumerate(predicted, start=1):
        if item in gold:
            return 1.0 / index
    return 0.0


def path_correct(path: list[str], expected_kinds: list[str]) -> bool:
    """Did the traversal walk the expected sequence of node kinds?

    Node recall alone does not demonstrate multi-hop retrieval; the *path*
    does. A system that finds T1190 by vector similarity scores on recall
    but fails path_correct because it never walked CVE → technique → tactic.

    Args:
        path: list of node IDs like ["cve:CVE-2021-44228", "technique:T1190", ...]
        expected_kinds: list of expected kind prefixes like ["cve", "technique", "tactic"]
    """
    if len(path) != len(expected_kinds):
        return False
    return all(
        node_id.split(":", 1)[0] == kind for node_id, kind in zip(path, expected_kinds, strict=True)
    )


def citation_coverage(claims: list[str], evidence_ids: set[str]) -> float:
    """Fraction of cited node IDs that resolve to the evidence set.

    Target is 1.0 — every claim the model makes must trace back to a node
    it was shown. An ungrounded citation is a bug, not a style preference.

    No claims means nothing was asserted, so nothing is ungrounded → 1.0.
    """
    if not claims:
        return 1.0
    return sum(1 for c in claims if c in evidence_ids) / len(claims)
