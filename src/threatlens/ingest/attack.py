"""Parse an ATT&CK STIX 2.1 bundle into nodes and edges.

Pure: no database, no network. Feed it a file path, get a Graph back.

Four things about the STIX format are easy to get wrong, and each one fails silently —
the parser still returns a graph, it is just missing data nobody notices until the
numbers downstream look strange. Each has a test:

  - A technique's ATT&CK id (T1190) is not a field on the object. It lives in
    external_references.
  - Technique -> tactic is not a relationship object. It comes from kill_chain_phases.
  - Retired techniques are still in the bundle and must be filtered out.
  - The ATT&CK version lives on a separate collection object.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from threatlens.models import Edge, Graph, Node

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

log = logging.getLogger(__name__)

STIX_KIND = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "course-of-action": "mitigation",
    "intrusion-set": "actor",
    "malware": "software",
    "tool": "software",
}

# (relationship_type, src_kind, dst_kind) -> (edge_kind, reverse)
RELATIONSHIP_EDGES = {
    ("mitigates", "mitigation", "technique"): ("MITIGATED_BY", True),
    ("uses", "actor", "technique"): ("USES", False),
    ("uses", "actor", "software"): ("USES_SOFTWARE", False),
    ("subtechnique-of", "technique", "technique"): ("SUBTECHNIQUE_OF", False),
}

# Relationship types we model at all. A type outside this set is out of scope, not
# "skipped" — conflating the two would make the skipped count meaningless on the real
# bundle, where thousands of `detects` relationships exist that we deliberately ignore.
MODELLED_RELATIONSHIP_TYPES = frozenset(k[0] for k in RELATIONSHIP_EDGES)


def _attack_ref(obj: dict) -> tuple[str, str] | None:
    """Pull the ATT&CK id and its documentation URL out of a STIX object.

    The id (T1190, M1030, G0016) is not a top-level field — it sits in
    external_references alongside references to CAPEC, NIST and others, so the
    source_name has to be checked. Objects also carry a STIX uuid, but nothing outside
    this bundle uses it: the CVE mappings, the ATT&CK website, and every analyst all
    speak T####. Miss this and nothing can be joined to anything.

    Returns (external_id, url), or None when the object has no ATT&CK identity.
    """
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"], ref.get("url", "")
    return None


def _is_dead(obj: dict) -> bool:
    """Has this object been retired?

    MITRE keeps revoked and deprecated objects in the bundle rather than deleting them,
    so consumers pinned to an older version do not break. They can never be correct
    answers, but they would compete in search and drag recall down.
    """
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _collection_version(objects: list[dict]) -> str:
    """Find which ATT&CK release this bundle is.

    Recorded against every ingest so a result can be reproduced later. "Built against
    ATT&CK v19.1" is checkable; "built against ATT&CK" is not.
    """
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version", "unknown")
    return "unknown"


def _tactic_order(objects: list[dict]) -> dict[str, int]:
    """Map each tactic's STIX id to its position in the kill chain.

    Nothing on a tactic object records where it sits in the sequence. The matrix object
    is the only place the order appears, as `tactic_refs` listed front to back, so
    reconnaissance first and impact last.

    Deriving it rather than hard-coding a list matters: v19.2 renamed Defense Evasion to
    Stealth and split Defense Impairment out of it, so any list written before that
    release is now both wrong and the wrong length.

    Returns an empty map when the bundle carries no matrix, which leaves every tactic
    unplaced rather than guessing an order.
    """
    matrix = next((o for o in objects if o.get("type") == "x-mitre-matrix"), None)
    if matrix is None:
        return {}
    return {ref: i for i, ref in enumerate(matrix.get("tactic_refs", []))}


def _node_attrs(obj: dict, kind: str, tactic_order: dict[str, int]) -> dict:
    """Per-kind extras worth keeping on the node.

    A tactic's shortname is what kill_chain_phases refers to it by, so keeping it here
    means the technique-to-tactic lookup can be derived from the nodes rather than
    threaded out of the parser separately. Its order is kept for the same reason —
    chain derivation needs to know which of two tactics comes first, and reading it off
    the node avoids re-parsing the bundle at derivation time.
    """
    if kind == "technique":
        return {"is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False))}
    if kind == "tactic":
        return {
            "shortname": obj.get("x_mitre_shortname", ""),
            # None, not a sentinel index. A tactic absent from the matrix has no place in
            # the kill chain, and a fabricated 0 would read as "first".
            "order": tactic_order.get(obj.get("id", "")),
        }
    return {}


def _build_nodes(objects: list[dict]) -> tuple[list[Node], int]:
    """Turn every STIX object we model into a Node.

    Returns the nodes plus a count of objects that should have become nodes and did not,
    so a degraded bundle is visible rather than quietly smaller.
    """
    nodes: dict[str, Node] = {}
    skipped = 0
    tactic_order = _tactic_order(objects)

    for obj in objects:
        kind = STIX_KIND.get(obj.get("type", ""))
        if kind is None:
            continue
        if _is_dead(obj):
            skipped += 1
            continue
        ref = _attack_ref(obj)
        if ref is None:
            skipped += 1
            log.warning("no mitre-attack reference on %s", obj.get("id"))
            continue

        external_id, url = ref
        node = Node(
            id=Node.make_id(kind, external_id),
            kind=kind,
            external_id=external_id,
            name=obj.get("name", external_id),
            source_url=url,
            description=obj.get("description"),
            stix_id=obj.get("id"),
            attrs=_node_attrs(obj, kind, tactic_order),
        )
        # Keyed by id, so two objects claiming the same ATT&CK id collapse to one node
        # rather than producing a duplicate the database would then reject.
        nodes[node.id] = node

    return list(nodes.values()), skipped


def _belongs_to_edges(
    objects: list[dict],
    by_stix: dict[str, Node],
    tactic_by_shortname: dict[str, Node],
    source: str,
) -> tuple[list[Edge], int]:
    """Link each technique to the tactics it belongs to.

    There is no relationship object for this. STIX models it as a "kill chain phase"
    on the technique itself, naming the tactic by shortname ("initial-access") rather
    than by id. Looking for a relationship instead produces zero tactic edges, and a
    graph that cannot answer the most basic question asked of it.

    A technique can sit in several tactics, which is why this yields one edge per phase
    rather than one per technique.
    """
    edges: list[Edge] = []
    skipped = 0

    for obj in objects:
        if obj.get("type") != "attack-pattern" or _is_dead(obj):
            continue
        node = by_stix.get(obj.get("id", ""))
        if node is None:
            continue
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tactic = tactic_by_shortname.get(phase.get("phase_name", ""))
            if tactic is None:
                skipped += 1
                log.warning("unknown tactic shortname %r", phase.get("phase_name"))
                continue
            edges.append(Edge(src=node.id, dst=tactic.id, kind="BELONGS_TO", source=source))

    return edges, skipped


def _relationship_edges(
    objects: list[dict], by_stix: dict[str, Node], out_of_scope_refs: set[str], source: str
) -> tuple[list[Edge], int]:
    """Turn STIX relationship objects into edges.

    The kind pair matters as well as the type: `uses` means one thing from an actor to
    a technique and another from an actor to a piece of software, so both endpoints are
    checked before an edge kind is chosen.

    `out_of_scope_refs` holds the STIX ids of objects present in the bundle whose *type*
    this schema does not model. It is what separates an edge we chose not to model from
    an edge we lost, and only the second is counted. An id absent from the bundle
    entirely is not out of scope — it is a broken reference, and it counts.
    """
    edges: list[Edge] = []
    skipped = 0

    for obj in objects:
        if obj.get("type") != "relationship" or _is_dead(obj):
            continue
        rel_type = obj.get("relationship_type", "")
        if rel_type not in MODELLED_RELATIONSHIP_TYPES:
            continue  # out of scope, not skipped

        src_ref, dst_ref = obj.get("source_ref", ""), obj.get("target_ref", "")

        # An endpoint of a type we never model is out of scope, exactly like an
        # unmodelled relationship_type above. ATT&CK v19.2 has 1,318 `uses` edges
        # pointing at `campaign` objects; counting those made the real bundle report
        # 1,723 losses when 2 objects were actually lost, and a loss alarm that reads
        # 1,723 on a healthy bundle is one nobody looks at again.
        if src_ref in out_of_scope_refs or dst_ref in out_of_scope_refs:
            continue

        src = by_stix.get(src_ref)
        dst = by_stix.get(dst_ref)
        if src is None or dst is None:
            # One end was filtered out (retired, or missing an ATT&CK id), so the edge
            # goes with it. An edge to a node that does not exist breaks traversal.
            skipped += 1
            continue
        mapping = RELATIONSHIP_EDGES.get((rel_type, src.kind, dst.kind))
        if mapping is None:
            continue
        edge_kind, reverse = mapping
        a, b = (dst, src) if reverse else (src, dst)
        edges.append(Edge(src=a.id, dst=b.id, kind=edge_kind, source=source))

    return edges, skipped


def parse_bundle(path: Path) -> Graph:
    """Read an ATT&CK STIX bundle and return the graph it describes.

    Usage:
        graph = parse_bundle(Path("data/raw/enterprise-attack.json"))

    Anything dropped along the way is counted into Graph.skipped rather than discarded
    quietly. A parser that loses edges without saying so still returns a graph that
    looks perfectly reasonable, and the loss only surfaces much later as numbers that
    are hard to explain.

    Raises KeyError if the file is not a STIX bundle, JSONDecodeError if it is not JSON.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = raw["objects"]

    version = _collection_version(objects)
    source = f"attack-stix v{version}"

    nodes, skipped = _build_nodes(objects)

    # Both lookups are views over the nodes we just built. Relationships reference
    # objects by STIX uuid; kill_chain_phases references tactics by shortname.
    by_stix = {n.stix_id: n for n in nodes if n.stix_id}
    tactic_by_shortname = {
        n.attrs["shortname"]: n for n in nodes if n.kind == "tactic" and n.attrs.get("shortname")
    }

    # Objects the schema has no kind for. A relationship touching one of these is a
    # modelling boundary, not a loss, so it must not reach the skipped count.
    out_of_scope_refs = {
        obj["id"]
        for obj in objects
        if obj.get("id") and obj.get("type") not in STIX_KIND and obj.get("type") != "relationship"
    }

    belongs_to, skipped_phases = _belongs_to_edges(objects, by_stix, tactic_by_shortname, source)
    relationships, skipped_rels = _relationship_edges(objects, by_stix, out_of_scope_refs, source)

    return Graph(
        nodes=nodes,
        edges=belongs_to + relationships,
        version=version,
        skipped=skipped + skipped_phases + skipped_rels,
    )


def ingest_attack(path: Path, sha256: str, conn: Connection) -> tuple[int, int]:
    """Parse the bundle and write it. Returns (node_count, edge_count).

    Nodes go first — edges carry foreign keys pointing at them.
    """
    from threatlens.graph.store import record_ingest_run, upsert_edges, upsert_nodes

    graph = parse_bundle(path)
    n_nodes = upsert_nodes(conn, graph.nodes)
    n_edges = upsert_edges(conn, graph.edges)
    record_ingest_run(conn, "attack-stix", graph.version, sha256, n_nodes, n_edges)
    if graph.skipped:
        log.info("skipped %d objects (revoked, deprecated, or dangling)", graph.skipped)
    return n_nodes, n_edges
