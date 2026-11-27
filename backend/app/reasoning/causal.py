"""Causal and temporal reasoning: which evidence explains which, over time and over the topology.

Three tests decide whether item A explains item B: a known mechanism links their findings, A is not later than B (with
a small tolerance for clock skew and sampling), and A and B are related in the topology (same device, neighbours on a
link, or B's site depends on A's device for its service paths). Root causes are the items that explain the most and are
explained by nothing; the result is the root-cause dependency graph.
"""
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache

from app.engine.schema import EvidenceItem, FaultDomain
from app.network.repository import load_topology
from app.reasoning.evidence_model import LABEL, LAYER_OF_DOMAIN, LAYERS, MECHANISMS, SYMPTOMS, layer_of
from app.reasoning.inference import observed

TOLERANCE = timedelta(minutes=2)
# These findings are stamped with the last time things were still fine; the failure itself starts some time after.
LAST_GOOD = {"TELEMETRY_GAP", "DHCP_TRANSACTIONS_STOPPED"}
CLUSTER = timedelta(minutes=2)
SYMPTOM = re.compile(SYMPTOMS)


@lru_cache(maxsize=1)
def topology_relations() -> tuple[dict[str, set[str]], dict[str, str], dict[str, set[str]], dict[str, set[str]]]:
    topology = load_topology()
    neighbours: dict[str, set[str]] = defaultdict(set)
    for link in topology.links:
        neighbours[link.a_device_id].add(link.b_device_id)
        neighbours[link.b_device_id].add(link.a_device_id)
    site_of = {d.device_id: d.site_id for d in topology.devices}
    depends: dict[str, set[str]] = defaultdict(set)  # device -> sites whose service paths cross it
    site_paths: dict[str, set[str]] = defaultdict(set)  # site -> devices on its paths
    for path in topology.paths:
        for device in path.device_ids:
            depends[device].add(path.source_site_id)
            site_paths[path.source_site_id].add(device)
    return dict(neighbours), site_of, dict(depends), dict(site_paths)


def related(cause: EvidenceItem, effect: EvidenceItem) -> tuple[bool, str]:
    neighbours, site_of, depends, _ = topology_relations()
    a, b = cause.device_id, effect.device_id
    if a is None or b is None:
        return True, "site-level evidence"
    if a == b:
        return True, f"same device ({a})"
    if b in neighbours.get(a, set()):
        return True, f"{a} and {b} share a link"
    if site_of.get(b) in depends.get(a, set()) or site_of.get(a) in depends.get(b, set()):
        return True, f"{site_of.get(b)} services depend on {a}"
    return False, "no topological relation"


@dataclass
class CausalEdge:
    cause: str
    effect: str
    mechanism: str
    reason: str
    lag_seconds: int | None
    weight: float


@dataclass
class CausalGraph:
    nodes: list[dict]
    edges: list[CausalEdge]
    roots: list[dict]
    chain: list[str]
    unexplained: list[str]
    coverage: float
    clusters: list[dict] = field(default_factory=list)


def lag(cause: EvidenceItem, effect: EvidenceItem) -> int | None:
    if cause.timestamp is None or effect.timestamp is None:
        return None
    return int((effect.timestamp - cause.timestamp).total_seconds())


def build_graph(evidence: list[EvidenceItem], onset: datetime | None) -> CausalGraph:
    # Raw log records join the graph only when a mechanism covers their finding (fault events, changes); routine logs
    # (logins, NTP, backups) stay out.
    items = [item for item in evidence if item.evidence_type.value != "record"
             or any(m.cause.match(item.code) or m.effect.match(item.code) for m in MECHANISMS)]
    edges: list[CausalEdge] = []
    for cause in items:
        for effect in items:
            if cause.evidence_id == effect.evidence_id:
                continue
            mechanism = next((m for m in MECHANISMS if m.cause.match(cause.code) and m.effect.match(effect.code)), None)
            if mechanism is None:
                continue
            seconds = lag(cause, effect)
            if seconds is not None and seconds < -TOLERANCE.total_seconds() and effect.code not in LAST_GOOD:
                continue  # the effect happened clearly before its supposed cause
            ok, why = related(cause, effect)
            if not ok:
                continue
            weight = (1.0 if observed(cause) else 0.7) * (1.0 if seconds is not None else 0.8)
            edges.append(CausalEdge(cause.evidence_id, effect.evidence_id, mechanism.name, f"{mechanism.explanation}; {why}", seconds,
                                    round(weight, 2)))
    # Break two-way edges (both orders pass the tolerance): keep the earlier cause, or the stronger mechanism.
    pairs = {(e.cause, e.effect): e for e in edges}
    by_id = {item.evidence_id: item for item in items}
    for (a, b), edge in list(pairs.items()):
        reverse = pairs.get((b, a))
        if reverse is None or (a, b) not in pairs:
            continue
        ta, tb = by_id[a].timestamp, by_id[b].timestamp
        drop = (b, a) if (ta and tb and ta <= tb) or (not (ta and tb) and edge.weight >= reverse.weight) else (a, b)
        pairs.pop(drop, None)
    edges = list(pairs.values())
    children: dict[str, set[str]] = defaultdict(set)
    parents: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        children[edge.cause].add(edge.effect)
        parents[edge.effect].add(edge.cause)

    def descendants(node: str) -> set[str]:
        seen, stack = set(), [node]
        while stack:
            for child in children.get(stack.pop(), ()):
                if child not in seen:
                    seen.add(child)
                    stack.append(child)
        return seen

    roots = []
    for item in items:
        node = item.evidence_id
        if children.get(node) and not parents.get(node):
            explained = descendants(node)
            roots.append({"evidence_id": node, "code": item.code, "device_id": item.device_id, "summary": item.summary,
                          "explains": sorted(explained, key=lambda x: int(x[1:]) if x[1:].isdigit() else 0),
                          "timestamp": item.timestamp.isoformat() if item.timestamp else None, "layer": layer_of(item.code)})
    roots.sort(key=lambda r: (-len(r["explains"]), r["timestamp"] or "9999"))
    symptoms = [item.evidence_id for item in items if SYMPTOM.match(item.code)]
    covered = set().union(*(set(r["explains"]) for r in roots)) if roots else set()
    unexplained = [s for s in symptoms if s not in covered]
    coverage = 1.0 if not symptoms else round(len([s for s in symptoms if s in covered]) / len(symptoms), 2)
    chain: list[str] = []
    if roots:
        node = roots[0]["evidence_id"]
        chain.append(node)
        while children.get(node) and len(chain) < 6:
            node = max(children[node], key=lambda c: (len(descendants(c)), -int(c[1:]) if c[1:].isdigit() else 0))
            if node in chain:
                break
            chain.append(node)
    nodes = [{"evidence_id": i.evidence_id, "code": i.code, "device_id": i.device_id, "layer": layer_of(i.code),
              "role": "root" if any(r["evidence_id"] == i.evidence_id for r in roots) else
              ("symptom" if SYMPTOM.match(i.code) else ("effect" if parents.get(i.evidence_id) else "context")),
              "timestamp": i.timestamp.isoformat() if i.timestamp else None} for i in items]
    return CausalGraph(nodes, edges, roots, chain, unexplained, coverage, temporal_clusters(items, onset))


def temporal_clusters(items: list[EvidenceItem], onset: datetime | None) -> list[dict]:
    """Evidence grouped into bursts no more than two minutes apart, each placed relative to the reported onset."""
    dated = sorted((i for i in items if i.timestamp), key=lambda i: i.timestamp)
    clusters: list[list[EvidenceItem]] = []
    for item in dated:
        if clusters and item.timestamp - clusters[-1][-1].timestamp <= CLUSTER:
            clusters[-1].append(item)
        else:
            clusters.append([item])
    return [{"start": c[0].timestamp.isoformat(), "end": c[-1].timestamp.isoformat(),
             "seconds_from_onset": int((c[0].timestamp - onset).total_seconds()) if onset else None,
             "evidence_ids": [i.evidence_id for i in c], "codes": sorted({i.code for i in c})} for c in clusters]


def precedence(evidence: list[EvidenceItem], onset: datetime | None) -> list[dict]:
    """Changes and faults that came before the onset, ordered by how close they were to it."""
    if onset is None:
        return []
    changes = [i for i in evidence if i.timestamp and i.timestamp <= onset + TOLERANCE
               and any(k in i.code for k in ("CHANGE", "CONFIG", "RULE_MODIFIED", "MTU", "HELPER"))]
    return [{"evidence_id": i.evidence_id, "code": i.code, "device_id": i.device_id,
             "seconds_before_onset": int((onset - i.timestamp).total_seconds())}
            for i in sorted(changes, key=lambda i: onset - i.timestamp)]


def localise(affected_sites: list[str], unaffected_sites: list[str]) -> dict:
    """Graph-based localisation: devices on every affected site's service paths and on no unaffected site's paths."""
    _, site_of, _, site_paths = topology_relations()
    sites = [s for s in affected_sites if s in site_paths]
    if not sites:
        return {"common_devices": [], "excluded_by_unaffected": [], "shared": False}
    common = set.intersection(*(site_paths[s] for s in sites))
    excluded = set().union(*(site_paths[s] for s in unaffected_sites if s in site_paths)) if unaffected_sites else set()
    candidates = sorted(d for d in common - excluded if site_of[d] not in sites or len(sites) == 1)
    return {"common_devices": candidates, "excluded_by_unaffected": sorted(common & excluded), "shared": len(sites) > 1 and bool(candidates)}


def cross_layer(evidence: list[EvidenceItem], conclusion: FaultDomain | None) -> dict:
    """Evidence placed on its layer, the lowest failing layer, and whether the conclusion sits on it. A fault at a lower
    layer usually explains symptoms above it, so the lowest failing layer is where a root cause is most often found."""
    by_layer: dict[str, list[str]] = defaultdict(list)
    for item in evidence:
        if item.evidence_type.value == "record":
            continue
        by_layer[layer_of(item.code)].append(item.evidence_id)
    failing = [layer for layer in LAYERS if by_layer.get(layer)]
    lowest = next((layer for layer in ("physical", "data_link", "network", "transport_policy", "services") if by_layer.get(layer)), None)
    conclusion_layer = LAYER_OF_DOMAIN.get(conclusion) if conclusion else None
    if conclusion_layer is None or lowest is None:
        assessment = "not enough layered evidence to compare"
    elif conclusion_layer == lowest or conclusion_layer == "platform":
        assessment = f"the conclusion ({LABEL[conclusion]}) sits at the lowest failing layer ({lowest.replace('_', ' ')})"
    elif LAYERS.index(conclusion_layer) > LAYERS.index(lowest):
        assessment = (f"the conclusion is at the {conclusion_layer.replace('_', ' ')} layer, but there is also {lowest.replace('_', ' ')} "
                      "evidence below it; check whether that lower-layer evidence is a cause or a side effect")
    else:
        assessment = f"the conclusion ({LABEL[conclusion]}) is below every other failing layer"
    return {"layers": {layer: by_layer.get(layer, []) for layer in LAYERS}, "failing_layers": failing, "lowest_failing_layer": lowest,
            "conclusion_layer": conclusion_layer, "assessment": assessment}
