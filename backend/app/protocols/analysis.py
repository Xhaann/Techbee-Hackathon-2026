"""Protocol analysis report: runs the requested engines, then correlates every finding with the rest of the evidence.

Correlation reuses earlier layers instead of re-deriving them:
- configuration changes and fault records from the core dataset (Phase A data), with the command parser of the change
  history tool;
- topology relations, localisation of a shared upstream device and the causal graph builder from Phase 2;
- Phase 1 packet journeys and traffic shifts, for routing and transport findings;
- the Phase 2 Bayesian fault model over the combined evidence, and its incident correlation (only incidents the caller
  may see are passed in).
Every evidence reference is checked against the records that exist; the report says if any does not.
"""
import re
from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.diagnostics.history import COMMAND
from app.engine.schema import EvidenceItem, EvidenceType
from app.network.repository import load_scenario, load_topology
from app.protocols.registry import BY_NAME, ENGINES, ProtocolCorrelation, ProtocolEngineResult, ProtocolFinding, run_engines
from app.protocols.repository import load_telemetry, record_index
from app.reasoning.causal import build_graph, localise
from app.reasoning.evidence_model import LABEL
from app.reasoning.inference import calibrate, percent, posterior, uncertainty
from app.reasoning.report import RelatedIncident, correlate_incidents
from app.security.provenance import record_index as core_index

CHANGE_TYPES = {"CONFIG_CHANGE", "CONFIG_COMMAND_LOGGED", "MTU_CHANGE", "POLICY_CHANGE", "ZONE_RELOAD"}
ROUTINE = {"LOGIN_SUCCESS", "NTP_SYNC", "CONFIG_ARCHIVED", "BACKUP_COMPLETED", "CONTENT_UPDATE", "SERVICE_HEALTH", "STP_STABLE",
           "SYSTEM_HEALTH", "ADMIN_LOGIN"}
CHANGE_WINDOW = timedelta(minutes=60)
SYMPTOM_CODES = {"TCP_RETRANSMISSION_HIGH", "TCP_HANDSHAKE_FAILURES", "TCP_RTT_INFLATION", "MCAST_NO_TRAFFIC", "IPV6_REACHABILITY_LOSS",
                 "QOS_CONGESTION_DROPS"}
SEVERITY_RANK = {"critical": 0, "major": 1, "minor": 2, "info": 3}
# A confirmed fault outranks a possible explanation whatever else is true: a minor "possible" finding is never put ahead of a
# measured fault as the cause.
STATUS_RANK = {"confirmed_fault": 0, "possible_explanation": 1}
STATUS_WORD = {"confirmed_fault": "confirmed", "possible_explanation": "possible", "suspicious_indicator": "suspicious"}
JOURNEY_CODES = {"BGP_ROUTE_LEAK", "BGP_ORIGIN_HIJACK_SUSPECTED", "MTU_BLACK_HOLE", "TCP_HANDSHAKE_FAILURES", "MCAST_RPF_FAILURE"}
SERVICE_TARGET = {"application": "10.100.100.40", "internet": "198.51.100.15", "files": "10.100.100.40"}
# Engines worth running next when a finding of one kind is present (offered, never run without approval).
FOLLOW_UP = {
    "TCP_RETRANSMISSION_HIGH": ["mtu", "qos", "stp"], "TCP_HANDSHAKE_FAILURES": ["nat", "bgp", "mtu"], "TCP_RTT_INFLATION": ["qos", "stp"],
    "MCAST_RPF_FAILURE": ["bgp"], "MCAST_NO_TRAFFIC": ["multicast", "bgp"], "ARP_GATEWAY_SPOOFING": ["tls", "threats"],
    "TLS_UNEXPECTED_CERTIFICATE": ["arp", "threats"], "SUSPICIOUS_PORT_SCAN": ["lateral", "threats"], "SUSPICIOUS_BEACONING": ["threats", "lateral"],
    "LATERAL_ADMIN_FANOUT": ["traffic", "threats"], "IPV6_REACHABILITY_LOSS": ["ipv6"], "OSPF_LSA_CHURN": ["tcp"], "VLAN_PRUNED": ["stp"],
    "STP_LOOP": ["arp", "tcp"], "NAT_TOP_CONSUMER": ["traffic"], "BGP_SESSION_DOWN": ["ipsec", "tcp"], "IPSEC_PEER_UNREACHABLE": ["bgp", "tcp"],
}
SYMPTOM_ENGINES = [
    (re.compile(r"voice|call|choppy|robotic|jitter|priority", re.I), ["qos", "tcp"]),
    (re.compile(r"large|download|upload|file cop|stall|hang|vpn overlay|mtu|fragment", re.I), ["mtu", "tcp"]),
    (re.compile(r"slow|retrans|timeout|lag", re.I), ["tcp", "stp"]),
    (re.compile(r"wi-?fi|wireless|ssid|access point", re.I), ["wireless"]),
    (re.compile(r"certificate|tls|ssl|https|not private", re.I), ["tls"]),
    (re.compile(r"vpn|tunnel|ipsec", re.I), ["ipsec"]),
    (re.compile(r"internet|website|nat", re.I), ["nat", "tcp"]),
    (re.compile(r"ipv6|dual.?stack", re.I), ["ipv6"]),
    (re.compile(r"video|stream|multicast", re.I), ["multicast"]),
    (re.compile(r"loop|storm|flapping|lights flash", re.I), ["stp"]),
    (re.compile(r"phone|vlan|trunk", re.I), ["vlan"]),
    (re.compile(r"duplicate|conflict|drops off|keeps losing", re.I), ["arp"]),
    (re.compile(r"route|bgp|unreachable|ospf", re.I), ["bgp", "ospf"]),
    (re.compile(r"security|ids|scan|attack|malware|suspicious|unusual|beacon|exfil|lateral|intrus", re.I), ["traffic", "lateral", "threats"]),
]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProtocolHypothesis(Model):
    domain: str
    label: str
    probability: float
    shown: str


class ProtocolCausalEdge(Model):
    cause: str
    effect: str
    mechanism: str
    reason: str


class ProtocolNextCheck(Model):
    engine: str
    title: str
    reason: str


class ProtocolValidation(Model):
    grounded: bool
    references_checked: int
    issues: list[str] = Field(default_factory=list)


class ProtocolReport(Model):
    scenario_id: str
    synthetic: Literal[True] = True
    data_source: str = "Synthetic protocol and security telemetry generated locally; no device or live network was contacted."
    scope: dict[str, str | None]
    engines: list[ProtocolEngineResult]
    findings: list[ProtocolFinding]
    counts: dict[str, int]
    headline: str
    root_causes: list[str]
    # Suspicious indicators that the causal graph links to confirmed symptoms: candidate causes, never stated as confirmed.
    suspected_causes: list[str] = Field(default_factory=list)
    causal_edges: list[ProtocolCausalEdge]
    causal_chain: list[str]
    hypotheses: list[ProtocolHypothesis]
    uncertainty: str
    threats: list[str]
    notes: list[str]
    missing: list[str]
    next_checks: list[ProtocolNextCheck]
    related_incidents: list[RelatedIncident] = Field(default_factory=list)
    validation: ProtocolValidation


def core_records(dataset) -> list[EvidenceItem]:
    items = []
    for event in dataset.events:
        if event.event_type in ROUTINE and event.severity.value in ("informational", "debug"):
            continue
        if event.event_type in ROUTINE:
            continue
        items.append(EvidenceItem(evidence_id=f"C{len(items) + 1}", call_id="core", tool="core_dataset", evidence_type=EvidenceType.RECORD,
                                  code=event.event_type, device_id=event.device_id, summary=event.message[:300], timestamp=event.timestamp,
                                  references=[{"collection": "events", "record_id": event.event_id, "timestamp": event.timestamp}]))
    return items


def representative_device(finding: ProtocolFinding) -> str | None:
    if finding.device_id:
        return finding.device_id
    branches = [s for s in finding.affected_sites if s in ("NYC", "SIN", "BLR")]
    return f"{branches[0]}-RTR-01" if len(branches) == 1 else None


def as_item(index: int, finding: ProtocolFinding) -> EvidenceItem:
    kind = EvidenceType.OBSERVED_FINDING if finding.status == "confirmed_fault" else EvidenceType.INFERRED_FINDING
    return EvidenceItem(evidence_id=f"P{index}", call_id="protocols", tool=f"protocol:{finding.engine}", evidence_type=kind, code=finding.code,
                        device_id=representative_device(finding), summary=finding.summary[:300], timestamp=finding.timestamp,
                        references=finding.evidence[:10])


def change_line(event) -> str:
    match = COMMAND.search(event.message)
    if match:
        return f"'{match['command'][:90]}' by {match['user']}"
    return event.message[:110]


def correlate_changes(finding: ProtocolFinding, dataset, topology) -> list[ProtocolCorrelation]:
    at = finding.timestamp or dataset.scenario.onset_at
    site_devices = {d.device_id for d in topology.devices if d.site_id in finding.affected_sites}
    devices = {finding.device_id} if finding.device_id else site_devices
    devices |= {d for d in (finding.facts.get("seen_on") or []) if isinstance(d, str)}
    hub = finding.facts.get("hub")
    if isinstance(hub, dict) is False and isinstance(hub, str):
        devices.add(hub)
    out = []
    for event in dataset.events:
        if event.event_type not in CHANGE_TYPES or event.device_id not in devices:
            continue
        gap = at - event.timestamp
        if timedelta(minutes=-2) <= gap <= CHANGE_WINDOW:
            minutes = int(gap.total_seconds() // 60)
            when = f"{minutes} min before" if minutes > 0 else "at the same time as"
            out.append(ProtocolCorrelation(kind="config_change", detail=f"{event.event_type.replace('_', ' ').lower()} on {event.device_id} {when} this finding: "
                                                                 f"{change_line(event)}",
                                   evidence=[{"collection": "events", "record_id": event.event_id, "timestamp": event.timestamp}]))
    return out[:3]


def timing(finding: ProtocolFinding, onset: datetime) -> ProtocolCorrelation | None:
    if finding.timestamp is None:
        return None
    seconds = int((finding.timestamp - onset).total_seconds())
    if abs(seconds) < 60:
        text = "starts at the reported onset"
    elif seconds < 0:
        text = f"starts {abs(seconds) // 60} min before the reported onset" if abs(seconds) < 86400 else "predates the incident window"
    else:
        text = f"starts {seconds // 60} min after the reported onset"
    return ProtocolCorrelation(kind="timing", detail=f"{finding.title} {text} ({finding.timestamp:%H:%M} UTC).")


def journey(scenario_id: str, finding: ProtocolFinding) -> ProtocolCorrelation | None:
    from app.observability.journey import trace
    sites = [s for s in finding.affected_sites if s in ("NYC", "SIN", "BLR")]
    if not sites:
        return None
    site = next((s for s in sites if s != finding.site_id), sites[0])
    service = finding.facts.get("service", "application")
    target = SERVICE_TARGET.get(service, "10.100.100.40")
    try:
        result = trace(scenario_id, f"{site}-SW-01", target, "tcp", 443)
    except Exception:  # a journey that cannot be traced is simply not shown
        return None
    hops = " → ".join(h["device_id"] for h in result["hops"])
    verdict = result.get("verdict_text") or result.get("verdict", "")
    return ProtocolCorrelation(kind="packet_journey", detail=f"Packet journey {site} → {target}: {hops} ({verdict.lower()}; path MTU {result.get('path_mtu')}).",
                       evidence=[{"collection": e["collection"], "record_id": e["record_id"], "timestamp": e.get("timestamp")}
                                 for e in result.get("evidence", [])[:2]])


def traffic(scenario_id: str, finding: ProtocolFinding) -> ProtocolCorrelation | None:
    from app.observability.traffic import traffic_summary
    sites = [s for s in finding.affected_sites if s in ("NYC", "SIN", "BLR")]
    if not sites:
        return None
    shifts = [s for s in traffic_summary(scenario_id)["traffic_shifts"] if s["site_id"] in sites]
    if not shifts:
        return None
    text = "; ".join(f"{s['site_id']} {s['service']} {s['flows_per_minute_before']:g} → {s['flows_per_minute_after']:g} flows/min" for s in shifts[:3])
    return ProtocolCorrelation(kind="traffic", detail=f"Flow records show traffic dropping off after the onset: {text}.")


def topology_note(finding: ProtocolFinding, all_sites: list[str]) -> ProtocolCorrelation | None:
    sites = [s for s in finding.affected_sites if s in ("NYC", "SIN", "BLR")]
    if len(sites) < 2:
        return None
    shared = localise(sites, [s for s in all_sites if s not in sites])["common_devices"]
    if not shared:
        return None
    return ProtocolCorrelation(kind="topology", detail=f"{', '.join(sites)} are affected together; the devices only their paths share are {', '.join(shared[:4])}.")


def suspected(findings: list[ProtocolFinding], roots: list[str]) -> list[str]:
    """Suspicious indicators that explain a confirmed symptom no fault explains, most symptoms explained first."""
    by_id = {f.finding_id: f for f in findings}
    covered = {e for r in roots for e in by_id[r].explains}
    open_symptoms = {f.finding_id for f in findings if f.status == "confirmed_fault" and f.code in SYMPTOM_CODES and f.finding_id not in covered}
    candidates = [f for f in findings if f.status == "suspicious_indicator" and f.code != "THREAT_CORRELATED_ACTIVITY"
                  and set(f.explains) & open_symptoms]
    candidates.sort(key=lambda f: (-len(set(f.explains) & open_symptoms), -(f.confidence or 0), f.finding_id))
    return [f.finding_id for f in candidates]


def describe(finding: ProtocolFinding) -> str:
    return f"{finding.title} ({STATUS_WORD.get(finding.status, finding.status)}, {finding.confidence_label or 'unknown'} confidence)"


def headline(findings: list[ProtocolFinding], roots: list[str], threats: list[str], suspects: list[str] | None = None) -> str:
    by_id = {f.finding_id: f for f in findings}
    effects = [f for f in findings if f.status == "confirmed_fault" and any(x.startswith("core:") for x in f.explained_by)]
    symptoms = [f for f in findings if f.code in SYMPTOM_CODES and f.status == "confirmed_fault"]
    if not roots and suspects:
        lead = next((s for s in symptoms if suspects[0] in s.explained_by), symptoms[0] if symptoms else None)
        cause = by_id[suspects[0]]
        start = f"{lead.title}. " if lead else ""
        return (f"{start}Suspected cause, not confirmed: {cause.title} (suspicious indicator). It fits the symptoms, but verify it before "
                "treating it as the cause or as an attack.")
    if not roots and (effects or symptoms):
        lead = (effects or symptoms)[0]
        core = next((c.detail for c in lead.correlations if c.kind == "core_evidence"), None)
        if core is None and any(x.startswith("core:") for x in lead.explained_by):
            change = next((c.detail for c in lead.correlations if c.kind == "config_change"), None)
            core = f"It follows a {change[0].lower() + change[1:]}" if change else None
        if core:
            return f"{lead.title}: an effect, not the cause. {core}"
        return f"{lead.title}. No protocol cause found: the cause is outside these checks."
    if roots:
        lead = by_id[roots[0]]
        text = f"Likely cause: {describe(lead)}."
        # A second cause the first does not explain (another tunnel, another site, a minor contributor) is named, not hidden.
        other = next((by_id[r] for r in roots[1:] if r not in lead.explains), None)
        if other is not None:
            text += f" {'Also' if other.status == 'confirmed_fault' else 'Secondary'}: {describe(other)}."
        return text
    if threats:
        lead = by_id[threats[0]]
        return f"{lead.title}: {lead.facts.get('likelihood', 'possible')} on correlated indicators, not confirmed; an analyst should review it."
    confirmed = [f for f in findings if f.status == "confirmed_fault"]
    if confirmed:
        return f"{confirmed[0].title} (confirmed)."
    suspicious = [f for f in findings if f.status == "suspicious_indicator"]
    if suspicious:
        return f"{suspicious[0].title} (suspicious, not confirmed)."
    possible = [f for f in findings if f.status == "possible_explanation"]
    if possible:
        gaps = " Some data is missing too." if any(f.status == "insufficient_evidence" for f in findings) else ""
        return f"Possible: {possible[0].title}. Nothing confirmed.{gaps}"
    if any(f.status == "insufficient_evidence" for f in findings):
        return "No problem found in the data available, but some data is missing, so this is not a clean bill of health."
    return "No protocol or security problem found in these checks."


def analyze(scenario_id: str, engines: list[str] | None = None, site_id: str | None = None, device_id: str | None = None,
            symptoms: str = "", current_incident: dict[str, Any] | None = None, other_incidents: list[dict[str, Any]] | None = None) -> ProtocolReport:
    topology, dataset = load_topology(), load_scenario(scenario_id)
    telemetry = load_telemetry(scenario_id)
    names = [n for n in (engines or [e.name for e in ENGINES]) if n in BY_NAME]
    results, findings = run_engines(topology, dataset, telemetry, names, site_id, device_id)
    onset = dataset.scenario.onset_at
    active = [f for f in findings if f.status != "insufficient_evidence"]
    # ---- causal graph over protocol findings plus core change and fault records (Phase 2 builder)
    items = [as_item(i + 1, f) for i, f in enumerate(active)]
    by_item = {item.evidence_id: f for item, f in zip(items, active)}
    records = core_records(dataset)
    graph = build_graph(items + records, onset)
    record_by_id = {r.evidence_id: r for r in records}
    edges = []
    for edge in graph.edges:
        cause = by_item.get(edge.cause)
        effect = by_item.get(edge.effect)
        if effect is None:
            continue
        if cause is not None:
            if cause.finding_id not in effect.explained_by:
                effect.explained_by.append(cause.finding_id)
                cause.explains.append(effect.finding_id)
            edges.append(ProtocolCausalEdge(cause=cause.finding_id, effect=effect.finding_id, mechanism=edge.mechanism, reason=edge.reason[:200]))
        elif edge.cause in record_by_id:
            record = record_by_id[edge.cause]
            core_id = f"core:{record.references[0].record_id}"
            if core_id not in effect.explained_by:
                effect.explained_by.append(core_id)
            if record.code in CHANGE_TYPES and not any(e.record_id == record.references[0].record_id for c in effect.correlations for e in c.evidence):
                match = COMMAND.search(record.summary)
                what = f"'{match['command'][:90]}' by {match['user']}" if match else record.summary[:110]
                effect.correlations.append(ProtocolCorrelation(kind="config_change", detail=f"{record.code.replace('_', ' ').lower()} on {record.device_id} at "
                                                                                    f"{record.timestamp:%H:%M} UTC: {what}", evidence=record.references[:1]))
            if record.code not in CHANGE_TYPES:  # changes are reported once, as config_change correlations
                effect.correlations.append(ProtocolCorrelation(kind="core_evidence", detail=f"Explained by {record.code.replace('_', ' ').lower()} on {record.device_id} at "
                                                                                     f"{record.timestamp:%H:%M} UTC: {record.summary[:140]}",
                                                       evidence=record.references[:1]))
            edges.append(ProtocolCausalEdge(cause=f"core:{record.references[0].record_id}", effect=effect.finding_id, mechanism=edge.mechanism,
                                        reason=edge.reason[:200]))
    # Root causes: faults nothing else explains. Symptoms (retransmissions, missing traffic) are never roots: when nothing
    # in the protocol data explains them the report says the cause lies elsewhere instead of promoting the symptom.
    fault_like = [f for f in active if f.status in ("confirmed_fault", "possible_explanation") and f.kind not in ("coverage", "conflicting_state") and f.code not in SYMPTOM_CODES]
    # A configuration change that introduced a misconfiguration is its trigger, not a reason to demote it to an effect.
    changes = {f"core:{r.references[0].record_id}" for r in records if r.code in CHANGE_TYPES}
    roots = [f.finding_id for f in fault_like if not [x for x in f.explained_by if x not in changes]]
    by_id = {f.finding_id: f for f in findings}
    ranked = sorted(roots, key=lambda fid: (STATUS_RANK.get(by_id[fid].status, 2), -len(by_id[fid].explains), SEVERITY_RANK[by_id[fid].severity],
                                            -(by_id[fid].confidence or 0)))
    for f in findings:
        f.root_cause = f.finding_id in ranked
    chain = []
    if ranked:
        node = ranked[0]
        while node and node not in chain and len(chain) < 6:
            chain.append(node)
            current = next(f for f in findings if f.finding_id == node)
            node = current.explains[0] if current.explains else None
    # ---- per-finding correlation
    sites = [s.site_id for s in topology.sites if s.site_id in ("NYC", "SIN", "BLR")]
    journeys = 0
    event_device = {e.event_id: e.device_id for e in dataset.events}
    path_devices = {path.path_id: set(path.device_ids) for path in topology.paths}
    for f in active:
        cited = {e.record_id for c in f.correlations for e in c.evidence}
        f.correlations[:0] = [c for c in correlate_changes(f, dataset, topology) if c.evidence[0].record_id not in cited]
        # Changes on a device the affected service actually crosses come first (a change elsewhere is context, not cause).
        on_path = set().union(*(path_devices.get(p, set()) for p in f.facts.get("paths", []))) if f.facts.get("paths") else set()
        if on_path:
            f.correlations.sort(key=lambda c: (c.kind != "config_change", not (c.evidence and event_device.get(c.evidence[0].record_id) in on_path)))
        note = timing(f, onset)
        if note:
            f.correlations.append(note)
        note = topology_note(f, sites)
        if note:
            f.correlations.append(note)
        if f.code in JOURNEY_CODES and journeys < 3:
            note = journey(scenario_id, f)
            if note:
                journeys += 1
                f.correlations.append(note)
        if f.code.startswith("TCP_") or f.code in ("NAT_POOL_EXHAUSTED", "BGP_ROUTE_LEAK", "STP_LOOP"):
            note = traffic(scenario_id, f)
            if note:
                f.correlations.append(note)
        for other in f.explained_by:
            if not other.startswith("core:"):
                f.correlations.append(ProtocolCorrelation(kind="protocol", detail=f"Explained by {other}: {by_id[other].title}.", related_finding=other))
    # ---- Phase 2 fault model over the combined evidence
    result = posterior(calibrate(items + records, onset))
    top = sorted(result.probabilities.items(), key=lambda kv: -kv[1])[:3]
    hypotheses = [ProtocolHypothesis(domain=d.value, label=LABEL[d], probability=round(p, 3), shown=percent(p)) for d, p in top]
    spread = uncertainty(result).statement if items else "No fault evidence: nothing to rank."
    threats = [f.finding_id for f in findings if f.code == "THREAT_CORRELATED_ACTIVITY"]
    suspects = suspected(findings, ranked)
    # ---- next checks: engines not run that the findings or the symptoms point at
    ran = set(names)
    suggestions: dict[str, str] = {}
    for f in active:
        for engine in FOLLOW_UP.get(f.code, []):
            if engine not in ran and engine not in suggestions:
                suggestions[engine] = f"{f.title} can come from or affect {BY_NAME[engine].title.lower()}"
    for pattern, engines_for in SYMPTOM_ENGINES:
        if symptoms and pattern.search(symptoms):
            for engine in engines_for:
                if engine not in ran and engine not in suggestions:
                    suggestions[engine] = "matches the reported symptoms"
    next_checks = [ProtocolNextCheck(engine=e, title=BY_NAME[e].title, reason=r) for e, r in list(suggestions.items())[:4]]
    # ---- provenance
    index = record_index(telemetry) | core_index(dataset, derived=True)
    checked, issues = 0, []
    for f in findings:
        for ref in f.evidence + [r for c in f.correlations for r in c.evidence]:
            checked += 1
            if ref.record_id not in index.get(ref.collection, set()):
                issues.append(f"{f.finding_id} cites {ref.collection}:{ref.record_id[:60]}, which is not in the data")
        if f.status != "insufficient_evidence" and not f.evidence:
            issues.append(f"{f.finding_id} has no evidence reference")
    notes = list(dict.fromkeys(n for r in results for n in r.notes))
    missing = list(dict.fromkeys(m for r in results for m in r.missing))
    counts = {status: sum(1 for f in findings if f.status == status)
              for status in ("confirmed_fault", "suspicious_indicator", "possible_explanation", "insufficient_evidence")}
    related = correlate_incidents(current_incident, other_incidents or []) if current_incident else []
    return ProtocolReport(
        scenario_id=scenario_id, scope={"site_id": site_id, "device_id": device_id}, engines=results, findings=findings, counts=counts,
        headline=headline(findings, ranked, threats, suspects), root_causes=ranked, suspected_causes=suspects, causal_edges=edges[:30],
        causal_chain=chain, hypotheses=hypotheses,
        uncertainty=spread, threats=threats, notes=notes, missing=missing, next_checks=next_checks, related_incidents=related,
        validation=ProtocolValidation(grounded=not issues, references_checked=checked, issues=issues[:10]))


def engines_for_symptoms(text: str) -> list[str]:
    chosen: list[str] = []
    for pattern, engines in SYMPTOM_ENGINES:
        if pattern.search(text or ""):
            chosen += [e for e in engines if e not in chosen]
    return chosen
