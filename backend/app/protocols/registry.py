"""The 17 protocol and security engines, how they run, and how their findings are calibrated.

Every finding gets its confidence here, from one rule set: how directly the data shows the problem, how many independent
sources agree, contradictions, and whether the data was stale or partial. Confirmed faults need a confidence of at least
0.7 (otherwise they are downgraded to possible explanations), suspicious indicators are capped at 0.85 because intent is
never certain from network data, and insufficient-evidence results carry no confidence at all.
"""
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.diagnostics import EvidenceRef
from app.engine.schema import FaultDomain
from app.network.models import NetworkTopology, ScenarioDataset
from app.protocols.commands import commands_for
from app.protocols.engines import arp, bgp, ipsec, ipv6, lateral, mtu, multicast, nat, ospf, qos, stp, tcp, threats, tls, traffic, vlan, wireless
from app.protocols.engines.base import Context, Draft, EngineOutput
from app.protocols.models import SECTION_OF, ProtocolTelemetry
from app.reasoning.inference import confidence_label

D = FaultDomain
EngineName = Literal["bgp", "ospf", "stp", "arp", "vlan", "nat", "ipsec", "tcp", "mtu", "qos", "ipv6", "wireless", "multicast", "tls",
                     "threats", "traffic", "lateral"]


@dataclass(frozen=True)
class Engine:
    name: str
    feature: int
    title: str
    specialist: str
    layer: str
    domain: FaultDomain | None
    category: Literal["protocol", "security"]
    analyze: Callable[[Context], EngineOutput]
    summary: str
    depends: tuple[str, ...] = ()


ENGINES: tuple[Engine, ...] = (
    Engine("bgp", 1, "BGP route anomaly detection", "routing", "network", D.ROUTING, "protocol", bgp.analyze,
           "origin and prefix-length checks, leaks, withdrawal bursts, flaps, sessions"),
    Engine("ospf", 2, "OSPF LSDB analysis", "routing", "network", D.ROUTING, "protocol", ospf.analyze,
           "database consistency, duplicate router IDs, MaxAge and churn"),
    Engine("stp", 3, "STP loop and topology-change detection", "switching", "data_link", D.SWITCHING, "protocol", stp.analyze,
           "loop indicators, topology-change storms, root bridge"),
    Engine("arp", 4, "ARP spoofing and conflict detection", "switching", "data_link", D.SWITCHING, "protocol", arp.analyze,
           "gateway impersonation, duplicate addresses"),
    Engine("vlan", 5, "VLAN and trunk mismatch detection", "switching", "data_link", D.SWITCHING, "protocol", vlan.analyze,
           "native, allowed and mode mismatches on trunks"),
    Engine("nat", 6, "NAT translation analysis", "transport", "transport_policy", D.FIREWALL, "protocol", nat.analyze,
           "pool exhaustion, rule coverage and order"),
    Engine("ipsec", 7, "IPsec VPN tunnel analysis", "transport", "transport_policy", D.FIREWALL, "protocol", ipsec.analyze,
           "proposals, selectors, dead peers, one-way tunnels"),
    Engine("tcp", 8, "TCP retransmission analysis", "transport", "transport_policy", D.INTERFACE_LINK, "protocol", tcp.analyze,
           "retransmissions, handshakes, RTT, zero windows"),
    Engine("mtu", 9, "MTU and fragmentation diagnosis", "transport", "network", D.INTERFACE_LINK, "protocol", mtu.analyze,
           "MTU mismatches, path-MTU black holes, MSS clamping"),
    Engine("qos", 10, "QoS and packet-priority analysis", "transport", "transport_policy", D.INTERFACE_LINK, "protocol", qos.analyze,
           "policies, DSCP re-marking, priority and congestion drops"),
    Engine("ipv6", 11, "IPv6 routing diagnosis", "routing", "network", D.ROUTING, "protocol", ipv6.analyze,
           "OSPFv3, default and site routes, dual-stack probes, router advertisements"),
    Engine("wireless", 12, "Wireless interference analysis", "wireless", "physical", D.INTERFACE_LINK, "protocol", wireless.analyze,
           "RF interference, co-channel contention, radar, rogue APs"),
    Engine("multicast", 13, "Multicast routing diagnosis", "routing", "network", D.ROUTING, "protocol", multicast.analyze,
           "RP agreement, RPF checks, PIM neighbours, receivers"),
    Engine("tls", 14, "Certificate and TLS connectivity diagnosis", "security", "services", D.UNKNOWN, "protocol", tls.analyze,
           "expiry, names, chains, unexpected certificates"),
    Engine("threats", 15, "Network threat correlation", "security", "services", None, "security", threats.analyze,
           "groups security indicators by host and time and scores them",
           ("arp", "tls", "ipv6", "wireless", "bgp", "stp", "traffic", "lateral")),
    Engine("traffic", 16, "Suspicious traffic detection", "security", "services", None, "security", traffic.analyze,
           "sweeps, beaconing, large uploads, DNS tunnelling, intel matches"),
    Engine("lateral", 17, "Lateral movement indicators", "security", "services", None, "security", lateral.analyze,
           "admin fan-out, credential spraying, hop chains, segmentation"),
)
BY_NAME = {engine.name: engine for engine in ENGINES}
SECTION_LABEL = {"bgp": "BGP", "ospf": "OSPF database", "stp": "spanning-tree", "arp": "ARP", "vlan": "trunk", "nat": "NAT", "ipsec": "IPsec",
                 "tcp": "TCP flow", "mtu": "MTU probe", "qos": "QoS", "ipv6": "IPv6", "wireless": "wireless controller", "multicast": "multicast",
                 "tls": "TLS", "security": "flow and authentication"}
BASE = {"two_sided": 0.92, "direct": 0.88, "measured": 0.82, "behavioural": 0.62, "inferred": 0.5}


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProtocolCommand(Model):
    device_id: str
    platform: str
    command: str
    purpose: str
    healthy: str
    faulty: str


class ProtocolCorrelation(Model):
    kind: Literal["config_change", "timing", "topology", "traffic", "packet_journey", "incident_history", "protocol", "core_evidence"]
    detail: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    related_finding: str | None = None


class ProtocolFinding(Model):
    finding_id: str
    engine: str
    feature: int
    code: str
    status: Literal["confirmed_fault", "suspicious_indicator", "possible_explanation", "insufficient_evidence"]
    kind: str
    severity: Literal["critical", "major", "minor", "info"]
    title: str
    summary: str
    basis: str
    device_id: str | None = None
    site_id: str | None = None
    affected_sites: list[str] = Field(default_factory=list)
    timestamp: datetime | None = None
    layer: str
    domain: FaultDomain | None = None
    confidence: float | None = None
    confidence_label: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    facts: dict[str, Any] = Field(default_factory=dict)
    hosts: list[str] = Field(default_factory=list)
    benign: list[str] = Field(default_factory=list)
    commands: list[ProtocolCommand] = Field(default_factory=list)
    correlations: list[ProtocolCorrelation] = Field(default_factory=list)
    explained_by: list[str] = Field(default_factory=list)
    explains: list[str] = Field(default_factory=list)
    root_cause: bool = False
    injection_ignored: bool = False


class ProtocolEngineResult(Model):
    engine: str
    feature: int
    title: str
    specialist: str
    status: Literal["fault", "suspicious", "possible", "healthy", "insufficient", "error"]
    checked: list[str]
    notes: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)


MAX_EVIDENCE = 16  # a merged finding keeps the references of each observation, up to this many


def calibrate(draft: Draft, stale: bool, partial: bool) -> tuple[float | None, str]:
    """Returns the confidence and the (possibly downgraded) status."""
    status = draft.status
    if status == "insufficient_evidence" or draft.strength == "none":
        return None, "insufficient_evidence"
    if "probability" in draft.facts:
        value = float(draft.facts["probability"])
    else:
        value = BASE[draft.strength] + 0.03 * min(draft.corroboration, 3) - 0.2 * draft.contradictions
        value -= 0.15 if stale else 0
        value -= 0.08 if partial else 0
    if status == "suspicious_indicator":
        value = min(value, 0.85)
    elif status == "possible_explanation":
        value = min(value, 0.65)
    value = round(max(0.05, min(0.97, value)), 2)
    if status == "confirmed_fault" and value < 0.7:
        status = "possible_explanation"
    return value, status


def identity(facts: dict) -> tuple:
    """The facts that say what a finding is about (a MAC, a prefix, an interface), not what was measured (counts, percentages)."""
    return tuple(sorted((k, repr(v)) for k, v in facts.items() if isinstance(v, bool) or not isinstance(v, (int, float))))


def merge_duplicates(drafts: list[Draft]) -> list[Draft]:
    """One finding per claim. Drafts that state the same thing about the same subject (same code, status, device, sites,
    title and identifying facts) are repeated observations of one condition, for example one per advertisement or per
    counter interval. They become one draft that keeps every distinct evidence reference, the earliest time and how often it
    was seen. Two sources or two interfaces never merge."""
    merged: dict[tuple, Draft] = {}
    seen: dict[tuple, int] = {}
    times: dict[tuple, list] = {}
    for draft in drafts:
        key = (draft.code, draft.status, draft.device_id, draft.site_id, tuple(sorted(draft.affected_sites)), draft.title, identity(draft.facts))
        if key not in merged:
            merged[key], seen[key], times[key] = draft, 1, [draft.timestamp] if draft.timestamp else []
            continue
        first = merged[key]
        seen[key] += 1
        if draft.timestamp:
            times[key].append(draft.timestamp)
        known = {(e.collection, e.record_id) for e in first.evidence}
        first.evidence += [e for e in draft.evidence if (e.collection, e.record_id) not in known]
        first.hosts += [h for h in draft.hosts if h not in first.hosts]
        first.corroboration = max(first.corroboration, draft.corroboration)
        first.injection = first.injection or draft.injection
        if draft.timestamp and (first.timestamp is None or draft.timestamp < first.timestamp):
            first.timestamp = draft.timestamp
    for key, draft in merged.items():
        if seen[key] > 1:
            span = sorted(times[key])
            draft.facts = {**draft.facts, "occurrences": seen[key]}
            draft.summary += (f" Seen {seen[key]} times" + (f" between {span[0]:%H:%M} and {span[-1]:%H:%M} UTC." if len(span) > 1 else "."))
    return list(merged.values())


def closure(names: list[str]) -> list[str]:
    ordered: list[str] = []

    def visit(name: str) -> None:
        for dependency in BY_NAME[name].depends:
            visit(dependency)
        if name not in ordered:
            ordered.append(name)

    for name in names:
        visit(name)
    return ordered


def in_scope(draft: Draft, site_id: str | None, device_id: str | None) -> bool:
    if draft.status == "insufficient_evidence":
        return True
    if device_id and not (draft.device_id == device_id or device_id in str(draft.facts) or device_id in draft.summary):
        return False
    if site_id and not (draft.site_id == site_id or site_id in draft.affected_sites):
        return False
    return True


def run_engines(topology: NetworkTopology, dataset: ScenarioDataset, telemetry: ProtocolTelemetry, names: list[str],
                site_id: str | None = None, device_id: str | None = None) -> tuple[list[ProtocolEngineResult], list[ProtocolFinding]]:
    requested = [n for n in dict.fromkeys(names) if n in BY_NAME]
    context = Context(topology, dataset, telemetry, site_id, device_id)
    outputs: dict[str, EngineOutput] = {}
    for name in closure(requested):
        engine = BY_NAME[name]
        section = getattr(telemetry, SECTION_OF[name])
        if section is None:
            outputs[name] = EngineOutput(
                drafts=[Draft("TELEMETRY_NOT_COLLECTED", "insufficient_evidence", "coverage", "info", f"No {SECTION_LABEL[SECTION_OF[name]]} data",
                              f"No {SECTION_LABEL[SECTION_OF[name]]} telemetry was collected for this period, so {engine.title.lower()} cannot "
                              "say anything either way.", "none", [], "the data source was unavailable")],
                checked=[], missing=[f"No {SECTION_LABEL[SECTION_OF[name]]} telemetry collected"], applicable=False)
        else:
            try:
                outputs[name] = engine.analyze(context)
                outputs[name].drafts = merge_duplicates(outputs[name].drafts)
            except Exception as exc:  # one engine's failure must not take the others down
                outputs[name] = EngineOutput(missing=[f"Engine error: {type(exc).__name__}"], applicable=False)
                outputs[name].notes.append("This check could not complete; no conclusion is drawn from it.")
        context.prior[name] = outputs[name].drafts
        context.prior[f"{name}:notes"] = outputs[name].notes  # type: ignore[assignment]
    results, findings = [], []
    for name in requested:
        engine, output = BY_NAME[name], outputs[name]
        section = getattr(telemetry, SECTION_OF[name])
        stale = section is not None and dataset.scenario.window_start > section.collected_at
        partial = bool(output.missing)
        ids = []
        for index, draft in enumerate((d for d in output.drafts if in_scope(d, site_id, device_id)), start=1):
            confidence, status = calibrate(draft, stale, partial)
            finding_id = f"{name.upper()}-{index}"
            ids.append(finding_id)
            findings.append(ProtocolFinding(
                finding_id=finding_id, engine=name, feature=engine.feature, code=draft.code, status=status, kind=draft.kind,
                severity=draft.severity, title=draft.title, summary=draft.summary, basis=draft.basis, device_id=draft.device_id,
                site_id=draft.site_id, affected_sites=draft.affected_sites, timestamp=draft.timestamp, layer=engine.layer,
                domain=engine.domain, confidence=confidence, confidence_label=confidence_label(confidence) if confidence is not None else None,
                evidence=draft.evidence[:MAX_EVIDENCE], facts=draft.facts, hosts=draft.hosts, benign=draft.benign,
                commands=[ProtocolCommand(**c) for c in commands_for(draft.code, draft.device_id, draft.facts)],
                injection_ignored=draft.injection))
        mine = [f for f in findings if f.finding_id in ids]
        statuses = {f.status for f in mine}
        if "error" in " ".join(output.missing).lower() and not mine:
            status = "error"
        elif "confirmed_fault" in statuses:
            status = "fault"
        elif "suspicious_indicator" in statuses:
            status = "suspicious"
        elif "possible_explanation" in statuses:
            status = "possible"
        elif "insufficient_evidence" in statuses or not output.applicable:
            status = "insufficient"
        else:
            status = "healthy"
        results.append(ProtocolEngineResult(engine=name, feature=engine.feature, title=engine.title, specialist=engine.specialist, status=status,
                                    checked=output.checked, notes=output.notes, missing=output.missing, finding_ids=ids))
    return results, findings
