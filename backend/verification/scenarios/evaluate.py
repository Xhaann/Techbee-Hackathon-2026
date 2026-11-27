"""Scores the diagnostic layers against the incident cards for SCN-01 to SCN-10.

The cards (app/protocols/cards.py) were written from the modelled faults before any engine ran on these scenarios, and
nothing in the diagnostic code reads them. This module only runs the existing layers and compares:
- Phase A: the rule-based diagnosis engine on the incident report;
- Phase 2: the specialist team and the Bayesian reasoning over its evidence;
- Phase 3: all 17 protocol and security engines with correlation.
"""
from dataclasses import dataclass, field

from app.engine.engine import DiagnosisEngine
from app.engine.schema import DiagnosisRequest
from app.network.repository import load_scenario
from app.protocols.analysis import ProtocolReport, analyze
from app.protocols.cards import CARD_BY_ID, CARDS, Card
from app.reasoning.report import analyze as reason
from app.reasoning.specialists import Scope, investigate
from app.security.provenance import provenance_issues

SCENARIOS = [card.scenario_id for card in CARDS]


@dataclass
class Outcome:
    scenario_id: str
    phase_a_domain: str | None = None
    phase_a_status: str = ""
    phase_a_confidence: str = ""
    phase_a_ok: bool = False
    phase_a_provenance: list[str] = field(default_factory=list)
    team_domain: str | None = None
    team_supported: bool = False
    team_ok: bool = False
    team_protocol_calls: int = 0
    expected_met: list[str] = field(default_factory=list)
    expected_missed: list[str] = field(default_factory=list)
    forbidden_hit: list[str] = field(default_factory=list)
    count_violations: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    root: str | None = None
    root_ok: bool = False
    threat_hosts: list[str] = field(default_factory=list)
    threats_ok: bool = True
    decoy_hits: list[str] = field(default_factory=list)
    grounded: bool = False
    headline: str = ""
    security_confirmed: list[str] = field(default_factory=list)
    report: ProtocolReport | None = None


SECURITY = ("SUSPICIOUS_", "LATERAL_", "THREAT_", "ARP_GATEWAY", "ARP_MAC", "ARP_GRAT", "TLS_UNEXPECTED", "IPV6_ROGUE", "WIFI_ROGUE",
            "BGP_ORIGIN_HIJACK", "STP_ROOT_UNEXPECTED")


def request_for(card: Card) -> DiagnosisRequest:
    dataset = load_scenario(card.scenario_id)
    return DiagnosisRequest(scenario_id=card.scenario_id, description=f"{dataset.incident.title}. {dataset.incident.description}",
                            site_ids=dataset.incident.affected_site_ids)


def phase_a(card: Card, outcome: Outcome) -> None:
    diagnosis = DiagnosisEngine().diagnose(request_for(card))  # no model provider: the rule-based engine
    domain = diagnosis.fault.fault_domain.value if diagnosis.fault else None
    outcome.phase_a_domain, outcome.phase_a_status = domain, diagnosis.incident.status.value
    outcome.phase_a_confidence = diagnosis.confidence.level.value
    outcome.phase_a_provenance = provenance_issues(diagnosis)
    honest = diagnosis.incident.status.value in ("no_fault_identified", "insufficient_evidence") or diagnosis.confidence.level.value in (
        "low", "insufficient_evidence")
    # When the core data shows the fault the domain must be right; when it does not, an honest "no fault" or low-confidence
    # answer is also right, and only a confident wrong domain counts against Phase A.
    outcome.phase_a_ok = domain in card.phase_a.acceptable_domains or (not card.phase_a.visible_in_core_data and honest)
    for decoy in card.decoys:
        if domain in decoy.must_not_conclude and diagnosis.confidence.level.value in ("medium", "high"):
            outcome.decoy_hits.append(f"Phase A concluded {domain} ({decoy.clue})")


def phase_2(card: Card, outcome: Outcome) -> None:
    dataset = load_scenario(card.scenario_id)
    text = " ".join([dataset.incident.title, dataset.incident.description, *dataset.incident.symptoms])
    scope = Scope(card.scenario_id, tuple(dataset.incident.affected_site_ids), (), (), tuple(card.unaffected_sites), text)
    run = investigate(scope)
    report = reason(run.evidence, scope, dataset.scenario.onset_at, run.executed)
    outcome.team_domain = report.leading.value if report.leading else None
    outcome.team_supported = report.fault_supported
    outcome.team_protocol_calls = sum(1 for check in run.executed if check.tool == "analyze_protocol")
    right = report.fault_supported and outcome.team_domain in card.phase_a.acceptable_domains
    outcome.team_ok = right or (not card.phase_a.visible_in_core_data and not report.fault_supported)


def phase_3(card: Card, outcome: Outcome) -> None:
    report = analyze(card.scenario_id, symptoms=" ".join(load_scenario(card.scenario_id).incident.symptoms))
    outcome.report, outcome.headline, outcome.grounded = report, report.headline, report.validation.grounded
    found = [(f.code, f.status, f.confidence) for f in report.findings]
    for expected in card.expected_findings:
        match = [c for code, status, c in found if code == expected.code and status == expected.status]
        within = [c for c in match if (expected.min_confidence is None or (c or 0) >= expected.min_confidence)
                  and (expected.max_confidence is None or (c or 0) <= expected.max_confidence)]
        (outcome.expected_met if within else outcome.expected_missed).append(f"{expected.code} ({expected.status})")
    known = {e.code for e in card.expected_findings} | set(card.acceptable_findings)
    outcome.forbidden_hit = sorted({code for code, _, _ in found if code in card.forbidden_findings})
    outcome.unexpected = sorted({code for code, status, _ in found if code not in known and code not in card.forbidden_findings
                                 and status != "insufficient_evidence"})
    for code, limit in card.max_counts.items():
        count = sum(1 for c, _, _ in found if c == code)
        if count > limit:
            outcome.count_violations.append(f"{code} reported {count} times (expected at most {limit})")
    by_id = {f.finding_id: f for f in report.findings}
    lead = by_id[report.root_causes[0]] if report.root_causes else None
    outcome.root = lead.code if lead else None

    def accepted(rule: str) -> bool:
        code, _, site = rule.partition("@")
        return lead is not None and lead.code == code and (not site or site in lead.affected_sites)
    outcome.root_ok = any(accepted(rule) for rule in card.acceptable_roots) if card.acceptable_roots else lead is None
    clusters = [f for f in report.findings if f.code == "THREAT_CORRELATED_ACTIVITY"]
    outcome.threat_hosts = sorted(f.facts.get("main_host") or "" for f in clusters)
    if card.threat_hosts:
        outcome.threats_ok = sorted(card.threat_hosts) == outcome.threat_hosts
    outcome.security_confirmed = [f.code for f in report.findings if f.code.startswith(SECURITY) and f.status == "confirmed_fault"]
    for decoy in card.decoys:
        if outcome.root and outcome.root in decoy.must_not_conclude:
            outcome.decoy_hits.append(f"Protocol root {outcome.root} ({decoy.clue})")
        hit = [code for code, status, _ in found if code in decoy.must_not_conclude and status == "confirmed_fault"]
        if hit:
            outcome.decoy_hits.append(f"Confirmed {', '.join(hit)} ({decoy.clue})")


def evaluate(scenario_id: str) -> Outcome:
    card = CARD_BY_ID[scenario_id]
    outcome = Outcome(scenario_id)
    phase_a(card, outcome)
    phase_2(card, outcome)
    phase_3(card, outcome)
    return outcome
