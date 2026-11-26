from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.agent.session import UNKNOWN, AgentRun, IncidentUnderstanding
from app.engine.evidence import build_catalog
from app.engine.safety import is_read_only_command
from app.engine.schema import (
    AffectedPath,
    Alternative,
    Confidence,
    DiagnosisMethod,
    EvidenceItem,
    EvidenceType,
    FaultDomain,
    NextCheck,
    TimelineEntry,
    ToolCallSummary,
)
from app.network.repository import load_topology
from app.security.provenance import provenance_issues

CONFIDENCE_ORDER = [Confidence.INSUFFICIENT_EVIDENCE, Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
OBSERVED = {EvidenceType.OBSERVED_FINDING, EvidenceType.OBSERVED_RESULT, EvidenceType.RECORD}
FINDINGS = {EvidenceType.OBSERVED_FINDING, EvidenceType.INFERRED_FINDING}
FAULT_RESULTS = {"DEVICE_AVAILABLE_WITH_FAULTS", "DEVICE_UNREACHABLE", "PATH_UNREACHABLE"}
BASE_CONFIRMATIONS = [
    "Confirm or reject the probable fault domain before it is recorded as a classification (human-only decision)",
    "Run the recommended read-only checks and compare the output with the expected observations",
    "Approve any escalation before it is sent; this assistant does not send escalations",
    "Plan and perform any remediation through authorised change control; this assistant never changes devices or incidents",
]


class ReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Hypothesis(ReportModel):
    statement: str
    origin: Literal["ai_agent", "rule_based_correlation"]
    reasoning: str
    device_ids: list[str]
    link_ids: list[str]
    verified_against_rules: bool
    evidence_support: Literal["supported", "unsupported", "not_applicable"]
    requires_human_confirmation: Literal[True] = True


class ConfidenceView(ReportModel):
    level: Confidence
    explanation: str
    capped_from: Confidence | None = None


class VerifiedFact(ReportModel):
    evidence_id: str
    statement: str
    device_id: str | None
    tool: str
    call_id: str
    basis: Literal["observed_in_synthetic_telemetry"] = "observed_in_synthetic_telemetry"


class GuidanceReference(ReportModel):
    reference_id: str
    title: str
    status: Literal["unverified_guidance"] = "unverified_guidance"


class EscalationView(ReportModel):
    team: str
    priority: str
    reason: str
    evidence_ids: list[str]
    unknowns: list[str]
    delivery_status: Literal["not_sent"] = "not_sent"


class AgentReport(ReportModel):
    incident_summary: str
    affected_site: list[str]
    affected_service: list[str]
    affected_path: AffectedPath | None
    correlated_timeline: list[TimelineEntry]
    fault_domain: FaultDomain
    root_cause_hypothesis: Hypothesis
    confidence: ConfidenceView
    alternatives: list[Alternative]
    evidence_references: list[EvidenceItem]
    verified_facts: list[VerifiedFact]
    recommended_next_checks: list[NextCheck]
    missing_evidence: list[str]
    escalation: EscalationView
    human_review_required: Literal[True] = True
    diagnostic_narrative: list[str]
    required_human_confirmations: list[str]
    discrepancies: list[str]
    knowledge_guidance: list[GuidanceReference]
    incident_understanding: IncidentUnderstanding
    method: DiagnosisMethod
    model: str | None
    status: str
    tool_calls: list[ToolCallSummary]
    validation_issues: list[str]
    security_flags: list[str]


def faulty_devices(run: AgentRun) -> set[str]:
    return {item.device_id for item in build_catalog(run.records) if item.device_id
            and (item.evidence_type in FINDINGS or item.code in FAULT_RESULTS)}


def evidence_support(run: AgentRun, faulty: set[str]) -> Literal["supported", "unsupported", "not_applicable"]:
    fault = run.diagnosis.fault
    if fault.fault_domain == FaultDomain.UNKNOWN or not fault.device_ids:
        return "not_applicable"
    return "supported" if set(fault.device_ids) & faulty else "unsupported"


def discrepancies_for(run: AgentRun, faulty: set[str]) -> list[str]:
    site_of = {device.device_id: device.site_id for device in load_topology().devices}
    fault_sites = {site_of[device] for device in faulty if device in site_of}
    catalog = build_catalog(run.records)
    notes = []
    for site in run.understanding.sites:
        if site in fault_sites:
            continue
        healthy = sorted({item.code for item in catalog if item.device_id and site_of.get(item.device_id) == site
                          and item.evidence_type == EvidenceType.OBSERVED_RESULT})
        observed = f"; evidence collected at {site} shows {', '.join(healthy)}" if healthy else ""
        notes.append(f"The report places the impact at {site}, but no collected evidence supports a fault there{observed}")
    if notes and fault_sites - set(run.understanding.sites):
        notes.append(f"Fault evidence points to sites outside the report: {', '.join(sorted(fault_sites - set(run.understanding.sites)))}")
    if evidence_support(run, faulty) == "unsupported":
        notes.append(f"The hypothesis names {', '.join(run.diagnosis.fault.device_ids)}, but no collected evidence shows a fault on them")
    return notes


def confidence_view(run: AgentRun, conflicts: list[str], support: str) -> ConfidenceView:
    level = run.diagnosis.confidence.level
    if support == "unsupported" and level != Confidence.INSUFFICIENT_EVIDENCE:
        return ConfidenceView(level=Confidence.INSUFFICIENT_EVIDENCE, capped_from=level,
                              explanation="No collected evidence shows a fault on the devices named by the hypothesis. "
                                          + run.diagnosis.confidence.explanation)
    if conflicts and CONFIDENCE_ORDER.index(level) > CONFIDENCE_ORDER.index(Confidence.LOW):
        return ConfidenceView(level=Confidence.LOW, capped_from=level,
                              explanation="Capped at low because the incident report conflicts with the collected evidence. "
                                          + run.diagnosis.confidence.explanation)
    return ConfidenceView(level=level, explanation=run.diagnosis.confidence.explanation)


def missing_for(run: AgentRun, conflicts: list[str]) -> list[str]:
    diagnosis = run.diagnosis
    gaps = [f"{item.device_id}: {item.summary} (missing telemetry is not proof of failure)"
            for item in build_catalog(run.records) if item.code == "TELEMETRY_GAP"]
    stated = [f"The report does not state the {name}" for name in run.understanding.unknown_fields]
    unresolved = ["Confirm the affected site with the reporter; the report and the telemetry disagree"] if conflicts else []
    return list(dict.fromkeys(gaps + diagnosis.limitations + diagnosis.escalation.unknowns + unresolved + stated))


def build_report(run: AgentRun) -> AgentReport:
    diagnosis = run.diagnosis
    provenance = provenance_issues(diagnosis)
    evidence = [] if provenance else list(diagnosis.evidence)
    faulty = faulty_devices(run)
    support = evidence_support(run, faulty)
    conflicts = discrepancies_for(run, faulty)
    from_agent = diagnosis.method == DiagnosisMethod.MODEL
    checks = [check for check in diagnosis.next_checks if is_read_only_command(check.command)]
    confirmations = list(BASE_CONFIRMATIONS)
    if conflicts:
        confirmations.insert(0, "Resolve the conflict between the incident report and the collected evidence")
    if diagnosis.method == DiagnosisMethod.RULE_BASED_FALLBACK:
        confirmations.insert(0, "The agent's own diagnosis was unavailable or rejected; review the rule-based result")
    narrative = run.events + [
        f"Conclusion ({'AI agent' if from_agent else 'rule-based correlation'}): {diagnosis.fault.fault_domain.value} - "
        f"{diagnosis.fault.root_cause}",
        diagnosis.explanation.summary,
        "Validation: " + ("evidence provenance verified" if not provenance else "evidence withheld after provenance failure")
        + (f"; {len(diagnosis.validation_issues)} validation issue(s) recorded" if diagnosis.validation_issues else ""),
    ]
    return AgentReport(
        incident_summary=run.understanding.summary,
        affected_site=run.understanding.sites or diagnosis.incident.site_ids or [UNKNOWN],
        affected_service=run.understanding.services or [UNKNOWN],
        affected_path=diagnosis.affected_path,
        correlated_timeline=diagnosis.timeline,
        fault_domain=diagnosis.fault.fault_domain,
        root_cause_hypothesis=Hypothesis(
            statement=diagnosis.fault.root_cause, origin="ai_agent" if from_agent else "rule_based_correlation",
            reasoning=diagnosis.fault.reasoning, device_ids=diagnosis.fault.device_ids, link_ids=diagnosis.fault.link_ids,
            verified_against_rules=diagnosis.fault.verified_against_rules, evidence_support=support,
        ),
        confidence=confidence_view(run, conflicts, support),
        alternatives=diagnosis.alternatives,
        evidence_references=evidence,
        verified_facts=[VerifiedFact(evidence_id=item.evidence_id, statement=item.summary, device_id=item.device_id,
                                     tool=item.tool, call_id=item.call_id)
                        for item in evidence if item.evidence_type in OBSERVED],
        recommended_next_checks=checks,
        missing_evidence=missing_for(run, conflicts),
        escalation=EscalationView(team=diagnosis.escalation.team, priority=diagnosis.escalation.priority.value,
                                  reason=diagnosis.escalation.reason, evidence_ids=diagnosis.escalation.evidence_ids,
                                  unknowns=diagnosis.escalation.unknowns),
        diagnostic_narrative=narrative,
        required_human_confirmations=confirmations,
        discrepancies=conflicts,
        knowledge_guidance=[GuidanceReference(reference_id=document.document_id, title=document.title)
                            for document in run.budget.documents.values()],
        incident_understanding=run.understanding,
        method=diagnosis.method,
        model=run.model,
        status=diagnosis.incident.status.value,
        tool_calls=diagnosis.tool_calls,
        validation_issues=diagnosis.validation_issues + provenance,
        security_flags=diagnosis.security_flags,
    )
