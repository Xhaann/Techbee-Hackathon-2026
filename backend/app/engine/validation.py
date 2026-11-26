from dataclasses import dataclass

from app.engine.correlation import Correlation
from app.engine.guidance import confidence_rank
from app.engine.safety import is_read_only_command, mentions_remediation
from app.security.leakage import leakage_categories
from app.engine.schema import Confidence, Diagnosis, DiagnosisDraft, EvidenceItem, FaultDomain, NextCheck
from app.network.models import NetworkTopology


@dataclass
class ValidatedDraft:
    draft: DiagnosisDraft
    verified: bool
    issues: list[str]
    next_checks: list[NextCheck]


def cap(level: Confidence, limit: Confidence) -> Confidence:
    return level if confidence_rank(level) <= confidence_rank(limit) else limit


def draft_texts(draft: DiagnosisDraft) -> list[str]:
    texts = [draft.root_cause, draft.reasoning, draft.confidence_explanation, draft.escalation.team, draft.escalation.reason,
             *draft.escalation.unknowns, draft.explanation.summary, *draft.explanation.observed_facts,
             *draft.explanation.hypotheses, *draft.explanation.recommended_actions]
    texts += [text for alternative in draft.alternatives for text in (alternative.hypothesis, alternative.verification)]
    texts += [text for check in draft.next_checks for text in (check.command, check.purpose, check.expected_observation, check.reason)]
    return texts


def diagnosis_texts(diagnosis: Diagnosis) -> list[str]:
    explanation = diagnosis.explanation
    texts = [diagnosis.fault.root_cause, diagnosis.fault.reasoning, diagnosis.confidence.explanation, diagnosis.escalation.reason,
             *diagnosis.escalation.unknowns, explanation.summary, *explanation.observed_facts, *explanation.hypotheses,
             *explanation.recommended_actions]
    texts += [text for alternative in diagnosis.alternatives for text in (alternative.hypothesis, alternative.verification)]
    return texts


def validate_draft(draft: DiagnosisDraft, catalog: list[EvidenceItem], topology: NetworkTopology,
                   correlation: Correlation, known_secrets: tuple[str, ...] = ()) -> tuple[ValidatedDraft | None, list[str]]:
    issues: list[str] = []
    leaks = leakage_categories(draft_texts(draft), known_secrets)
    if leaks:
        issues.append(f"Model draft rejected: output disclosed protected content ({', '.join(leaks)})")
        return None, issues
    known = {item.evidence_id: item for item in catalog}
    devices = {device.device_id for device in topology.devices}
    links = {link.link_id for link in topology.links}

    fabricated_devices = sorted(set(draft.root_cause_device_ids) - devices)
    fabricated_links = sorted(set(draft.root_cause_link_ids) - links)
    if fabricated_devices or fabricated_links:
        issues.append(f"Model draft rejected: unknown devices or links {', '.join(fabricated_devices + fabricated_links)}")
        return None, issues

    def keep(evidence_ids: list[str], label: str) -> list[str]:
        for evidence_id in evidence_ids:
            if evidence_id not in known:
                issues.append(f"Unknown evidence id '{evidence_id[:20]}' cited in {label} was removed")
        return list(dict.fromkeys(i for i in evidence_ids if i in known))

    supporting = keep(draft.supporting_evidence_ids, "supporting evidence")
    contradicting = keep(draft.contradictory_evidence_ids, "contradictory evidence")
    if draft.fault_domain != FaultDomain.UNKNOWN and not supporting:
        issues.append("Model draft rejected: the root cause has no valid supporting evidence")
        return None, issues

    candidates = ([correlation.top] if correlation.top else []) + correlation.alternatives
    matching = [c for c in candidates if c.domain == draft.fault_domain
                and (not draft.root_cause_device_ids or set(c.device_ids) & set(draft.root_cause_device_ids))]
    cited_devices = {known[i].device_id for i in supporting} | set(correlation.affected_path.path if correlation.affected_path else [])
    grounded = set(draft.root_cause_device_ids) <= cited_devices | {d for c in matching for d in c.device_ids}
    verified = bool(matching) and matching[0] is correlation.top and grounded
    if draft.fault_domain == FaultDomain.UNKNOWN:
        limit = Confidence.INSUFFICIENT_EVIDENCE
    elif verified:
        limit = correlation.confidence
    else:
        limit = Confidence.LOW
        issues.append("Model root cause is not corroborated by rule-based correlation; confidence capped at low")
    confidence = cap(draft.confidence, limit)
    if confidence != draft.confidence:
        issues.append(f"Model confidence {draft.confidence.value} reduced to {confidence.value}")

    checks = []
    for check in draft.next_checks:
        if check.device_id not in devices:
            issues.append(f"Recommended check for unknown device '{check.device_id[:40]}' was removed")
        elif not is_read_only_command(check.command):
            issues.append(f"Non read-only command '{check.command[:60]}' was removed")
        else:
            checks.append(NextCheck(**check.model_dump()))
    actions = [action for action in draft.explanation.recommended_actions if not mentions_remediation(action)]
    if len(actions) != len(draft.explanation.recommended_actions):
        issues.append("Recommended actions describing remediation were removed")
    alternatives = [
        alternative.model_copy(update={
            "supporting_evidence_ids": keep(alternative.supporting_evidence_ids, "alternative evidence"),
            "contradictory_evidence_ids": keep(alternative.contradictory_evidence_ids, "alternative evidence"),
        })
        for alternative in draft.alternatives
    ]
    cleaned = draft.model_copy(update={
        "supporting_evidence_ids": supporting, "contradictory_evidence_ids": contradicting, "confidence": confidence,
        "next_checks": [], "alternatives": alternatives,
        "explanation": draft.explanation.model_copy(update={"recommended_actions": actions}),
    })
    return ValidatedDraft(draft=cleaned, verified=verified, issues=issues, next_checks=checks), issues


def check_diagnosis(diagnosis: Diagnosis, catalog: list[EvidenceItem], topology: NetworkTopology,
                    known_secrets: tuple[str, ...] = ()) -> list[str]:
    issues = []
    leaks = leakage_categories(diagnosis_texts(diagnosis), known_secrets)
    if leaks:
        issues.append(f"Diagnosis text disclosed protected content ({', '.join(leaks)})")
    known = {item.evidence_id for item in catalog}
    devices = {device.device_id for device in topology.devices}
    connected = {frozenset((link.a_device_id, link.b_device_id)) for link in topology.links}
    cited = set(diagnosis.fault.supporting_evidence_ids) | set(diagnosis.fault.contradictory_evidence_ids)
    cited |= {entry.evidence_id for entry in diagnosis.timeline} | set(diagnosis.escalation.evidence_ids)
    for alternative in diagnosis.alternatives:
        cited |= set(alternative.supporting_evidence_ids) | set(alternative.contradictory_evidence_ids)
    cited |= {item.evidence_id for item in diagnosis.evidence}
    issues += [f"Evidence id {evidence_id} does not resolve to a tool result" for evidence_id in sorted(cited - known)]
    referenced = set(diagnosis.fault.device_ids) | {check.device_id for check in diagnosis.next_checks}
    if diagnosis.affected_path:
        referenced |= set(diagnosis.affected_path.path) | set(diagnosis.affected_path.affected_devices)
        path = diagnosis.affected_path.path
        if any(frozenset(pair) not in connected for pair in zip(path, path[1:])):
            issues.append("Affected path is not consistent with topology links")
    issues += [f"Device {device} does not exist in the topology" for device in sorted(referenced - devices)]
    issues += [f"Command '{check.command}' is not read-only" for check in diagnosis.next_checks
               if not is_read_only_command(check.command)]
    return issues
