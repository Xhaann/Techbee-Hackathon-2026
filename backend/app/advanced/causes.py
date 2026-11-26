from app.advanced.schema import CandidateStatus, EvidenceRole, RootCauseCandidate
from app.engine.schema import Confidence, Diagnosis, EvidenceItem, FaultDomain
from app.knowledge.service import KnowledgeAssessment

SYMPTOM_ROLES = {EvidenceRole.SECONDARY_SYMPTOM, EvidenceRole.DOWNSTREAM_SERVICE_IMPACT}
MAX_CHECKS = 6


def root_cause_candidates(diagnosis: Diagnosis, catalog: list[EvidenceItem], roles: dict[str, EvidenceRole],
                          assessment: KnowledgeAssessment | None, confirmed: FaultDomain | None) -> list[RootCauseCandidate]:
    by_id = {item.evidence_id: item for item in catalog}
    fault = diagnosis.fault
    candidates = []
    if fault.fault_domain != FaultDomain.UNKNOWN:
        status = CandidateStatus.HUMAN_CONFIRMED if confirmed == fault.fault_domain else CandidateStatus.SUSPECTED
        candidates.append(RootCauseCandidate(
            rank=1, status=status, fault_domain=fault.fault_domain, hypothesis=fault.root_cause, device_ids=fault.device_ids,
            link_ids=fault.link_ids,
            supporting_evidence_ids=[i for i in fault.supporting_evidence_ids if roles.get(i) not in SYMPTOM_ROLES],
            contradicting_evidence_ids=fault.contradictory_evidence_ids,
            missing_evidence=assessment.missing_evidence if assessment else ["No playbook expectations were available for comparison"],
            dependent_symptom_ids=[i for i in fault.supporting_evidence_ids if roles.get(i) in SYMPTOM_ROLES],
            confidence=diagnosis.confidence.level,
            verification_checks=[f"{check.device_id}: {check.command}" for check in diagnosis.next_checks][:MAX_CHECKS],
        ))
    for alternative in diagnosis.alternatives:
        contradicted = bool(alternative.contradictory_evidence_ids)
        cited = alternative.supporting_evidence_ids or alternative.contradictory_evidence_ids
        devices = sorted({by_id[i].device_id for i in cited if i in by_id and by_id[i].device_id})
        candidates.append(RootCauseCandidate(
            rank=len(candidates) + 1, status=CandidateStatus.CONTRADICTED if contradicted else CandidateStatus.ALTERNATIVE,
            fault_domain=alternative.fault_domain, hypothesis=alternative.hypothesis, device_ids=devices, link_ids=[],
            supporting_evidence_ids=alternative.supporting_evidence_ids,
            contradicting_evidence_ids=alternative.contradictory_evidence_ids,
            missing_evidence=[] if alternative.supporting_evidence_ids else ["No supporting evidence was collected for this hypothesis"],
            dependent_symptom_ids=[],
            confidence=Confidence.INSUFFICIENT_EVIDENCE if contradicted else Confidence.LOW,
            verification_checks=[alternative.verification],
        ))
    return candidates
