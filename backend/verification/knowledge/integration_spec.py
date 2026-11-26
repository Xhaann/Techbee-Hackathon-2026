import json

import pytest

from app.engine import DiagnosisEngine, DiagnosisRequest, diagnose
from app.engine.safety import is_read_only_command
from app.engine.schema import FaultDomain
from app.incidents import IncidentService, IncidentValidationError, JsonIncidentRepository, LifecycleStatus
from app.knowledge import KnowledgeNotFoundError, KnowledgeService
from verification.engine.helpers import ScriptedProvider, draft, final, incident_request, tool_call, tool_evidence
from verification.incidents.helpers import HUMAN, SYSTEM, SteppingClock, create, diagnosed, resolved

KNOWLEDGE = KnowledgeService()
EXPECTED = {
    "WAN-FAILURE": "PB-WAN-FAILURE", "PACKET-LOSS": "PB-PACKET-LOSS", "OSPF-ADJACENCY-FAILURE": "PB-OSPF-ADJACENCY-FAILURE",
    "FIREWALL-BLOCKING": "PB-FIREWALL-BLOCKING", "DHCP-ALLOCATION-FAILURE": "PB-DHCP-ALLOCATION-FAILURE",
    "DNS-RESOLUTION-FAILURE": "PB-DNS-RESOLUTION-FAILURE", "VLAN-AUTHENTICATION-FAILURE": "PB-VLAN-AUTHENTICATION-FAILURE",
    "SHARED-DEVICE-FAILURE": "PB-SHARED-DEVICE-FAILURE",
}


@pytest.fixture
def incidents(tmp_path) -> IncidentService:
    return IncidentService(JsonIncidentRepository(tmp_path / "incidents"), SteppingClock())


def strip_knowledge(diagnosis) -> dict:
    return diagnosis.model_dump(mode="json") | {"retrieved_document_ids": [], "security_flags": []}


@pytest.mark.parametrize("scenario_id, playbook_id", sorted(EXPECTED.items()))
def test_assessment_selects_playbook_and_compares_evidence(scenario_id: str, playbook_id: str) -> None:
    diagnosis = diagnose(incident_request(scenario_id))
    assessment = KNOWLEDGE.assess_diagnosis(diagnosis)
    assert assessment.selected_playbook_id == playbook_id and assessment.selection_reasons
    assert assessment.evidence_comparison and all(e.observed for e in assessment.evidence_comparison)
    evidence = {item.evidence_id: item for item in diagnosis.evidence}
    for expectation in assessment.evidence_comparison:
        assert expectation.evidence_ids and all(evidence[i].code in expectation.expected_codes for i in expectation.evidence_ids)
    assert assessment.runbook_ids and assessment.diagnosis_confidence == diagnosis.confidence.level
    assert assessment.confidence_changed is False and assessment.establishes_root_cause is False
    for check in assessment.supplementary_checks:
        assert check.illustrative and is_read_only_command(check.command)
        assert (check.device_id, check.command) not in {(c.device_id, c.command) for c in diagnosis.next_checks}


def test_engine_retrieves_knowledge_without_changing_conclusions() -> None:
    for scenario_id in ("WAN-FAILURE", "VLAN-AUTHENTICATION-FAILURE", "SHARED-DEVICE-FAILURE"):
        plain = diagnose(incident_request(scenario_id))
        guided = DiagnosisEngine(retriever=KNOWLEDGE.diagnosis_retriever()).diagnose(incident_request(scenario_id))
        assert guided.retrieved_document_ids and plain.retrieved_document_ids == []
        assert strip_knowledge(guided) == strip_knowledge(plain)


def test_knowledge_is_retrieved_by_text_before_evidence_is_collected() -> None:
    guided = DiagnosisEngine(retriever=KNOWLEDGE.diagnosis_retriever()).diagnose(incident_request("SHARED-DEVICE-FAILURE"))
    assert guided.retrieved_document_ids == ["PB-WAN-FAILURE"]
    assert guided.fault.fault_domain == FaultDomain.SHARED_INFRASTRUCTURE
    assert KNOWLEDGE.assess_diagnosis(guided).selected_playbook_id == "PB-SHARED-DEVICE-FAILURE"


def test_playbook_match_does_not_create_a_root_cause() -> None:
    request = DiagnosisRequest(scenario_id="BASELINE", site_ids=["SIN"],
                               description="Singapore users report the WAN circuit is down and the branch router is unreachable")
    diagnosis = DiagnosisEngine(retriever=KNOWLEDGE.diagnosis_retriever()).diagnose(request)
    assert "PB-WAN-FAILURE" in diagnosis.retrieved_document_ids
    assert diagnosis.fault.fault_domain == FaultDomain.UNKNOWN and diagnosis.incident.status.value == "no_fault_identified"
    assessment = KNOWLEDGE.assess_diagnosis(diagnosis)
    assert assessment.selected_playbook_id == "PB-WAN-FAILURE"
    assert not any(e.observed for e in assessment.evidence_comparison if e.requirement_id != "EV-WAN-PEER")
    assert assessment.missing_evidence and assessment.establishes_root_cause is False
    assert assessment.diagnosis_confidence.value == "insufficient_evidence"


def test_model_receives_knowledge_as_untrusted_reference() -> None:
    def step(messages: list, tools: object):
        return final(draft(supporting_evidence_ids=tool_evidence(messages, "NO_ROUTE_TO_DESTINATION")))
    provider = ScriptedProvider([tool_call("check_network_reachability", {"source": "SIN-SW-01", "destination": "DC1-SRV-APP-01"}), step])
    diagnosis = DiagnosisEngine(provider, KNOWLEDGE.diagnosis_retriever()).diagnose(incident_request("WAN-FAILURE"))
    opening = json.loads(provider.calls[0]["messages"][1]["content"])
    references = opening["untrusted_reference_documents"]
    assert references and references[0]["title"] == "WAN circuit failure at a branch"
    assert provider.calls[0]["messages"][0]["role"] == "system" and "Guidance only" in references[0]["content"]
    assert diagnosis.method.value == "model" and diagnosis.retrieved_document_ids == ["PB-WAN-FAILURE"]


def test_incident_knowledge_links_and_handover(incidents: IncidentService) -> None:
    incident = diagnosed(incidents, "OSPF-ADJACENCY-FAILURE")
    linked = KNOWLEDGE.link_to_incident(incidents, incident.incident_id, SYSTEM)
    references = {(k.record_id, k.match_type) for k in linked.knowledge_references}
    assert ("PB-OSPF-ADJACENCY-FAILURE", "exact") in references and ("RB-BLR-BRANCH", "site") in references
    assert all(k.diagnosis_id == incident.active_diagnosis_id and k.source_ids for k in linked.knowledge_references)
    event = linked.timeline[-1]
    assert event.event_type.value == "knowledge_linked" and "not evidence" in event.description
    assert (linked.status, linked.classification.confirmed_fault_domain, linked.resolutions) == (LifecycleStatus.DIAGNOSED, None, [])
    escalated = incidents.create_escalation(incident.incident_id, SYSTEM)
    assert "Reference knowledge (guidance only): PB-OSPF-ADJACENCY-FAILURE v1.0.0" in escalated.escalations[0].handover_summary
    with pytest.raises(IncidentValidationError, match="No new knowledge"):
        KNOWLEDGE.link_to_incident(incidents, incident.incident_id, SYSTEM)


def test_guidance_for_undiagnosed_incident(incidents: IncidentService) -> None:
    incident = create(incidents, "DHCP-ALLOCATION-FAILURE")
    assessment = KNOWLEDGE.guidance_for_incident(incident)
    assert assessment.selected_playbook_id == "PB-DHCP-ALLOCATION-FAILURE"
    assert assessment.diagnosis_confidence is None and assessment.missing_evidence
    assert not any(e.observed for e in assessment.evidence_comparison)


def test_guidance_only_for_unresolved_incidents(incidents: IncidentService) -> None:
    incident = resolved(incidents)
    with pytest.raises(KnowledgeNotFoundError):
        KNOWLEDGE.guidance_for_incident(incident)


def test_knowledge_references_survive_restart(tmp_path) -> None:
    store = tmp_path / "store"
    first = IncidentService(JsonIncidentRepository(store), SteppingClock())
    incident = diagnosed(first, "WAN-FAILURE")
    linked = KNOWLEDGE.link_to_incident(first, incident.incident_id, HUMAN)
    restarted = IncidentService(JsonIncidentRepository(store), SteppingClock())
    assert restarted.get_incident(incident.incident_id).knowledge_references == linked.knowledge_references


def test_existing_incident_files_without_knowledge_still_load(incidents: IncidentService) -> None:
    incident = create(incidents)
    path = incidents.repository.path_for(incident.incident_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    del payload["knowledge_references"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert IncidentService(JsonIncidentRepository(path.parent), SteppingClock()).get_incident(incident.incident_id).knowledge_references == []
