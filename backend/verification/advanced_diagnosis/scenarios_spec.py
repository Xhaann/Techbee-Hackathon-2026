import json

import pytest

from app.advanced import AdvancedDiagnosisEngine, AdvancedRequest
from app.advanced.schema import CandidateStatus, EvidenceRole
from app.engine import DiagnosisRequest
from app.engine.safety import is_read_only_command
from app.engine.schema import Confidence, FaultDomain
from app.network.repository import load_scenario
from verification.advanced_diagnosis.helpers import EXPECTED, KNOWLEDGE, analysis


@pytest.mark.parametrize("scenario_id", sorted(EXPECTED))
def test_primary_fault_matches_scenario(scenario_id: str) -> None:
    domain, devices = EXPECTED[scenario_id]
    result = analysis(scenario_id)
    primary = result.primary_fault
    assert primary.fault_domain == domain and primary.device_ids == devices
    assert primary.status == CandidateStatus.SUSPECTED and primary.confidence == Confidence.HIGH
    assert primary.confidence == result.base.confidence.level
    assert primary.supporting_evidence_ids and result.validation_issues == []
    truth = load_scenario(scenario_id).ground_truth
    assert set(truth.root_cause_device_ids) == set(devices)
    assert set(truth.affected_site_ids) <= set(result.blast_radius.affected_sites)
    assert result.human_verification_required is True


@pytest.mark.parametrize("scenario_id", sorted(EXPECTED))
def test_outputs_are_complete_read_only_and_serialisable(scenario_id: str) -> None:
    result = analysis(scenario_id)
    assert result.paths and result.next_checks and result.narrative and result.playbooks
    assert all(is_read_only_command(check.command) for check in result.next_checks)
    assert len(result.base.tool_calls) + len(result.supplementary_tool_calls) <= 10
    assert result.blast_radius.business_impact == "not_assessed"
    assert any("human verification" in line for line in result.narrative)
    json.dumps(result.model_dump(mode="json"))


@pytest.mark.parametrize("scenario_id, symptom_codes", [
    ("SHARED-DEVICE-FAILURE", {"NO_ROUTE_TO_DESTINATION", "LINK_DOWN_AT_FAILURE_POINT"}),
    ("VLAN-AUTHENTICATION-FAILURE", {"DHCP_TRANSACTIONS_STOPPED"}),
])
def test_dependent_symptoms_are_separated(scenario_id: str, symptom_codes: set[str]) -> None:
    result = analysis(scenario_id)
    codes = {e.code for e in result.cross_layer.aligned_evidence if e.evidence_id in result.primary_fault.dependent_symptom_ids}
    assert symptom_codes <= codes
    assert not set(result.primary_fault.dependent_symptom_ids) & set(result.primary_fault.supporting_evidence_ids)


def test_shared_failure_attributes_root_to_shared_device() -> None:
    result = analysis("SHARED-DEVICE-FAILURE")
    shared = [e for e in result.cross_layer.aligned_evidence if e.role == EvidenceRole.SHARED_DEPENDENCY_FAILURE]
    assert shared and {e.device_id for e in shared} == {"CORE-RTR-01"}
    secondary = {e.device_id for e in result.cross_layer.aligned_evidence if e.role == EvidenceRole.SECONDARY_SYMPTOM}
    assert {"NYC-RTR-01", "SIN-RTR-01"} <= secondary
    alternatives = [c for c in result.root_cause_candidates if c.rank > 1]
    assert len(alternatives) == 2 and all(c.status == CandidateStatus.CONTRADICTED for c in alternatives)
    assert all(c.confidence == Confidence.INSUFFICIENT_EVIDENCE for c in alternatives)


def test_healthy_baseline() -> None:
    engine = AdvancedDiagnosisEngine(knowledge=KNOWLEDGE)
    request = DiagnosisRequest(scenario_id="BASELINE", site_ids=["NYC"], description="Users report the ERP portal felt slow")
    result = engine.analyze(AdvancedRequest(diagnosis=request))
    assert result.primary_fault is None and result.root_cause_candidates == []
    assert result.base.fault.fault_domain == FaultDomain.UNKNOWN
    assert result.anomalies.anomalies == [] and result.changes.correlations == []
    assert result.paths[0].status == "reachable" and result.paths[0].failed_links == []
    assert {i.category.value for i in result.blast_radius.items} <= {"reported"}
    assert result.missing_evidence == ["No primary fault is supported by the collected evidence"]
    assert result.validation_issues == []
