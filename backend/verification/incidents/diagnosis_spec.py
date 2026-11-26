import json

import pytest

from app.engine import DiagnosisEngine, DiagnosisRequest, diagnose
from app.engine.schema import Confidence, DiagnosisMethod, FaultDomain
from app.incidents import IncidentService, IncidentValidationError, InvalidTransitionError
from app.incidents.models import AssetType, ImpactBasis, LifecycleStatus
from app.network.repository import load_scenario
from verification.engine.helpers import ScriptedProvider, draft, final, tool_call, tool_evidence
from verification.incidents.helpers import HUMAN, SYSTEM, create, diagnosed

EXPECTED = {
    "WAN-FAILURE": FaultDomain.WAN_ISP, "PACKET-LOSS": FaultDomain.WAN_ISP, "OSPF-ADJACENCY-FAILURE": FaultDomain.ROUTING,
    "FIREWALL-BLOCKING": FaultDomain.FIREWALL, "DHCP-ALLOCATION-FAILURE": FaultDomain.DHCP,
    "DNS-RESOLUTION-FAILURE": FaultDomain.DNS, "VLAN-AUTHENTICATION-FAILURE": FaultDomain.VLAN_AUTHENTICATION,
    "SHARED-DEVICE-FAILURE": FaultDomain.SHARED_INFRASTRUCTURE,
}


@pytest.mark.parametrize("scenario_id, domain", sorted(EXPECTED.items()))
def test_rule_based_diagnosis_is_associated(service: IncidentService, scenario_id: str, domain: FaultDomain) -> None:
    incident = diagnosed(service, scenario_id)
    record = incident.active_diagnosis
    assert incident.status == LifecycleStatus.DIAGNOSED
    assert record.diagnosis_id == f"DGN-{incident.incident_id[4:]}-01" and record.method == DiagnosisMethod.RULE_BASED
    assert record.probable_fault_domain == domain and record.human_verified is False
    assert incident.classification.probable_fault_domain == domain
    assert incident.classification.confirmed_fault_domain is None
    truth = load_scenario(scenario_id).ground_truth
    devices = {a.asset_id for a in incident.affected_assets if a.asset_type in (AssetType.DEVICE, AssetType.SHARED_DEPENDENCY)}
    assert set(truth.root_cause_device_ids) & devices
    evidence_ids = {item.evidence_id for item in record.diagnosis.evidence}
    assert incident.evidence and all(link.evidence_id in evidence_ids for link in incident.evidence)
    assert {link.evidence_id for link in incident.evidence} <= set(record.diagnosis.fault.supporting_evidence_ids)


def test_diagnosis_does_not_resolve_or_confirm(service: IncidentService) -> None:
    incident = diagnosed(service)
    assert incident.status == LifecycleStatus.DIAGNOSED and incident.resolutions == []
    event = next(e for e in incident.timeline if e.event_type.value == "diagnosis_completed")
    assert "Requires human verification" in event.description and event.diagnosis_id == incident.active_diagnosis_id
    assert event.evidence_ids and event.details["method"] == "rule_based"


def test_alternatives_and_confidence_are_preserved(service: IncidentService) -> None:
    incident = diagnosed(service, "SHARED-DEVICE-FAILURE")
    record = incident.active_diagnosis
    assert record.alternative_fault_domains == [FaultDomain.WAN_ISP, FaultDomain.WAN_ISP]
    assert record.confidence == Confidence.HIGH
    assert [a.fault_domain for a in record.diagnosis.alternatives] == record.alternative_fault_domains
    shared = [a for a in incident.affected_assets if a.asset_type == AssetType.SHARED_DEPENDENCY]
    assert [a.asset_id for a in shared] == ["CORE-RTR-01"] and shared[0].basis == ImpactBasis.INFERRED


def test_new_diagnosis_supersedes_without_deleting_history(service: IncidentService) -> None:
    incident = diagnosed(service)
    first = incident.active_diagnosis_id
    again = service.run_diagnosis(incident.incident_id, SYSTEM)
    assert len(again.diagnoses) == 2 and again.active_diagnosis_id != first
    assert again.diagnoses[0].superseded_by == again.active_diagnosis_id and again.diagnoses[1].superseded_by is None
    assert any(e.event_type.value == "diagnosis_superseded" and e.diagnosis_id == first for e in again.timeline)
    history = service.diagnosis_history(incident.incident_id)
    assert [h.diagnosis_id for h in history] == [first, again.active_diagnosis_id]
    assert history[1].changes_from_previous == []


def test_model_diagnosis_with_mocked_provider(service: IncidentService) -> None:
    def step(messages: list, tools: object):
        evidence = tool_evidence(messages, "NO_ROUTE_TO_DESTINATION") + tool_evidence(messages, "LINK_DOWN_AT_FAILURE_POINT")
        return final(draft(supporting_evidence_ids=evidence))
    provider = ScriptedProvider([tool_call("check_network_reachability", {"source": "SIN-SW-01", "destination": "DC1-SRV-APP-01"}), step])
    incident = create(service)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    updated = service.run_diagnosis(incident.incident_id, SYSTEM, DiagnosisEngine(provider))
    record = updated.active_diagnosis
    assert record.method == DiagnosisMethod.MODEL and record.diagnosis.provider.name == "scripted"
    assert updated.classification.probable_fault_domain == FaultDomain.WAN_ISP
    request = json.loads(provider.calls[0]["messages"][1]["content"])
    assert request["untrusted_incident"]["incident_id"] == incident.incident_id


def test_fallback_diagnosis_is_labelled(service: IncidentService) -> None:
    provider = ScriptedProvider([tool_call("check_network_reachability", {"source": "SIN-SW-01", "destination": "DC1-SRV-APP-01"}),
                                 final("not json")])
    incident = create(service)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    updated = service.run_diagnosis(incident.incident_id, SYSTEM, DiagnosisEngine(provider))
    assert updated.active_diagnosis.method == DiagnosisMethod.RULE_BASED_FALLBACK
    completed = next(e for e in updated.timeline if e.event_type.value == "diagnosis_completed")
    assert completed.description.startswith("rule_based_fallback diagnosis")


def test_unknown_diagnosis_keeps_investigating(service: IncidentService) -> None:
    incident = create(service, "WAN-FAILURE", site_ids=["NYC"], dataset_scenario_id="BASELINE",
                      title="NYC users report slowness", description="Users report the ERP portal felt slow")
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    updated = service.run_diagnosis(incident.incident_id, SYSTEM)
    assert updated.status == LifecycleStatus.INVESTIGATING
    assert updated.classification.probable_fault_domain == FaultDomain.UNKNOWN
    assert updated.severity.value == "medium"


def test_diagnosis_preconditions(service: IncidentService) -> None:
    incident = create(service)
    with pytest.raises(InvalidTransitionError):
        service.run_diagnosis(incident.incident_id, SYSTEM)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    other = diagnose(DiagnosisRequest(scenario_id="PACKET-LOSS", description="NYC slow", site_ids=["NYC"]))
    with pytest.raises(IncidentValidationError, match="different dataset"):
        service.associate_diagnosis(incident.incident_id, SYSTEM, other)
    with pytest.raises(IncidentValidationError):
        service.associate_diagnosis(incident.incident_id, SYSTEM, {"fault": "fake"})
    unlinked = create(service, dataset_scenario_id=None, force_new=True)
    service.change_status(unlinked.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    with pytest.raises(IncidentValidationError, match="not linked"):
        service.run_diagnosis(unlinked.incident_id, SYSTEM)


def test_affected_scope_tracking(service: IncidentService) -> None:
    incident = diagnosed(service)
    assets = {(a.asset_type.value, a.asset_id): a for a in incident.affected_assets}
    assert assets[("site", "SIN")].basis == ImpactBasis.REPORTED
    assert assets[("link", "LNK-WAN-SIN")].basis == ImpactBasis.INFERRED
    assert ("interface", "SIN-RTR-01:Gi0/0/0") in assets and ("path", "PATH-SIN-APPLICATION") in assets
    assert {"application", "dns", "internet"} <= {a.asset_id for a in incident.affected_assets if a.asset_type == AssetType.SERVICE}
    assert all(source.startswith(("human:", "diagnosis:")) for a in incident.affected_assets for source in a.sources)
    assert incident.affected_path == ["SIN-SW-01", "SIN-RTR-01"]
    assert len({(a.asset_type, a.asset_id) for a in incident.affected_assets}) == len(incident.affected_assets)
