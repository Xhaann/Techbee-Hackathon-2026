import json

import pytest

from app.engine import DiagnosisEngine, DiagnosisRequest, DiagnosisRequestError, diagnose
from app.engine import engine as engine_module
from app.engine.executor import ToolExecutor
from app.engine.registry import REGISTRY, ToolSpec
from app.engine.safety import is_read_only_command
from app.engine.schema import Confidence, DiagnosisMethod, DiagnosisStatus, FaultDomain, TimelineRelevance
from app.network.repository import load_scenario, load_topology
from verification.engine.helpers import incident_request

EXPECTED = {
    "WAN-FAILURE": FaultDomain.WAN_ISP,
    "PACKET-LOSS": FaultDomain.WAN_ISP,
    "OSPF-ADJACENCY-FAILURE": FaultDomain.ROUTING,
    "FIREWALL-BLOCKING": FaultDomain.FIREWALL,
    "DHCP-ALLOCATION-FAILURE": FaultDomain.DHCP,
    "DNS-RESOLUTION-FAILURE": FaultDomain.DNS,
    "VLAN-AUTHENTICATION-FAILURE": FaultDomain.VLAN_AUTHENTICATION,
    "SHARED-DEVICE-FAILURE": FaultDomain.SHARED_INFRASTRUCTURE,
}


@pytest.mark.parametrize("scenario_id, domain", sorted(EXPECTED.items()))
def test_rule_based_diagnosis_identifies_each_scenario(scenario_id: str, domain: FaultDomain) -> None:
    truth = load_scenario(scenario_id).ground_truth
    diagnosis = diagnose(incident_request(scenario_id))
    assert diagnosis.method == DiagnosisMethod.RULE_BASED and diagnosis.provider is None
    assert diagnosis.incident.status == DiagnosisStatus.COMPLETED
    assert diagnosis.fault.fault_domain == domain
    assert set(truth.root_cause_device_ids) & set(diagnosis.fault.device_ids)
    if domain == FaultDomain.SHARED_INFRASTRUCTURE:
        assert sorted(diagnosis.fault.link_ids) == ["LNK-WAN-NYC", "LNK-WAN-SIN"]
    else:
        assert diagnosis.fault.link_ids == sorted(truth.root_cause_link_ids)
    assert diagnosis.confidence.level == Confidence.HIGH
    assert diagnosis.fault.supporting_evidence_ids and diagnosis.fault.verified_against_rules
    assert 1 <= len(diagnosis.tool_calls) <= 10
    assert diagnosis.validation_issues == [] and diagnosis.human_verification_required is True


@pytest.mark.parametrize("scenario_id", sorted(EXPECTED))
def test_diagnosis_structure_is_complete_and_grounded(scenario_id: str) -> None:
    diagnosis = diagnose(incident_request(scenario_id))
    devices = {device.device_id for device in load_topology().devices}
    evidence = {item.evidence_id: item for item in diagnosis.evidence}
    assert set(diagnosis.fault.supporting_evidence_ids) <= set(evidence)
    assert {entry.evidence_id for entry in diagnosis.timeline} <= set(evidence)
    assert diagnosis.affected_path is not None and diagnosis.affected_path.path
    assert set(diagnosis.affected_path.affected_devices) <= devices
    assert [entry.timestamp for entry in diagnosis.timeline] == sorted(entry.timestamp for entry in diagnosis.timeline)
    assert any(entry.relevance == TimelineRelevance.FAULT_ONSET for entry in diagnosis.timeline)
    assert diagnosis.next_checks and all(is_read_only_command(check.command) for check in diagnosis.next_checks)
    assert all(check.device_id in devices for check in diagnosis.next_checks)
    assert diagnosis.escalation.team and diagnosis.escalation.evidence_ids
    assert diagnosis.escalation.priority == load_scenario(scenario_id).incident.priority
    explanation = diagnosis.explanation
    assert explanation.summary and explanation.observed_facts and explanation.hypotheses and explanation.recommended_actions
    assert all(item.evidence_type.value in ("observed_finding", "inferred_finding", "observed_result", "record")
               for item in diagnosis.evidence)
    json.dumps(diagnosis.model_dump(mode="json"))


def test_healthy_baseline_has_no_false_positive() -> None:
    request = DiagnosisRequest(scenario_id="BASELINE", site_ids=["NYC", "SIN", "BLR"],
                               description="Users report the ERP portal felt slow this morning.")
    diagnosis = diagnose(request)
    assert diagnosis.incident.status == DiagnosisStatus.NO_FAULT_IDENTIFIED
    assert diagnosis.fault.fault_domain == FaultDomain.UNKNOWN and diagnosis.fault.device_ids == []
    assert diagnosis.confidence.level == Confidence.INSUFFICIENT_EVIDENCE
    assert diagnosis.alternatives == [] and diagnosis.validation_issues == []
    assert diagnosis.next_checks and all(is_read_only_command(c.command) for c in diagnosis.next_checks)


def test_deterministic_output() -> None:
    first = diagnose(incident_request("SHARED-DEVICE-FAILURE")).model_dump(mode="json")
    second = diagnose(incident_request("SHARED-DEVICE-FAILURE")).model_dump(mode="json")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_early_termination_when_evidence_is_sufficient() -> None:
    diagnosis = diagnose(incident_request("DHCP-ALLOCATION-FAILURE"))
    assert [call.tool for call in diagnosis.tool_calls] == ["check_network_reachability", "get_dhcp_dns_status"]
    wan = diagnose(incident_request("WAN-FAILURE"))
    assert len(wan.tool_calls) < 10 and "get_firewall_logs" not in [call.tool for call in wan.tool_calls]


def test_tools_are_chosen_from_findings() -> None:
    routing = [c.tool for c in diagnose(incident_request("OSPF-ADJACENCY-FAILURE")).tool_calls]
    assert "analyze_routing_adjacency" in routing and "analyze_packet_loss" not in routing
    loss = [c.tool for c in diagnose(incident_request("PACKET-LOSS")).tool_calls]
    assert "analyze_interface_errors" in loss and "analyze_routing_adjacency" not in loss
    baseline = [c.tool for c in diagnose(DiagnosisRequest(scenario_id="BASELINE", site_ids=["NYC"], description="slow")).tool_calls]
    assert "analyze_interface_errors" not in baseline


def test_site_detection_from_description() -> None:
    def sites(scenario: str, description: str) -> list[str]:
        return diagnose(DiagnosisRequest(scenario_id=scenario, description=description)).incident.site_ids
    assert sites("WAN-FAILURE", "All users in the Singapore branch report outages") == ["SIN"]
    assert sites("DNS-RESOLUTION-FAILURE", "Users at all branches cannot resolve names") == ["NYC", "SIN", "BLR"]
    assert sites("SHARED-DEVICE-FAILURE", "New York and Singapore are down; Bengaluru is unaffected") == ["NYC", "SIN"]


def test_insufficient_evidence_without_site() -> None:
    diagnosis = diagnose(DiagnosisRequest(scenario_id="WAN-FAILURE", description="Something is wrong with the network"))
    assert diagnosis.incident.status == DiagnosisStatus.INSUFFICIENT_EVIDENCE
    assert diagnosis.tool_calls == [] and diagnosis.confidence.level == Confidence.INSUFFICIENT_EVIDENCE
    assert any("supply site_ids" in item for item in diagnosis.limitations)


def test_tool_budget_exhaustion_produces_partial_diagnosis() -> None:
    diagnosis = DiagnosisEngine(max_tool_calls=1).diagnose(incident_request("WAN-FAILURE"))
    assert len([c for c in diagnosis.tool_calls if c.status == "executed"]) == 1
    assert diagnosis.incident.status == DiagnosisStatus.PARTIAL
    assert any("budget" in item for item in diagnosis.limitations)
    assert diagnosis.confidence.level != Confidence.HIGH


def test_tool_failures_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    registry = dict(REGISTRY)
    spec = REGISTRY["check_network_reachability"]
    registry[spec.name] = ToolSpec(spec.name, spec.description, spec.arguments, broken, True)
    monkeypatch.setattr(engine_module, "ToolExecutor",
                        lambda scenario_id, max_calls: ToolExecutor(scenario_id, registry=registry, max_calls=max_calls))
    diagnosis = diagnose(incident_request("WAN-FAILURE"))
    assert any("TOOL_EXECUTION_ERROR" in item for item in diagnosis.limitations)
    assert diagnosis.incident.status != DiagnosisStatus.COMPLETED


@pytest.mark.parametrize("request_values", [{"scenario_id": "NOPE"}, {"scenario_id": "WAN-FAILURE", "site_ids": ["MARS"]}])
def test_invalid_requests_are_rejected(request_values: dict) -> None:
    with pytest.raises(DiagnosisRequestError):
        diagnose(DiagnosisRequest(description="Branch offline", **request_values))


@pytest.mark.parametrize("values", [{"description": ""}, {"description": "x" * 5000}, {"scenario_id": "../etc"},
                                    {"site_ids": ["A"] * 6}, {"severity": "urgent"}, {"reported_at": "2026-03-02T09:00:00"},
                                    {"unexpected": 1}])
def test_request_schema_validation(values: dict) -> None:
    with pytest.raises(ValueError):
        DiagnosisRequest(**({"scenario_id": "BASELINE", "description": "x"} | values))
