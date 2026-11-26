import json

import pytest

from app.advanced import AdvancedDiagnosisEngine, AdvancedRequest
from app.engine import diagnose
from app.incidents import IncidentService, InvalidTransitionError, JsonIncidentRepository, LifecycleStatus
from app.incidents.models import ImpactBasis
from app.main import create_app
from app.core.config import Settings
from fastapi.testclient import TestClient
from verification.advanced_diagnosis.helpers import KNOWLEDGE, analysis
from verification.api.helpers import EXPECTED_ROUTES, route_surface
from verification.engine.helpers import incident_request
from verification.incidents.helpers import HUMAN, SYSTEM, SteppingClock, create


def without_knowledge(diagnosis) -> dict:
    return diagnosis.model_dump(mode="json") | {"retrieved_document_ids": [], "security_flags": []}


def test_base_phase4_diagnosis_is_preserved() -> None:
    result = analysis("WAN-FAILURE")
    plain = diagnose(incident_request("WAN-FAILURE"))
    assert without_knowledge(result.base) == without_knowledge(plain)


def test_supplementary_calls_share_the_existing_budget() -> None:
    result = analysis("VLAN-AUTHENTICATION-FAILURE", supplementary=5)
    assert len(result.base.tool_calls) + len(result.supplementary_tool_calls) <= 10
    ids = [entry.split(":")[0] for entry in result.supplementary_tool_calls]
    assert ids == [f"C{len(result.base.tool_calls) + n}" for n in range(1, len(ids) + 1)]
    none = analysis("VLAN-AUTHENTICATION-FAILURE", supplementary=0)
    assert none.supplementary_tool_calls == []


def test_phase3_tool_contracts_feed_the_analysis() -> None:
    result = analysis("PACKET-LOSS")
    tools = {call.tool for call in result.base.tool_calls}
    assert {"check_network_reachability", "analyze_packet_loss", "analyze_interface_errors"} <= tools
    assert all(entry.split(":")[1] == "get_interface_stats" for entry in result.supplementary_tool_calls)


def test_phase6_playbooks_are_guidance_only() -> None:
    result = analysis("DNS-RESOLUTION-FAILURE")
    assert result.playbooks[0].record_id == "PB-DNS-RESOLUTION-FAILURE"
    assert result.primary_fault.confidence == result.base.confidence.level
    assert any(check.reason.startswith("Illustrative read-only check from") for check in result.next_checks)


def test_phase5_incident_integration(tmp_path) -> None:
    incidents = IncidentService(JsonIncidentRepository(tmp_path / "store"), SteppingClock())
    incident = create(incidents, "SHARED-DEVICE-FAILURE")
    engine = AdvancedDiagnosisEngine(knowledge=KNOWLEDGE, incidents=incidents)
    result = engine.analyze(AdvancedRequest(diagnosis=incident_request("SHARED-DEVICE-FAILURE"), incident_id=incident.incident_id))
    with pytest.raises(InvalidTransitionError):
        engine.apply_to_incident(result, SYSTEM)
    incidents.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    updated = engine.apply_to_incident(result, SYSTEM)
    assert updated.status == LifecycleStatus.DIAGNOSED and updated.active_diagnosis.diagnosis == result.base
    assert updated.classification.confirmed_fault_domain is None and updated.resolutions == [] and updated.escalations == []
    assert all(a.basis != ImpactBasis.CONFIRMED for a in updated.affected_assets)
    assert "CORE-RTR-01" in {a.asset_id for a in updated.affected_assets}
    assert {k.record_id for k in updated.knowledge_references} >= {"PB-SHARED-DEVICE-FAILURE"}
    again = engine.analyze(AdvancedRequest(diagnosis=incident_request("SHARED-DEVICE-FAILURE"), incident_id=incident.incident_id))
    assert again.primary_fault.status.value == "suspected"
    incidents.classify(incident.incident_id, HUMAN, result.primary_fault.fault_domain, "Confirmed on site")
    confirmed = engine.analyze(AdvancedRequest(diagnosis=incident_request("SHARED-DEVICE-FAILURE"), incident_id=incident.incident_id))
    assert confirmed.primary_fault.status.value == "human_confirmed"


def test_http_api_surface_unchanged() -> None:
    client = TestClient(create_app(Settings(_env_file=None)))
    assert route_surface(client) == EXPECTED_ROUTES
    assert client.get("/health").json() == {"status": "healthy"}
    json.dumps(analysis("WAN-FAILURE").model_dump(mode="json"))
