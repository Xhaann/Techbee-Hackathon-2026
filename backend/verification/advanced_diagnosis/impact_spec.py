import json

from app.advanced import AdvancedDiagnosisEngine, AdvancedRequest
from app.incidents import IncidentService, JsonIncidentRepository
from app.incidents.models import AssetType, ImpactBasis
from app.incidents.service import AssetUpdate
from verification.advanced_diagnosis.helpers import KNOWLEDGE, analysis, items
from verification.engine.helpers import incident_request
from verification.incidents.helpers import HUMAN, SteppingClock, create


def test_directly_observed_assets() -> None:
    result = analysis("PACKET-LOSS")
    assert items(result, "observed", "interface") >= {"NYC-RTR-01:Gi0/0/0"}
    assert items(result, "observed", "link") == {"LNK-WAN-NYC"}
    observed = [i for i in result.blast_radius.items if i.category.value == "observed" and i.asset_type.value == "interface"]
    assert all(i.evidence_ids for i in observed)


def test_inferred_assets_from_topology() -> None:
    result = analysis("WAN-FAILURE")
    assert items(result, "inferred", "path") == {f"PATH-SIN-{s}" for s in ("APPLICATION", "AUTHENTICATION", "DHCP", "DNS", "INTERNET")}
    assert items(result, "inferred", "service") == {f"SIN:{s}" for s in ("application", "authentication", "dhcp", "dns", "internet")}
    assert "CORE-RTR-01" not in items(result, "observed", "device")


def test_shared_dependency_and_multi_site_impact() -> None:
    result = analysis("SHARED-DEVICE-FAILURE")
    radius = result.blast_radius
    assert radius.affected_sites == ["NYC", "SIN"] and radius.potentially_affected_sites == []
    assert "CORE-RTR-01" in radius.shared_dependencies
    assert items(result, "observed", "device") == {"CORE-RTR-01", "NYC-RTR-01", "SIN-RTR-01"}
    assert not any(path.startswith("PATH-BLR") for path in items(result, "inferred", "path"))


def test_potential_impact_is_unverified_and_separate() -> None:
    result = analysis("DHCP-ALLOCATION-FAILURE")
    radius = result.blast_radius
    assert radius.affected_sites == ["BLR"] and radius.potentially_affected_sites == ["NYC", "SIN"]
    assert items(result, "potential", "path") == {"PATH-NYC-DHCP", "PATH-SIN-DHCP"}
    assert all("no evidence was collected" in i.basis for i in radius.items if i.category.value == "potential")


def test_no_business_impact_claims() -> None:
    for scenario in ("SHARED-DEVICE-FAILURE", "DNS-RESOLUTION-FAILURE"):
        radius = analysis(scenario).blast_radius
        text = json.dumps(radius.model_dump(mode="json")).lower()
        assert radius.business_impact == "not_assessed" and "not assessed" in radius.note
        for term in ("revenue", "customer impact", "sla breach", "cost"):
            assert term not in text.replace("customer, financial and sla impact are not assessed", "")


def test_reported_and_confirmed_assets_from_incident(tmp_path) -> None:
    incidents = IncidentService(JsonIncidentRepository(tmp_path / "store"), SteppingClock())
    incident = create(incidents, "WAN-FAILURE")
    incidents.update_affected_assets(incident.incident_id, HUMAN, [AssetUpdate(asset_type=AssetType.DEVICE, asset_id="SIN-SW-01",
                                                                               basis=ImpactBasis.CONFIRMED)])
    engine = AdvancedDiagnosisEngine(knowledge=KNOWLEDGE, incidents=incidents)
    result = engine.analyze(AdvancedRequest(diagnosis=incident_request("WAN-FAILURE"), incident_id=incident.incident_id))
    assert "SIN" in items(result, "reported", "site")
    confirmed = next(i for i in result.blast_radius.items if i.asset_id == "SIN-SW-01")
    assert confirmed.category.value == "observed" and "confirmed by a human" in confirmed.basis
