from app.advanced.layers import assign_roles, cross_layer, layer_of, onset_of
from app.advanced.schema import EvidenceRole, Layer, LayerStatus
from app.engine import DiagnosisRequest, diagnose
from app.engine.evidence import build_catalog
from app.engine.executor import ToolExecutor
from verification.advanced_diagnosis.helpers import analysis


def layers(result) -> dict[Layer, LayerStatus]:
    return {summary.layer: summary.status for summary in result.cross_layer.layers}


def test_cross_layer_correlation_links_physical_and_routing() -> None:
    result = analysis("WAN-FAILURE")
    status = layers(result)
    assert status[Layer.PHYSICAL_INTERFACE] == status[Layer.ROUTING] == LayerStatus.FAULT_INDICATED
    assert status[Layer.FIREWALL_SECURITY] == LayerStatus.NO_EVIDENCE
    pair = next(c for c in result.cross_layer.correlations if {c.from_layer, c.to_layer} == {Layer.ROUTING, Layer.PHYSICAL_INTERFACE})
    assert pair.relation == "concurrent" and abs(pair.seconds_apart) <= 60
    assert all(c.from_layer == pair.from_layer for c in result.cross_layer.correlations)


def test_timestamps_are_aligned_to_onset() -> None:
    result = analysis("OSPF-ADJACENCY-FAILURE")
    onset = result.cross_layer.onset
    assert onset == onset_of(result.base)
    for entry in result.cross_layer.aligned_evidence:
        if entry.timestamp is not None:
            assert entry.seconds_from_onset == int((entry.timestamp - onset).total_seconds())
    stamps = [e.timestamp for e in result.cross_layer.aligned_evidence if e.timestamp]
    assert stamps == sorted(stamps)


def test_unrelated_background_events_are_separated() -> None:
    result = analysis("OSPF-ADJACENCY-FAILURE")
    background = [e for e in result.cross_layer.aligned_evidence if e.role == EvidenceRole.UNRELATED_BACKGROUND]
    assert background and {e.code for e in background} <= {"NTP_SYNC", "LOGIN_SUCCESS", "CONFIG_ARCHIVED"}
    assert not set(e.evidence_id for e in background) & set(result.primary_fault.supporting_evidence_ids)


def test_conflicting_evidence_is_reported() -> None:
    result = analysis("SHARED-DEVICE-FAILURE")
    assert any("contradicts the alternative wan_isp hypothesis" in conflict for conflict in result.cross_layer.conflicts)
    assert all(e.role != EvidenceRole.PRIMARY_FAULT for e in result.cross_layer.aligned_evidence if e.role == EvidenceRole.CONTRADICTING)


def test_missing_telemetry_is_reported_not_invented() -> None:
    result = analysis("SHARED-DEVICE-FAILURE")
    assert any("No statistics for CORE-RTR-01" in note and "not evidence of failure" in note
               for note in result.cross_layer.missing_telemetry)
    assert all(e.timestamp is None or e.seconds_from_onset is not None for e in result.cross_layer.aligned_evidence)


def test_multiple_candidate_faults_without_corroboration() -> None:
    executor = ToolExecutor("SHARED-DEVICE-FAILURE")
    for source in ("NYC-SW-01", "SIN-SW-01"):
        executor.execute("check_network_reachability", {"source": source, "destination": "DC1-SRV-APP-01"})
    catalog = build_catalog(executor.records)
    plain = diagnose(DiagnosisRequest(scenario_id="SHARED-DEVICE-FAILURE", description="x", site_ids=["NYC", "SIN"]))
    roles = assign_roles(plain, catalog)
    assert set(roles) == {item.evidence_id for item in catalog}
    view = cross_layer(plain, catalog, roles, executor.records)
    assert {s.layer for s in view.layers if s.status == LayerStatus.FAULT_INDICATED} >= {Layer.ROUTING}


def test_unknown_codes_fall_back_to_background_layer() -> None:
    assert layer_of("SOMETHING_NEW") == Layer.BACKGROUND and layer_of("DNS_SERVFAIL") == Layer.DNS
