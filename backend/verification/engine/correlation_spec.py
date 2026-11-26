from app.engine import diagnose
from app.engine.correlation import correlate
from app.engine.evidence import build_catalog
from app.engine.executor import ToolExecutor
from app.engine.schema import Confidence, EvidenceType, FaultDomain, TimelineRelevance
from app.network.repository import load_scenario, load_topology
from verification.engine.helpers import incident_request


def correlation_for(scenario_id: str, calls: list[tuple[str, dict]], sites: list[str]):
    executor = ToolExecutor(scenario_id)
    for name, arguments in calls:
        executor.execute(name, arguments)
    catalog = build_catalog(executor.records)
    return correlate(executor.records, catalog, load_topology(), sites), catalog


def test_shared_device_is_preferred_over_independent_branch_failures() -> None:
    diagnosis = diagnose(incident_request("SHARED-DEVICE-FAILURE"))
    assert diagnosis.fault.fault_domain == FaultDomain.SHARED_INFRASTRUCTURE
    assert diagnosis.fault.device_ids == ["CORE-RTR-01"]
    assert sorted(diagnosis.fault.link_ids) == ["LNK-WAN-NYC", "LNK-WAN-SIN"]
    wan = [a for a in diagnosis.alternatives if a.fault_domain == FaultDomain.WAN_ISP]
    assert len(wan) == 2 and all(a.contradictory_evidence_ids for a in wan)
    assert diagnosis.affected_path.shared_dependencies == ["CORE-RTR-01"]
    codes = {item.code for item in diagnosis.evidence if item.evidence_id in diagnosis.fault.supporting_evidence_ids}
    assert {"TELEMETRY_GAP", "PEER_LINKS_DOWN", "DEVICE_FAILURE_LIKELY", "NO_ROUTE_TO_DESTINATION"} <= codes


def test_without_availability_evidence_branches_are_not_attributed_to_shared_device() -> None:
    calls = [("check_network_reachability", {"source": "NYC-SW-01", "destination": "DC1-SRV-APP-01"}),
             ("check_network_reachability", {"source": "SIN-SW-01", "destination": "DC1-SRV-APP-01"})]
    correlation, _ = correlation_for("SHARED-DEVICE-FAILURE", calls, ["NYC", "SIN"])
    assert correlation.top.domain == FaultDomain.WAN_ISP
    assert correlation.confidence != Confidence.HIGH


def test_contradictory_evidence_for_device_failure_alternative() -> None:
    diagnosis = diagnose(incident_request("WAN-FAILURE"))
    alternative = next(a for a in diagnosis.alternatives if a.fault_domain == FaultDomain.NETWORK_DEVICE_FAILURE)
    contradicting = [item for item in diagnosis.evidence if item.evidence_id in alternative.contradictory_evidence_ids]
    assert [item.code for item in contradicting] == ["DEVICE_AVAILABLE_WITH_FAULTS"]
    assert contradicting[0].device_id == "CORE-RTR-01"


def test_service_faults_exclude_connectivity_alternative() -> None:
    for scenario_id in ("FIREWALL-BLOCKING", "DHCP-ALLOCATION-FAILURE", "DNS-RESOLUTION-FAILURE", "VLAN-AUTHENTICATION-FAILURE"):
        diagnosis = diagnose(incident_request(scenario_id))
        wan = [a for a in diagnosis.alternatives if a.fault_domain == FaultDomain.WAN_ISP]
        assert wan and all(a.contradictory_evidence_ids for a in wan)
        contradicting = {item.code for item in diagnosis.evidence for a in wan if item.evidence_id in a.contradictory_evidence_ids}
        assert contradicting == {"PATH_REACHABLE"}


def test_dns_isolation_is_not_treated_as_dns_server_fault() -> None:
    diagnosis = diagnose(incident_request("WAN-FAILURE"))
    assert diagnosis.fault.fault_domain == FaultDomain.WAN_ISP
    assert all(a.fault_domain != FaultDomain.DNS for a in diagnosis.alternatives)
    assert all(d not in diagnosis.fault.device_ids for d in ("DC1-SRV-DNS-01", "DC1-SRV-DHCP-01"))


def test_timeline_ordering_and_cross_device_correlation() -> None:
    diagnosis = diagnose(incident_request("OSPF-ADJACENCY-FAILURE"))
    timeline = diagnosis.timeline
    assert [e.timestamp for e in timeline] == sorted(e.timestamp for e in timeline)
    onset = next(e for e in timeline if e.relevance == TimelineRelevance.FAULT_ONSET)
    assert onset.event_type == "CONFIG_CHANGE" and onset.device_id == "BLR-RTR-01"
    assert all(e.timestamp >= onset.timestamp for e in timeline if e.relevance == TimelineRelevance.CORRELATED)
    assert all(e.relevance in (TimelineRelevance.BACKGROUND, TimelineRelevance.CONCURRENT)
               for e in timeline if e.event_type in ("NTP_SYNC", "LOGIN_SUCCESS", "CONFIG_ARCHIVED"))


def test_cross_device_events_are_correlated_in_one_window() -> None:
    diagnosis = diagnose(incident_request("SHARED-DEVICE-FAILURE"))
    onset = next(e for e in diagnosis.timeline if e.relevance == TimelineRelevance.FAULT_ONSET)
    correlated = [e for e in diagnosis.timeline if e.relevance == TimelineRelevance.CORRELATED]
    assert {"CORE-RTR-01", "NYC-RTR-01", "SIN-RTR-01"} <= {e.device_id for e in correlated}
    assert all(e.timestamp >= onset.timestamp for e in correlated)
    assert any(e.relevance == TimelineRelevance.PRECEDES_FAULT and e.event_type == "TELEMETRY_GAP" for e in diagnosis.timeline)


def test_onset_precedes_incident_report() -> None:
    for scenario_id in ("WAN-FAILURE", "SHARED-DEVICE-FAILURE", "FIREWALL-BLOCKING", "PACKET-LOSS"):
        dataset = load_scenario(scenario_id)
        diagnosis = diagnose(incident_request(scenario_id))
        onset = next(e for e in diagnosis.timeline if e.relevance == TimelineRelevance.FAULT_ONSET)
        assert onset.timestamp <= dataset.incident.reported_at
        assert abs(onset.timestamp - dataset.scenario.onset_at).total_seconds() <= 180


def test_evidence_items_resolve_to_dataset_records() -> None:
    diagnosis = diagnose(incident_request("SHARED-DEVICE-FAILURE"))
    dataset = load_scenario("SHARED-DEVICE-FAILURE")
    events = {event.event_id for event in dataset.events}
    for item in diagnosis.evidence:
        for ref in item.references:
            if ref.collection == "events":
                assert ref.record_id in events
    assert all(item.call_id in {c.call_id for c in diagnosis.tool_calls} for item in diagnosis.evidence)


def test_confidence_is_not_high_for_single_tool_evidence() -> None:
    calls = [("get_dhcp_dns_status", {"site_id": "BLR"})]
    correlation, catalog = correlation_for("DHCP-ALLOCATION-FAILURE", calls, ["BLR"])
    assert correlation.top.domain == FaultDomain.DHCP
    assert correlation.confidence == Confidence.MEDIUM
    assert all(item.evidence_type != EvidenceType.RECORD for item in catalog)


def test_no_candidates_means_insufficient_evidence() -> None:
    correlation, _ = correlation_for("BASELINE", [("get_dhcp_dns_status", {"site_id": "NYC"})], ["NYC"])
    assert correlation.top is None and correlation.alternatives == []
    assert correlation.confidence == Confidence.INSUFFICIENT_EVIDENCE
