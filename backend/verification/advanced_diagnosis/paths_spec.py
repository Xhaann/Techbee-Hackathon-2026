from app.advanced.paths import alternatives, analyze_paths
from app.engine import DiagnosisRequest, diagnose
from app.engine.executor import ToolExecutor
from app.network.repository import load_topology
from verification.advanced_diagnosis.helpers import analysis

TOPOLOGY = load_topology()


def test_complete_path_has_roles_links_and_protocols() -> None:
    path = analysis("FIREWALL-BLOCKING").paths[0]
    assert path.status == "reachable" and path.complete
    assert [h.device_id for h in path.hops] == ["SIN-SW-01", "SIN-RTR-01", "CORE-RTR-01", "CORE-SW-01", "DC1-FW-01", "DC1-SW-01",
                                                "DC1-SRV-APP-01"]
    assert [h.role for h in path.hops][::6] == ["source", "destination"]
    assert path.hops[1].link_to_next == "LNK-WAN-SIN" and path.hops[1].routing_protocol == "bgp"
    assert path.hops[1].interfaces == ["CORE-RTR-01:Gi0/0/3", "SIN-RTR-01:Gi0/0/0"]
    assert path.modelled_path_id == "PATH-SIN-APPLICATION" and path.earliest_affected_point is None


def test_incomplete_path_and_failed_link() -> None:
    path = analysis("WAN-FAILURE").paths[0]
    assert path.status == "unreachable" and not path.complete
    assert path.failed_links == ["LNK-WAN-SIN"] and path.earliest_affected_point == "SIN-RTR-01"
    assert path.hops[-1].role == "intermediate" and path.modelled_path_devices[-1] == "DC1-SRV-APP-01"
    assert any("modelled path is shown for reference only" in note for note in path.limitations)


def test_one_way_reachability_limitation_is_explicit() -> None:
    for scenario in ("FIREWALL-BLOCKING", "WAN-FAILURE"):
        assert all(any("return path was not evaluated" in note for note in p.limitations) for p in analysis(scenario).paths)


def test_shared_dependencies_and_fault_beyond_failure_point() -> None:
    paths = analysis("SHARED-DEVICE-FAILURE").paths
    assert len(paths) == 2 and all(p.shared_devices[0] == "CORE-RTR-01" for p in paths)
    assert {p.earliest_affected_point for p in paths} == {"NYC-RTR-01", "SIN-RTR-01"}
    assert all(any("CORE-RTR-01 lies beyond it" in note for note in p.limitations) for p in paths)


def test_degraded_link_is_identified() -> None:
    path = analysis("PACKET-LOSS").paths[0]
    assert path.status == "reachable" and path.degraded_links == ["LNK-WAN-NYC"] and path.earliest_affected_point == "NYC-RTR-01"


def test_alternatives_come_only_from_topology() -> None:
    assert alternatives(TOPOLOGY, "SIN-SW-01", "DC1-SRV-APP-01", {"LNK-WAN-SIN"}, set(), []) == []
    route = alternatives(TOPOLOGY, "NYC-SW-01", "DC1-SRV-APP-01", {"LNK-CORE-RTR01-SW01"}, set(),
                         ["NYC-SW-01", "NYC-RTR-01", "CORE-RTR-01", "CORE-SW-01"])
    assert route == [["NYC-SW-01", "NYC-RTR-01", "CORE-RTR-01", "CORE-RTR-02", "CORE-SW-01", "DC1-FW-01", "DC1-SW-01", "DC1-SRV-APP-01"]]
    assert alternatives(TOPOLOGY, "NYC-SW-01", "DC1-SRV-APP-01", set(), set(), []) == []
    assert all(p.topology_alternatives == [] for p in analysis("SHARED-DEVICE-FAILURE").paths)


def test_missing_reachability_data_yields_no_invented_path() -> None:
    diagnosis = diagnose(DiagnosisRequest(scenario_id="WAN-FAILURE", description="x", site_ids=["SIN"]))
    executor = ToolExecutor("WAN-FAILURE")
    executor.execute("get_routing_state", {"device_id": "SIN-RTR-01"})
    assert analyze_paths(executor.records, TOPOLOGY, diagnosis, set()) == []
    indeterminate = ToolExecutor("SHARED-DEVICE-FAILURE")
    indeterminate.execute("check_network_reachability", {"source": "CORE-RTR-01", "destination": "DC1-SRV-APP-01"})
    result = analyze_paths(indeterminate.records, TOPOLOGY, diagnosis, set())[0]
    assert result.status == "indeterminate" and not result.complete
    assert any("indeterminate: no_routing_telemetry" in note for note in result.limitations)
