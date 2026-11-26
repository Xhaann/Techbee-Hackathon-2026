import pytest

from app.diagnostics import analyze_routing_adjacency, get_routing_state
from verification.diagnostics.helpers import codes, failed, ok


def test_routing_state_baseline() -> None:
    result = ok(get_routing_state("BASELINE", "NYC-RTR-01"))
    data = result.data
    table = data["routing_table"]
    assert table["route_count"] == table["returned_route_count"] > 5
    assert set(table["protocol_counts"]) == {"bgp", "connected"}
    assert data["bgp_asn"] == 65010 and data["router_id"] == "10.255.1.10"
    assert [n["state"] for n in data["bgp_neighbors"]] == ["established"]
    assert data["next_hops"] == [{"next_hop": "172.16.0.1", "interface_id": "NYC-RTR-01:Gi0/0/0", "protocol": "bgp"}]
    assert data["route_changes"] == [] and result.findings == []
    assert data["assessment"] == "observed"


def test_routing_state_prefix_lookup() -> None:
    data = ok(get_routing_state("BASELINE", "CORE-SW-01", prefix="10.10.10.25/32")).data
    assert data["best_match"]["prefix"] == "10.10.10.0/24" and data["best_match"]["protocol"] == "ospf"
    assert data["best_match"]["next_hop"] == "10.0.0.1"
    covering = ok(get_routing_state("BASELINE", "CORE-SW-01", prefix="10.10.0.0/16")).data
    assert {r["prefix"] for r in covering["routing_table"]["routes"]} == {"0.0.0.0/0", "10.10.10.0/24", "10.10.20.0/24",
                                                                         "10.10.99.0/24"}
    empty = ok(get_routing_state("BASELINE", "CORE-SW-01", prefix="192.0.2.0/24"))
    assert empty.data["routing_table"]["returned_route_count"] == 1 and empty.data["best_match"] is None


def test_routing_state_wan_failure() -> None:
    result = ok(get_routing_state("WAN-FAILURE", "SIN-RTR-01"))
    data = result.data
    assert set(data["routing_table"]["protocol_counts"]) == {"connected"}
    assert data["bgp_neighbors"][0]["state"] == "idle"
    assert all(change["change_type"] == "withdrawn" for change in data["route_changes"])
    assert codes(result) == ["NEIGHBOR_NOT_ESTABLISHED", "ROUTES_WITHDRAWN"]
    assert all(finding.kind.value == "observed" for finding in result.findings)


def test_routing_state_ospf_stuck() -> None:
    result = ok(get_routing_state("OSPF-ADJACENCY-FAILURE", "CORE-RTR-02"))
    stuck = [n for n in result.data["ospf_neighbors"] if n["neighbor_device_id"] == "BLR-RTR-01"]
    assert stuck[0]["state"] == "exstart" and "MTU" in stuck[0]["failure_reason"]
    assert "NEIGHBOR_NOT_ESTABLISHED" in codes(result)


def test_routing_state_missing_table_is_not_failure() -> None:
    result = ok(get_routing_state("SHARED-DEVICE-FAILURE", "CORE-RTR-01"))
    assert result.data["routing_table"] is None and result.findings == []
    assert result.data["assessment"] == "indeterminate"
    assert "not proof of failure" in result.missing_data[0]
    server = ok(get_routing_state("BASELINE", "DC1-SRV-APP-01"))
    assert server.data["routing_table"] is None and server.missing_data == []
    assert server.data["assessment"] == "not_applicable"
    assert "does not participate in routing" in server.warnings[0]


@pytest.mark.parametrize("kwargs, code", [({"device_id": "NOPE-RTR-01"}, "NOT_FOUND"),
                                          ({"device_id": "CORE-SW-01", "prefix": "10.10.10.1/24"}, "INVALID_ARGUMENT"),
                                          ({"device_id": "CORE-SW-01", "prefix": "everything"}, "INVALID_ARGUMENT")])
def test_routing_state_rejects_bad_arguments(kwargs: dict, code: str) -> None:
    failed(get_routing_state("BASELINE", **kwargs), code)


def test_adjacency_baseline_is_healthy() -> None:
    result = ok(analyze_routing_adjacency("BASELINE", "CORE-RTR-01"))
    assert result.data["adjacency_counts"] == {"healthy": 4}
    assert result.findings == []


def test_adjacency_mtu_failure_is_control_plane() -> None:
    result = ok(analyze_routing_adjacency("OSPF-ADJACENCY-FAILURE", "BLR-RTR-01"))
    adjacency = result.data["adjacencies"][0]
    assert adjacency["status"] == "stalled" and adjacency["link_id"] == "LNK-WAN-BLR"
    assert [state["latest_status"] for state in adjacency["interface_status"]] == ["up", "up"]
    assert {"OSPF_ADJACENCY_DOWN", "MTU_CHANGE"} <= {e["event_type"] for e in adjacency["related_events"]}
    assert adjacency["related_route_changes"]
    assert codes(result, "observed") == ["ADJACENCY_STALLED"]
    assert codes(result, "inferred") == ["CONTROL_PLANE_FAILURE_SUSPECTED"]


def test_adjacency_failure_after_interface_down() -> None:
    result = ok(analyze_routing_adjacency("WAN-FAILURE", "CORE-RTR-01"))
    counts = result.data["adjacency_counts"]
    assert counts == {"failed": 1, "healthy": 3}
    failed_adjacency = next(a for a in result.data["adjacencies"] if a["status"] == "failed")
    assert failed_adjacency["peer_device_id"] == "SIN-RTR-01" and failed_adjacency["protocol"] == "bgp"
    assert codes(result, "inferred") == ["ADJACENCY_LOSS_FOLLOWS_INTERFACE_DOWN"]


def test_adjacency_uses_peer_view_when_device_silent() -> None:
    result = ok(analyze_routing_adjacency("SHARED-DEVICE-FAILURE", "CORE-RTR-01"))
    assert result.data["adjacency_counts"] == {"failed": 4}
    assert all(a["local_view"] is None and a["peer_view"] is not None for a in result.data["adjacencies"])
    assert len(result.missing_data) == 4 and all("peer-reported state" in item for item in result.missing_data)


def test_adjacency_for_non_routing_device() -> None:
    result = ok(analyze_routing_adjacency("BASELINE", "NYC-SW-01"))
    assert result.data["adjacencies"] == [] and result.warnings
