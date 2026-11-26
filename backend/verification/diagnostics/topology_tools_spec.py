import pytest

from app.diagnostics import analyze_network_dependencies, check_network_reachability, get_topology
from app.network.repository import load_topology
from verification.diagnostics.helpers import codes, failed, ok


def test_get_topology_for_branch() -> None:
    data = ok(get_topology("NYC")).data
    assert [device["device_id"] for device in data["devices"]] == ["NYC-RTR-01", "NYC-SW-01"]
    assert {vlan["vlan_id"] for vlan in data["vlans"]} == {10, 20, 99}
    scopes = {link["link_id"]: link["scope"] for link in data["links"]}
    assert scopes == {"LNK-WAN-NYC": "external", "LNK-NYC-RTR01-SW01": "internal"}
    assert data["dependencies"]["NYC-SW-01"]["upstream"] == ["NYC-RTR-01"]
    assert data["dependencies"]["NYC-RTR-01"]["upstream"] == ["CORE-RTR-01"]
    assert data["dependencies"]["NYC-RTR-01"]["downstream"] == ["NYC-SW-01"]
    assert "DC1-SRV-AUTH-01" in data["external_dependencies"]
    assert {path["path_id"] for path in data["paths"]} == {
        f"PATH-NYC-{service}" for service in ("APPLICATION", "AUTHENTICATION", "DHCP", "DNS", "INTERNET")
    }
    shared = {item["device_id"]: item for item in data["shared_infrastructure"]}
    assert shared["CORE-RTR-01"]["sites_using"] == ["NYC", "SIN"]
    assert shared["CORE-SW-01"]["sites_using"] == ["BLR", "NYC", "SIN"]


def test_get_topology_for_shared_site() -> None:
    data = ok(get_topology("CORE")).data
    assert {path["role"] for path in data["paths"]} == {"transit_or_destination"}
    assert len(data["paths"]) == 15
    assert data["dependencies"]["CORE-RTR-01"]["redundant_peers"] == ["CORE-RTR-02"]
    assert sorted(data["dependencies"]["CORE-RTR-01"]["downstream"]) == ["NYC-RTR-01", "SIN-RTR-01"]


@pytest.mark.parametrize("site_id, code", [("XYZ", "NOT_FOUND"), ("nyc", "INVALID_ARGUMENT"), ("../DC1", "INVALID_ARGUMENT"),
                                           (None, "INVALID_ARGUMENT"), (7, "INVALID_ARGUMENT")])
def test_get_topology_rejects_bad_sites(site_id: object, code: str) -> None:
    result = failed(get_topology(site_id), code)
    if code == "NOT_FOUND":
        assert "NYC" in result.error.message


def test_dependencies_for_shared_device() -> None:
    result = ok(analyze_network_dependencies(device_id="CORE-RTR-01"))
    impact = result.data["failure_impact"]
    assert impact["affected_sites"] == ["NYC", "SIN"]
    assert len(impact["affected_path_ids"]) == 10
    assert impact["affected_services"] == ["application", "authentication", "dhcp", "dns", "internet"]
    assert impact["dependent_devices"] == ["NYC-RTR-01", "NYC-SW-01", "SIN-RTR-01", "SIN-SW-01"]
    assert "DC1-SRV-APP-01" in impact["downstream_of_failure"]
    assert "CORE-RTR-01" in result.data["shared_devices"]
    links = {item["link_id"]: item["affected_path_ids"] for item in result.data["link_impact"]}
    assert len(links["LNK-WAN-NYC"]) == 5 and links["LNK-CORE-RTR01-RTR02"] == []
    assert result.warnings


def test_dependencies_for_site_and_device_scope() -> None:
    data = ok(analyze_network_dependencies(site_id="BLR", device_id="CORE-RTR-01")).data
    assert data["failure_impact"]["affected_path_ids"] == []
    site = ok(analyze_network_dependencies(site_id="SIN")).data
    assert "failure_impact" not in site
    assert set(site["common_to_all_paths_in_scope"]) == {"SIN-SW-01", "SIN-RTR-01", "CORE-RTR-01", "CORE-SW-01"}
    assert site["devices_by_path_count"][0]["path_count"] == 5


def test_dependencies_require_arguments() -> None:
    failed(analyze_network_dependencies(), "INVALID_ARGUMENT")
    failed(analyze_network_dependencies(device_id="NOPE-RTR-01"), "NOT_FOUND")
    failed(analyze_network_dependencies(site_id="MARS"), "NOT_FOUND")


def test_reachability_baseline() -> None:
    result = ok(check_network_reachability("BASELINE", "NYC-SW-01", "DC1-SRV-APP-01"))
    data = result.data
    assert data["status"] == "reachable" and data["failure_point"] is None
    assert data["path"] == ["NYC-SW-01", "NYC-RTR-01", "CORE-RTR-01", "CORE-SW-01", "DC1-FW-01", "DC1-SW-01",
                            "DC1-SRV-APP-01"]
    assert [hop["segment"] for hop in data["hops"]] == ["layer2", "layer3", "layer3", "layer3", "layer3", "delivery", "layer2"]
    assert data["evidence"]
    assert result.findings == []


def test_reachability_from_client_address() -> None:
    data = ok(check_network_reachability("BASELINE", "10.30.10.120", "10.100.100.10")).data
    assert data["source"]["device_id"] is None and data["first_hop_device_id"] == "BLR-RTR-01"
    assert data["status"] == "reachable"


def test_reachability_wan_failure_identifies_failed_link() -> None:
    result = ok(check_network_reachability("WAN-FAILURE", "SIN-SW-01", "DC1-SRV-DNS-01"))
    assert result.data["status"] == "unreachable"
    assert result.data["failure_point"] == {"device_id": "SIN-RTR-01", "reason": "no_route", "link_id": None,
                                            "down_link_ids": ["LNK-WAN-SIN"]}
    assert codes(result, "observed") == ["NO_ROUTE_TO_DESTINATION", "LINK_DOWN_AT_FAILURE_POINT"]
    assert all(finding.evidence for finding in result.findings)


def test_reachability_ospf_failure_has_no_down_link() -> None:
    result = ok(check_network_reachability("OSPF-ADJACENCY-FAILURE", "BLR-SW-01", "DC1-SRV-APP-01"))
    assert result.data["failure_point"]["device_id"] == "BLR-RTR-01"
    assert result.data["failure_point"]["down_link_ids"] == []
    assert codes(result) == ["NO_ROUTE_TO_DESTINATION"]


def test_reachability_shared_device_failure() -> None:
    for source in ("NYC-SW-01", "SIN-SW-01"):
        data = ok(check_network_reachability("SHARED-DEVICE-FAILURE", source, "DC1-SRV-APP-01")).data
        assert data["status"] == "unreachable"
    assert ok(check_network_reachability("SHARED-DEVICE-FAILURE", "BLR-SW-01", "DC1-SRV-APP-01")).data["status"] == "reachable"


def test_reachability_is_layer3_only_for_firewall_scenario() -> None:
    result = ok(check_network_reachability("FIREWALL-BLOCKING", "10.20.10.120", "DC1-SRV-APP-01"))
    assert result.data["status"] == "reachable"
    assert any("firewall policy" in warning for warning in result.warnings)


def test_reachability_reports_missing_routing_telemetry() -> None:
    result = ok(check_network_reachability("SHARED-DEVICE-FAILURE", "CORE-RTR-01", "DC1-SRV-APP-01"))
    assert result.data["status"] == "indeterminate"
    assert result.data["first_hop_device_id"] == "CORE-RTR-01"
    assert result.data["failure_point"]["reason"] == "no_routing_telemetry"
    assert any("cannot be determined" in item for item in result.missing_data)
    assert result.findings == []


@pytest.mark.parametrize("source, destination, code", [
    ("8.8.8.8", "DC1-SRV-APP-01", "NOT_FOUND"),
    ("NYC-SW-01", "GHOST-SRV-01", "NOT_FOUND"),
    ("not an address", "DC1-SRV-APP-01", "INVALID_ARGUMENT"),
    (None, "DC1-SRV-APP-01", "INVALID_ARGUMENT"),
    ("NYC-SW-01", "10.100.100.300", "INVALID_ARGUMENT"),
])
def test_reachability_rejects_bad_endpoints(source: object, destination: object, code: str) -> None:
    failed(check_network_reachability("BASELINE", source, destination), code)


@pytest.mark.parametrize("scenario_id", ["BASELINE", "WAN-FAILURE", "OSPF-ADJACENCY-FAILURE", "SHARED-DEVICE-FAILURE"])
def test_reachability_paths_follow_topology_links(topology_links: set, scenario_id: str) -> None:
    for branch in ("NYC", "SIN", "BLR"):
        for server in ("DC1-SRV-APP-01", "DC1-SRV-DNS-02"):
            data = ok(check_network_reachability(scenario_id, f"{branch}-SW-01", server)).data
            path = data["path"]
            assert path[0] == f"{branch}-SW-01"
            assert all(frozenset(pair) in topology_links for pair in zip(path, path[1:]))
            if data["status"] == "reachable":
                assert path[-1] == server
            else:
                assert data["failure_point"]["device_id"] == path[-1]


@pytest.fixture(scope="module")
def topology_links() -> set:
    return {frozenset((link.a_device_id, link.b_device_id)) for link in load_topology().links}
