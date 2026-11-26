from datetime import timedelta, timezone
from ipaddress import IPv4Address, IPv4Network

import pytest

from app.network.models import (
    BgpState,
    DhcpEventType,
    DnsResult,
    FirewallAction,
    IncidentCategory,
    LeaseState,
    LinkStatus,
    NetworkTopology,
    OspfState,
    RouteChangeType,
    RoutingProtocol,
    ScenarioDataset,
)
from app.network.repository import find_reference_errors

FAILURE_SCENARIOS = {
    "WAN-FAILURE": IncidentCategory.WAN_CONNECTIVITY_FAILURE,
    "PACKET-LOSS": IncidentCategory.PACKET_LOSS,
    "OSPF-ADJACENCY-FAILURE": IncidentCategory.OSPF_ADJACENCY_FAILURE,
    "FIREWALL-BLOCKING": IncidentCategory.FIREWALL_BLOCKING,
    "DHCP-ALLOCATION-FAILURE": IncidentCategory.DHCP_ALLOCATION_FAILURE,
    "DNS-RESOLUTION-FAILURE": IncidentCategory.DNS_RESOLUTION_FAILURE,
    "VLAN-AUTHENTICATION-FAILURE": IncidentCategory.VLAN_AUTHENTICATION_FAILURE,
    "SHARED-DEVICE-FAILURE": IncidentCategory.SHARED_DEVICE_FAILURE,
}
SITE_NETWORKS = {"NYC": IPv4Network("10.10.0.0/16"), "SIN": IPv4Network("10.20.0.0/16"), "BLR": IPv4Network("10.30.0.0/16")}
APP_SERVER_IP = IPv4Address("10.100.100.40")


def post_onset(dataset: ScenarioDataset, items: list) -> list:
    return [item for item in items if item.timestamp >= dataset.scenario.onset_at]


def pre_onset(dataset: ScenarioDataset, items: list) -> list:
    return [item for item in items if item.timestamp < dataset.scenario.onset_at]


def samples(dataset: ScenarioDataset, interface_id: str) -> list:
    return [sample for sample in dataset.interface_statistics if sample.interface_id == interface_id]


def from_site(site: str, address: IPv4Address) -> bool:
    return address in SITE_NETWORKS[site]


def table(dataset: ScenarioDataset, device_id: str) -> dict:
    routing_table = next(t for t in dataset.routing.routing_tables if t.device_id == device_id)
    return {route.prefix: route for route in routing_table.routes}


def test_all_scenarios_present(scenarios: dict[str, ScenarioDataset]) -> None:
    assert set(scenarios) == {"BASELINE", *FAILURE_SCENARIOS}
    for scenario_id, category in FAILURE_SCENARIOS.items():
        dataset = scenarios[scenario_id]
        assert dataset.scenario.category == category
        assert dataset.incident.category == category
        assert dataset.ground_truth is not None
    assert scenarios["BASELINE"].incident is None and scenarios["BASELINE"].ground_truth is None


def test_datasets_reference_only_known_topology_objects(topology: NetworkTopology, scenarios: dict[str, ScenarioDataset]) -> None:
    for dataset in scenarios.values():
        assert find_reference_errors(topology, dataset) == []


def test_timestamps_are_utc_and_inside_window(scenarios: dict[str, ScenarioDataset]) -> None:
    onsets = []
    for dataset in scenarios.values():
        info = dataset.scenario
        onsets.append(info.onset_at)
        assert info.window_end - info.window_start == timedelta(minutes=40)
        for value in dataset.timestamps():
            assert value.utcoffset() == timedelta(0)
            assert info.window_start <= value <= info.window_end
        assert [event.timestamp for event in dataset.events] == sorted(event.timestamp for event in dataset.events)
        if dataset.incident is not None:
            assert dataset.incident.reported_at > info.onset_at
        for lease in dataset.dhcp.leases:
            assert lease.lease_start.tzinfo is not None and lease.lease_start.utcoffset() == timedelta(0)
            assert (lease.state == LeaseState.EXPIRED) == (lease.lease_end < info.window_end)
    assert len(set(onsets)) == len(onsets)
    assert all(onset.tzinfo is not None and onset.astimezone(timezone.utc) == onset for onset in onsets)


def test_every_scenario_samples_interfaces_consistently(topology: NetworkTopology, scenarios: dict[str, ScenarioDataset]) -> None:
    physical = {interface.interface_id for interface in topology.interfaces if interface.mode.value != "virtual"}
    for dataset in scenarios.values():
        sampled = {sample.interface_id for sample in pre_onset(dataset, dataset.interface_statistics)}
        assert sampled == physical
        for sample in dataset.interface_statistics:
            assert sample.in_bps <= 10_000_000_000 and sample.out_bps <= 10_000_000_000


def test_ground_truth_is_consistent_with_topology(topology: NetworkTopology, scenarios: dict[str, ScenarioDataset]) -> None:
    paths = {path.path_id: path for path in topology.paths}
    for scenario_id in FAILURE_SCENARIOS:
        truth = scenarios[scenario_id].ground_truth
        affected = [paths[path_id] for path_id in truth.affected_path_ids]
        assert sorted({path.source_site_id for path in affected}) == truth.affected_site_ids
        for device_id in truth.root_cause_device_ids:
            assert any(device_id in path.device_ids for path in affected)
        for link_id in truth.root_cause_link_ids:
            assert all(link_id in path.link_ids for path in affected)
        assert set(scenarios[scenario_id].incident.affected_site_ids) <= set(truth.affected_site_ids)


def test_baseline_is_healthy(scenarios: dict[str, ScenarioDataset]) -> None:
    dataset = scenarios["BASELINE"]
    assert all(sample.oper_status == LinkStatus.UP for sample in dataset.interface_statistics)
    assert all(sample.in_errors == 0 and sample.out_errors == 0 for sample in dataset.interface_statistics)
    assert all(neighbor.state == OspfState.FULL for neighbor in dataset.routing.ospf_neighbors)
    assert all(neighbor.state == BgpState.ESTABLISHED for neighbor in dataset.routing.bgp_neighbors)
    assert dataset.routing.route_changes == []
    assert {query.result for query in dataset.dns.queries} <= {DnsResult.NOERROR, DnsResult.NXDOMAIN}
    assert all(event.event_type == DhcpEventType.ALLOCATION_SUCCESS for event in dataset.dhcp.events)
    denied = [event for event in dataset.firewall.events if event.action == FirewallAction.DENY]
    assert [(event.rule_id, event.destination_port) for event in denied] == [("FWR-DC1-9999", 22)]
    for site in SITE_NETWORKS:
        routes = table(dataset, f"{site}-RTR-01")
        assert IPv4Network("10.100.100.0/24") in routes and IPv4Network("0.0.0.0/0") in routes


def test_routing_tables_are_internally_consistent(topology: NetworkTopology, scenarios: dict[str, ScenarioDataset]) -> None:
    interfaces = {interface.interface_id: interface for interface in topology.interfaces}
    for dataset in scenarios.values():
        for routing_table in dataset.routing.routing_tables:
            for route in routing_table.routes:
                interface = interfaces[route.interface_id]
                if route.protocol == RoutingProtocol.CONNECTED:
                    assert interface.ip_address.network == route.prefix
                else:
                    assert route.next_hop in interface.ip_address.network
        for neighbor in dataset.routing.bgp_neighbors:
            learned = [r for r in table(dataset, neighbor.device_id).values()
                       if r.protocol == RoutingProtocol.BGP and r.next_hop == neighbor.neighbor_ip]
            assert neighbor.prefixes_received == len(learned)


def test_wan_failure(scenarios: dict[str, ScenarioDataset]) -> None:
    dataset = scenarios["WAN-FAILURE"]
    for interface_id in ("SIN-RTR-01:Gi0/0/0", "CORE-RTR-01:Gi0/0/3"):
        assert {s.oper_status for s in pre_onset(dataset, samples(dataset, interface_id))} == {LinkStatus.UP}
        after = post_onset(dataset, samples(dataset, interface_id))
        assert {s.oper_status for s in after} == {LinkStatus.DOWN}
        assert all(s.packet_loss_percent == 100.0 and s.uptime_seconds == 0 for s in after)
    sin_sessions = [n for n in dataset.routing.bgp_neighbors if "SIN-RTR-01" in (n.device_id, n.neighbor_device_id)]
    assert len(sin_sessions) == 2 and all(n.state == BgpState.IDLE for n in sin_sessions)
    assert all(route.protocol == RoutingProtocol.CONNECTED for route in table(dataset, "SIN-RTR-01").values())
    assert {c.change_type for c in dataset.routing.route_changes} == {RouteChangeType.WITHDRAWN}
    sin_queries = [q for q in post_onset(dataset, dataset.dns.queries) if from_site("SIN", q.client_ip)]
    assert sin_queries and all(q.result == DnsResult.TIMEOUT for q in sin_queries)
    assert not [e for e in post_onset(dataset, dataset.firewall.events) if from_site("SIN", e.source_ip)]
    assert {"LINK_DOWN", "BGP_NEIGHBOR_DOWN", "CARRIER_LOSS"} <= {e.event_type for e in dataset.events}


def test_packet_loss(scenarios: dict[str, ScenarioDataset]) -> None:
    dataset, baseline = scenarios["PACKET-LOSS"], scenarios["BASELINE"]
    for interface_id in ("NYC-RTR-01:Gi0/0/0", "CORE-RTR-01:Gi0/0/2"):
        before = pre_onset(dataset, samples(dataset, interface_id))
        after = post_onset(dataset, samples(dataset, interface_id))
        assert all(s.packet_loss_percent == 0.0 and s.in_errors == 0 for s in before)
        assert all(s.oper_status == LinkStatus.UP for s in after)
        assert all(s.packet_loss_percent > 5 and s.in_errors > 1000 and s.latency_ms > 140 for s in after)
    unaffected = [s for s in post_onset(dataset, dataset.interface_statistics) if s.device_id.startswith(("SIN", "BLR"))]
    assert all((s.packet_loss_percent or 0) == 0 for s in unaffected)
    assert dataset.routing.route_changes == []
    assert all(n.state == BgpState.ESTABLISHED for n in dataset.routing.bgp_neighbors)
    assert [t.routes for t in dataset.routing.routing_tables] == [t.routes for t in baseline.routing.routing_tables]
    nyc = [q for q in dataset.dns.queries if from_site("NYC", q.client_ip) and q.response_time_ms is not None]
    assert min(q.response_time_ms for q in post_onset(dataset, nyc)) > max(q.response_time_ms for q in pre_onset(dataset, nyc))


def test_ospf_adjacency_failure(scenarios: dict[str, ScenarioDataset]) -> None:
    dataset = scenarios["OSPF-ADJACENCY-FAILURE"]
    blr = [n for n in dataset.routing.ospf_neighbors if "BLR-RTR-01" in (n.device_id, n.neighbor_device_id)]
    assert len(blr) == 2 and all(n.state == OspfState.EXSTART and "MTU" in n.failure_reason for n in blr)
    others = [n for n in dataset.routing.ospf_neighbors if n not in blr]
    assert others and all(n.state == OspfState.FULL for n in others)
    for interface_id in ("BLR-RTR-01:Gi0/0/0", "CORE-RTR-02:Gi0/0/2"):
        assert all(s.oper_status == LinkStatus.UP for s in samples(dataset, interface_id))
    assert IPv4Network("10.100.100.0/24") not in table(dataset, "BLR-RTR-01")
    assert IPv4Network("10.30.10.0/24") not in table(dataset, "CORE-SW-01")
    assert all(c.timestamp > dataset.scenario.onset_at for c in dataset.routing.route_changes)
    assert {"MTU_CHANGE", "OSPF_ADJACENCY_DOWN"} <= {e.event_type for e in dataset.events}
    assert "LINK_DOWN" not in {e.event_type for e in dataset.events}


def test_firewall_blocking(scenarios: dict[str, ScenarioDataset]) -> None:
    dataset = scenarios["FIREWALL-BLOCKING"]
    rule = next(r for r in dataset.firewall.rules if r.rule_id == "FWR-DC1-0125")
    assert rule.action == FirewallAction.DENY and rule.last_modified == dataset.scenario.onset_at
    app_flows = [e for e in dataset.firewall.events if e.destination_ip == APP_SERVER_IP and e.destination_port == 443]
    sin_after = [e for e in post_onset(dataset, app_flows) if from_site("SIN", e.source_ip)]
    assert sin_after and all(e.action == FirewallAction.DENY and e.rule_id == "FWR-DC1-0125" for e in sin_after)
    assert all(e.action == FirewallAction.ALLOW for e in pre_onset(dataset, app_flows))
    others_after = [e for e in post_onset(dataset, app_flows) if not from_site("SIN", e.source_ip)]
    assert others_after and all(e.action == FirewallAction.ALLOW for e in others_after)
    assert all(e.severity.value == "warning" for e in sin_after)
    assert dataset.routing.route_changes == []


def test_dhcp_allocation_failure(scenarios: dict[str, ScenarioDataset]) -> None:
    dataset = scenarios["DHCP-ALLOCATION-FAILURE"]
    pool = next(p for p in dataset.dhcp.pools if p.pool_id == "DHCP-BLR-USERS")
    leases = [lease for lease in dataset.dhcp.leases if lease.pool_id == pool.pool_id]
    assert len(leases) == pool.size
    assert sum(lease.state == LeaseState.CONFLICT for lease in leases) == 2
    assert all(lease.state != LeaseState.EXPIRED for lease in leases)
    events = [e for e in dataset.dhcp.events if e.pool_id == pool.pool_id]
    failures = [e for e in events if e.event_type == DhcpEventType.ALLOCATION_FAILURE]
    assert failures and all(e.timestamp >= dataset.scenario.onset_at for e in failures)
    conflicts = [e for e in events if e.event_type == DhcpEventType.IP_CONFLICT]
    assert len(conflicts) == 2 and all(e.timestamp < dataset.scenario.onset_at for e in conflicts)
    assert any(e.event_type == DhcpEventType.POOL_EXHAUSTED for e in events)
    other_pools = [e for e in dataset.dhcp.events if e.pool_id != pool.pool_id]
    assert all(e.event_type == DhcpEventType.ALLOCATION_SUCCESS for e in other_pools)
    for other in (p for p in dataset.dhcp.pools if p.pool_id != pool.pool_id):
        active = [l for l in dataset.dhcp.leases if l.pool_id == other.pool_id and l.state == LeaseState.ACTIVE]
        assert len(active) < other.size


def test_dns_resolution_failure(scenarios: dict[str, ScenarioDataset]) -> None:
    dataset = scenarios["DNS-RESOLUTION-FAILURE"]
    primary, secondary = IPv4Address("10.100.100.10"), IPv4Address("10.100.100.11")
    failures = [q for q in dataset.dns.queries if q.result == DnsResult.SERVFAIL]
    assert failures
    assert all(q.server_ip == primary and q.domain.endswith("corp.example.com") for q in failures)
    assert all(q.timestamp >= dataset.scenario.onset_at for q in failures)
    after = post_onset(dataset, dataset.dns.queries)
    assert all(q.result != DnsResult.SERVFAIL for q in after if q.server_ip == secondary or not q.domain.endswith("corp.example.com"))
    assert {site for site in SITE_NETWORKS if any(from_site(site, q.client_ip) for q in failures)} == set(SITE_NETWORKS)
    assert "ZONE_LOAD_FAILURE" in {e.event_type for e in dataset.events if e.device_id == "DC1-SRV-DNS-01"}


def test_vlan_authentication_failure(scenarios: dict[str, ScenarioDataset]) -> None:
    dataset = scenarios["VLAN-AUTHENTICATION-FAILURE"]
    auth_events = [e for e in dataset.events if e.event_type in ("DOT1X_AUTH_FAILURE", "PORT_UNAUTHORIZED")]
    assert auth_events and all(e.device_id == "NYC-SW-01" and e.timestamp >= dataset.scenario.onset_at for e in auth_events)
    assert any(e.device_id == "DC1-SRV-AUTH-01" and e.event_type == "RADIUS_INVALID_AUTHENTICATOR" for e in dataset.events)
    for port in ("NYC-SW-01:Gi1/0/1", "NYC-SW-01:Gi1/0/2"):
        after = post_onset(dataset, samples(dataset, port))
        assert all(s.oper_status == LinkStatus.UP and s.utilization_percent < 0.1 for s in after)
    phone = post_onset(dataset, samples(dataset, "NYC-SW-01:Gi1/0/3"))
    assert all(s.utilization_percent >= 0.1 for s in phone)
    nyc_clients = [q for q in post_onset(dataset, dataset.dns.queries) if from_site("NYC", q.client_ip)]
    assert nyc_clients == []
    assert all(n.state == BgpState.ESTABLISHED for n in dataset.routing.bgp_neighbors)


def test_shared_device_failure(topology: NetworkTopology, scenarios: dict[str, ScenarioDataset]) -> None:
    dataset = scenarios["SHARED-DEVICE-FAILURE"]
    onset = dataset.scenario.onset_at
    assert not [s for s in dataset.interface_statistics if s.device_id == "CORE-RTR-01" and s.timestamp >= onset]
    assert not [e for e in dataset.events if e.device_id == "CORE-RTR-01" and e.timestamp >= onset]
    assert "CORE-RTR-01" not in {t.device_id for t in dataset.routing.routing_tables}
    peers = {"CORE-SW-01:Te1/0/1", "CORE-RTR-02:Te0/0/1", "NYC-RTR-01:Gi0/0/0", "SIN-RTR-01:Gi0/0/0"}
    for interface_id in peers:
        assert {s.oper_status for s in post_onset(dataset, samples(dataset, interface_id))} == {LinkStatus.DOWN}
    assert {e.interface_id for e in dataset.events if e.event_type == "LINK_DOWN"} == peers
    assert {n.device_id for n in dataset.routing.bgp_neighbors} == {"NYC-RTR-01", "SIN-RTR-01"}
    assert all(n.state == BgpState.IDLE for n in dataset.routing.bgp_neighbors)
    shared_paths = [p.path_id for p in topology.paths if "CORE-RTR-01" in p.device_ids]
    assert dataset.ground_truth.affected_path_ids == shared_paths
    assert dataset.ground_truth.affected_site_ids == ["NYC", "SIN"]
    for site, expected in (("NYC", DnsResult.TIMEOUT), ("SIN", DnsResult.TIMEOUT)):
        queries = [q for q in post_onset(dataset, dataset.dns.queries) if from_site(site, q.client_ip)]
        assert queries and all(q.result == expected for q in queries)
    blr = [q for q in post_onset(dataset, dataset.dns.queries) if from_site("BLR", q.client_ip)]
    assert blr and all(q.result != DnsResult.TIMEOUT for q in blr)
    assert IPv4Network("10.100.100.0/24") in table(dataset, "BLR-RTR-01")


@pytest.mark.parametrize("scenario_id", ["FIREWALL-BLOCKING", "DHCP-ALLOCATION-FAILURE", "DNS-RESOLUTION-FAILURE",
                                         "VLAN-AUTHENTICATION-FAILURE", "PACKET-LOSS"])
def test_service_failures_keep_routing_intact(scenarios: dict[str, ScenarioDataset], scenario_id: str) -> None:
    dataset = scenarios[scenario_id]
    assert dataset.routing.route_changes == []
    assert all(n.state == OspfState.FULL for n in dataset.routing.ospf_neighbors)
    assert all(s.oper_status == LinkStatus.UP for s in dataset.interface_statistics)
