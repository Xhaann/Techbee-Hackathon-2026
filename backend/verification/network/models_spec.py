from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.network.models import (
    BgpNeighbor,
    DhcpData,
    DhcpEvent,
    DhcpLease,
    DhcpPool,
    DnsQuery,
    FirewallData,
    FirewallEvent,
    FirewallRule,
    Interface,
    InterfaceStatistics,
    Link,
    NetworkEvent,
    NetworkPath,
    NetworkTopology,
    OspfNeighbor,
    RouteChange,
    RouteEntry,
    ScenarioDataset,
    ScenarioInfo,
    Vlan,
)

NOW = datetime(2026, 3, 2, 9, 0, tzinfo=timezone.utc)


def interface_payload(**overrides: object) -> dict:
    payload = {
        "interface_id": "NYC-RTR-01:Gi0/0/0",
        "device_id": "NYC-RTR-01",
        "name": "Gi0/0/0",
        "mode": "routed",
        "description": "WAN",
        "ip_address": "172.16.0.2/30",
        "speed_mbps": 1000,
        "mtu": 1500,
    }
    return payload | overrides


def statistics_payload(**overrides: object) -> dict:
    payload = {
        "interface_id": "NYC-RTR-01:Gi0/0/0",
        "device_id": "NYC-RTR-01",
        "timestamp": NOW,
        "interval_seconds": 600,
        "oper_status": "up",
        "utilization_percent": 40.0,
        "in_bps": 1000,
        "out_bps": 1000,
        "in_drops": 0,
        "out_drops": 0,
        "in_errors": 0,
        "out_errors": 0,
        "uptime_seconds": 3600,
        "latency_ms": 74.0,
        "packet_loss_percent": 0.0,
    }
    return payload | overrides


def rule(rule_id: str, priority: int, action: str, **overrides: object) -> FirewallRule:
    payload = {
        "rule_id": rule_id,
        "device_id": "DC1-FW-01",
        "priority": priority,
        "name": rule_id,
        "action": action,
        "protocol": "tcp",
        "source": "10.0.0.0/8",
        "destination": "10.100.100.40/32",
        "destination_port": 443,
        "enabled": True,
        "last_modified": NOW - timedelta(days=30),
    }
    return FirewallRule(**(payload | overrides))


def firewall_event(**overrides: object) -> dict:
    payload = {
        "event_id": "FW-EVT-0001",
        "timestamp": NOW,
        "device_id": "DC1-FW-01",
        "rule_id": "FWR-ALLOW",
        "source_ip": "10.10.10.100",
        "destination_ip": "10.100.100.40",
        "source_port": 50000,
        "destination_port": 443,
        "protocol": "tcp",
        "action": "allow",
        "severity": "informational",
    }
    return payload | overrides


def pool() -> DhcpPool:
    return DhcpPool(
        pool_id="DHCP-NYC-USERS", server_device_id="DC1-SRV-DHCP-01", site_id="NYC", vlan_id=10,
        subnet="10.10.10.0/24", range_start="10.10.10.100", range_end="10.10.10.149", gateway="10.10.10.1",
        dns_servers=["10.100.100.10"], lease_time_seconds=28800,
    )


def lease(**overrides: object) -> dict:
    payload = {
        "pool_id": "DHCP-NYC-USERS",
        "ip_address": "10.10.10.100",
        "mac_address": "02:00:0a:0a:00:00",
        "hostname": "nyc-ws-001",
        "state": "active",
        "lease_start": NOW - timedelta(hours=1),
        "lease_end": NOW + timedelta(hours=7),
    }
    return payload | overrides


def dns_query(**overrides: object) -> dict:
    payload = {
        "query_id": "DNS-Q-0001",
        "timestamp": NOW,
        "client_ip": "10.10.10.100",
        "server_ip": "10.100.100.10",
        "domain": "erp.corp.example.com",
        "record_type": "A",
        "result": "noerror",
        "answers": ["10.100.100.40"],
        "response_time_ms": 78.2,
    }
    return payload | overrides


def test_valid_interface_and_statistics_are_accepted() -> None:
    assert Interface(**interface_payload()).interface_id == "NYC-RTR-01:Gi0/0/0"
    assert InterfaceStatistics(**statistics_payload()).oper_status.value == "up"


@pytest.mark.parametrize(
    "overrides",
    [
        {"interface_id": "NYC-RTR-01:Gi0/0/9"},
        {"device_id": "nyc-rtr-01"},
        {"mode": "access", "ip_address": None},
        {"mode": "trunk", "ip_address": None},
        {"vlan_ids": [10]},
        {"ip_address": None},
        {"ip_address": "999.1.1.1/30"},
        {"mtu": 100},
        {"speed_mbps": 0},
        {"unexpected": "field"},
    ],
)
def test_invalid_interfaces_are_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        Interface(**interface_payload(**overrides))


@pytest.mark.parametrize("field", ["interface_id", "device_id", "name", "mode", "speed_mbps", "mtu"])
def test_incomplete_interface_is_rejected(field: str) -> None:
    payload = interface_payload()
    del payload[field]
    with pytest.raises(ValidationError):
        Interface(**payload)


@pytest.mark.parametrize(
    "timestamp",
    ["2026-03-02T09:00:00", "2026-03-02T14:30:00+05:30", "not-a-date"],
)
def test_non_utc_timestamps_are_rejected(timestamp: str) -> None:
    with pytest.raises(ValidationError):
        NetworkEvent(event_id="EVT-1", timestamp=timestamp, device_id="NYC-RTR-01", severity="error",
                     event_type="LINK_DOWN", message="down")


def test_utc_timestamp_is_accepted_and_serialised_with_z() -> None:
    event = NetworkEvent(event_id="EVT-1", timestamp="2026-03-02T09:00:00Z", device_id="NYC-RTR-01",
                         severity="error", event_type="LINK_DOWN", message="down")
    assert event.model_dump(mode="json")["timestamp"] == "2026-03-02T09:00:00Z"


@pytest.mark.parametrize(
    "overrides",
    [
        {"interface_id": "SIN-RTR-01:Gi0/0/0"},
        {"severity": "loud"},
        {"event_type": "link down"},
        {"message": ""},
    ],
)
def test_invalid_events_are_rejected(overrides: dict) -> None:
    payload = {"event_id": "EVT-1", "timestamp": NOW, "device_id": "NYC-RTR-01", "interface_id": "NYC-RTR-01:Gi0/0/0",
               "severity": "error", "event_type": "LINK_DOWN", "message": "down"}
    with pytest.raises(ValidationError):
        NetworkEvent(**(payload | overrides))


@pytest.mark.parametrize(
    "overrides",
    [
        {"utilization_percent": 120.0},
        {"in_bps": -1},
        {"packet_loss_percent": 101.0},
        {"latency_ms": -1.0},
        {"device_id": "SIN-RTR-01"},
        {"oper_status": "down"},
        {"oper_status": "down", "in_bps": 0, "out_bps": 0, "utilization_percent": 0.0, "uptime_seconds": 0},
    ],
)
def test_invalid_interface_statistics_are_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        InterfaceStatistics(**statistics_payload(**overrides))


def test_down_interface_statistics_are_accepted() -> None:
    sample = InterfaceStatistics(**statistics_payload(
        oper_status="down", in_bps=0, out_bps=0, utilization_percent=0.0, uptime_seconds=0, latency_ms=None,
        packet_loss_percent=100.0,
    ))
    assert sample.packet_loss_percent == 100.0


def test_link_validation() -> None:
    base = {"link_id": "LNK-1", "link_type": "lan", "a_interface_id": "A-SW-01:Gi1", "b_interface_id": "B-SW-01:Gi1",
            "bandwidth_mbps": 1000, "latency_ms": 0.1}
    assert Link(**base).b_device_id == "B-SW-01"
    for overrides in ({"b_interface_id": "A-SW-01:Gi2"}, {"routing_protocol": "ospf"}, {"ospf_area": "0"},
                      {"link_type": "wan"}, {"routing_protocol": "connected"}):
        with pytest.raises(ValidationError):
            Link(**(base | overrides))


def test_vlan_gateway_must_be_inside_subnet() -> None:
    with pytest.raises(ValidationError):
        Vlan(segment_id="NYC-VLAN10", site_id="NYC", vlan_id=10, name="USERS", subnet="10.10.10.0/24",
             gateway="10.10.20.1", gateway_interface_id="NYC-RTR-01:Gi0/0/1.10")
    with pytest.raises(ValidationError):
        Vlan(segment_id="NYC-VLAN0", site_id="NYC", vlan_id=5000, name="BAD", subnet="10.10.10.0/24",
             gateway="10.10.10.1", gateway_interface_id="NYC-RTR-01:Gi0/0/1.10")


def test_path_requires_one_link_per_hop() -> None:
    with pytest.raises(ValidationError):
        NetworkPath(path_id="PATH-1", name="bad", service="dns", source_site_id="NYC",
                    device_ids=["NYC-SW-01", "NYC-RTR-01", "CORE-RTR-01"], link_ids=["LNK-1"])


def test_topology_rejects_broken_references(topology: NetworkTopology) -> None:
    data = topology.model_dump(mode="json")
    broken_device = data | {"interfaces": data["interfaces"] + [interface_payload(
        interface_id="GHOST-RTR-01:Gi0", device_id="GHOST-RTR-01", name="Gi0")]}
    duplicate_device = data | {"devices": data["devices"] + [data["devices"][0]]}
    reused_interface = data | {"links": data["links"] + [data["links"][0] | {"link_id": "LNK-DUPLICATE"}]}
    path = data["paths"][0]
    broken_path = data | {"paths": [path | {"link_ids": list(reversed(path["link_ids"]))}] + data["paths"][1:]}
    for payload in (broken_device, duplicate_device, reused_interface, broken_path):
        with pytest.raises(ValidationError):
            NetworkTopology.model_validate(payload)


def test_route_validation() -> None:
    connected = {"prefix": "10.10.10.0/24", "protocol": "connected", "interface_id": "NYC-RTR-01:Gi0/0/1.10",
                 "admin_distance": 0, "metric": 0}
    assert RouteEntry(**connected).next_hop is None
    with pytest.raises(ValidationError):
        RouteEntry(**(connected | {"next_hop": "10.10.10.2"}))
    with pytest.raises(ValidationError):
        RouteEntry(**(connected | {"protocol": "bgp"}))
    with pytest.raises(ValidationError):
        RouteEntry(**(connected | {"prefix": "10.10.10.1/24"}))


def test_neighbor_states_require_consistent_failure_reason() -> None:
    ospf = {"device_id": "CORE-RTR-02", "interface_id": "CORE-RTR-02:Gi0/0/2", "neighbor_device_id": "BLR-RTR-01",
            "neighbor_router_id": "10.255.1.30", "neighbor_ip": "172.16.0.10", "area": "10", "state": "full",
            "last_state_change": NOW}
    assert OspfNeighbor(**ospf).failure_reason is None
    for overrides in ({"failure_reason": "x"}, {"state": "exstart"}):
        with pytest.raises(ValidationError):
            OspfNeighbor(**(ospf | overrides))
    bgp = {"device_id": "NYC-RTR-01", "neighbor_device_id": "CORE-RTR-01", "neighbor_ip": "172.16.0.1",
           "local_asn": 65010, "remote_asn": 65000, "state": "established", "prefixes_received": 7,
           "last_state_change": NOW}
    assert BgpNeighbor(**bgp).prefixes_received == 7
    for overrides in ({"state": "idle", "failure_reason": "down"}, {"state": "idle"}, {"remote_asn": 0}):
        with pytest.raises(ValidationError):
            BgpNeighbor(**(bgp | overrides))


@pytest.mark.parametrize(
    "change_type, previous, new",
    [("added", "10.0.0.1", None), ("withdrawn", None, "10.0.0.1"), ("next_hop_changed", "10.0.0.1", "10.0.0.1")],
)
def test_inconsistent_route_changes_are_rejected(change_type: str, previous: str | None, new: str | None) -> None:
    with pytest.raises(ValidationError):
        RouteChange(change_id="RC-1", timestamp=NOW, device_id="NYC-RTR-01", prefix="10.20.10.0/24",
                    protocol="bgp", change_type=change_type, previous_next_hop=previous, new_next_hop=new)


def test_firewall_events_must_match_rule_base() -> None:
    rules = [rule("FWR-ALLOW", 100, "allow"), rule("FWR-DENY", 9999, "deny", protocol=None, source="0.0.0.0/0",
                                                  destination="0.0.0.0/0", destination_port=None)]
    assert FirewallData(rules=rules, events=[FirewallEvent(**firewall_event())]).events[0].action.value == "allow"
    inconsistent = (
        firewall_event(action="deny"),
        firewall_event(rule_id="FWR-DENY", action="deny"),
        firewall_event(rule_id="FWR-MISSING"),
        firewall_event(timestamp=NOW - timedelta(days=60)),
    )
    for event in inconsistent:
        with pytest.raises(ValidationError):
            FirewallData(rules=rules, events=[FirewallEvent(**event)])


def test_firewall_event_field_validation() -> None:
    for overrides in ({"protocol": "icmp"}, {"source_port": None}, {"destination_port": 70000},
                      {"source_ip": "10.10.10.300"}, {"action": "drop"}):
        with pytest.raises(ValidationError):
            FirewallEvent(**firewall_event(**overrides))
    with pytest.raises(ValidationError):
        rule("FWR-BAD", 1, "allow", protocol="icmp")


def test_dhcp_validation() -> None:
    assert pool().size == 50
    with pytest.raises(ValidationError):
        DhcpPool(**(pool().model_dump() | {"range_start": "10.10.10.200"}))
    with pytest.raises(ValidationError):
        DhcpPool(**(pool().model_dump() | {"gateway": "10.10.10.120"}))
    with pytest.raises(ValidationError):
        DhcpLease(**lease(lease_end=NOW - timedelta(hours=2)))
    with pytest.raises(ValidationError):
        DhcpLease(**lease(mac_address="02-00-0A-0A-00-00"))
    with pytest.raises(ValidationError):
        DhcpData(pools=[pool()], leases=[DhcpLease(**lease(ip_address="10.10.10.200"))], events=[])
    with pytest.raises(ValidationError):
        DhcpData(pools=[pool()], leases=[DhcpLease(**lease()), DhcpLease(**lease())], events=[])
    with pytest.raises(ValidationError):
        DhcpEvent(event_id="DHCP-EVT-1", timestamp=NOW, server_device_id="DC1-SRV-DHCP-01", pool_id="DHCP-NYC-USERS",
                  event_type="allocation_failure", mac_address="02:00:0a:0a:00:00", ip_address="10.10.10.100",
                  message="no free leases")


def test_dns_query_validation() -> None:
    assert DnsQuery(**dns_query()).answers
    for overrides in ({"answers": []}, {"result": "servfail"}, {"result": "timeout"},
                      {"result": "timeout", "answers": [], "response_time_ms": 10.0},
                      {"domain": "Not A Domain"}, {"record_type": "TXT"}):
        with pytest.raises(ValidationError):
            DnsQuery(**dns_query(**overrides))
    assert DnsQuery(**dns_query(result="timeout", answers=[], response_time_ms=None)).response_time_ms is None


def test_scenario_rejects_out_of_window_timestamps(scenarios: dict[str, ScenarioDataset]) -> None:
    data = scenarios["WAN-FAILURE"].model_dump(mode="json")
    late = data["events"][0] | {"timestamp": "2030-01-01T00:00:00Z"}
    with pytest.raises(ValidationError):
        ScenarioDataset.model_validate(data | {"events": [late] + data["events"][1:]})
    with pytest.raises(ValidationError):
        ScenarioDataset.model_validate(data | {"incident": None})
    with pytest.raises(ValidationError):
        ScenarioInfo(scenario_id="X", name="x", description="x", window_start=NOW, onset_at=NOW,
                     window_end=NOW + timedelta(minutes=1))
