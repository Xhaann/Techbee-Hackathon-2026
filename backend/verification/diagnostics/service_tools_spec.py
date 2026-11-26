from ipaddress import IPv4Address, IPv4Network

import pytest

from app.diagnostics import check_device_availability, get_dhcp_dns_status, get_firewall_logs
from app.network.repository import load_scenario
from verification.diagnostics.helpers import codes, failed, ok


def test_firewall_allow_and_deny_are_distinguished() -> None:
    result = ok(get_firewall_logs("FIREWALL-BLOCKING", source="10.20.0.0/16", destination="10.100.100.40"))
    data = result.data
    assert data["action_counts"] == {"allow": 4, "deny": 4}
    denied = [r for r in data["records"] if r["action"] == "deny"]
    assert {r["rule_id"] for r in denied} == {"FWR-DC1-0125"}
    assert all(r["severity"] == "warning" and r["protocol"] == "tcp" and r["destination_port"] == 443 for r in denied)
    assert all(r["timestamp"] > a["timestamp"] for r in denied for a in data["records"] if a["action"] == "allow")
    assert {rule["rule_id"] for rule in data["rules"]} == {"FWR-DC1-0125", "FWR-DC1-0130"}
    assert codes(result) == ["TRAFFIC_DENIED", "RULE_MODIFIED_IN_RANGE"]
    assert len(result.findings[0].evidence) == 4


def test_firewall_records_are_original_and_ordered() -> None:
    dataset = load_scenario("BASELINE")
    originals = {event.event_id: event.model_dump(mode="json") for event in dataset.firewall.events}
    records = ok(get_firewall_logs("BASELINE", destination="10.100.100.0/24", limit=500)).data["records"]
    assert records and all(originals[r["event_id"]] == r for r in records)
    assert [(r["timestamp"], r["event_id"]) for r in records] == sorted((r["timestamp"], r["event_id"]) for r in records)
    assert all(IPv4Address(r["destination_ip"]) in IPv4Network("10.100.100.0/24") for r in records)


def test_firewall_filters() -> None:
    deny = ok(get_firewall_logs("BASELINE", source="10.10.0.0/16", action="deny")).data
    assert [(r["rule_id"], r["destination_port"]) for r in deny["records"]] == [("FWR-DC1-9999", 22)]
    window = load_scenario("FIREWALL-BLOCKING").scenario
    before = ok(get_firewall_logs("FIREWALL-BLOCKING", source="10.20.0.0/16", end=window.onset_at.isoformat().replace("+00:00", "Z")))
    assert before.data["action_counts"]["deny"] == 0
    limited = ok(get_firewall_logs("BASELINE", destination="10.100.100.0/24", limit=2))
    assert limited.data["returned"] == 2 and limited.data["truncated"] is True


def test_firewall_empty_result() -> None:
    result = ok(get_firewall_logs("BASELINE", source="10.99.0.0/16"))
    assert result.data["records"] == [] and result.findings == [] and result.warnings


@pytest.mark.parametrize("kwargs", [{}, {"source": "10.20.10.5/24"}, {"source": "garbage"}, {"destination": 42},
                                    {"source": "10.0.0.0/8", "action": "drop"},
                                    {"source": "10.0.0.0/8", "start": "2026-03-06T10:00:00Z", "end": "2026-03-06T09:00:00Z"}])
def test_firewall_rejects_invalid_arguments(kwargs: dict) -> None:
    failed(get_firewall_logs("FIREWALL-BLOCKING", **kwargs), "INVALID_ARGUMENT")


def test_dhcp_exhaustion_and_conflicts() -> None:
    result = ok(get_dhcp_dns_status("DHCP-ALLOCATION-FAILURE", "BLR"))
    dhcp = result.data["dhcp"]
    assert dhcp["status"] == "degraded"
    users = next(p for p in dhcp["pools"] if p["pool"]["pool_id"] == "DHCP-BLR-USERS")
    assert users["status"] == "exhausted" and users["addresses_available"] == 0 and users["utilization_percent"] == 100.0
    assert users["lease_counts"]["conflict"] == 2 and len(users["conflict_leases"]) == 2
    assert users["event_counts"]["allocation_failure"] >= 1 and users["event_counts"]["ip_conflict"] == 2
    assert {"DHCP_POOL_EXHAUSTED", "DHCP_ALLOCATION_FAILURES", "DHCP_IP_CONFLICTS"} <= set(codes(result, "observed"))
    assert result.data["dns"]["status"] == "operational"
    voice = next(p for p in dhcp["pools"] if p["pool"]["pool_id"] == "DHCP-BLR-VOICE")
    assert voice["status"] == "ok"
    assert any("DHCP-BLR-VOICE" in item for item in result.missing_data)


def test_dns_resolution_failure_on_one_server() -> None:
    result = ok(get_dhcp_dns_status("DNS-RESOLUTION-FAILURE", "NYC"))
    dns = result.data["dns"]
    assert dns["status"] == "degraded"
    assert all(q["result"] == "servfail" and q["server_ip"] == "10.100.100.10" for q in dns["failed_queries"])
    primary = next(s for s in dns["servers"] if s["server"]["device_id"] == "DC1-SRV-DNS-01")
    assert primary["result_counts"]["servfail"] >= 1 and primary["response_time"]["count"] == primary["query_count"]
    assert codes(result, "observed") == ["DNS_SERVFAIL"]
    assert codes(result, "inferred") == ["DNS_SERVER_RESOLUTION_FAULT_SUSPECTED"]
    assert result.data["dhcp"]["status"] == "operational"


def test_dns_timeouts_when_site_isolated() -> None:
    result = ok(get_dhcp_dns_status("WAN-FAILURE", "SIN"))
    assert "DNS_TIMEOUTS" in codes(result, "observed")
    assert "DNS_UNREACHABLE_FROM_SITE_SUSPECTED" in codes(result, "inferred")
    assert "DNS_SERVER_RESOLUTION_FAULT_SUSPECTED" not in codes(result)
    assert all(q["response_time_ms"] is None for q in result.data["dns"]["failed_queries"])
    assert result.data["dhcp"]["status"] == "degraded" and "DHCP_TRANSACTIONS_STOPPED" in codes(result)


def test_dhcp_dns_baseline_is_operational() -> None:
    for site in ("NYC", "SIN", "BLR"):
        result = ok(get_dhcp_dns_status("BASELINE", site))
        assert result.data["dhcp"]["status"] == "operational" and result.data["dns"]["status"] == "operational"
        assert result.findings == []


def test_dhcp_dns_for_site_without_services() -> None:
    result = ok(get_dhcp_dns_status("BASELINE", "CORE"))
    assert result.data["dhcp"] == {"status": "no_data", "pools": []}
    assert result.data["dns"]["status"] == "no_data"
    assert len(result.missing_data) == 2


@pytest.mark.parametrize("site_id, code", [("LON", "NOT_FOUND"), ("", "INVALID_ARGUMENT"), (["NYC"], "INVALID_ARGUMENT")])
def test_dhcp_dns_rejects_bad_sites(site_id: object, code: str) -> None:
    failed(get_dhcp_dns_status("BASELINE", site_id), code)


@pytest.mark.parametrize("scenario_id, site_id", [("WAN-FAILURE", "SIN"), ("OSPF-ADJACENCY-FAILURE", "BLR"),
                                                   ("SHARED-DEVICE-FAILURE", "NYC"), ("VLAN-AUTHENTICATION-FAILURE", "NYC")])
def test_isolated_site_is_not_reported_as_server_failure(scenario_id: str, site_id: str) -> None:
    result = ok(get_dhcp_dns_status(scenario_id, site_id))
    servers = {"DC1-SRV-DHCP-01", "DC1-SRV-DNS-01", "DC1-SRV-DNS-02"}
    assert not [f for f in result.findings if f.device_id in servers]
    assert "DNS_SERVER_RESOLUTION_FAULT_SUSPECTED" not in codes(result)
    assert "DHCP_TRANSACTIONS_STOPPED" in codes(result, "observed")
    for server in sorted(servers):
        assert ok(check_device_availability(scenario_id, server)).data["status"] == "available"
