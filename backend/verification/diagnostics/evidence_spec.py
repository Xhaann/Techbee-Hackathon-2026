from datetime import datetime

import pytest

from app import diagnostics
from app.diagnostics import EvidenceRef, ToolResult
from app.network.models import InterfaceMode, ScenarioDataset
from app.network.repository import list_scenario_ids, load_scenario, load_topology
from app.observability.simulation import monitored_interfaces, scenario_flows
from verification.diagnostics.helpers import ok

SITE_NETWORKS = {"NYC": "10.10.0.0/16", "SIN": "10.20.0.0/16", "BLR": "10.30.0.0/16", "CORE": "10.0.0.0/24",
                 "DC1": "10.100.0.0/16"}
SERVERS = ("DC1-SRV-APP-01", "DC1-SRV-AUTH-01", "DC1-SRV-DHCP-01", "DC1-SRV-DNS-01", "DC1-SRV-DNS-02")


def record_index(dataset: ScenarioDataset) -> dict[str, dict[str, datetime | None]]:
    routing, firewall, dhcp = dataset.routing, dataset.firewall, dataset.dhcp
    return {
        "events": {e.event_id: e.timestamp for e in dataset.events},
        "interface_statistics": {f"{s.interface_id}@{s.timestamp.isoformat()}": s.timestamp
                                 for s in dataset.interface_statistics},
        "routing_tables": {t.device_id: t.collected_at for t in routing.routing_tables},
        "ospf_neighbors": {f"{n.device_id}->{n.neighbor_device_id}": n.last_state_change for n in routing.ospf_neighbors},
        "bgp_neighbors": {f"{n.device_id}->{n.neighbor_device_id}": n.last_state_change for n in routing.bgp_neighbors},
        "route_changes": {c.change_id: c.timestamp for c in routing.route_changes},
        "firewall_events": {e.event_id: e.timestamp for e in firewall.events},
        "firewall_rules": {r.rule_id: r.last_modified for r in firewall.rules},
        "dhcp_events": {e.event_id: e.timestamp for e in dhcp.events},
        "dhcp_leases": {f"{lease.pool_id}:{lease.ip_address}": None for lease in dhcp.leases},
        "dns_queries": {q.query_id: q.timestamp for q in dataset.dns.queries},
        "flows": {f.flow_id: f.start for f in scenario_flows(dataset.scenario.scenario_id)},
        "configurations": {d.device_id: None for d in load_topology().devices if d.device_type.value != "server"},
        "interface_history": {i: None for i in monitored_interfaces(dataset)},
    }


def sweep(scenario_id: str) -> list[ToolResult]:
    topology = load_topology()
    results = []
    results.append(diagnostics.get_change_history(scenario_id))
    for device in topology.devices:
        device_id = device.device_id
        results += [
            diagnostics.get_event_timeline(scenario_id, device_id=device_id),
            diagnostics.get_change_history(scenario_id, device_id=device_id),
            diagnostics.get_device_logs(scenario_id, device_id),
            diagnostics.get_interface_stats(scenario_id, device_id),
            diagnostics.get_routing_state(scenario_id, device_id),
            diagnostics.analyze_routing_adjacency(scenario_id, device_id),
            diagnostics.check_device_availability(scenario_id, device_id),
        ]
    for interface in topology.interfaces:
        if interface.mode != InterfaceMode.VIRTUAL:
            results.append(diagnostics.analyze_packet_loss(scenario_id, interface.device_id, interface.name))
            results.append(diagnostics.analyze_interface_errors(scenario_id, interface.device_id, interface.name))
    for site in topology.sites:
        results.append(diagnostics.get_dhcp_dns_status(scenario_id, site.site_id))
        results.append(diagnostics.get_firewall_logs(scenario_id, source=SITE_NETWORKS[site.site_id]))
    for branch in ("NYC", "SIN", "BLR"):
        for server in SERVERS:
            results.append(diagnostics.check_network_reachability(scenario_id, f"{branch}-SW-01", server))
            results.append(diagnostics.analyze_path_health(scenario_id, f"{branch}-SW-01", server))
        for server, protocol, port in (("DC1-SRV-APP-01", "tcp", 443), ("DC1-SRV-AUTH-01", "udp", 1812), ("DC1-SRV-DNS-01", "udp", 53)):
            results.append(diagnostics.trace_packet(scenario_id, f"{branch}-SW-01", server, protocol, port))
    results += [diagnostics.get_network_health(scenario_id), diagnostics.get_config_drift(scenario_id),
                diagnostics.analyze_traffic_flows(scenario_id), diagnostics.forecast_capacity(scenario_id)]
    results += [diagnostics.analyze_traffic_flows(scenario_id, site_id=site) for site in ("NYC", "SIN", "BLR")]
    return [ok(result) for result in results]


def references(result: ToolResult) -> list[EvidenceRef]:
    refs = [ref for finding in result.findings for ref in finding.evidence]
    if result.tool == "check_network_reachability":
        refs += [EvidenceRef(**item) for item in result.data["evidence"]]
    return refs


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_every_evidence_reference_resolves_to_a_dataset_record(scenario_id: str) -> None:
    index = record_index(load_scenario(scenario_id))
    checked = 0
    for result in sweep(scenario_id):
        for ref in references(result):
            assert ref.collection in index, ref
            assert ref.record_id in index[ref.collection], ref
            assert index[ref.collection][ref.record_id] == ref.timestamp, ref
            checked += 1
        for finding in result.findings:
            assert finding.evidence, finding
    assert checked > 0


def test_baseline_sweep_has_no_failure_findings() -> None:
    findings = [(result.tool, finding) for result in sweep("BASELINE") for finding in result.findings]
    assert [(tool, finding.code) for tool, finding in findings] == [("get_firewall_logs", "TRAFFIC_DENIED")]
    assert "FWR-DC1-9999" in findings[0][1].summary
    baseline = load_scenario("BASELINE")
    denied = [event for event in baseline.firewall.events if event.action.value == "deny"]
    assert [ref.record_id for ref in findings[0][1].evidence] == [event.event_id for event in denied]


@pytest.mark.parametrize("scenario_id", [s for s in list_scenario_ids() if s != "BASELINE"])
def test_failure_scenarios_produce_findings_on_root_cause_devices(scenario_id: str) -> None:
    truth = load_scenario(scenario_id).ground_truth
    flagged = {finding.device_id for result in sweep(scenario_id) for finding in result.findings}
    assert set(truth.root_cause_device_ids) & flagged, truth.root_cause_device_ids
