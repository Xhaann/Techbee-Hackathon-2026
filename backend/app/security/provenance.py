from app.engine.schema import Diagnosis
from app.network.models import DeviceType, ScenarioDataset
from app.network.repository import DatasetNotFoundError, load_scenario, load_topology
from app.observability.simulation import monitored_interfaces, scenario_flows


DERIVED = {"flows", "configurations", "interface_history"}
# Phase 3 protocol telemetry collections (app.protocols.repository); listed here to avoid importing the protocol layer.
PROTOCOL_COLLECTIONS = {
    "protocol_events", "bgp_routes", "bgp_updates", "bgp_sessions", "ospf_lsas", "lsa_updates", "ospf_router_ids", "stp_vlans", "stp_ports",
    "arp_entries", "trunk_ports", "vlan_databases", "nat_pools", "nat_rules", "nat_samples", "nat_talkers", "ipsec_tunnels", "tcp_samples",
    "mtu_probes", "mtu_interfaces", "mtu_counters", "qos_policies", "qos_samples", "qos_markings", "ipv6_routes", "ospfv3_neighbors",
    "router_adverts", "ipv6_probes", "radio_samples", "rogue_aps", "pim_neighbors", "rp_mappings", "mroutes", "igmp_groups", "certificates",
    "tls_handshakes", "security_flows", "auth_events", "dns_logs", "ids_alerts",
}


def derived_index(dataset: ScenarioDataset) -> dict[str, set[str]]:
    """Observability records derived deterministically from this dataset: flows, configurations, interface history."""
    return {
        "flows": {f.flow_id for f in scenario_flows(dataset.scenario.scenario_id)},
        "configurations": {d.device_id for d in load_topology().devices if d.device_type != DeviceType.SERVER},
        "interface_history": set(monitored_interfaces(dataset)),
    }


def record_index(dataset: ScenarioDataset, derived: bool = True) -> dict[str, set[str]]:
    routing, firewall, dhcp = dataset.routing, dataset.firewall, dataset.dhcp
    return ({
        "events": {e.event_id for e in dataset.events},
        "interface_statistics": {f"{s.interface_id}@{s.timestamp.isoformat()}" for s in dataset.interface_statistics},
        "routing_tables": {t.device_id for t in routing.routing_tables},
        "ospf_neighbors": {f"{n.device_id}->{n.neighbor_device_id}" for n in routing.ospf_neighbors},
        "bgp_neighbors": {f"{n.device_id}->{n.neighbor_device_id}" for n in routing.bgp_neighbors},
        "route_changes": {c.change_id for c in routing.route_changes},
        "firewall_events": {e.event_id for e in firewall.events},
        "firewall_rules": {r.rule_id for r in firewall.rules},
        "dhcp_events": {e.event_id for e in dhcp.events},
        "dhcp_leases": {f"{lease.pool_id}:{lease.ip_address}" for lease in dhcp.leases},
        "dns_queries": {q.query_id for q in dataset.dns.queries},
    } | (derived_index(dataset) if derived else {}))


def provenance_issues(diagnosis: Diagnosis) -> list[str]:
    try:
        dataset = load_scenario(diagnosis.incident.scenario_id)
    except DatasetNotFoundError:
        return [f"Diagnosis cites unknown dataset scenario '{diagnosis.incident.scenario_id[:40]}'"]
    # Derived collections cost a simulation pass; build them only when the diagnosis actually cites one.
    cited_collections = {ref.collection for item in diagnosis.evidence for ref in item.references}
    index = record_index(dataset, derived=bool(cited_collections & DERIVED))
    if cited_collections & PROTOCOL_COLLECTIONS:
        from app.protocols.repository import load_telemetry, record_index as protocol_index
        index |= protocol_index(load_telemetry(diagnosis.incident.scenario_id))
    issues = []
    evidence_ids = {item.evidence_id for item in diagnosis.evidence}
    cited = set(diagnosis.fault.supporting_evidence_ids) | set(diagnosis.fault.contradictory_evidence_ids)
    cited |= {entry.evidence_id for entry in diagnosis.timeline}
    issues += [f"Diagnosis cites evidence {evidence_id[:20]} that it does not contain" for evidence_id in sorted(cited - evidence_ids)]
    for item in diagnosis.evidence:
        for ref in item.references:
            known = index.get(ref.collection)
            if known is None or ref.record_id not in known:
                issues.append(f"Evidence {item.evidence_id} references {ref.collection}:{ref.record_id[:60]} which is not in the dataset")
    calls = {call.call_id for call in diagnosis.tool_calls if call.status == "executed"}
    issues += [f"Evidence {item.evidence_id} cites tool call {item.call_id} that was not executed"
               for item in diagnosis.evidence if item.call_id not in calls]
    return issues
