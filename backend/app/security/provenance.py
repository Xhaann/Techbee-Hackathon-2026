from app.engine.schema import Diagnosis
from app.network.models import ScenarioDataset
from app.network.repository import DatasetNotFoundError, load_scenario


def record_index(dataset: ScenarioDataset) -> dict[str, set[str]]:
    routing, firewall, dhcp = dataset.routing, dataset.firewall, dataset.dhcp
    return {
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
    }


def provenance_issues(diagnosis: Diagnosis) -> list[str]:
    try:
        dataset = load_scenario(diagnosis.incident.scenario_id)
    except DatasetNotFoundError:
        return [f"Diagnosis cites unknown dataset scenario '{diagnosis.incident.scenario_id[:40]}'"]
    index = record_index(dataset)
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
