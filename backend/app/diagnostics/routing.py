from collections import Counter
from datetime import timedelta
from typing import Any

from app.diagnostics.common import (
    EvidenceRef,
    Finding,
    FindingKind,
    ToolOutput,
    capped,
    diagnostic_tool,
    dump,
    event_refs,
    evidence,
    load_dataset,
    neighbor_ref,
    parse_network,
    peer_interface,
    require_device,
    sample_ref,
    samples_for,
)
from app.network.models import (
    BgpNeighbor,
    BgpState,
    Device,
    LinkStatus,
    NetworkTopology,
    OspfNeighbor,
    OspfState,
    RouteChange,
    RouteChangeType,
    RoutingProtocol,
    ScenarioDataset,
)

HEALTHY_STATES = (OspfState.FULL, BgpState.ESTABLISHED)
FAILED_STATES = (OspfState.DOWN, BgpState.IDLE, BgpState.ACTIVE)
CORRELATION_WINDOW = timedelta(minutes=5)
ROUTING_EVENT_TYPES = {"OSPF_ADJACENCY_DOWN", "BGP_NEIGHBOR_DOWN", "LINK_DOWN", "OSPF_MTU_MISMATCH", "MTU_CHANGE",
                       "CARRIER_LOSS"}


def participates_in_routing(topology: NetworkTopology, device: Device) -> bool:
    return any(
        link.routing_protocol is not None and device.device_id in (link.a_device_id, link.b_device_id)
        for link in topology.links
    )


def change_ref(change: RouteChange) -> EvidenceRef:
    return evidence("route_changes", change.change_id, change.timestamp)


def route_change_findings(device_id: str, changes: list[RouteChange]) -> list[Finding]:
    findings = []
    labels = {
        RouteChangeType.WITHDRAWN: ("ROUTES_WITHDRAWN", "withdrawn"),
        RouteChangeType.ADDED: ("ROUTES_ADDED", "added"),
        RouteChangeType.NEXT_HOP_CHANGED: ("NEXT_HOP_CHANGED", "changed next hop"),
    }
    for change_type, (code, label) in labels.items():
        matched = [change for change in changes if change.change_type == change_type]
        if matched:
            findings.append(Finding(
                code=code, kind=FindingKind.OBSERVED, device_id=device_id,
                summary=f"{len(matched)} routes {label} on {device_id} "
                        f"({', '.join(sorted({str(change.prefix) for change in matched})[:10])})",
                evidence=capped([change_ref(change) for change in matched]),
            ))
    return findings


@diagnostic_tool("get_routing_state")
def get_routing_state(scenario_id: str, device_id: str, prefix: Any = None) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    device = require_device(topology, device_id)
    network = parse_network(prefix, "prefix")
    table = next((t for t in dataset.routing.routing_tables if t.device_id == device.device_id), None)
    routes = [] if table is None else [r for r in table.routes if network is None or r.prefix.overlaps(network)]
    best_match = None
    if network is not None and network.num_addresses == 1 and routes:
        candidates = [r for r in routes if network.network_address in r.prefix]
        best_match = max(candidates, key=lambda r: r.prefix.prefixlen, default=None)
    ospf = [n for n in dataset.routing.ospf_neighbors if n.device_id == device.device_id]
    bgp = [n for n in dataset.routing.bgp_neighbors if n.device_id == device.device_id]
    changes = sorted((c for c in dataset.routing.route_changes if c.device_id == device.device_id),
                     key=lambda c: (c.timestamp, c.change_id))
    routes_expected = participates_in_routing(topology, device)
    assessment = "observed" if table is not None else "indeterminate" if routes_expected else "not_applicable"
    next_hops = sorted(
        {(str(r.next_hop), r.interface_id, r.protocol.value) for r in routes if r.next_hop is not None}
    )
    output = ToolOutput(
        scenario_id=dataset.scenario.scenario_id,
        data={
            "device_id": device.device_id,
            "site_id": device.site_id,
            "router_id": str(device.router_id) if device.router_id else None,
            "bgp_asn": device.bgp_asn,
            "assessment": assessment,
            "routing_table": None if table is None else {
                "collected_at": table.collected_at.isoformat(),
                "route_count": len(table.routes),
                "returned_route_count": len(routes),
                "protocol_counts": dict(sorted(Counter(r.protocol.value for r in table.routes).items())),
                "routes": [dump(route) for route in routes],
            },
            "best_match": dump(best_match) if best_match else None,
            "next_hops": [{"next_hop": hop, "interface_id": interface, "protocol": protocol}
                          for hop, interface, protocol in next_hops],
            "ospf_neighbors": [dump(n) for n in ospf],
            "bgp_neighbors": [dump(n) for n in bgp],
            "route_changes": [dump(c) for c in changes],
        },
    )
    if table is None:
        if routes_expected:
            output.missing_data.append(
                f"No routing table was collected from {device.device_id}; absence of telemetry is not proof of failure"
            )
        else:
            output.warnings.append(f"{device.device_id} does not participate in routing according to topology data")
    if network is not None and table is not None and not routes:
        output.warnings.append(f"No routes overlap {network}")
    for neighbor in ospf + bgp:
        if neighbor.state not in HEALTHY_STATES:
            protocol = "OSPF" if isinstance(neighbor, OspfNeighbor) else "BGP"
            output.findings.append(Finding(
                code="NEIGHBOR_NOT_ESTABLISHED", kind=FindingKind.OBSERVED, device_id=device.device_id,
                summary=f"{protocol} neighbor {neighbor.neighbor_device_id} is in state {neighbor.state.value} "
                        f"since {neighbor.last_state_change.isoformat()} (reported reason: {neighbor.failure_reason})",
                evidence=[neighbor_ref(neighbor)],
            ))
    output.findings += route_change_findings(device.device_id, changes)
    return output


def adjacency_status(views: list[OspfNeighbor | BgpNeighbor], window_start) -> str:
    if not views:
        return "unknown"
    if any(view.state in FAILED_STATES for view in views):
        return "failed"
    if any(view.state not in HEALTHY_STATES for view in views):
        return "stalled"
    if any(view.last_state_change >= window_start for view in views):
        return "recently_changed"
    return "healthy"


def interface_evidence(dataset: ScenarioDataset, interface_ids: list[str]) -> list[dict[str, Any]]:
    states = []
    for interface_id in interface_ids:
        samples = samples_for(dataset, interface_id)
        latest = samples[-1] if samples else None
        states.append({
            "interface_id": interface_id,
            "latest_status": latest.oper_status.value if latest else None,
            "latest_at": latest.timestamp.isoformat() if latest else None,
        })
    return states


@diagnostic_tool("analyze_routing_adjacency")
def analyze_routing_adjacency(scenario_id: str, device_id: str) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    device = require_device(topology, device_id)
    neighbors = dataset.routing.ospf_neighbors + dataset.routing.bgp_neighbors
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={})
    adjacencies = []
    for link in topology.links:
        if link.routing_protocol not in (RoutingProtocol.OSPF, RoutingProtocol.BGP):
            continue
        if device.device_id not in (link.a_device_id, link.b_device_id):
            continue
        local_interface = link.a_interface_id if link.a_device_id == device.device_id else link.b_interface_id
        peer_interface_id = peer_interface(link, local_interface)
        peer_id = peer_interface_id.split(":", 1)[0]
        kind = OspfNeighbor if link.routing_protocol == RoutingProtocol.OSPF else BgpNeighbor
        local_view = next((n for n in neighbors if isinstance(n, kind) and n.device_id == device.device_id
                           and n.neighbor_device_id == peer_id), None)
        peer_view = next((n for n in neighbors if isinstance(n, kind) and n.device_id == peer_id
                          and n.neighbor_device_id == device.device_id), None)
        views = [view for view in (local_view, peer_view) if view is not None]
        status = adjacency_status(views, dataset.scenario.window_start)
        interfaces = interface_evidence(dataset, [local_interface, peer_interface_id])
        changed_at = max((view.last_state_change for view in views), default=None)
        related_events, related_changes = [], []
        if changed_at is not None and changed_at >= dataset.scenario.window_start:
            related_events = sorted(
                (
                    e for e in dataset.events
                    if e.device_id in (device.device_id, peer_id)
                    and (e.event_type in ROUTING_EVENT_TYPES or e.interface_id in (local_interface, peer_interface_id))
                    and abs(e.timestamp - changed_at) <= CORRELATION_WINDOW
                ),
                key=lambda e: (e.timestamp, e.event_id),
            )
            related_changes = sorted(
                (
                    c for c in dataset.routing.route_changes
                    if c.device_id in (device.device_id, peer_id) and abs(c.timestamp - changed_at) <= CORRELATION_WINDOW
                ),
                key=lambda c: (c.timestamp, c.change_id),
            )
        adjacencies.append({
            "protocol": link.routing_protocol.value,
            "link_id": link.link_id,
            "ospf_area": link.ospf_area,
            "local_interface_id": local_interface,
            "peer_device_id": peer_id,
            "peer_interface_id": peer_interface_id,
            "status": status,
            "local_view": dump(local_view) if local_view else None,
            "peer_view": dump(peer_view) if peer_view else None,
            "interface_status": interfaces,
            "related_events": [dump(e) for e in related_events],
            "related_route_changes": [c.change_id for c in related_changes],
        })
        if local_view is None:
            output.missing_data.append(
                f"No {link.routing_protocol.value.upper()} neighbor record from {device.device_id} for {peer_id}"
                + ("; using the peer-reported state" if peer_view else "")
            )
        if status in ("failed", "stalled", "recently_changed"):
            refs = [neighbor_ref(view) for view in views] + event_refs(related_events)
            refs += [change_ref(c) for c in related_changes]
            reasons = sorted({view.failure_reason for view in views if view.failure_reason})
            output.findings.append(Finding(
                code=f"ADJACENCY_{status.upper()}", kind=FindingKind.OBSERVED, device_id=device.device_id,
                summary=f"{link.routing_protocol.value.upper()} adjacency {device.device_id} <-> {peer_id} on "
                        f"{link.link_id} is {status} (states: {', '.join(view.state.value for view in views)}; "
                        f"reported reasons: {'; '.join(reasons) or 'none'})",
                evidence=capped(refs),
            ))
            latest_states = [state["latest_status"] for state in interfaces]
            sample_refs = [sample_ref(samples_for(dataset, iid)[-1]) for iid in (local_interface, peer_interface_id)
                           if samples_for(dataset, iid)]
            if status in ("failed", "stalled") and latest_states == [LinkStatus.UP.value] * 2:
                output.findings.append(Finding(
                    code="CONTROL_PLANE_FAILURE_SUSPECTED", kind=FindingKind.INFERRED, device_id=device.device_id,
                    summary=f"Both interfaces on {link.link_id} report up while the adjacency is {status}; a protocol or "
                            "configuration mismatch is suspected rather than a physical link failure",
                    evidence=sample_refs + [neighbor_ref(view) for view in views],
                ))
            elif status in ("failed", "stalled") and LinkStatus.DOWN.value in latest_states:
                output.findings.append(Finding(
                    code="ADJACENCY_LOSS_FOLLOWS_INTERFACE_DOWN", kind=FindingKind.INFERRED, device_id=device.device_id,
                    summary=f"An interface on {link.link_id} reports down; the adjacency loss is consistent with the "
                            "interface outage",
                    evidence=sample_refs + [neighbor_ref(view) for view in views],
                ))
    if not adjacencies:
        output.warnings.append(f"{device.device_id} has no OSPF or BGP adjacencies in topology data")
    output.data = {
        "device_id": device.device_id,
        "site_id": device.site_id,
        "correlation_window_seconds": int(CORRELATION_WINDOW.total_seconds()),
        "adjacency_counts": dict(sorted(Counter(item["status"] for item in adjacencies).items())),
        "adjacencies": adjacencies,
    }
    return output
