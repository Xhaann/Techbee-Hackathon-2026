from ipaddress import IPv4Address
from typing import Any

from app.diagnostics.common import (
    EvidenceRef,
    Finding,
    FindingKind,
    ToolOutput,
    diagnostic_tool,
    dump,
    evidence,
    invalid,
    link_by_interface,
    load_dataset,
    load_topology,
    not_found,
    parse_address,
    require_device,
    require_site,
    sample_ref,
    samples_for,
)
from app.network.graph import build_adjacency, shortest_path
from app.network.models import (
    Device,
    InterfaceMode,
    LinkStatus,
    NetworkTopology,
    RelationshipType,
    RoutingProtocol,
    ScenarioDataset,
    Vlan,
)

MAX_FORWARDING_HOPS = 16
PATH_WARNING = "Path data models one path per branch service; alternate routes are not represented"


def device_dependencies(topology: NetworkTopology, device_id: str) -> dict[str, Any]:
    def related(relationship_type: RelationshipType, outgoing: bool) -> list[str]:
        return sorted(
            (r.target_device_id if outgoing else r.source_device_id)
            for r in topology.relationships
            if r.relationship_type == relationship_type
            and (r.source_device_id if outgoing else r.target_device_id) == device_id
        )

    peers = related(RelationshipType.REDUNDANT_PEER, True) + related(RelationshipType.REDUNDANT_PEER, False)
    connected = sorted(
        (link.b_device_id if link.a_device_id == device_id else link.a_device_id, link.link_id)
        for link in topology.links if device_id in (link.a_device_id, link.b_device_id)
    )
    return {
        "upstream": related(RelationshipType.UPSTREAM, True),
        "downstream": related(RelationshipType.UPSTREAM, False),
        "depends_on": related(RelationshipType.DEPENDS_ON, True),
        "required_by": related(RelationshipType.DEPENDS_ON, False),
        "redundant_peers": sorted(peers),
        "connected": [{"device_id": peer, "link_id": link_id} for peer, link_id in connected],
    }


def sites_using(topology: NetworkTopology, device_id: str) -> list[str]:
    return sorted({path.source_site_id for path in topology.paths if device_id in path.device_ids})


@diagnostic_tool("get_topology")
def get_topology(site_id: str) -> ToolOutput:
    topology = load_topology()
    site = require_site(topology, site_id)
    site_devices = sorted(device.device_id for device in topology.devices if device.site_id == site.site_id)
    members = set(site_devices)
    links = [
        dump(link) | {"scope": "internal" if {link.a_device_id, link.b_device_id} <= members else "external"}
        for link in topology.links if {link.a_device_id, link.b_device_id} & members
    ]
    relevant_paths = [
        path for path in topology.paths if path.source_site_id == site.site_id or members & set(path.device_ids)
    ]
    shared = sorted({device for path in relevant_paths for device in path.device_ids} - members)
    external_dependencies = sorted({
        target
        for device_id in site_devices
        for key in ("upstream", "depends_on")
        for target in device_dependencies(topology, device_id)[key]
        if target not in members
    })
    output = ToolOutput(data={
        "site": dump(site),
        "devices": [dump(device) for device in topology.devices if device.site_id == site.site_id],
        "interfaces": [dump(i) for i in topology.interfaces if i.device_id in members],
        "links": links,
        "vlans": [dump(vlan) for vlan in topology.vlans if vlan.site_id == site.site_id],
        "relationships": [
            dump(r) for r in topology.relationships if {r.source_device_id, r.target_device_id} & members
        ],
        "dependencies": {device_id: device_dependencies(topology, device_id) for device_id in site_devices},
        "external_dependencies": external_dependencies,
        "paths": [
            dump(path) | {"role": "originating" if path.source_site_id == site.site_id else "transit_or_destination"}
            for path in relevant_paths
        ],
        "shared_infrastructure": [
            {
                "device_id": device_id,
                "site_id": next(d.site_id for d in topology.devices if d.device_id == device_id),
                "path_ids": [p.path_id for p in relevant_paths if device_id in p.device_ids],
                "sites_using": sites_using(topology, device_id),
            }
            for device_id in shared
        ],
    })
    if not relevant_paths:
        output.warnings.append(f"No modelled network paths involve site {site.site_id}")
    return output


@diagnostic_tool("analyze_network_dependencies")
def analyze_network_dependencies(site_id: Any = None, device_id: Any = None) -> ToolOutput:
    topology = load_topology()
    if site_id is None and device_id is None:
        raise invalid("At least one of site_id or device_id is required")
    site = require_site(topology, site_id) if site_id is not None else None
    device = require_device(topology, device_id) if device_id is not None else None
    scope = [path for path in topology.paths if site is None or path.source_site_id == site.site_id]
    output = ToolOutput(data={}, warnings=[PATH_WARNING])
    data: dict[str, Any] = {
        "site_id": site.site_id if site else None,
        "device_id": device.device_id if device else None,
        "path_ids_in_scope": [path.path_id for path in scope],
    }
    usage: dict[str, list[str]] = {}
    for path in scope:
        for hop in path.device_ids:
            usage.setdefault(hop, []).append(path.path_id)
    data["devices_by_path_count"] = [
        {"device_id": hop, "path_count": len(path_ids), "sites_using": sites_using(topology, hop)}
        for hop, path_ids in sorted(usage.items(), key=lambda item: (-len(item[1]), item[0]))
    ]
    data["shared_devices"] = sorted(hop for hop in usage if len(sites_using(topology, hop)) > 1)
    if scope:
        data["common_to_all_paths_in_scope"] = sorted(hop for hop, path_ids in usage.items() if len(path_ids) == len(scope))
    if device is not None:
        through = [path for path in scope if device.device_id in path.device_ids]
        position = {path.path_id: path.device_ids.index(device.device_id) for path in through}
        data["dependencies"] = device_dependencies(topology, device.device_id)
        data["failure_impact"] = {
            "affected_path_ids": [path.path_id for path in through],
            "affected_sites": sorted({path.source_site_id for path in through}),
            "affected_services": sorted({path.service.value for path in through}),
            "dependent_devices": sorted({
                hop for path in through for hop in path.device_ids[:position[path.path_id]]
            }),
            "downstream_of_failure": sorted({
                hop for path in through for hop in path.device_ids[position[path.path_id] + 1:]
            }),
        }
        data["link_impact"] = [
            {
                "link_id": link.link_id,
                "link_type": link.link_type.value,
                "affected_path_ids": [path.path_id for path in scope if link.link_id in path.link_ids],
            }
            for link in topology.links if device.device_id in (link.a_device_id, link.b_device_id)
        ]
        if not through:
            output.warnings.append(f"No modelled paths in scope traverse {device.device_id}")
    output.data = data
    return output


def vlan_for(topology: NetworkTopology, address: IPv4Address) -> Vlan | None:
    return next((vlan for vlan in topology.vlans if address in vlan.subnet), None)


def resolve_endpoint(topology: NetworkTopology, value: Any, label: str) -> tuple[Device | None, IPv4Address, list[str]]:
    if not isinstance(value, str) or len(value) > 64:
        raise invalid(f"{label} must be a device identifier or an IPv4 address")
    address = parse_address(value)
    devices = {device.device_id: device for device in topology.devices}
    notes: list[str] = []
    if address is None:
        device = require_device(topology, value)
        candidates = [device.management_ip] + [
            i.ip_address.ip for i in topology.interfaces if i.device_id == device.device_id and i.mode == InterfaceMode.VIRTUAL
        ]
        routable = next((candidate for candidate in candidates if vlan_for(topology, candidate)), None)
        if routable is None:
            routable = next((i.ip_address.ip for i in topology.interfaces
                             if i.device_id == device.device_id and i.ip_address is not None), device.management_ip)
            notes.append(f"{device.device_id} has no VLAN-routed address; using {routable}")
        return device, routable, notes
    owner = next((i.device_id for i in topology.interfaces if i.ip_address is not None and i.ip_address.ip == address), None)
    owner = owner or next((d.device_id for d in topology.devices if d.management_ip == address), None)
    if owner is None and vlan_for(topology, address) is None:
        raise not_found(f"{label} address {address} is not part of the modelled network")
    return (devices[owner] if owner else None), address, notes


def link_status(dataset: ScenarioDataset, interface_ids: tuple[str, str]) -> tuple[str, list]:
    refs, statuses = [], []
    for interface_id in interface_ids:
        samples = samples_for(dataset, interface_id)
        if samples:
            refs.append(sample_ref(samples[-1]))
            statuses.append(samples[-1].oper_status)
    if LinkStatus.DOWN in statuses:
        return "down", refs
    return ("up" if len(statuses) == 2 else "unknown"), refs


class Forwarding:
    def __init__(self, topology: NetworkTopology, dataset: ScenarioDataset) -> None:
        self.topology = topology
        self.dataset = dataset
        self.tables = {t.device_id: t for t in dataset.routing.routing_tables}
        self.owners = {i.ip_address.ip: i for i in topology.interfaces if i.ip_address is not None}
        self.links = link_by_interface(topology)
        self.adjacency = build_adjacency(topology.links)
        self.hops: list[dict[str, Any]] = []
        self.evidence: list[EvidenceRef] = []
        self.failure_evidence: dict[str, list[EvidenceRef]] = {}

    def layer2(self, source: str, target: str) -> dict[str, Any] | None:
        if source == target:
            return None
        route = shortest_path(self.adjacency, source, target)
        if route is None:
            return {"device_id": source, "reason": "no_physical_path", "link_id": None}
        devices, link_ids = route
        links = {link.link_id: link for link in self.topology.links}
        for index, link_id in enumerate(link_ids):
            link = links[link_id]
            status, refs = link_status(self.dataset, (link.a_interface_id, link.b_interface_id))
            self.evidence += refs
            self.hops.append({"device_id": devices[index], "next_device_id": devices[index + 1], "link_id": link_id,
                              "segment": "layer2", "link_status": status})
            if status == "down":
                self.failure_evidence[link_id] = refs
                return {"device_id": devices[index], "reason": "link_down", "link_id": link_id}
        return None

    def path(self) -> list[str]:
        devices: list[str] = []
        for hop in self.hops:
            for device_id in (hop["device_id"], hop.get("next_device_id")):
                if device_id and (not devices or devices[-1] != device_id):
                    devices.append(device_id)
        return devices

    def down_links_at(self, device_id: str) -> list[str]:
        down = []
        for link in self.topology.links:
            if device_id in (link.a_device_id, link.b_device_id):
                status, refs = link_status(self.dataset, (link.a_interface_id, link.b_interface_id))
                if status == "down":
                    down.append(link.link_id)
                    self.evidence += refs
                    self.failure_evidence[link.link_id] = refs
        return down

    def run(self, start: str, destination: Device | None, address: IPv4Address) -> tuple[str, dict[str, Any] | None]:
        current, visited = start, set()
        for _ in range(MAX_FORWARDING_HOPS):
            if destination is not None and current == destination.device_id:
                return "reachable", None
            if current in visited:
                return "unreachable", {"device_id": current, "reason": "forwarding_loop", "link_id": None}
            visited.add(current)
            table = self.tables.get(current)
            if table is None:
                return "indeterminate", {"device_id": current, "reason": "no_routing_telemetry", "link_id": None}
            self.evidence.append(evidence("routing_tables", current, table.collected_at))
            matches = [route for route in table.routes if address in route.prefix]
            if not matches:
                return "unreachable", {"device_id": current, "reason": "no_route", "link_id": None,
                                       "down_link_ids": self.down_links_at(current)}
            route = max(matches, key=lambda item: item.prefix.prefixlen)
            if route.protocol == RoutingProtocol.CONNECTED:
                self.hops.append({"device_id": current, "route": str(route.prefix), "protocol": route.protocol.value,
                                  "interface_id": route.interface_id, "segment": "delivery"})
                if destination is None or destination.device_id == current:
                    return "reachable", None
                failure = self.layer2(current, destination.device_id)
                return ("unreachable", failure) if failure else ("reachable", None)
            owner = self.owners.get(route.next_hop)
            if owner is None:
                return "indeterminate", {"device_id": current, "reason": "unknown_next_hop", "link_id": None}
            link = self.links.get(route.interface_id)
            status, refs = ("unknown", []) if link is None else link_status(self.dataset, (link.a_interface_id, link.b_interface_id))
            self.evidence += refs
            self.hops.append({"device_id": current, "route": str(route.prefix), "protocol": route.protocol.value,
                              "next_hop": str(route.next_hop), "interface_id": route.interface_id,
                              "next_device_id": owner.device_id, "link_id": link.link_id if link else None,
                              "segment": "layer3", "link_status": status})
            if status == "down":
                self.failure_evidence[link.link_id] = refs
                return "unreachable", {"device_id": current, "reason": "link_down", "link_id": link.link_id}
            current = owner.device_id
        return "indeterminate", {"device_id": current, "reason": "hop_limit_exceeded", "link_id": None}


@diagnostic_tool("check_network_reachability")
def check_network_reachability(scenario_id: str, source: Any, destination: Any) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    source_device, source_address, source_notes = resolve_endpoint(topology, source, "source")
    destination_device, destination_address, destination_notes = resolve_endpoint(topology, destination, "destination")
    forwarding = Forwarding(topology, dataset)
    output = ToolOutput(
        scenario_id=dataset.scenario.scenario_id, data={},
        warnings=["Forward path only; return path, firewall policy and application state are not evaluated"],
        missing_data=source_notes + destination_notes,
    )
    routes_expected = source_device is not None and any(
        link.routing_protocol is not None and source_device.device_id in (link.a_device_id, link.b_device_id)
        for link in topology.links
    )
    if routes_expected:
        start, failure = source_device.device_id, None
    else:
        vlan = vlan_for(topology, source_address)
        if vlan is None:
            raise invalid(f"source {source_address} has no routing table and no gateway VLAN")
        start = vlan.gateway_interface_id.split(":", 1)[0]
        failure = forwarding.layer2(source_device.device_id, start) if source_device else None
    status = "unreachable"
    if failure is None:
        status, failure = forwarding.run(start, destination_device, destination_address)
    if failure is not None and failure.get("reason") == "no_route":
        output.findings.append(Finding(
            code="NO_ROUTE_TO_DESTINATION", kind=FindingKind.OBSERVED, device_id=failure["device_id"],
            summary=f"The routing table of {failure['device_id']} has no route covering {destination_address}",
            evidence=[evidence("routing_tables", failure["device_id"], forwarding.tables[failure["device_id"]].collected_at)],
        ))
        for link_id in failure.get("down_link_ids", []):
            output.findings.append(Finding(
                code="LINK_DOWN_AT_FAILURE_POINT", kind=FindingKind.OBSERVED, device_id=failure["device_id"],
                summary=f"Link {link_id} attached to {failure['device_id']} reports operational status down",
                evidence=forwarding.failure_evidence[link_id],
            ))
    elif failure is not None and failure.get("reason") == "link_down":
        output.findings.append(Finding(
            code="LINK_DOWN_ON_PATH", kind=FindingKind.OBSERVED, device_id=failure["device_id"],
            summary=f"Link {failure['link_id']} on the forwarding path reports operational status down",
            evidence=forwarding.failure_evidence[failure["link_id"]],
        ))
    elif failure is not None and failure.get("reason") == "no_routing_telemetry":
        output.missing_data.append(
            f"No routing table from {failure['device_id']}; reachability beyond it cannot be determined from evidence"
        )
    output.data = {
        "source": {"input": source, "device_id": source_device.device_id if source_device else None,
                   "address": str(source_address)},
        "destination": {"input": destination, "device_id": destination_device.device_id if destination_device else None,
                        "address": str(destination_address)},
        "evaluated_at": max((t.collected_at for t in dataset.routing.routing_tables), default=dataset.scenario.window_end).isoformat(),
        "status": status,
        "first_hop_device_id": start,
        "path": forwarding.path(),
        "hops": forwarding.hops,
        "failure_point": failure,
        "evidence": [dump(ref) for ref in forwarding.evidence],
    }
    return output
