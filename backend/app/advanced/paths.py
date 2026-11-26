from app.advanced.schema import PathAnalysis, PathHop
from app.engine.executor import ToolCallRecord
from app.engine.schema import Diagnosis, FaultDomain
from app.network.graph import build_adjacency, shortest_path
from app.network.models import NetworkTopology

FORWARD_ONLY = "Forward direction only; the return path was not evaluated"
DEVICE_DOMAINS = {FaultDomain.SHARED_INFRASTRUCTURE, FaultDomain.NETWORK_DEVICE_FAILURE}


def modelled_path(topology: NetworkTopology, source: str | None, destination: str | None):
    return next((path for path in topology.paths if path.device_ids[0] == source and path.device_ids[-1] == destination), None)


def alternatives(topology: NetworkTopology, source: str, destination: str, failed_links: set[str],
                 failed_devices: set[str], primary: list[str]) -> list[list[str]]:
    if not (failed_links or failed_devices) or not source or not destination:
        return []
    usable = [link for link in topology.links if link.link_id not in failed_links
              and not {link.a_device_id, link.b_device_id} & failed_devices]
    route = shortest_path(build_adjacency(usable), source, destination)
    if route is None or route[0] == primary:
        return []
    return [route[0]]


def analyze_paths(records: list[ToolCallRecord], topology: NetworkTopology, diagnosis: Diagnosis,
                  degraded_links: set[str]) -> list[PathAnalysis]:
    devices = {device.device_id: device for device in topology.devices}
    links = {link.link_id: link for link in topology.links}
    failed_devices = set(diagnosis.fault.device_ids) if diagnosis.fault.fault_domain in DEVICE_DOMAINS else set()
    analyses = []
    for record in records:
        if not (record.succeeded and record.tool == "check_network_reachability"):
            continue
        data = record.result.data
        path, status = data["path"], data["status"]
        source, destination = data["source"]["device_id"], data["destination"]["device_id"]
        failure = data["failure_point"] or {}
        failed = set(failure.get("down_link_ids", [])) | ({failure["link_id"]} if failure.get("link_id") else set())
        expected = modelled_path(topology, source, destination)
        complete = status == "reachable" and bool(path) and path[-1] == destination
        next_link = {(hop["device_id"], hop.get("next_device_id")): hop.get("link_id") for hop in data["hops"]}
        protocols = {hop["device_id"]: hop.get("protocol") for hop in data["hops"] if hop.get("segment") == "layer3"}
        hops = []
        for index, device_id in enumerate(path):
            following = path[index + 1] if index + 1 < len(path) else None
            link_id = next_link.get((device_id, following)) if following else None
            interfaces = [endpoint for endpoint in (links[link_id].a_interface_id, links[link_id].b_interface_id)] if link_id else []
            role = "source" if index == 0 else "destination" if complete and index == len(path) - 1 else "intermediate"
            hops.append(PathHop(device_id=device_id, site_id=devices[device_id].site_id, role=role, link_to_next=link_id,
                                interfaces=interfaces, routing_protocol=protocols.get(device_id)))
        reference_links = set(expected.link_ids) if expected else set()
        reference_links |= {hop.link_to_next for hop in hops if hop.link_to_next}
        degraded = sorted(degraded_links & reference_links)
        earliest = failure.get("device_id")
        if earliest is None and degraded:
            earliest = next((hop.device_id for hop in hops if hop.link_to_next in degraded), None)
        limitations = [FORWARD_ONLY]
        beyond = [d for d in (expected.device_ids if expected else []) if d in failed_devices and d not in path]
        if beyond and earliest:
            limitations.append(f"Forwarding stops at {earliest}; the suspected fault device {beyond[0]} lies beyond it on the modelled path")
        if not complete:
            limitations.append(f"Forwarding evidence ends at {path[-1] if path else source}; the modelled path is shown for reference only")
        if status == "indeterminate":
            limitations.append(f"Reachability is indeterminate: {failure.get('reason', 'unknown')}")
        analyses.append(PathAnalysis(
            source=data["source"]["input"], destination=data["destination"]["input"], status=status, complete=complete, hops=hops,
            modelled_path_id=expected.path_id if expected else None, modelled_path_devices=expected.device_ids if expected else [],
            earliest_affected_point=earliest, failed_links=sorted(failed), degraded_links=degraded, shared_devices=[],
            topology_alternatives=alternatives(topology, source, destination, failed, failed_devices,
                                               expected.device_ids if expected else path),
            limitations=limitations,
        ))
    if len(analyses) >= 2:
        sets = [set(a.modelled_path_devices or [hop.device_id for hop in a.hops]) for a in analyses]
        endpoints = {a.hops[0].device_id for a in analyses if a.hops}
        endpoints |= {a.modelled_path_devices[-1] for a in analyses if a.modelled_path_devices}
        shared = sorted(set.intersection(*sets) - endpoints)
        analyses = [a.model_copy(update={"shared_devices": shared}) for a in analyses]
    return analyses
