"""Path-wide health: every link on the forwarding path, not only the branch's own WAN egress."""
from typing import Any

from app.diagnostics.common import (
    EvidenceRef,
    Finding,
    FindingKind,
    ToolOutput,
    capped,
    diagnostic_tool,
    evidence,
    load_dataset,
    sample_ref,
    samples_for,
)
from app.diagnostics.telemetry import THRESHOLDS, drops_of, errors_of
from app.diagnostics.topology import Forwarding, resolve_endpoint, vlan_for
from app.network.models import LinkStatus, NetworkTopology

DEGRADATION_EVENTS = {"OPTICAL_RX_LOW", "INTERFACE_ERRORS", "CARRIER_LOSS"}
CONGESTION_EVENTS = {"QOS_QUEUE_DROPS", "SLA_THRESHOLD_EXCEEDED"}


def forward_links(topology: NetworkTopology, forwarding: Forwarding) -> list[str]:
    ordered: list[str] = []
    for hop in forwarding.hops:
        link_id = hop.get("link_id")
        if link_id and link_id not in ordered:
            ordered.append(link_id)
    return ordered


@diagnostic_tool("analyze_path_health")
def analyze_path_health(scenario_id: str, source: Any, destination: Any) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    source_device, source_address, notes = resolve_endpoint(topology, source, "source")
    destination_device, destination_address, more = resolve_endpoint(topology, destination, "destination")
    forwarding = Forwarding(topology, dataset)
    routed = source_device is not None and any(link.routing_protocol is not None and source_device.device_id in
                                               (link.a_device_id, link.b_device_id) for link in topology.links)
    if routed:
        status, failure = forwarding.run(source_device.device_id, destination_device, destination_address)
    else:
        vlan = vlan_for(topology, source_address)
        start = vlan.gateway_interface_id.split(":", 1)[0] if vlan else None
        failure = forwarding.layer2(source_device.device_id, start) if source_device and start else None
        status, failure = (forwarding.run(start, destination_device, destination_address) if start and failure is None
                           else ("unreachable", failure))
    links = {link.link_id: link for link in topology.links}
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={}, missing_data=notes + more,
                        warnings=["Forward path only; the return path and links off the path are not evaluated"])
    segments = []
    for link_id in forward_links(topology, forwarding):
        link = links[link_id]
        sides = []
        refs: list[EvidenceRef] = []
        loss = errors = drops = utilization = 0.0
        latency_ratio = None
        down = False
        for interface_id in (link.a_interface_id, link.b_interface_id):
            samples = samples_for(dataset, interface_id)
            up = [s for s in samples if s.oper_status == LinkStatus.UP]
            if samples and samples[-1].oper_status == LinkStatus.DOWN:
                down = True
                refs.append(sample_ref(samples[-1]))
            worst_loss = max((s.packet_loss_percent or 0 for s in up), default=0.0)
            worst_errors = max((errors_of(s) for s in samples), default=0)
            worst_drops = max((drops_of(s) for s in samples), default=0)
            worst_util = max((s.utilization_percent for s in samples), default=0.0)
            measured = [s.latency_ms / link.latency_ms for s in up if s.latency_ms is not None and link.latency_ms > 0]
            refs += [sample_ref(s) for s in samples if (s.packet_loss_percent or 0) >= THRESHOLDS["packet_loss_percent"]
                     or errors_of(s) > THRESHOLDS["errors_per_interval"] or s.utilization_percent >= THRESHOLDS["congestion_utilization_percent"]]
            loss, errors, drops = max(loss, worst_loss), max(errors, worst_errors), max(drops, worst_drops)
            utilization = max(utilization, worst_util)
            if measured:
                latency_ratio = max(latency_ratio or 0, max(measured))
            sides.append({"interface_id": interface_id, "samples": len(samples), "max_loss_percent": worst_loss,
                          "max_errors_per_interval": worst_errors, "max_drops_per_interval": worst_drops,
                          "max_utilization_percent": worst_util,
                          "latest_status": samples[-1].oper_status.value if samples else None})
        events = sorted((e for e in dataset.events if e.interface_id in (link.a_interface_id, link.b_interface_id)
                         and e.event_type in DEGRADATION_EVENTS | CONGESTION_EVENTS), key=lambda e: (e.timestamp, e.event_id))
        degradation_events = [e for e in events if e.event_type in DEGRADATION_EVENTS]
        congestion_events = [e for e in events if e.event_type in CONGESTION_EVENTS]
        lossy = loss >= THRESHOLDS["packet_loss_percent"]
        erroring = errors > THRESHOLDS["errors_per_interval"] or bool(degradation_events)
        busy = utilization >= THRESHOLDS["congestion_utilization_percent"] or bool(congestion_events)
        if down:
            state = "down"
        elif lossy and erroring:
            state = "degraded"
        elif (lossy or drops > THRESHOLDS["drops_per_interval"]) and busy:
            state = "congested"
        elif lossy:
            state = "lossy"
        else:
            state = "healthy"
        refs = capped(list({(r.collection, r.record_id): r for r in refs + [evidence("events", e.event_id, e.timestamp) for e in events]}.values()))
        endpoints = f"{link.a_device_id} {link.a_interface_id.split(':', 1)[1]} <-> {link.b_device_id} {link.b_interface_id.split(':', 1)[1]}"
        circuit = f", {link.provider} circuit {link.circuit_id}" if link.provider else ""
        segment = {"link_id": link.link_id, "link_type": link.link_type.value, "endpoints": endpoints, "state": state,
                   "max_loss_percent": loss, "max_errors_per_interval": errors, "max_utilization_percent": utilization,
                   "max_latency_ratio": round(latency_ratio, 2) if latency_ratio else None,
                   "events": [e.event_type for e in events], "sides": sides}
        segments.append(segment)
        label = f"Link {link.link_id} ({endpoints}{circuit})"
        if state == "down":
            output.findings.append(Finding(code="PATH_SEGMENT_DOWN", kind=FindingKind.OBSERVED, device_id=link.a_device_id,
                                           summary=f"{label} on the path is down", evidence=refs))
        elif state == "degraded":
            signals = [f"up to {loss:g}% loss" if lossy else None,
                       f"{int(errors)} errors per interval" if errors > THRESHOLDS["errors_per_interval"] else None,
                       ", ".join(sorted({e.event_type for e in degradation_events})) if degradation_events else None]
            output.findings.append(Finding(
                code="PATH_SEGMENT_DEGRADED", kind=FindingKind.OBSERVED, device_id=link.a_device_id,
                summary=f"{label} on the path shows {'; '.join(s for s in signals if s)}", evidence=refs))
        elif state == "congested":
            output.findings.append(Finding(
                code="PATH_SEGMENT_CONGESTED", kind=FindingKind.INFERRED, device_id=link.a_device_id,
                summary=f"{label} runs at up to {utilization:g}% utilisation with loss or drops but no error growth; "
                        "congestion is suspected rather than a physical fault", evidence=refs))
    worst = next((s["link_id"] for state in ("down", "degraded", "congested", "lossy") for s in segments if s["state"] == state), None)
    output.data = {
        "source": {"input": source, "device_id": source_device.device_id if source_device else None, "address": str(source_address)},
        "destination": {"input": destination, "device_id": destination_device.device_id if destination_device else None,
                        "address": str(destination_address)},
        "reachability": status, "failure_point": failure, "path": forwarding.path(), "segments": segments,
        "worst_segment": worst, "thresholds": {k: THRESHOLDS[k] for k in ("packet_loss_percent", "errors_per_interval",
                                                                        "congestion_utilization_percent")},
    }
    if not segments:
        output.missing_data.append("No links could be traced between the endpoints")
    return output
