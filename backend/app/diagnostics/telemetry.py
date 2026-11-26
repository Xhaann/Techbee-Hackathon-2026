from collections import Counter
from datetime import datetime
from typing import Any

from app.diagnostics.common import (
    DEFAULT_RECORDS,
    MAX_SAMPLE_EVIDENCE,
    Finding,
    FindingKind,
    ToolOutput,
    capped,
    collection_times,
    diagnostic_tool,
    dump,
    event_refs,
    link_by_interface,
    load_dataset,
    neighbor_ref,
    parse_event_types,
    parse_limit,
    parse_severity,
    parse_time_range,
    peer_interface,
    require_device,
    require_interface,
    sample_ref,
    samples_for,
    severity_rank,
)
from app.network.models import (
    BgpState,
    Interface,
    InterfaceMode,
    InterfaceStatistics,
    Link,
    LinkStatus,
    NetworkTopology,
    OspfState,
    ScenarioDataset,
    Severity,
)

THRESHOLDS = {
    "utilization_percent": 80.0,
    "packet_loss_percent": 1.0,
    "errors_per_interval": 100,
    "drops_per_interval": 100,
    "latency_increase_ratio": 1.5,
    "congestion_utilization_percent": 90.0,
}
FAULT_SEVERITY = Severity.ERROR
CRITICAL_SEVERITY = Severity.CRITICAL


def classify_pattern(flags: list[bool]) -> str:
    if not any(flags):
        return "none"
    if sum(flags) == 1:
        return "isolated"
    first = flags.index(True)
    return "sustained" if all(flags[first:]) else "intermittent"


def errors_of(sample: InterfaceStatistics) -> int:
    return sample.in_errors + sample.out_errors


def drops_of(sample: InterfaceStatistics) -> int:
    return sample.in_drops + sample.out_drops


def latency_exceeded(sample: InterfaceStatistics, link: Link | None) -> bool:
    if sample.latency_ms is None or link is None or link.latency_ms <= 0:
        return False
    return sample.latency_ms > link.latency_ms * THRESHOLDS["latency_increase_ratio"]


def link_summary(link: Link | None, interface_id: str) -> dict[str, Any] | None:
    if link is None:
        return None
    return {
        "link_id": link.link_id,
        "link_type": link.link_type.value,
        "peer_interface_id": peer_interface(link, interface_id),
        "bandwidth_mbps": link.bandwidth_mbps,
        "nominal_latency_ms": link.latency_ms,
    }


def missing_sample_times(dataset: ScenarioDataset, samples: list[InterfaceStatistics]) -> list[datetime]:
    present = {sample.timestamp for sample in samples}
    return [moment for moment in collection_times(dataset) if moment not in present]


def threshold_findings(interface: Interface, samples: list[InterfaceStatistics], link: Link | None) -> list[Finding]:
    checks = (
        ("INTERFACE_DOWN", lambda s: s.oper_status == LinkStatus.DOWN, "reported operational status down"),
        ("HIGH_PACKET_LOSS", lambda s: s.oper_status == LinkStatus.UP and (s.packet_loss_percent or 0) >= THRESHOLDS["packet_loss_percent"],
         f"measured packet loss at or above {THRESHOLDS['packet_loss_percent']}% while up"),
        ("HIGH_ERROR_COUNT", lambda s: errors_of(s) > THRESHOLDS["errors_per_interval"],
         f"reported more than {THRESHOLDS['errors_per_interval']} errors per interval"),
        ("HIGH_DROP_COUNT", lambda s: drops_of(s) > THRESHOLDS["drops_per_interval"],
         f"reported more than {THRESHOLDS['drops_per_interval']} drops per interval"),
        ("HIGH_UTILIZATION", lambda s: s.utilization_percent >= THRESHOLDS["utilization_percent"],
         f"reported utilization at or above {THRESHOLDS['utilization_percent']}%"),
        ("HIGH_LATENCY", lambda s: latency_exceeded(s, link),
         f"reported latency above {THRESHOLDS['latency_increase_ratio']}x the nominal link latency"),
    )
    findings = []
    for code, check, description in checks:
        matched = [sample for sample in samples if check(sample)]
        if matched:
            findings.append(Finding(
                code=code, kind=FindingKind.OBSERVED, device_id=interface.device_id,
                summary=f"{interface.interface_id} {description} in {len(matched)} of {len(samples)} samples "
                        f"(first at {matched[0].timestamp.isoformat()})",
                evidence=capped([sample_ref(sample) for sample in matched]),
            ))
    return findings


def physical_layer_suspicion(interface: Interface, samples: list[InterfaceStatistics]) -> Finding | None:
    lossy = [s for s in samples if s.oper_status == LinkStatus.UP and (s.packet_loss_percent or 0) >= THRESHOLDS["packet_loss_percent"]]
    corroborated = [s for s in lossy if errors_of(s) > THRESHOLDS["errors_per_interval"]]
    if not corroborated or len(corroborated) * 2 < len(lossy):
        return None
    return Finding(
        code="PHYSICAL_LAYER_DEGRADATION_SUSPECTED", kind=FindingKind.INFERRED, device_id=interface.device_id,
        summary=f"Packet loss on {interface.interface_id} coincides with high interface error counts in "
                f"{len(corroborated)} of {len(lossy)} lossy samples; a physical-layer or circuit fault is suspected",
        evidence=capped([sample_ref(sample) for sample in corroborated]),
    )


@diagnostic_tool("get_device_logs")
def get_device_logs(scenario_id: str, device_id: str, start: Any = None, end: Any = None, min_severity: Any = None,
                    event_types: Any = None, limit: Any = DEFAULT_RECORDS) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    device = require_device(topology, device_id)
    range_start, range_end = parse_time_range(dataset, start, end)
    severity = parse_severity(min_severity)
    types = parse_event_types(event_types)
    limit = parse_limit(limit)
    device_events = [event for event in dataset.events if event.device_id == device.device_id]
    matched = sorted(
        (
            event for event in device_events
            if range_start <= event.timestamp <= range_end
            and (severity is None or severity_rank(event.severity) <= severity_rank(severity))
            and (not types or event.event_type in types)
        ),
        key=lambda event: (event.timestamp, event.event_id),
    )
    records = matched[:limit]
    counts = Counter(event.severity for event in matched)
    output = ToolOutput(
        scenario_id=dataset.scenario.scenario_id,
        data={
            "device_id": device.device_id,
            "site_id": device.site_id,
            "time_range": {"start": range_start.isoformat(), "end": range_end.isoformat()},
            "filters": {"min_severity": severity.value if severity else None, "event_types": types},
            "total_matched": len(matched),
            "returned": len(records),
            "truncated": len(matched) > limit,
            "severity_counts": {item.value: counts[item] for item in Severity if counts[item]},
            "records": [dump(event) for event in records],
        },
    )
    if len(matched) > limit:
        output.warnings.append(f"Result truncated to {limit} of {len(matched)} matching records")
    if not device_events:
        output.missing_data.append(f"No log records exist for {device.device_id} in this dataset")
    elif not matched:
        output.warnings.append("No log records matched the requested time range and filters")
    return output


@diagnostic_tool("get_interface_stats")
def get_interface_stats(scenario_id: str, device_id: str, interface: Any = None) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    device = require_device(topology, device_id)
    if interface is None:
        interfaces = [item for item in topology.interfaces if item.device_id == device.device_id]
    else:
        interfaces = [require_interface(topology, device, interface)]
    links = link_by_interface(topology)
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={})
    entries = []
    for item in interfaces:
        samples = samples_for(dataset, item.interface_id)
        link = links.get(item.interface_id)
        missing = [] if item.mode == InterfaceMode.VIRTUAL else missing_sample_times(dataset, samples)
        if item.mode == InterfaceMode.VIRTUAL:
            output.missing_data.append(f"{item.interface_id} is a virtual interface; no statistics are collected for it")
        elif missing:
            output.missing_data.append(
                f"No statistics for {item.interface_id} at {', '.join(moment.isoformat() for moment in missing)}; "
                "missing samples are not evidence of failure"
            )
        if samples and all(sample.latency_ms is None for sample in samples):
            output.missing_data.append(f"Latency is not measured on {item.interface_id}")
        output.findings += threshold_findings(item, samples, link)
        entries.append({
            "interface": dump(item),
            "link": link_summary(link, item.interface_id),
            "sample_count": len(samples),
            "missing_sample_times": [moment.isoformat() for moment in missing],
            "latest": dump(samples[-1]) if samples else None,
            "samples": [dump(sample) for sample in samples],
        })
    output.data = {
        "device_id": device.device_id,
        "site_id": device.site_id,
        "thresholds": THRESHOLDS,
        "interfaces": entries,
    }
    return output


@diagnostic_tool("analyze_packet_loss")
def analyze_packet_loss(scenario_id: str, device_id: str, interface: Any) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    device = require_device(topology, device_id)
    item = require_interface(topology, device, interface)
    link = link_by_interface(topology).get(item.interface_id)
    samples = samples_for(dataset, item.interface_id)
    measured = [sample for sample in samples if sample.packet_loss_percent is not None]
    flags = [sample.packet_loss_percent >= THRESHOLDS["packet_loss_percent"] for sample in measured]
    lossy = [sample for sample, flag in zip(measured, flags) if flag]
    outage = [sample for sample in lossy if sample.oper_status == LinkStatus.DOWN]
    peer = None
    if link is not None:
        peer_id = peer_interface(link, item.interface_id)
        peer_samples = [s for s in samples_for(dataset, peer_id) if s.packet_loss_percent is not None]
        peer = {
            "interface_id": peer_id,
            "measurements": [{"timestamp": s.timestamp.isoformat(), "packet_loss_percent": s.packet_loss_percent,
                              "oper_status": s.oper_status.value} for s in peer_samples],
        }
    output = ToolOutput(
        scenario_id=dataset.scenario.scenario_id,
        data={
            "device_id": device.device_id,
            "interface_id": item.interface_id,
            "link": link_summary(link, item.interface_id),
            "threshold_percent": THRESHOLDS["packet_loss_percent"],
            "pattern": classify_pattern(flags) if measured else "not_measured",
            "lossy_sample_count": len(lossy),
            "measured_sample_count": len(measured),
            "outage_sample_count": len(outage),
            "first_loss_at": lossy[0].timestamp.isoformat() if lossy else None,
            "peak_loss_percent": max((s.packet_loss_percent for s in lossy), default=None),
            "measurements": [
                {
                    "timestamp": s.timestamp.isoformat(), "packet_loss_percent": s.packet_loss_percent,
                    "oper_status": s.oper_status.value, "latency_ms": s.latency_ms,
                    "in_errors": s.in_errors, "out_errors": s.out_errors, "in_drops": s.in_drops,
                    "out_drops": s.out_drops, "utilization_percent": s.utilization_percent,
                }
                for s in measured
            ],
            "peer": peer,
        },
    )
    if not measured:
        output.missing_data.append(f"Packet loss is not measured on {item.interface_id}")
        return output
    if lossy:
        output.findings.append(Finding(
            code="PACKET_LOSS_MEASURED", kind=FindingKind.OBSERVED, device_id=device.device_id,
            summary=f"{item.interface_id} measured loss at or above {THRESHOLDS['packet_loss_percent']}% in "
                    f"{len(lossy)} of {len(measured)} samples (peak {max(s.packet_loss_percent for s in lossy)}%)",
            evidence=capped([sample_ref(sample) for sample in lossy]),
        ))
    if outage:
        output.findings.append(Finding(
            code="LOSS_DURING_INTERFACE_DOWN", kind=FindingKind.INFERRED, device_id=device.device_id,
            summary=f"{len(outage)} lossy samples were taken while {item.interface_id} was down; "
                    "the loss reflects an outage rather than degradation",
            evidence=capped([sample_ref(sample) for sample in outage]),
        ))
    suspicion = physical_layer_suspicion(item, measured)
    if suspicion is not None:
        output.findings.append(suspicion)
    congested = [s for s in lossy if s.utilization_percent >= THRESHOLDS["congestion_utilization_percent"]]
    if congested:
        output.findings.append(Finding(
            code="CONGESTION_SUSPECTED", kind=FindingKind.INFERRED, device_id=device.device_id,
            summary=f"Loss on {item.interface_id} coincides with utilization at or above "
                    f"{THRESHOLDS['congestion_utilization_percent']}% in {len(congested)} samples",
            evidence=capped([sample_ref(sample) for sample in congested]),
        ))
    return output


@diagnostic_tool("analyze_interface_errors")
def analyze_interface_errors(scenario_id: str, device_id: str, interface: Any) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    device = require_device(topology, device_id)
    item = require_interface(topology, device, interface)
    samples = samples_for(dataset, item.interface_id)
    error_flags = [errors_of(s) > THRESHOLDS["errors_per_interval"] for s in samples]
    drop_flags = [drops_of(s) > THRESHOLDS["drops_per_interval"] for s in samples]
    related_events = sorted(
        (event for event in dataset.events if event.interface_id == item.interface_id),
        key=lambda event: (event.timestamp, event.event_id),
    )
    output = ToolOutput(
        scenario_id=dataset.scenario.scenario_id,
        data={
            "device_id": device.device_id,
            "interface_id": item.interface_id,
            "thresholds": {key: THRESHOLDS[key] for key in ("errors_per_interval", "drops_per_interval")},
            "error_pattern": classify_pattern(error_flags) if samples else "not_measured",
            "drop_pattern": classify_pattern(drop_flags) if samples else "not_measured",
            "measurements": [
                {
                    "timestamp": s.timestamp.isoformat(), "interval_seconds": s.interval_seconds,
                    "oper_status": s.oper_status.value, "in_errors": s.in_errors, "out_errors": s.out_errors,
                    "in_drops": s.in_drops, "out_drops": s.out_drops,
                    "errors_per_second": round(errors_of(s) / s.interval_seconds, 3),
                    "drops_per_second": round(drops_of(s) / s.interval_seconds, 3),
                }
                for s in samples
            ],
            "crc_errors": None,
            "related_events": [dump(event) for event in related_events],
        },
    )
    output.missing_data.append(
        "CRC counters are not part of the interface statistics dataset; CRC values appear only in related log messages"
    )
    if not samples:
        output.missing_data.append(f"No statistics are available for {item.interface_id}")
        return output
    for code, flags, label in (("HIGH_ERROR_COUNT", error_flags, "errors"), ("HIGH_DROP_COUNT", drop_flags, "drops")):
        matched = [sample for sample, flag in zip(samples, flags) if flag]
        if matched:
            output.findings.append(Finding(
                code=code, kind=FindingKind.OBSERVED, device_id=device.device_id,
                summary=f"{item.interface_id} exceeded the {label} threshold in {len(matched)} of {len(samples)} samples "
                        f"({classify_pattern(flags)} pattern, first at {matched[0].timestamp.isoformat()})",
                evidence=capped([sample_ref(sample) for sample in matched]),
            ))
    if error_flags and not error_flags[0] and any(error_flags):
        output.findings.append(Finding(
            code="ERROR_COUNT_INCREASE", kind=FindingKind.OBSERVED, device_id=device.device_id,
            summary=f"Error counts on {item.interface_id} rose above the threshold after a sample within normal range",
            evidence=capped([sample_ref(samples[0])] + [sample_ref(s) for s, f in zip(samples, error_flags) if f]),
        ))
    if related_events:
        output.findings.append(Finding(
            code="INTERFACE_EVENTS_LOGGED", kind=FindingKind.OBSERVED, device_id=device.device_id,
            summary=f"{len(related_events)} log events reference {item.interface_id}",
            evidence=event_refs(related_events),
        ))
    suspicion = physical_layer_suspicion(item, samples)
    if suspicion is not None:
        output.findings.append(suspicion)
    return output


def peer_link_states(topology: NetworkTopology, dataset: ScenarioDataset, device_id: str) -> list[dict[str, Any]]:
    states = []
    for link in topology.links:
        if device_id not in (link.a_device_id, link.b_device_id):
            continue
        local_id = link.a_interface_id if link.a_device_id == device_id else link.b_interface_id
        peer_id = peer_interface(link, local_id)
        peer_samples = samples_for(dataset, peer_id)
        latest = peer_samples[-1] if peer_samples else None
        states.append({
            "link_id": link.link_id,
            "peer_interface_id": peer_id,
            "peer_reported_status": latest.oper_status.value if latest else None,
            "peer_reported_at": latest.timestamp.isoformat() if latest else None,
            "evidence": sample_ref(latest) if latest else None,
        })
    return states


@diagnostic_tool("check_device_availability")
def check_device_availability(scenario_id: str, device_id: str) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    device = require_device(topology, device_id)
    device_samples = sorted((s for s in dataset.interface_statistics if s.device_id == device.device_id),
                            key=lambda s: (s.timestamp, s.interface_id))
    present_times = {s.timestamp for s in device_samples}
    missing_times = [moment for moment in collection_times(dataset) if moment not in present_times]
    events = sorted((e for e in dataset.events if e.device_id == device.device_id), key=lambda e: (e.timestamp, e.event_id))
    has_table = any(table.device_id == device.device_id for table in dataset.routing.routing_tables)
    routes_expected = any(
        link.routing_protocol is not None and device.device_id in (link.a_device_id, link.b_device_id)
        for link in topology.links
    )
    peer_states = peer_link_states(topology, dataset, device.device_id)
    peer_neighbors = [n for n in dataset.routing.ospf_neighbors + dataset.routing.bgp_neighbors
                      if n.neighbor_device_id == device.device_id]
    lost_adjacencies = [n for n in peer_neighbors if n.state not in (OspfState.FULL, BgpState.ESTABLISHED)]
    latest_time = max(present_times, default=None)
    latest_samples = [s for s in device_samples if s.timestamp == latest_time]
    down_interfaces = [s for s in latest_samples if s.oper_status == LinkStatus.DOWN]
    fault_events = [e for e in events if severity_rank(e.severity) <= severity_rank(FAULT_SEVERITY)]
    gap_start = next((moment for moment in missing_times if latest_time is None or moment > latest_time), None)
    critical_before_gap = [
        e for e in events
        if severity_rank(e.severity) <= severity_rank(CRITICAL_SEVERITY) and (gap_start is None or e.timestamp <= gap_start)
    ]
    peers_all_down = bool(peer_states) and all(state["peer_reported_status"] == LinkStatus.DOWN.value for state in peer_states)

    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={})
    if gap_start is None:
        status = "available_with_faults" if down_interfaces or lost_adjacencies or fault_events else "available"
    else:
        status = "unreachable" if peers_all_down else "telemetry_missing"
        output.findings.append(Finding(
            code="TELEMETRY_GAP", kind=FindingKind.OBSERVED, device_id=device.device_id,
            summary=f"No interface statistics from {device.device_id} from {gap_start.isoformat()} onwards "
                    f"(last sample {latest_time.isoformat() if latest_time else 'never'})",
            evidence=[sample_ref(sample) for sample in latest_samples[:MAX_SAMPLE_EVIDENCE]],
        ))
        if status == "telemetry_missing":
            output.warnings.append("Telemetry is missing but peers do not corroborate an outage; missing data is not proof of failure")
    if peers_all_down:
        output.findings.append(Finding(
            code="PEER_LINKS_DOWN", kind=FindingKind.OBSERVED, device_id=device.device_id,
            summary=f"All {len(peer_states)} peer interfaces facing {device.device_id} report operational status down",
            evidence=[state["evidence"] for state in peer_states if state["evidence"] is not None],
        ))
    if down_interfaces:
        output.findings.append(Finding(
            code="INTERFACES_DOWN", kind=FindingKind.OBSERVED, device_id=device.device_id,
            summary=f"{len(down_interfaces)} interfaces on {device.device_id} were down in its latest sample",
            evidence=[sample_ref(sample) for sample in down_interfaces],
        ))
    if lost_adjacencies:
        output.findings.append(Finding(
            code="PEER_ADJACENCIES_LOST", kind=FindingKind.OBSERVED, device_id=device.device_id,
            summary=f"{len(lost_adjacencies)} routing neighbors report their adjacency with {device.device_id} as not established",
            evidence=[neighbor_ref(n) for n in lost_adjacencies],
        ))
    if fault_events:
        output.findings.append(Finding(
            code="FAULT_EVENTS_LOGGED", kind=FindingKind.OBSERVED, device_id=device.device_id,
            summary=f"{device.device_id} logged {len(fault_events)} events of severity error or higher",
            evidence=event_refs(fault_events),
        ))
    if status == "unreachable":
        if critical_before_gap:
            output.findings.append(Finding(
                code="DEVICE_FAILURE_LIKELY", kind=FindingKind.INFERRED, device_id=device.device_id,
                summary=f"{device.device_id} logged critical events before its telemetry stopped and all peers report "
                        "their links to it down; a device failure is likely",
                evidence=event_refs(critical_before_gap),
            ))
        else:
            output.warnings.append("Peers report the device unreachable; the cause is not determined by available evidence")
    if routes_expected and not has_table:
        output.missing_data.append(f"No routing table was collected from {device.device_id}")
    output.data = {
        "device_id": device.device_id,
        "site_id": device.site_id,
        "status": status,
        "telemetry": {
            "collection_times": [moment.isoformat() for moment in collection_times(dataset)],
            "missing_collection_times": [moment.isoformat() for moment in missing_times],
            "last_statistics_at": latest_time.isoformat() if latest_time else None,
            "last_log_at": events[-1].timestamp.isoformat() if events else None,
            "routing_table_collected": has_table if routes_expected else None,
        },
        "peer_links": [{key: value for key, value in state.items() if key != "evidence"} for state in peer_states],
        "peer_reported_adjacencies": [
            {"reporting_device_id": n.device_id, "state": n.state.value, "failure_reason": n.failure_reason,
             "last_state_change": n.last_state_change.isoformat()}
            for n in peer_neighbors
        ],
        "latest_interface_status": {s.interface_id: s.oper_status.value for s in latest_samples},
    }
    return output
