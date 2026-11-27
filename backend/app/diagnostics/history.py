"""Time-aware diagnostics: state changes over the window and configuration changes, not just the latest snapshot."""
import re
from collections import Counter
from datetime import datetime
from typing import Any

from app.diagnostics.common import (
    DEFAULT_RECORDS,
    EvidenceRef,
    Finding,
    FindingKind,
    ToolOutput,
    capped,
    diagnostic_tool,
    dump,
    evidence,
    invalid,
    link_by_interface,
    load_dataset,
    parse_limit,
    parse_time_range,
    require_device,
    require_site,
)
from app.network.models import DhcpEventType, NetworkEvent, NetworkTopology, ScenarioDataset

# A "down" event and the event that ends it, keyed by what pairs them (the interface, or the device for sessions).
STATE_PAIRS = {
    "LINK_DOWN": ("link", "LINK_UP", "interface"), "CARRIER_LOSS": ("link", "LINK_UP", "interface"),
    "BGP_NEIGHBOR_DOWN": ("bgp_session", "BGP_NEIGHBOR_UP", "device"),
    "OSPF_ADJACENCY_DOWN": ("ospf_adjacency", "OSPF_ADJACENCY_UP", "device"),
    "WAN_PROBE_FAILURE": ("wan_probe", "WAN_PROBE_RECOVERED", "interface"),
    "RADIUS_SERVER_DEAD": ("radius_server", "RADIUS_SERVER_ALIVE", "device"),
    "ZONE_EXPIRED": ("dns_zone", "ZONE_LOADED", "device"), "ZONE_LOAD_FAILURE": ("dns_zone", "ZONE_LOADED", "device"),
}
CHANGE_TYPES = {"CONFIG_CHANGE": "configuration", "CONFIG_COMMAND_LOGGED": "configuration", "MTU_CHANGE": "mtu",
                "POLICY_CHANGE": "policy", "ZONE_RELOAD": "dns_zone"}
CHANGE_CODES = {"configuration": "CONFIG_CHANGED", "mtu": "MTU_CHANGED", "policy": "POLICY_CHANGED", "dns_zone": "ZONE_RELOADED"}
INSTABILITY_EVENTS = {"OPTICAL_RX_LOW", "INTERFACE_ERRORS", "CARRIER_LOSS"}
COMMAND = re.compile(r"User:(?P<user>[\w.@-]+) logged command:(?:interface (?P<interface>\S+) ; )?(?P<command>.+)$")
ACTOR = re.compile(r"(?:by|User:|user: )\s*'?(?P<user>[\w.@-]+)'?", re.IGNORECASE)
HELPER_REMOVED = re.compile(r"^no ip helper-address (?P<address>\d{1,3}(?:\.\d{1,3}){3})$")


def event_ref(event: NetworkEvent) -> EvidenceRef:
    return evidence("events", event.event_id, event.timestamp)


def scope_devices(topology: NetworkTopology, device_id: Any, site_id: Any, required: bool) -> tuple[list[str], dict[str, Any]]:
    if device_id is None and site_id is None:
        if required:
            raise invalid("At least one of device_id or site_id is required")
        return sorted(d.device_id for d in topology.devices), {"device_id": None, "site_id": None}
    if device_id is not None:
        device = require_device(topology, device_id)
        return [device.device_id], {"device_id": device.device_id, "site_id": device.site_id}
    site = require_site(topology, site_id)
    return sorted(d.device_id for d in topology.devices if d.site_id == site.site_id), {"device_id": None, "site_id": site.site_id}


def span(start: datetime, end: datetime) -> str:
    seconds = int((end - start).total_seconds())
    return f"{seconds // 60} min {seconds % 60} s" if seconds >= 60 else f"{seconds} s"


@diagnostic_tool("get_event_timeline")
def get_event_timeline(scenario_id: str, device_id: Any = None, site_id: Any = None, start: Any = None, end: Any = None,
                       limit: Any = DEFAULT_RECORDS) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    devices, scope = scope_devices(topology, device_id, site_id, required=True)
    range_start, range_end = parse_time_range(dataset, start, end)
    limit = parse_limit(limit)
    in_scope = set(devices)
    events = sorted((e for e in dataset.events if e.device_id in in_scope and range_start <= e.timestamp <= range_end),
                    key=lambda e: (e.timestamp, e.event_id))
    links = link_by_interface(topology)
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={},
                        warnings=["Intervals are built from logged state changes; an outage that logged nothing is not visible"])
    intervals: list[dict[str, Any]] = []
    open_states: dict[tuple[str, str], tuple[str, NetworkEvent, list[NetworkEvent]]] = {}
    def key_of(event: NetworkEvent, kind: str, scope_key: str) -> tuple[str, str]:
        return kind, (event.interface_id if scope_key == "interface" else event.device_id) or event.device_id

    for event in events:
        if event.event_type in STATE_PAIRS:
            kind, _, scope_key = STATE_PAIRS[event.event_type]
            key = key_of(event, kind, scope_key)
            if key in open_states:
                open_states[key][2].append(event)
            else:
                open_states[key] = (kind, event, [event])
            continue
        for down_type, (kind, up_type, scope_key) in STATE_PAIRS.items():
            if event.event_type == up_type and key_of(event, kind, scope_key) in open_states:
                kind, first, related = open_states.pop(key_of(event, kind, scope_key))
                intervals.append({"kind": kind, "first": first, "related": related, "end": event})
                break
    for kind, first, related in open_states.values():
        intervals.append({"kind": kind, "first": first, "related": related, "end": None})
    intervals.sort(key=lambda item: (item["first"].timestamp, item["first"].event_id))

    rendered = []
    for item in intervals:
        first, finish = item["first"], item["end"]
        link = links.get(first.interface_id) if first.interface_id else None
        refs = [event_ref(e) for e in item["related"]] + ([event_ref(finish)] if finish else [])
        target = f"{first.device_id} {first.interface_id.split(':', 1)[1]}" if first.interface_id else first.device_id
        label = {"link": f"Link {link.link_id} ({target})" if link else f"Interface {target}",
                 "bgp_session": f"BGP session on {first.device_id}", "ospf_adjacency": f"OSPF adjacency on {first.device_id}",
                 "wan_probe": f"WAN reachability probe on {target}", "radius_server": f"RADIUS server seen from {first.device_id}",
                 "dns_zone": f"DNS zone on {first.device_id}"}[item["kind"]]
        rendered.append({
            "kind": item["kind"], "device_id": first.device_id, "interface_id": first.interface_id,
            "link_id": link.link_id if link else None, "link_type": link.link_type.value if link else None,
            "started_at": first.timestamp.isoformat(), "ended_at": finish.timestamp.isoformat() if finish else None,
            "duration_seconds": int((finish.timestamp - first.timestamp).total_seconds()) if finish else None,
            "status": "recovered" if finish else "ongoing", "events": [e.event_id for e in item["related"]] + ([finish.event_id] if finish else []),
        })
        code_base = {"link": "LINK", "bgp_session": "ADJACENCY", "ospf_adjacency": "ADJACENCY", "wan_probe": "PROBE",
                     "radius_server": "SERVICE", "dns_zone": "SERVICE"}[item["kind"]]
        if finish:
            output.findings.append(Finding(
                code=f"{code_base}_FLAP_RECOVERED", kind=FindingKind.OBSERVED, device_id=first.device_id,
                summary=f"{label} went down at {first.timestamp.strftime('%H:%M:%S')} and recovered at "
                        f"{finish.timestamp.strftime('%H:%M:%S')} UTC ({span(first.timestamp, finish.timestamp)})",
                evidence=capped(refs)))
        else:
            output.findings.append(Finding(
                code=f"{code_base}_DOWN_ONGOING", kind=FindingKind.OBSERVED, device_id=first.device_id,
                summary=f"{label} went down at {first.timestamp.strftime('%H:%M:%S')} UTC and no recovery was logged by "
                        f"{range_end.strftime('%H:%M')} UTC",
                evidence=capped(refs)))
        if item["kind"] == "link" and finish and first.interface_id:
            unstable = [e for e in dataset.events if e.interface_id == first.interface_id and e.event_type in INSTABILITY_EVENTS
                        and e.event_id not in {r.event_id for r in item["related"]}]
            if unstable:
                output.findings.append(Finding(
                    code="INTERMITTENT_FAULT_SUSPECTED", kind=FindingKind.INFERRED, device_id=first.device_id,
                    summary=f"{label} recovered on its own but also logged {', '.join(sorted({e.event_type for e in unstable}))}; "
                            "physical-layer instability on this circuit may recur",
                    evidence=capped([event_ref(e) for e in unstable] + refs)))

    changes = sorted((c for c in dataset.routing.route_changes if c.device_id in in_scope and range_start <= c.timestamp <= range_end),
                     key=lambda c: (c.timestamp, c.change_id))
    withdrawn = {(c.device_id, str(c.prefix)): c for c in changes if c.change_type.value == "withdrawn"}
    restored = [c for c in changes if c.change_type.value == "added" and (c.device_id, str(c.prefix)) in withdrawn
                and c.timestamp > withdrawn[(c.device_id, str(c.prefix))].timestamp]
    if restored:
        first_withdrawal = min(withdrawn[(c.device_id, str(c.prefix))].timestamp for c in restored)
        output.findings.append(Finding(
            code="ROUTES_WITHDRAWN_AND_RESTORED", kind=FindingKind.OBSERVED, device_id=restored[0].device_id,
            summary=f"{len(restored)} routes on {', '.join(sorted({c.device_id for c in restored}))} were withdrawn from "
                    f"{first_withdrawal.strftime('%H:%M:%S')} and re-learned by {max(c.timestamp for c in restored).strftime('%H:%M:%S')} UTC",
            evidence=capped([evidence("route_changes", withdrawn[(c.device_id, str(c.prefix))].change_id,
                                      withdrawn[(c.device_id, str(c.prefix))].timestamp) for c in restored]
                            + [evidence("route_changes", c.change_id, c.timestamp) for c in restored])))
    output.data = {
        **scope, "devices": devices,
        "time_range": {"start": range_start.isoformat(), "end": range_end.isoformat()},
        "intervals": rendered,
        "route_changes": dict(Counter(c.change_type.value for c in changes)),
        "events": [dump(e) for e in events[:limit]], "events_total": len(events), "truncated": len(events) > limit,
    }
    if not events:
        output.missing_data.append("No log events were recorded for the scope in this time range")
    return output


def gateway_vlan(topology: NetworkTopology, interface_id: str):
    return next((vlan for vlan in topology.vlans if vlan.gateway_interface_id == interface_id), None)


def relay_findings(topology: NetworkTopology, dataset: ScenarioDataset, event: NetworkEvent, address: str,
                   interface_id: str) -> list[Finding]:
    vlan = gateway_vlan(topology, interface_id)
    if vlan is None:
        return []
    pool = next((p for p in dataset.dhcp.pools if p.site_id == vlan.site_id and p.vlan_id == vlan.vlan_id), None)
    server = next((d for d in topology.devices if str(d.management_ip) == address), None)
    serves_pool = pool is not None and server is not None and server.device_id == pool.server_device_id
    where = f"{event.device_id} {interface_id.split(':', 1)[1]}, the gateway of VLAN {vlan.vlan_id} at {vlan.site_id}"
    findings = [Finding(
        code="DHCP_RELAY_TO_SERVER_REMOVED" if serves_pool else "DHCP_HELPER_REMOVED", kind=FindingKind.OBSERVED,
        device_id=event.device_id,
        summary=f"ip helper-address {address}" + (f" ({server.device_id})" if server else "") + f" was removed from {where}"
                + (f" (pool {pool.pool_id})" if pool else "") + f" at {event.timestamp.strftime('%H:%M:%S')} UTC"
                + ("" if serves_pool else "; it is not the address of the pool's DHCP server"),
        evidence=[event_ref(event)])]
    if serves_pool:
        pool_events = [e for e in dataset.dhcp.events if e.pool_id == pool.pool_id]
        after = [e for e in pool_events if e.timestamp > event.timestamp]
        before = [e for e in pool_events if e.timestamp <= event.timestamp and e.event_type == DhcpEventType.ALLOCATION_SUCCESS]
        served_others = any(e.pool_id != pool.pool_id and e.timestamp > event.timestamp for e in dataset.dhcp.events
                            if e.server_device_id == pool.server_device_id)
        if not after and served_others:
            refs = [event_ref(event)] + ([evidence("dhcp_events", before[-1].event_id, before[-1].timestamp)] if before else [])
            findings.append(Finding(
                code="DHCP_RELAY_FAILURE_SUSPECTED", kind=FindingKind.INFERRED, device_id=event.device_id,
                summary=f"After the helper was removed, pool {pool.pool_id} received no DHCP requests while "
                        f"{pool.server_device_id} kept serving other pools; clients on VLAN {vlan.vlan_id} at {vlan.site_id} "
                        "can no longer reach the DHCP server through the relay",
                evidence=refs))
    return findings


@diagnostic_tool("get_change_history")
def get_change_history(scenario_id: str, device_id: Any = None, site_id: Any = None, start: Any = None, end: Any = None,
                       limit: Any = DEFAULT_RECORDS) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    devices, scope = scope_devices(topology, device_id, site_id, required=False)
    range_start, range_end = parse_time_range(dataset, start, end)
    limit = parse_limit(limit)
    in_scope = set(devices)
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={},
                        warnings=["Changes come from device change logs and firewall rule history; unlogged changes are not visible"])
    changes: list[dict[str, Any]] = []
    by_device: dict[tuple[str, str], list[NetworkEvent]] = {}
    for event in sorted(dataset.events, key=lambda e: (e.timestamp, e.event_id)):
        if event.event_type not in CHANGE_TYPES or event.device_id not in in_scope or not range_start <= event.timestamp <= range_end:
            continue
        category = CHANGE_TYPES[event.event_type]
        parsed = COMMAND.search(event.message) if event.event_type == "CONFIG_COMMAND_LOGGED" else None
        actor = parsed.group("user") if parsed else (m.group("user") if (m := ACTOR.search(event.message)) else None)
        interface_id = (f"{event.device_id}:{parsed.group('interface')}" if parsed and parsed.group("interface")
                        else event.interface_id)
        command = parsed.group("command").strip() if parsed else None
        changes.append({"change_id": event.event_id, "source": "device_change_log", "category": category,
                        "timestamp": event.timestamp.isoformat(), "device_id": event.device_id, "interface_id": interface_id,
                        "user": actor, "command": command, "description": event.message[:200]})
        by_device.setdefault((event.device_id, category), []).append(event)
        helper = HELPER_REMOVED.match(command) if command else None
        if helper and interface_id:
            output.findings += relay_findings(topology, dataset, event, helper.group("address"), interface_id)
    for rule in sorted(dataset.firewall.rules, key=lambda r: (r.last_modified, r.rule_id)):
        if rule.device_id in in_scope and range_start <= rule.last_modified <= range_end:
            changes.append({"change_id": rule.rule_id, "source": "firewall_rule_history", "category": "firewall_rule",
                            "timestamp": rule.last_modified.isoformat(), "device_id": rule.device_id, "interface_id": None,
                            "user": None, "command": None,
                            "description": f"Rule {rule.rule_id} ({rule.name}, {rule.action.value}, priority {rule.priority}) modified"})
            output.findings.append(Finding(
                code="FIREWALL_RULE_MODIFIED", kind=FindingKind.OBSERVED, device_id=rule.device_id,
                summary=f"Rule {rule.rule_id} ({rule.name}, {rule.action.value} {rule.source} -> {rule.destination}"
                        + (f" port {rule.destination_port}" if rule.destination_port else "")
                        + f", priority {rule.priority}) on {rule.device_id} was modified at "
                          f"{rule.last_modified.strftime('%H:%M:%S')} UTC",
                evidence=[evidence("firewall_rules", rule.rule_id, rule.last_modified)]))
    for (device, category), events in by_device.items():
        users = sorted({c["user"] for c in changes if c["device_id"] == device and c["category"] == category and c["user"]})
        commands = [c["command"] for c in changes if c["device_id"] == device and c["category"] == category and c["command"]]
        output.findings.append(Finding(
            code=CHANGE_CODES[category], kind=FindingKind.OBSERVED, device_id=device,
            summary=f"{len(events)} {category.replace('_', ' ')} change record(s) on {device} between "
                    f"{events[0].timestamp.strftime('%H:%M:%S')} and {events[-1].timestamp.strftime('%H:%M:%S')} UTC"
                    + (f" by {', '.join(users)}" if users else "")
                    + (f" (commands: {'; '.join(commands[:4])})" if commands else ""),
            evidence=capped([event_ref(e) for e in events])))
    changes.sort(key=lambda c: (c["timestamp"], c["change_id"]))
    output.data = {**scope, "time_range": {"start": range_start.isoformat(), "end": range_end.isoformat()},
                   "total": len(changes), "returned": min(len(changes), limit), "truncated": len(changes) > limit,
                   "changes": changes[:limit]}
    if not changes:
        output.missing_data.append("No configuration, policy or rule changes were recorded for the scope in this time range")
    return output
