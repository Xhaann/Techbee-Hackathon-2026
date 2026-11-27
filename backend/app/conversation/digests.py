"""Short, factual digests of tool results for conversational replies.

A digest restates a few fields of a validated ToolResult in plain language. It never passes raw tool output through,
and every string is redacted and length-limited.
"""
from typing import Any

from app.engine.executor import ToolCallRecord
from app.security.secrets import redact

MAX_DIGEST_CHARS = 420


def plural(count: int, word: str, many: str | None = None) -> str:
    return f"{count} {word if count == 1 else many or word + 's'}"


def counts(mapping: dict[str, Any] | None) -> str:
    if not mapping:
        return "none"
    return ", ".join(f"{value} {key}" for key, value in sorted(mapping.items(), key=lambda item: -int(item[1] or 0)))


def routing(data: dict) -> str:
    table = data.get("routing_table") or {}
    parts = [f"{plural(table.get('route_count', 0), 'route')} in the table ({counts(table.get('protocol_counts'))})"]
    routes = table.get("routes") or []
    if routes and not any(route.get("prefix") == "0.0.0.0/0" for route in routes):
        parts.append("no default route")
    best = data.get("best_match")
    if best:
        parts.append(f"best match {best.get('prefix')} via {best.get('next_hop') or best.get('interface_id')}")
    bgp = data.get("bgp_neighbors") or []
    if bgp:
        parts.append("BGP " + "; ".join(f"{n.get('neighbor_device_id') or n.get('neighbor_ip')} {n.get('state')}" for n in bgp[:3]))
    ospf = data.get("ospf_neighbors") or []
    if ospf:
        parts.append("OSPF " + "; ".join(f"{n.get('neighbor_device_id') or n.get('neighbor_ip')} {n.get('state')}" for n in ospf[:3]))
    changes = data.get("route_changes") or []
    if changes:
        parts.append(f"{plural(len(changes), 'route change')} recorded")
    return "; ".join(parts)


def adjacency(data: dict) -> str:
    return f"adjacencies by state: {counts(data.get('adjacency_counts'))}"


def availability(data: dict) -> str:
    telemetry = data.get("telemetry") or {}
    last = telemetry.get("last_statistics_at")
    return f"availability is {data.get('status', 'unknown')}" + (f" (last statistics {last})" if last else "")


def interface_stats(data: dict) -> str:
    interfaces = data.get("interfaces") or []
    names = [item.get("interface", {}).get("name") for item in interfaces][:6]
    return f"{plural(len(interfaces), 'interface')} sampled" + (f" ({', '.join(n for n in names if n)})" if names else "")


def packet_loss(data: dict) -> str:
    text = f"loss pattern is {data.get('pattern', 'unknown')} against a {data.get('threshold_percent')}% threshold"
    if data.get("outage_sample_count"):
        text += f"; {plural(int(data['outage_sample_count']), 'outage sample')}"
    return text


def interface_errors(data: dict) -> str:
    return f"error pattern is {data.get('pattern', 'unknown')}"


def logs(data: dict) -> str:
    return f"{plural(int(data.get('total_matched') or 0), 'log event')} ({counts(data.get('severity_counts'))})"


def firewall(data: dict) -> str:
    actions = data.get("action_counts") or {}
    return f"{plural(int(data.get('total_matched') or 0), 'firewall event')}: {actions.get('allow', 0)} allowed, {actions.get('deny', 0)} denied"


def dhcp_dns(data: dict) -> str:
    dhcp = (data.get("dhcp") or {}).get("status", "unknown")
    dns = data.get("dns") or {}
    return f"DHCP {dhcp}; DNS {dns.get('status', 'unknown')} ({counts(dns.get('result_counts'))} across {plural(int(dns.get('query_count') or 0), 'query', 'queries')})"


def topology(data: dict) -> str:
    devices = data.get("devices") or []
    site = (data.get("site") or {}).get("name", "the site")
    return f"{site} has {plural(len(devices), 'device')} ({', '.join(d.get('device_id', '') for d in devices[:6])}), " \
           f"{plural(len(data.get('links') or []), 'link')} and {plural(len(data.get('paths') or []), 'service path')}"


def dependencies(data: dict) -> str:
    common = data.get("common_to_all_paths_in_scope") or []
    shared = data.get("shared_devices") or []
    text = f"{plural(len(data.get('path_ids_in_scope') or []), 'service path')} in scope"
    if common:
        text += f"; every path depends on {', '.join(common[:6])}"
    if shared:
        text += f"; {plural(len(shared), 'device')} shared with other sites"
    return text


def reachability(data: dict) -> str:
    source = (data.get("source") or {}).get("input")
    destination = (data.get("destination") or {}).get("input")
    text = f"path {source} -> {destination} is {data.get('status', 'unknown')}"
    failure = data.get("failure_point")
    if failure:
        text += f", failing at {failure.get('device_id')} ({failure.get('reason')})"
    return text


def path_health(data: dict) -> str:
    segments = data["segments"]
    unhealthy = [f"{s['link_id']} {s['state']}" for s in segments if s["state"] != "healthy"]
    return (f"{plural(len(segments), 'link')} on the {data['reachability']} path; "
            + (", ".join(unhealthy) if unhealthy else "all healthy"))


def timeline(data: dict) -> str:
    intervals = data["intervals"]
    recovered = [i for i in intervals if i["status"] == "recovered"]
    ongoing = [i for i in intervals if i["status"] == "ongoing"]
    parts = [f"{plural(data['events_total'], 'event')} in the window"]
    if recovered:
        parts.append(f"{plural(len(recovered), 'outage')} that recovered")
    if ongoing:
        parts.append(f"{plural(len(ongoing), 'outage')} still open")
    if not intervals:
        parts.append("no outages logged")
    return "; ".join(parts)


def changes(data: dict) -> str:
    items = data["changes"]
    if not items:
        return "no configuration, policy or rule changes recorded"
    devices = sorted({c["device_id"] for c in items})
    return f"{plural(data['total'], 'change')} on {', '.join(devices[:4])}" + (f" and {len(devices) - 4} more" if len(devices) > 4 else "")


def health_scores(data: dict) -> str:
    network = data["network"]
    weak = [f"{s['site_id']} {s['score']:g}" for s in data["sites"] if s["status"] != "healthy"]
    return f"network {network['score']:g}/100 ({network['status']})" + (f"; weakest: {', '.join(weak[:4])}" if weak else "; every site healthy")


def drift(data: dict) -> str:
    summary = data["summary"]
    if not summary["items"]:
        return f"no drift on {plural(summary['devices'], 'device')}" + (f"; {plural(len(data['notes']), 'unverified change')}" if data["notes"] else "")
    devices = sorted({d["device_id"] for d in data["drift"]})
    return f"{plural(summary['items'], 'line')} differ from the golden config on {', '.join(devices[:4])}"


def traffic(data: dict) -> str:
    totals = data["totals"]
    parts = [f"{plural(totals['flows'], 'flow')}"]
    if totals["dropped_flows"]:
        parts.append(f"{totals['dropped_flows']} dropped by policy")
    if data["traffic_shifts"]:
        parts.append("traffic stopped for " + ", ".join(f"{s['site_id']} {s['service']}" for s in data["traffic_shifts"][:3]))
    return "; ".join(parts)


def journey(data: dict) -> str:
    request = data["request"]
    return (f"{request['protocol']}/{request['port'] or 'any'} {data['source']['address']} -> {data['destination']['address']}: "
            f"{data['verdict'].replace('_', ' ')} at hop {data['verdict_hop']} of {len(data['hops'])}, {data['total_latency_ms']:g} ms")


def capacity(data: dict) -> str:
    risky = [f"{l['link_id']} {l['level']}" for l in data["links"] if l["level"] in ("high", "medium")]
    return f"{plural(len(data['links']), 'link')} forecast; " + (", ".join(risky[:4]) if risky else "no congestion risk")


def protocol(data: dict) -> str:
    words = {"confirmed_fault": "confirmed", "suspicious_indicator": "suspicious", "possible_explanation": "possible",
             "insufficient_evidence": "not enough data"}
    findings = [f for f in data["findings"] if f["status"] != "insufficient_evidence"]
    if not findings:
        return f"{data['title']}: nothing wrong found" if data["status"] == "healthy" else f"{data['title']}: {data['status']}"
    lead = findings[0]
    more = f" (+{len(findings) - 1} more)" if len(findings) > 1 else ""
    return f"{data['title']}: {lead['title']} ({words[lead['status']]}){more}"


DIGESTS = {"get_network_health": health_scores, "analyze_protocol": protocol, "get_config_drift": drift, "analyze_traffic_flows": traffic,
           "trace_packet": journey, "forecast_capacity": capacity, "analyze_path_health": path_health, "get_event_timeline": timeline, "get_change_history": changes,
           "get_routing_state": routing, "analyze_routing_adjacency": adjacency, "check_device_availability": availability,
           "get_interface_stats": interface_stats, "analyze_packet_loss": packet_loss, "analyze_interface_errors": interface_errors,
           "get_device_logs": logs, "get_firewall_logs": firewall, "get_dhcp_dns_status": dhcp_dns, "get_topology": topology,
           "analyze_network_dependencies": dependencies, "check_network_reachability": reachability}


def digest(record: ToolCallRecord) -> str:
    if record.status == "duplicate":
        return f"Skipped: identical to {record.duplicate_of}"
    if not record.succeeded:
        reason = record.error or record.error_code or "the call did not complete"
        return redact(f"Did not complete ({record.error_code}): {reason}")[:MAX_DIGEST_CHARS]
    try:
        text = DIGESTS[record.tool](record.result.data)
    except Exception:
        text = "completed"
    if record.result.missing_data:
        text += f"; {plural(len(record.result.missing_data), 'gap')} in the data (e.g. {record.result.missing_data[0][:120]})"
    return redact(text)[:MAX_DIGEST_CHARS]
