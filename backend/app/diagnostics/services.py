from collections import Counter
from datetime import timedelta
from statistics import mean
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
    load_dataset,
    parse_limit,
    parse_network,
    parse_time_range,
    require_site,
)
from app.network.models import DhcpEventType, DnsQuery, DnsResult, FirewallAction, LeaseState

HIGH_POOL_UTILIZATION_PERCENT = 90.0
DHCP_SILENCE = timedelta(minutes=10)
DNS_FAILURE_RESULTS = (DnsResult.SERVFAIL, DnsResult.REFUSED, DnsResult.TIMEOUT)


@diagnostic_tool("get_firewall_logs")
def get_firewall_logs(scenario_id: str, source: Any = None, destination: Any = None, start: Any = None,
                      end: Any = None, action: Any = None, limit: Any = DEFAULT_RECORDS) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    source_network = parse_network(source, "source")
    destination_network = parse_network(destination, "destination")
    if source_network is None and destination_network is None:
        raise invalid("At least one of source or destination is required")
    range_start, range_end = parse_time_range(dataset, start, end)
    try:
        action_filter = FirewallAction(action) if action is not None else None
    except ValueError:
        raise invalid("action must be 'allow' or 'deny'") from None
    limit = parse_limit(limit)
    rules = {rule.rule_id: rule for rule in dataset.firewall.rules}
    matched = sorted(
        (
            event for event in dataset.firewall.events
            if range_start <= event.timestamp <= range_end
            and (source_network is None or event.source_ip in source_network)
            and (destination_network is None or event.destination_ip in destination_network)
            and (action_filter is None or event.action == action_filter)
        ),
        key=lambda event: (event.timestamp, event.event_id),
    )
    records = matched[:limit]
    counts = Counter(event.action.value for event in matched)
    output = ToolOutput(
        scenario_id=dataset.scenario.scenario_id,
        data={
            "source": str(source_network) if source_network else None,
            "destination": str(destination_network) if destination_network else None,
            "time_range": {"start": range_start.isoformat(), "end": range_end.isoformat()},
            "action": action_filter.value if action_filter else None,
            "total_matched": len(matched),
            "returned": len(records),
            "truncated": len(matched) > limit,
            "action_counts": {item.value: counts[item.value] for item in FirewallAction},
            "rule_counts": dict(sorted(Counter(event.rule_id for event in matched).items())),
            "rules": [dump(rules[rule_id]) for rule_id in sorted({event.rule_id for event in matched})],
            "records": [dump(event) for event in records],
        },
    )
    if not matched:
        output.warnings.append("No firewall events matched the requested addresses, time range and action")
    if len(matched) > limit:
        output.warnings.append(f"Result truncated to {limit} of {len(matched)} matching events")
    for rule_id in sorted({event.rule_id for event in matched if event.action == FirewallAction.DENY}):
        denied = [event for event in matched if event.rule_id == rule_id]
        rule = rules[rule_id]
        output.findings.append(Finding(
            code="TRAFFIC_DENIED", kind=FindingKind.OBSERVED, device_id=rule.device_id,
            summary=f"{len(denied)} flows denied by rule {rule_id} ({rule.name}) on {rule.device_id} between "
                    f"{denied[0].timestamp.isoformat()} and {denied[-1].timestamp.isoformat()}",
            evidence=capped([evidence("firewall_events", e.event_id, e.timestamp) for e in denied]),
        ))
        if range_start <= rule.last_modified <= range_end:
            output.findings.append(Finding(
                code="RULE_MODIFIED_IN_RANGE", kind=FindingKind.OBSERVED, device_id=rule.device_id,
                summary=f"Rule {rule_id} ({rule.name}) was last modified at {rule.last_modified.isoformat()}, "
                        "inside the queried time range",
                evidence=[evidence("firewall_rules", rule_id, rule.last_modified)],
            ))
    return output


def query_ref(query: DnsQuery) -> EvidenceRef:
    return evidence("dns_queries", query.query_id, query.timestamp)


def response_stats(queries: list[DnsQuery]) -> dict[str, Any] | None:
    times = [query.response_time_ms for query in queries if query.response_time_ms is not None]
    if not times:
        return None
    return {"count": len(times), "min_ms": min(times), "max_ms": max(times), "mean_ms": round(mean(times), 2)}


@diagnostic_tool("get_dhcp_dns_status")
def get_dhcp_dns_status(scenario_id: str, site_id: str) -> ToolOutput:
    topology, dataset = load_dataset(scenario_id)
    site = require_site(topology, site_id)
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={})
    pools = [pool for pool in dataset.dhcp.pools if pool.site_id == site.site_id]
    server_activity = {}
    for event in dataset.dhcp.events:
        if event.event_type == DhcpEventType.ALLOCATION_SUCCESS:
            latest = server_activity.get(event.server_device_id)
            server_activity[event.server_device_id] = event.timestamp if latest is None else max(latest, event.timestamp)
    pool_entries = []
    for pool in pools:
        leases = [lease for lease in dataset.dhcp.leases if lease.pool_id == pool.pool_id]
        states = Counter(lease.state for lease in leases)
        in_use = states[LeaseState.ACTIVE] + states[LeaseState.CONFLICT]
        utilization = round(in_use / pool.size * 100, 2)
        events = sorted((e for e in dataset.dhcp.events if e.pool_id == pool.pool_id), key=lambda e: (e.timestamp, e.event_id))
        by_type = {event_type: [e for e in events if e.event_type == event_type] for event_type in DhcpEventType}
        successes = by_type[DhcpEventType.ALLOCATION_SUCCESS]
        status = "exhausted" if in_use >= pool.size else "high_utilization" if utilization >= HIGH_POOL_UTILIZATION_PERCENT else "ok"
        server_latest = server_activity.get(pool.server_device_id)
        stopped = bool(successes) and server_latest - successes[-1].timestamp > DHCP_SILENCE
        pool_entries.append({
            "pool": dump(pool),
            "size": pool.size,
            "lease_counts": {state.value: states[state] for state in LeaseState},
            "addresses_in_use": in_use,
            "addresses_available": pool.size - in_use,
            "utilization_percent": utilization,
            "status": status,
            "conflict_leases": [dump(lease) for lease in leases if lease.state == LeaseState.CONFLICT],
            "event_counts": {event_type.value: len(items) for event_type, items in by_type.items()},
            "last_successful_allocation_at": successes[-1].timestamp.isoformat() if successes else None,
            "server_last_successful_allocation_at": server_latest.isoformat() if server_latest else None,
            "transactions_stopped": stopped,
            "events": [dump(event) for event in events if event.event_type != DhcpEventType.ALLOCATION_SUCCESS],
        })
        if status == "exhausted":
            output.findings.append(Finding(
                code="DHCP_POOL_EXHAUSTED", kind=FindingKind.OBSERVED, device_id=pool.server_device_id,
                summary=f"Pool {pool.pool_id} has {in_use} of {pool.size} addresses in use "
                        f"({states[LeaseState.CONFLICT]} in conflict state)",
                evidence=capped([evidence("dhcp_events", e.event_id, e.timestamp) for e in by_type[DhcpEventType.POOL_EXHAUSTED]]
                                + [evidence("dhcp_leases", f"{pool.pool_id}:{lease.ip_address}") for lease in leases
                                   if lease.state == LeaseState.CONFLICT]),
            ))
        elif status == "high_utilization":
            output.findings.append(Finding(
                code="DHCP_POOL_HIGH_UTILIZATION", kind=FindingKind.OBSERVED, device_id=pool.server_device_id,
                summary=f"Pool {pool.pool_id} utilization is {utilization}%", evidence=[],
            ))
        for event_type, code in ((DhcpEventType.ALLOCATION_FAILURE, "DHCP_ALLOCATION_FAILURES"),
                                 (DhcpEventType.IP_CONFLICT, "DHCP_IP_CONFLICTS")):
            items = by_type[event_type]
            if items:
                output.findings.append(Finding(
                    code=code, kind=FindingKind.OBSERVED, device_id=pool.server_device_id,
                    summary=f"{len(items)} {event_type.value.replace('_', ' ')} events for pool {pool.pool_id} "
                            f"between {items[0].timestamp.isoformat()} and {items[-1].timestamp.isoformat()}",
                    evidence=capped([evidence("dhcp_events", e.event_id, e.timestamp) for e in items]),
                ))
        if stopped:
            output.findings.append(Finding(
                code="DHCP_TRANSACTIONS_STOPPED", kind=FindingKind.OBSERVED, device_id=None,
                summary=f"No successful allocations for pool {pool.pool_id} after {successes[-1].timestamp.isoformat()} "
                        f"while {pool.server_device_id} kept serving other pools until {server_latest.isoformat()}",
                evidence=[evidence("dhcp_events", successes[-1].event_id, successes[-1].timestamp)],
            ))
        if not events:
            output.missing_data.append(f"No DHCP transactions were observed for pool {pool.pool_id}")
    if not pools:
        output.missing_data.append(f"No DHCP pools are defined for site {site.site_id}")

    subnets = [vlan.subnet for vlan in topology.vlans if vlan.site_id == site.site_id]
    queries = sorted((q for q in dataset.dns.queries if any(q.client_ip in subnet for subnet in subnets)),
                     key=lambda q: (q.timestamp, q.query_id))
    server_entries = []
    for server in dataset.dns.servers:
        served = [q for q in queries if q.server_ip == server.ip_address]
        results = Counter(q.result for q in served)
        server_entries.append({
            "server": dump(server),
            "query_count": len(served),
            "result_counts": {result.value: results[result] for result in DnsResult if results[result]},
            "response_time": response_stats(served),
        })
        for result, code in ((DnsResult.SERVFAIL, "DNS_SERVFAIL"), (DnsResult.TIMEOUT, "DNS_TIMEOUTS"),
                             (DnsResult.REFUSED, "DNS_REFUSED")):
            failed = [q for q in served if q.result == result]
            if failed:
                output.findings.append(Finding(
                    code=code, kind=FindingKind.OBSERVED,
                    device_id=None if result == DnsResult.TIMEOUT else server.device_id,
                    summary=f"{len(failed)} queries from {site.site_id} to {server.device_id} returned {result.value} "
                            f"between {failed[0].timestamp.isoformat()} and {failed[-1].timestamp.isoformat()} "
                            f"(domains: {', '.join(sorted({q.domain for q in failed}))})",
                    evidence=capped([query_ref(q) for q in failed]),
                ))
    servfail_servers = sorted({e["server"]["device_id"] for e in server_entries if e["result_counts"].get("servfail")})
    answering_servers = sorted({e["server"]["device_id"] for e in server_entries if e["result_counts"].get("noerror")})
    for server_id in servfail_servers:
        others = [other for other in answering_servers if other != server_id]
        if others:
            output.findings.append(Finding(
                code="DNS_SERVER_RESOLUTION_FAULT_SUSPECTED", kind=FindingKind.INFERRED, device_id=server_id,
                summary=f"SERVFAIL responses come from {server_id} while {', '.join(others)} answered queries "
                        "successfully; a server-side resolution fault is suspected",
                evidence=capped([query_ref(q) for q in queries if q.result == DnsResult.SERVFAIL]),
            ))
    first_timeout = next((index for index, q in enumerate(queries) if q.result == DnsResult.TIMEOUT), None)
    if first_timeout is not None:
        trailing = queries[first_timeout:]
        if len(trailing) >= 2 and all(q.result == DnsResult.TIMEOUT for q in trailing):
            output.findings.append(Finding(
                code="DNS_UNREACHABLE_FROM_SITE_SUSPECTED", kind=FindingKind.INFERRED, device_id=None,
                summary=f"All {len(trailing)} DNS queries from {site.site_id} since {trailing[0].timestamp.isoformat()} "
                        "timed out across servers; a network path problem is suspected rather than a DNS service fault",
                evidence=capped([query_ref(q) for q in trailing]),
            ))
    if not queries:
        output.missing_data.append(f"No DNS queries from clients at site {site.site_id} were observed")

    dhcp_faults = any(
        entry["status"] == "exhausted" or entry["event_counts"]["allocation_failure"] or entry["transactions_stopped"]
        for entry in pool_entries
    )
    dns_faults = any(q.result in DNS_FAILURE_RESULTS for q in queries)
    output.data = {
        "site_id": site.site_id,
        "dhcp": {
            "status": "no_data" if not pools else "degraded" if dhcp_faults else "operational",
            "pools": pool_entries,
        },
        "dns": {
            "status": "no_data" if not queries else "degraded" if dns_faults else "operational",
            "query_count": len(queries),
            "result_counts": {r.value: c for r, c in sorted(Counter(q.result for q in queries).items(), key=lambda i: i[0].value)},
            "response_time": response_stats(queries),
            "servers": server_entries,
            "failed_queries": [dump(q) for q in queries if q.result in DNS_FAILURE_RESULTS],
        },
    }
    return output
