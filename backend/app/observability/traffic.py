"""NetFlow/IPFIX traffic analysis: top talkers and applications, site-to-service matrix, policy drops and link load."""
from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache
from typing import Any

from app.network.repository import load_scenario, load_topology
from app.observability.simulation import Flow, scenario_flows

MAX_TOP = 25


def select(scenario_id: str, site_id: str | None = None, service: str | None = None, action: str | None = None,
           start: datetime | None = None, end: datetime | None = None) -> list[Flow]:
    return [f for f in scenario_flows(scenario_id)
            if (site_id is None or f.src_site == site_id) and (service is None or f.service == service)
            and (action is None or f.action == action) and (start is None or f.start >= start) and (end is None or f.start < end)]


def top(counter: Counter, limit: int) -> list[dict[str, Any]]:
    return [{"key": key, "bytes": value} for key, value in counter.most_common(limit)]


@lru_cache(maxsize=128)
def traffic_summary(scenario_id: str, site_id: str | None = None, service: str | None = None, top_n: int = 10) -> dict[str, Any]:
    dataset = load_scenario(scenario_id)
    flows = select(scenario_id, site_id, service)
    talkers, destinations, services, protocols = Counter(), Counter(), Counter(), Counter()
    matrix: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"bytes": 0, "flows": 0, "dropped": 0})
    drops: dict[tuple[str, str], dict[str, Any]] = {}
    per_minute: dict[str, Counter] = defaultdict(Counter)
    onset = dataset.scenario.onset_at
    before, after = Counter(), Counter()
    for flow in flows:
        talkers[flow.src_ip] += flow.bytes
        destinations[flow.dst_ip] += flow.bytes
        services[flow.service] += flow.bytes
        protocols[flow.protocol] += flow.bytes
        cell = matrix[(flow.src_site or "external", flow.service)]
        cell["bytes"] += flow.bytes
        cell["flows"] += 1
        cell["dropped"] += flow.action == "dropped"
        minute = flow.start.replace(second=0, microsecond=0).isoformat()
        per_minute[minute][flow.service] += flow.bytes
        (before if flow.start < onset else after)[(flow.src_site or "external", flow.service, flow.action)] += 1
        if flow.action == "dropped":
            rule = flow.origin.split(":", 1)[1] if flow.origin.startswith("firewall_events:") else None
            key = (flow.exporter_id, flow.service)
            entry = drops.setdefault(key, {"device_id": flow.exporter_id, "service": flow.service, "flows": 0, "sources": set(),
                                           "first_seen": flow.start, "last_seen": flow.start, "event_ids": []})
            entry["flows"] += 1
            entry["sources"].add(flow.src_site or flow.src_ip)
            entry["last_seen"] = max(entry["last_seen"], flow.start)
            if rule and len(entry["event_ids"]) < 10:
                entry["event_ids"].append(rule)
    rules = {r.rule_id: r for r in dataset.firewall.rules}
    events = {e.event_id: e for e in dataset.firewall.events}
    dropped = []
    for entry in sorted(drops.values(), key=lambda e: -e["flows"]):
        rule_ids = sorted({events[i].rule_id for i in entry["event_ids"] if i in events})
        dropped.append({**entry, "sources": sorted(entry["sources"]), "first_seen": entry["first_seen"].isoformat(),
                        "last_seen": entry["last_seen"].isoformat(),
                        "rules": [{"rule_id": r, "name": rules[r].name if r in rules else None} for r in rule_ids]})
    shifts = []
    for site in sorted({k[0] for k in before} | {k[0] for k in after}):
        for svc in sorted({k[1] for k in before if k[0] == site} | {k[1] for k in after if k[0] == site}):
            pre = before[(site, svc, "forwarded")]
            post = after[(site, svc, "forwarded")]
            pre_minutes = max(1, (onset - dataset.scenario.window_start).total_seconds() / 60)
            post_minutes = max(1, (dataset.scenario.window_end - onset).total_seconds() / 60)
            rate_pre, rate_post = pre / pre_minutes, post / post_minutes
            if rate_pre >= 0.5 and rate_post < rate_pre * 0.5:
                shifts.append({"site_id": site, "service": svc, "flows_per_minute_before": round(rate_pre, 2),
                               "flows_per_minute_after": round(rate_post, 2), "change": "dropped_off"})
    total_bytes = sum(f.bytes for f in flows)
    sankey_nodes = sorted({k[0] for k in matrix}) + sorted({f"service:{k[1]}" for k in matrix})
    sankey_links = [{"source": site, "target": f"service:{svc}", "bytes": cell["bytes"], "flows": cell["flows"],
                     "dropped": cell["dropped"]} for (site, svc), cell in sorted(matrix.items())]
    return {
        "source": "simulated NetFlow/IPFIX records derived from the scenario's DNS, DHCP and firewall logs plus seeded "
                  "application and internet traffic",
        "scenario_id": scenario_id, "filters": {"site_id": site_id, "service": service},
        "window": {"start": dataset.scenario.window_start.isoformat(), "onset": onset.isoformat(),
                   "end": dataset.scenario.window_end.isoformat()},
        "totals": {"flows": len(flows), "bytes": total_bytes, "dropped_flows": sum(f.action == "dropped" for f in flows),
                   "unanswered_flows": sum(f.action == "unanswered" for f in flows)},
        "top_talkers": top(talkers, top_n), "top_destinations": top(destinations, top_n),
        "applications": top(services, MAX_TOP), "protocols": top(protocols, 5),
        "matrix": [{"site_id": s, "service": v, **cell} for (s, v), cell in sorted(matrix.items())],
        "sankey": {"nodes": sankey_nodes, "links": sankey_links},
        "dropped_by_policy": dropped[:MAX_TOP], "traffic_shifts": shifts,
        "timeline": [{"minute": minute, **dict(counter)} for minute, counter in sorted(per_minute.items())],
    }


@lru_cache(maxsize=64)
def link_load(scenario_id: str) -> dict[str, dict[str, int]]:
    """Bytes attributed to each link by walking each forwarded flow along its site's documented service path."""
    topology = load_topology()
    paths = {(p.source_site_id, p.service.value): p for p in topology.paths}
    load: dict[str, dict[str, int]] = defaultdict(lambda: {"bytes": 0, "flows": 0})
    for flow in scenario_flows(scenario_id):
        path = paths.get((flow.src_site, flow.service)) if flow.src_site else None
        if path is None or flow.action != "forwarded":
            continue
        for link_id in path.link_ids:
            load[link_id]["bytes"] += flow.bytes
            load[link_id]["flows"] += 1
    return dict(load)


def flow_page(scenario_id: str, site_id: str | None, service: str | None, action: str | None, limit: int, offset: int) -> dict[str, Any]:
    flows = select(scenario_id, site_id, service, action)
    window = flows[offset:offset + limit]
    return {"items": [{"flow_id": f.flow_id, "start": f.start.isoformat(), "end": f.end.isoformat(), "exporter_id": f.exporter_id,
                       "src_ip": f.src_ip, "dst_ip": f.dst_ip, "src_port": f.src_port, "dst_port": f.dst_port, "protocol": f.protocol,
                       "bytes": f.bytes, "packets": f.packets, "src_site": f.src_site, "service": f.service, "action": f.action,
                       "origin": f.origin} for f in window],
            "total": len(flows), "limit": limit, "offset": offset}

