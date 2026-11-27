"""Agent tools over the observability analytics: health, configuration drift, traffic flows, packet journeys and capacity.

Each returns a compact summary computed in code (scores, top reasons, a handful of hops or flows) with evidence
references into the dataset, so a model never sees raw telemetry and every claim stays traceable.
"""
from datetime import datetime
from typing import Any

from app.diagnostics.common import (
    EvidenceRef,
    Finding,
    FindingKind,
    ToolOutput,
    capped,
    diagnostic_tool,
    evidence,
    invalid,
    load_dataset,
    require_device,
    require_site,
)

SERVICES = ("application", "internet", "dns", "dhcp", "authentication")
# The analytics modules are imported inside each tool: they build on this package, so a module-level import would be circular.


MAX_FINDING_EVIDENCE = 6  # enough to trace a claim; more only spends the model's context


def refs(items: list[dict[str, Any]]) -> list[EvidenceRef]:
    unique = {(i["collection"], i["record_id"]): i for i in items if i.get("record_id")}
    return capped([evidence(i["collection"], i["record_id"], datetime.fromisoformat(i["timestamp"]) if i.get("timestamp") else None)
                   for i in unique.values()])[:MAX_FINDING_EVIDENCE]


def scope(topology, site_id: Any, device_id: Any) -> tuple[str | None, str | None]:
    site = require_site(topology, site_id).site_id if site_id is not None else None
    device = require_device(topology, device_id).device_id if device_id is not None else None
    return site, device


@diagnostic_tool("get_network_health")
def get_network_health(scenario_id: str, site_id: Any = None, device_id: Any = None) -> ToolOutput:
    from app.observability.health import compact_health, network_health
    topology, dataset = load_dataset(scenario_id)
    site, device = scope(topology, site_id, device_id)
    health = network_health(dataset.scenario.scenario_id)
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data=compact_health(dataset.scenario.scenario_id, site, device),
                        warnings=["Scores are derived (100 minus explained deductions); the evidence behind each reason is cited"])
    devices = {d["device_id"]: d for d in health["devices"]}
    for service in health["services"]:
        if service["status"] != "critical" or (site and service["site_id"] != site):
            continue
        weakest = devices[service["weakest"]]
        verdict = service["journey"]["verdict"].replace("_", " ")
        output.findings.append(Finding(
            code="SERVICE_PATH_CRITICAL", kind=FindingKind.INFERRED, device_id=service["weakest"],
            summary=f"{service['site_id']} {service['service']} scores {service['score']:g}/100 (packet journey: {verdict}"
                    + (f"; down: {', '.join(service['down_links'])}" if service["down_links"] else "") + ")",
            evidence=refs([e for f in weakest["factors"] for e in f["evidence"]])))
    for entry in health["devices"]:
        if entry["status"] != "critical" or (site and entry["site_id"] != site) or (device and entry["device_id"] != device):
            continue
        output.findings.append(Finding(
            code="DEVICE_HEALTH_CRITICAL", kind=FindingKind.INFERRED, device_id=entry["device_id"],
            summary=f"{entry['device_id']} scores {entry['score']:g}/100: " + "; ".join(f["detail"] for f in entry["factors"][:3]),
            evidence=refs([e for f in entry["factors"] for e in f["evidence"]])))
    output.findings = output.findings[:8]
    return output


@diagnostic_tool("get_config_drift")
def get_config_drift(scenario_id: str, site_id: Any = None, device_id: Any = None) -> ToolOutput:
    from app.observability.inventory import config_drift
    topology, dataset = load_dataset(scenario_id)
    site, device = scope(topology, site_id, device_id)
    report = config_drift(dataset.scenario.scenario_id)
    devices = [d for d in report["devices"] if (site is None or d["site_id"] == site) and (device is None or d["device_id"] == device)]
    names = {d["device_id"] for d in devices}
    items = [i for i in report["items"] if i["device_id"] in names]
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={
        "summary": {"devices": len(devices), "drifted": sum(d["status"] == "drifted" for d in devices),
                    "unverified": sum(d["status"] == "unverified" for d in devices), "items": len(items)},
        "drift": [{k: i[k] for k in ("device_id", "section", "change", "line", "severity", "category", "attributed", "event_id",
                                     "changed_by", "ticket", "changed_at")} for i in items[:20]],
        "notes": [f"{d['device_id']}: {n}" for d in devices for n in d["notes"]],
    }, warnings=["Running configurations are reconstructed from the scenario's logged changes (simulated collection)"])
    for item in items:
        if item["severity"] not in ("critical", "high"):
            continue
        cited = [evidence("configurations", item["device_id"])] + (
            [evidence("events", item["event_id"], datetime.fromisoformat(item["changed_at"]))] if item["event_id"] else [])
        who = f" by {item['changed_by']}" if item["changed_by"] else ""
        ticket = f" under {item['ticket']}" if item["ticket"] else ""
        output.findings.append(Finding(
            code="CONFIG_DRIFT" if item["attributed"] else "UNATTRIBUTED_CONFIG_CHANGE", kind=FindingKind.OBSERVED,
            device_id=item["device_id"],
            summary=f"{item['device_id']} {item['section']}: '{item['line']}' {item['change']} versus the golden config "
                    f"({item['category'].replace('_', ' ')}, {item['severity']})"
                    + (f", changed{who}{ticket} at {item['changed_at'][11:16]}" if item["attributed"] and item["changed_at"] else
                       ", no logged change explains it" if not item["attributed"] else ""),
            evidence=cited))
    for entry in devices:
        for note in entry["notes"]:
            output.missing_data.append(f"{entry['device_id']}: {note}")
    output.findings = output.findings[:12]
    return output


@diagnostic_tool("analyze_traffic_flows")
def analyze_traffic_flows(scenario_id: str, site_id: Any = None, service: Any = None) -> ToolOutput:
    from app.observability.simulation import scenario_flows
    from app.observability.traffic import traffic_summary
    topology, dataset = load_dataset(scenario_id)
    site, _ = scope(topology, site_id, None)
    if service is not None and service not in SERVICES:
        raise invalid(f"service must be one of: {', '.join(SERVICES)}")
    summary = traffic_summary(dataset.scenario.scenario_id, site, service)
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={
        "totals": summary["totals"], "applications": summary["applications"][:6],
        "top_talkers": summary["top_talkers"][:5], "dropped_by_policy": [{k: d[k] for k in ("device_id", "service", "flows", "sources",
                                                                                           "first_seen", "rules")} for d in summary["dropped_by_policy"][:5]],
        "traffic_shifts": summary["traffic_shifts"][:6],
    }, warnings=["Flow records are simulated from the scenario's DNS, DHCP and firewall logs plus seeded application traffic"])
    flows = scenario_flows(dataset.scenario.scenario_id)
    for drop in summary["dropped_by_policy"][:5]:
        if drop["service"] == "other":
            continue
        times = {e.event_id: e.timestamp for e in dataset.firewall.events}
        rules = {r.rule_id: r.last_modified for r in dataset.firewall.rules}
        cited = [evidence("firewall_events", e, times.get(e)) for e in drop["event_ids"][:5]] + \
                [evidence("firewall_rules", r["rule_id"], rules.get(r["rule_id"])) for r in drop["rules"]]
        names = ", ".join(r["name"] or r["rule_id"] for r in drop["rules"]) or "an unlogged rule"
        output.findings.append(Finding(
            code="FLOWS_DROPPED_BY_POLICY", kind=FindingKind.OBSERVED, device_id=drop["device_id"],
            summary=f"{drop['device_id']} dropped {drop['flows']} {drop['service']} flows from {', '.join(drop['sources'])} "
                    f"since {drop['first_seen'][11:16]} ({names})", evidence=capped(cited)))
    onset = dataset.scenario.onset_at
    for shift in summary["traffic_shifts"][:4]:
        before = [f for f in flows if f.src_site == shift["site_id"] and f.service == shift["service"] and f.start < onset
                  and f.action == "forwarded"][-3:]
        output.findings.append(Finding(
            code="TRAFFIC_DROPPED_OFF", kind=FindingKind.OBSERVED, device_id=None,
            summary=f"{shift['site_id']} {shift['service']} traffic fell from {shift['flows_per_minute_before']:g} to "
                    f"{shift['flows_per_minute_after']:g} flows a minute after {onset:%H:%M}",
            evidence=[evidence("flows", f.flow_id, f.start) for f in before]))
    return output


@diagnostic_tool("trace_packet")
def trace_packet(scenario_id: str, source: Any, destination: Any, protocol: Any = "tcp", port: Any = None) -> ToolOutput:
    from app.observability.journey import trace
    _, dataset = load_dataset(scenario_id)
    journey = trace(dataset.scenario.scenario_id, source, destination, protocol, port)
    hops = [{"hop": h["index"], "device_id": h["device_id"],
             **({"route": h["route"]["prefix"] + " via " + h["route"]["protocol"]} if h.get("route") else {}),
             **({"policy": f"{h['policy']['name']} ({h['policy']['action']})"} if h.get("policy") else {}),
             **({"egress": f"{h['egress']['link_id']} {h['egress']['status']}, {h['egress']['latency_ms']} ms, MTU {h['egress']['mtu']}"}
                if h.get("egress") else {})} for h in journey["hops"]]
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={
        "verdict": journey["verdict"], "verdict_hop": journey["verdict_hop"], "hops": hops,
        "total_latency_ms": journey["total_latency_ms"], "path_mtu": journey["path_mtu"], "observed_flows": journey["observed_flows"],
        "source": journey["source"], "destination": journey["destination"], "request": journey["request"]},
        warnings=journey["limitations"][:1], missing_data=journey["notes"])
    stop = next((h for h in journey["hops"] if h["index"] == journey["verdict_hop"]), None)
    cited = refs(journey["evidence"])
    if journey["verdict"] == "dropped_by_policy" and stop:
        policy = stop["policy"]
        output.findings.append(Finding(
            code="PACKET_DROPPED_BY_POLICY", kind=FindingKind.OBSERVED, device_id=stop["device_id"],
            summary=f"{stop['device_id']} rule {policy['name']} ({policy['rule_id']}) drops {journey['request']['protocol']}"
                    f"/{journey['request']['port'] or 'any'} from {journey['source']['address']} to {journey['destination']['address']}",
            evidence=[evidence("firewall_rules", policy["rule_id"],
                               next(r.last_modified for r in dataset.firewall.rules if r.rule_id == policy["rule_id"]))]))
    elif journey["verdict"] == "link_down" and stop:
        output.findings.append(Finding(code="PATH_LINK_DOWN", kind=FindingKind.OBSERVED, device_id=stop["device_id"],
                                       summary=f"The packet stops at {stop['device_id']}: {stop['egress']['link_id']} is down",
                                       evidence=[r for r in cited if r.collection == "interface_statistics"][-2:]))
    elif journey["verdict"] == "no_route" and stop:
        output.findings.append(Finding(code="PACKET_NO_ROUTE", kind=FindingKind.OBSERVED, device_id=stop["device_id"],
                                       summary=f"{stop['device_id']} has no route to {journey['destination']['address']}",
                                       evidence=[evidence("routing_tables", stop["device_id"],
                                                          next((t.collected_at for t in dataset.routing.routing_tables
                                                                if t.device_id == stop["device_id"]), None))]))
    if journey["mtu_note"]:
        mismatched = [interface.split(":", 1)[0] for h in journey["hops"] for link in h.get("attached_links", []) if link["mismatch"]
                      for interface in link["mtu"]]
        reduced = [h["device_id"] for h in journey["hops"] if h.get("egress") and h["egress"]["mtu"] == journey["path_mtu"]]
        devices = list(dict.fromkeys(mismatched or reduced))[:3]
        output.findings.append(Finding(code="MTU_MISMATCH" if mismatched else "PATH_MTU_REDUCED", kind=FindingKind.INFERRED,
                                       device_id=devices[0] if devices else None, summary=journey["mtu_note"],
                                       evidence=[evidence("configurations", d) for d in devices]))
    return output


@diagnostic_tool("forecast_capacity")
def forecast_capacity(scenario_id: str, site_id: Any = None, link_id: Any = None) -> ToolOutput:
    from app.observability.analytics import congestion
    topology, dataset = load_dataset(scenario_id)
    site, _ = scope(topology, site_id, None)
    if link_id is not None and link_id not in {l.link_id for l in topology.links}:
        raise invalid(f"Unknown link '{str(link_id)[:40]}'")
    devices = {d.device_id: d.site_id for d in topology.devices}
    links = {l.link_id: l for l in topology.links}
    rows = [r for r in congestion(dataset.scenario.scenario_id)
            if (link_id is None or r["link_id"] == link_id)
            and (site is None or site in {devices[links[r["link_id"]].a_device_id], devices[links[r["link_id"]].b_device_id]})]
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={"links": [
        {k: r.get(k) for k in ("link_id", "level", "probability", "current_utilization", "trend_per_day", "days_to", "drivers",
                               "recommendation")} for r in rows[:8]]},
        warnings=["Forecasts come from 14 days of simulated 5-minute history; they are planning aids, not measurements"])
    for row in rows:
        if row["level"] != "high":
            continue
        output.findings.append(Finding(code="CONGESTION_RISK_HIGH", kind=FindingKind.INFERRED, device_id=links[row["link_id"]].a_device_id,
                                       summary=f"{row['link_id']}: " + "; ".join(row["drivers"][:3]),
                                       evidence=[evidence("interface_history", row["interface_id"])]))
    return output
