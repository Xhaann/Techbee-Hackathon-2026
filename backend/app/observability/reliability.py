"""Network reliability reports: availability, outages, MTBF/MTTR and SLA attainment over the 14-day history."""
import csv
import io
from functools import lru_cache
from typing import Any

from app.network.models import LinkType
from app.network.repository import load_scenario, load_topology
from app.observability.simulation import DOWN, STEP, UNKNOWN, UP, interface_history, monitored_interfaces

SLA_TARGETS = {LinkType.WAN: 99.9, LinkType.LAN: 99.95}
SERVICE_SLA = 99.5
PERIODS = {"7d": 7, "14d": 14}


def outages(states: list[int], start_moment, step=STEP) -> list[dict[str, Any]]:
    runs, current = [], None
    for index, state in enumerate(states):
        if state == DOWN and current is None:
            current = index
        elif state != DOWN and current is not None:
            runs.append((current, index))
            current = None
    if current is not None:
        runs.append((current, len(states)))
    return [{"start": (start_moment + step * a).isoformat(), "end": (start_moment + step * b).isoformat(),
             "minutes": int((b - a) * step.total_seconds() / 60), "ongoing": b == len(states)} for a, b in runs]


def availability(states: list[int]) -> dict[str, Any]:
    known = [s for s in states if s != UNKNOWN]
    up = sum(s == UP for s in known)
    return {"availability_percent": round(100 * up / len(known), 4) if known else None,
            "coverage_percent": round(100 * len(known) / len(states), 2) if states else 0.0,
            "up_minutes": up * 5, "down_minutes": (len(known) - up) * 5, "unknown_minutes": (len(states) - len(known)) * 5}


def summarise(states: list[int], start_moment, target: float) -> dict[str, Any]:
    stats = availability(states)
    events = outages(states, start_moment)
    failures = len(events)
    up_minutes, down_minutes = stats["up_minutes"], stats["down_minutes"]
    allowed = (up_minutes + down_minutes) * (100 - target) / 100
    stats.update(
        outages=failures, outage_list=events[-20:],
        mtbf_hours=round(up_minutes / 60 / failures, 1) if failures else None,
        mttr_minutes=round(down_minutes / failures, 1) if failures else None,
        sla_target_percent=target,
        sla_met=None if stats["availability_percent"] is None else stats["availability_percent"] >= target,
        error_budget_minutes=round(allowed, 1),
        error_budget_used_percent=round(100 * down_minutes / allowed, 1) if allowed else None,
    )
    return stats


@lru_cache(maxsize=64)
def reliability_report(scenario_id: str, period: str = "14d") -> dict[str, Any]:
    topology, dataset = load_topology(), load_scenario(scenario_id)
    days = PERIODS[period]
    slots = days * 288
    monitored = set(monitored_interfaces(dataset))
    reference = interface_history(scenario_id, min(monitored))
    period_start, end = reference.at(len(reference) - slots), reference.at(len(reference) - 1) + STEP
    link_rows, link_states = [], {}
    for link in topology.links:
        ends = [i for i in (link.a_interface_id, link.b_interface_id) if i in monitored]
        if not ends:
            continue
        histories = [interface_history(scenario_id, i) for i in ends]
        length = len(histories[0])
        first = length - slots
        # A link is down when either end reports down, unknown only when no end reports at all.
        states = []
        for index in range(first, length):
            values = [h.status[index] for h in histories]
            states.append(DOWN if DOWN in values else UP if UP in values else UNKNOWN)
        link_states[link.link_id] = states
        start_moment = histories[0].at(first)
        row = summarise(states, start_moment, SLA_TARGETS.get(link.link_type, 99.95))
        link_rows.append({"link_id": link.link_id, "link_type": link.link_type.value, "provider": link.provider,
                          "circuit_id": link.circuit_id, "endpoints": [link.a_device_id, link.b_device_id], **row})
    service_rows = []
    for path in topology.paths:
        tracked = [link_states[l] for l in path.link_ids if l in link_states]
        if not tracked:
            continue
        states = [DOWN if DOWN in column else UP if UP in column else UNKNOWN for column in zip(*tracked)]
        row = summarise(states, period_start, SERVICE_SLA)
        service_rows.append({"path_id": path.path_id, "site_id": path.source_site_id, "service": path.service.value,
                             "links_tracked": len(tracked), "links_total": len(path.link_ids), **row})
    site_rows = []
    for site in topology.sites:
        rows = [r for r in service_rows if r["site_id"] == site.site_id]
        if not rows:
            continue
        values = [r["availability_percent"] for r in rows if r["availability_percent"] is not None]
        site_rows.append({"site_id": site.site_id, "name": site.name, "services": len(rows),
                          "availability_percent": round(min(values), 4) if values else None,
                          "mean_service_availability_percent": round(sum(values) / len(values), 4) if values else None,
                          "outages": max(r["outages"] for r in rows), "sla_met": all(r["sla_met"] is not False for r in rows)})
    breached = [r["link_id"] for r in link_rows if r["sla_met"] is False] + [r["path_id"] for r in service_rows if r["sla_met"] is False]
    return {
        "scenario_id": scenario_id, "period": period, "period_start": period_start.isoformat(), "period_end": end.isoformat(),
        "source": "14-day simulated 5-minute interface history ending with the scenario window",
        "method": "Availability = up time / time with telemetry; a link is down when either end is down; a service path is down "
                  "when any tracked link on it is down. MTBF = up time / outages, MTTR = down time / outages.",
        "summary": {"links": len(link_rows), "services": len(service_rows), "breaches": breached,
                    "worst_link": min(link_rows, key=lambda r: r["availability_percent"] or 100)["link_id"] if link_rows else None,
                    "total_outages": sum(r["outages"] for r in link_rows)},
        "links": link_rows, "services": service_rows, "sites": site_rows,
    }


def export_markdown(report: dict[str, Any]) -> str:
    lines = [f"# Network reliability report: {report['scenario_id']}", "",
             f"Period: {report['period_start']} to {report['period_end']} ({report['period']})", "",
             f"Source: {report['source']}.", "", f"Method: {report['method']}", "",
             "## Sites", "", "| Site | Services | Lowest service availability | Outages | SLA |", "|---|---|---|---|---|"]
    lines += [f"| {r['site_id']} | {r['services']} | {r['availability_percent']}% | {r['outages']} | {'met' if r['sla_met'] else 'breached'} |"
              for r in report["sites"]]
    lines += ["", "## Links", "", "| Link | Type | Availability | Outages | MTBF (h) | MTTR (min) | Target | SLA |", "|---|---|---|---|---|---|---|---|"]
    lines += [f"| {r['link_id']} | {r['link_type']} | {r['availability_percent']}% | {r['outages']} | {r['mtbf_hours'] or '-'} | "
              f"{r['mttr_minutes'] or '-'} | {r['sla_target_percent']}% | {'met' if r['sla_met'] else 'breached'} |" for r in report["links"]]
    lines += ["", "## Services", "", "| Path | Site | Service | Availability | Outages | SLA |", "|---|---|---|---|---|---|"]
    lines += [f"| {r['path_id']} | {r['site_id']} | {r['service']} | {r['availability_percent']}% | {r['outages']} | "
              f"{'met' if r['sla_met'] else 'breached'} |" for r in report["services"]]
    return "\n".join(lines) + "\n"


def export_csv(report: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["kind", "id", "site_or_type", "availability_percent", "outages", "mtbf_hours", "mttr_minutes",
                     "sla_target_percent", "sla_met", "coverage_percent"])
    for r in report["links"]:
        writer.writerow(["link", r["link_id"], r["link_type"], r["availability_percent"], r["outages"], r["mtbf_hours"],
                         r["mttr_minutes"], r["sla_target_percent"], r["sla_met"], r["coverage_percent"]])
    for r in report["services"]:
        writer.writerow(["service", r["path_id"], r["site_id"], r["availability_percent"], r["outages"], r["mtbf_hours"],
                         r["mttr_minutes"], r["sla_target_percent"], r["sla_met"], r["coverage_percent"]])
    return buffer.getvalue()
