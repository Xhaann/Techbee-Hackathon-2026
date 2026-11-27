"""Network health scoring: 0-100 per link, device, site and network, with every deduction explained and evidenced."""
from datetime import datetime
from functools import lru_cache
from ipaddress import IPv4Network
from typing import Any

from app.diagnostics.common import sample_ref
from app.diagnostics.telemetry import THRESHOLDS
from app.network.models import DeviceType, LinkStatus, Severity
from app.network.repository import load_scenario, load_topology
from app.observability.analytics import interface_baseline
from app.observability.inventory import config_drift
from app.observability.journey import trace
from app.observability.simulation import SITE_GEO, USER_SUBNET, golden_config, monitored_interfaces, running_config, site_of

EVENT_PENALTY = {Severity.EMERGENCY: (15, 30), Severity.ALERT: (15, 30), Severity.CRITICAL: (15, 30), Severity.ERROR: (8, 24),
                 Severity.WARNING: (3, 9)}
DRIFT_PENALTY = {"critical": 15, "high": 10, "medium": 4, "low": 1}
BANDS = ((85, "healthy"), (60, "degraded"), (0, "critical"))
SERVICE_PROBES = {"application": ("tcp", 443, None), "dns": ("udp", 53, None), "dhcp": ("udp", 67, None),
                  "authentication": ("udp", 1812, None), "internet": ("tcp", 443, "203.0.113.10")}


def status_of(score: float | None) -> str:
    if score is None:
        return "unknown"
    return next(label for floor, label in BANDS if score >= floor)


def ref(collection: str, record_id: str, timestamp=None) -> dict[str, Any]:
    return {"collection": collection, "record_id": record_id, **({"timestamp": timestamp.isoformat()} if timestamp else {})}


class Score:
    def __init__(self) -> None:
        self.factors: list[dict[str, Any]] = []

    def deduct(self, factor: str, points: float, detail: str, evidence: list[dict[str, Any]] | None = None) -> None:
        if points > 0:
            self.factors.append({"factor": factor, "penalty": round(points, 1), "detail": detail, "evidence": (evidence or [])[:8]})

    @property
    def value(self) -> float:
        return max(0.0, round(100 - sum(f["penalty"] for f in self.factors), 1))


def interface_factors(score: Score, dataset, interface_id: str, nominal_latency: float | None) -> bool:
    samples = sorted((s for s in dataset.interface_statistics if s.interface_id == interface_id), key=lambda s: s.timestamp)
    if not samples:
        return False
    latest = samples[-1]
    name = interface_id.split(":", 1)[1]
    if latest.oper_status == LinkStatus.DOWN:
        score.deduct("availability", 45, f"{name} is down", [ref("interface_statistics", sample_ref(latest).record_id, latest.timestamp)])
        return True
    up = [s for s in samples if s.oper_status == LinkStatus.UP]
    worst_loss = max(up, key=lambda s: s.packet_loss_percent or 0)
    if (worst_loss.packet_loss_percent or 0) >= THRESHOLDS["packet_loss_percent"] / 2:
        score.deduct("packet_loss", min(30, (worst_loss.packet_loss_percent or 0) * 6),
                     f"{name} up to {worst_loss.packet_loss_percent:g}% packet loss",
                     [ref("interface_statistics", sample_ref(worst_loss).record_id, worst_loss.timestamp)])
    worst_errors = max(samples, key=lambda s: s.in_errors + s.out_errors)
    errors = worst_errors.in_errors + worst_errors.out_errors
    if errors > THRESHOLDS["errors_per_interval"]:
        score.deduct("errors", min(20, 8 + errors / 200), f"{name} {errors} errors in one interval",
                     [ref("interface_statistics", sample_ref(worst_errors).record_id, worst_errors.timestamp)])
    busiest = max(up, key=lambda s: s.utilization_percent) if up else None
    if busiest and busiest.utilization_percent >= THRESHOLDS["utilization_percent"]:
        score.deduct("utilization", 20 if busiest.utilization_percent >= THRESHOLDS["congestion_utilization_percent"] else 10,
                     f"{name} at {busiest.utilization_percent:g}% utilisation",
                     [ref("interface_statistics", sample_ref(busiest).record_id, busiest.timestamp)])
    measured = [s for s in up if s.latency_ms is not None]
    if nominal_latency and measured:
        slowest = max(measured, key=lambda s: s.latency_ms)
        ratio = slowest.latency_ms / nominal_latency
        if ratio >= THRESHOLDS["latency_increase_ratio"]:
            score.deduct("latency", 15 if ratio >= 2 else 8, f"{name} latency {slowest.latency_ms:g} ms ({ratio:.1f}x nominal)",
                         [ref("interface_statistics", sample_ref(slowest).record_id, slowest.timestamp)])
    return False


def relay_check(scenario_id: str, site_id: str) -> dict[str, Any] | None:
    """DHCP only works where the gateway relays it: compare each user and voice VLAN's helpers with the golden config."""
    topology = load_topology()
    notes, cap = [], 100.0
    for vlan in topology.vlans:
        if vlan.site_id != site_id or vlan.vlan_id not in (10, 20):
            continue
        device_id, name = vlan.gateway_interface_id.split(":", 1)
        golden = helpers_in(golden_config(device_id), name)
        running = helpers_in(list(running_config(scenario_id, device_id)), name)
        if golden and not running:
            notes.append(f"VLAN {vlan.vlan_id} ({vlan.name}) gateway {name} relays DHCP to no server")
            cap = min(cap, 40.0)
        elif len(running) < len(golden):
            notes.append(f"VLAN {vlan.vlan_id} gateway {name} relays to {len(running)} of {len(golden)} DHCP servers")
            cap = min(cap, 80.0)
    return {"cap": cap, "notes": notes} if notes else None


AUTH_FAILURES = {"DOT1X_AUTH_FAILURE", "PORT_UNAUTHORIZED", "RADIUS_SERVER_DEAD"}
DNS_FAILURES = {"servfail", "refused", "timeout"}


def service_signals(scenario_id: str, site_id: str, service: str) -> dict[str, Any] | None:
    """Application-layer evidence a packet trace cannot see: DNS answers, DHCP allocations, 802.1X and relay config."""
    topology, dataset = load_topology(), load_scenario(scenario_id)
    notes, cap = [], 100.0
    if service == "dhcp":
        relay = relay_check(scenario_id, site_id)
        if relay:
            notes += relay["notes"]
            cap = relay["cap"]
        pools = {p.pool_id for p in dataset.dhcp.pools if p.site_id == site_id}
        events = [e for e in dataset.dhcp.events if e.pool_id in pools]
        if any(e.event_type.value == "pool_exhausted" for e in events):
            notes.append("A DHCP pool for this site is exhausted")
            cap = min(cap, 40.0)
        elif failures := sum(e.event_type.value == "allocation_failure" for e in events):
            notes.append(f"{failures} DHCP allocation failure(s) for this site")
            cap = min(cap, 70.0)
    elif service == "dns":
        queries = [q for q in dataset.dns.queries if site_of(topology, str(q.client_ip)) == site_id]
        failed = [q for q in queries if q.result.value in DNS_FAILURES]
        if queries and failed:
            ratio = len(failed) / len(queries)
            notes.append(f"{len(failed)} of {len(queries)} DNS queries from this site failed (SERVFAIL, REFUSED or timeout)")
            cap = min(cap, 45.0 if ratio >= 0.3 else 75.0 if ratio >= 0.1 else 90.0)
    elif service == "authentication":
        devices = {d.device_id for d in topology.devices if d.site_id == site_id}
        failures = sorted({e.event_type for e in dataset.events if e.device_id in devices and e.event_type in AUTH_FAILURES})
        if failures:
            notes.append("802.1X failing at this site: " + ", ".join(failures))
            cap = min(cap, 45.0)
    return {"cap": cap, "notes": notes} if notes else None


def helpers_in(lines: list[str], interface: str) -> list[str]:
    try:
        start = lines.index(f"interface {interface}") + 1
    except ValueError:
        return []
    found = []
    for line in lines[start:]:
        if not line.startswith(" "):
            break
        if line.startswith(" ip helper-address "):
            found.append(line.split()[-1])
    return found


@lru_cache(maxsize=32)
def network_health(scenario_id: str) -> dict[str, Any]:
    topology, dataset = load_topology(), load_scenario(scenario_id)
    monitored = set(monitored_interfaces(dataset))
    latest_time = max((s.timestamp for s in dataset.interface_statistics), default=None)
    reporting = {s.device_id for s in dataset.interface_statistics if s.timestamp == latest_time}
    devices_by_id = {d.device_id: d for d in topology.devices}
    nominal = {i: l.latency_ms for l in topology.links for i in (l.a_interface_id, l.b_interface_id)}
    drift = config_drift(scenario_id)
    drift_by_device: dict[str, list[dict[str, Any]]] = {}
    for item in drift["items"]:
        drift_by_device.setdefault(item["device_id"], []).append(item)

    link_scores = {}
    for link in topology.links:
        # Both ends see the same fault; keep the worse end's deduction per factor instead of counting it twice.
        score, down, ends = Score(), False, []
        for interface_id in (link.a_interface_id, link.b_interface_id):
            end = Score()
            down |= interface_factors(end, dataset, interface_id, link.latency_ms)
            ends.append(end)
        for factor in sorted({f["factor"] for end in ends for f in end.factors}):
            score.factors.append(max((f for end in ends for f in end.factors if f["factor"] == factor), key=lambda f: f["penalty"]))
        tracked = any(i in monitored for i in (link.a_interface_id, link.b_interface_id))
        value = 0.0 if down else score.value
        link_scores[link.link_id] = {"link_id": link.link_id, "link_type": link.link_type.value,
                                     "endpoints": [link.a_device_id, link.b_device_id],
                                     "score": value if tracked else None, "status": status_of(value if tracked else None),
                                     "factors": score.factors}

    device_scores = {}
    for device in topology.devices:
        score = Score()
        interfaces = [i.interface_id for i in topology.interfaces if i.device_id == device.device_id and i.interface_id in monitored]
        for interface_id in interfaces:
            interface_factors(score, dataset, interface_id, nominal.get(interface_id))
        events = [e for e in dataset.events if e.device_id == device.device_id and e.severity in EVENT_PENALTY]
        for severity, (each, cap) in EVENT_PENALTY.items():
            matching = [e for e in events if e.severity == severity]
            if matching:
                kinds = sorted({e.event_type for e in matching})
                score.deduct("events", min(cap, each * len(matching)), f"{len(matching)} {severity.value} event(s): {', '.join(kinds[:4])}",
                             [ref("events", e.event_id, e.timestamp) for e in matching])
        anomalies = [(i, a) for i in interfaces for a in interface_baseline(scenario_id, i)["anomalies"] if a["kind"] in ("above", "below")]
        if anomalies:
            score.deduct("baseline", min(15, 5 * len(anomalies)),
                         "; ".join(f"{i.split(':', 1)[1]} {a['metric']} {a['kind']} baseline ({a['value']} vs {a['expected']})"
                                   for i, a in anomalies[:3]), [ref("interface_history", i) for i, _ in anomalies])
        items = drift_by_device.get(device.device_id, [])
        if items:
            penalty = sum(DRIFT_PENALTY[i["severity"]] * (1 if i["attributed"] else 1.5) for i in items)
            score.deduct("config_drift", min(25, penalty), f"{len(items)} configuration line(s) differ from the golden config"
                         + (f", {sum(not i['attributed'] for i in items)} unattributed" if any(not i["attributed"] for i in items) else ""),
                         [ref("configurations", device.device_id)] + [ref("events", i["event_id"], datetime.fromisoformat(i["changed_at"]))
                                                             for i in items if i["event_id"]])
        silent = device.device_type != DeviceType.SERVER and device.device_id not in reporting and interfaces
        if silent:
            score.deduct("telemetry", 10, "No interface telemetry in the latest collection; the score may be optimistic")
        link_floor = min((link_scores[l.link_id]["score"] for l in topology.links if device.device_id in (l.a_device_id, l.b_device_id)
                          and link_scores[l.link_id]["score"] is not None), default=None)
        value = score.value
        device_scores[device.device_id] = {
            "device_id": device.device_id, "hostname": device.hostname, "site_id": device.site_id,
            "device_type": device.device_type.value, "role": device.role.value, "score": value, "status": status_of(value),
            "confidence": "low" if silent else ("medium" if not interfaces else "high"), "worst_link_score": link_floor,
            "factors": sorted(score.factors, key=lambda f: -f["penalty"]),
        }

    service_scores = []
    for path in topology.paths:
        # A service is healthy only if a packet actually gets there: trace it, then take the weakest link and the server.
        protocol, port, target = SERVICE_PROBES[path.service.value]
        destination = target or path.device_ids[-1]
        journey = trace(scenario_id, str(IPv4Network(USER_SUBNET[path.source_site_id])[100]), destination, protocol, port)
        path_links = [link_scores[l] for l in path.link_ids]
        down = [l["link_id"] for l in path_links if l["score"] == 0.0]
        tracked = [l["score"] for l in path_links if l["score"] is not None]
        server = device_scores[path.device_ids[-1]]["score"] if devices_by_id[path.device_ids[-1]].device_type == DeviceType.SERVER else None
        values = tracked + ([server] if server is not None else [])
        reachable = journey["verdict"] in ("delivered", "leaves_network")
        value = 0.0 if down or not reachable else round(min(values), 1) if values else None
        relay = service_signals(scenario_id, path.source_site_id, path.service.value)
        if relay and value is not None:
            value = min(value, relay["cap"])
        service_scores.append({"path_id": path.path_id, "site_id": path.source_site_id, "service": path.service.value,
                               "score": value, "status": status_of(value), "down_links": down,
                               "journey": {"verdict": journey["verdict"], "hop": journey["verdict_hop"],
                                           "latency_ms": journey["total_latency_ms"]},
                               "notes": relay["notes"] if relay else [],
                               "weakest": min(path.device_ids, key=lambda d: device_scores[d]["score"])})

    site_scores = []
    for site in topology.sites:
        members = [d for d in device_scores.values() if d["site_id"] == site.site_id]
        services = [s for s in service_scores if s["site_id"] == site.site_id]
        values = [d["score"] for d in members]
        value = 0.4 * min(values) + 0.6 * (sum(values) / len(values)) if values else None
        notes = []
        if services:
            service_values = [s["score"] for s in services if s["score"] is not None]
            if service_values:
                value = 0.5 * value + 0.5 * (sum(service_values) / len(service_values))
            if any(s["status"] == "critical" for s in services):
                value = min(value, 55.0)
                notes.append("At least one service path from this site is critical")
            elif any(s["status"] == "degraded" for s in services):
                value = min(value, 80.0)
            notes += [note for s in services for note in s["notes"]]
        value = round(value, 1) if value is not None else None
        geo = SITE_GEO[site.site_id]
        site_scores.append({"site_id": site.site_id, "name": site.name, "city": site.city, "country": site.country,
                            "site_type": site.site_type.value, "latitude": geo.latitude, "longitude": geo.longitude,
                            "utc_offset_hours": geo.utc_offset_hours, "score": value, "status": status_of(value),
                            "devices": len(members), "critical_devices": sum(d["status"] == "critical" for d in members),
                            "degraded_devices": sum(d["status"] == "degraded" for d in members),
                            "services": [{k: s[k] for k in ("service", "score", "status", "down_links")} for s in services],
                            "worst_device": min(members, key=lambda d: d["score"])["device_id"] if members else None, "notes": notes})
    scored = [s["score"] for s in site_scores if s["score"] is not None]
    overall = round(min(scored) * 0.5 + sum(scored) / len(scored) * 0.5, 1) if scored else None
    return {
        "scenario_id": scenario_id, "evaluated_at": latest_time.isoformat() if latest_time else None,
        "method": "100 minus explained deductions (availability, loss, errors, utilisation, latency, events, baseline anomalies, "
                  "configuration drift, telemetry gaps); sites blend their weakest and average device with their service paths",
        "bands": {"healthy": ">= 85", "degraded": "60-84", "critical": "< 60"},
        "network": {"score": overall, "status": status_of(overall),
                    "worst_site": min(site_scores, key=lambda s: s["score"] if s["score"] is not None else 101)["site_id"]},
        "sites": site_scores, "devices": sorted(device_scores.values(), key=lambda d: (d["score"], d["device_id"])),
        "links": sorted(link_scores.values(), key=lambda l: (l["score"] if l["score"] is not None else 101, l["link_id"])),
        "services": service_scores,
    }


def compact_health(scenario_id: str, site_id: str | None = None, device_id: str | None = None, limit: int = 5) -> dict[str, Any]:
    """The agent's view: a few numbers and the top reasons, never raw telemetry."""
    health = network_health(scenario_id)
    devices = [d for d in health["devices"] if (site_id is None or d["site_id"] == site_id) and (device_id is None or d["device_id"] == device_id)]
    sites = [s for s in health["sites"] if site_id is None or s["site_id"] == site_id]
    return {
        "network": health["network"],
        "sites": [{k: s[k] for k in ("site_id", "score", "status", "worst_device", "notes")} for s in sites],
        "worst_devices": [{"device_id": d["device_id"], "score": d["score"], "status": d["status"], "confidence": d["confidence"],
                           "reasons": [f["detail"] for f in d["factors"][:3]]} for d in devices[:limit] if d["status"] != "healthy"
                          or device_id],
        "critical_services": [{k: s[k] for k in ("path_id", "score", "status", "down_links")} for s in health["services"]
                              if s["status"] != "healthy" and (site_id is None or s["site_id"] == site_id)][:limit],
    }
