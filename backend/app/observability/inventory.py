"""Topology discovery reconciliation, dependency graphs and configuration drift."""
import difflib
import re
from collections import defaultdict, deque
from functools import lru_cache
from typing import Any

from app.network.models import DeviceType, LinkStatus, NetworkEvent, PathService
from app.network.repository import load_scenario, load_topology
from app.observability.simulation import (
    SITE_GEO,
    golden_config,
    lldp_neighbors,
    running_config,
    scenario_flows,
)

CONFIGURED = (DeviceType.ROUTER, DeviceType.SWITCH, DeviceType.FIREWALL)
SERVICE_DEVICES = {PathService.APPLICATION: "DC1-SRV-APP-01", PathService.DNS: "DC1-SRV-DNS-01", PathService.DHCP: "DC1-SRV-DHCP-01",
                   PathService.AUTHENTICATION: "DC1-SRV-AUTH-01"}


# ---------------------------------------------------------------- discovery

@lru_cache(maxsize=32)
def discovery(scenario_id: str) -> dict[str, Any]:
    """Reconciles the (simulated) LLDP neighbour tables against the documented inventory."""
    topology, dataset = load_topology(), load_scenario(scenario_id)
    devices = {d.device_id: d for d in topology.devices}
    by_hostname = {d.hostname: d.device_id for d in topology.devices}
    interfaces = {i.interface_id: i for i in topology.interfaces}
    neighbors = lldp_neighbors(scenario_id)
    seen: dict[tuple[str, str], tuple[str | None, str]] = {}
    unexpected = []
    for entry in neighbors:
        remote_device = by_hostname.get(entry.remote_system)
        if remote_device is None:
            unexpected.append({"local_device_id": entry.local_device_id, "local_port": entry.local_port,
                               "remote_system": entry.remote_system, "remote_port": entry.remote_port,
                               "remote_management": entry.remote_management, "capabilities": entry.capabilities,
                               "note": "Neighbour is not in the documented inventory"})
            continue
        seen[(entry.local_device_id, entry.local_port)] = (remote_device, entry.remote_port)
    latest_time = max((s.timestamp for s in dataset.interface_statistics), default=None)
    reporting = {s.device_id for s in dataset.interface_statistics if s.timestamp == latest_time}
    matched, missing, one_sided = [], [], []
    for link in topology.links:
        a, b = interfaces[link.a_interface_id], interfaces[link.b_interface_id]
        a_view = seen.get((a.device_id, a.name))
        b_view = seen.get((b.device_id, b.name))
        record = {"link_id": link.link_id, "a": f"{a.device_id} {a.name}", "b": f"{b.device_id} {b.name}",
                  "link_type": link.link_type.value}
        if a_view == (b.device_id, b.name) and (b_view == (a.device_id, a.name) or devices[b.device_id].device_type == DeviceType.SERVER):
            matched.append(record)
        elif a_view or b_view:
            one_sided.append({**record, "seen_from": a.device_id if a_view else b.device_id})
        else:
            silent = [d for d in (a.device_id, b.device_id) if d not in reporting and devices[d].device_type != DeviceType.SERVER]
            down = [s.interface_id for s in dataset.interface_statistics if s.timestamp == latest_time
                    and s.interface_id in (a.interface_id, b.interface_id) and s.oper_status == LinkStatus.DOWN]
            reason = ("Interface down: " + ", ".join(down)) if down else (
                "No discovery data from " + ", ".join(silent) if silent else "Adjacency not seen")
            missing.append({**record, "reason": reason})
    baseline = discovery("BASELINE") if scenario_id != "BASELINE" else None
    changes = []
    if baseline is not None:
        before = {m["link_id"] for m in baseline["matched"]}
        after = {m["link_id"] for m in matched}
        changes = [{"link_id": l, "change": "adjacency_lost"} for l in sorted(before - after)] + \
                  [{"link_id": l, "change": "adjacency_gained"} for l in sorted(after - before)]
    return {
        "source": "simulated LLDP neighbour tables (no device is contacted)", "collected_at": latest_time.isoformat() if latest_time else None,
        "neighbors": len(neighbors), "devices_reporting": sorted(reporting),
        "documented_links": len(topology.links), "matched": matched, "missing": missing, "one_sided": one_sided,
        "unexpected": unexpected, "changes_since_baseline": changes,
        "coverage_percent": round(100 * len(matched) / len(topology.links), 1) if topology.links else 0.0,
    }


# ---------------------------------------------------------------- dependency graph

def reachable(adjacency: dict[str, set[str]], source: str, target: str, removed: str | None = None) -> bool:
    if source == removed or target == removed:
        return False
    queue, seen = deque([source]), {source}
    while queue:
        node = queue.popleft()
        if node == target:
            return True
        for neighbor in adjacency.get(node, ()):
            if neighbor != removed and neighbor not in seen:
                seen.add(neighbor)
                queue.append(neighbor)
    return False


@lru_cache(maxsize=32)
def dependency_graph(scenario_id: str) -> dict[str, Any]:
    """Sites, devices and services joined by physical links, documented relationships, service paths and observed flows.
    Criticality counts the site services that traverse a node; a single point of failure is a node or link whose loss
    disconnects a site from a service it depends on."""
    topology = load_topology()
    devices = {d.device_id: d for d in topology.devices}
    nodes = [{"id": s.site_id, "kind": "site", "label": s.name, "site_id": s.site_id} for s in topology.sites]
    nodes += [{"id": d.device_id, "kind": "device", "label": d.hostname, "site_id": d.site_id, "device_type": d.device_type.value,
               "role": d.role.value} for d in topology.devices]
    services = sorted({p.service.value for p in topology.paths})
    nodes += [{"id": f"service:{s}", "kind": "service", "label": s.replace("_", " ").title()} for s in services]
    edges = [{"source": l.a_device_id, "target": l.b_device_id, "kind": "link", "id": l.link_id, "link_type": l.link_type.value}
             for l in topology.links]
    edges += [{"source": r.source_device_id, "target": r.target_device_id, "kind": r.relationship_type.value, "id": None,
               "description": r.description} for r in topology.relationships]
    for path in topology.paths:
        edges.append({"source": path.source_site_id, "target": f"service:{path.service.value}", "kind": "depends_on", "id": path.path_id,
                      "via": path.device_ids})
    # Flow-observed dependencies: which sites actually exchange traffic with which services in this scenario.
    observed: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"flows": 0, "bytes": 0, "dropped": 0})
    for flow in scenario_flows(scenario_id):
        if flow.src_site and flow.service != "other":
            bucket = observed[(flow.src_site, flow.service)]
            bucket["flows"] += 1
            bucket["bytes"] += flow.bytes
            bucket["dropped"] += flow.action == "dropped"
    edges += [{"source": site, "target": f"service:{service}", "kind": "observed_traffic", "id": None, **stats}
              for (site, service), stats in sorted(observed.items())]
    adjacency: dict[str, set[str]] = defaultdict(set)
    for link in topology.links:
        adjacency[link.a_device_id].add(link.b_device_id)
        adjacency[link.b_device_id].add(link.a_device_id)
    criticality: dict[str, list[str]] = defaultdict(list)
    link_use: dict[str, list[str]] = defaultdict(list)
    spof: dict[str, set[str]] = defaultdict(set)
    for path in topology.paths:
        label = f"{path.source_site_id} {path.service.value}"
        start, target = path.device_ids[0], path.device_ids[-1]
        for device_id in path.device_ids:
            criticality[device_id].append(label)
            if device_id not in (start, target) and not reachable(adjacency, start, target, removed=device_id):
                spof[device_id].add(label)
        for link_id in path.link_ids:
            link_use[link_id].append(label)
        for link_id in path.link_ids:
            link = next(l for l in topology.links if l.link_id == link_id)
            pruned = {k: set(v) for k, v in adjacency.items()}
            pruned[link.a_device_id].discard(link.b_device_id)
            pruned[link.b_device_id].discard(link.a_device_id)
            if not reachable(pruned, start, target):
                spof[link_id].add(label)
        spof[start].add(label)
        spof[target].add(label)
    ranked = sorted(({"id": k, "label": devices[k].hostname, "site_id": devices[k].site_id, "services": len(v),
                      "dependents": sorted(set(v))} for k, v in criticality.items()), key=lambda r: (-r["services"], r["id"]))
    single_points = sorted(({"id": k, "kind": "device" if k in devices else "link", "services_at_risk": sorted(v),
                             "impact": len(v)} for k, v in spof.items()), key=lambda r: (-r["impact"], r["id"]))
    return {"nodes": nodes, "edges": edges, "criticality": ranked, "single_points_of_failure": single_points,
            "link_usage": {k: sorted(v) for k, v in sorted(link_use.items())},
            "sites": {s.site_id: {"city": SITE_GEO[s.site_id].city} for s in topology.sites}}


def blast_radius(scenario_id: str, node_id: str) -> dict[str, Any]:
    graph = dependency_graph(scenario_id)
    affected = next((s for s in graph["single_points_of_failure"] if s["id"] == node_id), None)
    traversing = next((c for c in graph["criticality"] if c["id"] == node_id), None)
    return {"id": node_id, "services_lost_if_down": affected["services_at_risk"] if affected else [],
            "services_traversing": traversing["dependents"] if traversing else graph["link_usage"].get(node_id, [])}


# ---------------------------------------------------------------- configuration drift

SEVERITY_RULES = [
    (re.compile(r"^rule "), "security_policy", "high"),
    (re.compile(r"ip helper-address"), "dhcp_relay", "high"),
    (re.compile(r"\bmtu\b"), "mtu", "high"),
    (re.compile(r"ospf|router ospf|area \d"), "routing", "high"),
    (re.compile(r"router bgp|neighbor "), "routing", "high"),
    (re.compile(r"radius|aaa|dot1x|authentication"), "access_control", "high"),
    (re.compile(r"^ ?shutdown$"), "interface_state", "high"),
    (re.compile(r"switchport|vlan"), "switching", "medium"),
    (re.compile(r"ip address"), "addressing", "high"),
    (re.compile(r"description|logging|hostname|ntp|snmp"), "management", "low"),
]
CHANGE_EVENTS = {"CONFIG_CHANGE", "CONFIG_COMMAND_LOGGED", "POLICY_CHANGE", "MTU_CHANGE"}
TICKET = re.compile(r"\b(?:change ticket|ticket|CHG)[ :#-]*([A-Z]{2,6}-\d{2,6})\b")
USER = re.compile(r"(?:User:|\bby '?)([A-Za-z0-9._-]+)'?")


def sections(lines: tuple[str, ...] | list[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current = "(global)"
    for line in lines:
        if line.startswith(" "):
            result.setdefault(current, []).append(line)
        else:
            current = line if line.startswith(("interface ", "router ", "radius ")) else "(global)"
            result.setdefault(current, [])
            if current == "(global)":
                result[current].append(line)
    return result


def classify(line: str) -> tuple[str, str]:
    for pattern, category, severity in SEVERITY_RULES:
        if pattern.search(line):
            if category == "security_policy" and " deny " in line:
                return category, "critical"
            return category, severity
    return "other", "medium"


def attribution(line: str, section: str, events: list[NetworkEvent]) -> NetworkEvent | None:
    body = line.strip()
    interface = section.split(" ", 1)[1] if section.startswith("interface ") else None
    rule = re.match(r"rule (\S+) priority \d+ name (\S+)", body)
    for event in events:
        message = event.message
        if event.event_type == "CONFIG_COMMAND_LOGGED":
            command = message.split("logged command:", 1)[-1]
            target = command.split(" ; ", 1)[-1].strip()
            named = target.removeprefix("no ")
            if (interface is None or f"interface {interface}" in command or interface in (event.interface_id or "")) and \
                    (target == body or named == body or body.startswith(named + " ")):
                return event
        if event.event_type == "MTU_CHANGE" and "mtu" in body and interface and interface in message:
            return event
        if event.event_type == "POLICY_CHANGE" and rule and (rule.group(2) in message or rule.group(1) in message):
            return event
    if rule:
        # A commit that names no rule ("1 rule added") still accounts for a rule created by that commit's author.
        return next((e for e in events if e.event_type == "POLICY_CHANGE" and "rule added" in e.message.lower()), None)
    return None


@lru_cache(maxsize=32)
def config_drift(scenario_id: str) -> dict[str, Any]:
    topology, dataset = load_topology(), load_scenario(scenario_id)
    rules = {r.rule_id: r for r in dataset.firewall.rules}
    devices_out, items = [], []
    for device in topology.devices:
        if device.device_type not in CONFIGURED:
            continue
        golden, running = sections(golden_config(device.device_id)), sections(running_config(scenario_id, device.device_id))
        events = sorted((e for e in dataset.events if e.device_id == device.device_id and e.event_type in CHANGE_EVENTS),
                        key=lambda e: (e.timestamp, e.event_id))
        device_items = []
        for section in sorted(set(golden) | set(running)):
            before, after = golden.get(section, []), running.get(section, [])
            for change, lines in (("removed", [l for l in before if l not in after]), ("added", [l for l in after if l not in before])):
                for line in lines:
                    category, severity = classify(line)
                    event = attribution(line, section, events)
                    rule_id = re.match(r"rule (\S+)", line.strip())
                    rule = rules.get(rule_id.group(1)) if rule_id else None
                    ticket = TICKET.search(event.message) if event else None
                    user = USER.search(event.message) if event else None
                    if event is not None and user is None:
                        # The commit or MTU message may not name the user; the configuration session around it does.
                        session = next((e for e in events if e.event_type == "CONFIG_CHANGE"
                                        and abs((e.timestamp - event.timestamp).total_seconds()) <= 300), None)
                        user = USER.search(session.message) if session else None
                    device_items.append({
                        "device_id": device.device_id, "section": section, "change": change, "line": line.strip(),
                        "category": category, "severity": severity,
                        "attributed": event is not None, "event_id": event.event_id if event else None,
                        "changed_at": (event.timestamp if event else rule.last_modified if rule else None),
                        "changed_by": user.group(1) if user else None, "ticket": ticket.group(1) if ticket else None,
                    })
        sessions_without_commands = [
            e for e in events if e.event_type == "CONFIG_CHANGE"
            and not any(x.event_type in ("CONFIG_COMMAND_LOGGED", "MTU_CHANGE") and abs((x.timestamp - e.timestamp).total_seconds()) <= 120
                        for x in events)]
        notes = [f"Configuration session at {e.timestamp:%H:%M} ({e.event_id}) logged no commands; the running configuration "
                 "should be re-collected to confirm what changed" for e in sessions_without_commands]
        for item in device_items:
            if item["changed_at"] is not None:
                item["changed_at"] = item["changed_at"].isoformat()
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        device_items.sort(key=lambda i: (order[i["severity"]], i["section"], i["line"]))
        status = "drifted" if device_items else ("unverified" if notes else "compliant")
        devices_out.append({"device_id": device.device_id, "site_id": device.site_id, "device_type": device.device_type.value,
                            "status": status, "drift_items": len(device_items),
                            "highest_severity": device_items[0]["severity"] if device_items else None,
                            "unattributed": sum(not i["attributed"] for i in device_items), "notes": notes,
                            "golden_lines": len(golden_config(device.device_id)),
                            "running_lines": len(running_config(scenario_id, device.device_id))})
        items += device_items
    return {
        "source": "golden configurations from the documented design; running configurations replay the scenario's logged "
                  "changes (simulated collection)",
        "summary": {"devices": len(devices_out), "drifted": sum(d["status"] == "drifted" for d in devices_out),
                    "unverified": sum(d["status"] == "unverified" for d in devices_out), "items": len(items),
                    "unattributed": sum(not i["attributed"] for i in items),
                    "by_severity": {s: sum(i["severity"] == s for i in items) for s in ("critical", "high", "medium", "low")}},
        "devices": devices_out, "items": items,
    }


def config_diff(scenario_id: str, device_id: str) -> dict[str, Any]:
    golden, running = golden_config(device_id), list(running_config(scenario_id, device_id))
    diff = list(difflib.unified_diff(golden, running, fromfile=f"{device_id} golden", tofile=f"{device_id} running", lineterm="", n=2))
    return {"device_id": device_id, "golden": golden, "running": running, "unified_diff": diff}
