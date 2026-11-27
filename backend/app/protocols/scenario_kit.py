"""The scenario-editing kit shared by every synthetic scenario module: Edit (helpers over a dataset's core records and its
protocol telemetry) and Spec (one scenario's definition)."""
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.protocols.baseline import Builder

Mutator = Callable[["Edit"], None]


class Edit:
    """Helpers over the plain dictionaries of a dataset (core) and its telemetry (protocol)."""

    def __init__(self, builder: Builder, core: dict[str, Any] | None, telemetry: dict[str, Any] | None) -> None:
        self.b, self.core, self.t = builder, core, telemetry
        self.n = 0

    def at(self, minutes: float) -> str:
        return self.b.at(minutes)

    # ---------- core dataset ----------

    def event(self, minutes: float, device: str, event_type: str, severity: str, message: str, interface: str | None = None,
              event_id: str | None = None) -> None:
        self.n += 1
        self.core["events"].append({"event_id": event_id or f"EVT-P3-{self.n:04d}", "timestamp": self.at(minutes), "device_id": device,
                                    "interface_id": interface, "severity": severity, "event_type": event_type, "message": message})

    def command(self, minutes: float, device: str, user: str, command: str, event_id: str | None = None) -> None:
        self.event(minutes, device, "CONFIG_COMMAND_LOGGED", "notice", f"%PARSER-5-CFGLOG_LOGGEDCMD: User:{user} logged command:{command}",
                   event_id=event_id)

    def drop_events(self, device: str, event_type: str, after: float = -20) -> None:
        self.core["events"] = [ev for ev in self.core["events"] if not (ev["device_id"] == device and ev["event_type"] == event_type
                                                                        and ev["timestamp"] > self.at(after))]

    def dns(self, query_id: str, minutes: float, client: str, server: str, domain: str, result: str, answers: list[str] | None = None,
            response_ms: float | None = None) -> None:
        self.core["dns"]["queries"].append({"query_id": query_id, "timestamp": self.at(minutes), "client_ip": client, "server_ip": server,
                                            "domain": domain, "record_type": "A", "result": result, "answers": answers or [],
                                            "response_time_ms": response_ms})

    def firewall_rule(self, rule_id: str, device: str, priority: int, name: str, action: str, protocol: str | None, source: str,
                      destination: str, port: int | None, minutes: float) -> None:
        self.core["firewall"]["rules"].append({"rule_id": rule_id, "device_id": device, "priority": priority, "name": name, "action": action,
                                               "protocol": protocol, "source": source, "destination": destination, "destination_port": port,
                                               "enabled": True, "last_modified": self.at(minutes)})

    def remove_routes(self, device: str, prefixes: set[str]) -> None:
        table = next(t for t in self.core["routing"]["routing_tables"] if t["device_id"] == device)
        table["routes"] = [r for r in table["routes"] if r["prefix"] not in prefixes]

    def bgp_neighbor(self, device: str, peer: str, **values: Any) -> None:
        for neighbour in self.core["routing"]["bgp_neighbors"]:
            if neighbour["device_id"] == device and neighbour["neighbor_device_id"] == peer:
                neighbour.update(values)

    def stats(self, interface: str, offsets: tuple[int, ...], **values: Any) -> None:
        times = {self.at(o) for o in offsets}
        for sample in self.core["interface_statistics"]:
            if sample["interface_id"] == interface and sample["timestamp"] in times:
                sample.update(values)

    def route(self, device: str, prefix: str, protocol: str, next_hop: str | None, interface: str, distance: int, metric: int = 0) -> None:
        table = next(t for t in self.core["routing"]["routing_tables"] if t["device_id"] == device)
        table["routes"].append({"prefix": prefix, "protocol": protocol, "next_hop": next_hop, "interface_id": interface,
                                "admin_distance": distance, "metric": metric})

    def route_change(self, change_id: str, minutes: float, device: str, prefix: str, kind: str, previous: str | None, new: str | None,
                     protocol: str = "bgp") -> None:
        self.core["routing"]["route_changes"].append({"change_id": change_id, "timestamp": self.at(minutes), "device_id": device, "prefix": prefix,
                                                      "protocol": protocol, "change_type": kind, "previous_next_hop": previous, "new_next_hop": new})

    def incident(self, title: str, description: str, category: str, priority: str, sites: list[str], symptoms: list[str], minutes: float = 6,
                 number: int = 301) -> None:
        self.core["incident"] = {"incident_id": f"INC-{self.b.onset:%Y%m%d}-{number}", "title": title, "description": description, "category": category,
                                 "priority": priority, "status": "open", "reported_at": self.at(minutes), "reported_by": "Service Desk",
                                 "affected_site_ids": sites, "symptoms": symptoms}
        self.core["scenario"]["category"] = category

    def truth(self, root_cause: str, devices: list[str], sites: list[str], paths: list[str], links: list[str] | None = None) -> None:
        self.core["ground_truth"] = {"root_cause": root_cause, "root_cause_device_ids": devices, "root_cause_link_ids": links or [],
                                     "affected_site_ids": sites, "affected_path_ids": paths}

    # ---------- telemetry ----------

    def proto_event(self, minutes: float, protocol: str, kind: str, device: str, detail: str, event_id: str | None = None, **extra: Any) -> None:
        self.t["events"].append({"event_id": event_id or f"PE-{len(self.t['events']) + 1:04d}", "timestamp": self.at(minutes), "protocol": protocol,
                                 "kind": kind, "device_id": device, "detail": detail, **extra})

    def samples(self, section: str, collection: str, **match: Any) -> list[dict[str, Any]]:
        return [item for item in self.t[section][collection] if all(item.get(k) == v for k, v in match.items())]

    def after(self, item: dict[str, Any], key: str = "timestamp") -> bool:
        return item[key] > self.at(0)

    def flow(self, minutes: float, src: str, dst: str, port: int | None, protocol: str, out: int, inn: int, state: str, sensor: str,
             duration: float = 1.0) -> None:
        flows = self.t["security"]["flows"]
        flows.append({"flow_id": f"FL-P3-{len(flows) + 1:05d}", "start": self.at(minutes), "duration_seconds": duration, "src_ip": src, "dst_ip": dst,
                      "dst_port": port, "protocol": protocol, "bytes_out": out, "bytes_in": inn, "packets": max(1, (out + inn) // 900),
                      "state": state, "sensor_device_id": sensor})

    def auth(self, minutes: float, src: str, host: str, account: str, protocol: str, result: str) -> None:
        events = self.t["security"]["auth"]
        events.append({"auth_id": f"AU-P3-{len(events) + 1:04d}", "timestamp": self.at(minutes), "src_ip": src, "dst_host": host, "account": account,
                       "protocol": protocol, "result": result})

    def alert(self, minutes: float, sensor: str, src: str, dst: str, signature: str, category: str, severity: str,
              alert_id: str | None = None) -> None:
        alerts = self.t["security"]["alerts"]
        alerts.append({"alert_id": alert_id or f"IDS-{len(alerts) + 1:04d}", "timestamp": self.at(minutes), "sensor_device_id": sensor, "src_ip": src, "dst_ip": dst,
                       "signature": signature, "category": category, "severity": severity})

    def lease_ip(self, site: str, index: int) -> str:
        return str(self.b.leases(site)[index].ip_address)

    def lease_mac(self, site: str, index: int) -> str:
        return self.b.leases(site)[index].mac_address

    def lease_ips(self, site: str) -> list[str]:
        return [str(lease.ip_address) for lease in self.b.leases(site)]


@dataclass(frozen=True)
class Spec:
    scenario_id: str
    name: str
    description: str
    kind: str  # normal | failure | edge | adversarial
    day: int  # days after the healthy baseline
    core: Mutator | None = None
    telemetry: Mutator | None = None
    features: tuple[str, ...] = field(default_factory=tuple)
