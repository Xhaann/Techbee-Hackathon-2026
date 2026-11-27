"""Deterministic synthetic observability data built on the existing topology and scenario datasets.

Nothing here touches a real network. Every value is derived from the scenario files plus a seeded generator, so the same
scenario always produces the same history, flows, configurations and neighbour tables:

- 14 days of 5-minute interface history per monitored interface, with site-local business hours, weekends, per-link
  growth and a few historic outages, ending in the scenario's own samples and logged outages.
- Flow records (NetFlow/IPFIX shape) for the scenario window, from the dataset's DNS queries, DHCP transactions and
  firewall events plus seeded application and internet traffic that respects link state and firewall policy.
- Golden and running device configurations, the running copy carrying the scenario's logged changes.
- LLDP neighbour tables reflecting which links are up.
"""
import dataclasses
import hashlib
import math
import random
import re
from array import array
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network

from app.network.models import (
    DeviceRole,
    DeviceType,
    FirewallAction,
    InterfaceMode,
    LinkStatus,
    LinkType,
    NetworkTopology,
    RoutingProtocol,
    ScenarioDataset,
    TransportProtocol,
    match_firewall_rule,
)
from app.network.repository import load_scenario, load_topology

STEP = timedelta(minutes=5)
HISTORY_DAYS = 14
POINTS_PER_DAY = 288
POINTS = HISTORY_DAYS * POINTS_PER_DAY
UP, DOWN, UNKNOWN = 1, 0, 2


@dataclass(frozen=True)
class SiteGeo:
    city: str
    latitude: float
    longitude: float
    utc_offset_hours: float


SITE_GEO = {
    "CORE": SiteGeo("London", 51.507, -0.128, 0.0), "DC1": SiteGeo("Slough", 51.511, -0.595, 0.0),
    "NYC": SiteGeo("New York", 40.713, -74.006, -5.0), "SIN": SiteGeo("Singapore", 1.352, 103.820, 8.0),
    "BLR": SiteGeo("Bengaluru", 12.972, 77.595, 5.5),
}


def seeded(*parts: object) -> random.Random:
    digest = hashlib.sha256("|".join(str(part) for part in parts).encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


@dataclass(frozen=True)
class LinkProfile:
    """`peak` is today's business-hours peak utilisation (percent), or None to derive it from the scenario's own level;
    utilisation grows by `growth` points a day. Outages are (hours before the history ends, minutes down)."""
    peak: float | None
    growth: float
    noise: float = 2.0
    outages: tuple[tuple[float, int], ...] = ()


LINK_PROFILES = {
    "LNK-WAN-NYC": LinkProfile(70, 1.3, 2.5, ((216.5, 6), (74.2, 4))),
    "LNK-WAN-SIN": LinkProfile(62, 0.25, 2.0, ((150.0, 12),)),
    "LNK-WAN-BLR": LinkProfile(72, 0.7, 2.0),
    "LNK-CORE-DC1-METRO": LinkProfile(48, 0.15, 1.5),
}
DEFAULT_PROFILES = {
    "core": LinkProfile(None, 0.05, 0.8), "server": LinkProfile(None, 0.1, 1.2),
    "access_trunk": LinkProfile(None, 0.1, 1.5), "edge_port": LinkProfile(None, 0.02, 0.6),
}


def profile_for(topology: NetworkTopology, interface_id: str) -> tuple[LinkProfile, str | None]:
    link = next((l for l in topology.links if interface_id in (l.a_interface_id, l.b_interface_id)), None)
    if link is None:
        return DEFAULT_PROFILES["edge_port"], None
    if link.link_id in LINK_PROFILES:
        return LINK_PROFILES[link.link_id], link.link_id
    devices = {d.device_id: d for d in topology.devices}
    roles = {devices[link.a_device_id].device_type, devices[link.b_device_id].device_type}
    if DeviceType.SERVER in roles:
        return DEFAULT_PROFILES["server"], link.link_id
    if link.link_type == LinkType.LAN and devices[link.a_device_id].site_id in ("CORE", "DC1"):
        return DEFAULT_PROFILES["core"], link.link_id
    return DEFAULT_PROFILES["access_trunk"], link.link_id


def anchors(dataset: ScenarioDataset, interface_id: str) -> tuple[float | None, float | None]:
    """The interface's own pre-incident utilisation and latency in this scenario: the history is calibrated to them so
    that a healthy scenario matches its baseline and only post-onset changes stand out."""
    before = [s for s in dataset.interface_statistics if s.interface_id == interface_id and s.timestamp < dataset.scenario.onset_at
              and s.oper_status == LinkStatus.UP]
    if not before:
        return None, None
    latencies = [s.latency_ms for s in before if s.latency_ms is not None]
    return (sum(s.utilization_percent for s in before) / len(before), sum(latencies) / len(latencies) if latencies else None)


def business_shape(moment: datetime, offset_hours: float) -> float:
    local = moment + timedelta(hours=offset_hours)
    hour = local.hour + local.minute / 60
    weekday = local.weekday() < 5
    bell = 0.5 - 0.5 * math.cos(2 * math.pi * (hour - 7) / 12) if 7 <= hour <= 19 else 0.0
    return bell * (1.0 if weekday else 0.3)


@dataclass
class InterfaceHistory:
    interface_id: str
    device_id: str
    site_id: str
    link_id: str | None
    speed_mbps: int
    nominal_latency_ms: float | None
    start: datetime
    utilization: array = field(default_factory=lambda: array("f"))
    loss: array = field(default_factory=lambda: array("f"))
    errors: array = field(default_factory=lambda: array("f"))
    latency: array = field(default_factory=lambda: array("f"))
    status: bytearray = field(default_factory=bytearray)
    window_start_index: int = 0

    def __len__(self) -> int:
        return len(self.utilization)

    def at(self, index: int) -> datetime:
        return self.start + STEP * index

    def index_of(self, moment: datetime) -> int:
        return max(0, min(len(self) - 1, int((moment - self.start) / STEP)))


def history_end(dataset: ScenarioDataset) -> datetime:
    end = dataset.scenario.window_end
    return end.replace(minute=end.minute - end.minute % 5, second=0, microsecond=0)


def monitored_interfaces(dataset: ScenarioDataset) -> list[str]:
    return sorted({sample.interface_id for sample in dataset.interface_statistics})


@lru_cache(maxsize=256)
def interface_history(scenario_id: str, interface_id: str) -> InterfaceHistory:
    topology, dataset = load_topology(), load_scenario(scenario_id)
    interface = next(i for i in topology.interfaces if i.interface_id == interface_id)
    device = next(d for d in topology.devices if d.device_id == interface.device_id)
    profile, link_id = profile_for(topology, interface_id)
    link = next((l for l in topology.links if l.link_id == link_id), None)
    end = history_end(dataset)
    start = end - STEP * (POINTS - 1)
    geo = SITE_GEO[device.site_id]
    anchor, latency_anchor = anchors(dataset, interface_id)
    if anchor is None:
        anchor, latency_anchor = anchors(load_scenario("BASELINE"), interface_id)
    anchor = 20.0 if anchor is None else anchor
    nominal = link.latency_ms if link and link.link_type == LinkType.WAN else None
    latency_anchor = latency_anchor or nominal
    # Solve off-hours and peak levels so the window's own time of day sits at the scenario's measured level.
    shape_window = business_shape(dataset.scenario.window_start + timedelta(minutes=20), geo.utc_offset_hours)
    peak = profile.peak if profile.peak is not None else min(85.0, anchor * 1.35 + 3)
    peak = max(peak, anchor + 2)
    off = (anchor - peak * shape_window) / (1 - shape_window) if shape_window < 0.97 else anchor * 0.4
    off = max(off, anchor * 0.3, 0.3)
    if shape_window >= 0.05:
        peak = max(off + 1, (anchor - off * (1 - shape_window)) / shape_window)
    # Both ends of a link share the link's traffic pattern; each end adds a little of its own noise.
    shared, own = seeded("link", link_id or interface_id), seeded("interface", interface_id)
    history = InterfaceHistory(interface_id, device.device_id, device.site_id, link_id, interface.speed_mbps, nominal, start)
    outage_slots: set[int] = set()
    for hours_before, minutes in profile.outages:
        first = POINTS - 1 - int(hours_before * 12)
        outage_slots.update(range(first, first + max(1, minutes // 5)))
    for index in range(POINTS):
        moment = start + STEP * index
        days_before_end = (POINTS - 1 - index) / POINTS_PER_DAY
        level = off + (peak - off) * business_shape(moment, geo.utc_offset_hours)
        value = level - profile.growth * days_before_end + shared.gauss(0, profile.noise) + own.gauss(0, profile.noise * 0.25)
        value = min(98.0, max(0.2, value))
        down = index in outage_slots
        history.utilization.append(0.0 if down else value)
        history.loss.append(100.0 if down else max(0.0, shared.gauss(0.01, 0.015)) if link_id else 0.0)
        history.errors.append(0.0 if down else float(own.randint(1, 6)) if own.random() < 0.01 else 0.0)
        history.latency.append(float("nan") if latency_anchor is None or down
                               else latency_anchor * (1 + (value - anchor) / 400) + shared.gauss(0, latency_anchor * 0.008))
        history.status.append(DOWN if down else UP)
    overlay_scenario(history, dataset)
    return history


def overlay_scenario(history: InterfaceHistory, dataset: ScenarioDataset) -> None:
    """From the window start on, the scenario is the truth: its samples, its logged outages and its telemetry gaps."""
    window_index = history.index_of(dataset.scenario.window_start)
    history.window_start_index = window_index
    samples = sorted((s for s in dataset.interface_statistics if s.interface_id == history.interface_id), key=lambda s: s.timestamp)
    if not samples:
        return
    collection = sorted({s.timestamp for s in dataset.interface_statistics})
    last_seen = samples[-1].timestamp
    gap_from = next((moment for moment in collection if moment > last_seen), None)
    for index in range(window_index, len(history)):
        moment = history.at(index)
        current = next((s for s in reversed(samples) if s.timestamp <= moment), None)
        if gap_from is not None and moment >= gap_from:
            history.utilization[index] = history.loss[index] = history.errors[index] = float("nan")
            history.latency[index] = float("nan")
            history.status[index] = UNKNOWN
            continue
        if current is None:
            continue
        down = current.oper_status == LinkStatus.DOWN
        history.utilization[index] = 0.0 if down else current.utilization_percent
        history.loss[index] = 100.0 if down else (current.packet_loss_percent or 0.0)
        history.errors[index] = (current.in_errors + current.out_errors) * 300 / current.interval_seconds
        history.latency[index] = float("nan") if down or current.latency_ms is None else current.latency_ms
        history.status[index] = DOWN if down else UP
    downs = {"LINK_DOWN", "CARRIER_LOSS"}
    events = sorted((e for e in dataset.events if e.interface_id == history.interface_id and e.event_type in downs | {"LINK_UP"}),
                    key=lambda e: e.timestamp)
    down_since = None
    for event in events:
        if event.event_type in downs and down_since is None:
            down_since = event.timestamp
        elif event.event_type == "LINK_UP" and down_since is not None:
            mark_down(history, down_since, event.timestamp)
            down_since = None
    if down_since is not None:
        mark_down(history, down_since, dataset.scenario.window_end + STEP)


def mark_down(history: InterfaceHistory, start: datetime, end: datetime) -> None:
    for index in range(history.index_of(start), len(history)):
        if history.at(index) >= end:
            break
        if history.at(index) >= start - STEP / 2:
            history.status[index], history.utilization[index], history.loss[index] = DOWN, 0.0, 100.0


# ---------------------------------------------------------------- flows

@dataclass(frozen=True)
class Flow:
    flow_id: str
    start: datetime
    end: datetime
    exporter_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes: int
    packets: int
    src_site: str | None
    service: str
    action: str
    origin: str


SERVICE_TARGETS = {"application": ("10.100.100.40", 443, "tcp"), "authentication": ("10.100.100.30", 1812, "udp"),
                   "dhcp": ("10.100.100.20", 67, "udp"), "dns": ("10.100.100.10", 53, "udp")}
INTERNET_HOSTS = ["203.0.113.10", "203.0.113.25", "203.0.113.80", "198.51.100.14"]
APPLICATION_RATE = {"NYC": 9, "SIN": 7, "BLR": 8}
USER_SUBNET = {"NYC": "10.10.10.0/24", "SIN": "10.20.10.0/24", "BLR": "10.30.10.0/24"}


def site_of(topology: NetworkTopology, address: str) -> str | None:
    ip = IPv4Address(address)
    return next((vlan.site_id for vlan in topology.vlans if ip in vlan.subnet), None)


def path_open(scenario_id: str, topology: NetworkTopology, path_id: str, moment: datetime) -> bool:
    path = next(p for p in topology.paths if p.path_id == path_id)
    links = {l.link_id: l for l in topology.links}
    dataset = load_scenario(scenario_id)
    monitored = set(monitored_interfaces(dataset))
    for link_id in path.link_ids:
        link = links[link_id]
        for interface_id in (link.a_interface_id, link.b_interface_id):
            if interface_id in monitored:
                history = interface_history(scenario_id, interface_id)
                if history.status[history.index_of(moment)] == DOWN:
                    return False
    return True


def firewall_verdict(topology: NetworkTopology, dataset: ScenarioDataset, path_id: str, src: str, dst: str, protocol: str,
                     port: int, moment: datetime) -> tuple[str, str | None]:
    path = next(p for p in topology.paths if p.path_id == path_id)
    kinds = {d.device_id: d.device_type for d in topology.devices}
    firewalls = [d for d in path.device_ids if kinds[d] == DeviceType.FIREWALL]
    for device in firewalls:
        rule = match_firewall_rule(dataset.firewall.rules, device, IPv4Address(src), IPv4Address(dst),
                                   TransportProtocol(protocol), port, moment)
        if rule is not None and rule.action == FirewallAction.DENY:
            return "dropped", device
    return "forwarded", firewalls[-1] if firewalls else None


@lru_cache(maxsize=32)
def scenario_flows(scenario_id: str) -> tuple[Flow, ...]:
    topology, dataset = load_topology(), load_scenario(scenario_id)
    rng = seeded("flows", scenario_id)
    window_start, window_end = dataset.scenario.window_start, dataset.scenario.window_end
    flows: list[Flow] = []

    def add(start: datetime, src: str, dst: str, src_port: int, dst_port: int, protocol: str, size: int, packets: int,
            service: str, exporter: str, action: str, origin: str) -> None:
        flows.append(Flow(f"FLW-{len(flows) + 1:05d}", start, start + timedelta(seconds=rng.randint(1, 50)), exporter, src, dst,
                          src_port, dst_port, protocol, size, packets, site_of(topology, src), service, action, origin))

    leases = {}
    for lease in dataset.dhcp.leases:
        pool = next(p for p in dataset.dhcp.pools if p.pool_id == lease.pool_id)
        if pool.vlan_id == 10:
            leases.setdefault(pool.site_id, []).append(str(lease.ip_address))
    edges = {site: next(d.device_id for d in topology.devices if d.site_id == site and d.role == DeviceRole.WAN_EDGE)
             for site in APPLICATION_RATE}
    minute = window_start
    while minute < window_end:
        for site, rate in APPLICATION_RATE.items():
            hosts = leases.get(site) or [str(IPv4Network(USER_SUBNET[site])[100])]
            activity = 0.25 + business_shape(minute, SITE_GEO[site].utc_offset_hours)
            for service, count in (("application", rate), ("internet", rate // 2 + 2)):
                path_id = f"PATH-{site}-{service.upper()}"
                if not path_open(scenario_id, topology, path_id, minute):
                    continue
                for _ in range(max(1, round(count * activity))):
                    src = rng.choice(hosts)
                    if service == "internet":
                        dst, port, protocol = rng.choice(INTERNET_HOSTS), 443, "tcp"
                    else:
                        dst, port, protocol = SERVICE_TARGETS[service]
                    action, firewall = firewall_verdict(topology, dataset, path_id, src, dst, protocol, port, minute)
                    size = 180 if action == "dropped" else int(rng.lognormvariate(11.2 if service == "application" else 10.4, 0.9))
                    add(minute + timedelta(seconds=rng.randint(0, 59)), src, dst, rng.randint(49152, 65535), port, protocol,
                        size, max(1, size // 900), service, firewall or edges[site], action, "simulated_traffic")
        minute += timedelta(minutes=1)
    for query in dataset.dns.queries:
        add(query.timestamp, str(query.client_ip), str(query.server_ip), rng.randint(49152, 65535), 53, "udp", 140, 2, "dns",
            "DC1-FW-01" if query.result.value != "timeout" else edges.get(site_of(topology, str(query.client_ip)) or "", "CORE-RTR-01"),
            "forwarded" if query.result.value != "timeout" else "unanswered", f"dns_queries:{query.query_id}")
    relay_of = {(v.site_id, v.vlan_id): v for v in topology.vlans}
    addresses = {d.device_id: str(d.management_ip) for d in topology.devices}
    for event in dataset.dhcp.events:
        # Each relayed DHCP transaction is a flow from the client VLAN's gateway (the relay) to the pool's server.
        pool = next(p for p in dataset.dhcp.pools if p.pool_id == event.pool_id)
        gateway = relay_of[(pool.site_id, pool.vlan_id)].gateway
        add(event.timestamp, str(gateway), addresses[pool.server_device_id], 67, 67, "udp", 620, 2, "dhcp", "DC1-FW-01",
            "forwarded", f"dhcp_events:{event.event_id}")
    for event in dataset.firewall.events:
        protocol = event.protocol.value
        service = {53: "dns", 67: "dhcp", 1812: "authentication", 443: "application"}.get(event.destination_port or 0, "other")
        if service == "application" and not str(event.destination_ip).startswith("10.100.100."):
            service = "internet"
        add(event.timestamp, str(event.source_ip), str(event.destination_ip), event.source_port or 50000,
            event.destination_port or 0, protocol, 400 if event.action == FirewallAction.ALLOW else 120, 4 if event.action ==
            FirewallAction.ALLOW else 1, service, event.device_id, "forwarded" if event.action == FirewallAction.ALLOW else "dropped",
            f"firewall_events:{event.event_id}")
    flows.sort(key=lambda flow: (flow.start, flow.flow_id))
    return tuple(dataclasses.replace(flow, flow_id=f"FLW-{index:05d}") for index, flow in enumerate(flows, start=1))


# ---------------------------------------------------------------- configurations

HELPERS = ("10.100.100.20", "10.100.100.21")
ROUTED_COMMAND = re.compile(r"logged command:(?:interface (?P<interface>\S+) ; )?(?P<command>.+)$")
MTU_EVENT = re.compile(r"Interface (?P<interface>\S+) IP MTU changed from \d+ to (?P<mtu>\d+)")


def golden_config(device_id: str) -> list[str]:
    topology = load_topology()
    device = next(d for d in topology.devices if d.device_id == device_id)
    lines = [f"hostname {device.hostname}", "service password-encryption", "logging host 10.255.0.210"]
    interfaces = [i for i in topology.interfaces if i.device_id == device_id]
    links = {endpoint: link for link in topology.links for endpoint in (link.a_interface_id, link.b_interface_id)}
    vlans = {v.gateway_interface_id: v for v in topology.vlans}
    if device.device_type == DeviceType.FIREWALL:
        baseline = load_scenario("BASELINE")
        lines += [f"interface {i.name}" + (f" ip {i.ip_address}" if i.ip_address else "") for i in interfaces]
        lines += [firewall_rule_line(rule) for rule in sorted(baseline.firewall.rules, key=lambda r: r.priority) if rule.device_id == device_id]
        return lines
    if device.device_type == DeviceType.SWITCH:
        site_vlans = sorted({vid for i in interfaces for vid in i.vlan_ids})
        lines += [f"vlan {vid}" for vid in site_vlans]
        lines += ["aaa new-model", "dot1x system-auth-control", "radius server RAD-1",
                  " address ipv4 10.100.100.30 auth-port 1812 acct-port 1813", " key 7 <removed>"] if device.role == DeviceRole.ACCESS_SWITCH else []
    for interface in interfaces:
        lines.append(f"interface {interface.name}")
        if interface.description:
            lines.append(f" description {interface.description}")
        if interface.mode == InterfaceMode.ACCESS:
            lines += [f" switchport access vlan {interface.vlan_ids[0]}", " authentication port-control auto", " dot1x pae authenticator"]
        elif interface.mode == InterfaceMode.TRUNK and device.device_type == DeviceType.SWITCH:
            lines += [" switchport mode trunk", f" switchport trunk allowed vlan {','.join(str(v) for v in interface.vlan_ids)}"]
        if interface.ip_address:
            lines.append(f" ip address {interface.ip_address.ip} {interface.ip_address.netmask}")
        vlan = vlans.get(interface.interface_id)
        if vlan is not None and interface.mode == InterfaceMode.VIRTUAL and device.role == DeviceRole.WAN_EDGE:
            lines.insert(len(lines) - 1, f" encapsulation dot1Q {vlan.vlan_id}")
            if vlan.vlan_id in (10, 20):
                lines += [f" ip helper-address {helper}" for helper in HELPERS]
        link = links.get(interface.interface_id)
        if link is not None and link.routing_protocol is not None and interface.mode == InterfaceMode.ROUTED:
            lines.append(f" mtu {interface.mtu}")
            if link.routing_protocol == RoutingProtocol.OSPF:
                lines += [" ip ospf authentication message-digest", " ip ospf message-digest-key 1 md5 <removed>"]
    if device.router_id is not None:
        ospf = [l for l in topology.links if l.routing_protocol == RoutingProtocol.OSPF and device_id in (l.a_device_id, l.b_device_id)]
        if ospf:
            lines += ["router ospf 1", f" router-id {device.router_id}", " area 0 authentication message-digest"]
        bgp = [l for l in topology.links if l.routing_protocol == RoutingProtocol.BGP and device_id in (l.a_device_id, l.b_device_id)]
        if bgp and device.bgp_asn:
            lines.append(f"router bgp {device.bgp_asn}")
            for link in bgp:
                peer_interface = link.b_interface_id if link.a_device_id == device_id else link.a_interface_id
                peer = next(i for i in topology.interfaces if i.interface_id == peer_interface)
                peer_device = next(d for d in topology.devices if d.device_id == peer.device_id)
                lines.append(f" neighbor {peer.ip_address.ip} remote-as {peer_device.bgp_asn}")
    return lines


def firewall_rule_line(rule) -> str:
    port = f" port {rule.destination_port}" if rule.destination_port else ""
    protocol = rule.protocol.value if rule.protocol else "any"
    return (f"rule {rule.rule_id} priority {rule.priority} name {rule.name} {rule.action.value} {protocol} "
            f"{rule.source} -> {rule.destination}{port}" + ("" if rule.enabled else " disabled"))


def apply_command(lines: list[str], interface: str | None, command: str) -> list[str]:
    """Applies one logged configuration command to a config, inside the interface section when one is named."""
    lines = list(lines)
    if interface is None:
        target_start, target_end = 0, len(lines)
    else:
        header = f"interface {interface}"
        if header not in lines:
            lines.append(header)
        target_start = lines.index(header) + 1
        target_end = next((i for i in range(target_start, len(lines)) if not lines[i].startswith(" ")), len(lines))
    entry = command.strip() if interface is None else f" {command.strip()}"
    if command.startswith("no "):
        removed = entry.replace("no ", "", 1) if interface is None else f" {command.strip()[3:]}"
        for index in range(target_start, target_end):
            # "no <command>" removes the configured line it names, whatever arguments that line carries.
            if lines[index] == removed or lines[index].startswith(removed + " "):
                del lines[index]
                break
    elif entry not in lines[target_start:target_end]:
        lines.insert(target_end, entry)
    return lines


@lru_cache(maxsize=256)
def running_config(scenario_id: str, device_id: str) -> tuple[str, ...]:
    dataset = load_scenario(scenario_id)
    device = next(d for d in load_topology().devices if d.device_id == device_id)
    lines = golden_config(device_id)
    if device.device_type == DeviceType.FIREWALL:
        base = [line for line in lines if not line.startswith("rule ")]
        return tuple(base + [firewall_rule_line(rule) for rule in sorted(dataset.firewall.rules, key=lambda r: r.priority)
                             if rule.device_id == device_id])
    for event in sorted(dataset.events, key=lambda e: (e.timestamp, e.event_id)):
        if event.device_id != device_id:
            continue
        if event.event_type == "CONFIG_COMMAND_LOGGED" and (match := ROUTED_COMMAND.search(event.message)):
            lines = apply_command(lines, match.group("interface"), match.group("command"))
        elif event.event_type == "MTU_CHANGE" and (match := MTU_EVENT.search(event.message)):
            section = apply_command(lines, match.group("interface"), "no mtu 1500")
            lines = apply_command(section, match.group("interface"), f"mtu {match.group('mtu')}")
    return tuple(lines)


# ---------------------------------------------------------------- neighbour discovery

@dataclass(frozen=True)
class LldpNeighbor:
    local_device_id: str
    local_port: str
    remote_system: str
    remote_port: str
    remote_management: str | None
    capabilities: str


UNDOCUMENTED_NEIGHBOR = LldpNeighbor("BLR-SW-01", "Gi1/0/48", "lab-ap-07", "eth0", "10.30.99.77", "WLAN access point")


@lru_cache(maxsize=32)
def lldp_neighbors(scenario_id: str) -> tuple[LldpNeighbor, ...]:
    topology, dataset = load_topology(), load_scenario(scenario_id)
    devices = {d.device_id: d for d in topology.devices}
    interfaces = {i.interface_id: i for i in topology.interfaces}
    latest: dict[str, LinkStatus] = {}
    for sample in sorted(dataset.interface_statistics, key=lambda s: s.timestamp):
        latest[sample.interface_id] = sample.oper_status
    reporting = {s.device_id for s in dataset.interface_statistics if s.timestamp == max(x.timestamp for x in dataset.interface_statistics)}
    entries = []
    for link in topology.links:
        ends = (link.a_interface_id, link.b_interface_id)
        if any(latest.get(end) == LinkStatus.DOWN for end in ends):
            continue
        for local, remote in (ends, ends[::-1]):
            local_device = interfaces[local].device_id
            if local_device not in reporting or devices[local_device].device_type == DeviceType.SERVER:
                continue
            remote_device = devices[interfaces[remote].device_id]
            entries.append(LldpNeighbor(local_device, interfaces[local].name, remote_device.hostname, interfaces[remote].name,
                                        str(remote_device.management_ip), remote_device.device_type.value))
    if "BLR-SW-01" in reporting:
        entries.append(UNDOCUMENTED_NEIGHBOR)
    return tuple(sorted(entries, key=lambda e: (e.local_device_id, e.local_port)))
