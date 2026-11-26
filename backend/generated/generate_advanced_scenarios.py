"""Generate advanced synthetic incident scenarios on top of the existing network simulation.

The scenarios reuse the shared topology and the Simulation engine from app.network.generator, then add
conditions the base generator does not model: intermittent faults that recover, monitoring gaps, misleading
but legitimate changes, subnet-scoped policy, absent telemetry and congestion decoys.

Output is written to backend/generated/scenarios/ and never touches app/network/data.

Run from backend/:  .venv/bin/python -m generated.generate_advanced_scenarios
"""
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

from app.network.generator import (
    APP_SERVER,
    AUTH_SERVER,
    BRANCHES,
    DC_FIREWALL,
    DHCP_SERVER,
    DNS_PRIMARY,
    DNS_RECORDS,
    DNS_SECONDARY,
    INTERNAL_ZONE,
    INTERNET_EDGE,
    METRO_LINK,
    MISSING_DOMAIN,
    RULE_BASELINE_TIME,
    SERVER_IP,
    EventTemplate,
    IncidentSpec,
    RuleSpec,
    ScenarioSpec,
    Simulation,
    build_topology,
    to_json,
)
from app.network.models import (
    BgpNeighbor,
    DhcpData,
    DhcpEvent,
    DhcpEventType,
    DhcpLease,
    DhcpPool,
    DnsData,
    DnsQuery,
    DnsRecordType,
    DnsResult,
    FirewallAction,
    FirewallData,
    FirewallEvent,
    FirewallRule,
    IncidentCategory,
    IncidentPriority,
    InterfaceStatistics,
    LeaseState,
    LinkStatus,
    OspfNeighbor,
    OspfState,
    PathService,
    RouteChange,
    RouteChangeType,
    RoutingData,
    RoutingTable,
    ScenarioDataset,
    Severity,
    TransportProtocol,
    device_of,
    match_firewall_rule,
)
from app.network.repository import find_reference_errors, load_scenario, load_topology

BACKEND = Path(__file__).resolve().parents[1]
OUTPUT_DIR = Path(__file__).resolve().parent / "scenarios"
FIRST_INDEX = 20
UDP, TCP = TransportProtocol.UDP, TransportProtocol.TCP
DENY, ALLOW = FirewallAction.DENY, FirewallAction.ALLOW


@dataclass(frozen=True)
class AdvancedSpec(ScenarioSpec):
    flap_recovery_seconds: int | None = None
    unpolled: tuple[tuple[str, tuple[int, ...]], ...] = ()
    quiet_interfaces: tuple[str, ...] = ()
    sample_overrides: tuple[tuple[str, int, tuple[tuple[str, Any], ...]], ...] = ()
    timed_rules: tuple[tuple[RuleSpec, int], ...] = ()
    extra_flows: tuple[tuple[int, str, str, str, TransportProtocol, int, int], ...] = ()
    ospf_failure: tuple[OspfState, str] | None = None
    dns_secondary_share: float = 0.15
    dns_degraded_all_sites: bool = False
    dns_extra_latency: tuple[float, float] = (80.0, 95.0)
    pool_fill: tuple[tuple[str, int], ...] = ()
    conflict_pool: tuple[str, int] | None = None
    voice_dhcp_activity: bool = False
    relay_broken_pool_id: str | None = None
    metro_profile: tuple[tuple[int, float, int], ...] = ()


def tpl(offset: int, device: str, interface: str | None, severity: Severity, event_type: str, message: str) -> EventTemplate:
    return EventTemplate(offset, device, interface, severity, event_type, message)


class AdvancedSimulation(Simulation):
    spec: AdvancedSpec

    def __init__(self, topology, spec: AdvancedSpec, index: int) -> None:
        super().__init__(topology, spec, index)
        self.outage_routes = self.routes
        self.flap_interfaces = set(self.down_interfaces) if spec.flap_recovery_seconds else set()
        self.recovery = self.at(spec.flap_recovery_seconds) if spec.flap_recovery_seconds else None
        self.routes_restored = self.recovery + timedelta(seconds=30) if self.recovery else None
        if spec.dns_degraded_all_sites:
            self.degraded_sites = {branch.site_id for branch in BRANCHES}
        self.unpolled = {(site_id, offset) for site_id, offsets in spec.unpolled for offset in offsets}
        self.overrides = {(interface_id, minute): dict(values) for interface_id, minute, values in spec.sample_overrides}
        self.metro = {minute: (loss, errors) for minute, loss, errors in spec.metro_profile}

    # Reachability and routing ---------------------------------------------------------------------------------

    def in_outage(self, at: datetime) -> bool:
        return at >= self.onset and (self.routes_restored is None or at < self.routes_restored)

    def reachable(self, site_id: str, destination: IPv4Address, at: datetime) -> bool:
        tables = self.outage_routes if self.in_outage(at) else self.baseline_routes
        table = tables.get(self.branches[site_id].router_id)
        return table is not None and any(destination in prefix for prefix in table)

    def build_routing(self) -> RoutingData:
        if self.recovery is None:
            routing = super().build_routing()
            return self.apply_ospf_failure(routing)
        outage_changes = self.build_route_changes()
        saved_routes, saved_down = self.routes, self.down_links
        self.routes, self.down_links = self.baseline_routes, set()
        try:
            tables = [
                RoutingTable(device_id=device_id, collected_at=self.window_end,
                             routes=[routes[prefix] for prefix in sorted(routes, key=lambda p: (int(p.network_address), p.prefixlen))])
                for device_id, routes in self.routes.items()
            ]
            ospf, bgp = self.build_neighbors()
        finally:
            self.routes, self.down_links = saved_routes, saved_down
        flap_links = {self.link_of[interface_id].link_id for interface_id in self.flap_interfaces}
        flap_pairs = {frozenset((self.links[link_id].a_device_id, self.links[link_id].b_device_id)) for link_id in flap_links}
        bgp = [
            BgpNeighbor.model_validate({**n.model_dump(), "last_state_change": self.routes_restored})
            if frozenset((n.device_id, n.neighbor_device_id)) in flap_pairs else n
            for n in bgp
        ]
        ospf = [
            OspfNeighbor.model_validate({**n.model_dump(), "last_state_change": self.routes_restored})
            if frozenset((n.device_id, n.neighbor_device_id)) in flap_pairs else n
            for n in ospf
        ]
        restored = []
        for change in outage_changes:
            reverse = {
                RouteChangeType.WITHDRAWN: (RouteChangeType.ADDED, None, change.previous_next_hop),
                RouteChangeType.ADDED: (RouteChangeType.WITHDRAWN, change.new_next_hop, None),
                RouteChangeType.NEXT_HOP_CHANGED: (RouteChangeType.NEXT_HOP_CHANGED, change.new_next_hop, change.previous_next_hop),
            }[change.change_type]
            restored.append(RouteChange(
                change_id=f"RC-{len(outage_changes) + len(restored) + 1:04d}", timestamp=self.routes_restored,
                device_id=change.device_id, prefix=change.prefix, protocol=change.protocol, change_type=reverse[0],
                previous_next_hop=reverse[1], new_next_hop=reverse[2],
            ))
        return RoutingData(routing_tables=tables, ospf_neighbors=ospf, bgp_neighbors=bgp, route_changes=outage_changes + restored)

    def apply_ospf_failure(self, routing: RoutingData) -> RoutingData:
        if self.spec.ospf_failure is None:
            return routing
        state, reason = self.spec.ospf_failure
        failed = {frozenset((self.links[l].a_device_id, self.links[l].b_device_id)) for l in self.spec.failed_adjacency_link_ids}
        ospf = [
            OspfNeighbor.model_validate({**n.model_dump(), "state": state, "failure_reason": reason})
            if frozenset((n.device_id, n.neighbor_device_id)) in failed else n
            for n in routing.ospf_neighbors
        ]
        return RoutingData(routing_tables=routing.routing_tables, ospf_neighbors=ospf,
                           bgp_neighbors=routing.bgp_neighbors, route_changes=routing.route_changes)

    # Interface statistics -------------------------------------------------------------------------------------

    def build_statistics(self) -> list[InterfaceStatistics]:
        samples = super().build_statistics()
        kept = []
        for sample in samples:
            minute = int((sample.timestamp - self.onset).total_seconds() // 60)
            if (self.devices[sample.device_id].site_id, minute) not in self.unpolled:
                kept.append(sample)
        return kept

    def sample(self, interface, at, in_load, out_load, since) -> InterfaceStatistics:
        if interface.interface_id in self.flap_interfaces and at >= self.recovery:
            saved = self.down_interfaces
            self.down_interfaces = set()
            try:
                result = super().sample(interface, at, in_load, out_load, self.recovery)
            finally:
                self.down_interfaces = saved
        else:
            result = super().sample(interface, at, in_load, out_load, since)
        values = result.model_dump()
        minute = int((at - self.onset).total_seconds() // 60)
        link = self.link_of.get(interface.interface_id)
        if at >= self.onset and interface.interface_id in self.spec.quiet_interfaces and result.oper_status == LinkStatus.UP:
            capacity = (link.bandwidth_mbps if link else interface.speed_mbps) * 1_000_000
            load = self.rng.uniform(0.05, 0.4)
            values.update(utilization_percent=round(load, 2), in_bps=int(capacity * load / 100),
                          out_bps=int(capacity * load * self.rng.uniform(0.8, 1.0) / 100))
        if link is not None and link.link_id == METRO_LINK and minute in self.metro:
            loss, errors = self.metro[minute]
            values.update(
                in_errors=errors + self.rng.randint(0, errors // 5), out_errors=self.rng.randint(0, errors // 10),
                in_drops=errors // 2 + self.rng.randint(0, 40), out_drops=self.rng.randint(0, 30),
                packet_loss_percent=round(loss * self.rng.uniform(0.92, 1.08), 2),
                latency_ms=round(link.latency_ms * self.rng.uniform(0.97, 1.03) + loss * self.rng.uniform(1.1, 1.4), 2),
            )
        values.update(self.overrides.get((interface.interface_id, minute), {}))
        return InterfaceStatistics.model_validate(values)

    # Firewall --------------------------------------------------------------------------------------------------

    def build_rules(self) -> list[FirewallRule]:
        rules = super().build_rules()
        rules += [
            FirewallRule(rule_id=rule.rule_id, device_id=rule.device_id, priority=rule.priority, name=rule.name,
                         action=rule.action, protocol=rule.protocol, source=rule.source, destination=rule.destination,
                         destination_port=rule.port, enabled=True, last_modified=self.at(offset))
            for rule, offset in self.spec.timed_rules
        ]
        return sorted(rules, key=lambda rule: (rule.device_id, rule.priority))

    def build_firewall(self) -> FirewallData:
        base = super().build_firewall()
        rules = base.rules
        flows = [(e.timestamp, e.device_id, e.source_ip, e.destination_ip, e.protocol, e.source_port, e.destination_port)
                 for e in base.events]
        for offset, device_id, source, destination, protocol, source_port, port in self.spec.extra_flows:
            flows.append((self.at(offset), device_id, IPv4Address(source), IPv4Address(destination), protocol, source_port, port))
        events = []
        for at, device_id, source, destination, protocol, source_port, port in sorted(
                flows, key=lambda f: (f[0], f[1], int(f[2]), int(f[3]), f[6] or 0)):
            rule = match_firewall_rule(rules, device_id, source, destination, protocol, port, at)
            events.append(FirewallEvent(
                event_id=f"FW-EVT-{len(events) + 1:04d}", timestamp=at, device_id=device_id, rule_id=rule.rule_id,
                source_ip=source, destination_ip=destination, source_port=source_port, destination_port=port,
                protocol=protocol, action=rule.action,
                severity=Severity.INFORMATIONAL if rule.action == ALLOW else Severity.WARNING,
            ))
        return FirewallData(rules=rules, events=events)

    # DHCP -------------------------------------------------------------------------------------------------------

    def build_leases(self, branch, pool: DhcpPool) -> list[DhcpLease]:
        fill = dict(self.spec.pool_fill).get(pool.pool_id)
        leases = super().build_leases(branch, pool)
        if fill is not None:
            lease_time = timedelta(seconds=pool.lease_time_seconds)
            kind = "ws" if pool.vlan_id == 10 else "ph"
            leases = []
            for index in range(pool.size):
                if index < fill:
                    start = self.window_end - timedelta(seconds=self.rng.randint(300, pool.lease_time_seconds - 300))
                    state = LeaseState.ACTIVE
                else:
                    start = self.window_start - lease_time - timedelta(seconds=self.rng.randint(600, 7200))
                    state = LeaseState.EXPIRED
                leases.append(DhcpLease(
                    pool_id=pool.pool_id, ip_address=pool.range_start + index, mac_address=self.mac(branch.octet, pool.vlan_id, index),
                    hostname=f"{branch.site_id.lower()}-{kind}-{index + 1:03d}", state=state, lease_start=start,
                    lease_end=start + lease_time,
                ))
        if self.spec.conflict_pool and self.spec.conflict_pool[0] == pool.pool_id:
            count = self.spec.conflict_pool[1]
            active = [i for i, lease in enumerate(leases) if lease.state == LeaseState.ACTIVE]
            for i in active[-count:]:
                leases[i] = DhcpLease.model_validate({**leases[i].model_dump(), "state": LeaseState.CONFLICT, "hostname": None})
        return leases

    def build_dhcp_events(self, pools, leases) -> list[DhcpEvent]:
        base = super().build_dhcp_events(pools, leases)
        records = [(e.timestamp, e.pool_id, e.event_type, e.mac_address, e.ip_address, e.message) for e in base]
        by_id = {pool.pool_id: pool for pool in pools}
        if self.spec.voice_dhcp_activity:
            for position, at in enumerate(self.activity_times()):
                for branch in BRANCHES:
                    pool = by_id[f"DHCP-{branch.site_id}-VOICE"]
                    if position % 2 and pool.pool_id != self.spec.relay_broken_pool_id:
                        continue
                    if pool.pool_id == self.spec.relay_broken_pool_id and at >= self.at(-240):
                        continue
                    active = [l for l in leases if l.pool_id == pool.pool_id and l.state == LeaseState.ACTIVE]
                    lease = self.rng.choice(active)
                    records.append((at + timedelta(seconds=7), pool.pool_id, DhcpEventType.ALLOCATION_SUCCESS, lease.mac_address,
                                    lease.ip_address, f"DHCPACK on {lease.ip_address} to {lease.mac_address} ({lease.hostname}) via {pool.gateway}"))
        if self.spec.conflict_pool:
            pool = by_id[self.spec.conflict_pool[0]]
            conflicts = [l for l in leases if l.pool_id == pool.pool_id and l.state == LeaseState.CONFLICT]
            for position, lease in enumerate(conflicts):
                records.append((self.at(-1080 + position * 420), pool.pool_id, DhcpEventType.IP_CONFLICT, lease.mac_address,
                                lease.ip_address, f"DHCPDECLINE of {lease.ip_address} from {lease.mac_address}: address already in use"))
        records.sort(key=lambda r: (r[0], r[1], r[2].value))
        return [
            DhcpEvent(event_id=f"DHCP-EVT-{n:04d}", timestamp=at, server_device_id=by_id[pool_id].server_device_id,
                      pool_id=pool_id, event_type=event_type, mac_address=mac, ip_address=address, message=message)
            for n, (at, pool_id, event_type, mac, address, message) in enumerate(records, start=1)
        ]

    # DNS ----------------------------------------------------------------------------------------------------------

    def build_dns(self) -> DnsData:
        base = super().build_dns()
        metro_latency = self.links[METRO_LINK].latency_ms
        low, high = self.spec.dns_extra_latency
        records = []
        for at in self.activity_times():
            for branch in BRANCHES:
                for _ in range(2):
                    client = self.user_host(branch)
                    domain = MISSING_DOMAIN if self.rng.random() < 0.08 else self.rng.choice(sorted(DNS_RECORDS))
                    server_id = DNS_SECONDARY if self.rng.random() < self.spec.dns_secondary_share else DNS_PRIMARY
                    response_time = branch.latency_ms + metro_latency + self.rng.uniform(0.4, 3.0)
                    lossy, extra = self.rng.random(), self.rng.uniform(low, high)
                    if not self.client_active(branch.site_id, at):
                        continue
                    degraded = at >= self.onset and branch.site_id in self.degraded_sites
                    answers: list[str] = []
                    if not self.reachable(branch.site_id, SERVER_IP[server_id], at) or (degraded and lossy < 0.2):
                        result, response_time = DnsResult.TIMEOUT, None
                    elif at >= self.onset and server_id == self.spec.failed_dns_server_id and domain.endswith(INTERNAL_ZONE):
                        result = DnsResult.SERVFAIL
                    elif domain not in DNS_RECORDS:
                        result = DnsResult.NXDOMAIN
                    else:
                        result, answers = DnsResult.NOERROR, [DNS_RECORDS[domain]]
                    if degraded and response_time is not None:
                        response_time += extra
                    records.append((at + timedelta(seconds=self.rng.randint(0, 25)), client, server_id, domain, result, answers, response_time))
        records = [r for r in records if r[0] <= self.window_end]
        records.sort(key=lambda r: (r[0], int(r[1]), r[3]))
        queries = [
            DnsQuery(query_id=f"DNS-Q-{n:04d}", timestamp=at, client_ip=client, server_ip=SERVER_IP[server_id], domain=domain,
                     record_type=DnsRecordType.A, result=result, answers=answers,
                     response_time_ms=round(rt, 2) if rt is not None else None)
            for n, (at, client, server_id, domain, result, answers, rt) in enumerate(records, start=1)
        ]
        return DnsData(servers=base.servers, queries=queries)


# --------------------------------------------------------------------------------------------------------------
# Scenario definitions
# --------------------------------------------------------------------------------------------------------------

E, W, N, I, C = Severity.ERROR, Severity.WARNING, Severity.NOTICE, Severity.INFORMATIONAL, Severity.CRITICAL

SPECS = (
    AdvancedSpec(
        scenario_id="ADV-NYC-WAN-FLAP",
        name="Intermittent WAN circuit outage that self-recovers",
        description="The New York WAN circuit drops for about eleven minutes and recovers on its own; routing has "
                    "reconverged by the time the incident is investigated.",
        category=IncidentCategory.WAN_CONNECTIVITY_FAILURE,
        incident=IncidentSpec(
            "New York office lost all services for several minutes, now working again",
            "New York users lost ERP, e-mail and internet at the same time for roughly ten minutes. Service came back "
            "without intervention and users ask whether it will happen again.",
            IncidentPriority.P2, 13, "Service Desk", ("NYC",),
            ("All applications unavailable for about ten minutes", "Service restored without intervention",
             "Monitoring alarms for New York devices cleared on their own"),
        ),
        root_cause="Carrier A circuit WAN-NYC-0001 lost signal for about eleven minutes; LNK-WAN-NYC went down, the BGP "
                   "session between NYC-RTR-01 and CORE-RTR-01 dropped and all New York routes were withdrawn until "
                   "the circuit recovered and BGP re-established.",
        root_cause_device_ids=("NYC-RTR-01",),
        root_cause_link_ids=("LNK-WAN-NYC",),
        down_link_ids=("LNK-WAN-NYC",),
        flap_recovery_seconds=660,
        unpolled=(("NYC", (5,)),),
        sample_overrides=(
            ("NYC-RTR-01:Gi0/0/0", 15, (("in_errors", 164), ("out_errors", 3))),
            ("CORE-RTR-01:Gi0/0/2", 15, (("in_errors", 141), ("out_errors", 0))),
        ),
        events=(
            tpl(-720, "CORE-RTR-01", None, N, "CONFIG_CHANGE",
                "%SYS-5-CONFIG_I: Configured from console by netops on vty1 (10.255.0.200)"),
            tpl(-715, "CORE-RTR-01", None, I, "CONFIG_COMMAND_LOGGED",
                "%PARSER-5-CFGLOG_LOGGEDCMD: User:netops logged command:logging host 10.255.0.210 transport udp port 514"),
            tpl(-2, "NYC-RTR-01", "Gi0/0/0", W, "OPTICAL_RX_LOW",
                "%TRANSCEIVER-4-THRESHOLD_VIOLATION: Gi0/0/0 Rx power -21.4 dBm crossed low warning threshold -18.0 dBm"),
            tpl(0, "NYC-RTR-01", "Gi0/0/0", E, "CARRIER_LOSS",
                "%ETHPORT-3-IF_DOWN_LINK_FAILURE: Interface Gi0/0/0 is down (loss of signal)"),
            tpl(1, "CORE-RTR-01", None, N, "BGP_NEIGHBOR_DOWN",
                "%BGP-5-ADJCHANGE: neighbor 172.16.0.2 Down BGP Notification sent: hold time expired after interface down"),
            tpl(1, "NYC-RTR-01", None, N, "BGP_NEIGHBOR_DOWN",
                "%BGP-5-ADJCHANGE: neighbor 172.16.0.1 Down Interface flap"),
            tpl(60, "NYC-RTR-01", "Gi0/0/0", W, "WAN_PROBE_FAILURE",
                "%TRACK-6-STATE: 10 ip sla 10 reachability Up -> Down (target 172.16.0.1)"),
            tpl(75, "CORE-RTR-01", "Gi0/0/2", W, "WAN_PROBE_FAILURE",
                "%TRACK-6-STATE: 12 ip sla 12 reachability Up -> Down (target 172.16.0.2)"),
            tpl(380, "NYC-SW-01", None, I, "STP_TOPOLOGY_CHANGE",
                "%SPANTREE-6-TOPOLOGY_CHANGE: Topology change received on VLAN 10 from Gi1/0/24"),
            tpl(660, "NYC-RTR-01", "Gi0/0/0", N, "LINK_UP",
                "%LINK-3-UPDOWN: Interface Gi0/0/0, changed state to up"),
            tpl(660, "CORE-RTR-01", "Gi0/0/2", N, "LINK_UP",
                "%LINK-3-UPDOWN: Interface Gi0/0/2, changed state to up"),
            tpl(690, "NYC-RTR-01", None, N, "BGP_NEIGHBOR_UP", "%BGP-5-ADJCHANGE: neighbor 172.16.0.1 Up"),
            tpl(690, "CORE-RTR-01", None, N, "BGP_NEIGHBOR_UP", "%BGP-5-ADJCHANGE: neighbor 172.16.0.2 Up"),
            tpl(700, "NYC-RTR-01", "Gi0/0/0", N, "WAN_PROBE_RECOVERED",
                "%TRACK-6-STATE: 10 ip sla 10 reachability Down -> Up (target 172.16.0.1)"),
            tpl(940, "NYC-RTR-01", "Gi0/0/0", W, "INTERFACE_ERRORS",
                "%INTERFACE-4-ERRORS: Gi0/0/0 input errors increased by 164 in 600 seconds (CRC 158)"),
        ),
    ),
    AdvancedSpec(
        scenario_id="ADV-SIN-ERP-SUBNET-BLOCK",
        name="Subnet-scoped firewall rule blocks ERP for Singapore users",
        description="A quarantine rule on the data centre firewall denies HTTPS from the Singapore user VLAN to the "
                    "ERP server only; management hosts, voice and internet access keep working.",
        category=IncidentCategory.FIREWALL_BLOCKING,
        incident=IncidentSpec(
            "Singapore staff cannot open ERP; IT admins at the same site can",
            "Singapore desktop users get a timeout when opening ERP. The local IT administrator reaches ERP from the "
            "management jump host and users suspect the slow Singapore WAN.",
            IncidentPriority.P2, 9, "Service Desk", ("SIN",),
            ("ERP connection timeout for desktop users", "ERP works from the site jump host",
             "Internet access works", "WAN is perceived as slow"),
        ),
        root_cause="Rule FWR-DC1-0127 (QUARANTINE-SIN-USERS-ERP), committed on DC1-FW-01 at incident onset, denies TCP "
                   "443 from 10.20.10.0/24 to 10.100.100.40/32 ahead of the ERP allow rule FWR-DC1-0130.",
        root_cause_device_ids=(DC_FIREWALL,),
        timed_rules=(
            (RuleSpec("FWR-CORE-0105", INTERNET_EDGE, 105, "ALLOW-PATCH-MIRROR", ALLOW, TCP, "10.0.0.0/8", "203.0.113.80/32", 8443), -900),
            (RuleSpec("FWR-DC1-0127", DC_FIREWALL, 127, "QUARANTINE-SIN-USERS-ERP", DENY, TCP, "10.20.10.0/24", "10.100.100.40/32", 443), 0),
        ),
        impacted_services=(("SIN", PathService.APPLICATION),),
        sample_overrides=(
            ("SIN-RTR-01:Gi0/0/0", 5, (("latency_ms", 201.6),)),
            ("CORE-RTR-01:Gi0/0/3", 5, (("latency_ms", 199.8),)),
        ),
        extra_flows=(
            (-840, INTERNET_EDGE, "10.20.10.117", "198.51.100.44", TCP, 51022, 8080),
            (-600, DC_FIREWALL, "10.20.99.10", "10.100.100.40", TCP, 52110, 443),
            (-420, INTERNET_EDGE, "10.20.10.131", "203.0.113.80", TCP, 50544, 8443),
            (240, INTERNET_EDGE, "10.20.10.104", "198.51.100.44", TCP, 53310, 8080),
            (330, DC_FIREWALL, "10.20.99.10", "10.100.100.40", TCP, 52998, 443),
            (390, DC_FIREWALL, "10.20.10.142", "10.100.100.40", TCP, 61002, 443),
            (395, DC_FIREWALL, "10.20.10.142", "10.100.100.40", TCP, 61003, 443),
            (610, DC_FIREWALL, "10.20.20.205", "10.100.100.40", TCP, 49920, 443),
            (720, DC_FIREWALL, "10.20.99.10", "10.100.100.40", TCP, 53401, 443),
            (880, INTERNET_EDGE, "10.20.10.119", "203.0.113.80", TCP, 57008, 8443),
        ),
        events=(
            tpl(-900, INTERNET_EDGE, None, N, "POLICY_CHANGE",
                "Security policy committed by 'fwadmin': rule ALLOW-PATCH-MIRROR added at priority 105 "
                "(allow tcp 10.0.0.0/8 -> 203.0.113.80/32:8443)"),
            tpl(-30, DC_FIREWALL, None, N, "ADMIN_LOGIN", "Administrator 'secops' logged in via HTTPS from 10.255.0.205"),
            tpl(0, DC_FIREWALL, None, N, "POLICY_CHANGE",
                "Security policy committed by 'secops': 1 rule added, 0 modified, 0 deleted (change ticket SEC-4471)"),
            tpl(300, "SIN-RTR-01", "Gi0/0/0", W, "SLA_THRESHOLD_EXCEEDED",
                "%SLA-4-THRESHOLD: ip sla 21 rtt 201 ms exceeds threshold 190 ms (target 172.16.0.5)"),
            tpl(420, APP_SERVER, None, I, "SERVICE_HEALTH", "erp-app: active sessions 412, no errors in the last 10 minutes"),
        ),
    ),
    AdvancedSpec(
        scenario_id="ADV-BLR-OSPF-AUTH-MISMATCH",
        name="OSPF authentication key mismatch after key rotation",
        description="An OSPF message-digest key rotation on CORE-RTR-02 leaves the Bengaluru adjacency down while the "
                    "WAN circuit stays up; Bengaluru devices also drop out of monitoring.",
        category=IncidentCategory.OSPF_ADJACENCY_FAILURE,
        incident=IncidentSpec(
            "Bengaluru office offline; carrier says the circuit is healthy",
            "Bengaluru users lost ERP, DHCP renewals and internet. Monitoring shows the Bengaluru devices as not "
            "responding, yet the carrier reports the WAN circuit is up and error free.",
            IncidentPriority.P1, 7, "Network Operations Centre", ("BLR",),
            ("No access to ERP", "No internet access", "Bengaluru devices not responding to monitoring",
             "Carrier reports circuit up"),
        ),
        root_cause="A message-digest key rotation on CORE-RTR-02 Gi0/0/2 removed key 1 and introduced key 2, which "
                   "BLR-RTR-01 does not have; hellos are rejected on both sides, the OSPF area 10 adjacency over "
                   "LNK-WAN-BLR is down and all routes between Bengaluru and the core were withdrawn.",
        root_cause_device_ids=("CORE-RTR-02", "BLR-RTR-01"),
        root_cause_link_ids=("LNK-WAN-BLR",),
        failed_adjacency_link_ids=("LNK-WAN-BLR",),
        ospf_failure=(OspfState.DOWN, "Dead timer expired: hello packets rejected, message-digest authentication key mismatch"),
        unpolled=(("BLR", (5, 15)),),
        quiet_interfaces=("CORE-RTR-02:Gi0/0/2", "BLR-RTR-01:Gi0/0/0"),
        sample_overrides=(
            ("BLR-RTR-01:Gi0/0/0", -15, (("in_errors", 132), ("out_errors", 0))),
        ),
        events=(
            tpl(-1020, "BLR-RTR-01", "Gi0/0/0", W, "INTERFACE_ERRORS",
                "%INTERFACE-4-ERRORS: Gi0/0/0 input errors increased by 132 in 600 seconds (CRC 129)"),
            tpl(-540, "BLR-SW-01", None, I, "STP_TOPOLOGY_CHANGE",
                "%SPANTREE-6-TOPOLOGY_CHANGE: Topology change received on VLAN 20 from Gi1/0/3"),
            tpl(-75, "CORE-RTR-02", None, N, "CONFIG_CHANGE",
                "%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (10.255.0.200)"),
            tpl(-70, "CORE-RTR-02", "Gi0/0/2", I, "CONFIG_COMMAND_LOGGED",
                "%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin logged command:interface Gi0/0/2 ; ip ospf message-digest-key 2 md5 <removed>"),
            tpl(-65, "CORE-RTR-02", "Gi0/0/2", I, "CONFIG_COMMAND_LOGGED",
                "%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin logged command:interface Gi0/0/2 ; no ip ospf message-digest-key 1"),
            tpl(12, "BLR-RTR-01", "Gi0/0/0", W, "OSPF_AUTH_MISMATCH",
                "%OSPF-4-ERRRCV: Received invalid packet: mismatched authentication key, message digest key 2 from 172.16.0.9, Gi0/0/0"),
            tpl(14, "CORE-RTR-02", "Gi0/0/2", W, "OSPF_AUTH_MISMATCH",
                "%OSPF-4-ERRRCV: Received invalid packet: mismatched authentication key, message digest key 1 from 172.16.0.10, Gi0/0/2"),
            tpl(120, "CORE-RTR-02", None, W, "MONITORING_POLL_FAILURE",
                "snmp-monitor: polling of 10.30.99.1 and 10.30.99.2 timed out (no route to host)"),
        ),
    ),
    AdvancedSpec(
        scenario_id="ADV-DNS-SECONDARY-ZONE-EXPIRED",
        name="Intermittent internal name failures from expired secondary zone",
        description="Zone transfers from the primary to the secondary DNS server have been failing on TSIG validation; "
                    "the secondary's copy of corp.example.com expires and it answers SERVFAIL for internal names.",
        category=IncidentCategory.DNS_RESOLUTION_FAILURE,
        incident=IncidentSpec(
            "Internal applications intermittently fail to open by name at all offices",
            "Users at every branch report that ERP and intranet sometimes fail with 'server not found' and work on "
            "retry. Internet sites are mostly fine.",
            IncidentPriority.P3, 15, "Service Desk", ("NYC", "SIN", "BLR"),
            ("Intermittent 'server not found' for internal names", "Retry usually succeeds",
             "Internet sites work", "All branches affected"),
        ),
        root_cause="DC1-SRV-DNS-02 can no longer transfer corp.example.com from DC1-SRV-DNS-01 because TSIG signature "
                   "verification fails; its secondary copy of the zone expired at incident onset and it now returns "
                   "SERVFAIL for every internal name, so clients that query the secondary fail intermittently.",
        root_cause_device_ids=(DNS_SECONDARY,),
        failed_dns_server_id=DNS_SECONDARY,
        dns_secondary_share=0.4,
        impacted_services=tuple((branch.site_id, PathService.DNS) for branch in BRANCHES),
        events=(
            tpl(-1080, DNS_SECONDARY, None, W, "ZONE_TRANSFER_FAILURE",
                "named[988]: transfer of 'corp.example.com/IN' from 10.100.100.10#53: failed while receiving responses: "
                "TSIG signature verification failure (BADSIG)"),
            tpl(-1079, DNS_PRIMARY, None, W, "ZONE_TRANSFER_DENIED",
                "named[1123]: client @0x7f 10.100.100.11#40211: zone transfer 'corp.example.com/AXFR/IN' denied: "
                "request has invalid TSIG signature"),
            tpl(-720, DNS_PRIMARY, None, N, "ZONE_RELOAD",
                "named[1123]: received control channel command 'reload corp.example.com'"),
            tpl(-718, DNS_PRIMARY, None, I, "ZONE_LOADED",
                "named[1123]: zone corp.example.com/IN: loaded serial 2026032401"),
            tpl(-480, DNS_SECONDARY, None, W, "ZONE_TRANSFER_FAILURE",
                "named[988]: transfer of 'corp.example.com/IN' from 10.100.100.10#53: failed while receiving responses: "
                "TSIG signature verification failure (BADSIG)"),
            tpl(-479, DNS_PRIMARY, None, W, "ZONE_TRANSFER_DENIED",
                "named[1123]: client @0x7f 10.100.100.11#40877: zone transfer 'corp.example.com/AXFR/IN' denied: "
                "request has invalid TSIG signature"),
            tpl(0, DNS_SECONDARY, None, E, "ZONE_EXPIRED",
                "named[988]: zone corp.example.com/IN: expired"),
            tpl(240, DNS_SECONDARY, None, W, "ZONE_TRANSFER_FAILURE",
                "named[988]: transfer of 'corp.example.com/IN' from 10.100.100.10#53: failed while receiving responses: "
                "TSIG signature verification failure (BADSIG)"),
            tpl(241, DNS_PRIMARY, None, W, "ZONE_TRANSFER_DENIED",
                "named[1123]: client @0x7f 10.100.100.11#41530: zone transfer 'corp.example.com/AXFR/IN' denied: "
                "request has invalid TSIG signature"),
            tpl(510, APP_SERVER, None, I, "SERVICE_HEALTH", "erp-app: back-end name resolution via 10.100.100.10 healthy"),
        ),
    ),
    AdvancedSpec(
        scenario_id="ADV-METRO-FIBRE-DEGRADATION",
        name="Metro fibre degradation between core and data centre",
        description="The metro fibre between CORE-SW-01 and DC1-FW-01 degrades with low optical power, CRC errors and "
                    "packet loss; every branch is affected for data centre services while internet access stays healthy. "
                    "A congested but error-free New York WAN acts as a decoy.",
        category=IncidentCategory.PACKET_LOSS,
        incident=IncidentSpec(
            "Slow ERP and intermittent login failures at every branch",
            "Users at New York, Singapore and Bengaluru report slow ERP, slow name resolution and occasional 802.1X "
            "re-authentication failures. Internet browsing feels normal. New York also reports slow file transfers.",
            IncidentPriority.P2, 11, "Service Desk", ("NYC", "SIN", "BLR"),
            ("Slow ERP at all branches", "Occasional login failures", "Internet browsing normal",
             "New York file transfers slow"),
        ),
        root_cause="Optical degradation on the metro fibre circuit MET-DC1-0001 (LNK-CORE-DC1-METRO) between CORE-SW-01 "
                   "Te1/0/4 and DC1-FW-01 ethernet1/1 causes CRC errors and 3-7% packet loss on all traffic between the "
                   "core and the data centre.",
        root_cause_device_ids=("CORE-SW-01", DC_FIREWALL),
        root_cause_link_ids=(METRO_LINK,),
        degraded_link_ids=(METRO_LINK,),
        dns_degraded_all_sites=True,
        dns_extra_latency=(6.0, 18.0),
        metro_profile=((5, 6.8, 1840), (15, 3.4, 910)),
        sample_overrides=(
            ("NYC-RTR-01:Gi0/0/0", 5, (("utilization_percent", 88.4), ("in_bps", 176800000), ("out_bps", 121300000),
                                        ("in_drops", 162), ("out_drops", 37))),
            ("NYC-RTR-01:Gi0/0/0", 15, (("utilization_percent", 91.2), ("in_bps", 182400000), ("out_bps", 117900000),
                                         ("in_drops", 214), ("out_drops", 41))),
            ("CORE-RTR-01:Gi0/0/2", 5, (("utilization_percent", 87.9), ("in_bps", 121000000), ("out_bps", 175800000))),
            ("CORE-RTR-01:Gi0/0/2", 15, (("utilization_percent", 90.6), ("in_bps", 118100000), ("out_bps", 181200000))),
        ),
        events=(
            tpl(-840, "NYC-SW-01", None, I, "BACKUP_JOB_STARTED",
                "%EEM-6-LOG: nyc-file-sync: scheduled replication job to 10.100.100.55 started"),
            tpl(-130, "CORE-SW-01", "Te1/0/4", W, "OPTICAL_RX_LOW",
                "%TRANSCEIVER-4-THRESHOLD_VIOLATION: Te1/0/4 Rx power -17.8 dBm crossed low warning threshold -14.0 dBm"),
            tpl(110, "CORE-SW-01", "Te1/0/4", W, "INTERFACE_ERRORS",
                "%INTERFACE-4-ERRORS: Te1/0/4 input errors increased by 1840 in 600 seconds (CRC 1795)"),
            tpl(150, DC_FIREWALL, "ethernet1/1", W, "INTERFACE_ERRORS",
                "Interface ethernet1/1: 412 CRC errors in the last 600 seconds"),
            tpl(320, "NYC-SW-01", None, W, "RADIUS_SERVER_DEAD",
                "%RADIUS-4-RADIUS_DEAD: RADIUS server 10.100.100.30:1812,1813 is not responding"),
            tpl(345, "NYC-SW-01", None, N, "RADIUS_SERVER_ALIVE",
                "%RADIUS-6-SERVERALIVE: RADIUS server 10.100.100.30:1812,1813 is responding again"),
            tpl(390, "NYC-RTR-01", "Gi0/0/0", W, "QOS_QUEUE_DROPS",
                "%QOS-4-QUEUE_DROP: Gi0/0/0 class-default output queue drops 214 in 600 seconds"),
            tpl(520, "BLR-SW-01", None, W, "RADIUS_SERVER_DEAD",
                "%RADIUS-4-RADIUS_DEAD: RADIUS server 10.100.100.30:1812,1813 is not responding"),
            tpl(548, "BLR-SW-01", None, N, "RADIUS_SERVER_ALIVE",
                "%RADIUS-6-SERVERALIVE: RADIUS server 10.100.100.30:1812,1813 is responding again"),
            tpl(700, "CORE-SW-01", "Te1/0/4", W, "INTERFACE_ERRORS",
                "%INTERFACE-4-ERRORS: Te1/0/4 input errors increased by 910 in 600 seconds (CRC 884)"),
        ),
    ),
    AdvancedSpec(
        scenario_id="ADV-NYC-VOICE-DHCP-RELAY",
        name="Voice VLAN DHCP relay removed during config clean-up",
        description="A config clean-up on NYC-RTR-01 removes the DHCP helper on the voice sub-interface; phones that "
                    "reboot after a firmware rollout cannot renew their address. The DHCP server sees nothing.",
        category=IncidentCategory.DHCP_ALLOCATION_FAILURE,
        incident=IncidentSpec(
            "New York desk phones stuck on 'Configuring IP' after firmware rollout",
            "After this morning's phone firmware rollout, New York desk phones reboot and stay on 'Configuring IP'. "
            "Desktops and laptops work normally. The telephony team blames the new firmware.",
            IncidentPriority.P3, 12, "Telephony Team", ("NYC",),
            ("Desk phones show 'Configuring IP'", "Desktops unaffected", "Started after phone firmware rollout"),
        ),
        root_cause="During a config clean-up at about 09:57 UTC the DHCP helper 10.100.100.20 was removed from NYC-RTR-01 "
                   "Gi0/0/1.20 (voice VLAN 20); DHCP requests from rebooting phones are no longer relayed to "
                   "DC1-SRV-DHCP-01, so pool DHCP-NYC-VOICE receives no traffic.",
        root_cause_device_ids=("NYC-RTR-01",),
        voice_dhcp_activity=True,
        relay_broken_pool_id="DHCP-NYC-VOICE",
        pool_fill=(("DHCP-BLR-USERS", 47),),
        conflict_pool=("DHCP-SIN-USERS", 2),
        quiet_interfaces=("NYC-SW-01:Gi1/0/3",),
        impacted_services=(("NYC", PathService.DHCP),),
        events=(
            tpl(-200, "NYC-RTR-01", None, N, "CONFIG_CHANGE",
                "%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (10.10.99.10)"),
            tpl(-195, "NYC-RTR-01", "Gi0/0/1.20", I, "CONFIG_COMMAND_LOGGED",
                "%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin logged command:interface Gi0/0/1.20 ; no ip helper-address 10.100.100.21"),
            tpl(-190, "NYC-RTR-01", "Gi0/0/1.20", I, "CONFIG_COMMAND_LOGGED",
                "%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin logged command:interface Gi0/0/1.20 ; no ip helper-address 10.100.100.20"),
            tpl(-185, "NYC-RTR-01", "Gi0/0/1.10", I, "CONFIG_COMMAND_LOGGED",
                "%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin logged command:interface Gi0/0/1.10 ; no ip helper-address 10.100.100.21"),
            tpl(0, "NYC-SW-01", "Gi1/0/3", N, "POE_POWER_CYCLE",
                "%ILPOWER-5-IEEE_DISCONNECT: Interface Gi1/0/3: PD removed"),
            tpl(18, "NYC-SW-01", "Gi1/0/3", N, "POE_POWER_GRANTED",
                "%ILPOWER-5-POWER_GRANTED: Interface Gi1/0/3: Power granted"),
            tpl(-1000, DHCP_SERVER, None, W, "DHCP_POOL_UTILIZATION_HIGH",
                "kea-dhcp4: pool 10.30.10.100-10.30.10.149 (DHCP-BLR-USERS) utilization 94% exceeds warning threshold 90%"),
            tpl(-1080, DHCP_SERVER, None, W, "DHCP_ADDRESS_CONFLICT",
                "kea-dhcp4: DHCP4_DECLINE_LEASE address declined by client in pool DHCP-SIN-USERS; lease placed in conflict state"),
        ),
    ),
    AdvancedSpec(
        scenario_id="ADV-SIN-RADIUS-UDP-BLOCK",
        name="802.1X failure caused by a broad firewall UDP deny",
        description="A rule meant to stop UDP scanning from Singapore is placed above the RADIUS allow rule on the data "
                    "centre firewall; DNS and DHCP are permitted by earlier rules, but RADIUS from SIN-SW-01 is denied "
                    "and 802.1X fails on the Singapore user VLAN.",
        category=IncidentCategory.VLAN_AUTHENTICATION_FAILURE,
        incident=IncidentSpec(
            "Singapore wired desktops fail 802.1X authentication",
            "Singapore desktops report 'authentication failed' and have no network. IP phones work. A switch port "
            "change was made at the site this morning.",
            IncidentPriority.P2, 10, "Service Desk", ("SIN",),
            ("802.1X authentication failed", "IP phones unaffected", "Switch change made this morning",
             "Other branches unaffected"),
        ),
        root_cause="Rule FWR-DC1-0115 (BLOCK-APAC-UDP-SCAN), committed on DC1-FW-01 one minute before onset, denies all "
                   "UDP from 10.20.0.0/16 to 10.100.100.0/24 above the RADIUS allow rule FWR-DC1-0120; RADIUS requests "
                   "from SIN-SW-01 to DC1-SRV-AUTH-01 are dropped and 802.1X fails on Singapore user VLAN 10.",
        root_cause_device_ids=(DC_FIREWALL,),
        timed_rules=(
            (RuleSpec("FWR-DC1-0115", DC_FIREWALL, 115, "BLOCK-APAC-UDP-SCAN", DENY, UDP, "10.20.0.0/16", "10.100.100.0/24", None), -60),
        ),
        isolated_site_ids=("SIN",),
        impacted_services=(("SIN", PathService.AUTHENTICATION),),
        extra_flows=(
            (-700, DC_FIREWALL, "10.20.99.2", "10.100.100.30", UDP, 1645, 1812),
            (-300, DC_FIREWALL, "10.20.99.2", "10.100.100.30", UDP, 1645, 1812),
            (25, DC_FIREWALL, "10.20.99.2", "10.100.100.30", UDP, 1645, 1812),
            (40, DC_FIREWALL, "10.10.99.2", "10.100.100.30", UDP, 1645, 1812),
            (95, DC_FIREWALL, "10.20.99.2", "10.100.100.30", UDP, 1645, 1812),
            (180, DC_FIREWALL, "10.20.20.211", "10.100.100.10", UDP, 50211, 53),
            (260, DC_FIREWALL, "10.20.99.2", "10.100.100.30", UDP, 1645, 1812),
            (300, DC_FIREWALL, "10.30.99.2", "10.100.100.30", UDP, 1645, 1812),
            (430, DC_FIREWALL, "10.20.99.2", "10.100.100.30", UDP, 1645, 1812),
            (520, DC_FIREWALL, "10.20.20.1", "10.100.100.20", UDP, 67, 67),
            (610, DC_FIREWALL, "10.20.99.2", "10.100.100.30", UDP, 1645, 1812),
            (780, DC_FIREWALL, "10.20.99.2", "10.100.100.30", UDP, 1645, 1812),
            (960, DC_FIREWALL, "10.20.99.2", "10.100.100.30", UDP, 1645, 1812),
        ),
        events=(
            tpl(-840, "SIN-SW-01", None, N, "CONFIG_CHANGE",
                "%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (10.20.99.10)"),
            tpl(-835, "SIN-SW-01", "Gi1/0/2", I, "CONFIG_COMMAND_LOGGED",
                "%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin logged command:interface Gi1/0/2 ; description User port (802.1X) desk 4B"),
            tpl(-600, AUTH_SERVER, None, W, "CERTIFICATE_EXPIRY_WARNING",
                "radiusd: EAP server certificate CN=radius.corp.example.com expires in 29 days"),
            tpl(-60, DC_FIREWALL, None, N, "POLICY_CHANGE",
                "Security policy committed by 'secops': 1 rule added, 0 modified, 0 deleted (change ticket SEC-4502)"),
            tpl(30, "SIN-SW-01", "Gi1/0/1", W, "DOT1X_AUTH_FAILURE",
                "%DOT1X-5-FAIL: Authentication failed for client (02:00:14:0a:00:07) on Interface Gi1/0/1"),
            tpl(35, "SIN-SW-01", None, W, "RADIUS_SERVER_DEAD",
                "%RADIUS-4-RADIUS_DEAD: RADIUS server 10.100.100.30:1812,1813 is not responding"),
            tpl(42, "SIN-SW-01", "Gi1/0/2", W, "DOT1X_AUTH_FAILURE",
                "%DOT1X-5-FAIL: Authentication failed for client (02:00:14:0a:00:12) on Interface Gi1/0/2"),
            tpl(60, "SIN-SW-01", "Gi1/0/1", W, "PORT_UNAUTHORIZED",
                "%AUTHMGR-5-FAIL: Exhausted all authentication methods on Interface Gi1/0/1; port unauthorized in VLAN 10"),
            tpl(65, "SIN-SW-01", "Gi1/0/2", W, "PORT_UNAUTHORIZED",
                "%AUTHMGR-5-FAIL: Exhausted all authentication methods on Interface Gi1/0/2; port unauthorized in VLAN 10"),
            tpl(300, AUTH_SERVER, None, I, "SERVICE_HEALTH",
                "radiusd: 38 Access-Accept in the last 300 seconds from clients nyc-sw-01, blr-sw-01"),
        ),
    ),
)


def build() -> list[ScenarioDataset]:
    topology = build_topology()
    return [AdvancedSimulation(topology, spec, FIRST_INDEX + i).build() for i, spec in enumerate(SPECS)]


def validate(datasets: list[ScenarioDataset]) -> None:
    topology = load_topology()
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        shutil.copy(BACKEND / "app" / "network" / "data" / "topology.json", data_dir / "topology.json")
        (data_dir / "scenarios").mkdir()
        for dataset in datasets:
            errors = find_reference_errors(topology, dataset)
            if errors:
                raise SystemExit(f"{dataset.scenario.scenario_id}: {'; '.join(errors)}")
            shutil.copy(OUTPUT_DIR / f"{dataset.scenario.scenario_id}.json", data_dir / "scenarios")
            load_scenario.cache_clear()
            reloaded = load_scenario(dataset.scenario.scenario_id, data_dir)
            assert reloaded == dataset, dataset.scenario.scenario_id


def main() -> None:
    datasets = build()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for dataset in datasets:
        (OUTPUT_DIR / f"{dataset.scenario.scenario_id}.json").write_text(to_json(dataset), encoding="utf-8", newline="\n")
    validate(datasets)
    for dataset in datasets:
        print(dataset.scenario.scenario_id, dataset.incident.incident_id, len(dataset.events), "events",
              len(dataset.interface_statistics), "samples", len(dataset.firewall.events), "fw",
              len(dataset.dhcp.events), "dhcp", len(dataset.dns.queries), "dns")


if __name__ == "__main__":
    sys.exit(main())
