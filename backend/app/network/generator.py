import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import NamedTuple

from pydantic import BaseModel

from app.network.models import (
    BgpNeighbor,
    BgpState,
    Device,
    DeviceRelationship,
    DeviceRole,
    DeviceType,
    DhcpData,
    DhcpEvent,
    DhcpEventType,
    DhcpLease,
    DhcpPool,
    DnsData,
    DnsQuery,
    DnsRecordType,
    DnsResult,
    DnsServer,
    DnsServerRole,
    FirewallAction,
    FirewallData,
    FirewallEvent,
    FirewallRule,
    GroundTruth,
    IncidentCategory,
    IncidentPriority,
    IncidentRecord,
    IncidentStatus,
    Interface,
    InterfaceMode,
    InterfaceStatistics,
    LeaseState,
    Link,
    LinkStatus,
    LinkType,
    NetworkEvent,
    NetworkPath,
    NetworkTopology,
    OspfNeighbor,
    OspfState,
    PathService,
    RelationshipType,
    RouteChange,
    RouteChangeType,
    RouteEntry,
    RoutingData,
    RoutingProtocol,
    RoutingTable,
    ScenarioDataset,
    ScenarioInfo,
    Severity,
    Site,
    SiteType,
    TransportProtocol,
    Vlan,
    device_of,
    match_firewall_rule,
)
from app.network.graph import breadth_first, build_adjacency, orient, shortest_path
from app.network.repository import DATA_DIR, SCENARIOS_DIR, TOPOLOGY_FILE

FIRST_ONSET = datetime(2026, 3, 2, 9, 0, tzinfo=timezone.utc)
HALF_WINDOW = timedelta(minutes=20)
SAMPLE_INTERVAL_SECONDS = 600
SAMPLE_OFFSETS_MINUTES = (-15, -5, 5, 15)
ACTIVITY_OFFSETS_MINUTES = (-18, -13, -8, -3, 2, 7, 12, 17)
RULE_BASELINE_TIME = datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)

CORE_ASN = 65000
DEFAULT_ROUTE = IPv4Network("0.0.0.0/0")
INTERNET_GATEWAY = IPv4Address("203.0.113.1")
INTERNET_EDGE = "CORE-FW-01"
INTERNET_EDGE_INTERFACE = "CORE-FW-01:ethernet1/1"
DC_FIREWALL = "DC1-FW-01"
METRO_LINK = "LNK-CORE-DC1-METRO"
ADMIN_DISTANCE = {
    RoutingProtocol.CONNECTED: 0,
    RoutingProtocol.STATIC: 1,
    RoutingProtocol.BGP: 20,
    RoutingProtocol.OSPF: 110,
}

DNS_PRIMARY = "DC1-SRV-DNS-01"
DNS_SECONDARY = "DC1-SRV-DNS-02"
DHCP_SERVER = "DC1-SRV-DHCP-01"
AUTH_SERVER = "DC1-SRV-AUTH-01"
APP_SERVER = "DC1-SRV-APP-01"
SERVERS = (
    (DNS_PRIMARY, DeviceRole.DNS_SERVER, "10.100.100.10", "Ubuntu 22.04 LTS / BIND 9.18"),
    (DNS_SECONDARY, DeviceRole.DNS_SERVER, "10.100.100.11", "Ubuntu 22.04 LTS / BIND 9.18"),
    (DHCP_SERVER, DeviceRole.DHCP_SERVER, "10.100.100.20", "Ubuntu 22.04 LTS / Kea DHCP 2.4"),
    (AUTH_SERVER, DeviceRole.AUTHENTICATION_SERVER, "10.100.100.30", "Ubuntu 22.04 LTS / FreeRADIUS 3.2"),
    (APP_SERVER, DeviceRole.APPLICATION_SERVER, "10.100.100.40", "RHEL 9.3 / ERP 12.4"),
)
SERVER_IP = {device_id: IPv4Address(address) for device_id, _, address, _ in SERVERS}
SERVICE_TARGETS = {
    PathService.APPLICATION: APP_SERVER,
    PathService.AUTHENTICATION: AUTH_SERVER,
    PathService.DHCP: DHCP_SERVER,
    PathService.DNS: DNS_PRIMARY,
    PathService.INTERNET: INTERNET_EDGE,
}

INTERNAL_ZONE = "corp.example.com"
MISSING_DOMAIN = "printer-07.corp.example.com"
DNS_RECORDS = {
    "erp.corp.example.com": "10.100.100.40",
    "files.corp.example.com": "10.100.100.55",
    "intranet.corp.example.com": "10.100.100.45",
    "mail.corp.example.com": "10.100.100.50",
    "updates.example.net": "203.0.113.80",
    "www.example.org": "198.51.100.80",
}


@dataclass(frozen=True)
class Branch:
    site_id: str
    name: str
    city: str
    country: str
    octet: int
    core_interface_id: str
    wan_subnet: str
    protocol: RoutingProtocol
    asn: int | None
    latency_ms: float
    provider: str
    circuit_id: str

    @property
    def router_id(self) -> str:
        return f"{self.site_id}-RTR-01"

    @property
    def switch_id(self) -> str:
        return f"{self.site_id}-SW-01"

    @property
    def wan_link_id(self) -> str:
        return f"LNK-WAN-{self.site_id}"


BRANCHES = (
    Branch("NYC", "New York Branch", "New York", "United States", 10, "CORE-RTR-01:Gi0/0/2", "172.16.0.0/30",
           RoutingProtocol.BGP, 65010, 74.0, "Carrier A", "WAN-NYC-0001"),
    Branch("SIN", "Singapore Branch", "Singapore", "Singapore", 20, "CORE-RTR-01:Gi0/0/3", "172.16.0.4/30",
           RoutingProtocol.BGP, 65020, 168.0, "Carrier B", "WAN-SIN-0001"),
    Branch("BLR", "Bengaluru Branch", "Bengaluru", "India", 30, "CORE-RTR-02:Gi0/0/2", "172.16.0.8/30",
           RoutingProtocol.OSPF, None, 132.0, "Carrier C", "WAN-BLR-0001"),
)
BRANCH_VLANS = ((10, "USERS"), (20, "VOICE"), (99, "MGMT"))
DHCP_SCOPES = ((10, "USERS", 100, 149, 8), (20, "VOICE", 200, 219, 24))


class RuleSpec(NamedTuple):
    rule_id: str
    device_id: str
    priority: int
    name: str
    action: FirewallAction
    protocol: TransportProtocol | None
    source: str
    destination: str
    port: int | None


BASELINE_RULES = (
    RuleSpec("FWR-DC1-0100", DC_FIREWALL, 100, "ALLOW-DNS", FirewallAction.ALLOW, TransportProtocol.UDP, "10.0.0.0/8", "10.100.100.10/31", 53),
    RuleSpec("FWR-DC1-0110", DC_FIREWALL, 110, "ALLOW-DHCP-RELAY", FirewallAction.ALLOW, TransportProtocol.UDP, "10.0.0.0/8", "10.100.100.20/32", 67),
    RuleSpec("FWR-DC1-0120", DC_FIREWALL, 120, "ALLOW-RADIUS", FirewallAction.ALLOW, TransportProtocol.UDP, "10.0.0.0/8", "10.100.100.30/32", 1812),
    RuleSpec("FWR-DC1-0130", DC_FIREWALL, 130, "ALLOW-ERP-HTTPS", FirewallAction.ALLOW, TransportProtocol.TCP, "10.0.0.0/8", "10.100.100.40/32", 443),
    RuleSpec("FWR-DC1-9999", DC_FIREWALL, 9999, "DENY-ALL", FirewallAction.DENY, None, "0.0.0.0/0", "0.0.0.0/0", None),
    RuleSpec("FWR-CORE-0100", INTERNET_EDGE, 100, "ALLOW-WEB-OUTBOUND", FirewallAction.ALLOW, TransportProtocol.TCP, "10.0.0.0/8", "0.0.0.0/0", 443),
    RuleSpec("FWR-CORE-9999", INTERNET_EDGE, 9999, "DENY-ALL", FirewallAction.DENY, None, "0.0.0.0/0", "0.0.0.0/0", None),
)

BACKGROUND_EVENTS = {
    DeviceType.ROUTER: (
        ("NTP_SYNC", Severity.NOTICE, "%NTP-5-PEERSYNC: NTP synced to peer 10.255.0.250"),
        ("LOGIN_SUCCESS", Severity.NOTICE, "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: netops] [Source: 10.255.0.200]"),
        ("CONFIG_ARCHIVED", Severity.INFORMATIONAL, "%ARCHIVE-6-CONFIG_SAVED: Running configuration archived"),
    ),
    DeviceType.SWITCH: (
        ("NTP_SYNC", Severity.NOTICE, "%NTP-5-PEERSYNC: NTP synced to peer 10.255.0.250"),
        ("LOGIN_SUCCESS", Severity.NOTICE, "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: netops] [Source: 10.255.0.200]"),
        ("STP_STABLE", Severity.INFORMATIONAL, "%SPANTREE-6-TOPOLOGY_STABLE: Spanning tree topology stable on all VLANs"),
    ),
    DeviceType.FIREWALL: (
        ("SYSTEM_HEALTH", Severity.INFORMATIONAL, "System health check passed: dataplane CPU 21%, session table 18%"),
        ("CONTENT_UPDATE", Severity.INFORMATIONAL, "Threat content update installed successfully"),
        ("ADMIN_LOGIN", Severity.NOTICE, "Administrator 'fwadmin' logged in via HTTPS from 10.255.0.200"),
    ),
    DeviceType.SERVER: (
        ("SERVICE_HEALTH", Severity.INFORMATIONAL, "Service health check passed"),
        ("BACKUP_COMPLETED", Severity.INFORMATIONAL, "Configuration backup completed and verified"),
        ("LOGIN_SUCCESS", Severity.NOTICE, "sshd: Accepted publickey for ops from 10.255.0.200"),
    ),
}


class EventTemplate(NamedTuple):
    offset_seconds: int
    device_id: str
    interface_name: str | None
    severity: Severity
    event_type: str
    message: str


class IncidentSpec(NamedTuple):
    title: str
    description: str
    priority: IncidentPriority
    reported_after_minutes: int
    reported_by: str
    affected_site_ids: tuple[str, ...]
    symptoms: tuple[str, ...]


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    name: str
    description: str
    category: IncidentCategory | None = None
    incident: IncidentSpec | None = None
    root_cause: str | None = None
    root_cause_device_ids: tuple[str, ...] = ()
    root_cause_link_ids: tuple[str, ...] = ()
    down_link_ids: tuple[str, ...] = ()
    down_device_ids: tuple[str, ...] = ()
    failed_adjacency_link_ids: tuple[str, ...] = ()
    degraded_link_ids: tuple[str, ...] = ()
    isolated_site_ids: tuple[str, ...] = ()
    added_rules: tuple[RuleSpec, ...] = ()
    exhausted_pool_id: str | None = None
    failed_dns_server_id: str | None = None
    impacted_services: tuple[tuple[str, PathService], ...] = ()
    events: tuple[EventTemplate, ...] = ()


SCENARIOS = (
    ScenarioSpec(
        scenario_id="BASELINE",
        name="Healthy baseline",
        description="Normal operation across all sites with no active incident.",
    ),
    ScenarioSpec(
        scenario_id="WAN-FAILURE",
        name="WAN connectivity failure",
        description="The Singapore WAN circuit loses signal and the branch is isolated from the core.",
        category=IncidentCategory.WAN_CONNECTIVITY_FAILURE,
        incident=IncidentSpec(
            "Singapore office cannot reach any corporate service",
            "All users in the Singapore branch report that ERP, e-mail and internet access stopped working.",
            IncidentPriority.P1, 8, "Service Desk", ("SIN",),
            ("No access to ERP", "No internet access", "Branch router unreachable from monitoring"),
        ),
        root_cause="Carrier B circuit WAN-SIN-0001 lost signal; LNK-WAN-SIN is down and the BGP session "
                   "between SIN-RTR-01 and CORE-RTR-01 failed, withdrawing all Singapore routes.",
        root_cause_device_ids=("SIN-RTR-01",),
        root_cause_link_ids=("LNK-WAN-SIN",),
        down_link_ids=("LNK-WAN-SIN",),
        events=(
            EventTemplate(0, "SIN-RTR-01", "Gi0/0/0", Severity.ERROR, "CARRIER_LOSS",
                          "%ETHPORT-3-IF_DOWN_LINK_FAILURE: Interface Gi0/0/0 is down (loss of signal)"),
            EventTemplate(60, "SIN-RTR-01", "Gi0/0/0", Severity.WARNING, "WAN_PROBE_FAILURE",
                          "%TRACK-6-STATE: 10 ip sla 10 reachability Up -> Down (target 172.16.0.5)"),
        ),
    ),
    ScenarioSpec(
        scenario_id="PACKET-LOSS",
        name="Packet loss on WAN circuit",
        description="The New York WAN circuit degrades with CRC errors, packet loss and high latency.",
        category=IncidentCategory.PACKET_LOSS,
        incident=IncidentSpec(
            "New York users report slow applications and choppy calls",
            "Users in New York report that ERP pages load slowly and voice calls drop intermittently.",
            IncidentPriority.P2, 12, "Service Desk", ("NYC",),
            ("Slow ERP response", "Choppy voice calls", "Slow name resolution"),
        ),
        root_cause="Physical degradation on Carrier A circuit WAN-NYC-0001 causes CRC errors, about 11% "
                   "packet loss and roughly 85 ms of additional latency on LNK-WAN-NYC.",
        root_cause_device_ids=("NYC-RTR-01",),
        root_cause_link_ids=("LNK-WAN-NYC",),
        degraded_link_ids=("LNK-WAN-NYC",),
        events=(
            EventTemplate(120, "NYC-RTR-01", "Gi0/0/0", Severity.WARNING, "INTERFACE_ERRORS",
                          "%INTERFACE-4-ERRORS: Gi0/0/0 input errors increased by 2140 in 600 seconds (CRC 1980)"),
            EventTemplate(180, "CORE-RTR-01", "Gi0/0/2", Severity.WARNING, "INTERFACE_ERRORS",
                          "%INTERFACE-4-ERRORS: Gi0/0/2 input errors increased by 1875 in 600 seconds (CRC 1712)"),
            EventTemplate(240, "NYC-RTR-01", "Gi0/0/0", Severity.WARNING, "SLA_THRESHOLD_EXCEEDED",
                          "%SLA-4-THRESHOLD: ip sla 20 packet loss 11% exceeds threshold 2% (target 172.16.0.1)"),
        ),
    ),
    ScenarioSpec(
        scenario_id="OSPF-ADJACENCY-FAILURE",
        name="OSPF adjacency failure",
        description="An MTU change on the Bengaluru WAN edge leaves the OSPF adjacency stuck in EXSTART.",
        category=IncidentCategory.OSPF_ADJACENCY_FAILURE,
        incident=IncidentSpec(
            "Bengaluru office lost access to data centre applications",
            "Bengaluru users cannot reach ERP or the internet although the WAN circuit shows as up.",
            IncidentPriority.P1, 10, "Network Operations Centre", ("BLR",),
            ("No access to ERP", "No internet access", "WAN circuit reported up by carrier"),
        ),
        root_cause="The IP MTU on BLR-RTR-01 Gi0/0/0 was changed to 1400 while CORE-RTR-02 Gi0/0/2 uses 1500; "
                   "the OSPF area 10 adjacency is stuck in EXSTART and all routes between Bengaluru and the core were withdrawn.",
        root_cause_device_ids=("BLR-RTR-01", "CORE-RTR-02"),
        root_cause_link_ids=("LNK-WAN-BLR",),
        failed_adjacency_link_ids=("LNK-WAN-BLR",),
        events=(
            EventTemplate(-5, "BLR-RTR-01", None, Severity.NOTICE, "CONFIG_CHANGE",
                          "%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (10.30.99.10)"),
            EventTemplate(0, "BLR-RTR-01", "Gi0/0/0", Severity.INFORMATIONAL, "MTU_CHANGE",
                          "Interface Gi0/0/0 IP MTU changed from 1500 to 1400"),
            EventTemplate(90, "CORE-RTR-02", "Gi0/0/2", Severity.WARNING, "OSPF_MTU_MISMATCH",
                          "OSPF neighbor 10.255.1.30 on Gi0/0/2 stuck in EXSTART: DBD MTU 1400 does not match interface MTU 1500"),
        ),
    ),
    ScenarioSpec(
        scenario_id="FIREWALL-BLOCKING",
        name="Firewall blocking application traffic",
        description="A new data centre firewall rule unintentionally denies HTTPS from Singapore to the server VLAN.",
        category=IncidentCategory.FIREWALL_BLOCKING,
        incident=IncidentSpec(
            "Singapore users cannot open the ERP portal",
            "ERP times out for Singapore users while internet access and other sites work normally.",
            IncidentPriority.P2, 9, "Service Desk", ("SIN",),
            ("ERP portal connection timeout", "Internet access works", "Other branches unaffected"),
        ),
        root_cause="Rule FWR-DC1-0125 (BLOCK-APAC-LEGACY-WEB), committed on DC1-FW-01 at incident onset, denies TCP 443 "
                   "from 10.20.0.0/16 to 10.100.100.0/24 ahead of the ERP allow rule.",
        root_cause_device_ids=(DC_FIREWALL,),
        added_rules=(
            RuleSpec("FWR-DC1-0125", DC_FIREWALL, 125, "BLOCK-APAC-LEGACY-WEB", FirewallAction.DENY,
                     TransportProtocol.TCP, "10.20.0.0/16", "10.100.100.0/24", 443),
        ),
        impacted_services=(("SIN", PathService.APPLICATION),),
        events=(
            EventTemplate(0, DC_FIREWALL, None, Severity.NOTICE, "POLICY_CHANGE",
                          "Security policy committed by 'fwadmin': rule BLOCK-APAC-LEGACY-WEB added at priority 125 "
                          "(deny tcp 10.20.0.0/16 -> 10.100.100.0/24:443)"),
        ),
    ),
    ScenarioSpec(
        scenario_id="DHCP-ALLOCATION-FAILURE",
        name="DHCP allocation failure",
        description="The Bengaluru user DHCP scope is exhausted and new clients receive no address.",
        category=IncidentCategory.DHCP_ALLOCATION_FAILURE,
        incident=IncidentSpec(
            "New laptops in Bengaluru cannot obtain an IP address",
            "Recently connected laptops in Bengaluru show a self-assigned address; existing users are unaffected.",
            IncidentPriority.P3, 14, "Service Desk", ("BLR",),
            ("Self-assigned 169.254.x.x address", "Existing users unaffected", "Only wired user VLAN affected"),
        ),
        root_cause="DHCP pool DHCP-BLR-USERS on DC1-SRV-DHCP-01 is exhausted: all 50 addresses are leased and two "
                   "are held in conflict state after DHCPDECLINE.",
        root_cause_device_ids=(DHCP_SERVER,),
        exhausted_pool_id="DHCP-BLR-USERS",
        impacted_services=(("BLR", PathService.DHCP),),
        events=(
            EventTemplate(0, DHCP_SERVER, None, Severity.WARNING, "DHCP_POOL_EXHAUSTED",
                          "kea-dhcp4: ALLOC_ENGINE_V4_ALLOC_FAIL no free addresses in pool "
                          "10.30.10.100-10.30.10.149 (DHCP-BLR-USERS)"),
        ),
    ),
    ScenarioSpec(
        scenario_id="DNS-RESOLUTION-FAILURE",
        name="DNS resolution failure",
        description="The primary DNS server fails to load the internal zone and returns SERVFAIL for internal names.",
        category=IncidentCategory.DNS_RESOLUTION_FAILURE,
        incident=IncidentSpec(
            "Users cannot reach internal sites by name",
            "Users at all branches report that internal web sites and ERP fail to open by name; internet sites work.",
            IncidentPriority.P2, 11, "Service Desk", ("NYC", "SIN", "BLR"),
            ("Internal host names do not resolve", "Internet sites work", "Access by IP address works"),
        ),
        root_cause="After a reload, DC1-SRV-DNS-01 failed to load zone corp.example.com (truncated zone file) and "
                   "returns SERVFAIL for all internal names.",
        root_cause_device_ids=(DNS_PRIMARY,),
        failed_dns_server_id=DNS_PRIMARY,
        impacted_services=tuple((branch.site_id, PathService.DNS) for branch in BRANCHES),
        events=(
            EventTemplate(-10, DNS_PRIMARY, None, Severity.NOTICE, "ZONE_RELOAD",
                          "named[1123]: received control channel command 'reload corp.example.com'"),
            EventTemplate(0, DNS_PRIMARY, None, Severity.ERROR, "ZONE_LOAD_FAILURE",
                          "named[1123]: zone corp.example.com/IN: loading from master file corp.example.com.db failed: "
                          "unexpected end of input"),
            EventTemplate(5, DNS_PRIMARY, None, Severity.ERROR, "ZONE_NOT_LOADED",
                          "named[1123]: zone corp.example.com/IN: not loaded due to errors"),
            EventTemplate(90, APP_SERVER, None, Severity.WARNING, "DNS_LOOKUP_FAILURE",
                          "erp-app: lookup of db.corp.example.com failed: SERVFAIL"),
        ),
    ),
    ScenarioSpec(
        scenario_id="VLAN-AUTHENTICATION-FAILURE",
        name="VLAN authentication failure",
        description="802.1X authentication fails on the New York user VLAN after a RADIUS key change on the access switch.",
        category=IncidentCategory.VLAN_AUTHENTICATION_FAILURE,
        incident=IncidentSpec(
            "New York users cannot connect wired desktops to the network",
            "Wired desktops in New York show 'authentication failed' and get no network access; phones work.",
            IncidentPriority.P2, 10, "Service Desk", ("NYC",),
            ("802.1X authentication failed", "No network on wired desktops", "IP phones unaffected"),
        ),
        root_cause="The RADIUS shared secret on NYC-SW-01 was changed during maintenance and no longer matches "
                   "DC1-SRV-AUTH-01; 802.1X on user VLAN 10 fails and ports remain unauthorized.",
        root_cause_device_ids=("NYC-SW-01", AUTH_SERVER),
        isolated_site_ids=("NYC",),
        impacted_services=(("NYC", PathService.AUTHENTICATION),),
        events=(
            EventTemplate(-5, "NYC-SW-01", None, Severity.NOTICE, "CONFIG_CHANGE",
                          "%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (10.10.99.10)"),
            EventTemplate(20, "NYC-SW-01", "Gi1/0/1", Severity.WARNING, "DOT1X_AUTH_FAILURE",
                          "%DOT1X-5-FAIL: Authentication failed for client (02:00:0a:0a:00:05) on Interface Gi1/0/1"),
            EventTemplate(21, AUTH_SERVER, None, Severity.WARNING, "RADIUS_INVALID_AUTHENTICATOR",
                          "radiusd: Dropping packet from client nyc-sw-01 (10.10.99.2): invalid Message-Authenticator "
                          "(shared secret is incorrect)"),
            EventTemplate(25, "NYC-SW-01", "Gi1/0/2", Severity.WARNING, "DOT1X_AUTH_FAILURE",
                          "%DOT1X-5-FAIL: Authentication failed for client (02:00:0a:0a:00:11) on Interface Gi1/0/2"),
            EventTemplate(30, "NYC-SW-01", "Gi1/0/1", Severity.WARNING, "PORT_UNAUTHORIZED",
                          "%AUTHMGR-5-FAIL: Exhausted all authentication methods on Interface Gi1/0/1; port unauthorized in VLAN 10"),
            EventTemplate(35, "NYC-SW-01", None, Severity.WARNING, "RADIUS_SERVER_DEAD",
                          "%RADIUS-4-RADIUS_DEAD: RADIUS server 10.100.100.30:1812,1813 is not responding"),
        ),
    ),
    ScenarioSpec(
        scenario_id="SHARED-DEVICE-FAILURE",
        name="Shared core router failure",
        description="CORE-RTR-01 loses both power supplies, cutting the New York and Singapore paths that share it.",
        category=IncidentCategory.SHARED_DEVICE_FAILURE,
        incident=IncidentSpec(
            "New York and Singapore offices are both offline",
            "Two branches lost all corporate and internet connectivity at the same time; Bengaluru is unaffected.",
            IncidentPriority.P1, 6, "Network Operations Centre", ("NYC", "SIN"),
            ("Two branches offline simultaneously", "Bengaluru unaffected", "Core router not responding to monitoring"),
        ),
        root_cause="CORE-RTR-01 shut down after both power entry modules failed; it is the shared WAN aggregation "
                   "point for the New York and Singapore branches.",
        root_cause_device_ids=("CORE-RTR-01",),
        down_device_ids=("CORE-RTR-01",),
        events=(
            EventTemplate(-30, "CORE-RTR-01", None, Severity.CRITICAL, "POWER_SUPPLY_FAILURE",
                          "%IOSXE_PEM-3-PEMFAIL: The PEM in slot P0 is switched off or encountering a failure condition"),
            EventTemplate(-5, "CORE-RTR-01", None, Severity.EMERGENCY, "SYSTEM_SHUTDOWN",
                          "%IOSXE_PEM-3-PEMFAIL: The PEM in slot P1 is encountering a failure condition; system shutting down"),
        ),
    ),
)


def prefix_key(prefix: IPv4Network) -> tuple[int, int]:
    return int(prefix.network_address), prefix.prefixlen


class TopologyBuilder:
    def __init__(self) -> None:
        self.sites: list[Site] = []
        self.devices: list[Device] = []
        self.interfaces: dict[str, Interface] = {}
        self.links: list[Link] = []
        self.vlans: list[Vlan] = []
        self.relationships: list[DeviceRelationship] = []

    def add_device(self, device_id: str, device_type: DeviceType, role: DeviceRole, site_id: str, vendor: str,
                   model: str, os_version: str, management_ip: str, router_id: str | None = None,
                   bgp_asn: int | None = None) -> None:
        self.devices.append(Device(
            device_id=device_id, hostname=device_id.lower(), device_type=device_type, role=role, site_id=site_id,
            vendor=vendor, model=model, os_version=os_version, management_ip=management_ip, router_id=router_id,
            bgp_asn=bgp_asn,
        ))

    def add_interface(self, device_id: str, name: str, mode: InterfaceMode, speed_mbps: int, description: str,
                      ip_address: str | None = None, vlan_ids: tuple[int, ...] = ()) -> str:
        interface = Interface(
            interface_id=f"{device_id}:{name}", device_id=device_id, name=name, mode=mode, description=description,
            ip_address=ip_address, speed_mbps=speed_mbps, mtu=1500, vlan_ids=list(vlan_ids),
        )
        self.interfaces[interface.interface_id] = interface
        return interface.interface_id

    def add_link(self, link_id: str, link_type: LinkType, a_interface_id: str, b_interface_id: str,
                 bandwidth_mbps: int, latency_ms: float, routing_protocol: RoutingProtocol | None = None,
                 ospf_area: str | None = None, provider: str | None = None, circuit_id: str | None = None) -> None:
        self.links.append(Link(
            link_id=link_id, link_type=link_type, a_interface_id=a_interface_id, b_interface_id=b_interface_id,
            bandwidth_mbps=bandwidth_mbps, latency_ms=latency_ms, routing_protocol=routing_protocol,
            ospf_area=ospf_area, provider=provider, circuit_id=circuit_id,
        ))

    def add_routed_link(self, link_id: str, link_type: LinkType, a_interface_id: str, b_interface_id: str,
                        subnet: str, speed_mbps: int, latency_ms: float, routing_protocol: RoutingProtocol,
                        ospf_area: str | None = None, bandwidth_mbps: int | None = None,
                        provider: str | None = None, circuit_id: str | None = None) -> None:
        network = IPv4Network(subnet)
        hosts = list(network.hosts())
        for interface_id, peer_id, address in ((a_interface_id, b_interface_id, hosts[0]), (b_interface_id, a_interface_id, hosts[1])):
            device_id, name = interface_id.split(":", 1)
            self.add_interface(device_id, name, InterfaceMode.ROUTED, speed_mbps, f"To {peer_id}",
                               f"{address}/{network.prefixlen}")
        self.add_link(link_id, link_type, a_interface_id, b_interface_id, bandwidth_mbps or speed_mbps, latency_ms,
                      routing_protocol, ospf_area, provider, circuit_id)

    def add_vlan(self, site_id: str, vlan_id: int, name: str, gateway_interface_id: str) -> None:
        gateway = self.interfaces[gateway_interface_id].ip_address
        self.vlans.append(Vlan(
            segment_id=f"{site_id}-VLAN{vlan_id}", site_id=site_id, vlan_id=vlan_id, name=name,
            subnet=gateway.network, gateway=gateway.ip, gateway_interface_id=gateway_interface_id,
        ))

    def relate(self, source: str, target: str, relationship_type: RelationshipType, description: str) -> None:
        self.relationships.append(DeviceRelationship(
            source_device_id=source, target_device_id=target, relationship_type=relationship_type,
            description=description,
        ))

    def build_paths(self) -> list[NetworkPath]:
        adjacency = build_adjacency(self.links)
        paths = []
        for branch in BRANCHES:
            for service, target in SERVICE_TARGETS.items():
                device_ids, link_ids = shortest_path(adjacency, branch.switch_id, target)
                paths.append(NetworkPath(
                    path_id=f"PATH-{branch.site_id}-{service.name}", name=f"{branch.name} {service.value} path to {target}",
                    service=service, source_site_id=branch.site_id, device_ids=device_ids, link_ids=link_ids,
                ))
        return paths

    def build(self) -> NetworkTopology:
        return NetworkTopology(
            sites=self.sites, devices=self.devices, interfaces=list(self.interfaces.values()), links=self.links,
            vlans=self.vlans, relationships=self.relationships, paths=self.build_paths(),
        )


def build_topology() -> NetworkTopology:
    builder = TopologyBuilder()
    builder.sites.append(Site(site_id="CORE", name="London Core Network", site_type=SiteType.CORE,
                              city="London", country="United Kingdom"))
    builder.sites.append(Site(site_id="DC1", name="Slough Data Centre", site_type=SiteType.DATA_CENTRE,
                              city="Slough", country="United Kingdom"))

    for index, device_id in enumerate(("CORE-RTR-01", "CORE-RTR-02"), start=1):
        builder.add_device(device_id, DeviceType.ROUTER, DeviceRole.CORE_ROUTER, "CORE", "Cisco", "ASR 1001-X",
                           "IOS XE 17.9.4a", f"10.255.0.{index}", f"10.255.0.{index}", CORE_ASN)
    builder.add_device("CORE-SW-01", DeviceType.SWITCH, DeviceRole.CORE_SWITCH, "CORE", "Cisco",
                       "Catalyst 9500-24Y4C", "IOS XE 17.9.4a", "10.255.0.3", "10.255.0.3")
    builder.add_device(INTERNET_EDGE, DeviceType.FIREWALL, DeviceRole.PERIMETER_FIREWALL, "CORE",
                       "Palo Alto Networks", "PA-3220", "PAN-OS 10.2.7", "10.255.0.4")
    builder.add_device(DC_FIREWALL, DeviceType.FIREWALL, DeviceRole.DATA_CENTRE_FIREWALL, "DC1",
                       "Palo Alto Networks", "PA-3220", "PAN-OS 10.2.7", "10.255.0.5")
    builder.add_device("DC1-SW-01", DeviceType.SWITCH, DeviceRole.DISTRIBUTION_SWITCH, "DC1", "Cisco",
                       "Catalyst 9300-48T", "IOS XE 17.9.4a", "10.255.0.6", "10.255.0.6")

    ospf, static = RoutingProtocol.OSPF, RoutingProtocol.STATIC
    builder.add_routed_link("LNK-CORE-RTR01-SW01", LinkType.LAN, "CORE-RTR-01:Te0/0/0", "CORE-SW-01:Te1/0/1",
                            "10.0.0.0/30", 10000, 0.2, ospf, "0")
    builder.add_routed_link("LNK-CORE-RTR02-SW01", LinkType.LAN, "CORE-RTR-02:Te0/0/0", "CORE-SW-01:Te1/0/2",
                            "10.0.0.4/30", 10000, 0.2, ospf, "0")
    builder.add_routed_link("LNK-CORE-RTR01-RTR02", LinkType.LAN, "CORE-RTR-01:Te0/0/1", "CORE-RTR-02:Te0/0/1",
                            "10.0.0.8/30", 10000, 0.2, ospf, "0")
    builder.add_routed_link("LNK-CORE-SW01-FW01", LinkType.LAN, "CORE-SW-01:Te1/0/3", "CORE-FW-01:ethernet1/2",
                            "10.0.0.12/30", 10000, 0.2, static)
    builder.add_routed_link(METRO_LINK, LinkType.METRO, "CORE-SW-01:Te1/0/4", "DC1-FW-01:ethernet1/1",
                            "10.0.0.16/30", 10000, 1.8, static, provider="Metro Fibre", circuit_id="MET-DC1-0001")
    builder.add_routed_link("LNK-DC1-FW01-SW01", LinkType.LAN, "DC1-FW-01:ethernet1/2", "DC1-SW-01:Te1/1/1",
                            "10.0.0.20/30", 10000, 0.2, static)
    builder.add_interface(INTERNET_EDGE, "ethernet1/1", InterfaceMode.ROUTED, 1000, "Internet uplink", "203.0.113.2/29")

    server_gateway = builder.add_interface("DC1-SW-01", "Vlan100", InterfaceMode.VIRTUAL, 1000,
                                           "Server VLAN gateway", "10.100.100.1/24", (100,))
    builder.add_vlan("DC1", 100, "SERVERS", server_gateway)
    for port, (device_id, role, address, os_version) in enumerate(SERVERS, start=1):
        builder.add_device(device_id, DeviceType.SERVER, role, "DC1", "Dell", "PowerEdge R650", os_version, address)
        server_nic = builder.add_interface(device_id, "eth0", InterfaceMode.ROUTED, 1000, "Primary NIC", f"{address}/24")
        switch_port = builder.add_interface("DC1-SW-01", f"Gi1/0/{port}", InterfaceMode.ACCESS, 1000,
                                            f"Server {device_id}", vlan_ids=(100,))
        builder.add_link(f"LNK-{device_id}", LinkType.LAN, switch_port, server_nic, 1000, 0.1)
        builder.relate(device_id, "DC1-SW-01", RelationshipType.UPSTREAM, "Server access uplink")

    for branch in BRANCHES:
        site, octet = branch.site_id, branch.octet
        builder.sites.append(Site(site_id=site, name=branch.name, site_type=SiteType.BRANCH,
                                  city=branch.city, country=branch.country))
        builder.add_device(branch.router_id, DeviceType.ROUTER, DeviceRole.WAN_EDGE, site, "Cisco", "ISR 4331",
                           "IOS XE 17.6.5", f"10.{octet}.99.1", f"10.255.1.{octet}", branch.asn)
        builder.add_device(branch.switch_id, DeviceType.SWITCH, DeviceRole.ACCESS_SWITCH, site, "Cisco",
                           "Catalyst 9200-24P", "IOS XE 17.6.5", f"10.{octet}.99.2")
        builder.add_routed_link(
            branch.wan_link_id, LinkType.WAN, branch.core_interface_id, f"{branch.router_id}:Gi0/0/0",
            branch.wan_subnet, 1000, branch.latency_ms, branch.protocol,
            "10" if branch.protocol == RoutingProtocol.OSPF else None, 200, branch.provider, branch.circuit_id,
        )
        trunk_vlans = tuple(vlan_id for vlan_id, _ in BRANCH_VLANS)
        router_trunk = builder.add_interface(branch.router_id, "Gi0/0/1", InterfaceMode.TRUNK, 1000,
                                             f"Trunk to {branch.switch_id}", vlan_ids=trunk_vlans)
        switch_trunk = builder.add_interface(branch.switch_id, "Gi1/0/24", InterfaceMode.TRUNK, 1000,
                                             f"Trunk to {branch.router_id}", vlan_ids=trunk_vlans)
        builder.add_link(f"LNK-{site}-RTR01-SW01", LinkType.LAN, router_trunk, switch_trunk, 1000, 0.1)
        for vlan_id, name in BRANCH_VLANS:
            gateway = builder.add_interface(branch.router_id, f"Gi0/0/1.{vlan_id}", InterfaceMode.VIRTUAL, 1000,
                                            f"{name} VLAN gateway", f"10.{octet}.{vlan_id}.1/24", (vlan_id,))
            builder.add_vlan(site, vlan_id, name, gateway)
        for port, vlan_id, description in (("Gi1/0/1", 10, "User port (802.1X)"), ("Gi1/0/2", 10, "User port (802.1X)"),
                                           ("Gi1/0/3", 20, "IP phone port")):
            builder.add_interface(branch.switch_id, port, InterfaceMode.ACCESS, 1000, description, vlan_ids=(vlan_id,))

        core_router = device_of(branch.core_interface_id)
        builder.relate(branch.switch_id, branch.router_id, RelationshipType.UPSTREAM, "Access switch uplink to WAN edge")
        builder.relate(branch.router_id, core_router, RelationshipType.UPSTREAM, "WAN uplink to core router")
        builder.relate(branch.router_id, DHCP_SERVER, RelationshipType.DEPENDS_ON, "DHCP relay target for branch VLANs")
        builder.relate(branch.switch_id, AUTH_SERVER, RelationshipType.DEPENDS_ON, "RADIUS server for 802.1X")

    builder.relate("CORE-RTR-01", "CORE-RTR-02", RelationshipType.REDUNDANT_PEER, "Core router pair")
    builder.relate(INTERNET_EDGE, "CORE-SW-01", RelationshipType.UPSTREAM, "Internet edge firewall inside uplink")
    builder.relate(DC_FIREWALL, "CORE-SW-01", RelationshipType.UPSTREAM, "Data centre metro uplink")
    builder.relate("DC1-SW-01", DC_FIREWALL, RelationshipType.UPSTREAM, "Data centre switch uplink")
    builder.relate(DNS_PRIMARY, DNS_SECONDARY, RelationshipType.REDUNDANT_PEER, "Primary and secondary DNS")
    builder.relate(APP_SERVER, DNS_PRIMARY, RelationshipType.DEPENDS_ON, "Name resolution for application back ends")
    return builder.build()


class Simulation:
    def __init__(self, topology: NetworkTopology, spec: ScenarioSpec, index: int) -> None:
        self.topology = topology
        self.spec = spec
        self.index = index
        self.rng = random.Random(spec.scenario_id)
        self.onset = FIRST_ONSET + timedelta(days=index)
        self.window_start = self.onset - HALF_WINDOW
        self.window_end = self.onset + HALF_WINDOW
        self.devices = {device.device_id: device for device in topology.devices}
        self.interfaces = {interface.interface_id: interface for interface in topology.interfaces}
        self.links = {link.link_id: link for link in topology.links}
        self.link_of = {endpoint: link for link in topology.links for endpoint in (link.a_interface_id, link.b_interface_id)}
        self.down_devices = set(spec.down_device_ids)
        self.down_links = set(spec.down_link_ids) | {
            link.link_id for link in topology.links if {link.a_device_id, link.b_device_id} & self.down_devices
        }
        self.down_interfaces = self.endpoints(self.down_links)
        self.degraded_interfaces = self.endpoints(set(spec.degraded_link_ids))
        self.degraded_sites = {branch.site_id for branch in BRANCHES if branch.wan_link_id in spec.degraded_link_ids}
        delay = 40 if spec.failed_adjacency_link_ids else 1
        self.change_time = self.onset + timedelta(seconds=delay)
        self.established_since = {
            link.link_id: self.window_start - timedelta(seconds=self.rng.randint(3 * 86400, 90 * 86400))
            for link in topology.links
        }
        self.baseline_routes = self.compute_routes(set(), set(), set())
        self.routes = self.compute_routes(
            self.down_links | set(spec.failed_adjacency_link_ids), self.down_devices, self.down_interfaces,
        )
        self.branches = {branch.site_id: branch for branch in BRANCHES}

    def endpoints(self, link_ids: set[str]) -> set[str]:
        return {endpoint for link_id in link_ids for endpoint in (self.links[link_id].a_interface_id, self.links[link_id].b_interface_id)}

    def at(self, offset_seconds: float) -> datetime:
        return self.onset + timedelta(seconds=offset_seconds)

    def is_down(self, device_id: str, at: datetime) -> bool:
        return device_id in self.down_devices and at >= self.onset

    def compute_routes(self, excluded_links: set[str], excluded_devices: set[str],
                       down_interfaces: set[str]) -> dict[str, dict[IPv4Network, RouteEntry]]:
        routed = [link for link in self.topology.links if link.routing_protocol is not None]
        routers = sorted({device for link in routed for device in (link.a_device_id, link.b_device_id)} - excluded_devices)
        active = [
            link for link in routed
            if link.link_id not in excluded_links and not {link.a_device_id, link.b_device_id} & excluded_devices
        ]
        adjacency = build_adjacency(active)
        tables: dict[str, dict[IPv4Network, RouteEntry]] = {device_id: {} for device_id in routers}
        for interface in self.topology.interfaces:
            if interface.device_id in tables and interface.ip_address is not None and interface.interface_id not in down_interfaces:
                tables[interface.device_id][interface.ip_address.network] = RouteEntry(
                    prefix=interface.ip_address.network, protocol=RoutingProtocol.CONNECTED,
                    interface_id=interface.interface_id, admin_distance=0, metric=0,
                )
        if INTERNET_EDGE in tables:
            tables[INTERNET_EDGE][DEFAULT_ROUTE] = RouteEntry(
                prefix=DEFAULT_ROUTE, protocol=RoutingProtocol.STATIC, next_hop=INTERNET_GATEWAY,
                interface_id=INTERNET_EDGE_INTERFACE, admin_distance=ADMIN_DISTANCE[RoutingProtocol.STATIC], metric=0,
            )
        origins = [(vlan.subnet, device_of(vlan.gateway_interface_id)) for vlan in self.topology.vlans]
        origins.append((DEFAULT_ROUTE, INTERNET_EDGE))
        for prefix, origin in origins:
            if origin not in tables:
                continue
            for device_id, hop in breadth_first(adjacency, origin).items():
                if hop.link is None:
                    continue
                local_id, remote_id = orient(hop.link, device_id)
                protocol = hop.link.routing_protocol
                tables[device_id][prefix] = RouteEntry(
                    prefix=prefix, protocol=protocol, next_hop=self.interfaces[remote_id].ip_address.ip,
                    interface_id=local_id, admin_distance=ADMIN_DISTANCE[protocol],
                    metric=hop.depth * 10 if protocol == RoutingProtocol.OSPF else 0,
                )
        return tables

    def reachable(self, site_id: str, destination: IPv4Address, at: datetime) -> bool:
        tables = self.routes if at >= self.onset else self.baseline_routes
        table = tables.get(self.branches[site_id].router_id)
        return table is not None and any(destination in prefix for prefix in table)

    def client_active(self, site_id: str, at: datetime) -> bool:
        return not (site_id in self.spec.isolated_site_ids and at >= self.onset)

    def activity_times(self) -> list[datetime]:
        return [self.at(minutes * 60 + self.rng.randint(0, 59)) for minutes in ACTIVITY_OFFSETS_MINUTES]

    def user_host(self, branch: Branch) -> IPv4Address:
        return IPv4Address(f"10.{branch.octet}.10.{self.rng.randint(100, 149)}")

    def build_routing(self) -> RoutingData:
        tables = [
            RoutingTable(device_id=device_id, collected_at=self.window_end,
                         routes=[routes[prefix] for prefix in sorted(routes, key=prefix_key)])
            for device_id, routes in self.routes.items()
        ]
        ospf_neighbors, bgp_neighbors = self.build_neighbors()
        return RoutingData(routing_tables=tables, ospf_neighbors=ospf_neighbors, bgp_neighbors=bgp_neighbors,
                           route_changes=self.build_route_changes())

    def build_neighbors(self) -> tuple[list[OspfNeighbor], list[BgpNeighbor]]:
        ospf_neighbors, bgp_neighbors = [], []
        for link in self.topology.links:
            if link.routing_protocol not in (RoutingProtocol.OSPF, RoutingProtocol.BGP):
                continue
            link_down = link.link_id in self.down_links
            failed = link_down or link.link_id in self.spec.failed_adjacency_link_ids
            since = self.change_time if failed else self.established_since[link.link_id]
            for device_id in (link.a_device_id, link.b_device_id):
                if device_id in self.down_devices:
                    continue
                local_id, remote_id = orient(link, device_id)
                remote_ip = self.interfaces[remote_id].ip_address.ip
                remote_device = self.devices[device_of(remote_id)]
                if link.routing_protocol == RoutingProtocol.OSPF:
                    state, reason = OspfState.FULL, None
                    if link_down:
                        state, reason = OspfState.DOWN, "Dead timer expired after interface down"
                    elif failed:
                        state, reason = OspfState.EXSTART, "Database description exchange stalled: interface MTU mismatch"
                    ospf_neighbors.append(OspfNeighbor(
                        device_id=device_id, interface_id=local_id, neighbor_device_id=remote_device.device_id,
                        neighbor_router_id=remote_device.router_id, neighbor_ip=remote_ip, area=link.ospf_area,
                        state=state, last_state_change=since, failure_reason=reason,
                    ))
                else:
                    prefixes = sum(
                        1 for route in self.routes[device_id].values()
                        if route.protocol == RoutingProtocol.BGP and route.next_hop == remote_ip
                    )
                    bgp_neighbors.append(BgpNeighbor(
                        device_id=device_id, neighbor_device_id=remote_device.device_id, neighbor_ip=remote_ip,
                        local_asn=self.devices[device_id].bgp_asn, remote_asn=remote_device.bgp_asn,
                        state=BgpState.IDLE if failed else BgpState.ESTABLISHED, prefixes_received=prefixes,
                        last_state_change=since, failure_reason="Hold timer expired after interface down" if failed else None,
                    ))
        return ospf_neighbors, bgp_neighbors

    def build_route_changes(self) -> list[RouteChange]:
        changes = []
        for device_id, routes in self.routes.items():
            before = {prefix: route for prefix, route in self.baseline_routes[device_id].items() if route.protocol != RoutingProtocol.CONNECTED}
            after = {prefix: route for prefix, route in routes.items() if route.protocol != RoutingProtocol.CONNECTED}
            for prefix in sorted(set(before) | set(after), key=prefix_key):
                old, new = before.get(prefix), after.get(prefix)
                if old is not None and new is not None and old.next_hop == new.next_hop:
                    continue
                if old is None:
                    change_type = RouteChangeType.ADDED
                elif new is None:
                    change_type = RouteChangeType.WITHDRAWN
                else:
                    change_type = RouteChangeType.NEXT_HOP_CHANGED
                changes.append(RouteChange(
                    change_id=f"RC-{len(changes) + 1:04d}", timestamp=self.change_time, device_id=device_id,
                    prefix=prefix, protocol=(new or old).protocol, change_type=change_type,
                    previous_next_hop=old.next_hop if old else None, new_next_hop=new.next_hop if new else None,
                ))
        return changes

    def build_statistics(self) -> list[InterfaceStatistics]:
        profiles = {}
        for interface in self.topology.interfaces:
            if interface.mode == InterfaceMode.VIRTUAL:
                continue
            link = self.link_of.get(interface.interface_id)
            low, high = self.load_range(interface, link)
            since = self.established_since[link.link_id] if link else self.window_start - timedelta(
                seconds=self.rng.randint(86400, 60 * 86400))
            profiles[interface.interface_id] = (self.rng.uniform(low, high), self.rng.uniform(low, high), since)
        samples = []
        for minutes in SAMPLE_OFFSETS_MINUTES:
            at = self.at(minutes * 60)
            for interface_id, profile in profiles.items():
                if not self.is_down(device_of(interface_id), at):
                    samples.append(self.sample(self.interfaces[interface_id], at, *profile))
        return samples

    def load_range(self, interface: Interface, link: Link | None) -> tuple[float, float]:
        if link is not None:
            return {LinkType.WAN: (35.0, 65.0), LinkType.METRO: (20.0, 40.0), LinkType.LAN: (10.0, 35.0)}[link.link_type]
        if interface.mode == InterfaceMode.ACCESS:
            return (0.5, 3.0) if 20 in interface.vlan_ids else (2.0, 15.0)
        return 30.0, 55.0

    def sample(self, interface: Interface, at: datetime, in_load: float, out_load: float,
               since: datetime) -> InterfaceStatistics:
        link = self.link_of.get(interface.interface_id)
        probed = link is not None and link.link_type in (LinkType.WAN, LinkType.METRO)
        capacity_bps = (link.bandwidth_mbps if link else interface.speed_mbps) * 1_000_000
        after_onset = at >= self.onset
        common = {
            "interface_id": interface.interface_id, "device_id": interface.device_id, "timestamp": at,
            "interval_seconds": SAMPLE_INTERVAL_SECONDS,
        }
        if after_onset and interface.interface_id in self.down_interfaces:
            return InterfaceStatistics(
                **common, oper_status=LinkStatus.DOWN, utilization_percent=0.0, in_bps=0, out_bps=0, in_drops=0,
                out_drops=0, in_errors=0, out_errors=0, uptime_seconds=0, latency_ms=None,
                packet_loss_percent=100.0 if probed else None,
            )
        in_load *= self.rng.uniform(0.9, 1.1)
        out_load *= self.rng.uniform(0.9, 1.1)
        in_drops, out_drops = self.rng.randint(0, 3), self.rng.randint(0, 3)
        in_errors = out_errors = 0
        latency = link.latency_ms * self.rng.uniform(0.97, 1.03) if probed else None
        loss = 0.0 if probed else None
        if after_onset and interface.interface_id in self.degraded_interfaces:
            in_errors, out_errors = self.rng.randint(1200, 2600), self.rng.randint(1200, 2600)
            in_drops += self.rng.randint(600, 1400)
            out_drops += self.rng.randint(600, 1400)
            loss = self.rng.uniform(9.0, 13.0)
            latency += self.rng.uniform(80.0, 95.0)
        site_id = self.devices[interface.device_id].site_id
        if after_onset and site_id in self.spec.isolated_site_ids and interface.mode == InterfaceMode.ACCESS and 10 in interface.vlan_ids:
            in_load, out_load = self.rng.uniform(0.01, 0.05), self.rng.uniform(0.01, 0.05)
        return InterfaceStatistics(
            **common, oper_status=LinkStatus.UP, utilization_percent=round(max(in_load, out_load), 2),
            in_bps=int(capacity_bps * in_load / 100), out_bps=int(capacity_bps * out_load / 100),
            in_drops=in_drops, out_drops=out_drops, in_errors=in_errors, out_errors=out_errors,
            uptime_seconds=int((at - since).total_seconds()),
            latency_ms=round(latency, 2) if latency is not None else None,
            packet_loss_percent=round(loss, 2) if loss is not None else None,
        )

    def build_rules(self) -> list[FirewallRule]:
        specs = [(rule, RULE_BASELINE_TIME) for rule in BASELINE_RULES]
        specs += [(rule, self.onset) for rule in self.spec.added_rules]
        rules = [
            FirewallRule(
                rule_id=rule.rule_id, device_id=rule.device_id, priority=rule.priority, name=rule.name,
                action=rule.action, protocol=rule.protocol, source=rule.source, destination=rule.destination,
                destination_port=rule.port, enabled=True, last_modified=modified,
            )
            for rule, modified in specs
        ]
        return sorted(rules, key=lambda rule: (rule.device_id, rule.priority))

    def build_firewall(self) -> FirewallData:
        rules = self.build_rules()
        flows = []
        for at in self.activity_times():
            for branch in BRANCHES:
                client = self.user_host(branch)
                infrastructure = self.rng.choice(("dns", "radius", "dhcp"))
                candidates = [(True, DC_FIREWALL, client, SERVER_IP[APP_SERVER], TransportProtocol.TCP, 443)]
                if infrastructure == "dns":
                    candidates.append((True, DC_FIREWALL, client, SERVER_IP[DNS_PRIMARY], TransportProtocol.UDP, 53))
                elif infrastructure == "radius":
                    candidates.append((False, DC_FIREWALL, IPv4Address(f"10.{branch.octet}.99.2"),
                                       SERVER_IP[AUTH_SERVER], TransportProtocol.UDP, 1812))
                else:
                    candidates.append((False, DC_FIREWALL, IPv4Address(f"10.{branch.octet}.10.1"),
                                       SERVER_IP[DHCP_SERVER], TransportProtocol.UDP, 67))
                candidates.append((True, INTERNET_EDGE, client, IPv4Address(f"198.51.100.{self.rng.randint(10, 250)}"),
                                   TransportProtocol.TCP, 443))
                for from_client, device_id, source, destination, protocol, port in candidates:
                    source_port = 67 if port == 67 else self.rng.randint(49152, 65535)
                    if from_client and not self.client_active(branch.site_id, at):
                        continue
                    if self.reachable(branch.site_id, destination, at):
                        flows.append((at, device_id, source, destination, protocol, source_port, port))
        flows.append((self.at(-660), DC_FIREWALL, IPv4Address("10.10.10.123"), SERVER_IP[APP_SERVER],
                      TransportProtocol.TCP, 51515, 22))
        events = []
        for at, device_id, source, destination, protocol, source_port, port in sorted(flows, key=lambda flow: (flow[0], flow[1], int(flow[2]), int(flow[3]))):
            rule = match_firewall_rule(rules, device_id, source, destination, protocol, port, at)
            events.append(FirewallEvent(
                event_id=f"FW-EVT-{len(events) + 1:04d}", timestamp=at, device_id=device_id, rule_id=rule.rule_id,
                source_ip=source, destination_ip=destination, source_port=source_port, destination_port=port,
                protocol=protocol, action=rule.action,
                severity=Severity.INFORMATIONAL if rule.action == FirewallAction.ALLOW else Severity.WARNING,
            ))
        return FirewallData(rules=rules, events=events)

    def build_dhcp(self) -> DhcpData:
        pools, leases = [], []
        for branch in BRANCHES:
            for vlan_id, label, first, last, lease_hours in DHCP_SCOPES:
                pool = DhcpPool(
                    pool_id=f"DHCP-{branch.site_id}-{label}", server_device_id=DHCP_SERVER, site_id=branch.site_id,
                    vlan_id=vlan_id, subnet=f"10.{branch.octet}.{vlan_id}.0/24",
                    range_start=f"10.{branch.octet}.{vlan_id}.{first}", range_end=f"10.{branch.octet}.{vlan_id}.{last}",
                    gateway=f"10.{branch.octet}.{vlan_id}.1",
                    dns_servers=[SERVER_IP[DNS_PRIMARY], SERVER_IP[DNS_SECONDARY]],
                    lease_time_seconds=lease_hours * 3600,
                )
                pools.append(pool)
                leases += self.build_leases(branch, pool)
        return DhcpData(pools=pools, leases=leases, events=self.build_dhcp_events(pools, leases))

    def build_leases(self, branch: Branch, pool: DhcpPool) -> list[DhcpLease]:
        exhausted = pool.pool_id == self.spec.exhausted_pool_id
        count = pool.size if exhausted else int(pool.size * self.rng.uniform(0.5, 0.75))
        kind = "ws" if pool.vlan_id == 10 else "ph"
        lease_time = timedelta(seconds=pool.lease_time_seconds)
        leases = []
        for index in range(min(count + 2, pool.size)):
            if index < count:
                start = self.window_end - timedelta(seconds=self.rng.randint(300, pool.lease_time_seconds - 300))
                state = LeaseState.CONFLICT if exhausted and index >= count - 2 else LeaseState.ACTIVE
            else:
                start = self.window_start - lease_time - timedelta(seconds=self.rng.randint(600, 7200))
                state = LeaseState.EXPIRED
            leases.append(DhcpLease(
                pool_id=pool.pool_id, ip_address=pool.range_start + index,
                mac_address=self.mac(branch.octet, pool.vlan_id, index),
                hostname=None if state == LeaseState.CONFLICT else f"{branch.site_id.lower()}-{kind}-{index + 1:03d}",
                state=state, lease_start=start, lease_end=start + lease_time,
            ))
        return leases

    @staticmethod
    def mac(octet: int, vlan_id: int, index: int) -> str:
        return f"02:00:{octet:02x}:{vlan_id:02x}:{index // 256:02x}:{index % 256:02x}"

    def build_dhcp_events(self, pools: list[DhcpPool], leases: list[DhcpLease]) -> list[DhcpEvent]:
        records = []
        user_pools = {pool.site_id: pool for pool in pools if pool.vlan_id == 10}
        failures = 0
        for at in self.activity_times():
            for branch in BRANCHES:
                pool = user_pools[branch.site_id]
                active = [lease for lease in leases if lease.pool_id == pool.pool_id and lease.state == LeaseState.ACTIVE]
                lease = self.rng.choice(active)
                if not (self.client_active(branch.site_id, at) and self.reachable(branch.site_id, SERVER_IP[DHCP_SERVER], at)):
                    continue
                records.append((at, pool, DhcpEventType.ALLOCATION_SUCCESS, lease.mac_address, lease.ip_address,
                                f"DHCPACK on {lease.ip_address} to {lease.mac_address} ({lease.hostname}) via {pool.gateway}"))
                if pool.pool_id == self.spec.exhausted_pool_id and at >= self.onset:
                    failures += 1
                    mac = self.mac(branch.octet, 0xFF, failures)
                    records.append((at + timedelta(seconds=2), pool, DhcpEventType.ALLOCATION_FAILURE, mac, None,
                                    f"DHCPDISCOVER from {mac} via {pool.gateway}: network {pool.subnet}: no free leases"))
        exhausted = next((pool for pool in pools if pool.pool_id == self.spec.exhausted_pool_id), None)
        if exhausted is not None:
            records.append((self.onset, exhausted, DhcpEventType.POOL_EXHAUSTED, None, None,
                            f"Pool {exhausted.pool_id} exhausted: {exhausted.size} of {exhausted.size} addresses in use"))
            conflicts = [lease for lease in leases if lease.pool_id == exhausted.pool_id and lease.state == LeaseState.CONFLICT]
            for position, lease in enumerate(conflicts):
                records.append((self.at(-360 + position * 120), exhausted, DhcpEventType.IP_CONFLICT, lease.mac_address,
                                lease.ip_address, f"DHCPDECLINE of {lease.ip_address} from {lease.mac_address}: address already in use"))
        records.sort(key=lambda record: (record[0], record[1].pool_id, record[2].value))
        return [
            DhcpEvent(event_id=f"DHCP-EVT-{number:04d}", timestamp=at, server_device_id=pool.server_device_id,
                      pool_id=pool.pool_id, event_type=event_type, mac_address=mac, ip_address=address, message=message)
            for number, (at, pool, event_type, mac, address, message) in enumerate(records, start=1)
        ]

    def build_dns(self) -> DnsData:
        servers = [
            DnsServer(device_id=device_id, ip_address=SERVER_IP[device_id], role=role, zones=[INTERNAL_ZONE],
                      forwarders=[IPv4Address("198.51.100.53")])
            for device_id, role in ((DNS_PRIMARY, DnsServerRole.PRIMARY), (DNS_SECONDARY, DnsServerRole.SECONDARY))
        ]
        metro_latency = self.links[METRO_LINK].latency_ms
        records = []
        for at in self.activity_times():
            for branch in BRANCHES:
                client = self.user_host(branch)
                domain = MISSING_DOMAIN if self.rng.random() < 0.1 else self.rng.choice(sorted(DNS_RECORDS))
                server_id = DNS_PRIMARY if self.rng.random() < 0.85 else DNS_SECONDARY
                response_time = branch.latency_ms + metro_latency + self.rng.uniform(0.4, 3.0)
                lossy, extra_latency = self.rng.random(), self.rng.uniform(80.0, 95.0)
                if not self.client_active(branch.site_id, at):
                    continue
                degraded = at >= self.onset and branch.site_id in self.degraded_sites
                answers: list[str] = []
                if not self.reachable(branch.site_id, SERVER_IP[server_id], at) or (degraded and lossy < 0.25):
                    result, response_time = DnsResult.TIMEOUT, None
                elif at >= self.onset and server_id == self.spec.failed_dns_server_id and domain.endswith(INTERNAL_ZONE):
                    result = DnsResult.SERVFAIL
                elif domain not in DNS_RECORDS:
                    result = DnsResult.NXDOMAIN
                else:
                    result, answers = DnsResult.NOERROR, [DNS_RECORDS[domain]]
                if degraded and response_time is not None:
                    response_time += extra_latency
                records.append((at, client, server_id, domain, result, answers, response_time))
        records.sort(key=lambda record: (record[0], int(record[1])))
        queries = [
            DnsQuery(query_id=f"DNS-Q-{number:04d}", timestamp=at, client_ip=client, server_ip=SERVER_IP[server_id],
                     domain=domain, record_type=DnsRecordType.A, result=result, answers=answers,
                     response_time_ms=round(response_time, 2) if response_time is not None else None)
            for number, (at, client, server_id, domain, result, answers, response_time) in enumerate(records, start=1)
        ]
        return DnsData(servers=servers, queries=queries)

    def build_events(self, routing: RoutingData) -> list[NetworkEvent]:
        records = []
        window_seconds = int((self.window_end - self.window_start).total_seconds())
        for device in self.topology.devices:
            for _ in range(2):
                event_type, severity, message = self.rng.choice(BACKGROUND_EVENTS[device.device_type])
                at = self.window_start + timedelta(seconds=self.rng.randint(0, window_seconds))
                if not self.is_down(device.device_id, at):
                    records.append((at, device.device_id, None, severity, event_type, message))
        for link_id in sorted(self.down_links):
            for interface_id in (self.links[link_id].a_interface_id, self.links[link_id].b_interface_id):
                interface = self.interfaces[interface_id]
                if interface.device_id in self.down_devices:
                    continue
                if self.devices[interface.device_id].device_type == DeviceType.FIREWALL:
                    message = f"Interface {interface.name} link status changed to down"
                else:
                    message = f"%LINK-3-UPDOWN: Interface {interface.name}, changed state to down"
                records.append((self.onset, interface.device_id, interface_id, Severity.ERROR, "LINK_DOWN", message))
        for neighbor in routing.ospf_neighbors:
            if neighbor.state != OspfState.FULL:
                name = self.interfaces[neighbor.interface_id].name
                records.append((neighbor.last_state_change, neighbor.device_id, neighbor.interface_id, Severity.NOTICE,
                                "OSPF_ADJACENCY_DOWN",
                                f"%OSPF-5-ADJCHG: Process 1, Nbr {neighbor.neighbor_router_id} on {name} from FULL to "
                                f"{neighbor.state.value.upper()}, {neighbor.failure_reason}"))
        for neighbor in routing.bgp_neighbors:
            if neighbor.state != BgpState.ESTABLISHED:
                records.append((neighbor.last_state_change, neighbor.device_id, None, Severity.NOTICE, "BGP_NEIGHBOR_DOWN",
                                f"%BGP-5-ADJCHANGE: neighbor {neighbor.neighbor_ip} Down {neighbor.failure_reason}"))
        for template in self.spec.events:
            interface_id = f"{template.device_id}:{template.interface_name}" if template.interface_name else None
            records.append((self.at(template.offset_seconds), template.device_id, interface_id, template.severity,
                            template.event_type, template.message))
        records.sort(key=lambda record: (record[0], record[1], record[4], record[5]))
        return [
            NetworkEvent(event_id=f"EVT-{number:05d}", timestamp=at, device_id=device_id, interface_id=interface_id,
                         severity=severity, event_type=event_type, message=message)
            for number, (at, device_id, interface_id, severity, event_type, message) in enumerate(records, start=1)
        ]

    def affected_path_ids(self) -> list[str]:
        failed_links = self.down_links | set(self.spec.failed_adjacency_link_ids) | set(self.spec.degraded_link_ids)
        impacted = set(self.spec.impacted_services)
        return [
            path.path_id for path in self.topology.paths
            if set(path.link_ids) & failed_links
            or set(path.device_ids) & self.down_devices
            or (path.source_site_id, path.service) in impacted
        ]

    def build_incident(self) -> tuple[IncidentRecord | None, GroundTruth | None]:
        spec = self.spec
        if spec.incident is None:
            return None, None
        incident = IncidentRecord(
            incident_id=f"INC-{self.onset:%Y%m%d}-{self.index:03d}", title=spec.incident.title,
            description=spec.incident.description, category=spec.category, priority=spec.incident.priority,
            status=IncidentStatus.OPEN, reported_at=self.at(spec.incident.reported_after_minutes * 60),
            reported_by=spec.incident.reported_by, affected_site_ids=list(spec.incident.affected_site_ids),
            symptoms=list(spec.incident.symptoms),
        )
        path_ids = self.affected_path_ids()
        paths = {path.path_id: path for path in self.topology.paths}
        ground_truth = GroundTruth(
            root_cause=spec.root_cause, root_cause_device_ids=list(spec.root_cause_device_ids),
            root_cause_link_ids=list(spec.root_cause_link_ids),
            affected_site_ids=sorted({paths[path_id].source_site_id for path_id in path_ids}),
            affected_path_ids=path_ids,
        )
        return incident, ground_truth

    def build(self) -> ScenarioDataset:
        routing = self.build_routing()
        interface_statistics = self.build_statistics()
        firewall = self.build_firewall()
        dhcp = self.build_dhcp()
        dns = self.build_dns()
        events = self.build_events(routing)
        incident, ground_truth = self.build_incident()
        return ScenarioDataset(
            scenario=ScenarioInfo(
                scenario_id=self.spec.scenario_id, name=self.spec.name, description=self.spec.description,
                category=self.spec.category, window_start=self.window_start, onset_at=self.onset,
                window_end=self.window_end,
            ),
            incident=incident, ground_truth=ground_truth, events=events, interface_statistics=interface_statistics,
            routing=routing, firewall=firewall, dhcp=dhcp, dns=dns,
        )


def build_scenarios(topology: NetworkTopology) -> list[ScenarioDataset]:
    return [Simulation(topology, spec, index).build() for index, spec in enumerate(SCENARIOS)]


def to_json(model: BaseModel) -> str:
    return json.dumps(model.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"


def write_datasets(data_dir: Path = DATA_DIR) -> None:
    topology = build_topology()
    scenario_dir = data_dir / SCENARIOS_DIR
    scenario_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / TOPOLOGY_FILE).write_text(to_json(topology), encoding="utf-8", newline="\n")
    for dataset in build_scenarios(topology):
        path = scenario_dir / f"{dataset.scenario.scenario_id}.json"
        path.write_text(to_json(dataset), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    write_datasets()
