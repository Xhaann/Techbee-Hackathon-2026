from datetime import datetime, timedelta
from enum import Enum
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Annotated

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, model_validator


def require_utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC")
    return value


UtcDatetime = Annotated[AwareDatetime, AfterValidator(require_utc)]
Identifier = Annotated[str, Field(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")]
DeviceId = Annotated[str, Field(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$")]
InterfaceId = Annotated[str, Field(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+:[A-Za-z0-9/.]+$")]
EventType = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]*$")]
MacAddress = Annotated[str, Field(pattern=r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")]
DomainName = Annotated[str, Field(max_length=253, pattern=r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")]
VlanNumber = Annotated[int, Field(ge=1, le=4094)]
Port = Annotated[int, Field(ge=1, le=65535)]
Asn = Annotated[int, Field(ge=1, le=4294967295)]
Percent = Annotated[float, Field(ge=0, le=100)]
Count = Annotated[int, Field(ge=0)]
NonEmptyText = Annotated[str, Field(min_length=1)]


def device_of(interface_id: str) -> str:
    return interface_id.split(":", 1)[0]


def find_duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for value in values:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    return duplicates


def ensure_unique(values: list[str], label: str) -> None:
    duplicates = find_duplicates(values)
    if duplicates:
        raise ValueError(f"duplicate {label}: {', '.join(duplicates)}")


def ensure_known(values: list[str], known: set[str], label: str) -> None:
    unknown = sorted({value for value in values if value not in known})
    if unknown:
        raise ValueError(f"unknown {label}: {', '.join(unknown)}")


class NetworkModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SiteType(str, Enum):
    BRANCH = "branch"
    CORE = "core"
    DATA_CENTRE = "data_centre"


class DeviceType(str, Enum):
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"


class DeviceRole(str, Enum):
    WAN_EDGE = "wan_edge"
    CORE_ROUTER = "core_router"
    CORE_SWITCH = "core_switch"
    DISTRIBUTION_SWITCH = "distribution_switch"
    ACCESS_SWITCH = "access_switch"
    PERIMETER_FIREWALL = "perimeter_firewall"
    DATA_CENTRE_FIREWALL = "data_centre_firewall"
    DNS_SERVER = "dns_server"
    DHCP_SERVER = "dhcp_server"
    AUTHENTICATION_SERVER = "authentication_server"
    APPLICATION_SERVER = "application_server"


class InterfaceMode(str, Enum):
    ROUTED = "routed"
    ACCESS = "access"
    TRUNK = "trunk"
    VIRTUAL = "virtual"


class LinkStatus(str, Enum):
    UP = "up"
    DOWN = "down"


class LinkType(str, Enum):
    WAN = "wan"
    METRO = "metro"
    LAN = "lan"


class RoutingProtocol(str, Enum):
    CONNECTED = "connected"
    STATIC = "static"
    OSPF = "ospf"
    BGP = "bgp"


class RelationshipType(str, Enum):
    UPSTREAM = "upstream"
    DEPENDS_ON = "depends_on"
    REDUNDANT_PEER = "redundant_peer"


class PathService(str, Enum):
    APPLICATION = "application"
    AUTHENTICATION = "authentication"
    DHCP = "dhcp"
    DNS = "dns"
    INTERNET = "internet"


class Severity(str, Enum):
    EMERGENCY = "emergency"
    ALERT = "alert"
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFORMATIONAL = "informational"
    DEBUG = "debug"


class OspfState(str, Enum):
    DOWN = "down"
    INIT = "init"
    TWO_WAY = "two_way"
    EXSTART = "exstart"
    EXCHANGE = "exchange"
    LOADING = "loading"
    FULL = "full"


class BgpState(str, Enum):
    IDLE = "idle"
    CONNECT = "connect"
    ACTIVE = "active"
    OPEN_SENT = "open_sent"
    OPEN_CONFIRM = "open_confirm"
    ESTABLISHED = "established"


class RouteChangeType(str, Enum):
    ADDED = "added"
    WITHDRAWN = "withdrawn"
    NEXT_HOP_CHANGED = "next_hop_changed"


class FirewallAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class TransportProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


class LeaseState(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    CONFLICT = "conflict"


class DhcpEventType(str, Enum):
    ALLOCATION_SUCCESS = "allocation_success"
    ALLOCATION_FAILURE = "allocation_failure"
    IP_CONFLICT = "ip_conflict"
    POOL_EXHAUSTED = "pool_exhausted"


class DnsServerRole(str, Enum):
    PRIMARY = "primary"
    SECONDARY = "secondary"


class DnsRecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    MX = "MX"


class DnsResult(str, Enum):
    NOERROR = "noerror"
    NXDOMAIN = "nxdomain"
    SERVFAIL = "servfail"
    REFUSED = "refused"
    TIMEOUT = "timeout"


class IncidentCategory(str, Enum):
    WAN_CONNECTIVITY_FAILURE = "wan_connectivity_failure"
    PACKET_LOSS = "packet_loss"
    OSPF_ADJACENCY_FAILURE = "ospf_adjacency_failure"
    FIREWALL_BLOCKING = "firewall_blocking"
    DHCP_ALLOCATION_FAILURE = "dhcp_allocation_failure"
    DNS_RESOLUTION_FAILURE = "dns_resolution_failure"
    VLAN_AUTHENTICATION_FAILURE = "vlan_authentication_failure"
    SHARED_DEVICE_FAILURE = "shared_device_failure"


class IncidentPriority(str, Enum):
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class Site(NetworkModel):
    site_id: Identifier
    name: NonEmptyText
    site_type: SiteType
    city: NonEmptyText
    country: NonEmptyText


class Device(NetworkModel):
    device_id: DeviceId
    hostname: NonEmptyText
    device_type: DeviceType
    role: DeviceRole
    site_id: Identifier
    vendor: NonEmptyText
    model: NonEmptyText
    os_version: NonEmptyText
    management_ip: IPv4Address
    router_id: IPv4Address | None = None
    bgp_asn: Asn | None = None


class Interface(NetworkModel):
    interface_id: InterfaceId
    device_id: DeviceId
    name: NonEmptyText
    mode: InterfaceMode
    description: str
    ip_address: IPv4Interface | None = None
    speed_mbps: int = Field(gt=0)
    mtu: int = Field(ge=576, le=9216)
    vlan_ids: list[VlanNumber] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_consistency(self) -> "Interface":
        if self.interface_id != f"{self.device_id}:{self.name}":
            raise ValueError("interface_id must be '<device_id>:<name>'")
        if self.mode in (InterfaceMode.ACCESS, InterfaceMode.VIRTUAL) and len(self.vlan_ids) != 1:
            raise ValueError(f"{self.mode.value} interface requires exactly one VLAN")
        if self.mode == InterfaceMode.TRUNK and not self.vlan_ids:
            raise ValueError("trunk interface requires at least one VLAN")
        if self.mode == InterfaceMode.ROUTED and self.vlan_ids:
            raise ValueError("routed interface cannot carry VLANs")
        if self.mode in (InterfaceMode.ROUTED, InterfaceMode.VIRTUAL) and self.ip_address is None:
            raise ValueError(f"{self.mode.value} interface requires an IP address")
        return self


class Vlan(NetworkModel):
    segment_id: Identifier
    site_id: Identifier
    vlan_id: VlanNumber
    name: NonEmptyText
    subnet: IPv4Network
    gateway: IPv4Address
    gateway_interface_id: InterfaceId

    @model_validator(mode="after")
    def check_gateway(self) -> "Vlan":
        if self.gateway not in self.subnet:
            raise ValueError("gateway must be inside the VLAN subnet")
        return self


class Link(NetworkModel):
    link_id: Identifier
    link_type: LinkType
    a_interface_id: InterfaceId
    b_interface_id: InterfaceId
    bandwidth_mbps: int = Field(gt=0)
    latency_ms: float = Field(ge=0)
    routing_protocol: RoutingProtocol | None = None
    ospf_area: str | None = None
    provider: str | None = None
    circuit_id: str | None = None

    @property
    def a_device_id(self) -> str:
        return device_of(self.a_interface_id)

    @property
    def b_device_id(self) -> str:
        return device_of(self.b_interface_id)

    @model_validator(mode="after")
    def check_endpoints(self) -> "Link":
        if self.a_device_id == self.b_device_id:
            raise ValueError("link endpoints must be on different devices")
        if self.routing_protocol == RoutingProtocol.CONNECTED:
            raise ValueError("connected is not a link routing protocol")
        if (self.routing_protocol == RoutingProtocol.OSPF) != (self.ospf_area is not None):
            raise ValueError("ospf_area is required for OSPF links only")
        if self.link_type == LinkType.WAN and not (self.provider and self.circuit_id):
            raise ValueError("WAN links require provider and circuit_id")
        return self


class DeviceRelationship(NetworkModel):
    source_device_id: DeviceId
    target_device_id: DeviceId
    relationship_type: RelationshipType
    description: NonEmptyText

    @model_validator(mode="after")
    def check_distinct(self) -> "DeviceRelationship":
        if self.source_device_id == self.target_device_id:
            raise ValueError("relationship requires two different devices")
        return self


class NetworkPath(NetworkModel):
    path_id: Identifier
    name: NonEmptyText
    service: PathService
    source_site_id: Identifier
    device_ids: list[DeviceId] = Field(min_length=2)
    link_ids: list[Identifier] = Field(min_length=1)

    @model_validator(mode="after")
    def check_lengths(self) -> "NetworkPath":
        if len(self.link_ids) != len(self.device_ids) - 1:
            raise ValueError("a path needs exactly one link between consecutive devices")
        ensure_unique(self.device_ids, "path devices")
        return self


class NetworkTopology(NetworkModel):
    sites: list[Site] = Field(min_length=1)
    devices: list[Device] = Field(min_length=1)
    interfaces: list[Interface]
    links: list[Link]
    vlans: list[Vlan]
    relationships: list[DeviceRelationship]
    paths: list[NetworkPath]

    @model_validator(mode="after")
    def check_references(self) -> "NetworkTopology":
        ensure_unique([site.site_id for site in self.sites], "site ids")
        ensure_unique([device.device_id for device in self.devices], "device ids")
        ensure_unique([interface.interface_id for interface in self.interfaces], "interface ids")
        ensure_unique([link.link_id for link in self.links], "link ids")
        ensure_unique([vlan.segment_id for vlan in self.vlans], "VLAN segment ids")
        ensure_unique([f"{vlan.site_id}:{vlan.vlan_id}" for vlan in self.vlans], "site VLANs")
        ensure_unique([path.path_id for path in self.paths], "path ids")

        site_ids = {site.site_id for site in self.sites}
        devices = {device.device_id: device for device in self.devices}
        interfaces = {interface.interface_id: interface for interface in self.interfaces}
        ensure_known([device.site_id for device in self.devices], site_ids, "device sites")
        ensure_known([interface.device_id for interface in self.interfaces], set(devices), "interface devices")

        endpoints = [interface_id for link in self.links for interface_id in (link.a_interface_id, link.b_interface_id)]
        ensure_known(endpoints, set(interfaces), "link interfaces")
        ensure_unique(endpoints, "link interfaces")
        for link in self.links:
            if any(interfaces[endpoint].mode == InterfaceMode.VIRTUAL for endpoint in (link.a_interface_id, link.b_interface_id)):
                raise ValueError(f"link {link.link_id} cannot terminate on a virtual interface")

        for vlan in self.vlans:
            ensure_known([vlan.site_id], site_ids, "VLAN sites")
            ensure_known([vlan.gateway_interface_id], set(interfaces), "VLAN gateway interfaces")
            gateway = interfaces[vlan.gateway_interface_id]
            if gateway.ip_address is None or gateway.ip_address.ip != vlan.gateway or vlan.vlan_id not in gateway.vlan_ids:
                raise ValueError(f"VLAN {vlan.segment_id} gateway does not match its interface")
            if devices[gateway.device_id].site_id != vlan.site_id:
                raise ValueError(f"VLAN {vlan.segment_id} gateway is on another site")

        for relationship in self.relationships:
            ensure_known([relationship.source_device_id, relationship.target_device_id], set(devices), "relationship devices")

        connections = {frozenset((link.a_device_id, link.b_device_id)): link.link_id for link in self.links}
        links = {link.link_id: link for link in self.links}
        for path in self.paths:
            ensure_known(path.device_ids, set(devices), "path devices")
            ensure_known(path.link_ids, set(links), "path links")
            if devices[path.device_ids[0]].site_id != path.source_site_id:
                raise ValueError(f"path {path.path_id} does not start at its source site")
            for index, link_id in enumerate(path.link_ids):
                pair = frozenset(path.device_ids[index:index + 2])
                if connections.get(pair) != link_id:
                    raise ValueError(f"path {path.path_id} link {link_id} does not connect consecutive devices")
        return self


class NetworkEvent(NetworkModel):
    event_id: Identifier
    timestamp: UtcDatetime
    device_id: DeviceId
    interface_id: InterfaceId | None = None
    severity: Severity
    event_type: EventType
    message: NonEmptyText

    @model_validator(mode="after")
    def check_interface(self) -> "NetworkEvent":
        if self.interface_id is not None and device_of(self.interface_id) != self.device_id:
            raise ValueError("event interface must belong to the event device")
        return self


class InterfaceStatistics(NetworkModel):
    interface_id: InterfaceId
    device_id: DeviceId
    timestamp: UtcDatetime
    interval_seconds: int = Field(gt=0)
    oper_status: LinkStatus
    utilization_percent: Percent
    in_bps: Count
    out_bps: Count
    in_drops: Count
    out_drops: Count
    in_errors: Count
    out_errors: Count
    uptime_seconds: Count
    latency_ms: float | None = Field(default=None, ge=0)
    packet_loss_percent: Percent | None = None

    @model_validator(mode="after")
    def check_status(self) -> "InterfaceStatistics":
        if device_of(self.interface_id) != self.device_id:
            raise ValueError("statistics interface must belong to the device")
        if self.oper_status == LinkStatus.DOWN:
            if self.in_bps or self.out_bps or self.utilization_percent or self.uptime_seconds:
                raise ValueError("a down interface cannot carry traffic or accumulate uptime")
            if self.latency_ms is not None:
                raise ValueError("a down interface cannot report latency")
        return self


class RouteEntry(NetworkModel):
    prefix: IPv4Network
    protocol: RoutingProtocol
    next_hop: IPv4Address | None = None
    interface_id: InterfaceId
    admin_distance: int = Field(ge=0, le=255)
    metric: Count

    @model_validator(mode="after")
    def check_next_hop(self) -> "RouteEntry":
        if (self.protocol == RoutingProtocol.CONNECTED) != (self.next_hop is None):
            raise ValueError("only connected routes omit the next hop")
        return self


class RoutingTable(NetworkModel):
    device_id: DeviceId
    collected_at: UtcDatetime
    routes: list[RouteEntry]

    @model_validator(mode="after")
    def check_routes(self) -> "RoutingTable":
        ensure_unique([str(route.prefix) for route in self.routes], f"prefixes on {self.device_id}")
        if any(device_of(route.interface_id) != self.device_id for route in self.routes):
            raise ValueError("route interfaces must belong to the routing table device")
        return self


class OspfNeighbor(NetworkModel):
    device_id: DeviceId
    interface_id: InterfaceId
    neighbor_device_id: DeviceId
    neighbor_router_id: IPv4Address
    neighbor_ip: IPv4Address
    area: NonEmptyText
    state: OspfState
    last_state_change: UtcDatetime
    failure_reason: str | None = None

    @model_validator(mode="after")
    def check_state(self) -> "OspfNeighbor":
        if device_of(self.interface_id) != self.device_id:
            raise ValueError("neighbor interface must belong to the device")
        if (self.state == OspfState.FULL) == bool(self.failure_reason):
            raise ValueError("failure_reason is required exactly when the adjacency is not full")
        return self


class BgpNeighbor(NetworkModel):
    device_id: DeviceId
    neighbor_device_id: DeviceId
    neighbor_ip: IPv4Address
    local_asn: Asn
    remote_asn: Asn
    state: BgpState
    prefixes_received: Count
    last_state_change: UtcDatetime
    failure_reason: str | None = None

    @model_validator(mode="after")
    def check_state(self) -> "BgpNeighbor":
        established = self.state == BgpState.ESTABLISHED
        if established == bool(self.failure_reason):
            raise ValueError("failure_reason is required exactly when the session is not established")
        if not established and self.prefixes_received:
            raise ValueError("a session that is not established cannot hold prefixes")
        return self


class RouteChange(NetworkModel):
    change_id: Identifier
    timestamp: UtcDatetime
    device_id: DeviceId
    prefix: IPv4Network
    protocol: RoutingProtocol
    change_type: RouteChangeType
    previous_next_hop: IPv4Address | None = None
    new_next_hop: IPv4Address | None = None

    @model_validator(mode="after")
    def check_next_hops(self) -> "RouteChange":
        previous, new = self.previous_next_hop, self.new_next_hop
        valid = {
            RouteChangeType.ADDED: previous is None and new is not None,
            RouteChangeType.WITHDRAWN: previous is not None and new is None,
            RouteChangeType.NEXT_HOP_CHANGED: previous is not None and new is not None and previous != new,
        }[self.change_type]
        if not valid:
            raise ValueError(f"next hops are inconsistent with change type {self.change_type.value}")
        return self


class RoutingData(NetworkModel):
    routing_tables: list[RoutingTable]
    ospf_neighbors: list[OspfNeighbor]
    bgp_neighbors: list[BgpNeighbor]
    route_changes: list[RouteChange]

    @model_validator(mode="after")
    def check_unique(self) -> "RoutingData":
        ensure_unique([table.device_id for table in self.routing_tables], "routing table devices")
        ensure_unique([change.change_id for change in self.route_changes], "route change ids")
        return self


class FirewallRule(NetworkModel):
    rule_id: Identifier
    device_id: DeviceId
    priority: int = Field(ge=1)
    name: NonEmptyText
    action: FirewallAction
    protocol: TransportProtocol | None = None
    source: IPv4Network
    destination: IPv4Network
    destination_port: Port | None = None
    enabled: bool
    last_modified: UtcDatetime

    @model_validator(mode="after")
    def check_port(self) -> "FirewallRule":
        if self.destination_port is not None and self.protocol not in (TransportProtocol.TCP, TransportProtocol.UDP):
            raise ValueError("destination_port requires TCP or UDP")
        return self

    def matches(self, source_ip: IPv4Address, destination_ip: IPv4Address, protocol: TransportProtocol, port: int | None) -> bool:
        return (
            self.enabled
            and source_ip in self.source
            and destination_ip in self.destination
            and self.protocol in (None, protocol)
            and self.destination_port in (None, port)
        )


def match_firewall_rule(
    rules: list[FirewallRule],
    device_id: str,
    source_ip: IPv4Address,
    destination_ip: IPv4Address,
    protocol: TransportProtocol,
    port: int | None,
    at: datetime,
) -> FirewallRule | None:
    candidates = sorted(
        (rule for rule in rules if rule.device_id == device_id and rule.last_modified <= at),
        key=lambda rule: rule.priority,
    )
    return next((rule for rule in candidates if rule.matches(source_ip, destination_ip, protocol, port)), None)


class FirewallEvent(NetworkModel):
    event_id: Identifier
    timestamp: UtcDatetime
    device_id: DeviceId
    rule_id: Identifier
    source_ip: IPv4Address
    destination_ip: IPv4Address
    source_port: Port | None = None
    destination_port: Port | None = None
    protocol: TransportProtocol
    action: FirewallAction
    severity: Severity

    @model_validator(mode="after")
    def check_ports(self) -> "FirewallEvent":
        has_ports = self.source_port is not None and self.destination_port is not None
        no_ports = self.source_port is None and self.destination_port is None
        if self.protocol == TransportProtocol.ICMP and not no_ports:
            raise ValueError("ICMP events cannot include ports")
        if self.protocol != TransportProtocol.ICMP and not has_ports:
            raise ValueError("TCP and UDP events require source and destination ports")
        return self


class FirewallData(NetworkModel):
    rules: list[FirewallRule]
    events: list[FirewallEvent]

    @model_validator(mode="after")
    def check_events_match_rules(self) -> "FirewallData":
        ensure_unique([rule.rule_id for rule in self.rules], "firewall rule ids")
        ensure_unique([event.event_id for event in self.events], "firewall event ids")
        for event in self.events:
            matched = match_firewall_rule(
                self.rules, event.device_id, event.source_ip, event.destination_ip, event.protocol,
                event.destination_port, event.timestamp,
            )
            if matched is None or matched.rule_id != event.rule_id or matched.action != event.action:
                raise ValueError(f"firewall event {event.event_id} is inconsistent with the rule base")
        return self


class DhcpPool(NetworkModel):
    pool_id: Identifier
    server_device_id: DeviceId
    site_id: Identifier
    vlan_id: VlanNumber
    subnet: IPv4Network
    range_start: IPv4Address
    range_end: IPv4Address
    gateway: IPv4Address
    dns_servers: list[IPv4Address] = Field(min_length=1)
    lease_time_seconds: int = Field(gt=0)

    @property
    def size(self) -> int:
        return int(self.range_end) - int(self.range_start) + 1

    def contains(self, address: IPv4Address) -> bool:
        return self.range_start <= address <= self.range_end

    @model_validator(mode="after")
    def check_range(self) -> "DhcpPool":
        if self.range_start > self.range_end:
            raise ValueError("range_start must not exceed range_end")
        if not all(address in self.subnet for address in (self.range_start, self.range_end, self.gateway)):
            raise ValueError("pool range and gateway must be inside the subnet")
        if self.contains(self.gateway):
            raise ValueError("gateway cannot be inside the allocatable range")
        return self


class DhcpLease(NetworkModel):
    pool_id: Identifier
    ip_address: IPv4Address
    mac_address: MacAddress
    hostname: str | None = None
    state: LeaseState
    lease_start: UtcDatetime
    lease_end: UtcDatetime

    @model_validator(mode="after")
    def check_times(self) -> "DhcpLease":
        if self.lease_end <= self.lease_start:
            raise ValueError("lease_end must be after lease_start")
        return self


class DhcpEvent(NetworkModel):
    event_id: Identifier
    timestamp: UtcDatetime
    server_device_id: DeviceId
    pool_id: Identifier
    event_type: DhcpEventType
    mac_address: MacAddress | None = None
    ip_address: IPv4Address | None = None
    message: NonEmptyText

    @model_validator(mode="after")
    def check_fields(self) -> "DhcpEvent":
        needs_address = self.event_type in (DhcpEventType.ALLOCATION_SUCCESS, DhcpEventType.IP_CONFLICT)
        if needs_address and (self.ip_address is None or self.mac_address is None):
            raise ValueError(f"{self.event_type.value} requires an IP and MAC address")
        if self.event_type == DhcpEventType.ALLOCATION_FAILURE and (self.mac_address is None or self.ip_address is not None):
            raise ValueError("allocation_failure requires a MAC address and no IP address")
        return self


class DhcpData(NetworkModel):
    pools: list[DhcpPool]
    leases: list[DhcpLease]
    events: list[DhcpEvent]

    @model_validator(mode="after")
    def check_references(self) -> "DhcpData":
        ensure_unique([pool.pool_id for pool in self.pools], "DHCP pool ids")
        ensure_unique([event.event_id for event in self.events], "DHCP event ids")
        ensure_unique([f"{lease.pool_id}:{lease.ip_address}" for lease in self.leases], "DHCP lease addresses")
        pools = {pool.pool_id: pool for pool in self.pools}
        ensure_known([lease.pool_id for lease in self.leases], set(pools), "lease pools")
        ensure_known([event.pool_id for event in self.events], set(pools), "DHCP event pools")
        for lease in self.leases:
            if not pools[lease.pool_id].contains(lease.ip_address):
                raise ValueError(f"lease {lease.ip_address} is outside pool {lease.pool_id}")
        for event in self.events:
            pool = pools[event.pool_id]
            if event.server_device_id != pool.server_device_id:
                raise ValueError(f"DHCP event {event.event_id} server does not serve its pool")
            if event.ip_address is not None and not pool.contains(event.ip_address):
                raise ValueError(f"DHCP event {event.event_id} address is outside its pool")
        return self


class DnsServer(NetworkModel):
    device_id: DeviceId
    ip_address: IPv4Address
    role: DnsServerRole
    zones: list[DomainName] = Field(min_length=1)
    forwarders: list[IPv4Address]


class DnsQuery(NetworkModel):
    query_id: Identifier
    timestamp: UtcDatetime
    client_ip: IPv4Address
    server_ip: IPv4Address
    domain: DomainName
    record_type: DnsRecordType
    result: DnsResult
    answers: list[IPv4Address] = Field(default_factory=list)
    response_time_ms: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def check_result(self) -> "DnsQuery":
        if (self.result == DnsResult.NOERROR) != bool(self.answers):
            raise ValueError("answers are required exactly when the query succeeds")
        if (self.result == DnsResult.TIMEOUT) != (self.response_time_ms is None):
            raise ValueError("response_time_ms is omitted exactly when the query times out")
        return self


class DnsData(NetworkModel):
    servers: list[DnsServer] = Field(min_length=1)
    queries: list[DnsQuery]

    @model_validator(mode="after")
    def check_servers(self) -> "DnsData":
        ensure_unique([server.device_id for server in self.servers], "DNS servers")
        ensure_unique([query.query_id for query in self.queries], "DNS query ids")
        ensure_known([str(query.server_ip) for query in self.queries], {str(server.ip_address) for server in self.servers}, "DNS server addresses")
        return self


class IncidentRecord(NetworkModel):
    incident_id: Identifier
    title: NonEmptyText
    description: NonEmptyText
    category: IncidentCategory
    priority: IncidentPriority
    status: IncidentStatus
    reported_at: UtcDatetime
    reported_by: NonEmptyText
    affected_site_ids: list[Identifier] = Field(min_length=1)
    symptoms: list[NonEmptyText] = Field(min_length=1)


class GroundTruth(NetworkModel):
    root_cause: NonEmptyText
    root_cause_device_ids: list[DeviceId] = Field(min_length=1)
    root_cause_link_ids: list[Identifier]
    affected_site_ids: list[Identifier] = Field(min_length=1)
    affected_path_ids: list[Identifier] = Field(min_length=1)


class ScenarioInfo(NetworkModel):
    scenario_id: Identifier
    name: NonEmptyText
    description: NonEmptyText
    category: IncidentCategory | None = None
    window_start: UtcDatetime
    onset_at: UtcDatetime
    window_end: UtcDatetime

    @model_validator(mode="after")
    def check_window(self) -> "ScenarioInfo":
        if not self.window_start < self.onset_at < self.window_end:
            raise ValueError("onset_at must fall strictly inside the scenario window")
        return self


class ScenarioDataset(NetworkModel):
    scenario: ScenarioInfo
    incident: IncidentRecord | None = None
    ground_truth: GroundTruth | None = None
    events: list[NetworkEvent]
    interface_statistics: list[InterfaceStatistics]
    routing: RoutingData
    firewall: FirewallData
    dhcp: DhcpData
    dns: DnsData

    def timestamps(self) -> list[datetime]:
        values = [event.timestamp for event in self.events]
        values += [sample.timestamp for sample in self.interface_statistics]
        values += [table.collected_at for table in self.routing.routing_tables]
        values += [change.timestamp for change in self.routing.route_changes]
        values += [event.timestamp for event in self.firewall.events]
        values += [event.timestamp for event in self.dhcp.events]
        values += [query.timestamp for query in self.dns.queries]
        if self.incident is not None:
            values.append(self.incident.reported_at)
        return values

    @model_validator(mode="after")
    def check_consistency(self) -> "ScenarioDataset":
        scenario = self.scenario
        has_category = scenario.category is not None
        if (self.incident is not None) != has_category or (self.ground_truth is not None) != has_category:
            raise ValueError("incident and ground_truth are required exactly when the scenario has a category")
        if self.incident is not None and self.incident.category != scenario.category:
            raise ValueError("incident category must match the scenario category")
        if any(not scenario.window_start <= value <= scenario.window_end for value in self.timestamps()):
            raise ValueError("all timestamps must fall inside the scenario window")
        neighbor_changes = [neighbor.last_state_change for neighbor in self.routing.ospf_neighbors + self.routing.bgp_neighbors]
        if any(value > scenario.window_end for value in neighbor_changes):
            raise ValueError("neighbor state changes cannot be after the scenario window")
        ensure_unique([event.event_id for event in self.events], "event ids")
        ensure_unique([f"{sample.interface_id}@{sample.timestamp.isoformat()}" for sample in self.interface_statistics], "interface samples")
        return self
