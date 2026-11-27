"""Synthetic protocol and security telemetry layered over a scenario dataset.

Every file is generated locally (app.protocols.generator) and marked synthetic. Sections are optional: a section that is
absent means it was not collected, which the engines report as insufficient evidence instead of guessing. Records carry
stable ids so every finding can cite exactly what it was based on.
"""
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Interface, IPv6Network
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.network.models import Asn, Count, DeviceId, EventType, Identifier, InterfaceId, MacAddress, Percent, UtcDatetime, VlanNumber

RecordId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/@>|-]*$", max_length=120)]
PortName = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9/.]*$", max_length=32)]
Text = Annotated[str, Field(min_length=1, max_length=300)]
HostName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$", max_length=120)]
Fingerprint = Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")]
Engine = Literal["bgp", "ospf", "stp", "arp", "vlan", "nat", "ipsec", "tcp", "mtu", "qos", "ipv6", "wireless", "multicast",
                 "tls", "threats", "traffic", "lateral"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Section(Model):
    collected_from: list[str] = Field(default_factory=list, max_length=60)
    collected_at: UtcDatetime


class ProtocolEvent(Model):
    """A protocol log line or controller event. `detail` is untrusted text from the device and is never followed."""
    event_id: RecordId
    timestamp: UtcDatetime
    protocol: Engine
    kind: EventType
    device_id: str = Field(min_length=1, max_length=64)
    detail: Text
    port: PortName | None = None
    vlan_id: VlanNumber | None = None
    peer: str | None = Field(default=None, max_length=64)
    ip: IPv4Address | None = None
    mac: MacAddress | None = None
    previous_mac: MacAddress | None = None
    count: int = Field(default=1, ge=1)


# ---------- BGP ----------

class BgpRoute(Model):
    route_id: RecordId
    device_id: DeviceId
    prefix: IPv4Network
    next_hop: IPv4Address
    peer_device_id: DeviceId | None = None
    as_path: list[Asn] = Field(default_factory=list, max_length=20)
    origin_asn: Asn
    local_pref: int = Field(default=100, ge=0)
    best: bool = True
    learned_at: UtcDatetime


class BgpUpdate(Model):
    update_id: RecordId
    timestamp: UtcDatetime
    device_id: DeviceId
    peer_device_id: DeviceId
    prefix: IPv4Network
    action: Literal["announce", "withdraw"]
    as_path: list[Asn] = Field(default_factory=list, max_length=20)


class PrefixAuthorization(Model):
    prefix: IPv4Network
    origin_asn: Asn
    max_length: int = Field(ge=0, le=32)


class BgpSession(Model):
    session_id: RecordId
    device_id: DeviceId
    peer_device_id: DeviceId
    state: Literal["established", "idle", "active", "connect", "opensent", "openconfirm"]
    last_change: UtcDatetime


class BgpData(Section):
    routes: list[BgpRoute]
    updates: list[BgpUpdate]
    authorizations: list[PrefixAuthorization]
    sessions: list[BgpSession] = Field(default_factory=list)


# ---------- OSPF link-state database ----------

class OspfLsa(Model):
    lsa_id: RecordId
    observed_by: DeviceId
    area: str = Field(min_length=1, max_length=16)
    lsa_type: Literal["router", "network", "summary", "external"]
    link_state_id: IPv4Address
    advertising_router: IPv4Address
    sequence: int = Field(ge=0)
    age_seconds: int = Field(ge=0, le=3600)
    checksum: str = Field(pattern=r"^0x[0-9a-f]{4}$")
    link_count: Count = 0


class LsaUpdate(Model):
    update_id: RecordId
    timestamp: UtcDatetime
    observed_by: DeviceId
    lsa_type: Literal["router", "network", "summary", "external"]
    link_state_id: IPv4Address
    advertising_router: IPv4Address
    sequence: int = Field(ge=0)


class OspfLsdbData(Section):
    lsas: list[OspfLsa]
    updates: list[LsaUpdate]
    router_ids: dict[str, IPv4Address] = Field(default_factory=dict)  # device -> configured router id, as collected


# ---------- Spanning tree ----------

class ExpectedRoot(Model):
    site_id: Identifier
    vlan_id: VlanNumber
    device_id: DeviceId


class StpVlanState(Model):
    state_id: RecordId
    device_id: DeviceId
    vlan_id: VlanNumber
    bridge_mac: MacAddress
    bridge_priority: int = Field(ge=0, le=61440)
    root_mac: MacAddress
    root_priority: int = Field(ge=0, le=61440)
    root_port: PortName | None = None
    topology_changes: Count
    last_topology_change: UtcDatetime | None = None
    tc_source_port: PortName | None = None


class StpPort(Model):
    port_id: RecordId
    device_id: DeviceId
    port: PortName
    vlan_id: VlanNumber
    role: Literal["root", "designated", "alternate", "backup", "disabled"]
    state: Literal["forwarding", "blocking", "learning", "listening", "disabled", "err-disabled"]
    edge: bool = False
    bpdu_guard: bool = False


class StpData(Section):
    expected_roots: list[ExpectedRoot]
    vlans: list[StpVlanState]
    ports: list[StpPort]


# ---------- ARP ----------

class ArpEntry(Model):
    entry_id: RecordId
    device_id: DeviceId
    vlan_id: VlanNumber
    ip: IPv4Address
    mac: MacAddress
    port: PortName | None = None
    first_seen: UtcDatetime
    last_seen: UtcDatetime


class GatewayMac(Model):
    site_id: Identifier
    vlan_id: VlanNumber
    ip: IPv4Address
    mac: MacAddress
    device_id: DeviceId
    virtual: bool = False  # a first-hop redundancy (HSRP/VRRP) virtual MAC shared by design


class StaticHost(Model):
    ip: IPv4Address
    mac: MacAddress
    hostname: HostName


class ArpData(Section):
    entries: list[ArpEntry]
    gateways: list[GatewayMac]
    static_hosts: list[StaticHost] = Field(default_factory=list)


# ---------- VLAN trunks ----------

class TrunkPort(Model):
    port_id: RecordId
    device_id: DeviceId
    interface_id: InterfaceId
    link_id: Identifier
    mode: Literal["trunk", "access", "dot1q_subinterfaces"]
    native_vlan: VlanNumber
    allowed_vlans: list[VlanNumber] = Field(max_length=200)
    dtp: Literal["on", "desirable", "auto", "nonegotiate"] = "nonegotiate"


class VlanDatabase(Model):
    device_id: DeviceId
    vlans: list[VlanNumber]


class TrunkData(Section):
    ports: list[TrunkPort]
    databases: list[VlanDatabase]


# ---------- NAT ----------

class NatPool(Model):
    pool_id: Identifier
    device_id: DeviceId
    kind: Literal["pat", "dynamic", "static"]
    public_addresses: int = Field(ge=1, le=65536)
    ports_per_address: int = Field(ge=1, le=64512)


class NatRule(Model):
    rule_id: Identifier
    device_id: DeviceId
    order: int = Field(ge=1)
    source: IPv4Network
    pool_id: Identifier | None = None  # None: traffic matching this rule is not translated
    enabled: bool = True
    last_modified: UtcDatetime


class NatSample(Model):
    sample_id: RecordId
    timestamp: UtcDatetime
    pool_id: Identifier
    active_translations: Count
    allocation_failures: Count


class NatTopTalker(Model):
    talker_id: RecordId
    timestamp: UtcDatetime
    pool_id: Identifier
    inside_ip: IPv4Address
    translations: Count
    destinations: Count


class NatData(Section):
    pools: list[NatPool]
    rules: list[NatRule]
    samples: list[NatSample]
    top_talkers: list[NatTopTalker]
    site_networks: dict[str, list[IPv4Network]] = Field(default_factory=dict)  # site -> user networks that need internet


# ---------- IPsec ----------

class IpsecProposal(Model):
    encryption: str = Field(min_length=1, max_length=32)
    integrity: str = Field(min_length=1, max_length=32)
    dh_group: int = Field(ge=1, le=32)
    lifetime_seconds: int = Field(ge=60, le=86400)


class IpsecTunnel(Model):
    tunnel_id: Identifier
    device_id: DeviceId
    peer_device_id: DeviceId
    local_ip: IPv4Address
    peer_ip: IPv4Address
    role: Literal["primary", "backup"]
    ike_version: Literal[1, 2] = 2
    auth: Literal["psk", "certificate"] = "psk"
    local_proposal: IpsecProposal
    peer_proposal: IpsecProposal | None = None  # what the peer offered, when it was logged
    local_selectors: list[IPv4Network]
    peer_selectors: list[IPv4Network] | None = None
    phase1: Literal["up", "down", "negotiating"]
    phase2_sas: Count
    encaps: Count
    decaps: Count
    errors: Count = 0
    dpd_timeouts: Count = 0
    underlay_interface_id: InterfaceId | None = None
    last_change: UtcDatetime


class IpsecData(Section):
    tunnels: list[IpsecTunnel]


# ---------- TCP ----------

class TcpSample(Model):
    sample_id: RecordId
    timestamp: UtcDatetime
    site_id: Identifier
    service: Literal["application", "internet", "files"]
    path_id: Identifier
    server_device_id: DeviceId | None = None
    flows: Count
    retransmission_percent: Percent
    bulk_retransmission_percent: Percent | None = None
    small_retransmission_percent: Percent | None = None
    rtt_ms: float = Field(ge=0)
    syn_retry_percent: Percent = 0
    zero_window_events: Count = 0
    resets: Count = 0


class TcpData(Section):
    samples: list[TcpSample]


# ---------- MTU ----------

class MtuProbe(Model):
    probe_id: RecordId
    timestamp: UtcDatetime
    source_device_id: DeviceId
    destination_ip: IPv4Address
    path_id: Identifier | None = None
    size: int = Field(ge=68, le=9216)
    df: bool
    result: Literal["ok", "timeout", "frag_needed"]


class InterfaceMtu(Model):
    interface_id: InterfaceId
    ip_mtu: int = Field(ge=576, le=9216)
    tunnel_overhead: int = Field(default=0, ge=0, le=200)
    mss_clamp: int | None = Field(default=None, ge=536, le=9176)


class FragmentCounter(Model):
    counter_id: RecordId
    timestamp: UtcDatetime
    device_id: DeviceId
    fragments_created: Count
    reassembly_failures: Count
    frag_needed_sent: Count


class MtuData(Section):
    probes: list[MtuProbe]
    interfaces: list[InterfaceMtu]
    counters: list[FragmentCounter]
    icmp_filtered_on: list[DeviceId] = Field(default_factory=list)


# ---------- QoS ----------

class QosClass(Model):
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]*$", max_length=40)
    dscp: list[int] = Field(max_length=64)
    priority: bool = False
    bandwidth_percent: int = Field(ge=0, le=100)
    drops_expected: bool = False  # a scavenger or best-effort class where drops under congestion are by design


class QosPolicy(Model):
    policy_id: RecordId
    interface_id: InterfaceId
    direction: Literal["input", "output"]
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]*$", max_length=40)
    classes: list[QosClass]
    applied: bool = True


class ExpectedPolicy(Model):
    interface_id: InterfaceId
    direction: Literal["input", "output"]
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]*$", max_length=40)


class QosSample(Model):
    sample_id: RecordId
    timestamp: UtcDatetime
    interface_id: InterfaceId
    class_name: str = Field(max_length=40)
    offered_kbps: float = Field(ge=0)
    drop_percent: Percent
    queue_depth: Count = 0


class DscpObservation(Model):
    observation_id: RecordId
    timestamp: UtcDatetime
    interface_id: InterfaceId
    direction: Literal["input", "output"]
    traffic: Literal["voice", "video", "signalling", "business", "bulk", "best_effort", "scavenger"]
    expected_dscp: int = Field(ge=0, le=63)
    observed_dscp: int = Field(ge=0, le=63)
    share_percent: Percent = 100


class QosData(Section):
    expected: list[ExpectedPolicy]
    policies: list[QosPolicy]
    samples: list[QosSample]
    markings: list[DscpObservation]


# ---------- IPv6 ----------

class Ipv6Address(Model):
    interface_id: InterfaceId
    address: IPv6Interface
    link_local: IPv6Address


class Ipv6Route(Model):
    route_id: RecordId
    device_id: DeviceId
    prefix: IPv6Network
    protocol: Literal["connected", "static", "ospfv3", "bgp", "nd"]
    next_hop: IPv6Address | None = None
    interface_id: InterfaceId


class Ospfv3Neighbor(Model):
    neighbor_id: RecordId
    device_id: DeviceId
    interface_id: InterfaceId
    neighbor_device_id: DeviceId
    state: Literal["full", "2way", "init", "exstart", "down"]
    last_change: UtcDatetime


class RouterAdvert(Model):
    ra_id: RecordId
    timestamp: UtcDatetime
    site_id: Identifier
    vlan_id: VlanNumber
    source_mac: MacAddress
    source_link_local: IPv6Address
    router_device_id: DeviceId | None = None  # None: the source is not a known router
    prefix: IPv6Network
    router_lifetime: int = Field(ge=0, le=9000)


class SitePrefix(Model):
    site_id: Identifier
    vlan_id: VlanNumber
    prefix: IPv6Network


class Ipv6Probe(Model):
    probe_id: RecordId
    timestamp: UtcDatetime
    site_id: Identifier
    service: Literal["application", "internet", "dns"]
    ipv4_ok: bool
    ipv6_ok: bool


class Ipv6Data(Section):
    addresses: list[Ipv6Address]
    routes: list[Ipv6Route]
    neighbors: list[Ospfv3Neighbor]
    adverts: list[RouterAdvert]
    site_prefixes: list[SitePrefix]
    probes: list[Ipv6Probe]


# ---------- Wireless ----------

class WirelessController(Model):
    controller_id: Annotated[str, Field(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$")]
    platform: str = Field(min_length=1, max_length=60)
    synthetic: Literal[True] = True


class AccessPoint(Model):
    ap_id: Annotated[str, Field(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$")]
    site_id: Identifier
    controller_id: str = Field(max_length=64)
    switch_device_id: DeviceId
    switch_port: PortName


class RadioSample(Model):
    sample_id: RecordId
    timestamp: UtcDatetime
    ap_id: str = Field(max_length=64)
    band: Literal["2.4GHz", "5GHz", "6GHz"]
    channel: int = Field(ge=1, le=233)
    channel_utilization: Percent
    non_wifi_interference: Percent
    noise_floor_dbm: float = Field(ge=-110, le=-40)
    retry_percent: Percent
    clients: Count
    avg_rssi_dbm: float = Field(ge=-100, le=-10)
    avg_snr_db: float = Field(ge=0, le=80)
    co_channel_aps: Count = 0


class RogueAp(Model):
    rogue_id: RecordId
    site_id: Identifier
    bssid: MacAddress
    ssid: str = Field(min_length=1, max_length=32)
    channel: int = Field(ge=1, le=233)
    first_seen: UtcDatetime
    detected_on_wire: bool = False


class WirelessData(Section):
    controllers: list[WirelessController]
    access_points: list[AccessPoint]
    samples: list[RadioSample]
    rogues: list[RogueAp] = Field(default_factory=list)
    corporate_ssids: list[str] = Field(default_factory=list)


# ---------- Multicast ----------

class PimNeighbor(Model):
    neighbor_id: RecordId
    device_id: DeviceId
    interface_id: InterfaceId
    neighbor_device_id: DeviceId
    state: Literal["up", "down"]
    last_change: UtcDatetime


class RpMapping(Model):
    mapping_id: RecordId
    device_id: DeviceId
    group_range: IPv4Network
    rp_address: IPv4Address


class Mroute(Model):
    mroute_id: RecordId
    device_id: DeviceId
    source: IPv4Address | None = None
    group: IPv4Address
    incoming_interface_id: InterfaceId | None = None
    outgoing_interface_ids: list[InterfaceId] = Field(default_factory=list)
    packets_per_second: float = Field(ge=0)
    rpf_failures: Count = 0


class IgmpGroup(Model):
    group_id: RecordId
    device_id: DeviceId
    vlan_id: VlanNumber
    group: IPv4Address
    members: Count
    querier_present: bool = True


class MulticastStream(Model):
    stream_id: Identifier
    name: str = Field(min_length=1, max_length=60)
    source_ip: IPv4Address
    source_device_id: DeviceId
    group: IPv4Address
    receiver_sites: list[Identifier]


class MulticastData(Section):
    expected_rp: IPv4Address
    group_range: IPv4Network
    streams: list[MulticastStream]
    neighbors: list[PimNeighbor]
    rp_mappings: list[RpMapping]
    mroutes: list[Mroute]
    groups: list[IgmpGroup]


# ---------- TLS ----------

class Certificate(Model):
    certificate_id: Identifier
    service: str = Field(min_length=1, max_length=40)
    device_id: DeviceId
    common_name: HostName
    sans: list[HostName] = Field(max_length=20)
    issuer: str = Field(min_length=1, max_length=80)
    self_signed: bool = False
    not_before: UtcDatetime
    not_after: UtcDatetime
    key_bits: int = Field(ge=256, le=16384)
    chain_complete: bool = True
    fingerprint: Fingerprint


class TlsHandshake(Model):
    handshake_id: RecordId
    timestamp: UtcDatetime
    client_site_id: Identifier
    client_ip: IPv4Address
    server_ip: IPv4Address
    sni: HostName
    result: Literal["success", "failure"]
    alert: Literal["certificate_expired", "unknown_ca", "bad_certificate", "handshake_failure", "protocol_version"] | None = None
    tls_version: Literal["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"] | None = None
    presented_fingerprint: Fingerprint | None = None
    via_inspection: bool = False

    @model_validator(mode="after")
    def check_alert(self) -> "TlsHandshake":
        if (self.result == "failure") != (self.alert is not None):
            raise ValueError("an alert is recorded exactly when the handshake fails")
        return self


class InspectionPolicy(Model):
    device_id: DeviceId
    decrypts: bool
    resign_ca: str = Field(min_length=1, max_length=80)
    sites: list[Identifier] = Field(default_factory=list)


class TlsData(Section):
    certificates: list[Certificate]
    handshakes: list[TlsHandshake]
    inspection: list[InspectionPolicy] = Field(default_factory=list)
    trusted_cas: list[str] = Field(default_factory=list)


# ---------- Security ----------

class Host(Model):
    ip: IPv4Address
    hostname: HostName
    site_id: Identifier
    role: Literal["workstation", "server", "printer", "phone", "scanner", "jump_host", "backup", "network"]
    mac: MacAddress | None = None


class SecurityFlow(Model):
    flow_id: RecordId
    start: UtcDatetime
    duration_seconds: float = Field(ge=0)
    src_ip: IPv4Address
    dst_ip: IPv4Address
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp", "icmp"]
    bytes_out: Count
    bytes_in: Count
    packets: Count
    state: Literal["established", "rejected", "no_reply", "reset"]
    sensor_device_id: DeviceId


class AuthEvent(Model):
    auth_id: RecordId
    timestamp: UtcDatetime
    src_ip: IPv4Address
    dst_host: HostName
    account: str = Field(pattern=r"^[a-z0-9._-]{1,40}$")
    protocol: Literal["kerberos", "ntlm", "ssh", "rdp", "winrm", "smb", "radius", "ldap"]
    result: Literal["success", "failure"]


class DnsLog(Model):
    log_id: RecordId
    timestamp: UtcDatetime
    client_ip: IPv4Address
    qname: str = Field(pattern=r"^[a-z0-9.-]{1,253}$")
    qtype: Literal["A", "AAAA", "TXT", "CNAME", "MX", "NULL"]
    response_bytes: Count


class IdsAlert(Model):
    alert_id: RecordId
    timestamp: UtcDatetime
    sensor_device_id: DeviceId
    src_ip: IPv4Address
    dst_ip: IPv4Address
    signature: Text
    category: Literal["recon", "credential_access", "lateral_movement", "command_and_control", "exfiltration", "policy"]
    severity: Literal["low", "medium", "high"]


class IntelIndicator(Model):
    indicator: str = Field(min_length=1, max_length=253)
    kind: Literal["ip", "domain"]
    label: str = Field(min_length=1, max_length=80)
    synthetic: Literal[True] = True


class MaintenanceWindow(Model):
    start: UtcDatetime
    end: UtcDatetime
    reason: Text
    devices: list[str] = Field(default_factory=list)
    hosts: list[IPv4Address] = Field(default_factory=list)


class Allowlist(Model):
    scanners: list[IPv4Address] = Field(default_factory=list)
    jump_hosts: list[IPv4Address] = Field(default_factory=list)
    backup_servers: list[IPv4Address] = Field(default_factory=list)
    periodic_destinations: list[str] = Field(default_factory=list)
    maintenance: list[MaintenanceWindow] = Field(default_factory=list)


class SecurityData(Section):
    hosts: list[Host]
    flows: list[SecurityFlow]
    auth: list[AuthEvent]
    dns_logs: list[DnsLog]
    alerts: list[IdsAlert]
    intel: list[IntelIndicator]
    allowlist: Allowlist


class ProtocolTelemetry(Model):
    scenario_id: Identifier
    synthetic: Literal[True] = True
    description: str = Field(min_length=1, max_length=400)
    events: list[ProtocolEvent] = Field(default_factory=list)
    bgp: BgpData | None = None
    ospf: OspfLsdbData | None = None
    stp: StpData | None = None
    arp: ArpData | None = None
    vlan: TrunkData | None = None
    nat: NatData | None = None
    ipsec: IpsecData | None = None
    tcp: TcpData | None = None
    mtu: MtuData | None = None
    qos: QosData | None = None
    ipv6: Ipv6Data | None = None
    wireless: WirelessData | None = None
    multicast: MulticastData | None = None
    tls: TlsData | None = None
    security: SecurityData | None = None


# Which telemetry section each engine reads. The three security correlation engines share the security section.
SECTION_OF: dict[str, str] = {
    "bgp": "bgp", "ospf": "ospf", "stp": "stp", "arp": "arp", "vlan": "vlan", "nat": "nat", "ipsec": "ipsec", "tcp": "tcp",
    "mtu": "mtu", "qos": "qos", "ipv6": "ipv6", "wireless": "wireless", "multicast": "multicast", "tls": "tls",
    "threats": "security", "traffic": "security", "lateral": "security",
}
