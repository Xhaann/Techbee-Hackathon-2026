"""Vendor-aware, read-only verification commands for protocol findings, with what healthy and faulty output look like.

The platform comes from the topology (Cisco IOS XE routers and switches, PAN-OS firewalls, Linux servers, and the
synthetic wireless controller). Every command passes the read-only safety check before it is offered; commands are
suggestions for an engineer to run, and the tool never runs them on a device.
"""
from dataclasses import asdict, dataclass
from typing import Any

from app.engine.safety import is_read_only_command
from app.network.repository import load_topology


@dataclass(frozen=True)
class Check:
    device_id: str
    platform: str
    command: str
    purpose: str
    healthy: str
    faulty: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def platform(device_id: str | None) -> str:
    if not device_id:
        return "Cisco IOS XE"
    device = next((d for d in load_topology().devices if d.device_id == device_id), None)
    if device is None:
        return "Cisco Catalyst 9800 (synthetic controller)" if "-AP-" in device_id or "-WLC-" in device_id else "Cisco IOS XE"
    if device.vendor.startswith("Palo Alto"):
        return "PAN-OS"
    if device.device_type.value == "server":
        return "Linux"
    return "Cisco IOS XE"


def short(interface: str | None) -> str:
    return interface.split(":", 1)[1] if interface and ":" in interface else (interface or "")


def make(device: str | None, command: str, purpose: str, healthy: str, faulty: str) -> Check | None:
    if not device or not is_read_only_command(command):
        return None
    return Check(device, platform(device), command, purpose, healthy, faulty)


def commands_for(code: str, device: str | None, facts: dict[str, Any]) -> list[dict[str, Any]]:
    f = facts
    candidates: list[Check | None] = []
    if code == "BGP_ROUTE_LEAK" or code == "BGP_ORIGIN_HIJACK_SUSPECTED":
        prefix = f.get("prefix", "")
        network, _, length = prefix.partition("/")
        mask = {"24": "255.255.255.0", "25": "255.255.255.128", "26": "255.255.255.192", "27": "255.255.255.224", "28": "255.255.255.240"}.get(length, "255.255.255.0")
        for seen in (f.get("seen_on") or [device])[:2]:
            candidates.append(make(seen, f"show ip bgp {network} {mask}", f"See who originates {prefix} and the AS path",
                                   f"No entry, or origin AS{f.get('registered_origin')}", f"Origin AS{f.get('origin_asn')} with path {', '.join(f.get('as_paths', []))}"))
        candidates.append(make(device, "show ip bgp summary", "Check prefixes sent and received per neighbour", "Expected prefix counts",
                               "One more prefix than usual from the leaking peer"))
    elif code in ("BGP_SESSION_DOWN", "BGP_SESSION_STATE_CONFLICT", "BGP_WITHDRAWAL_BURST", "BGP_ROUTE_FLAP", "BGP_NEXT_HOP_UNREACHABLE"):
        candidates.append(make(device, "show ip bgp summary", "Session state and uptime for every neighbour", "Established with a long uptime",
                               "Idle/Active, or an uptime of a few minutes (it reset)"))
        candidates.append(make(device, "show logging | include BGP", "BGP state changes in the log", "No recent ADJCHANGE lines",
                               "Down/Up ADJCHANGE lines at the incident time"))
    elif code.startswith("OSPF_"):
        rid = f.get("router_id")
        candidates.append(make(device or "CORE-RTR-01", f"show ip ospf database router {rid}" if rid else "show ip ospf database",
                               "Compare the router LSA on several routers", "Same sequence and checksum everywhere, age under 1800 s",
                               "Different sequences or checksums, rising sequence numbers, or age 3600 (MaxAge)"))
        candidates.append(make(device or "CORE-RTR-01", "show ip ospf", "Router ID and SPF run count", "A unique router ID and few SPF runs",
                               "A router ID used elsewhere, or SPF running every few seconds"))
    elif code.startswith("STP_"):
        vlan = f.get("vlan", 10)
        candidates.append(make(device, f"show spanning-tree vlan {vlan} detail", "Topology changes and where they come from",
                               "A handful of changes, the last one long ago", f"Hundreds of changes, the last seconds ago, from {f.get('source_port') or 'an access port'}"))
        candidates.append(make(device, "show mac address-table notification mac-move", "MAC moves between ports", "No moves",
                               "The gateway MAC moving between the uplink and an access port"))
        candidates.append(make(device, "show interfaces counters", "Broadcast and multicast counters per port", "Broadcasts a small share of traffic",
                               "Broadcast counters climbing on the looped ports"))
    elif code.startswith("ARP_"):
        ip = f.get("gateway") or f.get("ip")
        vlan = f.get("vlan", 10)
        if ip:
            candidates.append(make(device, f"show ip arp {ip}", f"Which MAC answers for {ip}", "The expected MAC",
                                   f"{f.get('claimed_by') or 'a different MAC'}, or the entry changing between checks"))
        candidates.append(make(device, f"show ip arp vlan {vlan}", "All ARP entries in the VLAN", "One MAC per address",
                               "One address with two MACs, or one MAC answering for many addresses"))
        candidates.append(make(device, "show ip dhcp snooping binding", "Which MAC DHCP leased each address to", "Bindings match the ARP table",
                               "An ARP entry with no matching binding"))
    elif code.startswith("VLAN_"):
        candidates.append(make(device, "show interfaces trunk", "Allowed and native VLANs on each trunk", "Both ends list the same VLANs and native VLAN",
                               "A VLAN missing on one end, or different native VLANs"))
        candidates.append(make(device, "show cdp neighbors detail", "What the far end reports, including native VLAN", "Native VLAN matches",
                               "A native VLAN mismatch warning"))
        candidates.append(make(device, "show vlan brief", "VLANs present in the switch database", "Every site VLAN listed", "A site VLAN missing"))
    elif code.startswith("NAT_"):
        candidates.append(make(device, "show running nat-policy", "NAT rules in order", "A rule translating every user network", "A missing or shadowed rule"))
        candidates.append(make(device, "show running ippool", "Pool size and usage", "Usage well below capacity", "Usage at 100% with allocation failures"))
        candidates.append(make(device, "show session info", "Session table and NAT allocation counters", "No NAT allocation failures",
                               "NAT allocation failures increasing"))
    elif code.startswith("IPSEC_"):
        if platform(device) == "PAN-OS":
            candidates.append(make(device, "show vpn ike-sa", "IKE SA state per peer", "Established SAs for every branch", "No SA, or repeated negotiation"))
            candidates.append(make(device, "show vpn ipsec-sa", "IPsec SA state", "Two SAs per tunnel", "No SAs"))
        else:
            candidates.append(make(device, "show crypto ikev2 sa", "IKE SA state", "READY", "No SA, or stuck in negotiation"))
            candidates.append(make(device, "show crypto ipsec sa", "Encapsulation and decapsulation counters", "Both counters increasing",
                                   "Encaps rising with decaps at zero (one-way), or no SA"))
    elif code.startswith("TCP_"):
        server = f.get("server")
        site = f.get("path", "")
        if server:
            candidates.append(make(server, "netstat -s", "Retransmission and window statistics on the server",
                                   "Few retransmits, no zero windows", "Zero-window or retransmit counters rising"))
        router = f"{site.split('-')[1]}-RTR-01" if site.startswith("PATH-") else device
        candidates.append(make(router, "show interfaces", "Errors, drops and load on the site router's interfaces", "No CRC errors or output drops",
                               "CRC errors, output drops or load near 255/255"))
        candidates.append(make(router, "ping 10.100.100.40 repeat 100", "Loss and latency to the data centre", "0% loss, steady latency",
                               "Loss above 1% or latency spikes"))
    elif code.startswith("MTU_"):
        source = f.get("source") or device
        candidates.append(make(source, "ping 10.100.100.40 size 1500 df-bit", "Does a full-size packet get through without fragmentation?",
                               "Success", "Timeouts with no 'M' (fragmentation needed) replies"))
        candidates.append(make(source, f"ping 10.100.100.40 size {f.get('effective_mtu', 1400)} df-bit", "Largest size that passes", "Success", "Timeouts"))
        candidates.append(make(source, f"show interfaces {short(device + ':Gi0/0/0') if device else 'Gi0/0/0'}", "Configured MTU on the WAN interface",
                               "MTU 1500 and matching the far end", "A lower MTU or one that differs from the far end"))
    elif code.startswith("QOS_"):
        interface = f.get("first_wrong") or f.get("interface")
        candidates.append(make(device, f"show policy-map interface {short(interface) or 'Gi0/0/0'} output", "Per-class traffic and drops",
                               "Voice in the priority class with no drops", "Voice class empty or dropping; class-default dropping"))
        candidates.append(make(device, "show class-map", "What each class matches", "VOICE matches DSCP EF or the RTP ACL", "VOICE matches an ACL that does not exist"))
    elif code.startswith("IPV6_"):
        candidates.append(make(device, "show ipv6 ospf neighbor", "OSPFv3 adjacencies", "FULL", "Missing or DOWN"))
        candidates.append(make(device, "show ipv6 route", "IPv6 default and site routes", "A ::/0 route and the site prefixes", "No ::/0, or site prefixes missing"))
        candidates.append(make(device, "show ipv6 interface brief", "IPv6 addressing per interface", "Addresses up", "Interface down or no address"))
    elif code.startswith("WIFI_"):
        candidates.append(make("CORE-WLC-01", f"show ap name {device} config dot11 24ghz" if device else "show ap summary",
                               "Channel, power and noise for the radio", "Noise around -94 dBm", "Noise above -85 dBm"))
        candidates.append(make("CORE-WLC-01", "show ap auto-rf dot11 24ghz", "Interference and utilisation per AP", "Low interference",
                               "High non-Wi-Fi interference on neighbouring APs"))
        candidates.append(make("CORE-WLC-01", "show wireless wps rogue ap summary", "Rogue and neighbouring APs", "No rogues on the wire",
                               "A rogue using our SSID or seen on our wired network"))
    elif code.startswith("MCAST_"):
        candidates.append(make(device, "show ip pim rp mapping", "RP used for the group range", "RP 10.255.0.1", "Any other RP"))
        candidates.append(make(device, f"show ip mroute {f.get('group', '239.10.1.1')}", "Multicast state and incoming interface",
                               "(S,G) with traffic and the right incoming interface", "Only (*,G), zero rate, or RPF failures"))
        candidates.append(make(device, f"show ip rpf {f.get('source', '10.100.100.40')}", "Interface used to reach the source",
                               "The same interface as the mroute's incoming interface", "A different interface"))
    elif code.startswith("TLS_"):
        name = f.get("sni") or f.get("common_name") or "erp.corp.example.com"
        candidates.append(make(device or "DC1-SRV-APP-01", f"openssl s_client -connect {name}:443 -servername {name} -brief",
                               "Which certificate the server presents and whether it verifies", "Verification OK, a current notAfter",
                               "certificate has expired, an unexpected issuer, or verify error"))
        candidates.append(make(device or "DC1-SRV-APP-01", "journalctl -u nginx --since -1h", "Web server TLS errors", "No certificate errors",
                               "Certificate or handshake errors"))
    elif code.startswith(("SUSPICIOUS_", "LATERAL_", "THREAT_")):
        host = f.get("source") or f.get("client") or f.get("main_host") or (f.get("hosts") or [None])[0]
        fw = "CORE-FW-01"
        if host:
            candidates.append(make(fw, "show log threat", "Threat log entries", "No entries for the host", f"Entries involving {host}"))
            candidates.append(make(fw, "show log traffic", "Traffic log entries", "Normal destinations", f"Repeated or bulk sessions from {host}"))
        site = f"{(host or '').split('.')[1] if host and host.count('.') == 3 else ''}"
        switch = {"10": "NYC-SW-01", "20": "SIN-SW-01", "30": "BLR-SW-01"}.get(site)
        if switch and host:
            candidates.append(make(switch, f"show ip arp {host}", "Which port and MAC the host uses", "One MAC on one access port",
                                   "Unexpected MAC or port"))
    return [c.as_dict() for c in candidates if c is not None][:3]
