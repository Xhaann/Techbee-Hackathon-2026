"""Read-only commands for each device, with what a healthy and a faulty result look like and what to do next.

Commands are rendered for the device's platform (Cisco IOS XE routers and switches, Palo Alto PAN-OS firewalls, Linux
servers) with real interface names and peer addresses from the topology. Every rendered command must pass
app.engine.safety.is_read_only_command; any that does not is dropped, so nothing here can change a device.
"""
from dataclasses import dataclass
from functools import lru_cache

from app.engine.safety import is_read_only_command
from app.engine.schema import FaultDomain
from app.network.models import DeviceRole, DeviceType, RoutingProtocol
from app.network.repository import load_topology

SERVICE_SERVER = {"application": "DC1-SRV-APP-01", "dns": "DC1-SRV-DNS-01", "dhcp": "DC1-SRV-DHCP-01", "authentication": "DC1-SRV-AUTH-01"}
SERVICE_PORT = {"application": ("tcp", 443), "dns": ("udp", 53), "dhcp": ("udp", 67), "authentication": ("udp", 1812),
                "internet": ("tcp", 443)}
INTERNAL_NAME = "erp.corp.example.com"


@dataclass(frozen=True)
class Command:
    device_id: str
    command: str
    platform: str
    purpose: str
    healthy: str
    faulty: str
    if_faulty: str
    if_healthy: str
    domain: FaultDomain
    tool_equivalent: tuple[str, dict] | None = None

    def as_dict(self) -> dict:
        return {"device_id": self.device_id, "command": self.command, "platform": self.platform, "purpose": self.purpose,
                "expected_healthy": self.healthy, "expected_fault": self.faulty, "if_fault": self.if_faulty,
                "if_healthy": self.if_healthy, "domain": self.domain.value,
                "tool_equivalent": {"tool": self.tool_equivalent[0], "arguments": self.tool_equivalent[1]} if self.tool_equivalent else None}


@lru_cache(maxsize=1)
def facts() -> dict:
    topology = load_topology()
    devices = {d.device_id: d for d in topology.devices}
    interfaces = {i.interface_id: i for i in topology.interfaces}
    edge = {d.site_id: d.device_id for d in topology.devices if d.role == DeviceRole.WAN_EDGE}
    switch = {d.site_id: d.device_id for d in topology.devices if d.role == DeviceRole.ACCESS_SWITCH}
    wan = {}
    for link in topology.links:
        if link.link_type.value == "wan":
            for local, remote in ((link.a_interface_id, link.b_interface_id), (link.b_interface_id, link.a_interface_id)):
                device = interfaces[local].device_id
                if devices[device].role == DeviceRole.WAN_EDGE:
                    wan[device] = (interfaces[local].name, str(interfaces[remote].ip_address.ip) if interfaces[remote].ip_address else None,
                                   link.link_id, link.routing_protocol, interfaces[remote].device_id, interfaces[remote].name)
    users = {}
    for vlan in topology.vlans:
        if vlan.vlan_id == 10:
            users[vlan.site_id] = (str(vlan.subnet), str(vlan.subnet[100]), vlan.gateway_interface_id.split(":", 1)[1])
    access_port = {}
    for interface in topology.interfaces:
        if devices[interface.device_id].role == DeviceRole.ACCESS_SWITCH and interface.mode.value == "access" and 10 in interface.vlan_ids:
            access_port.setdefault(interface.device_id, interface.name)
    servers = {d.device_id: str(d.management_ip) for d in topology.devices if d.device_type == DeviceType.SERVER}
    return {"devices": devices, "edge": edge, "switch": switch, "wan": wan, "users": users, "access_port": access_port,
            "servers": servers}


def platform(device_id: str) -> str:
    device = facts()["devices"][device_id]
    if device.device_type == DeviceType.FIREWALL:
        return "PAN-OS"
    if device.device_type == DeviceType.SERVER:
        return "Linux"
    return "Cisco IOS XE"


def safe(commands: list[Command]) -> list[Command]:
    return [c for c in commands if is_read_only_command(c.command)]


def wan_edge_commands(site_id: str) -> list[Command]:
    f = facts()
    edge = f["edge"].get(site_id)
    if edge is None or edge not in f["wan"]:
        return []
    name, peer, link_id, protocol, core, core_if = f["wan"][edge]
    commands = [
        Command(edge, f"show interfaces {name}", "Cisco IOS XE", f"State and error counters of the WAN interface ({link_id})",
                f"{name} is up, line protocol is up; input errors and CRC not increasing",
                f"{name} is down (or line protocol down), or CRC/input errors rising",
                f"The circuit or its optics are failing: collect the counters and open a case with the carrier for {link_id}.",
                "The interface is fine: move on to the routing session.", FaultDomain.WAN_ISP,
                ("get_interface_stats", {"device_id": edge, "interface": name})),
    ]
    if peer:
        commands.append(Command(edge, f"ping {peer} source {name} repeat 100", "Cisco IOS XE", f"Loss to the core end of {link_id} ({core} {core_if})",
                                "Success rate is 100 percent (100/100)", "Success rate below 100 percent, or 0 percent",
                                "Loss on the directly connected circuit points at the carrier or the physical link.",
                                "The circuit passes traffic: the fault is above layer 1.", FaultDomain.WAN_ISP,
                                ("analyze_packet_loss", {"device_id": edge, "interface": name})))
    if protocol == RoutingProtocol.BGP:
        commands.append(Command(edge, "show ip bgp summary", "Cisco IOS XE", f"BGP session to {core} over {link_id}",
                                f"Neighbor {peer} with a prefix count in State/PfxRcd (session Established)",
                                f"Neighbor {peer} in Idle or Active, or 0 prefixes",
                                "No BGP session means no routes to the data centre; check the interface first, then the BGP configuration.",
                                "Routing is up: check reachability to the service.", FaultDomain.ROUTING,
                                ("analyze_routing_adjacency", {"device_id": edge})))
    elif protocol == RoutingProtocol.OSPF:
        commands.append(Command(edge, "show ip ospf neighbor", "Cisco IOS XE", f"OSPF adjacency to {core} over {link_id}",
                                f"Neighbor {core} in FULL state", "Neighbor missing, or stuck in INIT/EXSTART/EXCHANGE",
                                "EXSTART/EXCHANGE usually means an MTU mismatch; missing usually means authentication or hello mismatch. "
                                "Compare both ends.", "OSPF is up: check reachability to the service.", FaultDomain.ROUTING,
                                ("analyze_routing_adjacency", {"device_id": edge})))
        commands.append(Command(edge, f"show ip ospf interface {name}", "Cisco IOS XE", "OSPF parameters on the WAN interface (MTU, authentication)",
                                "Same network type, timers and authentication as the core end", "Authentication or MTU differs from the core end",
                                "A parameter mismatch on one end: compare with the core router's interface and the change history.",
                                "Parameters match: look at the core end.", FaultDomain.ROUTING, ("get_change_history", {"device_id": edge})))
    commands.append(Command(edge, "show ip route 10.100.100.0", "Cisco IOS XE", "Route from the branch to the data-centre server subnet",
                            "Routing entry for 10.100.100.0/24 via the WAN next hop", "% Network not in table",
                            "No route: the routing session is down or the prefix is filtered.", "The route is present: test the path to the service.",
                            FaultDomain.ROUTING, ("get_routing_state", {"device_id": edge, "prefix": "10.100.100.0/24"})))
    return safe(commands)


def service_commands(site_id: str, service: str) -> list[Command]:
    f = facts()
    users = f["users"].get(site_id)
    edge = f["edge"].get(site_id)
    commands: list[Command] = []
    if service in ("application", "internet") and users and edge:
        subnet, host, gateway = users
        target = f["servers"]["DC1-SRV-APP-01"] if service == "application" else "203.0.113.10"
        commands.append(Command(edge, f"traceroute {target} source {gateway}", "Cisco IOS XE",
                                f"Path from the {site_id} user gateway to the {'ERP server' if service == 'application' else 'internet edge'}",
                                "Every hop answers through the core to the data centre", "The trace stops (* * *) at a hop",
                                "Where the trace stops is the failing hop: check that device's interfaces, routes and policy.",
                                "The path is complete at layer 3: check firewall policy and the service itself.", FaultDomain.ROUTING,
                                ("trace_packet", {"source": host, "destination": "DC1-SRV-APP-01" if service == "application" else "203.0.113.10",
                                                  "protocol": "tcp", "port": 443})))
        commands.append(Command("DC1-FW-01", "show log traffic action equal deny", "PAN-OS",
                                f"Denied sessions from {subnet} on the data-centre firewall",
                                f"No deny entries for {subnet}", f"Deny entries from {subnet} to 10.100.100.40 port 443 naming a rule",
                                "A rule is denying the traffic: identify it and raise a change to correct it (a human decision).",
                                "The firewall is not denying it: check the server and DNS.", FaultDomain.FIREWALL,
                                ("get_firewall_logs", {"source": subnet})))
    if service == "dns" and users:
        commands.append(Command("DC1-SRV-DNS-01", f"dig @10.100.100.10 {INTERNAL_NAME} A", "Linux",
                                "Whether the primary DNS server answers for the internal zone", "status: NOERROR with an A record",
                                "status: SERVFAIL, or connection timed out", "The DNS server cannot answer for the zone: check its zone status.",
                                "DNS answers: the problem is elsewhere.", FaultDomain.DNS, ("get_dhcp_dns_status", {"site_id": site_id})))
        commands.append(Command("DC1-SRV-DNS-01", "rndc zonestatus corp.example.com", "Linux", "Load state and expiry of the internal zone",
                                "zone loaded, not expired", "zone not loaded or expired",
                                "Zone load or transfer failure: check the zone file and transfer logs.", "Zone is healthy.", FaultDomain.DNS))
    if service == "dhcp" and users and edge:
        subnet, host, gateway = users
        commands.append(Command(edge, f"show ip interface {gateway}", "Cisco IOS XE", "DHCP relay (helper) addresses on the user VLAN gateway",
                                "Helper addresses are 10.100.100.20 and 10.100.100.21", "Helper address is not set, or only one is listed",
                                "The relay is missing: DHCP requests never reach the server. Check the change history for who removed it.",
                                "The relay is in place: check the DHCP server's pool.", FaultDomain.DHCP,
                                ("get_change_history", {"device_id": edge})))
        commands.append(Command("DC1-SRV-DHCP-01", 'journalctl -u kea-dhcp4 --since "1 hour ago"', "Linux", "DHCP server allocations and failures",
                                "DHCP4_LEASE_ALLOC entries for the site's pool", "DHCP4_LEASE_ALLOC_FAIL or no-address-available entries",
                                "The pool is exhausted or failing: check pool size and lease time.", "The server allocates leases.", FaultDomain.DHCP,
                                ("get_dhcp_dns_status", {"site_id": site_id})))
    if service == "authentication":
        switch = f["switch"].get(site_id)
        port = f["access_port"].get(switch) if switch else None
        if switch and port:
            commands.append(Command(switch, f"show authentication sessions interface {port}", "Cisco IOS XE", "802.1X state of a user port",
                                    "Status: Authorized, Method: dot1x", "Status: Unauthorized, or method failing over",
                                    "Authentication is failing: check RADIUS reachability and the shared secret.", "The port authenticates.",
                                    FaultDomain.VLAN_AUTHENTICATION, ("get_device_logs", {"device_id": switch, "min_severity": "warning"})))
        commands.append(Command("DC1-SRV-AUTH-01", 'journalctl -u freeradius --since "1 hour ago"', "Linux", "Requests reaching the RADIUS server",
                                f"Access-Request and Access-Accept entries from the {site_id} switch",
                                "No requests from the site switch, or 'invalid Message-Authenticator' errors",
                                "No requests means something on the path drops UDP 1812; invalid authenticator means a shared-secret mismatch.",
                                "RADIUS is answering: check the switch configuration.", FaultDomain.VLAN_AUTHENTICATION))
        if users:
            commands.append(Command("DC1-FW-01", "show log traffic action equal deny", "PAN-OS", "Denied RADIUS (UDP 1812) from the site",
                                    f"No deny entries from {site_id} to 10.100.100.30 port 1812",
                                    "Deny entries to 10.100.100.30 port 1812 naming a rule",
                                    "A firewall rule is blocking RADIUS: raise a change to correct it (a human decision).",
                                    "RADIUS traffic is allowed.", FaultDomain.FIREWALL, ("get_firewall_logs", {"source": users[0]})))
    return safe(commands)


def core_commands(device_id: str) -> list[Command]:
    if device_id not in facts()["devices"]:
        return []
    kind = platform(device_id)
    if kind != "Cisco IOS XE":
        return []
    return safe([
        Command(device_id, "show interfaces", "Cisco IOS XE", f"State of every interface on {device_id}", "All interfaces up/up",
                "Several interfaces down at once", "Several links down together points at the device itself (power, line card, crash).",
                "The device is forwarding: look elsewhere.", FaultDomain.NETWORK_DEVICE_FAILURE,
                ("check_device_availability", {"device_id": device_id})),
        Command(device_id, "show logging | include PLATFORM", "Cisco IOS XE", f"Platform alarms on {device_id}", "No recent PLATFORM alarms",
                "Power supply, fan or line-card alarms", "Hardware fault: engage the hardware team and the vendor.", "No hardware alarms.",
                FaultDomain.NETWORK_DEVICE_FAILURE, ("get_device_logs", {"device_id": device_id, "min_severity": "warning"})),
    ])


def firewall_commands(device_id: str) -> list[Command]:
    return safe([
        Command(device_id, "show log traffic action equal deny", "PAN-OS", f"Sessions {device_id} denied recently",
                "Only expected denies (the catch-all rule, scanners)", "Repeated denies for a site's subnet naming a specific rule",
                "That rule is blocking legitimate traffic: raise a change to correct it (a human decision).", "Policy isn't denying it.",
                FaultDomain.FIREWALL, ("get_firewall_logs", {"destination": "10.100.100.0/24"})),
        Command(device_id, "show running security-policy", "PAN-OS", f"The security rules on {device_id}, in evaluation order",
                "Allow rules for ERP, DNS, DHCP and RADIUS above any broad deny", "A deny rule above the allow rule for the affected traffic",
                "A rule placed too high shadows the allow rule: compare with the change history.", "Rule order is as designed.",
                FaultDomain.FIREWALL, ("get_change_history", {"device_id": device_id})),
        Command(device_id, "show session all", "PAN-OS", "Active sessions through the firewall", "Sessions from every branch subnet",
                "No sessions from the affected subnet", "Traffic isn't reaching or passing the firewall: check the path before policy.",
                "Sessions flow.", FaultDomain.FIREWALL),
        Command(device_id, "show interface all", "PAN-OS", "Firewall interface state", "All data interfaces up", "A data interface down",
                "An interface fault on the firewall: check the cabling and the neighbouring switch.", "Interfaces are up.",
                FaultDomain.INTERFACE_LINK, ("get_interface_stats", {"device_id": device_id})),
    ])


def commands_for(device_id: str | None = None, site_id: str | None = None, services: list[str] | None = None,
                 domain: FaultDomain | None = None) -> list[Command]:
    """Read-only commands for a device, a site or a fault domain, most relevant first."""
    f = facts()
    services = services or ["application"]
    pool: list[Command] = []
    if site_id:
        pool += wan_edge_commands(site_id)
        for service in services:
            pool += service_commands(site_id, service)
    if device_id:
        device = f["devices"].get(device_id)
        if device is not None:
            if device.role == DeviceRole.WAN_EDGE:
                pool = wan_edge_commands(device.site_id) + [c for c in pool if c.device_id != device_id]
            elif device.device_type == DeviceType.SERVER:
                service = next((s for s, server in SERVICE_SERVER.items() if server == device_id), None)
                site = site_id or next(iter(f["users"]))
                pool = [c for c in service_commands(site, service) if c.device_id == device_id] + pool if service else pool
            elif device.role == DeviceRole.ACCESS_SWITCH:
                pool = [c for c in service_commands(device.site_id, "authentication") if c.device_id == device_id] + pool
            elif device.device_type == DeviceType.FIREWALL:
                pool = firewall_commands(device_id) + pool
            else:
                pool = core_commands(device_id) + pool
            pool = [c for c in pool if c.device_id == device_id] + [c for c in pool if c.device_id != device_id]
    if domain is not None:
        pool = [c for c in pool if c.domain == domain] + [c for c in pool if c.domain != domain]
    unique: dict[tuple[str, str], Command] = {}
    for command in pool:
        unique.setdefault((command.device_id, command.command), command)
    return list(unique.values())
