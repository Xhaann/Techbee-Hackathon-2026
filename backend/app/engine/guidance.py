import re

from app.engine.correlation import Candidate, Correlation
from app.engine.schema import Confidence, Escalation, Explanation, FaultDomain, NextCheck
from app.network.models import DeviceType, IncidentPriority, NetworkTopology, RoutingProtocol

TEAMS = {
    FaultDomain.WAN_ISP: "WAN Operations / carrier liaison",
    FaultDomain.ROUTING: "Network Engineering - Routing",
    FaultDomain.SWITCHING: "LAN Engineering",
    FaultDomain.FIREWALL: "Network Security Operations",
    FaultDomain.VLAN_AUTHENTICATION: "Network Access Control team",
    FaultDomain.DHCP: "Infrastructure Services - DHCP/DNS",
    FaultDomain.DNS: "Infrastructure Services - DHCP/DNS",
    FaultDomain.NETWORK_DEVICE_FAILURE: "Network Operations - Core and Data Centre",
    FaultDomain.INTERFACE_LINK: "Network Operations",
    FaultDomain.SHARED_INFRASTRUCTURE: "Network Operations - Core and Data Centre",
    FaultDomain.UNKNOWN: "Network Operations - L2 triage",
}
DEFAULT_PRIORITY = {
    FaultDomain.SHARED_INFRASTRUCTURE: IncidentPriority.P1,
    FaultDomain.NETWORK_DEVICE_FAILURE: IncidentPriority.P1,
    FaultDomain.WAN_ISP: IncidentPriority.P2,
    FaultDomain.ROUTING: IncidentPriority.P2,
    FaultDomain.INTERFACE_LINK: IncidentPriority.P2,
    FaultDomain.SWITCHING: IncidentPriority.P2,
}
SINCE = '--since "1 hour ago"'


class Guidance:
    def __init__(self, topology: NetworkTopology) -> None:
        self.topology = topology
        self.devices = {device.device_id: device for device in topology.devices}
        self.interfaces = {interface.interface_id: interface for interface in topology.interfaces}
        self.links = {link.link_id: link for link in topology.links}

    def check(self, device_id: str, command: str, purpose: str, expected: str, reason: str) -> NextCheck:
        return NextCheck(device_id=device_id, command=command, purpose=purpose, expected_observation=expected, reason=reason)

    def endpoints(self, link_id: str, device_id: str) -> tuple[str, str]:
        link = self.links[link_id]
        local, remote = (link.a_interface_id, link.b_interface_id) if link.a_device_id == device_id else (
            link.b_interface_id, link.a_interface_id)
        return local, remote

    def name(self, interface_id: str) -> str:
        return self.interfaces[interface_id].name

    def address(self, interface_id: str) -> str | None:
        ip = self.interfaces[interface_id].ip_address
        return str(ip.ip) if ip else None

    def protocol_check(self, device_id: str, link_id: str) -> NextCheck | None:
        protocol = self.links[link_id].routing_protocol
        if protocol == RoutingProtocol.BGP:
            return self.check(device_id, "show ip bgp summary", "Confirm the BGP session state and prefixes received",
                              "Session not Established and zero prefixes received", f"{link_id} carries BGP")
        if protocol == RoutingProtocol.OSPF:
            return self.check(device_id, "show ip ospf neighbor", "Confirm the OSPF neighbor state",
                              "Neighbor missing or not in FULL state", f"{link_id} carries OSPF")
        return None

    def link_checks(self, candidate: Candidate) -> list[NextCheck]:
        checks = []
        for link_id in candidate.link_ids:
            device_id = next((d for d in candidate.device_ids if d in (self.links[link_id].a_device_id, self.links[link_id].b_device_id)),
                             self.links[link_id].a_device_id)
            local, remote = self.endpoints(link_id, device_id)
            checks.append(self.check(device_id, f"show interfaces {self.name(local)}",
                                     "Confirm interface state and error counters", "Line protocol down, carrier loss or rising CRC/input errors",
                                     f"{link_id} is the suspected failure point"))
            peer = self.address(remote)
            if peer:
                checks.append(self.check(device_id, f"ping {peer} source {self.name(local)} repeat 100",
                                         "Measure loss to the directly connected peer", "No replies or measurable loss across the link",
                                         "Separates a link fault from upstream routing"))
            protocol = self.protocol_check(device_id, link_id)
            if protocol:
                checks.append(protocol)
        return checks

    def routing_checks(self, candidate: Candidate) -> list[NextCheck]:
        checks = []
        for link_id in candidate.link_ids:
            for device_id in (self.links[link_id].a_device_id, self.links[link_id].b_device_id):
                local, _ = self.endpoints(link_id, device_id)
                protocol = self.protocol_check(device_id, link_id)
                if protocol:
                    checks.append(protocol)
                checks.append(self.check(device_id, f"show ip ospf interface {self.name(local)}",
                                         "Compare interface MTU, area and timers with the peer",
                                         "Mismatched MTU or OSPF parameters between the two ends",
                                         "Adjacency stalls with both interfaces up point to a parameter mismatch"))
        return checks

    def device_failure_checks(self, candidate: Candidate) -> list[NextCheck]:
        checks = []
        for device_id in candidate.device_ids:
            device = self.devices[device_id]
            remotes = [self.endpoints(link.link_id, device_id)[1] for link in self.topology.links
                       if device_id in (link.a_device_id, link.b_device_id)]
            for remote in remotes[:3]:
                peer = remote.split(":", 1)[0]
                checks.append(self.check(peer, f"show interfaces {self.name(remote)}",
                                         f"Confirm how {peer} sees its link to {device_id}", "Interface down with no carrier",
                                         f"Independent peer evidence for the state of {device_id}"))
            if remotes:
                checks.append(self.check(remotes[0].split(":", 1)[0], f"ping {device.management_ip} repeat 5",
                                         f"Test management reachability of {device_id}", "No replies",
                                         "Distinguishes a device outage from a single link failure"))
            checks.append(self.check(device_id, "show environment power",
                                     "Inspect power supply status through out-of-band console access",
                                     "Failed or missing power entry modules", "Critical events preceded the telemetry gap"))
        return checks

    def service_checks(self, candidate: Candidate) -> list[NextCheck]:
        checks = []
        for device_id in candidate.device_ids:
            device = self.devices[device_id]
            if candidate.domain == FaultDomain.FIREWALL:
                checks += [
                    self.check(device_id, "show running security-policy", "Review the active rule order and recent additions",
                               "A deny rule placed ahead of the expected allow rule", "Denied flows match a recently modified rule"),
                    self.check(device_id, "show log traffic action equal deny", "Confirm which flows are denied and by which rule",
                               "Denies for the affected source and destination", "Corroborates the firewall evidence"),
                ]
            elif candidate.domain == FaultDomain.DHCP:
                checks += [
                    self.check(device_id, "keactrl status", "Confirm the DHCP service is running", "Service active",
                               "Separates pool exhaustion from a service outage"),
                    self.check(device_id, f"journalctl -u kea-dhcp4 {SINCE}", "Review allocation failures and declines",
                               "No-free-lease and DHCPDECLINE messages for the affected pool", "Pool exhaustion was observed"),
                ]
            elif candidate.domain == FaultDomain.DNS:
                domain = self.failed_domain(candidate)
                checks.append(self.check(device_id, "rndc status", "Confirm the DNS service state and loaded zones",
                                         "Service running with zones reported", "Queries to this server return SERVFAIL"))
                if domain:
                    checks.append(self.check(device_id, f"dig @{device.management_ip} {domain} A",
                                             "Reproduce the failing resolution", "SERVFAIL from this server",
                                             f"{domain} failed in the collected evidence"))
                checks.append(self.check(device_id, f"journalctl -u named {SINCE}", "Look for zone load errors",
                                         "Zone loading errors for the internal zone", "Server-side resolution fault suspected"))
            elif candidate.domain == FaultDomain.VLAN_AUTHENTICATION:
                if device.device_type == DeviceType.SWITCH:
                    checks += [
                        self.check(device_id, "show authentication sessions", "List 802.1X session states per port",
                                   "Ports in unauthorized state", "802.1X failures were logged on this switch"),
                        self.check(device_id, "show aaa servers", "Confirm RADIUS server state and response counters",
                                   "RADIUS server marked dead or rejecting requests", "RADIUS problems were logged"),
                    ]
                else:
                    checks.append(self.check(device_id, f"journalctl -u freeradius {SINCE}", "Review rejected RADIUS requests",
                                             "Requests dropped for an invalid shared secret", "The RADIUS server logged rejections"))
        return checks

    def failed_domain(self, candidate: Candidate) -> str | None:
        for item in candidate.support:
            match = re.search(r"domains: ([a-z0-9.-]+)", item.summary)
            if match:
                return match.group(1)
        return None

    def triage_checks(self, sites: list[str]) -> list[NextCheck]:
        checks = []
        for device in self.topology.devices:
            if device.site_id in sites and device.device_type in (DeviceType.ROUTER, DeviceType.SWITCH):
                checks.append(self.check(device.device_id, "show logging", "Review recent device events", "Events matching the reported symptoms",
                                         "No fault domain was identified from the collected evidence"))
        return checks[:4]

    def next_checks(self, correlation: Correlation, sites: list[str]) -> list[NextCheck]:
        top = correlation.top
        if top is None:
            return self.triage_checks(sites)
        if top.domain in (FaultDomain.SHARED_INFRASTRUCTURE, FaultDomain.NETWORK_DEVICE_FAILURE):
            checks = self.device_failure_checks(top)
        elif top.domain == FaultDomain.ROUTING:
            checks = self.routing_checks(top)
        elif top.domain in (FaultDomain.WAN_ISP, FaultDomain.INTERFACE_LINK, FaultDomain.SWITCHING):
            checks = self.link_checks(top)
        else:
            checks = self.service_checks(top)
        unique = {(check.device_id, check.command): check for check in checks}
        return list(unique.values())[:8]

    def escalation(self, correlation: Correlation, severity: IncidentPriority | None, unknowns: list[str]) -> Escalation:
        top = correlation.top
        domain = top.domain if top else FaultDomain.UNKNOWN
        reason = (f"Probable {domain.value} fault: {top.root_cause}" if top
                  else "No fault domain could be established from the available evidence")
        return Escalation(
            team=TEAMS[domain], priority=severity or DEFAULT_PRIORITY.get(domain, IncidentPriority.P3), reason=reason,
            evidence_ids=[item.evidence_id for item in top.support][:10] if top else [],
            unknowns=(unknowns + ["The hypothesis requires human verification before any change is made"])[:10],
        )

    def explanation(self, correlation: Correlation, checks: list[NextCheck], escalation: Escalation) -> Explanation:
        top = correlation.top
        level = correlation.confidence.value.replace("_", " ")
        if top:
            summary = f"Probable {top.domain.value.replace('_', ' ')} fault: {top.root_cause}. Confidence: {level}."
            facts = [item.summary for item in top.support if item.evidence_type.value != "inferred_finding"][:8]
            hypotheses = [f"Primary: {top.root_cause}"] + [
                f"Alternative ({c.domain.value}): {c.root_cause}" for c in correlation.alternatives[:4]
            ]
        else:
            summary = f"No fault domain is supported by the collected evidence. Confidence: {level}."
            facts, hypotheses = [], []
        actions = [f"{check.device_id}: {check.command} ({check.purpose})" for check in checks]
        actions.append(f"Escalate to {escalation.team} at priority {escalation.priority.value.upper()}")
        return Explanation(summary=summary[:2000], observed_facts=facts, hypotheses=hypotheses[:8], recommended_actions=actions[:12])


def confidence_rank(level: Confidence) -> int:
    return [Confidence.INSUFFICIENT_EVIDENCE, Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH].index(level)
