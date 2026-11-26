import re
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Network

from app.engine.executor import ToolCallRecord, ToolExecutor
from app.engine.schema import DiagnosisRequest
from app.network.models import DeviceRole, NetworkTopology, SiteType

SERVICE_KEYWORDS = (
    (DeviceRole.DNS_SERVER, re.compile(r"\b(dns|resolv\w*|by name|host ?names?|name resolution)\b", re.IGNORECASE)),
    (DeviceRole.DHCP_SERVER, re.compile(r"\b(dhcp|ip address(es)?|self-assigned|169\.254|obtain an? (ip|address))\b", re.IGNORECASE)),
    (DeviceRole.AUTHENTICATION_SERVER, re.compile(r"\b(802\.1x|dot1x|authenticat\w*|radius)\b", re.IGNORECASE)),
)
ALL_BRANCHES = re.compile(r"\b(all|every|multiple)\s+(branch(es)?|sites|offices|locations)\b", re.IGNORECASE)
MAX_SITES = 3
LOSSY_PATTERNS = {"isolated", "intermittent", "sustained"}


UNAFFECTED = r"[^.;,]{0,30}\b(unaffected|not affected|working normally|works normally|is fine)\b"


def mentioned_as_affected(text: str, terms: tuple[str, ...]) -> bool:
    for term in terms:
        for match in re.finditer(rf"\b{re.escape(term)}\b", text, re.IGNORECASE):
            if not re.match(UNAFFECTED, text[match.end():], re.IGNORECASE):
                return True
    return False


class DiagnosisRequestError(ValueError):
    pass


@dataclass(frozen=True)
class IncidentContext:
    sites: list[str]
    target_device_id: str
    target_role: DeviceRole


def resolve_context(request: DiagnosisRequest, topology: NetworkTopology) -> IncidentContext:
    known = {site.site_id for site in topology.sites}
    unknown = [site for site in request.site_ids if site not in known]
    if unknown:
        raise DiagnosisRequestError(f"Unknown site identifiers: {', '.join(unknown)}")
    branches = [site for site in topology.sites if site.site_type == SiteType.BRANCH]
    if request.site_ids:
        sites = list(dict.fromkeys(request.site_ids))
    elif ALL_BRANCHES.search(request.description):
        sites = [site.site_id for site in branches]
    else:
        sites = [site.site_id for site in topology.sites
                 if mentioned_as_affected(request.description, (site.site_id, site.name, site.city))]
    role = next((role for role, pattern in SERVICE_KEYWORDS if pattern.search(request.description)),
                DeviceRole.APPLICATION_SERVER)
    target = sorted(device.device_id for device in topology.devices if device.role == role)[0]
    return IncidentContext(sites=sites, target_device_id=target, target_role=role)


class RuleBasedPlanner:
    def __init__(self, topology: NetworkTopology, context: IncidentContext) -> None:
        self.topology = topology
        self.context = context
        self.devices = {device.device_id: device for device in topology.devices}
        self.links = {link.link_id: link for link in topology.links}

    def site_device(self, site: str, role: DeviceRole) -> str | None:
        return next((d.device_id for d in self.topology.devices if d.site_id == site and d.role == role), None)

    def site_network(self, site: str) -> str | None:
        subnets = [vlan.subnet for vlan in self.topology.vlans if vlan.site_id == site]
        if not subnets:
            return None
        network: IPv4Network = subnets[0]
        while not all(subnet.subnet_of(network) for subnet in subnets):
            network = network.supernet()
        return str(network)

    def far_ends(self, failure: dict) -> list[str]:
        ends = []
        for link_id in failure.get("down_link_ids", []):
            link = self.links[link_id]
            ends.append(link.b_device_id if link.a_device_id == failure["device_id"] else link.a_device_id)
        return ends

    def run(self, executor: ToolExecutor, sufficient: Callable[[], bool]) -> None:
        sites = self.context.sites[:MAX_SITES]
        target = self.context.target_device_id
        reach: dict[str, ToolCallRecord] = {}
        for site in sites:
            switch = self.site_device(site, DeviceRole.ACCESS_SWITCH)
            if switch:
                reach[site] = executor.execute("check_network_reachability", {"source": switch, "destination": target})
        failures = [r.result.data["failure_point"] for r in reach.values()
                    if r.succeeded and r.result.data["status"] == "unreachable"]
        ends = [end for failure in failures for end in self.far_ends(failure)]
        shared = sorted({end for end in ends if ends.count(end) >= 2})
        for device in shared[:1]:
            executor.execute("analyze_network_dependencies", {"device_id": device})
            executor.execute("check_device_availability", {"device_id": device})
            if sufficient():
                return
        for failure in failures[:2]:
            for end in self.far_ends(failure):
                executor.execute("check_device_availability", {"device_id": end})
            executor.execute("analyze_routing_adjacency", {"device_id": failure["device_id"]})
            executor.execute("get_device_logs", {"device_id": failure["device_id"]})
            if sufficient():
                return
        for site in sites:
            executor.execute("get_dhcp_dns_status", {"site_id": site})
            if sufficient():
                return
        if failures or not sites:
            return
        primary = sites[0]
        router = self.site_device(primary, DeviceRole.WAN_EDGE)
        record = reach.get(primary)
        hops = record.result.data["hops"] if record and record.succeeded else []
        egress = next((hop["interface_id"] for hop in hops if hop["device_id"] == router and hop["segment"] == "layer3"), None)
        if egress:
            interface = egress.split(":", 1)[1]
            loss = executor.execute("analyze_packet_loss", {"device_id": router, "interface": interface})
            if loss.succeeded and loss.result.data["pattern"] in LOSSY_PATTERNS:
                executor.execute("analyze_interface_errors", {"device_id": router, "interface": interface})
            if sufficient():
                return
        network = self.site_network(primary)
        if network:
            executor.execute("get_firewall_logs", {"source": network, "destination": str(self.devices[target].management_ip)})
            if sufficient():
                return
        switch = self.site_device(primary, DeviceRole.ACCESS_SWITCH)
        if switch:
            executor.execute("get_device_logs", {"device_id": switch, "min_severity": "warning"})
        if self.context.target_role == DeviceRole.AUTHENTICATION_SERVER:
            executor.execute("get_device_logs", {"device_id": target, "min_severity": "warning"})
