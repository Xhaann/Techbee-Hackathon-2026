import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Network

from app.engine.executor import ToolCallRecord, ToolExecutor
from app.network.aliases import aliases_for
from app.engine.schema import DiagnosisRequest
from app.network.models import DeviceRole, NetworkTopology, SiteType
from app.network.repository import load_scenario

SERVICE_KEYWORDS = (
    (DeviceRole.DNS_SERVER, re.compile(r"\b(dns|resolv\w*|by name|host ?names?|name resolution)\b", re.IGNORECASE)),
    (DeviceRole.DHCP_SERVER, re.compile(r"\b(dhcp|ip address(es)?|self-assigned|169\.254|obtain an? (ip|address))\b", re.IGNORECASE)),
    (DeviceRole.AUTHENTICATION_SERVER, re.compile(r"\b(802\.1x|dot1x|authenticat\w*|radius)\b", re.IGNORECASE)),
)
ALL_BRANCHES = re.compile(r"\b(all|every|multiple|several|both|two|three)\s+(?:of\s+(?:the|our)\s+)?(branch(es)?|sites|offices|locations)\b",
                          re.IGNORECASE)
MAX_SITES = 3
LOSSY_PATTERNS = {"isolated", "intermittent", "sustained"}
# The report itself says something was changed: the change log of the affected site is worth one call.
CHANGE_WORDS = re.compile(r"\b(?:change[sd]?|clean-?up|cleanup|upgrade[sd]?|maintenance|reconfigur\w*|migrat\w*|re-?cabl\w*)\b",
                          re.IGNORECASE)


UNAFFECTED = r"[^.;,]{0,30}\b(unaffected|not affected|working normally|works normally|is fine)\b"


def mentioned_as_unaffected(text: str, terms: tuple[str, ...]) -> bool:
    return any(re.match(UNAFFECTED, text[match.end():], re.IGNORECASE)
               for term in terms for match in re.finditer(rf"\b{re.escape(term)}\b", text, re.IGNORECASE))


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
    onset: datetime | None = None  # when the fault began, in the data's own timeline: failures that ended well before it are background
    description: str = ""


def data_onset(scenario_id: str) -> datetime | None:
    """The onset in the dataset's timeline. Not the request's report time: an incident opened today on a historical dataset
    would make every record look old."""
    try:
        return load_scenario(scenario_id).scenario.onset_at
    except Exception:  # an unknown scenario is reported by the tools themselves
        return None


def resolve_context(request: DiagnosisRequest, topology: NetworkTopology) -> IncidentContext:
    known = {site.site_id for site in topology.sites}
    unknown = [site for site in request.site_ids if site not in known]
    if unknown:
        raise DiagnosisRequestError(f"Unknown site identifiers: {', '.join(unknown)}")
    branches = [site for site in topology.sites if site.site_type == SiteType.BRANCH]
    if request.site_ids:
        sites = list(dict.fromkeys(request.site_ids))
    elif ALL_BRANCHES.search(request.description):
        sites = [site.site_id for site in branches if not mentioned_as_unaffected(
            request.description, (site.site_id, site.name, site.city, *aliases_for(site.site_id)))]
    else:
        sites = [site.site_id for site in topology.sites
                 if mentioned_as_affected(request.description, (site.site_id, site.name, site.city, *aliases_for(site.site_id)))]
    role = next((role for role, pattern in SERVICE_KEYWORDS if pattern.search(request.description)),
                DeviceRole.APPLICATION_SERVER)
    target = sorted(device.device_id for device in topology.devices if device.role == role)[0]
    return IncidentContext(sites=sites, target_device_id=target, target_role=role, onset=data_onset(request.scenario_id),
                           description=request.description)


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

    def stopped_pool_gateways(self, records: list[ToolCallRecord]) -> list[str]:
        gateways: list[str] = []
        for record in records:
            if not record.succeeded:
                continue
            for pool in record.result.data["dhcp"]["pools"]:
                if not pool["transactions_stopped"]:
                    continue
                vlan = next((v for v in self.topology.vlans if v.site_id == pool["pool"]["site_id"] and v.vlan_id == pool["pool"]["vlan_id"]), None)
                device = vlan.gateway_interface_id.split(":", 1)[0] if vlan else None
                if device and device not in gateways:
                    gateways.append(device)
        return gateways

    def upstream_failures(self, records: list[ToolCallRecord]) -> bool:
        """DNS answers our own names but not internet names: the servers cannot get out."""
        return any(record.succeeded and any(f.code == "DNS_UPSTREAM_RESOLUTION_FAILURE" for f in record.result.findings)
                   for record in records)

    def internet_edges(self) -> list[str]:
        return sorted(d.device_id for d in self.topology.devices if d.role == DeviceRole.PERIMETER_FIREWALL)

    def unhealthy_segments(self, record: ToolCallRecord | None, site: str) -> list[tuple[str, str]]:
        """(device, interface) to examine for each degraded or down segment, worst first: the affected site's own end of
        the link when it has one, otherwise the end with the most errors. Congestion alone is not followed up."""
        if record is None or not record.succeeded:
            return []
        targets = []
        for state in ("down", "degraded"):
            for segment in record.result.data["segments"]:
                if segment["state"] != state:
                    continue
                local = [side for side in segment["sides"] if self.devices[side["interface_id"].split(":", 1)[0]].site_id == site]
                side = local[0] if local else max(segment["sides"], key=lambda item: item["max_errors_per_interval"])
                device, interface = side["interface_id"].split(":", 1)
                targets.append((device, interface))
        return targets

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
        services = [executor.execute("get_dhcp_dns_status", {"site_id": site}) for site in sites]
        if sufficient():
            return
        if not failures:
            # A pool that stopped receiving requests while its server served others: look for a change on its gateway.
            gateways = self.stopped_pool_gateways(services)
            for device in gateways[:2]:
                executor.execute("get_change_history", {"device_id": device})
            if gateways and sufficient():
                return
            # Internet names failing while ours resolve points at the way out: check what changed on the internet edge.
            if self.upstream_failures(services):
                for device in self.internet_edges()[:1]:
                    executor.execute("get_change_history", {"device_id": device})
                if sufficient():
                    return
            if sites and CHANGE_WORDS.search(self.context.description):
                executor.execute("get_change_history", {"site_id": sites[0]})
                if sufficient():
                    return
        if failures or not sites:
            return
        primary = sites[0]
        router = self.site_device(primary, DeviceRole.WAN_EDGE)
        switch = self.site_device(primary, DeviceRole.ACCESS_SWITCH)
        path = executor.execute("analyze_path_health", {"source": switch, "destination": target}) if switch else None
        unhealthy = self.unhealthy_segments(path, primary)
        if unhealthy:
            device, interface = unhealthy[0]
            executor.execute("analyze_packet_loss", {"device_id": device, "interface": interface})
            executor.execute("analyze_interface_errors", {"device_id": device, "interface": interface})
            if sufficient():
                return
            if len(sites) > 1:
                second = self.site_device(sites[1], DeviceRole.ACCESS_SWITCH)
                if second:
                    executor.execute("analyze_path_health", {"source": second, "destination": target})
            if sufficient():
                return
        if router:
            timeline = executor.execute("get_event_timeline", {"device_id": router})
            if timeline.succeeded and any(i["kind"] == "link" for i in timeline.result.data["intervals"]):
                executor.execute("analyze_routing_adjacency", {"device_id": router})
            if sufficient():
                return
        record = reach.get(primary)
        hops = record.result.data["hops"] if record and record.succeeded else []
        egress = next((hop["interface_id"] for hop in hops if hop["device_id"] == router and hop["segment"] == "layer3"), None)
        if egress and not (path and path.succeeded):
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
