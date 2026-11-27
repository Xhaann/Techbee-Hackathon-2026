import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address

from app.engine.evidence import EVENT_COLLECTIONS
from app.engine.executor import ToolCallRecord
from app.engine.schema import (
    AffectedPath,
    Confidence,
    EvidenceItem,
    EvidenceType,
    FaultDomain,
    TimelineEntry,
    TimelineRelevance,
)
from app.network.models import LinkType, NetworkTopology

CORRELATION_WINDOW = timedelta(minutes=10)
MAX_TIMELINE = 50
LINK_EVENTS = {"LINK_DOWN", "CARRIER_LOSS", "WAN_PROBE_FAILURE", "BGP_NEIGHBOR_DOWN", "OSPF_ADJACENCY_DOWN"}
ROUTING_EVENTS = {"CONFIG_CHANGE", "MTU_CHANGE", "OSPF_ADJACENCY_DOWN", "OSPF_MTU_MISMATCH", "BGP_NEIGHBOR_DOWN"}
AUTH_EVENTS = {"DOT1X_AUTH_FAILURE", "PORT_UNAUTHORIZED", "RADIUS_SERVER_DEAD", "RADIUS_INVALID_AUTHENTICATOR"}
LAST_GOOD_CODES = {"TELEMETRY_GAP", "DHCP_TRANSACTIONS_STOPPED"}
ISOLATION_CODES = {"DNS_UNREACHABLE_FROM_SITE_SUSPECTED", "DHCP_TRANSACTIONS_STOPPED", "DNS_TIMEOUTS"}
PRECEDENCE = {FaultDomain.SHARED_INFRASTRUCTURE: 0, FaultDomain.NETWORK_DEVICE_FAILURE: 1}
WEIGHTS = {EvidenceType.OBSERVED_FINDING: 2, EvidenceType.RECORD: 2, EvidenceType.OBSERVED_RESULT: 1,
           EvidenceType.INFERRED_FINDING: 1}
SERVICE_DOMAINS = {FaultDomain.FIREWALL, FaultDomain.DHCP, FaultDomain.DNS, FaultDomain.VLAN_AUTHENTICATION}
FLAP_CODES = {"LINK_FLAP_RECOVERED", "ADJACENCY_FLAP_RECOVERED", "PROBE_FLAP_RECOVERED", "ROUTES_WITHDRAWN_AND_RESTORED",
              "INTERMITTENT_FAULT_SUSPECTED", "LINK_DOWN_ONGOING"}
RELAY_CODES = {"DHCP_RELAY_TO_SERVER_REMOVED", "DHCP_RELAY_FAILURE_SUSPECTED"}
CHANGE_SUPPORT = {FaultDomain.ROUTING: {"MTU_CHANGED", "CONFIG_CHANGED"}, FaultDomain.FIREWALL: {"POLICY_CHANGED", "FIREWALL_RULE_MODIFIED"},
                  FaultDomain.DNS: {"ZONE_RELOADED"}}
# Failures of a service (as opposed to changes or causes): when they stopped well before the fault began and did not come
# back, they are background, not the cause of this incident.
SERVICE_FAILURE_CODES = {"DNS_SERVFAIL", "DNS_TIMEOUTS", "DNS_SERVER_RESOLUTION_FAULT_SUSPECTED", "DNS_UPSTREAM_RESOLUTION_FAILURE",
                         "DHCP_ALLOCATION_FAILURES", "DHCP_IP_CONFLICTS", "DHCP_POOL_EXHAUSTED"}
BACKGROUND_GAP = timedelta(minutes=10)
EXTERNAL_ONLY = "names outside our DNS zones only"  # how the DNS tool marks failures that only concern internet names
EDGE_CHANGE_WINDOW = timedelta(hours=2)
EDGE_CHANGE_CODES = {"POLICY_CHANGED", "CONFIG_CHANGED", "FIREWALL_RULE_MODIFIED"}
VLAN_LOG_CODES = {"VLAN_INACTIVE", "VLAN_NOT_FOUND", "VLAN_MISSING"}
VLAN_DELETED = re.compile(r"\bno vlan (\d+)\b", re.IGNORECASE)
VLAN_NUMBER = re.compile(r"\bvlan (\d+)\b", re.IGNORECASE)
# Evidence that only rules a cause out (the layer-3 path works) corroborates a service hypothesis but is not evidence for it.
EXCLUSIONARY_CODES = {"PATH_REACHABLE"}


@dataclass
class Candidate:
    domain: FaultDomain
    device_ids: list[str]
    link_ids: list[str]
    root_cause: str
    reasoning: str
    support: list[EvidenceItem] = field(default_factory=list)
    contradicting: list[EvidenceItem] = field(default_factory=list)
    sites: set[str] = field(default_factory=set)
    # Highest confidence the kind of evidence allows, with the reason: a cause inferred from timing alone is never "high".
    ceiling: tuple[Confidence, str] | None = None

    @property
    def key(self) -> tuple:
        return self.domain, tuple(self.device_ids), tuple(self.link_ids)

    @property
    def score(self) -> int:
        return sum(WEIGHTS[item.evidence_type] for item in self.support)

    @property
    def tools(self) -> set[str]:
        return {item.tool for item in self.support}

    def add(self, items: list[EvidenceItem], contradicting: bool = False) -> None:
        target = self.contradicting if contradicting else self.support
        known = {item.evidence_id for item in target}
        for item in items:
            if item.evidence_id not in known:
                known.add(item.evidence_id)
                target.append(item)


@dataclass
class Correlation:
    top: Candidate | None
    alternatives: list[Candidate]
    confidence: Confidence
    confidence_explanation: str
    timeline: list[TimelineEntry]
    affected_path: AffectedPath | None
    limitations: list[str]


class Correlator:
    def __init__(self, records: list[ToolCallRecord], catalog: list[EvidenceItem], topology: NetworkTopology,
                 sites: list[str], reference: datetime | None = None) -> None:
        self.reference = reference  # the fault's onset in the data's timeline; None: no timing rules apply
        self.background: list[str] = []  # failures set aside as background, reported only when nothing is concluded
        self.records = [record for record in records if record.succeeded]
        self.catalog = catalog
        self.topology = topology
        self.sites = sites
        self.devices = {device.device_id: device for device in topology.devices}
        self.links = {link.link_id: link for link in topology.links}
        self.by_call: dict[str, list[EvidenceItem]] = {}
        for item in catalog:
            self.by_call.setdefault(item.call_id, []).append(item)
        self.candidates: dict[tuple, Candidate] = {}
        self.limitations: list[str] = []

    def current(self, items: list[EvidenceItem]) -> list[EvidenceItem]:
        """Service failures still relevant to the incident: drops those whose last occurrence ended well before it was reported."""
        if self.reference is None:
            return items
        kept = []
        for item in items:
            stamps = [ref.timestamp for ref in item.references if ref.timestamp is not None]
            if item.code in SERVICE_FAILURE_CODES and stamps and max(stamps) < self.reference - BACKGROUND_GAP:
                note = (f"{item.code.replace('_', ' ').lower()} ({item.evidence_id}) ended at {max(stamps):%H:%M} UTC, well before the "
                        "fault began: treated as background, not as its cause")
                if note not in self.background:
                    self.background.append(note)
                continue
            kept.append(item)
        return kept

    def calls(self, tool: str) -> list[ToolCallRecord]:
        return [record for record in self.records if record.tool == tool]

    def pick(self, record: ToolCallRecord, codes: set[str] | None = None) -> list[EvidenceItem]:
        return [item for item in self.by_call.get(record.call_id, []) if codes is None or item.code in codes]

    def candidate(self, domain: FaultDomain, device_ids: list[str], link_ids: list[str], root_cause: str,
                  reasoning: str) -> Candidate:
        new = Candidate(domain, sorted(set(device_ids)), sorted(set(link_ids)), root_cause, reasoning)
        return self.candidates.setdefault(new.key, new)

    def site_of(self, record: ToolCallRecord) -> str | None:
        source = record.result.data["source"]
        if source["device_id"]:
            return self.devices[source["device_id"]].site_id
        address = IPv4Address(source["address"])
        return next((vlan.site_id for vlan in self.topology.vlans if address in vlan.subnet), None)

    def site_items(self, site: str | None, codes: set[str]) -> list[EvidenceItem]:
        return [item for record in self.calls("get_dhcp_dns_status") if record.result.data["site_id"] == site
                for item in self.pick(record, codes)]

    def reachable_items(self, site: str | None) -> list[EvidenceItem]:
        return [item for record in self.calls("check_network_reachability") if self.site_of(record) == site
                for item in self.pick(record, {"PATH_REACHABLE"})]

    def far_ends(self, record: ToolCallRecord) -> list[tuple[str, str]]:
        failure = record.result.data["failure_point"] or {}
        device = failure.get("device_id")
        ends = []
        for link_id in failure.get("down_link_ids", []):
            link = self.links[link_id]
            ends.append((link_id, link.b_device_id if link.a_device_id == device else link.a_device_id))
        return ends

    def site_router(self, site: str) -> str | None:
        return next((d.device_id for d in self.topology.devices if d.site_id == site and d.role.value == "wan_edge"), None)

    def availability(self) -> dict[str, ToolCallRecord]:
        return {record.result.data["device_id"]: record for record in self.calls("check_device_availability")}

    def describe_link(self, link_id: str) -> str:
        link = self.links[link_id]
        circuit = f" ({link.provider} circuit {link.circuit_id})" if link.provider else ""
        return f"{link_id}{circuit}"

    def connectivity(self) -> None:
        availability = self.availability()
        unreachable = [r for r in self.calls("check_network_reachability") if r.result.data["status"] == "unreachable"]
        failed_devices = [device for device, record in availability.items()
                          if record.result.data["status"] == "unreachable" and self.pick(record, {"DEVICE_FAILURE_LIKELY"})]
        claimed: dict[str, str] = {}
        for device in failed_devices:
            related = [r for r in unreachable if device in {end for _, end in self.far_ends(r)}]
            sites = sorted({self.site_of(r) for r in related} - {None})
            links = [link for r in related for link, end in self.far_ends(r) if end == device]
            claimed.update({link: device for link in links})
            shared = len(sites) >= 2
            domain = FaultDomain.SHARED_INFRASTRUCTURE if shared else FaultDomain.NETWORK_DEVICE_FAILURE
            scope = f"the shared upstream for {', '.join(sites)}" if shared else "on the failed path"
            candidate = self.candidate(
                domain, [device], links, f"{device} appears to have failed; it is {scope}",
                f"{device} stopped reporting telemetry, all peers report their links to it down, and the affected "
                f"paths all traverse it",
            )
            candidate.sites.update(sites)
            candidate.add(self.pick(availability[device]))
            for record in related:
                candidate.add(self.pick(record))
            dependency = [r for r in self.calls("analyze_network_dependencies") if r.result.data["device_id"] == device]
            if shared and dependency:
                impact = dependency[0].result.data["failure_impact"]["affected_sites"]
                candidate.reasoning += f"; topology shows {device} carries paths for {', '.join(impact)}"
        for record in unreachable:
            failure = record.result.data["failure_point"]
            site = self.site_of(record)
            device = failure["device_id"]
            if failure["reason"] == "no_route" and failure.get("down_link_ids"):
                for link_id, far_end in self.far_ends(record):
                    link = self.links[link_id]
                    domain = FaultDomain.WAN_ISP if link.link_type == LinkType.WAN else FaultDomain.INTERFACE_LINK
                    candidate = self.candidate(
                        domain, [device], [link_id], f"Link {self.describe_link(link_id)} is down, isolating {device}",
                        f"{device} has no route to the destination and its link {link_id} reports down",
                    )
                    candidate.sites.add(site)
                    candidate.add(self.pick(record))
                    candidate.add(self.site_items(site, ISOLATION_CODES))
                    for adjacency in self.calls("analyze_routing_adjacency"):
                        if adjacency.result.data["device_id"] == device:
                            candidate.add(self.pick(adjacency, {"ADJACENCY_FAILED", "ADJACENCY_LOSS_FOLLOWS_INTERFACE_DOWN"}))
                    for logs in self.calls("get_device_logs"):
                        if logs.result.data["device_id"] == device:
                            candidate.add(self.pick(logs, LINK_EVENTS))
                    if link_id in claimed:
                        candidate.add(self.pick(availability[claimed[link_id]]), contradicting=True)
                    elif far_end in availability and availability[far_end].result.data["status"] != "unreachable":
                        alive = [item for item in self.pick(availability[far_end])
                                 if item.evidence_type == EvidenceType.OBSERVED_RESULT]
                        candidate.add(alive)
                        alternative = self.candidate(
                            FaultDomain.NETWORK_DEVICE_FAILURE, [far_end], [link_id],
                            f"{far_end} failed, taking down {link_id}",
                            f"{far_end} terminates the failed link",
                        )
                        alternative.add(self.pick(record, {"PATH_UNREACHABLE"}))
                        alternative.add(alive, contradicting=True)
            elif failure["reason"] == "no_route":
                adjacency = next((r for r in self.calls("analyze_routing_adjacency") if r.result.data["device_id"] == device), None)
                failed = [a for a in adjacency.result.data["adjacencies"] if a["status"] in ("failed", "stalled")] if adjacency else []
                peers = [a["peer_device_id"] for a in failed]
                reasons = sorted({view["failure_reason"] for a in failed for view in (a["local_view"], a["peer_view"])
                                  if view and view["failure_reason"]})
                detail = f" ({'; '.join(reasons)})" if reasons else ""
                candidate = self.candidate(
                    FaultDomain.ROUTING, [device, *peers], [a["link_id"] for a in failed],
                    f"Routing adjacency failure between {device} and {', '.join(peers) or 'its peers'}{detail}",
                    f"{device} has no route to the destination while its links report up",
                )
                candidate.sites.add(site)
                candidate.add(self.pick(record))
                candidate.add(self.site_items(site, ISOLATION_CODES))
                if adjacency:
                    candidate.add(self.pick(adjacency))
                for logs in self.calls("get_device_logs"):
                    if logs.result.data["device_id"] in (device, *peers):
                        candidate.add(self.pick(logs, ROUTING_EVENTS))
            elif failure["reason"] == "link_down":
                link = self.links[failure["link_id"]]
                domain = FaultDomain.WAN_ISP if link.link_type == LinkType.WAN else FaultDomain.SWITCHING
                candidate = self.candidate(domain, [device], [link.link_id], f"Link {self.describe_link(link.link_id)} is down",
                                           f"The forwarding path crosses {link.link_id}, which reports down")
                candidate.sites.add(site)
                candidate.add(self.pick(record))
            else:
                self.limitations.append(f"Reachability from {site} could not be determined: {failure['reason']}")

    def degradation(self) -> None:
        for record in self.calls("analyze_packet_loss"):
            data = record.result.data
            if not self.pick(record, {"PACKET_LOSS_MEASURED"}) or self.pick(record, {"LOSS_DURING_INTERFACE_DOWN"}):
                continue
            link = data["link"]
            device = data["device_id"]
            domain = FaultDomain.WAN_ISP if link and link["link_type"] == "wan" else FaultDomain.INTERFACE_LINK
            link_ids = [link["link_id"]] if link else []
            label = self.describe_link(link["link_id"]) if link else data["interface_id"]
            physical = self.pick(record, {"PHYSICAL_LAYER_DEGRADATION_SUSPECTED"})
            congested = self.pick(record, {"CONGESTION_SUSPECTED"})
            if physical or not congested:
                candidate = self.candidate(
                    domain, [device], link_ids,
                    f"{label} is degraded: {data['pattern']} packet loss up to {data['peak_loss_percent']}%"
                    + (" with high error counts" if physical else ""),
                    f"Packet loss measured on {data['interface_id']}" + (" coincides with interface errors" if physical else ""),
                )
            else:
                candidate = self.candidate(domain, [device], link_ids, f"{label} is congested: loss coincides with high utilisation",
                                           f"Loss on {data['interface_id']} appears only at high utilisation, without error growth")
            candidate.sites.add(self.devices[device].site_id)
            candidate.add(self.pick(record))
            for errors in self.calls("analyze_interface_errors"):
                if errors.result.data["interface_id"] == data["interface_id"]:
                    candidate.add(self.pick(errors))
        for record in self.calls("analyze_path_health"):
            data = record.result.data
            source = data["source"]["device_id"]
            site = self.devices[source].site_id if source else None
            for segment in data["segments"]:
                if segment["state"] not in ("degraded", "congested", "down"):
                    continue
                link = self.links[segment["link_id"]]
                code = {"degraded": "PATH_SEGMENT_DEGRADED", "congested": "PATH_SEGMENT_CONGESTED", "down": "PATH_SEGMENT_DOWN"}[segment["state"]]
                items = [item for item in self.pick(record, {code}) if link.link_id in item.summary]
                domain = FaultDomain.WAN_ISP if link.link_type == LinkType.WAN else FaultDomain.INTERFACE_LINK
                devices = [link.a_device_id, link.b_device_id]
                existing = next((c for c in self.candidates.values() if c.domain == domain and c.link_ids == [link.link_id]
                                 and segment["state"] != "congested" and "congested" not in c.root_cause), None)
                if existing is not None:
                    # The same link already has a hypothesis (from loss or error analysis): add the path evidence to it.
                    existing.add(items)
                    if site:
                        existing.sites.add(site)
                    continue
                if segment["state"] == "congested":
                    candidate = self.candidate(domain, devices, [link.link_id],
                                               f"{self.describe_link(link.link_id)} is congested ({segment['max_utilization_percent']:g}% "
                                               "utilisation) without error growth",
                                               "High utilisation and drops on the path without interface errors point to capacity")
                else:
                    detail = (f"up to {segment['max_loss_percent']:g}% loss and {int(segment['max_errors_per_interval'])} errors per "
                              "interval" if segment["state"] == "degraded" else "operational status down")
                    candidate = self.candidate(
                        domain, devices, [link.link_id], f"{self.describe_link(link.link_id)} is {segment['state']} ({detail})",
                        f"Path health shows {link.link_id} {segment['state']} on the forwarding path")
                if site:
                    candidate.sites.add(site)
                candidate.add(items)
                interfaces = {link.a_interface_id, link.b_interface_id}
                for errors in self.calls("analyze_interface_errors"):
                    if errors.result.data["interface_id"] in interfaces:
                        candidate.add(self.pick(errors))
                for loss in self.calls("analyze_packet_loss"):
                    if loss.result.data["interface_id"] in interfaces:
                        candidate.add(self.pick(loss, {"PACKET_LOSS_MEASURED", "PHYSICAL_LAYER_DEGRADATION_SUSPECTED"}))
                if len(candidate.sites) > 1 and "shared by the paths" not in candidate.reasoning:
                    candidate.reasoning += "; the segment is shared by the paths of several affected sites"

    def temporal(self) -> None:
        for record in self.calls("get_event_timeline"):
            data = record.result.data
            for interval in data["intervals"]:
                if interval["kind"] != "link" or not interval["link_id"]:
                    continue
                link = self.links[interval["link_id"]]
                domain = FaultDomain.WAN_ISP if link.link_type == LinkType.WAN else FaultDomain.INTERFACE_LINK
                device = interval["device_id"]
                if interval["status"] == "recovered":
                    minutes = round(interval["duration_seconds"] / 60)
                    root = (f"{self.describe_link(link.link_id)} dropped at {interval['started_at'][11:19]} and recovered at "
                            f"{interval['ended_at'][11:19]} UTC (about {minutes} min); routing reconverged and the outage has ended")
                    reasoning = "Logged link, routing and probe state changes show an outage that recovered on its own"
                else:
                    root = f"{self.describe_link(link.link_id)} went down at {interval['started_at'][11:19]} UTC and has not recovered"
                    reasoning = "Logged link state changes show the link down with no recovery"
                candidate = self.candidate(domain, [device], [link.link_id], root, reasoning)
                candidate.sites.add(self.devices[device].site_id)
                candidate.add([item for item in self.pick(record, FLAP_CODES) if item.device_id == device])
                for adjacency in self.calls("analyze_routing_adjacency"):
                    if adjacency.result.data["device_id"] == device:
                        candidate.add(self.pick(adjacency, {"ADJACENCY_RECENTLY_CHANGED", "ADJACENCY_FAILED"}))

    def changes(self) -> None:
        stopped = [item for record in self.calls("get_dhcp_dns_status") for item in self.pick(record, {"DHCP_TRANSACTIONS_STOPPED"})]
        for record in self.calls("get_change_history"):
            relays = self.pick(record, RELAY_CODES)
            for device in sorted({item.device_id for item in relays if item.device_id}):
                removed = next((item for item in relays if item.device_id == device and item.code == "DHCP_RELAY_TO_SERVER_REMOVED"), None)
                pool = re.search(r"pool (DHCP-[A-Z0-9-]+)", removed.summary).group(1) if removed and "pool DHCP-" in removed.summary else None
                candidate = self.candidate(
                    FaultDomain.DHCP, [device], [],
                    f"The DHCP relay on {device} was removed" + (f": requests for pool {pool} no longer reach the DHCP server" if pool else ""),
                    f"A logged configuration change removed the ip helper-address pointing at the DHCP server on {device}, and the "
                    "pool then stopped receiving requests")
                candidate.sites.add(self.devices[device].site_id)
                candidate.add([item for item in relays if item.device_id == device])
                candidate.add([item for item in self.pick(record, {"CONFIG_CHANGED"}) if item.device_id == device])
                candidate.add([item for item in stopped if pool and pool in item.summary])
        for candidate in self.candidates.values():
            codes = CHANGE_SUPPORT.get(candidate.domain)
            if not codes:
                continue
            for record in self.calls("get_change_history"):
                candidate.add([item for item in self.pick(record, codes) if item.device_id in candidate.device_ids])

    def covered_sites(self, candidate: Candidate) -> set[str]:
        """Sites a hypothesis explains: those its evidence came from, plus, for a link or shared device, every site whose
        modelled service paths run through it."""
        sites = {site for site in candidate.sites if site}
        if candidate.link_ids:
            sites |= {path.source_site_id for path in self.topology.paths if set(path.link_ids) & set(candidate.link_ids)}
        if candidate.domain in (FaultDomain.SHARED_INFRASTRUCTURE, FaultDomain.NETWORK_DEVICE_FAILURE):
            sites |= {path.source_site_id for path in self.topology.paths if set(path.device_ids) & set(candidate.device_ids)}
        return sites

    def covers(self, candidate: Candidate) -> bool:
        """Whether the hypothesis explains every affected site (unknown site coverage counts as covering)."""
        covered = self.covered_sites(candidate)
        return not covered or not self.sites or set(self.sites) <= covered

    def services(self) -> None:
        for record in self.calls("get_firewall_logs"):
            data = record.result.data
            rules = {rule["rule_id"]: rule for rule in data["rules"]}
            modified = self.pick(record, {"RULE_MODIFIED_IN_RANGE"})
            for rule_id, count in data["rule_counts"].items():
                rule = rules[rule_id]
                recent = [item for item in modified if rule_id in item.summary]
                if rule["action"] != "deny" or not (recent or count >= 3):
                    continue
                denied = [item for item in self.pick(record, {"TRAFFIC_DENIED"}) if rule_id in item.summary]
                candidate = self.candidate(
                    FaultDomain.FIREWALL, [rule["device_id"]], [],
                    f"Firewall rule {rule_id} ({rule['name']}) on {rule['device_id']} denies the affected traffic "
                    f"({rule['source']} -> {rule['destination']})",
                    f"{count} matching flows were denied by {rule_id} while the layer-3 path is reachable",
                )
                candidate.add(denied + recent)
        for record in self.calls("get_dhcp_dns_status"):
            site = record.result.data["site_id"]
            exhausted = [pool["pool"]["pool_id"] for pool in record.result.data["dhcp"]["pools"] if pool["status"] == "exhausted"]
            # A service fault needs exhaustion or failed allocations. An address conflict alone is a host using an address that
            # was leased to another (usually a static IP): its own, narrower hypothesis, never "the pool cannot allocate".
            dhcp = self.current(self.pick(record, {"DHCP_POOL_EXHAUSTED", "DHCP_ALLOCATION_FAILURES"}))
            conflicts = self.current(self.pick(record, {"DHCP_IP_CONFLICTS"}))
            if dhcp:
                server = next(item.device_id for item in dhcp if item.device_id)
                pools = f"pool {', '.join(exhausted)}" if exhausted else "address pools"
                candidate = self.candidate(FaultDomain.DHCP, [server], [], f"DHCP {pools} on {server} cannot allocate addresses",
                                           f"{server} reports exhaustion or allocation failures for {site}")
                candidate.sites.add(site)
                candidate.add(dhcp)
                candidate.add([item for item in conflicts if item.device_id == server])
            elif conflicts:
                server = next((item.device_id for item in conflicts if item.device_id), None)
                pools = sorted({m for item in conflicts for m in re.findall(r"pool (\S+)", item.summary)})
                candidate = self.candidate(
                    FaultDomain.DHCP, [server] if server else [], [],
                    f"Address conflict in {', '.join(pools) or 'a DHCP pool'}: a host is using an address {server or 'the server'} leased to "
                    "another device (typically a static address), so those two hosts keep losing connectivity",
                    f"{server or 'The DHCP server'} detected an address that another host answers on after leasing it")
                candidate.sites.add(site)
                candidate.add(conflicts)
                candidate.ceiling = (Confidence.MEDIUM, "An address conflict affects the hosts involved, not the DHCP service as a whole")
            # Failures that concern only internet names are the DNS servers reaching out, not the DNS service (see egress()).
            dns = [item for item in self.current(self.pick(record, {"DNS_SERVFAIL", "DNS_SERVER_RESOLUTION_FAULT_SUSPECTED"}))
                   if EXTERNAL_ONLY not in item.summary]
            for server in sorted({item.device_id for item in dns if item.device_id}):
                candidate = self.candidate(FaultDomain.DNS, [server], [],
                                           f"{server} fails to resolve internal names (SERVFAIL) while other servers answer",
                                           f"Queries to {server} return SERVFAIL")
                candidate.sites.add(site)
                candidate.add([item for item in dns if item.device_id == server])
        auth = [item for record in self.calls("get_device_logs") for item in self.pick(record, AUTH_EVENTS)]
        if auth:
            devices = sorted({item.device_id for item in auth if item.device_id})
            switches = [device for device in devices if self.devices[device].device_type.value == "switch"] or devices
            candidate = self.candidate(
                FaultDomain.VLAN_AUTHENTICATION, devices, [],
                f"802.1X authentication is failing on {', '.join(switches)}; RADIUS requests are rejected or unanswered",
                "Access switch logs show 802.1X failures and unauthorized ports",
            )
            candidate.sites.update(self.devices[device].site_id for device in switches)
            candidate.add(auth)
        for candidate in list(self.candidates.values()):
            if candidate.domain not in SERVICE_DOMAINS:
                continue
            sites = candidate.sites or set(self.sites)
            reachable = [item for site in sorted(sites) for item in self.reachable_items(site)]
            candidate.add(reachable)
            if candidate.domain == FaultDomain.VLAN_AUTHENTICATION:
                candidate.add([item for site in sorted(sites) for item in self.site_items(site, {"DHCP_TRANSACTIONS_STOPPED"})])
            if reachable:
                for site in sorted(sites):
                    router = self.site_router(site)
                    wan = self.candidate(FaultDomain.WAN_ISP, [router] if router else [], [],
                                         f"Loss of WAN connectivity from {site}",
                                         f"Symptoms at {site} could indicate a connectivity failure")
                    wan.sites.add(site)
                    wan.add(self.reachable_items(site), contradicting=True)

    def egress(self) -> None:
        """Internet names fail while our own names resolve: the DNS servers cannot reach the internet. The cause is on the
        way out (firewall, NAT or ISP), so look for a change on the internet edge shortly before; without one, say so."""
        upstream = [item for record in self.calls("get_dhcp_dns_status")
                    for item in self.current(self.pick(record, {"DNS_UPSTREAM_RESOLUTION_FAILURE"}))]
        if not upstream:
            return
        external = [item for record in self.calls("get_dhcp_dns_status")
                    for item in self.current(self.pick(record, {"DNS_SERVFAIL", "DNS_TIMEOUTS"})) if EXTERNAL_ONLY in item.summary]
        edges = {d.device_id for d in self.topology.devices if d.role.value == "perimeter_firewall"}
        changes = []
        for record in self.calls("get_change_history"):
            for item in self.pick(record, EDGE_CHANGE_CODES):
                if item.device_id in edges and item.timestamp is not None and (
                        self.reference is None or self.reference - EDGE_CHANGE_WINDOW <= item.timestamp <= self.reference):
                    changes.append(item)
        if not changes:
            self.limitations.append("Internet names fail while internal names resolve, so internet egress is failing; no logged change on "
                                    "the internet edge explains it, so its cause is not established")
            return
        changes.sort(key=lambda item: item.timestamp)
        device = changes[-1].device_id
        detail = next((c["description"] for record in reversed(self.calls("get_change_history")) for c in reversed(record.result.data["changes"])
                       if c["device_id"] == device), changes[-1].summary)
        sites = {item.summary.split(" from ", 1)[1].split(" ", 1)[0] for item in upstream if " from " in item.summary}
        candidate = self.candidate(
            FaultDomain.FIREWALL, [device], [],
            f"A change on the internet edge {device} at {changes[-1].timestamp:%H:%M} UTC is the likely cause of lost internet egress: "
            f"{detail[:160]}",
            "Names outside our zones fail at the affected sites while our own names resolve, and the internet edge was changed "
            "shortly before; the DNS errors are a consequence of lost egress, not a DNS fault")
        candidate.sites.update(site for site in sites if site in {s.site_id for s in self.topology.sites})
        candidate.add(changes + upstream + external)
        candidate.ceiling = (Confidence.MEDIUM, "The change is tied to the failure by timing; its effect on egress is not directly observed")

    def switching(self) -> None:
        """A VLAN that no longer exists on a switch: its ports go inactive and everything in it loses the network."""
        logs = [item for record in self.calls("get_device_logs") for item in self.pick(record, VLAN_LOG_CODES)]
        deletions = [item for record in self.calls("get_change_history") for item in self.pick(record, {"CONFIG_CHANGED"})
                     if VLAN_DELETED.search(item.summary)]
        trunk = [item for record in self.calls("get_change_history") for item in self.pick(record, {"CONFIG_CHANGED"})
                 if "trunk allowed vlan" in item.summary.lower()]
        for device in sorted({item.device_id for item in logs + deletions if item.device_id}):
            if device not in self.devices or self.devices[device].device_type.value != "switch":
                continue
            mine = [item for item in logs + deletions if item.device_id == device]
            vlans = sorted({int(n) for item in logs if item.device_id == device for n in VLAN_NUMBER.findall(item.summary)}
                           | {int(n) for item in deletions if item.device_id == device for n in VLAN_DELETED.findall(item.summary)})
            label = f"VLAN {', '.join(map(str, vlans))}" if vlans else "A VLAN"
            candidate = self.candidate(
                FaultDomain.SWITCHING, [device], [],
                f"{label} no longer exists on {device}: ports assigned to it are inactive, so its devices have no network",
                "Switch logs show access ports in a VLAN that does not exist" + (" after a logged change deleted it" if deletions else ""))
            candidate.sites.add(self.devices[device].site_id)
            candidate.add(mine + [item for item in trunk if item.device_id == device])

    def rank(self) -> list[Candidate]:
        def order(candidate: Candidate) -> tuple:
            return (bool(candidate.contradicting), PRECEDENCE.get(candidate.domain, 2), not self.covers(candidate), -candidate.score,
                    candidate.key)
        return sorted((c for c in self.candidates.values() if c.support or c.contradicting), key=order)

    def confidence(self, ranked: list[Candidate]) -> tuple[Confidence, str]:
        if not ranked or ranked[0].contradicting or not ranked[0].support:
            return Confidence.INSUFFICIENT_EVIDENCE, "No fault hypothesis is supported by uncontradicted evidence"
        top = ranked[0]
        if not self.covers(top):
            explained = ", ".join(sorted(self.covered_sites(top)))
            return Confidence.LOW, (f"The hypothesis explains only {explained} of the affected sites "
                                    f"({', '.join(self.sites)}); the cause of the wider impact is not established")
        rivals = [c for c in ranked[1:] if not c.contradicting]
        runner = rivals[0].score if rivals else 0
        observed = [i for i in top.support if i.evidence_type in (EvidenceType.OBSERVED_FINDING, EvidenceType.RECORD)]
        positive = [i for i in observed if i.code not in EXCLUSIONARY_CODES]
        if len(observed) >= 2 and len(positive) >= 2 and len(top.tools) >= 2 and top.score >= 1.5 * runner:
            if top.ceiling and top.ceiling[0] == Confidence.MEDIUM:
                return Confidence.MEDIUM, f"{len(observed)} observed evidence items from {len(top.tools)} tools; {top.ceiling[1].lower()}"
            return Confidence.HIGH, (f"{len(observed)} observed evidence items from {len(top.tools)} tools support the "
                                     f"hypothesis with no contradicting evidence")
        if observed and top.score > runner:
            return Confidence.MEDIUM, (f"Observed evidence supports the hypothesis but corroboration is limited "
                                       f"({len(top.tools)} tool(s))" + (" and competing hypotheses remain" if rivals else ""))
        return Confidence.LOW, "The hypothesis rests on inferred or weakly corroborated evidence, or competes closely with alternatives"

    def timeline(self, top: Candidate | None) -> list[TimelineEntry]:
        dated = sorted((item for item in self.catalog if item.timestamp is not None),
                       key=lambda item: (item.timestamp, int(item.evidence_id[1:])))
        supporting = {item.evidence_id for item in top.support} if top else set()
        observed = [item for item in dated if item.evidence_id in supporting and item.code not in LAST_GOOD_CODES
                    and item.evidence_type in (EvidenceType.OBSERVED_FINDING, EvidenceType.RECORD)]
        eventful = [item for item in observed if any(ref.collection in EVENT_COLLECTIONS for ref in item.references)]
        anchors = eventful or observed
        anchor: datetime | None = anchors[0].timestamp if anchors else None
        entries = []
        for item in dated:
            if anchor is None:
                relevance = TimelineRelevance.BACKGROUND
            elif item.evidence_id in supporting:
                relevance = (TimelineRelevance.FAULT_ONSET if item.timestamp == anchor
                             else TimelineRelevance.PRECEDES_FAULT if item.timestamp < anchor else TimelineRelevance.CORRELATED)
            elif abs(item.timestamp - anchor) <= CORRELATION_WINDOW:
                relevance = TimelineRelevance.CONCURRENT
            else:
                relevance = TimelineRelevance.BACKGROUND
            entries.append(TimelineEntry(timestamp=item.timestamp, device_id=item.device_id, event=item.summary,
                                         event_type=item.code, evidence_id=item.evidence_id, relevance=relevance))
        if len(entries) > MAX_TIMELINE:
            keep = {id(entry) for entry in [e for e in entries if e.relevance != TimelineRelevance.BACKGROUND][:MAX_TIMELINE]}
            entries = [e for e in entries if id(e) in keep] or entries[:MAX_TIMELINE]
        return entries

    def affected_path(self, top: Candidate | None) -> AffectedPath | None:
        reach = self.calls("check_network_reachability")
        if not reach:
            return None
        primary = next((r for r in reach if r.result.data["status"] != "reachable"), reach[0])
        data = primary.result.data
        path = data["path"]
        links = sorted({hop["link_id"] for hop in data["hops"] if hop.get("link_id")})
        endpoints = {data["source"]["device_id"], data["destination"]["device_id"]}
        paths = [set(r.result.data["path"][1:-1]) for r in reach if len(r.result.data["path"]) > 2]
        shared = set.intersection(*paths) - endpoints if len(paths) >= 2 else set()
        for record in self.calls("analyze_network_dependencies"):
            dependency = record.result.data
            shared |= set(dependency["shared_devices"]) & set(path) - endpoints
            if dependency["device_id"] and len(dependency["failure_impact"]["affected_sites"]) >= 2:
                shared.add(dependency["device_id"])
        affected = sorted(set(path) | (set(top.device_ids) if top else set()))
        return AffectedPath(
            source=data["source"]["input"], destination=data["destination"]["input"], reachability=data["status"],
            path=path, affected_devices=affected, affected_links=sorted(set(links) | (set(top.link_ids) if top else set())),
            shared_dependencies=sorted(shared),
        )

    def run(self) -> Correlation:
        self.connectivity()
        self.degradation()
        self.temporal()
        self.egress()
        self.switching()
        self.changes()
        self.services()
        ranked = self.rank()
        confidence, explanation = self.confidence(ranked)
        top = ranked[0] if ranked and not ranked[0].contradicting else None
        if top is None:
            self.limitations += self.background
        return Correlation(
            top=top, alternatives=[c for c in ranked if c is not top],
            confidence=confidence, confidence_explanation=explanation,
            timeline=self.timeline(top), affected_path=self.affected_path(top), limitations=self.limitations,
        )


def correlate(records: list[ToolCallRecord], catalog: list[EvidenceItem], topology: NetworkTopology,
              sites: list[str], reference: datetime | None = None) -> Correlation:
    return Correlator(records, catalog, topology, sites, reference).run()
