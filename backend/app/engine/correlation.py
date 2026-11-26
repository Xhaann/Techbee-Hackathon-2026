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
        target.extend(item for item in items if item.evidence_id not in known)


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
                 sites: list[str]) -> None:
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
            candidate = self.candidate(
                domain, [device], link_ids,
                f"{label} is degraded: {data['pattern']} packet loss up to {data['peak_loss_percent']}% with high error counts",
                f"Packet loss measured on {data['interface_id']} coincides with interface errors",
            )
            candidate.sites.add(self.devices[device].site_id)
            candidate.add(self.pick(record))
            for errors in self.calls("analyze_interface_errors"):
                if errors.result.data["interface_id"] == data["interface_id"]:
                    candidate.add(self.pick(errors))

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
            dhcp = self.pick(record, {"DHCP_POOL_EXHAUSTED", "DHCP_ALLOCATION_FAILURES", "DHCP_IP_CONFLICTS"})
            if dhcp:
                server = next(item.device_id for item in dhcp if item.device_id)
                pools = f"pool {', '.join(exhausted)}" if exhausted else "address pools"
                candidate = self.candidate(FaultDomain.DHCP, [server], [], f"DHCP {pools} on {server} cannot allocate addresses",
                                           f"{server} reports exhaustion or allocation failures for {site}")
                candidate.sites.add(site)
                candidate.add(dhcp)
            dns = self.pick(record, {"DNS_SERVFAIL", "DNS_SERVER_RESOLUTION_FAULT_SUSPECTED"})
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

    def rank(self) -> list[Candidate]:
        def order(candidate: Candidate) -> tuple:
            return (bool(candidate.contradicting), PRECEDENCE.get(candidate.domain, 2), -candidate.score, candidate.key)
        return sorted((c for c in self.candidates.values() if c.support or c.contradicting), key=order)

    def confidence(self, ranked: list[Candidate]) -> tuple[Confidence, str]:
        if not ranked or ranked[0].contradicting or not ranked[0].support:
            return Confidence.INSUFFICIENT_EVIDENCE, "No fault hypothesis is supported by uncontradicted evidence"
        top = ranked[0]
        rivals = [c for c in ranked[1:] if not c.contradicting]
        runner = rivals[0].score if rivals else 0
        observed = [i for i in top.support if i.evidence_type in (EvidenceType.OBSERVED_FINDING, EvidenceType.RECORD)]
        if len(observed) >= 2 and len(top.tools) >= 2 and top.score >= 1.5 * runner:
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
        self.services()
        ranked = self.rank()
        confidence, explanation = self.confidence(ranked)
        top = ranked[0] if ranked and not ranked[0].contradicting else None
        return Correlation(
            top=top, alternatives=[c for c in ranked if c is not top],
            confidence=confidence, confidence_explanation=explanation,
            timeline=self.timeline(top), affected_path=self.affected_path(top), limitations=self.limitations,
        )


def correlate(records: list[ToolCallRecord], catalog: list[EvidenceItem], topology: NetworkTopology,
              sites: list[str]) -> Correlation:
    return Correlator(records, catalog, topology, sites).run()
