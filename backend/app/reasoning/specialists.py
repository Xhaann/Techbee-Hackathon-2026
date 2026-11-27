"""Specialist diagnosis agents and the coordinator that runs them under one shared, bounded tool budget.

Each specialist owns a few fault domains. It plans the read-only checks that test them, and reviews the evidence for
them afterwards: implicated, possible, cleared or inconclusive, with the evidence behind its view and the read-only
commands an engineer would run next. Specialists are deterministic agents; they never call a model, and every tool call
goes through ToolExecutor, so the allowlist, budget, deduplication, cancellation and provenance rules all apply.
"""
import ipaddress
import re
import threading
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from app.engine.evidence import build_catalog
from app.engine.executor import MAX_TOOL_CALLS, ToolCallRecord, ToolExecutor
from app.engine.schema import EvidenceItem, FaultDomain
from app.network.models import DeviceRole
from app.network.repository import load_topology
from app.reasoning.causal import localise
from app.reasoning.commands import SERVICE_PORT, SERVICE_SERVER, commands_for, facts
from app.reasoning.evidence_model import LABEL, likelihood
from app.reasoning.inference import Posterior, percent

D = FaultDomain


@dataclass(frozen=True)
class Scope:
    scenario_id: str
    site_ids: tuple[str, ...]
    services: tuple[str, ...] = ()
    device_ids: tuple[str, ...] = ()
    unaffected_site_ids: tuple[str, ...] = ()
    text: str = ""

    @property
    def site(self) -> str | None:
        return self.site_ids[0] if self.site_ids else None


@dataclass(frozen=True)
class PlannedCheck:
    agent: str
    tool: str
    arguments: dict[str, Any]
    reason: str
    tests: tuple[FaultDomain, ...]

    @property
    def key(self) -> tuple:
        return self.tool, tuple(sorted((k, str(v)) for k, v in self.arguments.items()))


@dataclass
class SpecialistReview:
    agent: str
    title: str
    domains: list[str]
    verdict: str
    probability: float
    statement: str
    evidence_ids: list[str]
    checks_run: int
    recommended_commands: list[dict]
    missing: list[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def site_facts() -> dict[str, dict]:
    topology = load_topology()
    out: dict[str, dict] = {}
    for site in topology.sites:
        vlans = [v for v in topology.vlans if v.site_id == site.site_id]
        network = None
        if vlans:
            first = vlans[0].subnet.network_address.packed
            network = str(ipaddress.ip_network(f"{first[0]}.{first[1]}.0.0/16"))
        out[site.site_id] = {
            "edge": next((d.device_id for d in topology.devices if d.site_id == site.site_id and d.role == DeviceRole.WAN_EDGE), None),
            "switch": next((d.device_id for d in topology.devices if d.site_id == site.site_id and d.role == DeviceRole.ACCESS_SWITCH), None),
            "network": network, "user_host": next((str(v.subnet[100]) for v in vlans if v.vlan_id == 10), None),
        }
    return out


def sentence(text: str) -> str:
    return text[:1].upper() + text[1:]


# Phase 3: protocol engines each specialist owns, and the symptoms strong enough to spend budget on them. Only clearly
# protocol-specific wording counts, so the core plans (and the Phase 2 benchmark) are unchanged for ordinary outages.
PROTOCOL_OWNER = {"routing": ("bgp", "ospf", "ipv6", "multicast"), "transport": ("tcp", "mtu", "qos", "nat", "ipsec"),
                  "security": ("arp", "tls", "traffic", "lateral", "threats"), "switching": ("stp", "vlan", "wireless")}
PROTOCOL_DOMAIN = {"bgp": (D.ROUTING,), "ospf": (D.ROUTING,), "ipv6": (D.ROUTING,), "multicast": (D.ROUTING,), "tcp": (D.INTERFACE_LINK, D.WAN_ISP),
                   "mtu": (D.INTERFACE_LINK,), "qos": (D.INTERFACE_LINK,), "nat": (D.FIREWALL,), "ipsec": (D.FIREWALL, D.WAN_ISP),
                   "stp": (D.SWITCHING,), "vlan": (D.SWITCHING,), "wireless": (D.INTERFACE_LINK,), "arp": (D.SWITCHING,), "tls": (D.UNKNOWN,),
                   "traffic": (), "lateral": (), "threats": ()}
STRONG_SYMPTOMS = [(re.compile(p, re.I), engines) for p, engines in [
    (r"\bloop\b|broadcast storm|lights flash|mac flap", ("stp", "tcp")),
    (r"\btrunk\b|native vlan|vlan (?:mismatch|missing|pruned)|phones? (?:show|have) no|no network after", ("vlan", "stp")),
    (r"duplicate (?:ip|address)|ip conflict|keeps losing (?:its |the )?network|drops off the network", ("arp",)),
    (r"certificate|\btls\b|\bssl\b|not private", ("tls", "arp")),
    (r"\bvpn\b|\btunnels?\b|\bipsec\b|\bike\b", ("ipsec",)),
    (r"large (?:downloads?|transfers?|files?)|file cop|\bstall|\bhang|\bmtu\b|fragment", ("mtu", "tcp")),
    (r"robotic|voice quality|\bqos\b|\bdscp\b", ("qos",)),
    (r"wi-?fi|wireless|\bssid\b|access point", ("wireless",)),
    (r"\bipv6\b|dual.?stack", ("ipv6",)),
    (r"multicast|all-hands|video stream", ("multicast",)),
    (r"\bbgp\b|route leak|\bospf\b|router.?id|flapping routes", ("bgp", "ospf")),
    (r"\bnat\b|some websites fail|internet access failing", ("nat", "tcp")),
    (r"security|\bids\b|port sweep|\bscan|malware|beacon|exfil|lateral|unusual (?:internal )?traffic|odd dns|intrus", ("traffic", "lateral", "threats")),
    (r"zero window|server is slow|application is slow|erp is very slow", ("tcp",)),
]]
# Vague wording that still says something about the mechanism. Only some hosts at a site failing while their neighbours
# work points at something per address (a more-specific route for part of the subnet, an address conflict), not at the
# site's path. Short freezes that keep coming back, or a new device connected at the edge, point at layer 2 (spanning-tree
# changes flush MAC tables and flood). Everyone failing ("users cannot reach ERP") is not partial and adds nothing here.
VAGUE_SYMPTOMS = [(re.compile(p, re.I), engines) for p, engines in [
    (r"\b(?:half|some|part|a few|a subset|a portion|only some|only a few)\s+(?:of\s+)?(?:the\s+|our\s+)?(?:\w+\s+)?"
     r"(?:users|desktops|pcs|clients|laptops|machines|hosts|staff|people|devices)\b|\bother half\b", ("bgp", "arp")),
    (r"\b(?:short|brief|momentary|few[- ]second)\s+(?:freezes?|pauses?|stalls?|drop-?outs?)\b|"
     r"\bfreez\w*\s+(?:for\s+)?(?:a\s+few|a\s+couple\s+of|\d+)\s+seconds?\b", ("stp",)),
    (r"\bnew\s+(?:desk|switch|hub|access point|device)\b[^.;]{0,40}?\b(?:set up|installed|plugged in|connected|added)\b|"
     r"\b(?:plugged|connected)\s+in\s+(?:a|an|another)\s+(?:switch|hub)\b", ("stp",)),
]]
# A mention whose own predicate says the thing is fine or merely busy ("Wi-Fi busy", "Wi-Fi has been busy", "the VPN is
# fine") is context, not a complaint. Only the words straight after the match count, so "robotic; data seems fine" and
# "robotic in the busy hour" stay complaints, and so does "Wi-Fi not working".
BENIGN_PREDICATE = re.compile(r"^\s*(?:(?:is|are|was|were|seems?|looks?|has been|have been|remains?|stays?|still)\s+){0,2}"
                              r"(?:fine|ok|okay|normal|working|unaffected|busy|stable|as usual)\b", re.I)
PROTOCOL_RESERVE = 3


def benign(after: str) -> bool:
    return bool(BENIGN_PREDICATE.match(after))


def complaint(pattern: re.Pattern[str], text: str) -> bool:
    return any(not benign(text[m.end():m.end() + 60]) for m in pattern.finditer(text))


def collected(scenario_id: str) -> set[str] | None:
    """Engines whose telemetry exists for the scenario (None when unknown): an engine with no data can only say so."""
    from app.protocols.registry import SECTION_OF
    from app.protocols.repository import load_telemetry
    try:
        telemetry = load_telemetry(scenario_id)
    except Exception:  # unknown scenario: plan as before and let the executor report it
        return None
    return {engine for engine, section in SECTION_OF.items() if getattr(telemetry, section, None) is not None}


def protocol_engines(scope: "Scope") -> list[str]:
    chosen: list[str] = []
    for pattern, engines in STRONG_SYMPTOMS + VAGUE_SYMPTOMS:
        if complaint(pattern, scope.text):
            chosen += [e for e in engines if e not in chosen]
    available = collected(scope.scenario_id) if chosen else None
    return [e for e in chosen if available is None or e in available]


class Specialist:
    name = "specialist"
    title = "Specialist"
    domains: tuple[FaultDomain, ...] = ()

    def plan(self, scope: Scope) -> list[PlannedCheck]:
        return []

    def protocol_plan(self, scope: Scope) -> list[PlannedCheck]:
        owned = PROTOCOL_OWNER.get(self.name, ())
        return [PlannedCheck(self.name, "analyze_protocol", {"protocol": engine, **({"site_id": scope.site} if scope.site and engine != "threats" else {})},
                             f"Do the {engine.upper() if len(engine) <= 4 else engine} checks explain the symptoms at {scope.site or 'the affected sites'}?",
                             PROTOCOL_DOMAIN[engine]) for engine in protocol_engines(scope) if engine in owned]

    def check(self, tool: str, arguments: dict, reason: str, *tests: FaultDomain) -> PlannedCheck:
        return PlannedCheck(self.name, tool, {k: v for k, v in arguments.items() if v is not None}, reason, tests or self.domains)

    def review(self, evidence: list[EvidenceItem], result: Posterior, scope: Scope, ran: list[PlannedCheck],
               fault_supported: bool = True) -> SpecialistReview:
        probability = round(sum(result.probabilities.get(d, 0.0) for d in self.domains), 3)
        mine = [item for item in evidence if any(likelihood(item).get(d, 0) > 0 for d in self.domains)]
        # Measured findings speak first; raw log lines only when nothing measured supports the domain.
        mine.sort(key=lambda item: (item.evidence_type.value == "record", -max(likelihood(item).get(d, 0) for d in self.domains)))
        lead = max(self.domains, key=lambda d: result.probabilities.get(d, 0.0))
        tested = [c for c in ran if set(c.tests) & set(self.domains)]
        if not fault_supported:
            verdict = "cleared" if tested else "inconclusive"
            statement = (f"Checked {len(tested)} way{'s' if len(tested) != 1 else ''}; nothing points at {LABEL[lead]}." if tested
                         else f"No {LABEL[lead]} checks have run yet.")
        elif probability >= 0.5:
            verdict = "implicated"
            statement = (f"{sentence(LABEL[lead])} is the likely fault ({percent(probability)})"
                         + (f": {mine[0].summary}" if mine else "."))
        elif probability >= 0.15:
            verdict = "possible"
            statement = f"{sentence(LABEL[lead])} is possible ({percent(probability)}) but not the leading explanation."
        elif tested and probability < 0.05:
            verdict = "cleared"
            statement = f"Checked {len(tested)} way{'s' if len(tested) != 1 else ''} and found nothing pointing at {LABEL[lead]}."
        else:
            verdict = "inconclusive"
            statement = f"Not enough {LABEL[lead]} evidence either way."
        site = scope.site
        devices = sorted({item.device_id for item in mine if item.device_id})
        commands = []
        for domain in self.domains:
            commands += [c.as_dict() for c in commands_for(device_id=devices[0] if devices else None, site_id=site,
                                                            services=list(scope.services) or ["application"], domain=domain)
                         if c.domain == domain]
        unique = {(c["device_id"], c["command"]): c for c in commands}
        missing = [c.reason for c in self.plan(scope) if c.key not in {r.key for r in ran}]
        return SpecialistReview(self.name, self.title, [d.value for d in self.domains], verdict, probability, statement,
                                [item.evidence_id for item in mine[:5]], len(tested), list(unique.values())[:3], missing[:3])


class RoutingAgent(Specialist):
    name, title, domains = "routing", "Routing specialist", (D.ROUTING,)

    def plan(self, scope: Scope) -> list[PlannedCheck]:
        site = site_facts().get(scope.site or "", {})
        edge, switch = site.get("edge"), site.get("switch")
        server = SERVICE_SERVER.get(next((s for s in scope.services if s in SERVICE_SERVER), "application"))
        checks = []
        if edge:
            checks.append(self.check("analyze_routing_adjacency", {"device_id": edge}, f"Are {edge}'s OSPF/BGP adjacencies up?",
                                     D.ROUTING, D.WAN_ISP))
        if switch:
            checks.append(self.check("check_network_reachability", {"source": switch, "destination": server},
                                     f"Does {scope.site} have a layer-3 path to {server}?", D.ROUTING, D.WAN_ISP, D.SHARED_INFRASTRUCTURE))
        if edge:
            checks.append(self.check("get_routing_state", {"device_id": edge}, f"Which routes does {edge} hold?", D.ROUTING))
        return checks


class SecurityAgent(Specialist):
    name, title, domains = "security", "Security specialist", (D.FIREWALL, D.VLAN_AUTHENTICATION)

    def plan(self, scope: Scope) -> list[PlannedCheck]:
        site = site_facts().get(scope.site or "", {})
        service = next((s for s in scope.services if s in SERVICE_PORT), "application")
        checks = []
        if site.get("network"):
            checks.append(self.check("get_firewall_logs", {"source": site["network"]}, f"Is a firewall denying traffic from {scope.site}?",
                                     D.FIREWALL))
        if site.get("switch"):
            checks.append(self.check("get_device_logs", {"device_id": site["switch"], "min_severity": "warning"},
                                     f"Is 802.1X or RADIUS failing on {site['switch']}?", D.VLAN_AUTHENTICATION))
        if site.get("user_host"):
            protocol, port = SERVICE_PORT[service]
            target = SERVICE_SERVER.get(service, "203.0.113.10")
            checks.append(self.check("trace_packet", {"source": site["user_host"], "destination": target, "protocol": protocol, "port": port},
                                     f"Which policy does a {scope.site} user's {service} packet hit?", D.FIREWALL, D.ROUTING))
        return checks


class DnsDhcpAgent(Specialist):
    name, title, domains = "dns_dhcp", "DNS/DHCP specialist", (D.DNS, D.DHCP)

    def plan(self, scope: Scope) -> list[PlannedCheck]:
        checks = []
        if scope.site:
            checks.append(self.check("get_dhcp_dns_status", {"site_id": scope.site}, f"Are DNS answers and DHCP leases healthy for {scope.site}?"))
            checks.append(self.check("get_change_history", {"site_id": scope.site},
                                     f"Did a change at {scope.site} remove a relay or alter addressing?", D.DHCP, D.ROUTING, D.FIREWALL))
        return checks


class TransportAgent(Specialist):
    name, title = "transport", "WAN and platform specialist"
    domains = (D.WAN_ISP, D.INTERFACE_LINK, D.NETWORK_DEVICE_FAILURE, D.SHARED_INFRASTRUCTURE)

    def plan(self, scope: Scope) -> list[PlannedCheck]:
        site = site_facts().get(scope.site or "", {})
        edge, switch = site.get("edge"), site.get("switch")
        server = SERVICE_SERVER.get(next((s for s in scope.services if s in SERVICE_SERVER), "application"))
        checks = []
        if switch:
            checks.append(self.check("analyze_path_health", {"source": switch, "destination": server},
                                     f"Is any link on {scope.site}'s path to {server} down or degraded?", D.WAN_ISP, D.INTERFACE_LINK))
        if scope.site:
            checks.append(self.check("get_event_timeline", {"site_id": scope.site}, f"Did anything at {scope.site} fail and recover?",
                                     D.WAN_ISP, D.ROUTING))
        shared = localise(list(scope.site_ids), list(scope.unaffected_site_ids))["common_devices"]
        core = [d for d in shared if d.startswith("CORE-RTR")] or (["CORE-RTR-01"] if len(scope.site_ids) > 1 else [])
        for device in core[:1]:
            checks.append(self.check("check_device_availability", {"device_id": device}, f"Is {device}, shared by the affected sites, up?",
                                     D.NETWORK_DEVICE_FAILURE, D.SHARED_INFRASTRUCTURE))
        if edge and edge in facts()["wan"]:
            checks.append(self.check("analyze_packet_loss", {"device_id": edge, "interface": facts()["wan"][edge][0]},
                                     f"Is {edge}'s WAN circuit losing packets?", D.WAN_ISP, D.INTERFACE_LINK))
        return checks


class SwitchingAgent(Specialist):
    """Phase 3: spanning tree, trunks and Wi-Fi. It has no core checks of its own; it acts only when the symptoms point at
    layer 2 or wireless, through the protocol engines."""
    name, title, domains = "switching", "Switching and wireless specialist", (D.SWITCHING,)


AGENTS: dict[str, Specialist] = {agent.name: agent for agent in (TransportAgent(), RoutingAgent(), SecurityAgent(), DnsDhcpAgent(),
                                                                 SwitchingAgent())}
SERVICE_PRIORITY = {"dns": "dns_dhcp", "dhcp": "dns_dhcp", "authentication": "security"}


def priority(scope: Scope) -> list[str]:
    """Which specialist goes first: the one that owns the services users named, then transport and routing (an outage
    of everything is most often a path problem), then the rest."""
    text = scope.text.lower()
    order = [SERVICE_PRIORITY[s] for s in scope.services if s in SERVICE_PRIORITY]
    if any(w in text for w in ("802.1x", "authentication failed", "radius", "sign-in", "dot1x")):
        order.append("security")
    if any(w in text for w in ("ip address", "configuring ip", "self-assigned", "169.254", "dhcp")):
        order.append("dns_dhcp")
    if any(w in text for w in ("name", "resolve", "dns", "server not found")):
        order.append("dns_dhcp")
    if any(w in text for w in ("timeout", "blocked", "denied", "erp portal", "cannot open")) and "security" not in order:
        order.append("security")
    order += ["transport", "routing", "security", "dns_dhcp", "switching"]
    return list(dict.fromkeys(order))


def coordinate(scope: Scope, budget: int = MAX_TOOL_CALLS) -> list[PlannedCheck]:
    """The multi-agent plan: specialists in priority order, interleaved one check at a time, duplicates removed, cut to
    the shared budget."""
    plans = {name: AGENTS[name].plan(scope) for name in priority(scope)}
    order: list[PlannedCheck] = []
    seen: set[tuple] = set()
    depth = max((len(p) for p in plans.values()), default=0)
    for index in range(depth):
        for name, checks in plans.items():
            if index < len(checks) and checks[index].key not in seen:
                seen.add(checks[index].key)
                order.append(checks[index])
    # Phase 3: protocol checks the symptoms call for, interleaved across specialists, in at most PROTOCOL_RESERVE slots.
    protocol_plans = {name: AGENTS[name].protocol_plan(scope) for name in plans}
    extra: list[PlannedCheck] = []
    for index in range(max((len(p) for p in protocol_plans.values()), default=0)):
        for checks in protocol_plans.values():
            if index < len(checks) and checks[index].key not in seen:
                seen.add(checks[index].key)
                extra.append(checks[index])
    reserve = min(PROTOCOL_RESERVE, len(extra), budget)
    return order[:budget - reserve] + extra[:reserve]


@dataclass
class TeamRun:
    plan: list[PlannedCheck]
    records: list[ToolCallRecord]
    evidence: list[EvidenceItem]
    executed: list[PlannedCheck]
    cancelled: bool = False


def investigate(scope: Scope, budget: int = MAX_TOOL_CALLS, observer=None, cancel_event: threading.Event | None = None,
                evidence_offset: int = 0) -> TeamRun:
    plan = coordinate(scope, budget)
    executor = ToolExecutor(scope.scenario_id, max_calls=budget, observer=observer, cancel_event=cancel_event,
                            evidence_offset=evidence_offset)
    executed: list[PlannedCheck] = []
    for check in plan:
        if cancel_event is not None and cancel_event.is_set():
            break
        record = executor.execute(check.tool, check.arguments)
        if record.status in ("executed", "failed"):
            executed.append(check)
    return TeamRun(plan, executor.records, build_catalog(executor.records), executed,
                   cancelled=bool(cancel_event and cancel_event.is_set()))


def review_all(evidence: list[EvidenceItem], result: Posterior, scope: Scope, ran: list[PlannedCheck],
               fault_supported: bool = True) -> list[SpecialistReview]:
    return [AGENTS[name].review(evidence, result, scope, ran, fault_supported) for name in priority(scope)]


TOOL_TESTS = {"get_firewall_logs": ("security", (D.FIREWALL,)), "get_device_logs": ("security", (D.VLAN_AUTHENTICATION,)),
              "get_dhcp_dns_status": ("dns_dhcp", (D.DNS, D.DHCP)), "get_change_history": ("dns_dhcp", (D.DHCP, D.ROUTING, D.FIREWALL)),
              "analyze_routing_adjacency": ("routing", (D.ROUTING,)), "get_routing_state": ("routing", (D.ROUTING,)),
              "check_network_reachability": ("routing", (D.ROUTING, D.WAN_ISP)), "trace_packet": ("security", (D.FIREWALL, D.ROUTING)),
              "analyze_path_health": ("transport", (D.WAN_ISP, D.INTERFACE_LINK)),
              "analyze_packet_loss": ("transport", (D.WAN_ISP, D.INTERFACE_LINK)),
              "analyze_interface_errors": ("transport", (D.INTERFACE_LINK, D.WAN_ISP)),
              "get_interface_stats": ("transport", (D.WAN_ISP, D.INTERFACE_LINK)),
              "check_device_availability": ("transport", (D.NETWORK_DEVICE_FAILURE, D.SHARED_INFRASTRUCTURE)),
              "get_event_timeline": ("transport", (D.WAN_ISP, D.ROUTING))}


def checks_from_records(records: list[ToolCallRecord]) -> list[PlannedCheck]:
    """Tool calls another engine already made, attributed to the specialist that owns them (for reviews of its evidence)."""
    out = []
    for record in records:
        if record.status not in ("executed", "failed"):
            continue
        if record.tool == "analyze_protocol":
            engine = record.arguments.get("protocol", "")
            owner = next((name for name, engines in PROTOCOL_OWNER.items() if engine in engines), "transport")
            out.append(PlannedCheck(owner, record.tool, dict(record.arguments), "already run", PROTOCOL_DOMAIN.get(engine, ())))
            continue
        owner, tests = TOOL_TESTS.get(record.tool, ("transport", ()))
        out.append(PlannedCheck(owner, record.tool, dict(record.arguments), "already run", tests))
    return out
