"""Entity extraction against the synthetic topology. Nothing here calls a diagnostic tool."""
import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache

from app.agent.session import SERVICE_TERMS, SYMPTOM_TERMS, TIMEFRAME_TERMS
from app.conversation.models import Entities, Scope
from app.network.aliases import SITE_ALIASES, UPPERCASE_ONLY_ALIASES
from app.network.models import DeviceRole, LinkType, NetworkTopology
from app.network.repository import load_topology

INTERFACE_PATTERN = re.compile(
    r"\b(?:(GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet|Gi|Te|Fa|Eth|Et|ge-|xe-)\s?(\d+(?:/\d+){0,3}(?:\.\d+)?))\b",
    re.IGNORECASE)
INTERFACE_PREFIX = {"gigabitethernet": "Gi", "gi": "Gi", "tengigabitethernet": "Te", "te": "Te", "fastethernet": "Fa",
                    "fa": "Fa", "ethernet": "Eth", "eth": "Eth", "et": "Eth", "ge-": "ge-", "xe-": "xe-"}
WAN_INTERFACE = re.compile(r"\b(wan (?:interface|link|port|circuit|uplink)|uplink|wan side|carrier (?:link|circuit))\b", re.IGNORECASE)
EVIDENCE_PATTERN = re.compile(r"(?:\bevidence\s+(?:item\s+)?#?\s*[eE]?(\d{1,4})\b|\b[E](\d{1,4})\b)")
IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")
SCOPES: list[tuple[Scope, re.Pattern[str]]] = [
    ("single", re.compile(r"\b(one user|a single user|single user|only me|just me|just one (?:user|person)|one person|only one (?:user|person)"
                          r"|one laptop|one machine|my (?:laptop|machine|pc))\b", re.IGNORECASE)),
    ("some", re.compile(r"\b(some (?:users|people|staff|of (?:them|the users))|a few|several (?:users|people)|part of|only some|a subset"
                        r"|some$|half (?:of )?the|a handful|certain users|a couple of)\b", re.IGNORECASE)),
    ("everyone", re.compile(r"\b(everyone|everybody|all (?:the )?(?:users|staff|employees|people|of them|devices|clients)|whole (?:office|site|branch|team|building)"
                            r"|entire (?:office|site|branch|building)|site[- ]wide|office[- ]wide|nobody|no one|all of (?:them|us)|every user|all$|all users"
                            r"|lost all|(?:both|all) (?:offices|sites|branches|locations)|(?:completely|totally|fully) (?:offline|down))\b",
                            re.IGNORECASE)),
]
UNAFFECTED_AFTER = re.compile(r"^[^.;,!?]{0,40}?\b(?:is|are|seems?|looks?|remains?|stays?)?\s*(?:fine|ok|okay|unaffected|not affected|"
                              r"working(?: normally| fine)?|works(?: normally| fine)?|good|healthy|normal|up)\b", re.IGNORECASE)
UNAFFECTED_BEFORE = re.compile(r"\b(?:except(?: for)?|apart from|other than|but not|not including|excluding)\s+(?:the\s+)?$", re.IGNORECASE)
ROLE_WORDS: list[tuple[DeviceRole, re.Pattern[str]]] = [
    (DeviceRole.WAN_EDGE, re.compile(r"\b(routers?|rtr|wan edges?|edge routers?|gateways?)\b", re.IGNORECASE)),
    (DeviceRole.ACCESS_SWITCH, re.compile(r"\b(switch(?:es)?|access switch(?:es)?|sw)\b", re.IGNORECASE)),
]
SERVICE_TARGET_ROLE = {"application": DeviceRole.APPLICATION_SERVER, "dns": DeviceRole.DNS_SERVER, "dhcp": DeviceRole.DHCP_SERVER,
                       "authentication": DeviceRole.AUTHENTICATION_SERVER}


@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    description: str
    link_type: str | None
    link_id: str | None


@dataclass
class TopologyIndex:
    topology: NetworkTopology
    devices: dict[str, object] = field(default_factory=dict)
    site_names: dict[str, str] = field(default_factory=dict)
    interfaces: dict[str, list[InterfaceInfo]] = field(default_factory=dict)

    @classmethod
    def build(cls, topology: NetworkTopology) -> "TopologyIndex":
        index = cls(topology=topology)
        index.devices = {device.device_id: device for device in topology.devices}
        index.site_names = {site.site_id: site.name for site in topology.sites}
        by_interface = {}
        for link in topology.links:
            by_interface[link.a_interface_id] = link
            by_interface[link.b_interface_id] = link
        for interface in topology.interfaces:
            link = by_interface.get(interface.interface_id)
            index.interfaces.setdefault(interface.device_id, []).append(InterfaceInfo(
                name=interface.name, description=interface.description or "",
                link_type=link.link_type.value if link is not None else None, link_id=link.link_id if link is not None else None))
        return index

    def device_site(self, device_id: str) -> str | None:
        device = self.devices.get(device_id)
        return getattr(device, "site_id", None)

    def site_device(self, site_id: str, role: DeviceRole) -> str | None:
        return next((d.device_id for d in self.topology.devices if d.site_id == site_id and d.role == role), None)

    def wan_interface(self, device_id: str) -> str | None:
        wan = [i.name for i in self.interfaces.get(device_id, []) if i.link_type == LinkType.WAN.value]
        return wan[0] if len(wan) == 1 else None

    def normalize_interface(self, device_id: str, raw: str) -> str | None:
        names = {i.name.lower(): i.name for i in self.interfaces.get(device_id, [])}
        return names.get(raw.lower())

    def service_target(self, service: str) -> str | None:
        role = SERVICE_TARGET_ROLE.get(service)
        if role is None:
            return None
        return sorted(d.device_id for d in self.topology.devices if d.role == role)[0]

    def site_network(self, site_id: str) -> str | None:
        subnets = [vlan.subnet for vlan in self.topology.vlans if vlan.site_id == site_id]
        if not subnets:
            return None
        network = subnets[0]
        while not all(subnet.subnet_of(network) for subnet in subnets):
            network = network.supernet()
        return str(network)


@lru_cache
def topology_index() -> TopologyIndex:
    return TopologyIndex.build(load_topology())


def ordered_devices(text: str, index: TopologyIndex) -> list[tuple[int, str]]:
    found: dict[str, int] = {}
    for device_id in index.devices:
        match = re.search(rf"(?<![A-Za-z0-9-]){re.escape(device_id)}(?![A-Za-z0-9-])", text, re.IGNORECASE)
        if match:
            found[device_id] = match.start()
    return sorted(((position, device) for device, position in found.items()))


def site_spans(text: str, index: TopologyIndex) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for site_id, name in index.site_names.items():
        for pattern, flags in ((rf"(?<![A-Za-z0-9-]){re.escape(site_id)}(?![A-Za-z0-9-])", 0), (rf"\b{re.escape(name)}\b", re.IGNORECASE)):
            spans += [(m.start(), m.end(), site_id) for m in re.finditer(pattern, text, flags)]
    for alias, site_id in SITE_ALIASES.items():
        spans += [(m.start(), m.end(), site_id) for m in re.finditer(rf"\b{re.escape(alias)}\b", text, re.IGNORECASE)]
    for alias, site_id in UPPERCASE_ONLY_ALIASES.items():
        spans += [(m.start(), m.end(), site_id) for m in re.finditer(rf"\b{re.escape(alias)}\b", text)]
    return sorted(spans)


def site_mentions(text: str, index: TopologyIndex) -> list[str]:
    """Sites the text names as affected, in order. A site described as fine or excluded ("Bengaluru is fine",
    "everyone except Singapore") is left out; see unaffected_sites."""
    affected: list[str] = []
    for start, end, site_id in site_spans(text, index):
        fine = UNAFFECTED_AFTER.match(text[end:])
        rest = text[end + fine.end():] if fine else ""
        asked = fine is not None and re.match(r"^(?:(?!\b(?:but|and|while|whereas)\b)[^.;!?])*\?", rest, re.IGNORECASE) is not None
        if (fine and not asked) or UNAFFECTED_BEFORE.search(text[:start]):
            continue
        if site_id not in affected:
            affected.append(site_id)
    return affected


def unaffected_sites(text: str, index: TopologyIndex) -> list[str]:
    named = list(dict.fromkeys(site_id for _, _, site_id in site_spans(text, index)))
    affected = set(site_mentions(text, index))
    return [site_id for site_id in named if site_id not in affected]


def alias_devices(text: str, sites: list[str], index: TopologyIndex) -> list[str]:
    devices = []
    for site in sites:
        for role, pattern in ROLE_WORDS:
            if pattern.search(text):
                device = index.site_device(site, role)
                if device:
                    devices.append(device)
    return devices


def interfaces_in(text: str) -> list[str]:
    names = []
    for match in INTERFACE_PATTERN.finditer(text):
        prefix = INTERFACE_PREFIX.get(match.group(1).lower(), match.group(1))
        names.append(f"{prefix}{match.group(2)}")
    return list(dict.fromkeys(names))


def evidence_ids_in(text: str) -> list[str]:
    ids = []
    for match in EVIDENCE_PATTERN.finditer(text):
        number = match.group(1) or match.group(2)
        if number and int(number) > 0:
            ids.append(f"E{int(number)}")
    return list(dict.fromkeys(ids))[:10]


def ip_addresses_in(text: str) -> list[str]:
    addresses = []
    for match in IPV4.finditer(text):
        try:
            ipaddress.ip_network(match.group(1), strict=False)
        except ValueError:
            continue
        addresses.append(match.group(1))
    return list(dict.fromkeys(addresses))[:5]


def scope_in(text: str) -> Scope | None:
    for scope, pattern in SCOPES:
        if pattern.search(text.strip()):
            return scope
    return None


def extract(text: str, index: TopologyIndex | None = None) -> Entities:
    index = index or topology_index()
    devices = [device for _, device in ordered_devices(text, index)]
    sites = site_mentions(text, index)
    devices += [device for device in alias_devices(text, sites, index) if device not in devices]
    for device in devices:
        site = index.device_site(device)
        if site and site not in sites:
            sites.append(site)
    services = [service.value for service, pattern in SERVICE_TERMS.items() if pattern.search(text)]
    symptoms = list(dict.fromkeys(match.group(0).lower() for match in SYMPTOM_TERMS.finditer(text)))[:10]
    timeframe = next((match.group(0) for match in TIMEFRAME_TERMS.finditer(text)), None)
    return Entities(site_ids=sites[:5], device_ids=devices[:10], interfaces=interfaces_in(text)[:5], services=services,
                    symptoms=symptoms, scope=scope_in(text), timeframe=timeframe, evidence_ids=evidence_ids_in(text),
                    ip_addresses=ip_addresses_in(text), unaffected_site_ids=[s for s in unaffected_sites(text, index) if s not in sites])


def wan_interface_requested(text: str) -> bool:
    return bool(WAN_INTERFACE.search(text))
