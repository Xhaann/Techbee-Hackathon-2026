"""Plain-language wording for chat replies.

Evidence and diagnoses are recorded for audit: full layer-3 paths, ISO timestamps, circuit and rule identifiers. A chat
reply needs the same facts said the way an engineer says them to a colleague. Nothing here decides anything. It only
rewords what the engines produced, and callers keep the evidence ids, so the full record stays one click away.
"""
import re
from typing import Iterable

from app.conversation.entities import TopologyIndex
from app.engine.schema import Diagnosis, EvidenceItem, EvidenceType
from app.network.models import DeviceRole

SITE = {"NYC": "New York", "SIN": "Singapore", "BLR": "Bengaluru", "CORE": "the core", "DC1": "the data centre"}
ROLE = {
    DeviceRole.WAN_EDGE: "{site} router", DeviceRole.ACCESS_SWITCH: "{site} switch", DeviceRole.CORE_ROUTER: "core router",
    DeviceRole.CORE_SWITCH: "core switch", DeviceRole.DISTRIBUTION_SWITCH: "data-centre switch",
    DeviceRole.PERIMETER_FIREWALL: "internet firewall", DeviceRole.DATA_CENTRE_FIREWALL: "data-centre firewall",
    DeviceRole.DNS_SERVER: "DNS server", DeviceRole.DHCP_SERVER: "DHCP server", DeviceRole.AUTHENTICATION_SERVER: "RADIUS server",
    DeviceRole.APPLICATION_SERVER: "application server",
}
PER_SITE = {DeviceRole.WAN_EDGE, DeviceRole.ACCESS_SWITCH}
DEVICE_ID = re.compile(r"\b[A-Z][A-Z0-9]{1,5}-(?:[A-Z]{2,5}-){0,2}\d{2}\b")
INTERFACE = re.compile(r"\b([A-Z][A-Z0-9]{1,5}-(?:[A-Z]{2,5}-){0,2}\d{2}):([A-Za-z]+[\d/.]+)")
LINK_ID = re.compile(r"\b(?:[Ll]ink )?(LNK-[A-Z0-9-]*[A-Z0-9])")
SITE_CODE = re.compile(r"(?<![\w-])(NYC|SIN|BLR)(?![\w-])")
SINGULAR = re.compile(r"\b1 (queries|flows|events|transactions|conflicts|requests|sessions)\b")
SINGULAR_WORD = {"queries": "query", "flows": "flow", "events": "event", "transactions": "transaction", "conflicts": "conflict",
                 "requests": "request", "sessions": "session"}
ORDINAL = {1: "first", 2: "second", 3: "third", 4: "fourth"}
ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}T(\d{2}:\d{2})(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")
BETWEEN = re.compile(r"between (\d{2}:\d{2}) UTC and (\d{2}:\d{2}) UTC")
PATH_TAIL = re.compile(r";\s*path [^;]*")
PARENS = re.compile(r"\s*\([^()]*\)")
REACH = re.compile(r"Layer-3 path (\S+) -> (\S+) is (\w+)(?: at (\S+) \(([^)]*)\))?")
DENIED = re.compile(r"(\d+) flows? denied by rule (\S+)(?: \([^)]*\))? on (\S+)")
HEALTHY = {"PATH_REACHABLE", "DEVICE_AVAILABLE", "NO_PACKET_LOSS_MEASURED"}
HEALTHY_MEANING = {"PATH_REACHABLE": "So it isn't a broken network path.", "DEVICE_AVAILABLE": "So the device itself is up.",
                   "NO_PACKET_LOSS_MEASURED": "So that link isn't losing packets."}
KIND = {EvidenceType.OBSERVED_RESULT: "a check result", EvidenceType.OBSERVED_FINDING: "a measured finding",
        EvidenceType.INFERRED_FINDING: "an inferred finding", EvidenceType.RECORD: "a log line"}
FAULT_PLAIN = {"wan_isp": "a WAN circuit fault", "routing": "a routing problem", "switching": "a switching problem",
               "firewall": "a firewall policy block", "vlan_authentication": "an 802.1X sign-in problem", "dhcp": "a DHCP problem",
               "dns": "a DNS problem", "network_device_failure": "a failed device", "interface_link": "a link or interface fault",
               "shared_infrastructure": "a shared core device fault", "unknown": "an unknown cause"}
PROBLEMS = [
    (re.compile(r"certificat|\btls\b|\bssl\b", re.I), "the certificate errors"),
    (re.compile(r"\bdns\b|name resolution|resolv", re.I), "the DNS errors"),
    (re.compile(r"\bdhcp\b|no ip|ip address", re.I), "the addressing problem"),
    (re.compile(r"\bvpn\b|tunnel", re.I), "the VPN problem"),
    (re.compile(r"wi-?fi|wireless", re.I), "the Wi-Fi problem"),
    (re.compile(r"\bvoice\b|\bcalls?\b|\bphones?\b", re.I), "the call problems"),
    (re.compile(r"freez", re.I), "the freezes"),
    (re.compile(r"\bslow|latency|\blag", re.I), "the slowness"),
    (re.compile(r"\bdrop|disconnect|flap|cut out", re.I), "the drops"),
    (re.compile(r"log-?ins?\b|sign-?in|authenticat", re.I), "the sign-in failures"),
    (re.compile(r"can'?t|cannot|unable|\bdown\b|unreachable|no access|outage|not able|lost", re.I), "the outage"),
]
SECURITY = re.compile(r"port[- ]?(?:sweep|scan)|\bscan(?:s|ning|ner)?\b|failed log-?ins?|brute[- ]?force|password spray|malware|"
                      r"ransomware|\bvirus|intrusion|\bIDS\b|\bIPS\b|ddos|exfiltrat|lateral movement|phishing|unauthori[sz]ed|"
                      r"\battack|breach|compromis", re.I)
SECURITY_LABELS = [(re.compile(r"port[- ]?(?:sweep|scan)", re.I), "a port sweep"), (re.compile(r"\bscan", re.I), "a scan"),
                   (re.compile(r"failed log-?ins?|brute[- ]?force|password spray", re.I), "failed logins"),
                   (re.compile(r"malware|ransomware|\bvirus", re.I), "possible malware"),
                   (re.compile(r"exfiltrat", re.I), "possible data exfiltration"),
                   (re.compile(r"lateral movement", re.I), "possible lateral movement"),
                   (re.compile(r"\battack|breach|compromis|intrusion", re.I), "a possible attack")]
PROPER = {"New", "York", "Singapore", "Bengaluru", "London", "Slough", "Carrier", "Metro", "Corp", "I", "IDS", "IPS", "ERP"}


def join(items: Iterable[str]) -> str:
    items = [item for item in items if item]
    if not items:
        return ""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def ids_text(ids: Iterable[str]) -> str:
    """E1 / E1 and E4 / E1 to E3: evidence ids written the way people read them."""
    ids = list(dict.fromkeys(ids))
    numbers = [int(i[1:]) for i in ids if i[1:].isdigit()]
    if len(ids) >= 3 and len(numbers) == len(ids) and numbers == list(range(numbers[0], numbers[0] + len(ids))):
        return f"{ids[0]} to {ids[-1]}"
    return join(ids)


def lower_first(text: str) -> str:
    """Lower-cases a sentence's opening word for use mid-sentence, leaving names and identifiers alone."""
    word = text.split(" ", 1)[0] if text else ""
    if re.fullmatch(r"[A-Z][a-z]+(?:-[a-z]+)?", word) and word not in PROPER:
        return text[0].lower() + text[1:]
    return text


MENTION = re.compile(r" (LNK-[A-Z0-9-]*[A-Z0-9]|[A-Z][A-Z0-9]{1,5}-(?:[A-Z]{2,5}-){0,2}\d{2})\b(?![:-])")


def first_mention(text: str) -> str:
    """Keeps a device or link identifier only where it first appears, so a reply names it once and then just says "the router"."""
    seen: set[str] = set()

    def keep(match: re.Match[str]) -> str:
        if match.group(1) in seen:
            return ""
        seen.add(match.group(1))
        return match.group(0)
    return MENTION.sub(keep, text)


def capital(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def sentence(text: str) -> str:
    text = text.strip()
    return capital(text) + ("" if text.endswith((".", "?", "!")) else ".")


def problem(title: str, symptoms: list[str], description: str = "") -> str:
    """What users are seeing, as a short noun phrase ("the certificate errors"), taken from the report itself."""
    for text in [title.split(";")[0], *symptoms[:1], title, description]:
        for pattern, phrase in PROBLEMS:
            if pattern.search(text or ""):
                return phrase
    return "the reported problem"


class Namer:
    """Turns topology identifiers into the names people use: NYC-RTR-01 is "the New York router"."""

    def __init__(self, index: TopologyIndex) -> None:
        self.index = index
        counts: dict[DeviceRole, int] = {}
        for device in index.topology.devices:
            counts[device.role] = counts.get(device.role, 0) + 1
        self.shared = {role for role, count in counts.items() if count > 1 and role not in PER_SITE}
        self.links = {link.link_id: link for link in index.topology.links}

    def site(self, site_id: str) -> str:
        return SITE.get(site_id, self.index.site_names.get(site_id, site_id))

    def sites(self, site_ids: Iterable[str]) -> str:
        return join([self.site(site) for site in site_ids])

    def label(self, device_id: str) -> str | None:
        device = self.index.devices.get(device_id)
        if device is None:
            return None
        return ROLE.get(device.role, "device").format(site=SITE.get(device.site_id, device.site_id))

    def device(self, device_id: str | None, with_id: bool = False) -> str:
        if not device_id:
            return "the device"
        label = self.label(device_id)
        if label is None:
            return device_id
        if with_id:
            return f"the {label} {device_id}"
        if self.index.devices[device_id].role in self.shared:
            number = int(device_id.rsplit("-", 1)[1]) if device_id.rsplit("-", 1)[1].isdigit() else 0
            return f"the {ORDINAL[number]} {label}" if number in ORDINAL else f"{label} {device_id}"
        return f"the {label}"

    def link(self, link_id: str, with_id: bool = False) -> str:
        link = self.links.get(link_id)
        if link is None:
            return link_id
        ends = [link.a_device_id, link.b_device_id]
        if link.link_type.value == "wan":
            branch = next((self.index.device_site(d) for d in ends if self.index.device_site(d) not in ("CORE", "DC1")), None)
            label = f"{SITE.get(branch or '', branch)} WAN link"
        elif link.link_type.value == "metro":
            label = "metro link to the data centre"
        else:
            label = f"link between the {self.label(ends[0])} and the {self.label(ends[1])}"
        return f"the {label} {link_id}" if with_id else f"the {label}"

    def where(self, endpoint: str, fallback_device: str | None = None) -> str:
        """The site a path starts from, for "traffic from New York"."""
        site = self.index.device_site(endpoint) or (self.index.device_site(fallback_device) if fallback_device else None)
        return SITE.get(site, site) if site else endpoint

    def words(self, text: str, with_ids: bool = False) -> str:
        """An audit summary rewritten for reading: no full paths, short times, names instead of identifiers."""
        text = SITE_CODE.sub(lambda m: SITE[m.group(1)], text)
        text = PATH_TAIL.sub("", text)
        text = PARENS.sub("", text)
        text = SINGULAR.sub(lambda m: f"1 {SINGULAR_WORD[m.group(1)]}", text)
        text = ISO.sub(lambda m: f"{m.group(1)} UTC", text)
        text = BETWEEN.sub(lambda m: f"at {m.group(1)} UTC" if m.group(1) == m.group(2)
                           else f"between {m.group(1)} and {m.group(2)} UTC", text)
        text = INTERFACE.sub(lambda m: f"{m.group(2)} on {self.device(m.group(1), with_ids)}", text)
        text = LINK_ID.sub(lambda m: self.link(m.group(1), with_ids), text)
        text = DEVICE_ID.sub(lambda m: self.device(m.group(0), with_ids), text)
        return re.sub(r"\s{2,}", " ", text).strip().rstrip(".")

    # ---------- evidence ----------

    def clause(self, item: EvidenceItem, with_ids: bool = False) -> str:
        """What one evidence item shows, as a clause that can follow "I found that"."""
        reach = REACH.match(item.summary) if item.code.startswith("PATH_") else None
        if reach:
            source, target, status = self.where(reach.group(1), item.device_id), reach.group(2), reach.group(3)
            destination = self.device(target, with_ids) if target in self.index.devices else target
            if status == "reachable":
                return f"traffic from {source} gets through to {destination}"
            if status == "unreachable":
                stop = f", stopping at {self.device(reach.group(4), with_ids)}" if reach.group(4) else ""
                return f"traffic from {source} can't reach {destination}{stop}"
            return f"it isn't clear whether traffic from {source} reaches {destination}"
        denied = DENIED.search(item.summary) if item.code == "TRAFFIC_DENIED" else None
        if denied:
            count = int(denied.group(1))
            what = "one connection" if count == 1 else f"{count} connections"
            rule = f" with rule {denied.group(2)}" if with_ids else ""
            when = re.search(r" (?:at|between) \d{2}:\d{2}.*UTC", self.words(item.summary))
            return f"{self.device(denied.group(3), with_ids)} blocked {what}{rule}{when.group(0) if when else ''}"
        if item.evidence_type == EvidenceType.RECORD:
            message = re.sub(r"^\[\w+\]\s*", "", item.summary)
            return f"{self.device(item.device_id, with_ids)} logged \"{message.rstrip('.')}\""
        return lower_first(self.words(item.summary, with_ids))

    def grouped(self, items: list[EvidenceItem], with_ids: bool = False,
                offices: list[str] | None = None) -> list[tuple[str, list[str]]]:
        """Clauses for a set of evidence. Paths that end at the same place are said once ("the paths from ... all work")."""
        order: list[tuple] = []
        groups: dict[tuple, tuple[list[str], list[str]]] = {}
        for item in items:
            reach = REACH.match(item.summary) if item.code.startswith("PATH_") else None
            if reach and reach.group(3) in ("reachable", "unreachable") and not reach.group(4):
                key = ("path", reach.group(3), reach.group(2))
                source = self.where(reach.group(1), item.device_id)
            else:
                key = ("item", item.evidence_id)
                source = None
            if key not in groups:
                order.append(key)
                groups[key] = ([], [])
            if source and source not in groups[key][0]:
                groups[key][0].append(source)
            groups[key][1].append(item.evidence_id)
        by_id = {item.evidence_id: item for item in items}
        office_names = [self.site(s) for s in offices or [] if s not in ("CORE", "DC1")]
        out: list[tuple[str, list[str]]] = []
        seen: dict[str, int] = {}
        for key in order:
            sources, ids = groups[key]
            if key[0] == "item":
                text = self.clause(by_id[key[1]], with_ids)
                if text in seen:
                    out[seen[text]][1].extend(ids)
                else:
                    seen[text] = len(out)
                    out.append((text, ids))
                continue
            _, status, target = key
            destination = self.device(target, with_ids) if target in self.index.devices else target
            everyone = len(sources) >= 2 and office_names and set(sources) == set(office_names)
            if everyone:
                origin = "both offices" if len(sources) == 2 else f"all {len(sources) if len(sources) > 3 else 'three'} offices"
            else:
                origin = join(sources)
            if status == "reachable":
                text = (f"the paths from {origin} to {destination} all work" if len(sources) > 1
                        else f"traffic from {origin} gets through to {destination}")
            else:
                text = f"traffic from {origin} can't reach {destination}"
            out.append((text, ids))
        return out

    def meaning(self, item: EvidenceItem, diagnosis: Diagnosis | None) -> str:
        """Why one piece of evidence matters for the current diagnosis, in a sentence."""
        if diagnosis is not None:
            fault = diagnosis.fault
            if item.evidence_id in fault.supporting_evidence_ids:
                note = " It was inferred from other data, so it's weaker than a direct measurement." \
                    if item.evidence_type == EvidenceType.INFERRED_FINDING else ""
                return "It's one of the main reasons for the diagnosis." + note
            if item.evidence_id in fault.contradictory_evidence_ids:
                return "It doesn't fit the diagnosis, which is part of why confidence isn't higher."
            for alternative in diagnosis.alternatives:
                if item.evidence_id in alternative.supporting_evidence_ids:
                    return f"It fits the other possibility, {FAULT_PLAIN.get(alternative.fault_domain.value, 'another cause')}, better."
        if item.code in HEALTHY:
            return HEALTHY_MEANING[item.code]
        if diagnosis is None:
            return "It came from a targeted check, not a full diagnosis, so it isn't tied to a cause."
        return "The diagnosis didn't tie it to the problem."

    # ---------- diagnoses ----------

    def cause(self, root_cause: str, with_ids: bool = False) -> str:
        """The root-cause statement as a clause: "LNK-WAN-NYC (...) is degraded: loss" becomes "the New York WAN link is degraded"."""
        return lower_first(self.words(root_cause.split(": ")[0], with_ids))

    def cause_detail(self, root_cause: str, with_ids: bool = False) -> str | None:
        tail = root_cause.split(": ", 1)[1] if ": " in root_cause else None
        return sentence(self.words(tail, with_ids)) if tail else None

    def verdict(self, diagnosis: Diagnosis, confirmed: bool, with_ids: bool = False, confidence: str | None = None) -> str:
        """Where the diagnosis stands, worded to match its confidence. A hypothesis never reads as a confirmed finding."""
        level = (confidence or diagnosis.confidence.level.value).replace(" ", "_")
        if diagnosis.fault.fault_domain.value == "unknown" or level == "insufficient_evidence":
            return "I haven't found the cause yet."
        cause = self.cause(diagnosis.fault.root_cause, with_ids)
        if confirmed:
            return f"{capital(cause)}, and someone on the team has confirmed it."
        if level in ("high", "very_high"):
            return f"It's most likely that {cause}. Nobody has confirmed it yet."
        if level == "medium":
            return f"It looks like {cause}, but that isn't confirmed."
        return f"My best guess is that {cause}, but the evidence is thin."

    # ---------- reports ----------

    def security_mentions(self, title: str, description: str, symptoms: list[str]) -> list[str]:
        """Security activity the report mentions. These are reports, not findings, and replies must never drop them."""
        found = []
        for symptom in symptoms:
            if SECURITY.search(symptom):
                phrase = lower_first(SITE_CODE.sub(lambda m: SITE[m.group(1)], symptom.strip().rstrip(".")))
                plural = re.match(r"(?:failed|multiple|many|several|repeated|\d)", phrase, re.I) or phrase.split()[-1].endswith("s")
                found.append(phrase if plural else f"the {phrase}")
        if not found:
            text = f"{title}. {description}"
            found = [label for pattern, label in SECURITY_LABELS if pattern.search(text)]
            if "a port sweep" in found or "a scan" in found:
                found = [label for label in found if label != "a possible attack"]
        return list(dict.fromkeys(found))[:3]
