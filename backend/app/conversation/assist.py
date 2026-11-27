"""Operator assistance built from verified facts only: customer emails and updates, step-by-step troubleshooting,
read-only command lists, interpretation of pasted command output, and help when a step fails.

Nothing here runs a tool or sends anything. Drafts are marked "not sent" and use [placeholders] for anything that is
not known (customer name, next update time, ETA); validators reject drafts that state an unconfirmed root cause, a
resolution that has not happened, an ETA nobody gave, or internal identifiers in customer-facing text.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from app.advanced.layers import layer_of
from app.advanced.schema import Layer
from app.protocols import interpret as protocol_output
from app.engine.safety import injection_flags, is_read_only_command
from app.engine.schema import EvidenceItem, FaultDomain
from app.reasoning.commands import Command, commands_for, facts as topo_facts

SERVICE_TEXT = {"application": "business applications such as ERP", "internet": "internet access", "dns": "name resolution",
                "dhcp": "network address assignment", "authentication": "network sign-in", "email": "email"}
SITE_NAME = {"NYC": "New York", "SIN": "Singapore", "BLR": "Bengaluru", "CORE": "London core", "DC1": "Slough data centre"}
Audience = Literal["customer", "internal"]
Tone = Literal["friendly", "formal"]


# ---------------------------------------------------------------- customer communication

@dataclass
class Facts:
    """The only facts a draft may use, each with the place it came from."""
    incident_id: str | None
    title: str | None
    sites: list[str]
    services: list[str]
    symptoms: list[str]
    status: str | None
    severity: str | None
    priority: str | None
    reported_at: datetime | None
    root_cause: str | None
    root_cause_confirmed: bool
    fault_label: str | None
    diagnosis_confidence: str | None
    cause_supported: bool = False  # False when the diagnosis found no cause: drafts must not claim a likely cause then
    workaround: str | None = None
    eta: str | None = None
    next_update: str | None = None


def stage_of(f: Facts) -> Literal["investigating", "identified", "monitoring", "resolved"]:
    if f.status in ("resolved", "closed"):
        return "resolved"
    if f.status == "monitoring":
        return "monitoring"
    if f.root_cause_confirmed:
        return "identified"
    return "investigating"


def where(sites: list[str]) -> str:
    names = [SITE_NAME.get(s, s) for s in sites]
    if not names:
        return "[affected location]"
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def impact(f: Facts) -> str:
    services = [SERVICE_TEXT.get(s, s) for s in f.services if s in SERVICE_TEXT]
    if services:
        return ", ".join(services[:3])
    if f.symptoms:
        first = f.symptoms[0]
        # Lower-case the opening word mid-sentence, but never an acronym or identifier (IDS, ERP, VPN, NYC-RTR-01).
        return first[0].lower() + first[1:] if len(first) > 1 and first[1].islower() else first
    return "some network services"


def short_email(f: Facts, audience: Audience, tone: Tone) -> dict[str, Any]:
    """The same facts in three lines, for "make it shorter"."""
    stage = stage_of(f)
    place = where(f.sites)
    since = f" since {f.reported_at:%H:%M} UTC" if f.reported_at else ""
    state = {"resolved": "It's resolved now.", "monitoring": "A fix is in place and we're watching it.",
             "identified": "We know the cause and are working on a fix."}.get(
        stage, "We think we know the cause and are confirming it." if f.root_cause and f.cause_supported else "We're investigating.")
    follow = "" if stage == "resolved" else " We'll update you by [time]."
    subject_state = {"investigating": "Investigating", "identified": "Cause identified", "monitoring": "Monitoring", "resolved": "Resolved"}[stage]
    body = "\n".join(["Hello [customer name]," if tone == "formal" else "Hi [customer name],", "",
                      f"Users at {place} are having trouble with {impact(f)}{since}. {state}{follow}", "",
                      "Kind regards," if tone == "formal" else "Thanks,", "[your name]"])
    subject = f"[{subject_state}] Network issue at {place}" + (f" ({f.incident_id})" if audience == "internal" and f.incident_id else "")
    return {"kind": "email", "audience": audience, "tone": tone, "stage": stage, "subject": subject, "body": body, "length": "short",
            "placeholders": sorted(set(re.findall(r"\[[a-z ]+\]", body + subject))),
            "facts_used": [{"statement": "location", "source": f"incident sites: {', '.join(f.sites) or 'unknown'}"},
                           {"statement": "impact", "source": "incident symptoms and affected services"}],
            "status": "draft_not_sent", "notice": "Draft only. Nothing has been sent; review it and send it yourself."}


def draft_email(f: Facts, audience: Audience = "customer", tone: Tone = "friendly", short: bool = False) -> dict[str, Any]:
    if short:
        return short_email(f, audience, tone)
    stage = stage_of(f)
    place = where(f.sites)
    greeting = "Hello [customer name]," if tone == "formal" else "Hi [customer name],"
    sign = "Kind regards," if tone == "formal" else "Thanks,"
    used = [("location", f"incident sites: {', '.join(f.sites) or 'unknown'}"), ("impact", "incident symptoms and affected services")]
    lines = [greeting, ""]
    subject_state = {"investigating": "Investigating", "identified": "Cause identified", "monitoring": "Fix in place, monitoring",
                     "resolved": "Resolved"}[stage]
    subject = f"[{subject_state}] Network issue affecting {place}" + (f" ({f.incident_id})" if audience == "internal" and f.incident_id else "")
    lines.append(f"We're aware of an issue affecting {impact(f)} for users at {place}"
                 + (f", first reported at {f.reported_at:%H:%M} UTC on {f.reported_at:%d %b}" if f.reported_at else "") + ".")
    if f.reported_at:
        used.append(("time", "incident reported_at"))
    if stage == "resolved":
        lines.append("The issue has been resolved and services are working normally again.")
        used.append(("status", f"incident status {f.status}"))
    elif stage == "monitoring":
        lines.append("A fix is in place and our engineers are monitoring to make sure services stay stable.")
        used.append(("status", "incident status monitoring"))
    elif stage == "identified" and f.root_cause_confirmed:
        cause = f.root_cause if audience == "internal" else f"a fault in our {f.fault_label or 'network'}"
        lines.append(f"Our engineers have confirmed the cause ({cause}) and are working on the fix.")
        used.append(("cause", "human-confirmed fault domain"))
    elif f.root_cause and f.cause_supported:
        lines.append("Our engineers have identified the likely cause and are confirming it before making any changes.")
        used.append(("cause", "diagnosis hypothesis (not stated: awaiting human confirmation)"))
    else:
        lines.append("Our network team is investigating and will share more as soon as we know it.")
    if audience == "internal" and not f.cause_supported:
        lines.append("No cause has been identified yet.")
    elif audience == "internal" and f.root_cause and not f.root_cause_confirmed:
        lines.append(f"Working hypothesis (not yet confirmed): {f.root_cause}" + (f" ({f.diagnosis_confidence} confidence)." if f.diagnosis_confidence else "."))
        used.append(("hypothesis", "current diagnosis, labelled unconfirmed"))
    if f.workaround:
        lines.append(f"In the meantime: {f.workaround}")
    if stage != "resolved":
        lines.append(f"Estimated restoration: {f.eta}." if f.eta else "We don't have a confirmed restoration time yet; we'll include one as soon as we do.")
        lines.append(f"Next update: {f.next_update}." if f.next_update else "We'll send the next update by [time].")
    lines += ["", "We're sorry for the disruption." if stage != "resolved" else "Thank you for your patience.", "", sign, "[your name]",
              "Network Operations"]
    body = "\n".join(lines)
    placeholders = sorted(set(re.findall(r"\[[a-z ]+\]", body + subject)))
    return {"kind": "email", "audience": audience, "tone": tone, "stage": stage, "subject": subject, "body": body,
            "placeholders": placeholders, "facts_used": [{"statement": k, "source": v} for k, v in used],
            "status": "draft_not_sent", "notice": "Draft only. Nothing has been sent; review it and send it yourself."}


def draft_update(f: Facts, audience: Audience = "customer") -> dict[str, Any]:
    stage = stage_of(f)
    place = where(f.sites)
    heading = {"investigating": "Investigating", "identified": "Identified", "monitoring": "Monitoring", "resolved": "Resolved"}[stage]
    current = {"investigating": "A likely cause has been identified and is being confirmed." if f.root_cause and f.cause_supported
               else "Our network team is investigating the cause.",
               "identified": "The cause has been confirmed and a fix is being prepared." if f.root_cause_confirmed
               else "A likely cause has been identified and is being confirmed.",
               "monitoring": "A fix is in place and we are monitoring.", "resolved": "The issue is resolved."}[stage]
    lines = [f"**Status: {heading}**", f"Affected: {impact(f)} at {place}.", f"Current status: {current}"]
    if audience == "internal":
        if f.incident_id:
            lines.insert(1, f"Incident: {f.incident_id}" + (f" ({(f.severity or '').capitalize()} severity, {(f.priority or '').upper()})" if f.severity else ""))
        if f.root_cause and f.cause_supported:
            lines.append(f"Hypothesis: {f.root_cause} ({'confirmed' if f.root_cause_confirmed else 'not yet confirmed'}).")
        elif not f.cause_supported:
            lines.append("Hypothesis: none yet; the diagnosis hasn't found a cause.")
    if stage != "resolved":
        lines.append(f"Restoration estimate: {f.eta}." if f.eta else "Restoration estimate: not yet available.")
        lines.append(f"Next update: {f.next_update}." if f.next_update else "Next update: [time].")
    text = "\n".join(lines)
    return {"kind": "update", "audience": audience, "stage": stage, "title": f"Incident update: {heading}", "body": text,
            "placeholders": sorted(set(re.findall(r"\[[a-z ]+\]", text))), "status": "draft_not_sent",
            "notice": "Draft only. Nothing has been posted or sent."}


ETA = re.compile(r"\b(?:within|in (?:about |around |the next )?|by|until|before|expected (?:at|by))\s+(?:\d+\s*(?:min(?:ute)?s?|hours?|hrs?|h)\b|"
                 r"\d{1,2}(?::\d{2})?\s*(?:am|pm|utc)?\b|(?:tonight|today|tomorrow|end of day|eod)\b)", re.IGNORECASE)
INTERNAL_ID = re.compile(r"\b(?:[A-Z]{2,5}-(?:RTR|SW|FW|SRV)-[A-Z0-9-]+|LNK-[A-Z0-9-]+|FWR-[A-Z0-9-]+|E\d{1,4}|INV-[0-9a-f]+|\d{1,3}(?:\.\d{1,3}){3})\b")
RESOLVED = re.compile(r"\b(?:resolved|fixed|restored|working normally)\b", re.IGNORECASE)


def draft_issues(draft: dict[str, Any], f: Facts) -> list[str]:
    """What would make the draft untrue: invented ETA, unconfirmed cause stated as fact, premature resolution, or
    internal identifiers in a customer message."""
    text = draft.get("subject", "") + "\n" + draft["body"]
    issues = []
    for match in ETA.finditer(text):
        if not (f.eta and f.eta in text) and not (f.next_update and f.next_update in text) and "[time]" not in match.group(0):
            issues.append(f"states a time nobody provided: '{match.group(0)}'")
    if draft.get("audience") == "customer" and (ids := INTERNAL_ID.findall(text)):
        issues.append(f"exposes internal identifiers to the customer: {', '.join(sorted(set(ids))[:4])}")
    if f.root_cause and not f.root_cause_confirmed and f.root_cause in text and "not yet confirmed" not in text:
        issues.append("states an unconfirmed root cause as fact")
    if not f.cause_supported and re.search(r"identified the likely cause|likely cause has been identified|know the cause", text, re.I):
        issues.append("claims a likely cause the diagnosis does not support")
    if stage_of(f) != "resolved" and RESOLVED.search(text) and "resolved" not in (f.status or ""):
        bad = [m.group(0) for m in RESOLVED.finditer(text) if not re.search(r"(?:will|once|until|not|before)\s+\w*\s*" + m.group(0), text)]
        if bad:
            issues.append(f"claims the issue is {bad[0]} while the incident is {f.status}")
    return issues


# ---------------------------------------------------------------- troubleshooting guidance

def steps_from(commands: list[Command], limit: int = 6) -> list[dict[str, Any]]:
    steps = []
    for number, command in enumerate(commands[:limit], start=1):
        steps.append({"number": number, "device_id": command.device_id, "platform": command.platform, "title": command.purpose,
                      "command": command.command, "expected_healthy": command.healthy, "expected_fault": command.faulty,
                      "if_fault": command.if_faulty, "if_healthy": command.if_healthy, "domain": command.domain.value,
                      "tool_equivalent": {"tool": command.tool_equivalent[0], "arguments": command.tool_equivalent[1]}
                      if command.tool_equivalent else None})
    return steps


# What a guide may rest on. A step is offered only when a fault area is justified by the diagnosis, by evidence that conflicts
# with it, by evidence that looks wrong, or by a specific user report. Affected connectivity alone never implies the WAN.
LAYER_DOMAINS = {
    Layer.PHYSICAL_INTERFACE: {FaultDomain.INTERFACE_LINK, FaultDomain.WAN_ISP},
    Layer.WAN_CONNECTIVITY: {FaultDomain.WAN_ISP, FaultDomain.INTERFACE_LINK},
    Layer.ROUTING: {FaultDomain.ROUTING},
    Layer.SWITCHING_VLAN: {FaultDomain.SWITCHING, FaultDomain.VLAN_AUTHENTICATION},
    Layer.FIREWALL_SECURITY: {FaultDomain.FIREWALL},
    Layer.DHCP: {FaultDomain.DHCP},
    Layer.DNS: {FaultDomain.DNS},
    Layer.SHARED_INFRASTRUCTURE: {FaultDomain.NETWORK_DEVICE_FAILURE, FaultDomain.SHARED_INFRASTRUCTURE},
}
# Commands that test a fault area. A WAN fault takes the routing session down with it, so its checks include the session.
COVERS = {
    FaultDomain.WAN_ISP: {FaultDomain.WAN_ISP, FaultDomain.INTERFACE_LINK, FaultDomain.ROUTING},
    FaultDomain.INTERFACE_LINK: {FaultDomain.INTERFACE_LINK, FaultDomain.WAN_ISP, FaultDomain.NETWORK_DEVICE_FAILURE},
    FaultDomain.SWITCHING: {FaultDomain.SWITCHING, FaultDomain.VLAN_AUTHENTICATION},
    FaultDomain.VLAN_AUTHENTICATION: {FaultDomain.VLAN_AUTHENTICATION, FaultDomain.SWITCHING},
    FaultDomain.SHARED_INFRASTRUCTURE: {FaultDomain.SHARED_INFRASTRUCTURE, FaultDomain.NETWORK_DEVICE_FAILURE},
    FaultDomain.NETWORK_DEVICE_FAILURE: {FaultDomain.NETWORK_DEVICE_FAILURE, FaultDomain.SHARED_INFRASTRUCTURE},
}
HEALTHY_CODES = {"PATH_REACHABLE", "DEVICE_AVAILABLE", "NO_PACKET_LOSS_MEASURED"}
STRENGTH = {"diagnosis": 0, "conflict": 1, "evidence": 2, "report": 3}
# Within one strength, check bottom-up: the link before the routing session, the session before policy and services.
BOTTOM_UP = [FaultDomain.INTERFACE_LINK, FaultDomain.WAN_ISP, FaultDomain.NETWORK_DEVICE_FAILURE, FaultDomain.SHARED_INFRASTRUCTURE,
             FaultDomain.SWITCHING, FaultDomain.VLAN_AUTHENTICATION, FaultDomain.ROUTING, FaultDomain.FIREWALL, FaultDomain.DHCP,
             FaultDomain.DNS]
TELEMETRY_CODES = {"TELEMETRY_GAP", "DEVICE_TELEMETRY_MISSING"}
# Specific symptoms only. "Slow" or "freezes" on their own say nothing about where to look, so they justify no step.
SYMPTOM_DOMAINS = [
    (re.compile(r"\bdns\b|name resolution|\bresolv|nxdomain|servfail", re.I), {FaultDomain.DNS}),
    (re.compile(r"\bdhcp\b|no ip address|(?:has|have|get|gets) no ip\b|configuring ip|169\.254|\bapipa\b|\bleases?\b|address pool|"
                r"pool warning", re.I), {FaultDomain.DHCP}),
    (re.compile(r"802\.1x|\bdot1x\b|\bradius\b|network sign-?in|port (?:is )?unauthori[sz]ed", re.I), {FaultDomain.VLAN_AUTHENTICATION}),
    (re.compile(r"\bfirewall|\bblocked\b|\bdenied\b|\bdeny\b|\bacl\b|security polic", re.I), {FaultDomain.FIREWALL}),
    (re.compile(r"\b(?:branch|edge|site|wan) router\b.{0,20}\b(?:unreachable|down|offline|not responding)\b", re.I),
     {FaultDomain.WAN_ISP}),
    (re.compile(r"\bbgp\b|\bospf\b|\broutes?\b|\brouting\b|unreachable|can'?t reach|cannot reach|unable to reach|can'?t get to|"
                r"lost (?:all )?connectivity|no connectivity|\boffline\b|\boutage\b|\bdown\b", re.I), {FaultDomain.ROUTING}),
    (re.compile(r"packet loss|\bloss\b|\blatency\b|\bjitter\b|\bchoppy\b|\bdrop(?:s|ping|ped)?\b|\bflap|cut(?:s|ting)? out|\bcircuit\b|"
                r"\bcarrier\b|\bisp\b|\bwan\b", re.I), {FaultDomain.WAN_ISP}),
]
# A clause about a specific technology points at that technology, not at the WAN or routing in general.
TECHNOLOGY = re.compile(r"wi-?fi|wireless|\bvpn\b|tunnel|\bvideo\b|multicast|ipv6|certificat|\btls\b|\bssl\b|\bdns\b|\bdhcp\b|"
                        r"ip address|\bradar\b|\bap\b|\bids\b|port[- ]?sweep|log-?ins?\b|\bscan", re.I)
# One machine misbehaving says nothing about the site's circuit or routing, which would take everyone down with it.
SINGLE_HOST = re.compile(r"\b(?:one|a single|single|1)\s+(?:desktop|pc|laptop|user|machine|computer|phone|host|workstation)\b", re.I)
FINE = re.compile(r"\b(?:fine|works?|working|ok|okay|normal|unaffected|not affected)\s*\.?$", re.I)
USER_SITES = ("NYC", "SIN", "BLR")


@dataclass
class Grounds:
    """Everything a troubleshooting guide may rest on: the diagnosis and its state, evidence, and the user's report."""
    status: Literal["confirmed", "suspected", "conflicting", "unknown"] = "unknown"
    domain: FaultDomain | None = None
    report: list[str] = field(default_factory=list)  # the incident's title, description and symptoms, as clauses
    sites: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    contradicting: list[EvidenceItem] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)  # devices the diagnosis names


@dataclass
class Plan:
    commands: list[Command]
    status: str
    reasons: list[str]  # what each kind of step rests on, for the reply
    evidence_ids: list[str]
    ruled_out: dict[str, list[str]]  # site -> evidence ids showing its path works
    telemetry_gaps: list[EvidenceItem]


def weak(item: EvidenceItem) -> bool:
    """One denied flow (usually the catch-all rule) or one failed DNS query is too little to send anyone to a device."""
    if item.code == "TRAFFIC_DENIED":
        count = re.match(r"(\d+) flows? denied", item.summary)
    elif item.code.startswith("DNS_"):
        count = re.match(r"(\d+) quer(?:y|ies) ", item.summary)
    else:
        return False
    return bool(count and int(count.group(1)) < 2)


def clauses(*texts: str) -> list[str]:
    return [c.strip() for text in texts for c in re.split(r"[;.]\s+|\n", text or "") if c.strip()]


def report_domains(report: list[str], sites: list[str]) -> list[tuple[FaultDomain, str]]:
    user_sites = [s for s in sites if s in USER_SITES]
    found: list[tuple[FaultDomain, str]] = []
    for clause in report:
        if FINE.search(clause):
            continue
        technology = TECHNOLOGY.search(clause) or SINGLE_HOST.search(clause)
        for pattern, domains in SYMPTOM_DOMAINS:
            if not pattern.search(clause):
                continue
            for domain in domains:
                if domain in (FaultDomain.WAN_ISP, FaultDomain.ROUTING) and technology:
                    continue
                if domain == FaultDomain.WAN_ISP and len(user_sites) != 1:
                    continue  # a problem at several offices at once is not one branch's circuit
                found.append((domain, clause))
    return found


def plan_checks(grounds: Grounds, site_id: str | None, device_id: str | None = None, limit: int = 6) -> Plan:
    """device_id is a device the user named: its commands are what they asked for, so they are listed in full and first."""
    """Read-only commands that the diagnosis, the evidence or the user's report actually justify, most relevant first.
    Returns no commands when nothing does; the caller then says more evidence is needed instead of guessing."""
    ranked: list[tuple[FaultDomain, str]] = []  # (fault area, why), strongest first
    evidence_ids: list[str] = []
    if grounds.domain is not None and grounds.domain != FaultDomain.UNKNOWN and grounds.status != "unknown":
        ranked.append((grounds.domain, "diagnosis"))
    for item in grounds.contradicting:
        for domain in sorted(LAYER_DOMAINS.get(layer_of(item.code), set()), key=lambda d: d.value):
            ranked.append((domain, "conflict"))
        evidence_ids.append(item.evidence_id)
    odd = [item for item in grounds.evidence if item.code not in HEALTHY_CODES and layer_of(item.code) in LAYER_DOMAINS
           and not weak(item)]
    for item in odd:
        for domain in sorted(LAYER_DOMAINS[layer_of(item.code)], key=lambda d: d.value):
            ranked.append((domain, "evidence"))
        evidence_ids.append(item.evidence_id)
    ranked += [(domain, "report") for domain, _ in report_domains(grounds.report, grounds.sites)]
    order: dict[FaultDomain, tuple[int, int]] = {}
    for domain, why in ranked:
        rank = (STRENGTH[why], BOTTOM_UP.index(domain) if domain in BOTTOM_UP else len(BOTTOM_UP))
        for covered in COVERS.get(domain, {domain}):
            order[covered] = min(order.get(covered, rank), rank)
    strong = {d for d, why in ranked if why in ("diagnosis", "conflict", "evidence")}
    # A working path from a site rules out routing at that site, unless the diagnosis or the evidence says otherwise.
    ruled_out: dict[str, list[str]] = {}
    for item in grounds.evidence:
        if item.code == "PATH_REACHABLE" and item.device_id:
            site = topo_facts()["devices"][item.device_id].site_id if item.device_id in topo_facts()["devices"] else None
            if site:
                ruled_out.setdefault(site, []).append(item.evidence_id)
    devices = list(dict.fromkeys(grounds.devices + [i.device_id for i in odd + grounds.contradicting if i.device_id]))
    services = [service for service, domain in (("dns", FaultDomain.DNS), ("dhcp", FaultDomain.DHCP),
                                                ("authentication", FaultDomain.VLAN_AUTHENTICATION),
                                                ("application", FaultDomain.ROUTING), ("application", FaultDomain.FIREWALL))
                if domain in order]
    pool: list[Command] = []
    for device in devices:
        pool += commands_for(device_id=device, site_id=site_id, services=list(dict.fromkeys(services)) or None)
    if site_id:
        pool += commands_for(site_id=site_id, services=list(dict.fromkeys(services)) or None)
    devices_info = topo_facts()["devices"]
    chosen: dict[tuple[str, str], Command] = {}
    if device_id:
        for command in commands_for(device_id=device_id, site_id=site_id):
            if command.device_id == device_id:
                chosen.setdefault((command.device_id, command.command), command)
    for command in pool:
        if command.domain not in order:
            continue
        site = devices_info[command.device_id].site_id if command.device_id in devices_info else None
        if command.domain == FaultDomain.ROUTING and site in ruled_out and FaultDomain.ROUTING not in strong \
                and FaultDomain.WAN_ISP not in strong:
            continue
        chosen.setdefault((command.device_id, command.command), command)
    def place(command: Command) -> int:
        if command.device_id == device_id:
            return 0
        site = devices_info[command.device_id].site_id if command.device_id in devices_info else None
        return 1 if site == site_id or command.device_id in devices else 2
    # A device the user named comes first, then the strongest fault area; location only breaks ties within an area.
    commands = sorted(chosen.values(), key=lambda c: (place(c) != 0, order.get(c.domain, (9, 0)), place(c)))[:limit]
    reasons = list(dict.fromkeys(why for _, why in ranked))
    gaps = [item for item in grounds.evidence if item.code in TELEMETRY_CODES]
    return Plan(commands=commands, status=grounds.status, reasons=reasons, evidence_ids=list(dict.fromkeys(evidence_ids)),
                ruled_out={site: ids for site, ids in ruled_out.items() if site in USER_SITES}, telemetry_gaps=gaps)


def troubleshooting_guide(site_id: str | None, services: list[str], device_id: str | None = None,
                          domain: FaultDomain | None = None, leading_devices: list[str] | None = None,
                          grounds: Grounds | None = None) -> dict[str, Any]:
    """Numbered read-only steps: what to run where, what healthy and faulty output look like, and what to do next. With
    grounds, only justified steps are listed (see plan_checks); without, the leading hypothesis decides the order."""
    if grounds is not None:
        plan = plan_checks(grounds, site_id, device_id)
        pool = plan.commands
    else:
        plan = None
        pool = commands_for(device_id=device_id or (leading_devices[0] if leading_devices else None), site_id=site_id,
                            services=services or ["application"], domain=domain)
        if domain is not None:
            pool = [c for c in pool if c.domain == domain] + [c for c in pool if c.domain != domain]
    steps = steps_from(pool)
    focus = f"{SITE_NAME.get(site_id, site_id)}" if site_id else (device_id or "the network")
    guide = {"title": f"Read-only troubleshooting for {focus}", "site_id": site_id, "device_id": device_id,
             "domain": domain.value if domain else None, "steps": steps, "current": 0,
             "notice": "Every command is read-only. Changes, if needed, go through your change process."}
    if plan is not None:
        guide |= {"status": plan.status, "basis": plan.reasons, "evidence_ids": plan.evidence_ids,
                  "ruled_out": plan.ruled_out, "telemetry_gaps": [i.evidence_id for i in plan.telemetry_gaps]}
    return guide


def render_guide(guide: dict[str, Any], start: int = 0, count: int | None = None) -> str:
    chosen = guide["steps"][start:start + count if count else None]
    blocks = []
    for step in chosen:
        blocks.append(f"{step['number']}. **{step['title']}** on {step['device_id']}\n"
                      f"   Run: `{step['command']}`\n"
                      f"   Expect: {step['expected_healthy']}\n"
                      f"   If you see instead: {step['expected_fault']}. {step['if_fault']}\n"
                      f"   If it looks healthy: {step['if_healthy']}")
    return "\n".join(blocks)


def runnable(steps: list[dict[str, Any]], registry: set[str]) -> list[dict[str, Any]]:
    """The steps the assistant can run itself as read-only tool calls (with the user's approval)."""
    return [s for s in steps if s.get("tool_equivalent") and s["tool_equivalent"]["tool"] in registry]


# ---------------------------------------------------------------- pasted command output

ERRORS = [
    (re.compile(r"% ?Invalid input detected|% ?Unrecognized command|Unknown command|% ?Incomplete command|% ?Ambiguous command", re.I),
     "syntax", "The device didn't accept the command syntax. It may be a different platform or software version."),
    (re.compile(r"Permission denied|% ?Authorization failed|not authorized|access denied|privilege", re.I),
     "privilege", "Your account doesn't have the privilege level for that command."),
    (re.compile(r"timed out|Connection refused|No route to host|unreachable|Connection closed", re.I),
     "unreachable", "The device didn't answer, so the command never ran. That itself is a finding: the device or its management path is down."),
    (re.compile(r"command not found|No such file", re.I), "missing_tool", "That command isn't installed on this host."),
]
PARSERS: list[tuple[str, re.Pattern[str]]] = [
    ("show ip ospf neighbor", re.compile(r"Neighbor ID\s+Pri\s+State", re.I)),
    ("show ip bgp summary", re.compile(r"BGP router identifier|Neighbor\s+V\s+AS\s+MsgRcvd", re.I)),
    ("show interfaces", re.compile(r"\bis (?:up|down|administratively down), line protocol is (?:up|down)", re.I)),
    ("ping", re.compile(r"Success rate is \d+ percent|\d+ packets transmitted", re.I)),
    ("dig", re.compile(r";; ->>HEADER<<-|status: (?:NOERROR|SERVFAIL|NXDOMAIN|REFUSED)|;; connection timed out", re.I)),
    ("show ip route", re.compile(r"Routing entry for|% Network not in table|% Subnet not in table", re.I)),
    ("traceroute", re.compile(r"Tracing the route to|traceroute to", re.I)),
    ("show authentication sessions", re.compile(r"Status:\s*(?:Authorized|Unauthorized)|Method\s+status", re.I)),
    ("show log traffic", re.compile(r"\bdeny\b.*\b(?:rule|from)\b|action\s+deny", re.I)),
    ("show ip interface", re.compile(r"Helper address(?:es)? (?:is|are)", re.I)),
]


ERROR_LINE = re.compile(r"^\s*(?:%\s?\w|Permission denied|Connection (?:timed out|refused)|\S+: command not found|"
                        r"ssh: connect to host|Request timed out)", re.I | re.M)


def looks_like_output(text: str) -> bool:
    """Pasted device output rather than a sentence: a known output signature, or a device error line."""
    return any(p.search(text) for _, p in PARSERS) or bool(ERROR_LINE.search(text)) or protocol_output.recognises(text)


def interpret(text: str) -> dict[str, Any]:
    """Reads pasted output and says what it shows. The text is treated as data: nothing in it is executed or obeyed."""
    flags = injection_flags("pasted output", text)
    for pattern, kind, meaning in ERRORS:
        if pattern.search(text):
            return {"command": None, "verdict": "error", "error_kind": kind, "summary": meaning, "evidence_lines": [l for l in
                    text.splitlines() if pattern.search(l)][:3], "security_flags": flags}
    command = next((name for name, pattern in PARSERS if pattern.search(text)), None)
    if command == "ping" and re.search(r"DF bit set", text, re.I):
        command = None  # a don't-fragment ping is an MTU test: the protocol reader knows what its loss means
    if command is None and (protocol := protocol_output.read(text)) is not None:
        return protocol | {"security_flags": flags}
    lines = [l.rstrip() for l in text.splitlines() if l.strip()]
    verdict, summary, key = "unclear", "I can't tell what that output shows. Paste the whole output, including the command.", []
    if command == "show ip ospf neighbor":
        rows = [l for l in lines if re.search(r"\b(?:FULL|INIT|2WAY|EXSTART|EXCHANGE|LOADING|DOWN|ATTEMPT)\b", l)]
        bad = [l for l in rows if not re.search(r"\bFULL\b", l)]
        if not rows:
            verdict, summary = "fault", "No OSPF neighbours are listed: the adjacency hasn't formed at all (check hello/authentication settings on both ends)."
        elif bad:
            state = re.search(r"\b(INIT|2WAY|EXSTART|EXCHANGE|LOADING|DOWN|ATTEMPT)\b", bad[0]).group(1)
            hint = "an MTU mismatch between the two ends" if state in ("EXSTART", "EXCHANGE") else "hellos only seen one way (authentication, timers or a filter)"
            verdict, summary, key = "fault", f"An OSPF neighbour is stuck in {state}. That usually means {hint}.", bad[:2]
        else:
            verdict, summary, key = "healthy", f"All {len(rows)} OSPF neighbour(s) are FULL.", rows[:2]
    elif command == "show ip bgp summary":
        rows = [l for l in lines if re.match(r"^\s*\d{1,3}(?:\.\d{1,3}){3}\s+\d", l)]
        down = [l for l in rows if re.search(r"\b(?:Idle|Active|Connect|OpenSent|OpenConfirm)\b", l, re.I) or l.split()[-1] == "0"]
        if down:
            verdict, summary, key = "fault", f"BGP session to {down[0].split()[0]} is not established ({down[0].split()[-1]}): no routes are being learned over it.", down[:2]
        elif rows:
            verdict, summary, key = "healthy", f"{len(rows)} BGP session(s) established, receiving prefixes.", rows[:2]
    elif command == "show interfaces":
        state = re.search(r"(\S+) is (up|down|administratively down), line protocol is (up|down)", text, re.I)
        errors = re.search(r"(\d+) input errors, (\d+) CRC", text, re.I)
        if state and (state.group(2).lower() != "up" or state.group(3).lower() != "up"):
            verdict, summary = "fault", f"{state.group(1)} is {state.group(2)}, line protocol {state.group(3)}: the link isn't passing traffic."
        elif errors and int(errors.group(2)) > 100:
            verdict, summary = "fault", f"{state.group(1) if state else 'The interface'} is up but has {errors.group(2)} CRC errors: a physical-layer problem (optics, cable or circuit)."
        elif state:
            verdict, summary = "healthy", f"{state.group(1)} is up/up" + (f" with {errors.group(2)} CRC errors." if errors else ".")
        key = [l for l in lines if re.search(r"line protocol|input errors|CRC", l, re.I)][:3]
    elif command == "ping":
        rate = re.search(r"Success rate is (\d+) percent \((\d+)/(\d+)\)", text) or re.search(r"(\d+)% packet loss", text)
        if rate:
            ok = int(rate.group(1)) if "Success" in rate.group(0) else 100 - int(rate.group(1))
            verdict = "healthy" if ok == 100 else "fault"
            summary = ("No loss: the path is clean." if ok == 100 else "Total loss: nothing gets through." if ok == 0
                       else f"{100 - ok}% loss: the path is up but dropping packets (degradation, not an outage).")
            key = [rate.group(0)]
    elif command == "dig":
        status = re.search(r"status: (\w+)", text)
        if re.search(r"connection timed out", text, re.I):
            verdict, summary = "fault", "The DNS server didn't answer at all: it's unreachable from here or the service is down."
        elif status and status.group(1) == "NOERROR":
            verdict, summary = "healthy", "The DNS server answered normally (NOERROR)."
        elif status:
            verdict, summary = "fault", {"SERVFAIL": "SERVFAIL: the server can't answer for the zone (zone not loaded or expired).",
                                         "NXDOMAIN": "NXDOMAIN: the name doesn't exist in the zone (typo or missing record).",
                                         "REFUSED": "REFUSED: the server won't answer this client (ACL or view)."}.get(status.group(1), status.group(1))
        key = [status.group(0)] if status else []
    elif command == "show ip route":
        if re.search(r"not in table", text, re.I):
            verdict, summary = "fault", "There is no route to that destination: the routing session that should provide it is down or filtered."
        else:
            via = re.search(r"Known via \"([^\"]+)\"", text)
            verdict, summary = "healthy", f"The route exists{' (learned via ' + via.group(1) + ')' if via else ''}."
    elif command == "traceroute":
        stars = [l for l in lines if re.match(r"^\s*\d+\s+\*\s+\*\s+\*", l)]
        hops = [l for l in lines if re.match(r"^\s*\d+\s+\S", l)]
        if stars:
            last = next((l for l in reversed(hops) if "*" not in l), None)
            verdict, summary = "fault", "The trace stops" + (f" after {last.split()[1]}" if last else "") + ": that's where the path breaks."
            key = stars[:1] + ([last] if last else [])
        elif hops:
            verdict, summary = "healthy", f"The trace completes in {len(hops)} hops."
    elif command == "show authentication sessions":
        if re.search(r"Unauthorized", text, re.I):
            verdict, summary = "fault", "The port is Unauthorized: 802.1X is failing (RADIUS unreachable, shared-secret mismatch or bad credentials)."
        else:
            verdict, summary = "healthy", "The port is Authorized."
    elif command == "show log traffic":
        rules = sorted(set(re.findall(r"rule[:= ]+([\w-]+)", text, re.I)))
        verdict, summary = "fault", "The firewall is denying this traffic" + (f" (rule {', '.join(rules[:2])})." if rules else ".")
    elif command == "show ip interface":
        helpers = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", text.split("Helper", 1)[1]) if "Helper" in text else []
        if re.search(r"Helper address is not set", text, re.I) or not helpers:
            verdict, summary = "fault", "No DHCP helper is set on this interface: DHCP requests from the VLAN never reach the server."
        else:
            verdict, summary = ("healthy" if len(helpers) >= 2 else "fault"), (f"DHCP relay points at {', '.join(helpers)}."
                                + ("" if len(helpers) >= 2 else " Only one helper: the design has two."))
    return {"command": command, "verdict": verdict, "summary": summary, "evidence_lines": key[:3], "security_flags": flags}


ALTERNATIVES = {**protocol_output.ALTERNATIVES, "show ip ospf neighbor": "show ip ospf interface brief", "show ip bgp summary": "show bgp ipv4 unicast summary",
                "show interfaces": "show ip interface brief", "show authentication sessions": "show dot1x all",
                "show log traffic": "show session all", "show ip interface": "show ip interface brief"}


def failure_help(text: str, step: dict[str, Any] | None) -> dict[str, Any]:
    """What to try when a step fails: the likely reason and a read-only alternative or the next step."""
    found = interpret(text) if any(p.search(text) for p, _, _ in ERRORS) else None
    kind = found["error_kind"] if found else "unknown"
    reason = found["summary"] if found else "The step didn't give a usable result."
    alternative = None
    if step:
        base = next((k for k in ALTERNATIVES if step["command"].startswith(k)), None)
        candidate = ALTERNATIVES.get(base) if base else None
        if candidate and is_read_only_command(candidate):
            alternative = {"device_id": step["device_id"], "command": candidate}
    advice = {"syntax": "If the alternative fails too, tell me the software version and I'll adjust.",
              "privilege": "Ask for read-only (privilege 1/operator) access, or have someone with access run it.",
              "unreachable": "Treat the device as unreachable: check its upstream link and power, or skip to the next step.",
              "missing_tool": "Run it on a host that has the tool, or use the device's own show command.",
              "unknown": "Paste the output and I'll read it, or move on to the next step."}[kind]
    return {"kind": kind, "reason": reason, "advice": advice, "alternative": alternative,
            "next_step": step["number"] + 1 if step else None}


def placeholders_only(text: str) -> bool:
    return bool(re.search(r"\[[a-z ]+\]", text))


def site_from_ip(address: str) -> str | None:
    for site, (subnet, _, _) in topo_facts()["users"].items():
        if address.startswith(subnet.rsplit(".", 2)[0]):
            return site
    return None
