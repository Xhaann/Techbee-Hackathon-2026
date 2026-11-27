"""Recognises requests for the Phase 3 protocol and security checks.

The vocabulary is deliberately distinct from the Phase 2 targeted checks: "check BGP on NYC-RTR-01" stays an adjacency
check, while "any BGP route anomalies?" or "is there a spanning-tree loop?" asks for a protocol engine. Definitions
("what is ARP spoofing?") stay knowledge questions. Requests to actively scan a network are recognised so they can be
declined: the assistant only reads telemetry that was already collected.
"""
import re

ENGINE_TERMS: list[tuple[str, re.Pattern[str]]] = [(e, re.compile(p, re.IGNORECASE)) for e, p in [
    ("bgp", r"\bbgp (?:route|routes|leaks?|hijack\w*|anomal\w*|origin|prefix\w*|flap\w*|withdraw\w*|updates?)\b|\broute leak\w*|\bhijack\w*|"
            r"\bprefix origin|\borigin as\b"),
    ("ospf", r"\blsdb\b|\blink[- ]state (?:database|db)\b|\bospf (?:database|lsdb|lsas?)\b|\brouter[- ]ids?\b|\blsa churn\b"),
    ("stp", r"\bspanning[- ]tree\b|\bstp\b|\blayer[- ]?2 loop|\bswitching loop|\bloops?\b|\bbroadcast storm|\btopology changes?\b"),
    ("arp", r"\barp\b|\bspoof\w*|\bduplicate (?:ip|address)\w*|\bip conflict|\baddress conflict|\bgateway impersonat\w*|\bman[- ]in[- ]the[- ]middle|\bmitm\b"),
    ("vlan", r"\btrunks?\b|\bnative vlan|\ballowed vlans?|\bvlan mismatch|\bpruned vlan"),
    ("nat", r"\bnat\b|\bpat pool|\baddress translation|\btranslations?\b|\bnat pool"),
    ("ipsec", r"\bipsec\b|\bvpns?\b|\bike\b|\btunnels?\b"),
    ("tcp", r"\bretransmi\w*|\btcp\b|\bzero[- ]window|\bhandshakes?\b"),
    ("mtu", r"\bmtu\b|\bfragment\w*|\bblack ?hole|\bmss\b"),
    ("qos", r"\bqos\b|\bdscp\b|\bpriority queue|\bvoice quality|\bre-?mark\w*|\bclass of service\b"),
    ("ipv6", r"\bipv6\b|\bospfv3\b|\bdual[- ]stack|\brouter advertisements?\b|\brogue ra\b"),
    ("wireless", r"\bwi-?fi\b|\bwireless\b|\binterference\b|\brogue (?:ap|access point)s?\b|\baccess points?\b|\bssids?\b|\bradio\b"),
    ("multicast", r"\bmulticast\b|\bpim\b|\brendezvous point\b|\bigmp\b|\bmroutes?\b|\bvideo stream\b"),
    ("tls", r"\bcertificates?\b|\bcerts?\b|\btls\b|\bssl\b|\bhttps errors?\b"),
    ("threats", r"\bthreats?\b|\battacks?\b|\bcompromis\w*|\bmalicious\b|\bbreach\w*|\bintrusions?\b|\bhacked\b|\bmalware\b"),
    ("traffic", r"\bsuspicious (?:traffic|activity|connections?)|\bbeacon\w*|\bexfiltrat\w*|\bdns tunnel\w*|\bport (?:scan|sweep)s?\b|\bc2\b|"
                r"\bcommand[- ]and[- ]control\b"),
    ("lateral", r"\blateral\b|\bcredential spray\w*|\bpassword spray\w*|\badmin shares?\b|\bpass[- ]the[- ]hash\b"),
]]
CHECK_CUE = re.compile(r"\b(?:check|checks|look (?:at|into|for)|analy[sz]e|analysis|inspect|investigate|review|run|any|is there|are there|"
                       r"see if|find|detect|verify|diagnose|could (?:it|this) be|is it|what about|anything (?:wrong|odd|suspicious)|"
                       r"problems? with|issues? with|signs? of)\b", re.IGNORECASE)
ALL_PROTOCOLS = re.compile(r"\b(?:all|every|each) (?:the )?protocols?\b|\bprotocol (?:checks?|analysis|sweep|review|engines?)\b|"
                           r"\ball (?:17|seventeen) (?:checks|engines)\b", re.IGNORECASE)
SECURITY_SWEEP = re.compile(r"\bsecurity (?:checks?|review|analysis|sweep|scan)\b|\bthreat (?:hunt|check|review)\b", re.IGNORECASE)
SCAN_REQUEST = re.compile(r"\b(?:scan|nmap|probe|ping[- ]sweep|port[- ]scan|sweep)\b\s+(?:the |our |this |that |a |all |every )?"
                          r"(?:network|subnet|hosts?|range|site|lan|vlan|devices?|machines?|\d{1,3}\.\d)", re.IGNORECASE)
DEFINITION_ONLY = re.compile(r"^(?:what(?:'s| is| are| does)|define|explain what|tell me (?:what|about))\b", re.IGNORECASE)


def scan_requested(body: str) -> bool:
    return bool(SCAN_REQUEST.search(body))


def protocol_request(body: str) -> list[str] | None:
    """The engines a message asks for, ["all"] for a full sweep, or None when it is not a protocol request."""
    if ALL_PROTOCOLS.search(body):
        return ["all"]
    if SECURITY_SWEEP.search(body):
        return ["traffic", "lateral", "arp", "tls", "threats"]
    engines = [engine for engine, pattern in ENGINE_TERMS if pattern.search(body)]
    if not engines:
        return None
    if DEFINITION_ONLY.match(body) and not re.search(r"\b(?:here|now|today|at \w+|in (?:new york|singapore|bengaluru|\w{3}))\b", body, re.I):
        return None
    if not CHECK_CUE.search(body) and not body.rstrip().endswith("?"):
        return None
    if "threats" in engines:
        engines = [e for e in engines if e != "threats"] + ["traffic", "lateral", "threats"]
    return list(dict.fromkeys(engines))[:6]
