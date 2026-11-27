"""Short, general definitions of common networking terms, used to answer concept questions without a model.

These are textbook descriptions, not evidence about any incident; replies say so.
"""
import re

CONCEPTS: list[tuple[str, re.Pattern[str], str]] = [
    ("OSPF", re.compile(r"\bospf\b", re.IGNORECASE),
     "OSPF (Open Shortest Path First) is a link-state routing protocol used inside one organisation's network. Routers in an "
     "area flood link-state advertisements, build the same map of links and compute shortest paths from it, so they converge "
     "quickly after a change. Neighbours must agree on area, timers, authentication and MTU to reach the FULL state."),
    ("BGP", re.compile(r"\bbgp\b", re.IGNORECASE),
     "BGP (Border Gateway Protocol) is a path-vector protocol that exchanges reachability between autonomous systems over TCP "
     "port 179. Each route carries attributes such as the AS path and local preference, and policy decides which path wins. "
     "It runs between organisations and providers and across large enterprise WANs."),
    ("DNS", re.compile(r"\bdns\b|\bname resolution\b", re.IGNORECASE),
     "DNS translates names such as erp.corp.example.com into IP addresses. NXDOMAIN means the name does not exist, SERVFAIL "
     "means the server could not produce an answer (for example a zone that failed to load), and a timeout means no answer "
     "came back at all, which often points at the network path rather than the server."),
    ("DHCP", re.compile(r"\bdhcp\b", re.IGNORECASE),
     "DHCP hands out IP addresses, gateways and DNS servers from address pools. On routed networks a relay (ip helper-address) "
     "on each client VLAN's gateway forwards requests to the DHCP server; an exhausted pool or a missing relay leaves clients "
     "without a usable address."),
    ("VLAN", re.compile(r"\bvlans?\b", re.IGNORECASE),
     "A VLAN splits one switched network into separate layer-2 broadcast domains. Trunk links carry several VLANs with 802.1Q "
     "tags; a VLAN missing from a trunk's allowed list cuts its hosts off from their gateway."),
    ("802.1X", re.compile(r"\b802\.1x\b|\bdot1x\b|\bradius\b", re.IGNORECASE),
     "802.1X is port-based access control: the switch relays a client's credentials to a RADIUS server and opens the port only "
     "after the server accepts them. An unreachable RADIUS server or a shared-secret mismatch leaves ports unauthorised."),
    ("MTU", re.compile(r"\bmtu\b|\bfragment\w*\b", re.IGNORECASE),
     "The MTU is the largest packet an interface sends without fragmenting. Mismatched MTUs can stall OSPF neighbours in "
     "EXSTART/EXCHANGE and create black holes where small packets pass but large ones are dropped."),
    ("NAT", re.compile(r"\bnat\b", re.IGNORECASE),
     "NAT rewrites addresses, usually private to public, as traffic crosses a boundary and keeps a translation table so "
     "replies find their way back."),
    ("ACL", re.compile(r"\bacls?\b|\bfirewall rules?\b", re.IGNORECASE),
     "An ACL or firewall rule permits or denies traffic by source, destination, protocol and port. Rules are evaluated in "
     "order and the first match wins, so a new rule placed above an older permit can silently block traffic."),
    ("Latency", re.compile(r"\blatency\b", re.IGNORECASE),
     "Latency is the time a packet takes to cross the path. It rises with distance, queueing on congested links and "
     "retransmissions on lossy ones."),
    ("Jitter", re.compile(r"\bjitter\b", re.IGNORECASE),
     "Jitter is the variation in latency from packet to packet. Real-time traffic such as voice suffers first, because "
     "packets that arrive too late are discarded."),
    ("Packet loss", re.compile(r"\bpacket loss\b", re.IGNORECASE),
     "Packet loss is the share of packets that never arrive. Loss together with rising interface errors usually points at a "
     "physical or circuit fault; loss with high utilisation and no errors points at congestion."),
    ("CRC errors", re.compile(r"\bcrcs?\b", re.IGNORECASE),
     "CRC errors are frames that arrive corrupted and fail the frame checksum. Rising CRC counts point at the physical layer: "
     "optics, cabling or a degraded circuit, rather than congestion."),
    ("STP", re.compile(r"\bstp\b|\bspanning[- ]tree\b", re.IGNORECASE),
     "STP (Spanning Tree Protocol) blocks redundant layer-2 paths so switched networks cannot loop; a loop or repeated "
     "topology changes cause flooding and outages."),
    ("ARP", re.compile(r"\barp\b", re.IGNORECASE),
     "ARP maps an IPv4 address to a MAC address on the local network; stale or conflicting entries send traffic to the "
     "wrong host."),
    ("WAN", re.compile(r"\bwan\b", re.IGNORECASE),
     "A WAN links sites over distance, usually through carrier circuits. When a site's WAN circuit fails, its local network "
     "keeps working but everything beyond the site becomes unreachable."),
    ("Subnet", re.compile(r"\bsubnets?\b|\bsubnetting\b", re.IGNORECASE),
     "A subnet is a block of addresses that share a prefix, such as 10.20.0.0/24. Hosts in the same subnet talk directly; "
     "traffic to anything else goes through the gateway."),
]
COMPARISONS: dict[frozenset[str], str] = {
    frozenset({"OSPF", "BGP"}): ("In short: OSPF finds the best path inside your own network from a shared map of links, while "
                                 "BGP chooses between paths across organisational boundaries by policy. OSPF neighbours form "
                                 "automatically on shared links; BGP sessions are configured peer by peer over TCP."),
    frozenset({"Latency", "Jitter"}): "Latency is how long packets take; jitter is how much that time varies.",
}
QUESTION = re.compile(r"^(?:what(?:'s| is| are| does)|define|explain|tell me about|how (?:does|do)|why (?:does|do|would)|"
                      r"difference between|what'?s the difference)\b|\bdifference between\b|\bvs\.?\b|\bversus\b", re.IGNORECASE)


def explain_concepts(text: str, limit: int = 3) -> list[tuple[str, str]]:
    """Definitions for the terms a concept question names, in the order of CONCEPTS; empty when it names none."""
    if not QUESTION.search(text):
        return []
    found = [(name, definition) for name, pattern, definition in CONCEPTS if pattern.search(text)]
    return found[:limit]


def comparison(names: list[str]) -> str | None:
    return COMPARISONS.get(frozenset(names)) if len(names) == 2 else None
