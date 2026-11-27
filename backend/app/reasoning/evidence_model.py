"""What each kind of evidence says about each fault domain: likelihoods, layers and causal mechanisms.

The numbers are log-likelihood ratios (natural log) for "this evidence would appear if the fault were in domain D"
against "if it were elsewhere". They are hand-set from how each finding is produced by the tools, then checked against
the benchmark scenarios (verification/reasoning). They are a model of the synthetic network, not universal constants.
"""
import re
from dataclasses import dataclass

from app.engine.schema import EvidenceItem, EvidenceType, FaultDomain

D = FaultDomain
DOMAINS = [d for d in FaultDomain if d != FaultDomain.UNKNOWN] + [FaultDomain.UNKNOWN]
PRIORS = {D.WAN_ISP: 0.14, D.ROUTING: 0.10, D.FIREWALL: 0.10, D.DNS: 0.10, D.DHCP: 0.10, D.VLAN_AUTHENTICATION: 0.08,
          D.INTERFACE_LINK: 0.10, D.SWITCHING: 0.06, D.NETWORK_DEVICE_FAILURE: 0.07, D.SHARED_INFRASTRUCTURE: 0.07,
          D.UNKNOWN: 0.08}
LABEL = {D.WAN_ISP: "WAN / ISP circuit", D.ROUTING: "routing", D.SWITCHING: "switching", D.FIREWALL: "firewall policy",
         D.VLAN_AUTHENTICATION: "VLAN / 802.1X authentication", D.DHCP: "DHCP", D.DNS: "DNS",
         D.NETWORK_DEVICE_FAILURE: "network device failure", D.INTERFACE_LINK: "interface / physical link",
         D.SHARED_INFRASTRUCTURE: "shared infrastructure", D.UNKNOWN: "unknown"}
# Domains a correct answer may reasonably be confused with; agreement checks treat each group as one answer.
EQUIVALENT = [{D.WAN_ISP, D.INTERFACE_LINK}, {D.SHARED_INFRASTRUCTURE, D.NETWORK_DEVICE_FAILURE}]

# Reliability of each kind of evidence: a direct measurement counts fully, an inference less, a raw log line least.
TYPE_WEIGHT = {EvidenceType.OBSERVED_FINDING: 1.0, EvidenceType.OBSERVED_RESULT: 0.85, EvidenceType.INFERRED_FINDING: 0.6,
               EvidenceType.RECORD: 0.5}

# Phase 3 protocol and security findings. Exact code lists, checked before the core rules, so no core code changes meaning.
# Security indicators carry no fault-domain weight: they say something may be malicious, not where a fault is.
PROTOCOL_LIKELIHOODS: list[tuple[re.Pattern[str], dict[FaultDomain, float]]] = [(re.compile(p), w) for p, w in [
    (r"^(?:BGP_ROUTE_LEAK|OSPF_DUPLICATE_ROUTER_ID)$", {D.ROUTING: 3.0}),
    (r"^(?:BGP_ORIGIN_HIJACK_SUSPECTED|BGP_NEXT_HOP_UNREACHABLE|OSPF_LSA_CHURN|OSPF_LSDB_MISMATCH|IPV6_DEFAULT_ROUTE_MISSING|"
     r"IPV6_PREFIX_UNREACHABLE)$", {D.ROUTING: 2.0}),
    (r"^(?:IPV6_OSPFV3_ADJACENCY_DOWN|MCAST_RP_MISMATCH|MCAST_RPF_FAILURE|MCAST_PIM_NEIGHBOR_DOWN)$", {D.ROUTING: 2.5}),
    (r"^(?:OSPF_LSDB_STALE|IPV6_REACHABILITY_LOSS|MCAST_NO_TRAFFIC|IPV6_RA_MISCONFIG)$", {D.ROUTING: 1.0}),
    (r"^(?:OSPF_MAXAGE_LSA|OSPF_ROUTER_LSA_MISSING)$", {D.ROUTING: 1.0, D.NETWORK_DEVICE_FAILURE: 0.8, D.SHARED_INFRASTRUCTURE: 0.5}),
    (r"^(?:BGP_SESSION_DOWN|BGP_WITHDRAWAL_BURST)$", {D.WAN_ISP: 1.2, D.ROUTING: 0.8}),
    (r"^BGP_ROUTE_FLAP$", {D.WAN_ISP: 1.4, D.ROUTING: 0.6}),
    (r"^STP_LOOP$", {D.SWITCHING: 3.5}),
    (r"^(?:STP_TC_STORM|STP_ROOT_UNEXPECTED)$", {D.SWITCHING: 2.0}),
    (r"^(?:STP_BPDU_GUARD_ERRDISABLE|MCAST_NO_QUERIER)$", {D.SWITCHING: 1.5}),
    (r"^(?:VLAN_NATIVE_MISMATCH|VLAN_PRUNED|VLAN_MODE_MISMATCH|VLAN_MISSING_FROM_DATABASE)$", {D.SWITCHING: 3.0}),
    (r"^ARP_IP_CONFLICT$", {D.SWITCHING: 1.2, D.DHCP: 0.8}),
    (r"^(?:NAT_POOL_EXHAUSTED|NAT_RULE_MISSING)$", {D.FIREWALL: 3.0}),
    (r"^(?:NAT_RULE_SHADOWED|IPSEC_PROPOSAL_MISMATCH|IPSEC_SELECTOR_MISMATCH|IPSEC_AUTH_FAILURE)$", {D.FIREWALL: 2.0, D.WAN_ISP: 0.3}),
    (r"^NAT_POOL_NEAR_EXHAUSTION$", {D.FIREWALL: 1.0}),
    (r"^IPSEC_PEER_UNREACHABLE$", {D.WAN_ISP: 1.5, D.INTERFACE_LINK: 0.5}),
    (r"^(?:MTU_BLACK_HOLE|MTU_OVERHEAD_NO_MSS_CLAMP)$", {D.INTERFACE_LINK: 1.8, D.FIREWALL: 0.6}),
    (r"^(?:QOS_REMARKING|QOS_CLASSIFICATION_FAILURE|QOS_POLICY_MISSING)$", {D.INTERFACE_LINK: 1.8}),
    (r"^(?:QOS_PRIORITY_DROPS|QOS_CONGESTION_DROPS)$", {D.INTERFACE_LINK: 0.8, D.WAN_ISP: 0.6}),
    (r"^QOS_LINK_SATURATION$", {D.INTERFACE_LINK: 1.8, D.SHARED_INFRASTRUCTURE: 0.6}),
    (r"^WIFI_INTERFERENCE$", {D.INTERFACE_LINK: 2.5}),
    (r"^(?:WIFI_CO_CHANNEL|WIFI_LOW_SNR|WIFI_DFS_CHANNEL_CHANGE)$", {D.INTERFACE_LINK: 0.8}),
    (r"^(?:TLS_CERTIFICATE_EXPIRED|TLS_NAME_MISMATCH|TLS_CHAIN_INCOMPLETE|TLS_VERSION_MISMATCH)$", {D.UNKNOWN: 2.5}),
    (r"^TLS_INSPECTION_UNTRUSTED$", {D.FIREWALL: 1.5}),
    (r"^TCP_ZERO_WINDOW$", {D.UNKNOWN: 1.5}),
    (r"^TCP_RETRANSMISSION_HIGH$", {D.INTERFACE_LINK: 0.6, D.WAN_ISP: 0.6, D.SWITCHING: 0.3}),
    (r"^TCP_HANDSHAKE_FAILURES$", {D.FIREWALL: 0.5, D.ROUTING: 0.5, D.WAN_ISP: 0.4}),
    (r"^TCP_RTT_INFLATION$", {D.WAN_ISP: 0.5, D.INTERFACE_LINK: 0.4}),
    (r"^(?:SUSPICIOUS_\w+|LATERAL_\w+|THREAT_\w+|ARP_GATEWAY_SPOOFING|ARP_MAC_MULTI_IP|ARP_GRATUITOUS_FLOOD|TLS_UNEXPECTED_CERTIFICATE|"
     r"IPV6_ROGUE_RA|WIFI_ROGUE_AP|BGP_SESSION_STATE_CONFLICT|VLAN_STP_CONFLICT|MTU_PATH_REDUCED|MTU_FRAGMENTATION|IPSEC_ONE_WAY|"
     r"IPSEC_TUNNEL_DOWN|NAT_TOP_CONSUMER)$", {}),
]]

# (pattern on the finding code, {domain: log-likelihood ratio}). The first matching rule applies.
LIKELIHOODS: list[tuple[re.Pattern[str], dict[FaultDomain, float]]] = [(re.compile(p), w) for p, w in [
    # Physical and circuit
    (r"^CARRIER_LOSS$", {D.WAN_ISP: 2.5, D.INTERFACE_LINK: 1.0}),
    (r"^LINK_FLAP_RECOVERED$", {D.WAN_ISP: 2.5, D.INTERFACE_LINK: 1.0}),
    (r"^(?:LINK_DOWN|PATH_LINK_DOWN|PATH_SEGMENT_DOWN|LINK_DOWN_ON_PATH)$", {D.WAN_ISP: 1.8, D.INTERFACE_LINK: 1.0, D.SHARED_INFRASTRUCTURE: 0.3}),
    (r"^LINK_DOWN_AT_FAILURE_POINT$", {D.WAN_ISP: 1.5, D.SHARED_INFRASTRUCTURE: 0.8, D.NETWORK_DEVICE_FAILURE: 0.5}),
    (r"^INTERFACES_DOWN$", {D.WAN_ISP: 1.2, D.INTERFACE_LINK: 1.0, D.NETWORK_DEVICE_FAILURE: 0.6}),
    (r"^(?:WAN_PROBE_FAILURE|PROBE_FLAP_RECOVERED)$", {D.WAN_ISP: 1.5, D.INTERFACE_LINK: 0.5}),
    (r"^INTERMITTENT_FAULT_SUSPECTED$", {D.WAN_ISP: 1.0, D.INTERFACE_LINK: 0.8}),
    (r"^(?:PATH_SEGMENT_DEGRADED|PHYSICAL_LAYER_DEGRADATION_SUSPECTED)$", {D.INTERFACE_LINK: 2.0, D.WAN_ISP: 1.2}),
    (r"^(?:HIGH_ERROR_COUNT|ERROR_COUNT_INCREASE|OPTICAL\w*|INTERFACE_ERRORS)$", {D.INTERFACE_LINK: 1.6, D.WAN_ISP: 0.9}),
    (r"^PACKET_LOSS_MEASURED$", {D.WAN_ISP: 1.4, D.INTERFACE_LINK: 1.4}),
    (r"^HIGH_DROP_COUNT$", {D.WAN_ISP: 0.7, D.INTERFACE_LINK: 0.7}),
    (r"^PATH_SEGMENT_CONGESTED$", {D.WAN_ISP: 0.6, D.INTERFACE_LINK: 0.4}),
    (r"^INTERFACE_EVENTS_LOGGED$", {D.INTERFACE_LINK: 0.6, D.WAN_ISP: 0.4}),
    # Routing and control plane
    (r"^(?:OSPF_AUTH_MISMATCH|OSPF_MTU_MISMATCH|MTU_MISMATCH)$", {D.ROUTING: 3.0}),
    (r"^ADJACENCY_STALLED$", {D.ROUTING: 2.5}),
    (r"^(?:ADJACENCY_FAILED|OSPF_ADJACENCY_DOWN|CONTROL_PLANE_FAILURE_SUSPECTED)$", {D.ROUTING: 2.0, D.WAN_ISP: 0.3}),
    (r"^ADJACENCY_LOSS_FOLLOWS_INTERFACE_DOWN$", {D.WAN_ISP: 2.0, D.INTERFACE_LINK: 0.8, D.ROUTING: -1.0}),
    (r"^MTU_CHANGE$", {D.ROUTING: 1.5}),
    (r"^BGP_NEIGHBOR_DOWN$", {D.WAN_ISP: 1.2, D.ROUTING: 1.0}),
    (r"^(?:ROUTES_WITHDRAWN_AND_RESTORED|ADJACENCY_FLAP_RECOVERED)$", {D.WAN_ISP: 1.0, D.ROUTING: 0.5}),
    (r"^ADJACENCY_RECENTLY_CHANGED$", {D.WAN_ISP: 0.5, D.ROUTING: 0.5}),
    (r"^PEER_ADJACENCIES_LOST$", {D.SHARED_INFRASTRUCTURE: 0.8, D.NETWORK_DEVICE_FAILURE: 0.8, D.WAN_ISP: 0.5}),
    (r"^(?:NO_ROUTE_TO_DESTINATION|PACKET_NO_ROUTE)$", {D.ROUTING: 0.6, D.WAN_ISP: 0.5, D.SHARED_INFRASTRUCTURE: 0.4}),
    (r"^PATH_UNREACHABLE$", {D.WAN_ISP: 0.4, D.ROUTING: 0.4, D.SHARED_INFRASTRUCTURE: 0.4, D.NETWORK_DEVICE_FAILURE: 0.3}),
    # Security policy
    (r"^(?:TRAFFIC_DENIED|PACKET_DROPPED_BY_POLICY)$", {D.FIREWALL: 2.5}),
    (r"^(?:RULE_MODIFIED\w*|FLOWS_DROPPED_BY_POLICY|POLICY_\w+)$", {D.FIREWALL: 2.0}),
    # 802.1X and RADIUS
    (r"^RADIUS_INVALID_AUTHENTICATOR$", {D.VLAN_AUTHENTICATION: 2.5}),
    (r"^(?:DOT1X_AUTH_FAILURE|DOT1X_\w+)$", {D.VLAN_AUTHENTICATION: 2.3, D.FIREWALL: 0.4}),
    (r"^PORT_UNAUTHORIZED$", {D.VLAN_AUTHENTICATION: 2.0, D.FIREWALL: 0.3}),
    (r"^RADIUS_SERVER_DEAD$", {D.VLAN_AUTHENTICATION: 1.4, D.FIREWALL: 1.0, D.WAN_ISP: 0.3}),
    # DHCP
    (r"^(?:DHCP_POOL_EXHAUSTED|DHCP_RELAY_TO_SERVER_REMOVED)$", {D.DHCP: 3.0}),
    (r"^(?:DHCP_HELPER_REMOVED|DHCP_ALLOCATION_FAILURES)$", {D.DHCP: 2.5}),
    (r"^DHCP_RELAY_FAILURE_SUSPECTED$", {D.DHCP: 2.0}),
    (r"^DHCP_IP_CONFLICTS$", {D.DHCP: 1.0}),
    (r"^DHCP_TRANSACTIONS_STOPPED$", {D.DHCP: 0.8, D.VLAN_AUTHENTICATION: 0.6, D.WAN_ISP: 0.3, D.FIREWALL: 0.3}),
    # DNS
    (r"^(?:DNS_SERVFAIL|DNS_SERVER_RESOLUTION_FAULT_SUSPECTED|ZONE_\w+)$", {D.DNS: 2.5}),
    (r"^DNS_UPSTREAM_RESOLUTION_FAILURE$", {D.FIREWALL: 1.0, D.WAN_ISP: 0.8, D.DNS: 0.2}),
    (r"^DNS_(?:LOOKUP_FAILURE|NXDOMAIN\w*)$", {D.DNS: 1.5}),
    (r"^DNS_TIMEOUTS$", {D.DNS: 0.8, D.WAN_ISP: 0.8, D.INTERFACE_LINK: 0.6}),
    (r"^DNS_UNREACHABLE_FROM_SITE\w*$", {D.WAN_ISP: 0.6, D.ROUTING: 0.4, D.DNS: 0.3}),
    # Platform
    (r"^(?:DEVICE_FAILURE_LIKELY|POWER_SUPPLY_FAILURE|SYSTEM_SHUTDOWN)$", {D.NETWORK_DEVICE_FAILURE: 2.5, D.SHARED_INFRASTRUCTURE: 2.0}),
    (r"^PEER_LINKS_DOWN$", {D.SHARED_INFRASTRUCTURE: 2.0, D.NETWORK_DEVICE_FAILURE: 1.5}),
    (r"^DEVICE_UNREACHABLE$", {D.NETWORK_DEVICE_FAILURE: 1.5, D.SHARED_INFRASTRUCTURE: 1.5, D.WAN_ISP: 0.4}),
    (r"^TELEMETRY_GAP$", {D.NETWORK_DEVICE_FAILURE: 1.0, D.SHARED_INFRASTRUCTURE: 1.0}),
    (r"^DEVICE_HEALTH_CRITICAL$", {D.NETWORK_DEVICE_FAILURE: 0.4}),
    # Evidence that the network path itself is fine: argues against path-level faults.
    (r"^PATH_REACHABLE$", {D.WAN_ISP: -1.5, D.ROUTING: -1.5, D.SHARED_INFRASTRUCTURE: -1.2, D.NETWORK_DEVICE_FAILURE: -1.2,
                           D.INTERFACE_LINK: -0.4}),
    (r"^DEVICE_AVAILABLE_WITH_FAULTS$", {D.NETWORK_DEVICE_FAILURE: -0.6}),
]]
# Configuration findings say little by themselves: the line that changed decides the domain.
CHANGE_CODES = re.compile(r"^(?:CONFIG_CHANGED?|CONFIG_DRIFT|UNATTRIBUTED_CONFIG_CHANGE)$")
CHANGE_KEYWORDS = [(re.compile(r"helper|dhcp relay", re.I), {D.DHCP: 1.8}),
                   (re.compile(r"\bmtu\b|ospf|bgp|routing|router ", re.I), {D.ROUTING: 1.6}),
                   (re.compile(r"rule |security policy|deny|acl", re.I), {D.FIREWALL: 1.6}),
                   (re.compile(r"radius|dot1x|802\.1x|aaa|access control", re.I), {D.VLAN_AUTHENTICATION: 1.4}),
                   (re.compile(r"switchport|vlan", re.I), {D.SWITCHING: 1.2})]
GENERIC = {"SERVICE_PATH_CRITICAL", "TRAFFIC_DROPPED_OFF", "FAULT_EVENTS_LOGGED", "CONGESTION_RISK_HIGH", "PATH_MTU_REDUCED"}


PHYSICAL = re.compile(r"^(?:PATH_SEGMENT_DEGRADED|PHYSICAL_LAYER\w*|HIGH_ERROR_COUNT|ERROR_COUNT_INCREASE|OPTICAL\w*|INTERFACE_ERRORS|"
                      r"PACKET_LOSS_MEASURED|HIGH_DROP_COUNT)$")
WAN_CIRCUIT = re.compile(r"\bLNK-WAN-|\bWAN (?:circuit|link|interface)\b|carrier circuit|\bcircuit [A-Z0-9-]+", re.I)


DEFAULT_DENY = re.compile(r"\bDENY-ALL\b|default deny|implicit deny", re.I)


EXTERNAL_ONLY = "names outside our DNS zones only"  # the DNS tool's mark on failures that concern internet names only


def likelihood(item: EvidenceItem) -> dict[FaultDomain, float]:
    weights = base_likelihood(item)
    if item.code in ("DNS_SERVFAIL", "DNS_TIMEOUTS") and EXTERNAL_ONLY in item.summary:
        # Our own names resolve; only internet names fail. That is weak evidence against DNS itself and points at the way out.
        return {D.DNS: 0.5, D.FIREWALL: 0.4, D.WAN_ISP: 0.4}
    if item.code == "TRAFFIC_DENIED" and DEFAULT_DENY.search(item.summary) and not re.search(r"\b(?:[2-9]|\d{2,}) flows", item.summary):
        # A single flow hitting the catch-all deny happens on a healthy network too; it is background, not a fault.
        return {D.FIREWALL: 0.3}
    if PHYSICAL.match(item.code) and WAN_CIRCUIT.search(item.summary):
        # The same physical symptom on a carrier circuit points at the WAN provider rather than an internal cable.
        weights = dict(weights)
        weights[D.WAN_ISP], weights[D.INTERFACE_LINK] = max(weights.get(D.WAN_ISP, 0), weights.get(D.INTERFACE_LINK, 0)) + 0.3, \
            min(weights.get(D.WAN_ISP, 0), weights.get(D.INTERFACE_LINK, 0))
    return weights


def base_likelihood(item: EvidenceItem) -> dict[FaultDomain, float]:
    if CHANGE_CODES.match(item.code):
        for pattern, weights in CHANGE_KEYWORDS:
            if pattern.search(item.summary):
                return weights
        return {}
    for pattern, weights in PROTOCOL_LIKELIHOODS:
        if pattern.match(item.code):
            return weights
    for pattern, weights in LIKELIHOODS:
        if pattern.match(item.code):
            return weights
    return {}


# ---------------------------------------------------------------- layers (for cross-layer reasoning)

LAYERS = ["physical", "data_link", "network", "transport_policy", "services", "platform"]
LAYER_OF_DOMAIN = {D.INTERFACE_LINK: "physical", D.WAN_ISP: "physical", D.SWITCHING: "data_link", D.VLAN_AUTHENTICATION: "data_link",
                   D.ROUTING: "network", D.FIREWALL: "transport_policy", D.DNS: "services", D.DHCP: "services",
                   D.NETWORK_DEVICE_FAILURE: "platform", D.SHARED_INFRASTRUCTURE: "platform", D.UNKNOWN: "services"}
LAYER_RULES = [(re.compile(p), layer) for p, layer in [
    (r"^(?:WIFI_\w+)$", "physical"),
    (r"^(?:STP_\w+|ARP_\w+|VLAN_NATIVE\w*|VLAN_PRUNED|VLAN_MODE\w*|VLAN_MISSING\w*|VLAN_STP\w*|MCAST_NO_QUERIER)$", "data_link"),
    (r"^(?:BGP_ROUTE_LEAK|BGP_ORIGIN\w+|BGP_SESSION\w+|BGP_WITHDRAWAL\w+|BGP_ROUTE_FLAP|BGP_NEXT_HOP\w+|OSPF_LSDB\w+|OSPF_LSA\w+|"
     r"OSPF_MAXAGE\w+|OSPF_DUPLICATE\w+|OSPF_ROUTER_LSA\w+|IPV6_\w+|MCAST_\w+|MTU_BLACK_HOLE|MTU_OVERHEAD\w+|MTU_PATH\w+)$", "network"),
    (r"^(?:TCP_\w+|NAT_\w+|IPSEC_\w+|QOS_\w+)$", "transport_policy"),
    (r"^(?:TLS_\w+|SUSPICIOUS_\w+|LATERAL_\w+|THREAT_\w+)$", "services"),
    (r"CARRIER|LINK_|PHYSICAL|ERROR_COUNT|OPTICAL|INTERFACE|PACKET_LOSS|DROP_COUNT|SEGMENT|PROBE|INTERMITTENT", "physical"),
    (r"DOT1X|PORT_UNAUTHORIZED|RADIUS|VLAN|STP", "data_link"),
    (r"ADJACENC|OSPF|BGP|ROUTE|NO_ROUTE|PATH_UNREACHABLE|PATH_REACHABLE|CONTROL_PLANE|MTU", "network"),
    (r"TRAFFIC_DENIED|RULE_|POLICY|DROPPED_BY_POLICY", "transport_policy"),
    (r"DNS|DHCP|ZONE|SERVICE_PATH|TRAFFIC_DROPPED_OFF", "services"),
    (r"DEVICE|TELEMETRY_GAP|PEER_|POWER|SYSTEM", "platform"),
    (r"CONFIG", "network"),
]]


def layer_of(code: str) -> str:
    return next((layer for pattern, layer in LAYER_RULES if pattern.search(code)), "services")


# ---------------------------------------------------------------- causal mechanisms

@dataclass(frozen=True)
class Mechanism:
    name: str
    cause: re.Pattern[str]
    effect: re.Pattern[str]
    explanation: str


def mechanism(name: str, cause: str, effect: str, explanation: str) -> Mechanism:
    return Mechanism(name, re.compile(cause), re.compile(effect), explanation)


SYMPTOMS = (r"^(?:NO_ROUTE\w*|PACKET_NO_ROUTE|PATH_UNREACHABLE|DNS_TIMEOUTS|DNS_UNREACHABLE\w*|DHCP_TRANSACTIONS_STOPPED|"
            r"SERVICE_PATH_CRITICAL|TRAFFIC_DROPPED_OFF|WAN_PROBE_FAILURE|PROBE_FLAP_RECOVERED|TCP_RETRANSMISSION_HIGH|TCP_HANDSHAKE_FAILURES|"
            r"TCP_RTT_INFLATION|MCAST_NO_TRAFFIC|IPV6_REACHABILITY_LOSS|QOS_CONGESTION_DROPS)$")
MECHANISMS = [
    mechanism("link_loss", r"^(?:CARRIER_LOSS|LINK_DOWN\w*|PATH_LINK_DOWN|PATH_SEGMENT_DOWN|INTERFACES_DOWN|LINK_FLAP_RECOVERED)$",
              r"^(?:BGP_NEIGHBOR_DOWN|ADJACENCY_\w+|OSPF_ADJACENCY_DOWN|PEER_ADJACENCIES_LOST|ROUTES_WITHDRAWN\w*|NO_ROUTE\w*|"
              r"PACKET_NO_ROUTE|PATH_UNREACHABLE|WAN_PROBE_FAILURE|PROBE_FLAP_RECOVERED|DNS_TIMEOUTS|DHCP_TRANSACTIONS_STOPPED|"
              r"SERVICE_PATH_CRITICAL|TRAFFIC_DROPPED_OFF|RADIUS_SERVER_DEAD)$",
              "a link that is down takes the routing sessions and every service behind it down with it"),
    mechanism("degradation", r"^(?:PATH_SEGMENT_DEGRADED|PHYSICAL_LAYER\w*|HIGH_ERROR_COUNT|ERROR_COUNT_INCREASE|OPTICAL\w*)$",
              r"^(?:PACKET_LOSS_MEASURED|HIGH_DROP_COUNT|DNS_TIMEOUTS|RADIUS_SERVER_DEAD|DOT1X_AUTH_FAILURE|SERVICE_PATH_CRITICAL|"
              r"PATH_SEGMENT_CONGESTED)$",
              "a degrading physical link corrupts and drops packets, so latency-sensitive services time out"),
    mechanism("config_to_control_plane", r"^(?:MTU_CHANGE|CONFIG_CHANGED?|CONFIG_DRIFT|UNATTRIBUTED_CONFIG_CHANGE)$",
              r"^(?:OSPF_\w+|MTU_MISMATCH|ADJACENCY_STALLED|ADJACENCY_FAILED|CONTROL_PLANE\w*|DHCP_\w+)$",
              "a configuration change on the device breaks the protocol that depends on that setting"),
    mechanism("control_plane", r"^(?:ADJACENCY_STALLED|ADJACENCY_FAILED|OSPF_\w+|MTU_MISMATCH|CONTROL_PLANE\w*)$",
              r"^(?:NO_ROUTE\w*|PACKET_NO_ROUTE|PATH_UNREACHABLE|DNS_TIMEOUTS|DHCP_TRANSACTIONS_STOPPED|SERVICE_PATH_CRITICAL|"
              r"TRAFFIC_DROPPED_OFF)$",
              "without a routing adjacency the site has no route to the data centre, so its services fail"),
    mechanism("policy_change", r"^(?:RULE_MODIFIED\w*|POLICY_\w+|CONFIG_DRIFT)$",
              r"^(?:TRAFFIC_DENIED|FLOWS_DROPPED_BY_POLICY|PACKET_DROPPED_BY_POLICY)$",
              "a new or changed firewall rule starts denying the traffic it matches"),
    mechanism("policy_denial", r"^(?:TRAFFIC_DENIED|FLOWS_DROPPED_BY_POLICY|PACKET_DROPPED_BY_POLICY)$",
              r"^(?:TRAFFIC_DROPPED_OFF|SERVICE_PATH_CRITICAL|RADIUS_SERVER_DEAD|DOT1X_AUTH_FAILURE|PORT_UNAUTHORIZED|"
              r"DHCP_TRANSACTIONS_STOPPED)$",
              "denied packets never reach the service, so users of that service fail"),
    mechanism("radius", r"^(?:RADIUS_INVALID_AUTHENTICATOR|RADIUS_SERVER_DEAD)$",
              r"^(?:DOT1X_AUTH_FAILURE|PORT_UNAUTHORIZED|DHCP_TRANSACTIONS_STOPPED)$",
              "when RADIUS rejects or never answers, 802.1X ports stay unauthorised and clients never get an address"),
    mechanism("dot1x", r"^(?:DOT1X_AUTH_FAILURE|PORT_UNAUTHORIZED)$", r"^(?:DHCP_TRANSACTIONS_STOPPED|SERVICE_PATH_CRITICAL)$",
              "an unauthorised port drops client traffic before DHCP or applications"),
    mechanism("dhcp", r"^(?:DHCP_POOL_EXHAUSTED|DHCP_RELAY_TO_SERVER_REMOVED|DHCP_HELPER_REMOVED)$",
              r"^(?:DHCP_ALLOCATION_FAILURES|DHCP_TRANSACTIONS_STOPPED|DHCP_RELAY_FAILURE_SUSPECTED|SERVICE_PATH_CRITICAL)$",
              "with no free lease or no relay, new clients never get an address"),
    mechanism("dns_server", r"^(?:DNS_SERVFAIL|DNS_SERVER_RESOLUTION_FAULT_SUSPECTED|ZONE_\w+)$",
              r"^(?:DNS_LOOKUP_FAILURE|SERVICE_PATH_CRITICAL|DNS_TIMEOUTS)$",
              "a DNS server that cannot answer for the zone makes every name in it fail"),
    # ---- Phase 3: protocol mechanisms (cause and effect codes are protocol findings, plus core change and fault records)
    mechanism("config_to_protocol", r"^(?:CONFIG_CHANGED?|CONFIG_CHANGE|CONFIG_COMMAND_LOGGED|CONFIG_DRIFT|MTU_CHANGE|POLICY_CHANGE)$",
              r"^(?:BGP_ROUTE_LEAK|OSPF_DUPLICATE_ROUTER_ID|VLAN_NATIVE_MISMATCH|VLAN_PRUNED|VLAN_MODE_MISMATCH|NAT_POOL_EXHAUSTED|NAT_RULE_\w+|"
              r"IPSEC_PROPOSAL_MISMATCH|IPSEC_SELECTOR_MISMATCH|MTU_OVERHEAD_NO_MSS_CLAMP|QOS_REMARKING|QOS_CLASSIFICATION_FAILURE|"
              r"QOS_POLICY_MISSING|IPV6_OSPFV3_ADJACENCY_DOWN|MCAST_RP_MISMATCH)$",
              "the change set exactly the parameter this protocol depends on"),
    mechanism("policy_block", r"^(?:RULE_MODIFIED\w*|POLICY_CHANGE)$", r"^TCP_HANDSHAKE_FAILURES$",
              "a new or changed policy refuses the connections it matches, so handshakes go unanswered"),
    mechanism("route_leak", r"^(?:BGP_ROUTE_LEAK|BGP_ORIGIN_HIJACK_SUSPECTED)$",
              r"^(?:MCAST_RPF_FAILURE|TCP_HANDSHAKE_FAILURES|TCP_RETRANSMISSION_HIGH|PATH_UNREACHABLE|NO_ROUTE\w*|SERVICE_PATH_CRITICAL)$",
              "a more-specific route pulls the traffic (and the multicast RPF check) towards the router that leaked it"),
    mechanism("ospf_identity", r"^OSPF_DUPLICATE_ROUTER_ID$",
              r"^(?:OSPF_LSA_CHURN|OSPF_LSDB_MISMATCH|OSPF_MAXAGE_LSA|OSPF_ROUTER_LSA_MISSING|TCP_RETRANSMISSION_HIGH)$",
              "two routers with one router ID keep overwriting each other's LSA, so the database and the routes never settle"),
    mechanism("lsdb_instability", r"^(?:OSPF_LSA_CHURN|OSPF_LSDB_MISMATCH)$", r"^TCP_RETRANSMISSION_HIGH$",
              "constant SPF recalculation moves routes and drops packets in transit"),
    mechanism("mtu_adjacency", r"^MTU_MISMATCH$", r"^(?:OSPF_LSDB_STALE|OSPF_MAXAGE_LSA)$",
              "an MTU mismatch stops the adjacency, so that router's copy of the database stops being refreshed"),
    mechanism("adjacency_loss_lsdb", r"^(?:OSPF_AUTH_MISMATCH|OSPF_MTU_MISMATCH|OSPF_ADJACENCY_DOWN|ADJACENCY_STALLED|ADJACENCY_FAILED)$",
              r"^(?:OSPF_LSDB_STALE|OSPF_MAXAGE_LSA|OSPF_ROUTER_LSA_MISSING)$",
              "when the adjacency fails, the neighbour's LSAs stop being refreshed and age out of the database"),
    mechanism("l2_loop", r"^STP_LOOP$", r"^(?:STP_TC_STORM|TCP_RETRANSMISSION_HIGH|TCP_RTT_INFLATION|HIGH_DROP_COUNT|PATH_SEGMENT_CONGESTED|"
              r"PACKET_LOSS_MEASURED|MAC_FLAP|STP_TOPOLOGY_CHANGE|QOS_LINK_SATURATION)$",
              "a layer-2 loop floods broadcasts until links saturate, so every flow at the site loses packets"),
    mechanism("trunk_prune", r"^(?:VLAN_PRUNED|VLAN_MODE_MISMATCH|VLAN_MISSING_FROM_DATABASE)$",
              r"^(?:DHCP_TRANSACTIONS_STOPPED|DHCP_ALLOCATION_FAILURES|SERVICE_PATH_CRITICAL)$",
              "a VLAN that does not cross the trunk cannot reach its gateway or DHCP relay"),
    mechanism("nat_exhaustion", r"^(?:NAT_POOL_EXHAUSTED|NAT_RULE_MISSING)$", r"^(?:TCP_HANDSHAKE_FAILURES|TCP_RETRANSMISSION_HIGH|NAT_ALLOCATION_FAILURE)$",
              "with no free translation, new outbound sessions are refused"),
    mechanism("mtu_overhead", r"^(?:MTU_OVERHEAD_NO_MSS_CLAMP|MTU_CHANGE)$", r"^(?:MTU_BLACK_HOLE|TCP_RETRANSMISSION_HIGH)$",
              "encapsulation without MSS clamping leaves TCP sending segments too large for the path"),
    mechanism("mtu_black_hole", r"^MTU_BLACK_HOLE$", r"^TCP_RETRANSMISSION_HIGH$",
              "full-size segments are silently dropped, so bulk transfers retransmit and stall"),
    mechanism("link_saturation", r"^QOS_LINK_SATURATION$",
              r"^(?:QOS_CONGESTION_DROPS|TCP_RETRANSMISSION_HIGH|TCP_RTT_INFLATION|INTERFACE_DROPS|HIGH_DROP_COUNT|PATH_SEGMENT_CONGESTED|"
              r"PACKET_LOSS_MEASURED)$",
              "a saturated link queues and then drops whatever crosses it, so every flow through it retransmits and waits"),
    mechanism("queue_congestion", r"^QOS_CONGESTION_DROPS$", r"^(?:TCP_RETRANSMISSION_HIGH|TCP_RTT_INFLATION)$",
              "packets dropped from a full queue are retransmitted, and the queue itself adds delay"),
    mechanism("rogue_router", r"^IPV6_ROGUE_RA$", r"^IPV6_REACHABILITY_LOSS$",
              "clients that accept a router advertisement from a host that is not a router send their IPv6 traffic to it, and it does not "
              "forward it"),
    mechanism("qos_classification", r"^(?:QOS_CLASSIFICATION_FAILURE|QOS_REMARKING|QOS_POLICY_MISSING)$",
              r"^(?:QOS_CONGESTION_DROPS|QOS_PRIORITY_DROPS)$",
              "voice that loses its marking queues with best effort and is dropped when the link is busy"),
    mechanism("ipv6_adjacency", r"^IPV6_OSPFV3_ADJACENCY_DOWN$", r"^(?:IPV6_DEFAULT_ROUTE_MISSING|IPV6_PREFIX_UNREACHABLE|IPV6_REACHABILITY_LOSS)$",
              "without the OSPFv3 adjacency the site learns no IPv6 routes"),
    mechanism("ipv6_routes", r"^(?:IPV6_DEFAULT_ROUTE_MISSING|IPV6_PREFIX_UNREACHABLE)$", r"^IPV6_REACHABILITY_LOSS$",
              "with no IPv6 route, IPv6 connections fail while IPv4 keeps working"),
    mechanism("multicast_tree", r"^(?:MCAST_RP_MISMATCH|MCAST_RPF_FAILURE|MCAST_PIM_NEIGHBOR_DOWN)$", r"^MCAST_NO_TRAFFIC$",
              "the distribution tree never reaches the site, so joined receivers get nothing"),
    mechanism("interception", r"^ARP_GATEWAY_SPOOFING$", r"^TLS_UNEXPECTED_CERTIFICATE$",
              "a host that answers for the gateway sits in the path and can present its own certificate"),
    mechanism("wan_loss_protocols", r"^(?:CARRIER_LOSS|LINK_DOWN\w*|PATH_LINK_DOWN|PATH_SEGMENT_DOWN|INTERFACES_DOWN|BGP_SESSION_DOWN)$",
              r"^(?:BGP_SESSION_DOWN|BGP_WITHDRAWAL_BURST|BGP_ROUTE_FLAP|IPSEC_PEER_UNREACHABLE|TCP_HANDSHAKE_FAILURES|MCAST_PIM_NEIGHBOR_DOWN|MCAST_NO_TRAFFIC|"
              r"IPV6_DEFAULT_ROUTE_MISSING|IPV6_REACHABILITY_LOSS)$",
              "losing the link (and the BGP session over it) takes the tunnel, the multicast tree and every new session with it"),
    mechanism("degradation_tcp", r"^(?:PATH_SEGMENT_DEGRADED|PHYSICAL_LAYER\w*|HIGH_ERROR_COUNT|ERROR_COUNT_INCREASE|OPTICAL\w*|INTERFACE_ERRORS|"
              r"CRC_ERRORS\w*)$", r"^(?:TCP_RETRANSMISSION_HIGH|TCP_RTT_INFLATION)$",
              "corrupted frames are discarded, so TCP retransmits and round trips stretch"),
    mechanism("device_failure_protocols", r"^(?:DEVICE_FAILURE_LIKELY|POWER_SUPPLY_FAILURE|SYSTEM_SHUTDOWN|DEVICE_UNREACHABLE|TELEMETRY_GAP)$",
              r"^(?:OSPF_MAXAGE_LSA|BGP_SESSION_DOWN|MCAST_PIM_NEIGHBOR_DOWN|TCP_HANDSHAKE_FAILURES)$",
              "a failed router drops every protocol session it terminates"),
    mechanism("device_failure", r"^(?:DEVICE_FAILURE_LIKELY|POWER_SUPPLY_FAILURE|SYSTEM_SHUTDOWN|DEVICE_UNREACHABLE|TELEMETRY_GAP)$",
              r"^(?:PEER_LINKS_DOWN|PEER_ADJACENCIES_LOST|LINK_DOWN_AT_FAILURE_POINT|NO_ROUTE\w*|PACKET_NO_ROUTE|PATH_UNREACHABLE|"
              r"BGP_NEIGHBOR_DOWN|SERVICE_PATH_CRITICAL|DNS_TIMEOUTS|DHCP_TRANSACTIONS_STOPPED)$",
              "a failed device drops every link and session it terminates"),
]
