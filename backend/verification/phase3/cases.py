"""Expected outcomes of the protocol engines on every scenario (test-only ground truth; the engines never read this).

expect: codes that must be reported, with the status each must have.
root:   the finding code the report must name as the likely cause (None: no root expected).
host:   for security scenarios, the host the threat cluster must centre on (the actor, not a victim).
allowed: further codes that are correct but secondary (effects of the fault); anything else is a false positive.
"""
from dataclasses import dataclass, field

C, S, P, I = "confirmed_fault", "suspicious_indicator", "possible_explanation", "insufficient_evidence"


@dataclass(frozen=True)
class Case:
    scenario_id: str
    kind: str
    expect: dict[str, str] = field(default_factory=dict)
    root: str | None = None
    allowed: frozenset[str] = frozenset()
    host: str | None = None


TCP = frozenset({"TCP_RETRANSMISSION_HIGH", "TCP_HANDSHAKE_FAILURES", "TCP_RTT_INFLATION"})
# Added with the link-capacity check (QOS_LINK_SATURATION): both scenarios' interface data shows a link rising to saturation
# with output drops at the onset. In the loop it is an effect of the loop; in the busy-hour re-marking case it is the busy
# link that the misclassified voice then queues behind. Neither is the root.
SATURATION = frozenset({"QOS_LINK_SATURATION"})
CASES = {case.scenario_id: case for case in (
    # ---- Phase 3 scenarios
    Case("P3-HEALTHY-BUSY", "normal"),
    Case("P3-BGP-ROUTE-LEAK", "failure", {"BGP_ROUTE_LEAK": C, "MCAST_RPF_FAILURE": C}, "BGP_ROUTE_LEAK", TCP | {"MCAST_NO_TRAFFIC"}),
    Case("P3-OSPF-DUPLICATE-RID", "failure", {"OSPF_DUPLICATE_ROUTER_ID": C, "OSPF_LSA_CHURN": C, "OSPF_LSDB_MISMATCH": C}, "OSPF_DUPLICATE_ROUTER_ID",
         TCP | {"OSPF_MAXAGE_LSA"}),
    Case("P3-STP-LOOP-NYC", "failure", {"STP_LOOP": C}, "STP_LOOP", TCP | SATURATION),
    Case("P3-ARP-IP-CONFLICT-SIN", "failure", {"ARP_IP_CONFLICT": C}, "ARP_IP_CONFLICT"),
    Case("P3-VLAN-TRUNK-PRUNE-BLR", "failure", {"VLAN_PRUNED": C, "VLAN_NATIVE_MISMATCH": C}, "VLAN_PRUNED"),
    Case("P3-NAT-EXHAUSTION", "failure", {"NAT_POOL_EXHAUSTED": C}, "NAT_POOL_EXHAUSTED", TCP),
    Case("P3-IPSEC-DH-MISMATCH", "failure", {"IPSEC_PROPOSAL_MISMATCH": C}, "IPSEC_PROPOSAL_MISMATCH"),
    Case("P3-MTU-BLACKHOLE-SIN", "failure", {"MTU_BLACK_HOLE": C, "MTU_OVERHEAD_NO_MSS_CLAMP": C}, "MTU_OVERHEAD_NO_MSS_CLAMP", TCP),
    Case("P3-QOS-REMARK-NYC", "failure", {"QOS_REMARKING": C, "QOS_CLASSIFICATION_FAILURE": C}, "QOS_CLASSIFICATION_FAILURE",
         frozenset({"QOS_CONGESTION_DROPS"}) | SATURATION),
    Case("P3-IPV6-OSPFV3-BLR", "failure", {"IPV6_OSPFV3_ADJACENCY_DOWN": C, "IPV6_DEFAULT_ROUTE_MISSING": C, "IPV6_REACHABILITY_LOSS": C},
         "IPV6_OSPFV3_ADJACENCY_DOWN", frozenset({"IPV6_PREFIX_UNREACHABLE"})),
    Case("P3-WIFI-INTERFERENCE-SIN", "failure", {"WIFI_INTERFERENCE": C, "WIFI_DFS_CHANNEL_CHANGE": P}, "WIFI_INTERFERENCE"),
    Case("P3-MCAST-RP-MISMATCH", "failure", {"MCAST_RP_MISMATCH": C, "MCAST_NO_TRAFFIC": C}, "MCAST_RP_MISMATCH"),
    Case("P3-TLS-CERT-EXPIRED", "failure", {"TLS_CERTIFICATE_EXPIRED": C}, "TLS_CERTIFICATE_EXPIRED"),
    Case("P3-TCP-ZERO-WINDOW-ERP", "edge", {"TCP_ZERO_WINDOW": P}, "TCP_ZERO_WINDOW"),
    Case("P3-SEC-ARP-MITM-SIN", "adversarial", {"ARP_GATEWAY_SPOOFING": S, "TLS_UNEXPECTED_CERTIFICATE": S, "THREAT_CORRELATED_ACTIVITY": S},
         host="10.20.10.103"),
    Case("P3-SEC-LATERAL-MOVEMENT-NYC", "adversarial", {
        "SUSPICIOUS_PORT_SCAN": S, "SUSPICIOUS_BEACONING": S, "SUSPICIOUS_LARGE_UPLOAD": S, "LATERAL_ADMIN_FANOUT": S,
        "LATERAL_CREDENTIAL_SPRAY": S, "LATERAL_MOVEMENT_CHAIN": S, "THREAT_CORRELATED_ACTIVITY": S}, host="10.10.10.102",
        allowed=frozenset({"SUSPICIOUS_THREAT_INTEL_MATCH"})),
    Case("P3-SEC-DNS-TUNNEL-BLR", "adversarial", {"SUSPICIOUS_DNS_TUNNELING": S, "SUSPICIOUS_BEACONING": S, "THREAT_CORRELATED_ACTIVITY": S},
         host="10.30.10.101"),
    Case("P3-ADV-DECOYS", "adversarial"),
    Case("P3-EDGE-PARTIAL-TELEMETRY", "edge", {"BGP_SESSION_STATE_CONFLICT": P, "OSPF_LSDB_PARTIAL": I, "STP_DATA_STALE": I,
                                               "TELEMETRY_NOT_COLLECTED": I, "VLAN_STP_CONFLICT": I, "LATERAL_VISIBILITY_GAP": I}),
    # ---- core scenarios: protocol effects consistent with their existing fault, and clean controls
    Case("BASELINE", "normal"),
    Case("WAN-FAILURE", "core", {"BGP_SESSION_DOWN": C, "IPSEC_PEER_UNREACHABLE": C, "MCAST_PIM_NEIGHBOR_DOWN": C}, None,
         TCP | {"IPV6_DEFAULT_ROUTE_MISSING", "MCAST_NO_TRAFFIC"}),
    Case("PACKET-LOSS", "core", {"TCP_RETRANSMISSION_HIGH": C}, None, TCP),
    Case("OSPF-ADJACENCY-FAILURE", "core", {"MTU_MISMATCH": C, "OSPF_LSDB_STALE": C}, "MTU_MISMATCH"),
    Case("ADV-BLR-OSPF-AUTH-MISMATCH", "core", {"OSPF_MAXAGE_LSA": C}),
    Case("ADV-NYC-WAN-FLAP", "core", {"BGP_WITHDRAWAL_BURST": C}),
    Case("ADV-METRO-FIBRE-DEGRADATION", "core", {"TCP_RETRANSMISSION_HIGH": C}, None, TCP),
    Case("SHARED-DEVICE-FAILURE", "core", {"BGP_SESSION_DOWN": C, "OSPF_MAXAGE_LSA": C, "MCAST_PIM_NEIGHBOR_DOWN": C}, None, TCP),
    Case("FIREWALL-BLOCKING", "core", {"TCP_HANDSHAKE_FAILURES": C}, None, TCP),
    Case("ADV-SIN-ERP-SUBNET-BLOCK", "core", {"TCP_HANDSHAKE_FAILURES": C}, None, TCP),
    Case("DHCP-ALLOCATION-FAILURE", "normal"), Case("DNS-RESOLUTION-FAILURE", "normal"), Case("VLAN-AUTHENTICATION-FAILURE", "normal"),
    Case("ADV-DNS-SECONDARY-ZONE-EXPIRED", "normal"), Case("ADV-NYC-VOICE-DHCP-RELAY", "normal"), Case("ADV-SIN-RADIUS-UDP-BLOCK", "normal"),
)}
SECURITY_CODES = ("SUSPICIOUS_", "LATERAL_", "THREAT_", "ARP_GATEWAY", "ARP_MAC", "ARP_GRAT", "TLS_UNEXPECTED", "IPV6_ROGUE", "WIFI_ROGUE",
                  "BGP_ORIGIN_HIJACK")
FEATURE_SCENARIO = {  # one failure (or adversarial) scenario per feature, for the per-feature tests
    "bgp": ("P3-BGP-ROUTE-LEAK", "BGP_ROUTE_LEAK"), "ospf": ("P3-OSPF-DUPLICATE-RID", "OSPF_DUPLICATE_ROUTER_ID"),
    "stp": ("P3-STP-LOOP-NYC", "STP_LOOP"), "arp": ("P3-SEC-ARP-MITM-SIN", "ARP_GATEWAY_SPOOFING"), "vlan": ("P3-VLAN-TRUNK-PRUNE-BLR", "VLAN_PRUNED"),
    "nat": ("P3-NAT-EXHAUSTION", "NAT_POOL_EXHAUSTED"), "ipsec": ("P3-IPSEC-DH-MISMATCH", "IPSEC_PROPOSAL_MISMATCH"),
    "tcp": ("PACKET-LOSS", "TCP_RETRANSMISSION_HIGH"), "mtu": ("P3-MTU-BLACKHOLE-SIN", "MTU_BLACK_HOLE"),
    "qos": ("P3-QOS-REMARK-NYC", "QOS_REMARKING"), "ipv6": ("P3-IPV6-OSPFV3-BLR", "IPV6_OSPFV3_ADJACENCY_DOWN"),
    "wireless": ("P3-WIFI-INTERFERENCE-SIN", "WIFI_INTERFERENCE"), "multicast": ("P3-MCAST-RP-MISMATCH", "MCAST_RP_MISMATCH"),
    "tls": ("P3-TLS-CERT-EXPIRED", "TLS_CERTIFICATE_EXPIRED"), "threats": ("P3-SEC-LATERAL-MOVEMENT-NYC", "THREAT_CORRELATED_ACTIVITY"),
    "traffic": ("P3-SEC-DNS-TUNNEL-BLR", "SUSPICIOUS_DNS_TUNNELING"), "lateral": ("P3-SEC-LATERAL-MOVEMENT-NYC", "LATERAL_MOVEMENT_CHAIN"),
}


def correct(scenario_id: str, code: str) -> bool:
    case = CASES[scenario_id]
    return code in case.expect or code in case.allowed
