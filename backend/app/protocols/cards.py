"""Incident cards: what a correct diagnosis of each SCN scenario should conclude.

Ground truth, kept apart from the diagnostic code: no engine, reasoning or conversation module imports this file (a test
enforces it). The cards were written from the network fault each scenario models, before any engine was run on the
scenarios, and are used only to score the engines and to document the incidents.

Write the JSON copies (app/protocols/data/cards) with:  .venv/bin/python -m app.protocols.cards

Revision after the first scoring run (disclosed, not a detection change): phase_a.acceptable_domains had been filled in only
where the core data shows the fault. SCN-08 and SCN-09 (switch configuration) and SCN-10 (the firewall's TLS inspection) now
carry their truth domain too, consistent with SCN-05 and SCN-06. "visible_in_core_data" is unchanged. SCN-06's acceptable roots
were made stricter (CODE@SITE): the first run named the right code for the wrong tunnel, which the code-only check missed.

Revision on 2026-11-27, SCN-07 (independently reviewed against the raw data, not the engine output): acceptable_roots was empty,
meaning "no protocol finding should be named as the root". That contradicted the card's own root_cause and the dataset's ground
truth, which name the metro link LNK-CORE-DC1-METRO (CORE-SW-01, DC1-FW-01) and the WAN egress as the place the bulk transfer
saturates. The empty list was written when no protocol finding could express a capacity cause. The raw data supports the cause:
at 08:59 DC1-FW-01 logs 2,400 new tcp/445 sessions from 10.100.100.50 (dc1-bkp-01, an allowlisted backup server; no maintenance
window), 12 SMB transfers start at 08:59:30; from 09:00 the metro link reads 98% (35% before) with ~47,000 output drops per
interval, a queue-full log and zero errors; the 200 Mbps WAN egress links read 93% (55-64% before) with 8,800 drops and the BULK
class jumps from ~8.5 to ~60 Mbps (about 52 Mbps per link, matching the ~166 Mbps of recorded transfers), while voice stays clean;
retransmissions rise from 0.2-0.5% to ~4.5% for small and large segments alike (not size-dependent, so not an MTU problem).
Fragmentation (reassembly failures only after the onset) stays an acceptable secondary finding, never the root. One caveat is
recorded rather than hidden: the metro interface's byte counters do not rise with its utilisation percentage in the generated
data, and the recorded flows alone do not account for 98% of 10 Gbps; the WAN egress figures are consistent. QOS_LINK_SATURATION
is therefore expected (confirmed) and accepted as the root.
"""
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CARD_DIR = Path(__file__).resolve().parent / "data" / "cards"
Status = Literal["confirmed_fault", "suspicious_indicator", "possible_explanation", "insufficient_evidence"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Step(Model):
    minute: float
    evidence: str
    what: str


class Decoy(Model):
    clue: str
    evidence: list[str]
    why_misleading: str
    must_not_conclude: list[str]  # fault domains or finding codes that would be the wrong conclusion


class Expected(Model):
    engine: str
    code: str
    status: Status
    role: Literal["root", "effect", "independent", "indicator"]
    min_confidence: float | None = None
    max_confidence: float | None = None


class Command(Model):
    device_id: str
    command: str
    expect: str


class ConfigExpectation(Model):
    device_id: str
    golden_contains: list[str] = Field(default_factory=list)
    running_contains: list[str] = Field(default_factory=list)
    running_lacks: list[str] = Field(default_factory=list)


class PhaseA(Model):
    visible_in_core_data: bool
    acceptable_domains: list[str]
    note: str


class Card(Model):
    scenario_id: str
    incident_id: str
    title: str
    difficulty: list[Literal["straightforward", "multi-layer", "multiple-symptoms", "shared-device", "multi-site", "cascading",
                             "misleading-evidence", "security-uncertainty"]]
    capabilities: list[str]
    sites: list[str]
    unaffected_sites: list[str]
    affected_devices: list[str]
    affected_services: list[str]
    affected_paths: list[str]
    timeline: list[Step]
    root_cause: str
    symptoms: list[str]
    secondary_effects: list[str]
    decoys: list[Decoy]
    phase_a: PhaseA
    expected_findings: list[Expected]
    acceptable_findings: list[str] = Field(default_factory=list)
    forbidden_findings: list[str] = Field(default_factory=list)
    max_counts: dict[str, int] = Field(default_factory=dict)
    acceptable_roots: list[str] = Field(default_factory=list)  # CODE or CODE@SITE; empty: no protocol finding should be the cause
    threat_hosts: list[str] = Field(default_factory=list)  # one entry per separate threat cluster expected
    evidence: list[str]
    configuration: list[ConfigExpectation] = Field(default_factory=list)
    commands: list[Command]
    confidence: str


def ref(day: int, interface: str, minute: int) -> str:
    return f"interface_statistics:{interface}@2026-04-{day:02d}T09:{minute:02d}:00+00:00"


SECURITY_MAX = 0.85

CARDS: tuple[Card, ...] = (
    Card(
        scenario_id="SCN-01-NYC-WAN-FLAP-STORM", incident_id="INC-20260421-401", title="New York circuit bouncing",
        difficulty=["multi-layer", "cascading", "multiple-symptoms", "misleading-evidence"],
        capabilities=["interface statistics", "event timeline", "routing adjacency", "BGP", "OSPF LSDB", "IPsec", "TCP", "multicast", "MTU", "DNS"],
        sites=["NYC"], unaffected_sites=["SIN", "BLR"], affected_devices=["NYC-RTR-01", "CORE-RTR-01"],
        affected_services=["application", "dns", "internet", "voice", "video"],
        affected_paths=["PATH-NYC-APPLICATION", "PATH-NYC-DNS", "PATH-NYC-INTERNET"],
        timeline=[Step(minute=-8, evidence="events:EVT-S01-001", what="CRC errors start on NYC-RTR-01 Gi0/0/0"),
                  Step(minute=-6, evidence="events:EVT-S01-002", what="Unrelated firewall rule committed on CORE-FW-01 (decoy)"),
                  Step(minute=0, evidence="events:EVT-S01-003", what="First loss of signal; BGP session drops"),
                  Step(minute=1.2, evidence="events:EVT-S01-010", what="Link and BGP back; prefixes re-announced"),
                  Step(minute=12, evidence="events:EVT-S01-039", what="Fifth loss of signal"),
                  Step(minute=14, evidence="events:EVT-S01-051", what="Probe recovers; circuit still erroring")],
        root_cause="Carrier circuit WAN-NYC-0001 (LNK-WAN-NYC) degrading and bouncing; everything else is a consequence.",
        symptoms=["Drops every few minutes", "Calls and ERP cut out", "All-hands video freezes"],
        secondary_effects=["BGP routes flap", "OSPF externals for New York re-flooded", "Backup VPN dead-peer timeouts",
                           "TCP retransmissions and longer round trips", "DNS timeouts during each drop", "PIM neighbour bounces"],
        decoys=[Decoy(clue="Firewall rule ALLOW-SAAS-CRM committed six minutes before the onset", evidence=["events:EVT-S01-002"],
                      why_misleading="It allows a new port outbound and touches no New York traffic; the timing is coincidence.",
                      must_not_conclude=["firewall"]),
                Decoy(clue="DNS lookups time out", evidence=["dns_queries:DNS-Q-S01-01", "dns_queries:DNS-Q-S01-02"],
                      why_misleading="They time out only while the circuit is down; the DNS servers are healthy.", must_not_conclude=["dns"])],
        phase_a=PhaseA(visible_in_core_data=True, acceptable_domains=["wan_isp", "interface_link"],
                       note="Interface errors, carrier loss and BGP state changes are all in the core data."),
        expected_findings=[Expected(engine="bgp", code="BGP_ROUTE_FLAP", status="confirmed_fault", role="effect", min_confidence=0.7),
                           Expected(engine="tcp", code="TCP_RETRANSMISSION_HIGH", status="confirmed_fault", role="effect", min_confidence=0.7)],
        acceptable_findings=["TCP_HANDSHAKE_FAILURES", "TCP_RTT_INFLATION", "OSPF_LSA_CHURN", "BGP_WITHDRAWAL_BURST", "IPSEC_PEER_UNREACHABLE"],
        forbidden_findings=["NAT_RULE_MISSING", "NAT_RULE_SHADOWED", "TLS_CERTIFICATE_EXPIRED", "MTU_BLACK_HOLE", "STP_LOOP"],
        acceptable_roots=[],
        evidence=["events:EVT-S01-001", "events:EVT-S01-003", "route_changes:RC-S01-001", "bgp_updates:BU-S01-001", "lsa_updates:LSU-S01-001",
                  "protocol_events:PE-S01-01", ref(21, "NYC-RTR-01:Gi0/0/0", 5), "dns_queries:DNS-Q-S01-01"],
        configuration=[ConfigExpectation(device_id="CORE-FW-01", running_contains=[
            "rule FWR-CORE-0105 priority 105 name ALLOW-SAAS-CRM allow tcp 10.0.0.0/8 -> 0.0.0.0/0 port 8443"])],
        commands=[Command(device_id="NYC-RTR-01", command="show interfaces Gi0/0/0", expect="Rising CRC and input errors, several resets"),
                  Command(device_id="NYC-RTR-01", command="show ip bgp summary", expect="Session to 172.16.0.1 up only a few minutes"),
                  Command(device_id="CORE-RTR-02", command="show ip ospf database external 10.10.10.0", expect="A recent sequence number"),
                  Command(device_id="NYC-RTR-01", command="ping 172.16.0.1 repeat 100", expect="Loss of several percent")],
        confidence="The physical cause is in the core data, so a diagnosis should be high confidence on the WAN circuit; protocol findings are "
                   "effects, confirmed with confidence of at least 0.7."),
    Card(
        scenario_id="SCN-02-SIN-ORIGIN-ANOMALY", incident_id="INC-20260422-402", title="Unexpected origin for Singapore users",
        difficulty=["multi-site", "multi-layer", "misleading-evidence", "security-uncertainty"],
        capabilities=["routing state", "reachability", "BGP", "TCP", "DNS", "wireless", "STP", "threat correlation"],
        sites=["SIN"], unaffected_sites=["NYC", "BLR"], affected_devices=["NYC-RTR-01", "CORE-RTR-01"],
        affected_services=["application", "dns", "internet"], affected_paths=["PATH-SIN-APPLICATION", "PATH-SIN-DNS", "PATH-SIN-INTERNET"],
        timeline=[Step(minute=-6, evidence="events:EVT-S02-001", what="Lab peering configured on NYC-RTR-01"),
                  Step(minute=0, evidence="route_changes:RC-S02-001", what="CORE-RTR-01 installs 10.20.10.96/28 via New York"),
                  Step(minute=1, evidence="dns_queries:DNS-Q-S02-01", what="Clients in .96-.111 start timing out")],
        root_cause="A lab AS (64999) peered with NYC-RTR-01 announces a more-specific of Singapore's user subnet; return traffic for half of "
                   "Singapore goes to New York.",
        symptoms=["Half of Singapore's desktops can't reach ERP or DNS", "The other half is fine"],
        secondary_effects=["TCP handshake failures from Singapore", "DNS timeouts for clients in .96-.111 only"],
        decoys=[Decoy(clue="Wi-Fi busy all morning", evidence=["radio_samples:SIN-AP-01|5GHz@2026-04-22T09:05:00Z"],
                      why_misleading="High utilisation with clean RF and low retries; wired desktops are affected too.",
                      must_not_conclude=["WIFI_INTERFERENCE", "WIFI_CO_CHANNEL"]),
                Decoy(clue="Two STP topology changes on SIN-SW-01", evidence=["events:EVT-S02-010", "events:EVT-S02-011"],
                      why_misleading="Two changes in forty minutes is normal port activity.", must_not_conclude=["STP_TC_STORM", "STP_LOOP"])],
        phase_a=PhaseA(visible_in_core_data=True, acceptable_domains=["routing"],
                       note="The more-specific route is in the core routing tables; the origin AS is only in the BGP telemetry."),
        expected_findings=[Expected(engine="bgp", code="BGP_ORIGIN_HIJACK_SUSPECTED", status="suspicious_indicator", role="root",
                                    max_confidence=SECURITY_MAX),
                           Expected(engine="tcp", code="TCP_HANDSHAKE_FAILURES", status="confirmed_fault", role="effect", min_confidence=0.7)],
        acceptable_findings=["TCP_RETRANSMISSION_HIGH", "THREAT_CORRELATED_ACTIVITY"],
        forbidden_findings=["WIFI_INTERFERENCE", "WIFI_CO_CHANNEL", "STP_TC_STORM", "STP_LOOP", "BGP_ROUTE_LEAK"],
        acceptable_roots=[],
        evidence=["events:EVT-S02-001", "route_changes:RC-S02-001", "bgp_updates:BU-S02-001", "bgp_routes:NYC-RTR-01|10.20.10.96/28|lab",
                  "dns_queries:DNS-Q-S02-01", "dns_queries:DNS-Q-S02-11"],
        configuration=[ConfigExpectation(device_id="NYC-RTR-01", golden_contains=["router bgp 65010"],
                                         running_contains=["router bgp 65010 ; neighbor 10.10.99.251 remote-as 64999"])],
        commands=[Command(device_id="CORE-RTR-01", command="show ip bgp 10.20.10.96 255.255.255.240", expect="Path 65010 64999, origin AS64999"),
                  Command(device_id="NYC-RTR-01", command="show ip bgp summary", expect="A new neighbour 10.10.99.251 in AS64999"),
                  Command(device_id="SIN-SW-01", command="traceroute 10.100.100.40", expect="Replies to .96-.111 hosts route via New York")],
        confidence="The origin anomaly must stay a suspicious indicator (at most 0.85, never confirmed, no attribution): the data shows an "
                   "unregistered origin, not intent. The TCP impact is confirmed."),
    Card(
        scenario_id="SCN-03-BLR-ROGUE-STP-ROOT", incident_id="INC-20260423-403", title="Rogue switch takes the STP root",
        difficulty=["multi-layer", "misleading-evidence", "security-uncertainty"],
        capabilities=["device logs", "interface statistics", "STP", "ARP", "TCP", "DHCP"],
        sites=["BLR"], unaffected_sites=["NYC", "SIN"], affected_devices=["BLR-SW-01"], affected_services=["application", "dns"],
        affected_paths=["PATH-BLR-APPLICATION", "PATH-BLR-DNS"],
        timeline=[Step(minute=-2, evidence="events:EVT-S03-001", what="Gi1/0/7 comes up"),
                  Step(minute=-1.9, evidence="events:EVT-S03-002", what="VLAN 10 root moves to an unknown bridge"),
                  Step(minute=1, evidence="protocol_events:PE-S03-02", what="Topology changes keep arriving on Gi1/0/7")],
        root_cause="A priority-0 switch on BLR-SW-01 Gi1/0/7 (no BPDU guard) became STP root; its unstable link keeps triggering topology changes.",
        symptoms=["Freezes every few minutes in Bengaluru"],
        secondary_effects=["MAC table flushes and flooding", "TCP retransmissions"],
        decoys=[Decoy(clue="DHCP pool 82% utilised warning", evidence=["events:EVT-S03-020"],
                      why_misleading="82% is not exhaustion and allocations continue.", must_not_conclude=["dhcp", "DHCP_POOL_EXHAUSTED"])],
        phase_a=PhaseA(visible_in_core_data=True, acceptable_domains=["switching"],
                       note="Root change and topology-change logs are in the core data; Phase A has no STP-specific tool."),
        expected_findings=[Expected(engine="stp", code="STP_ROOT_UNEXPECTED", status="suspicious_indicator", role="root", max_confidence=SECURITY_MAX),
                           Expected(engine="stp", code="STP_TC_STORM", status="confirmed_fault", role="effect", min_confidence=0.7)],
        acceptable_findings=["TCP_RETRANSMISSION_HIGH", "THREAT_CORRELATED_ACTIVITY"],
        forbidden_findings=["ARP_GATEWAY_SPOOFING", "ARP_IP_CONFLICT", "STP_LOOP", "VLAN_NATIVE_MISMATCH"],
        acceptable_roots=["STP_TC_STORM", "STP_ROOT_UNEXPECTED"],
        evidence=["events:EVT-S03-001", "events:EVT-S03-002", "stp_vlans:BLR-SW-01|10", "stp_ports:BLR-SW-01|Gi1/0/7|10", "protocol_events:PE-S03-02"],
        commands=[Command(device_id="BLR-SW-01", command="show spanning-tree vlan 10 detail", expect="Root on Gi1/0/7, many recent topology changes"),
                  Command(device_id="BLR-SW-01", command="show spanning-tree root", expect="Root priority 0 with an unknown MAC"),
                  Command(device_id="BLR-SW-01", command="show cdp neighbors Gi1/0/7 detail", expect="Another switch on a user port")],
        confidence="The topology-change storm is confirmed; the unknown root bridge is a suspicious indicator (a desk switch, not necessarily "
                   "hostile), at most 0.85."),
    Card(
        scenario_id="SCN-04-NYC-VOICE-VLAN-DELETED", incident_id="INC-20260424-404", title="Voice VLAN deleted, plus an address conflict",
        difficulty=["multiple-symptoms", "misleading-evidence", "straightforward"],
        capabilities=["change history", "config drift", "DHCP", "VLAN/trunk", "ARP", "STP"],
        sites=["NYC"], unaffected_sites=["SIN", "BLR"], affected_devices=["NYC-SW-01"], affected_services=["voice", "dhcp"],
        affected_paths=["PATH-NYC-DHCP"],
        timeline=[Step(minute=-5, evidence="events:EVT-S04-001", what="'no vlan 20' on NYC-SW-01"),
                  Step(minute=-4.8, evidence="events:EVT-S04-002", what="Trunk allowed list trimmed to 10,99"),
                  Step(minute=-3, evidence="events:EVT-S04-004", what="DHCP server CPU warning (decoy)"),
                  Step(minute=4, evidence="dhcp_events:DHCP-EVT-S04-001", what="Unrelated printer address conflict")],
        root_cause="VLAN 20 deleted from NYC-SW-01 and its trunk; an unrelated printer address conflict at the same time.",
        symptoms=["Phones have no IP address", "One desktop keeps disconnecting"],
        secondary_effects=["No DHCP transactions for the voice pool", "Gi1/0/3 inactive"],
        decoys=[Decoy(clue="DHCP server high CPU", evidence=["events:EVT-S04-004"],
                      why_misleading="The server still answers the users pool; voice requests never reach it.", must_not_conclude=["dhcp"])],
        phase_a=PhaseA(visible_in_core_data=True, acceptable_domains=["switching"],
                       note="The change log and the stopped voice DHCP are visible; the VLAN database is only in the protocol telemetry."),
        expected_findings=[Expected(engine="vlan", code="VLAN_MISSING_FROM_DATABASE", status="confirmed_fault", role="root", min_confidence=0.8),
                           Expected(engine="vlan", code="VLAN_PRUNED", status="confirmed_fault", role="root", min_confidence=0.8),
                           Expected(engine="arp", code="ARP_IP_CONFLICT", status="confirmed_fault", role="independent", min_confidence=0.8)],
        forbidden_findings=["ARP_GATEWAY_SPOOFING", "VLAN_NATIVE_MISMATCH", "STP_LOOP"],
        acceptable_roots=["VLAN_MISSING_FROM_DATABASE", "VLAN_PRUNED", "ARP_IP_CONFLICT"],
        evidence=["events:EVT-S04-001", "events:EVT-S04-002", "events:EVT-S04-003", "vlan_databases:NYC-SW-01", "trunk_ports:NYC-SW-01:Gi1/0/24",
                  "dhcp_events:DHCP-EVT-S04-001", "protocol_events:PE-S04-01"],
        configuration=[ConfigExpectation(device_id="NYC-SW-01", golden_contains=["vlan 20", " switchport trunk allowed vlan 10,20,99"],
                                         running_contains=[" switchport trunk allowed vlan 10,99"], running_lacks=["vlan 20"])],
        commands=[Command(device_id="NYC-SW-01", command="show vlan brief", expect="No VLAN 20"),
                  Command(device_id="NYC-SW-01", command="show interfaces trunk", expect="Gi1/0/24 allows 10,99 only"),
                  Command(device_id="NYC-RTR-01", command="show ip arp vlan 10", expect="The conflicting address alternating between two MACs")],
        confidence="Both VLAN findings are two-sided configuration evidence (high, at least 0.8); the address conflict is independently confirmed."),
    Card(
        scenario_id="SCN-05-EDGE-NAT-RULE-SHADOW", incident_id="INC-20260425-405", title="No-NAT rule shadows internet PAT",
        difficulty=["shared-device", "multi-site", "misleading-evidence", "cascading"],
        capabilities=["firewall logs", "traffic flows", "NAT", "TCP", "DNS", "TLS"],
        sites=["NYC", "SIN", "BLR"], unaffected_sites=[], affected_devices=["CORE-FW-01"], affected_services=["internet", "dns"],
        affected_paths=["PATH-BLR-INTERNET", "PATH-NYC-INTERNET", "PATH-SIN-INTERNET"],
        timeline=[Step(minute=-3, evidence="events:EVT-S05-001", what="NONAT-PARTNER-VPN committed at position 50"),
                  Step(minute=1, evidence="events:EVT-S05-002", what="DNS forwarders time out"),
                  Step(minute=2, evidence="dns_queries:DNS-Q-S05-01", what="External names SERVFAIL; internal names fine")],
        root_cause="A no-NAT rule above the PAT rule exempts all internal traffic from translation; replies never return.",
        symptoms=["No external websites at any office", "DNS errors for external names", "ERP fine"],
        secondary_effects=["PAT pool almost empty", "External DNS forwarding fails", "Internet TCP handshakes never complete"],
        decoys=[Decoy(clue="DNS forwarder timeouts and SERVFAIL for external names", evidence=["events:EVT-S05-002", "dns_queries:DNS-Q-S05-01"],
                      why_misleading="Internal names resolve (DNS-Q-S05-11); the forwarders are on the internet, which is what broke.",
                      must_not_conclude=["dns"])],
        phase_a=PhaseA(visible_in_core_data=False, acceptable_domains=["firewall"],
                       note="The NAT rule base is only in the protocol telemetry; the core data shows the policy commit and DNS symptoms."),
        expected_findings=[Expected(engine="nat", code="NAT_RULE_SHADOWED", status="confirmed_fault", role="root", min_confidence=0.8),
                           Expected(engine="nat", code="NAT_RULE_MISSING", status="confirmed_fault", role="root", min_confidence=0.8),
                           Expected(engine="tcp", code="TCP_HANDSHAKE_FAILURES", status="confirmed_fault", role="effect", min_confidence=0.7)],
        forbidden_findings=["TLS_INSPECTION_UNTRUSTED", "TLS_CERTIFICATE_EXPIRED", "NAT_POOL_EXHAUSTED"],
        acceptable_roots=["NAT_RULE_SHADOWED", "NAT_RULE_MISSING"],
        evidence=["events:EVT-S05-001", "nat_rules:NONAT-PARTNER-VPN", "nat_rules:NAT-0100", "dns_queries:DNS-Q-S05-01", "dns_queries:DNS-Q-S05-11"],
        commands=[Command(device_id="CORE-FW-01", command="show running nat-policy", expect="NONAT-PARTNER-VPN above the PAT rule"),
                  Command(device_id="CORE-FW-01", command="show running ippool", expect="PAT pool nearly unused"),
                  Command(device_id="DC1-SRV-DNS-01", command="dig @10.100.100.10 www.example.org", expect="SERVFAIL for external names only")],
        confidence="The NAT findings are direct configuration evidence (at least 0.8). DNS must not be concluded."),
    Card(
        scenario_id="SCN-06-HUB-VPN-PSK-AND-ROUTE", incident_id="INC-20260426-406", title="Hub VPN changes break two tunnels",
        difficulty=["shared-device", "multi-site", "multiple-symptoms"],
        capabilities=["change history", "IPsec", "routing", "TLS (expiry note)"],
        sites=["NYC", "BLR"], unaffected_sites=["SIN"], affected_devices=["CORE-FW-01"], affected_services=["backup vpn"],
        affected_paths=["PATH-BLR-INTERNET", "PATH-NYC-INTERNET"],
        timeline=[Step(minute=-8, evidence="events:EVT-S06-001", what="New York PSK rotated on the hub only"),
                  Step(minute=-7, evidence="protocol_events:PE-S06-01", what="IKE authentication failures from New York"),
                  Step(minute=-4, evidence="events:EVT-S06-002", what="Bengaluru return route deleted"),
                  Step(minute=3, evidence="events:EVT-S06-004", what="Bengaluru tunnel probe fails")],
        root_cause="Two hub changes: PSK rotated for New York on CORE-FW-01 only, and the static route back to Bengaluru through its tunnel deleted.",
        symptoms=["NYC backup VPN down", "BLR backup VPN up but its probe fails"],
        secondary_effects=["One-way traffic in the Bengaluru tunnel"],
        decoys=[Decoy(clue="RADIUS certificate expires in 20 days", evidence=["certificates:CERT-RADIUS"],
                      why_misleading="Still valid; unrelated to IPsec, which uses pre-shared keys.", must_not_conclude=["TLS_CERTIFICATE_EXPIRED"])],
        phase_a=PhaseA(visible_in_core_data=False, acceptable_domains=["firewall"],
                       note="Primary paths are healthy; only the change log on CORE-FW-01 hints at the cause in the core data."),
        expected_findings=[Expected(engine="ipsec", code="IPSEC_AUTH_FAILURE", status="confirmed_fault", role="root", min_confidence=0.8),
                           Expected(engine="ipsec", code="IPSEC_ONE_WAY", status="possible_explanation", role="root", max_confidence=0.65)],
        forbidden_findings=["IPSEC_PROPOSAL_MISMATCH", "IPSEC_SELECTOR_MISMATCH", "TLS_CERTIFICATE_EXPIRED"],
        max_counts={"IPSEC_AUTH_FAILURE": 1},
        acceptable_roots=["IPSEC_AUTH_FAILURE@NYC", "IPSEC_ONE_WAY@BLR"],
        evidence=["events:EVT-S06-001", "events:EVT-S06-002", "protocol_events:PE-S06-01", "ipsec_tunnels:TUN-NYC-BACKUP-HUB", "ipsec_tunnels:TUN-BLR-BACKUP"],
        commands=[Command(device_id="CORE-FW-01", command="show vpn ike-sa", expect="No SA for 198.51.100.10"),
                  Command(device_id="NYC-RTR-01", command="show crypto ikev2 sa", expect="No READY SA"),
                  Command(device_id="BLR-RTR-01", command="show crypto ipsec sa", expect="Encaps rising, decaps zero")],
        confidence="Authentication failure for New York is confirmed by the hub's logs and must be attributed to New York only (Singapore's "
                   "healthy tunnel is the comparison). The one-way tunnel is a possible explanation (at most 0.65)."),
    Card(
        scenario_id="SCN-07-METRO-PATCH-CONGESTION", incident_id="INC-20260427-407", title="Patch push saturates the metro link",
        difficulty=["shared-device", "multi-site", "misleading-evidence", "cascading"],
        capabilities=["path health", "interface statistics", "capacity", "TCP", "QoS", "MTU", "suspicious traffic", "lateral movement"],
        sites=["NYC", "SIN", "BLR"], unaffected_sites=[], affected_devices=["CORE-SW-01", "DC1-FW-01"], affected_services=["application"],
        affected_paths=["PATH-BLR-APPLICATION", "PATH-NYC-APPLICATION", "PATH-SIN-APPLICATION"],
        timeline=[Step(minute=-1, evidence="events:EVT-S07-001", what="Session spike from 10.100.100.50 (patch distribution)"),
                  Step(minute=2, evidence="events:EVT-S07-002", what="Output drops on the metro link (queue full)")],
        root_cause="A mis-scheduled patch push from 10.100.100.50 saturates the metro link and WAN egress; congestion, not a physical fault.",
        symptoms=["ERP and file shares slow everywhere", "Calls fine"],
        secondary_effects=["TCP retransmissions and long round trips", "BULK class drops on WAN egress", "Fragmentation of jumbo transfers"],
        decoys=[Decoy(clue="The metro fibre had a fault last month", evidence=[ref(27, "CORE-SW-01:Te1/0/4", 5)],
                      why_misleading="No CRC or input errors: drops are output queue overflow at 98% utilisation.",
                      must_not_conclude=["PHYSICAL_LAYER_DEGRADATION_SUSPECTED"]),
                Decoy(clue="Gigabytes leave 10.100.100.50 to many hosts over SMB", evidence=["events:EVT-S07-001"],
                      why_misleading="It is the authorised backup/distribution server on the allowlist.",
                      must_not_conclude=["SUSPICIOUS_LARGE_UPLOAD", "LATERAL_ADMIN_FANOUT", "THREAT_CORRELATED_ACTIVITY"])],
        phase_a=PhaseA(visible_in_core_data=True, acceptable_domains=["shared_infrastructure", "interface_link", "wan_isp"],
                       note="Utilisation and output drops on the metro link are in the core data."),
        expected_findings=[Expected(engine="qos", code="QOS_LINK_SATURATION", status="confirmed_fault", role="root", min_confidence=0.7),
                           Expected(engine="tcp", code="TCP_RETRANSMISSION_HIGH", status="confirmed_fault", role="effect", min_confidence=0.7),
                           Expected(engine="tcp", code="TCP_RTT_INFLATION", status="confirmed_fault", role="effect", min_confidence=0.7),
                           Expected(engine="qos", code="QOS_CONGESTION_DROPS", status="confirmed_fault", role="effect", min_confidence=0.7)],
        acceptable_findings=["MTU_FRAGMENTATION"],
        forbidden_findings=["SUSPICIOUS_LARGE_UPLOAD", "LATERAL_ADMIN_FANOUT", "LATERAL_MOVEMENT_CHAIN", "THREAT_CORRELATED_ACTIVITY",
                            "QOS_PRIORITY_DROPS", "QOS_CLASSIFICATION_FAILURE"],
        acceptable_roots=["QOS_LINK_SATURATION"],
        evidence=["events:EVT-S07-001", "events:EVT-S07-002", ref(27, "CORE-SW-01:Te1/0/4", 5), ref(27, "DC1-FW-01:ethernet1/1", 15)],
        commands=[Command(device_id="CORE-SW-01", command="show interfaces Te1/0/4", expect="Load near 255/255, output drops, no CRC errors"),
                  Command(device_id="CORE-RTR-01", command="show policy-map interface Gi0/0/2 output", expect="BULK dropping, VOICE clean"),
                  Command(device_id="DC1-FW-01", command="show session info", expect="Session spike from 10.100.100.50")],
        confidence="Congestion is in the core data and is the cause: link saturation by the bulk transfer. TCP and QoS drop findings are its "
                   "effects and fragmentation is secondary. The bulk transfer must not raise a security indicator."),
    Card(
        scenario_id="SCN-08-SIN-ROGUE-IPV6-RA", incident_id="INC-20260428-408", title="Laptop advertising IPv6 routes",
        difficulty=["misleading-evidence", "security-uncertainty", "multi-layer"],
        capabilities=["IPv6", "DNS", "DHCP", "threat correlation"],
        sites=["SIN"], unaffected_sites=["NYC", "BLR"], affected_devices=["SIN-SW-01"], affected_services=["application", "internet"],
        affected_paths=["PATH-SIN-APPLICATION", "PATH-SIN-INTERNET"],
        timeline=[Step(minute=-14, evidence="events:EVT-S08-001", what="Unrelated DNS SERVFAILs for an external name (decoy)"),
                  Step(minute=-1, evidence="router_adverts:SIN|10|rogue@2026-04-28T08:59:00Z", what="First rogue router advertisement")],
        root_cause="A laptop with connection sharing sends IPv6 router advertisements on Singapore's user VLAN; IPv6 is black-holed.",
        symptoms=["Slow connections", "IPv6-only portal fails", "IPv4 works"],
        secondary_effects=["Dual-stack fallback delays"],
        decoys=[Decoy(clue="DNS SERVFAILs earlier at every site", evidence=["events:EVT-S08-001", "dns_queries:DNS-Q-S08-01"],
                      why_misleading="An upstream problem with one external name, at all sites, before the onset; internal names resolve.",
                      must_not_conclude=["dns"])],
        phase_a=PhaseA(visible_in_core_data=False, acceptable_domains=["switching"],
                       note="Router advertisements and dual-stack probes exist only in the protocol telemetry; the core data holds only the decoy."),
        expected_findings=[Expected(engine="ipv6", code="IPV6_ROGUE_RA", status="suspicious_indicator", role="root", max_confidence=SECURITY_MAX),
                           Expected(engine="ipv6", code="IPV6_REACHABILITY_LOSS", status="confirmed_fault", role="effect", min_confidence=0.7)],
        acceptable_findings=["THREAT_CORRELATED_ACTIVITY"],
        forbidden_findings=["IPV6_DEFAULT_ROUTE_MISSING", "IPV6_OSPFV3_ADJACENCY_DOWN", "IPV6_PREFIX_UNREACHABLE"],
        acceptable_roots=[],
        evidence=["events:EVT-S08-001", "router_adverts:SIN|10|rogue@2026-04-28T08:59:00Z", "dns_queries:DNS-Q-S08-11"],
        commands=[Command(device_id="SIN-SW-01", command="show ipv6 neighbors", expect="A router entry for a host MAC"),
                  Command(device_id="SIN-RTR-01", command="show ipv6 interface Gi0/0/1.10", expect="The router's own RA settings (healthy)"),
                  Command(device_id="SIN-SW-01", command="show mac address-table address 02:00:14:0a:00:07", expect="The laptop's access port")],
        confidence="The rogue advertisement is a suspicious indicator (likely a misconfigured laptop, intent unknown), at most 0.85; the IPv6 "
                   "loss is confirmed by probes."),
    Card(
        scenario_id="SCN-09-NYC-IGMP-QUERIER-WIFI", incident_id="INC-20260429-409", title="Multicast flood slows Wi-Fi",
        difficulty=["multi-layer", "cascading", "misleading-evidence"],
        capabilities=["change history", "multicast", "wireless", "interface statistics"],
        sites=["NYC"], unaffected_sites=["SIN", "BLR"], affected_devices=["NYC-SW-01"], affected_services=["wi-fi", "video"],
        affected_paths=["PATH-NYC-APPLICATION"],
        timeline=[Step(minute=-7, evidence="events:EVT-S09-001", what="IGMP snooping querier disabled on NYC-SW-01"),
                  Step(minute=2, evidence="events:EVT-S09-002", what="No querier: group entries ageing out"),
                  Step(minute=6, evidence="protocol_events:PE-S09-01", what="Radar event on NYC-AP-01 (decoy)")],
        root_cause="IGMP snooping querier disabled; the video floods VLAN 10 including the AP uplinks and consumes Wi-Fi airtime.",
        symptoms=["Wi-Fi very slow", "Video drops for wired viewers"],
        secondary_effects=["High channel utilisation and retries without RF interference"],
        decoys=[Decoy(clue="Radar event on NYC-AP-01", evidence=["protocol_events:PE-S09-01"],
                      why_misleading="One channel change; both APs and both bands are slow.", must_not_conclude=["WIFI_INTERFERENCE"])],
        phase_a=PhaseA(visible_in_core_data=False, acceptable_domains=["switching"],
                       note="Only the change log and uplink utilisation are in the core data."),
        expected_findings=[Expected(engine="multicast", code="MCAST_NO_QUERIER", status="confirmed_fault", role="root", min_confidence=0.8),
                           Expected(engine="wireless", code="WIFI_CO_CHANNEL", status="possible_explanation", role="effect", max_confidence=0.65)],
        acceptable_findings=["WIFI_DFS_CHANNEL_CHANGE"],
        forbidden_findings=["WIFI_INTERFERENCE", "MCAST_RP_MISMATCH", "MCAST_RPF_FAILURE"],
        acceptable_roots=["MCAST_NO_QUERIER"],
        evidence=["events:EVT-S09-001", "events:EVT-S09-002", "igmp_groups:NYC-SW-01|10|239.10.1.1", "protocol_events:PE-S09-01"],
        commands=[Command(device_id="NYC-SW-01", command="show ip igmp snooping querier", expect="No querier on VLAN 10"),
                  Command(device_id="NYC-SW-01", command="show ip igmp snooping groups vlan 10", expect="Entries missing or ageing"),
                  Command(device_id="CORE-WLC-01", command="show ap auto-rf dot11 5ghz", expect="High utilisation, low interference")],
        confidence="The missing querier is direct configuration evidence (at least 0.8); the Wi-Fi contention is a possible explanation of the "
                   "slowness (at most 0.65); interference must not be concluded."),
    Card(
        scenario_id="SCN-10-INSPECTION-CA-AND-SECURITY", incident_id="INC-20260430-410", title="Inspection CA, scanner and password spraying",
        difficulty=["multiple-symptoms", "multi-site", "security-uncertainty", "misleading-evidence"],
        capabilities=["TLS", "suspicious traffic", "lateral movement", "threat correlation", "firewall"],
        sites=["NYC", "SIN", "BLR"], unaffected_sites=[], affected_devices=["CORE-FW-01"], affected_services=["internet"],
        affected_paths=["PATH-BLR-INTERNET", "PATH-NYC-INTERNET", "PATH-SIN-INTERNET"],
        timeline=[Step(minute=-12, evidence="events:EVT-S10-001", what="Inspection certificate changed to 'Corp Inspection CA 2027'"),
                  Step(minute=-9, evidence="ids_alerts:IDS-S10-01", what="Port sweep from 10.100.100.61"),
                  Step(minute=3, evidence="ids_alerts:IDS-S10-02", what="Password spraying from a Bengaluru desktop")],
        root_cause="New inspection CA not trusted by clients; separately an unregistered scanner and a spraying desktop.",
        symptoms=["Certificate warnings on external sites at every office", "ERP fine"],
        secondary_effects=["IDS alerts"],
        decoys=[Decoy(clue="Port sweep from a data-centre address", evidence=["ids_alerts:IDS-S10-01"],
                      why_misleading="It is IT's new scanner, not yet allowlisted: suspicious from the data alone, and it must not be merged with "
                                     "the Bengaluru desktop's activity.", must_not_conclude=["confirmed attack"])],
        phase_a=PhaseA(visible_in_core_data=False, acceptable_domains=["firewall"],
                       note="TLS handshakes and security telemetry are not in the core data."),
        expected_findings=[Expected(engine="tls", code="TLS_INSPECTION_UNTRUSTED", status="confirmed_fault", role="root", min_confidence=0.8),
                           Expected(engine="traffic", code="SUSPICIOUS_PORT_SCAN", status="suspicious_indicator", role="indicator",
                                    max_confidence=SECURITY_MAX),
                           Expected(engine="lateral", code="LATERAL_CREDENTIAL_SPRAY", status="suspicious_indicator", role="indicator",
                                    max_confidence=SECURITY_MAX),
                           Expected(engine="threats", code="THREAT_CORRELATED_ACTIVITY", status="suspicious_indicator", role="indicator",
                                    max_confidence=SECURITY_MAX)],
        forbidden_findings=["TLS_CERTIFICATE_EXPIRED", "TLS_UNEXPECTED_CERTIFICATE", "LATERAL_ADMIN_FANOUT", "LATERAL_MOVEMENT_CHAIN"],
        acceptable_roots=["TLS_INSPECTION_UNTRUSTED"],
        threat_hosts=["10.100.100.61", "10.30.10.103"],
        evidence=["events:EVT-S10-001", "ids_alerts:IDS-S10-01", "ids_alerts:IDS-S10-02"],
        commands=[Command(device_id="CORE-FW-01", command="show system setting ssl-decrypt setting", expect="Forward-proxy CA 'Corp Inspection CA 2027'"),
                  Command(device_id="CORE-FW-01", command="show log threat", expect="Scan and authentication entries"),
                  Command(device_id="BLR-SW-01", command="show ip arp 10.30.10.103", expect="The spraying desktop's port and MAC")],
        confidence="The CA problem is confirmed (at least 0.8). Both security clusters stay suspicious (at most 0.85, never confirmed, no "
                   "attribution) and separate."),
)
CARD_BY_ID = {card.scenario_id: card for card in CARDS}


def write_cards(directory: Path = CARD_DIR) -> list[str]:
    directory.mkdir(parents=True, exist_ok=True)
    for card in CARDS:
        (directory / f"{card.scenario_id}.json").write_text(json.dumps(card.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
                                                            encoding="utf-8")
    return [card.scenario_id for card in CARDS]


if __name__ == "__main__":
    print("\n".join(write_cards()))
