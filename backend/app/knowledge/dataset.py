import json
from datetime import datetime, timezone
from pathlib import Path

from app.engine.schema import FaultDomain
from app.knowledge.models import (
    Applicability,
    CommandSpec,
    DecisionCondition,
    DiagnosticProcedure,
    DiagnosticStep,
    DocumentType,
    EscalationCriterion,
    EvidenceRequirement,
    KnowledgeBase,
    KnowledgeCategory,
    KnowledgeDocument,
    NetworkLayer,
    Platform,
    Playbook,
    Runbook,
    SourceReference,
    ToolReference,
)
from app.knowledge.repository import DATA_FILE
from app.network.models import DeviceType, IncidentPriority, PathService

CREATED = datetime(2026, 2, 1, tzinfo=timezone.utc)
UPDATED = datetime(2026, 2, 15, tzinfo=timezone.utc)
PLAYBOOK_SOURCE = "SRC-SYNTHETIC-PLAYBOOKS"
RUNBOOK_SOURCE = "SRC-SYNTHETIC-RUNBOOKS"
REFERENCE_SOURCE = "SRC-SYNTHETIC-REFERENCE"
ROUTER, SWITCH, FIREWALL, SERVER = DeviceType.ROUTER, DeviceType.SWITCH, DeviceType.FIREWALL, DeviceType.SERVER
CISCO, PANOS, LINUX = Platform.CISCO_IOS_XE, Platform.PAN_OS, Platform.LINUX
P1, P2, P3 = IncidentPriority.P1, IncidentPriority.P2, IncidentPriority.P3
SINCE = '--since "1 hour ago"'
STAMPS = {"version": "1.0.0", "created_at": CREATED, "updated_at": UPDATED}


def cmd(text: str, platform: Platform, types: tuple[DeviceType, ...], purpose: str) -> CommandSpec:
    return CommandSpec(text=text, platform=platform, device_types=list(types), purpose=purpose)


def tool(name: str, purpose: str) -> ToolReference:
    return ToolReference(tool=name, purpose=purpose)


def evidence(requirement_id: str, description: str, codes: list[str], tool_name: str, purpose: str) -> EvidenceRequirement:
    return EvidenceRequirement(requirement_id=requirement_id, description=description, codes=codes, tool=tool(tool_name, purpose))


def step(order: int, action: str, expected: str, tool_ref: ToolReference | None = None,
         commands: list[CommandSpec] | None = None) -> DiagnosticStep:
    return DiagnosticStep(order=order, action=action, tool=tool_ref, commands=commands or [], expected_observation=expected)


def decide(condition: str, conclusion: str, next_record_id: str | None = None) -> DecisionCondition:
    return DecisionCondition(condition=condition, conclusion=conclusion, next_record_id=next_record_id)


def escalate(condition: str, team: str, priority: IncidentPriority) -> EscalationCriterion:
    return EscalationCriterion(condition=condition, team=team, priority=priority)


INTERFACE = cmd("show interfaces {interface}", CISCO, (ROUTER, SWITCH), "Interface state, line protocol and error counters")
PING_PEER = cmd("ping {peer_ip} source {interface} repeat 100", CISCO, (ROUTER,), "Loss and latency to the directly connected peer")
BGP_SUMMARY = cmd("show ip bgp summary", CISCO, (ROUTER,), "BGP session state and prefixes received")
OSPF_NEIGHBOR = cmd("show ip ospf neighbor", CISCO, (ROUTER, SWITCH), "OSPF neighbor list and adjacency state")
OSPF_INTERFACE = cmd("show ip ospf interface {interface}", CISCO, (ROUTER, SWITCH), "OSPF interface parameters including MTU and timers")
ROUTE = cmd("show ip route {prefix}", CISCO, (ROUTER, SWITCH), "Routing table entry and next hop for a prefix")
LOGGING = cmd("show logging", CISCO, (ROUTER, SWITCH), "Recent device log messages")
ENV_POWER = cmd("show environment power", CISCO, (ROUTER, SWITCH), "Power supply status, via out-of-band console")
AUTH_SESSIONS = cmd("show authentication sessions interface {interface} details", CISCO, (SWITCH,), "802.1X session state for a port")
AAA_SERVERS = cmd("show aaa servers", CISCO, (SWITCH,), "RADIUS server state and response counters")
SECURITY_POLICY = cmd("show running security-policy", PANOS, (FIREWALL,), "Active security rule order")
DENY_LOG = cmd("show log traffic action equal deny", PANOS, (FIREWALL,), "Recently denied traffic and matching rules")
DNS_ZONE = cmd("rndc zonestatus {zone}", LINUX, (SERVER,), "Zone load status on the DNS server")
DNS_QUERY = cmd("dig @{dns_server} {domain} A", LINUX, (SERVER,), "Reproduce a name resolution against one server")
DNS_LOG = cmd(f"journalctl -u named {SINCE}", LINUX, (SERVER,), "DNS server log messages")
KEA_STATUS = cmd("keactrl status", LINUX, (SERVER,), "DHCP service process state")
KEA_LOG = cmd(f"journalctl -u kea-dhcp4 {SINCE}", LINUX, (SERVER,), "DHCP allocation failures and declines")
RADIUS_LOG = cmd(f"journalctl -u freeradius {SINCE}", LINUX, (SERVER,), "RADIUS request rejections")

WAN_TEAM = "WAN Operations / carrier liaison"
ROUTING_TEAM = "Network Engineering - Routing"
SECURITY_TEAM = "Network Security Operations"
NAC_TEAM = "Network Access Control team"
SERVICES_TEAM = "Infrastructure Services - DHCP/DNS"
CORE_TEAM = "Network Operations - Core and Data Centre"
TRIAGE_TEAM = "Network Operations - L2 triage"


def playbooks() -> list[Playbook]:
    reach = tool("check_network_reachability", "Locate where the forward path stops")
    return [
        Playbook(
            record_id="PB-WAN-FAILURE", title="WAN circuit failure at a branch", category=KnowledgeCategory.CONNECTIVITY,
            description="A branch loses all connectivity to the core because its WAN circuit or WAN edge interface is down.",
            fault_domains=[FaultDomain.WAN_ISP], layers=[NetworkLayer.PHYSICAL, NetworkLayer.NETWORK],
            applicability=Applicability(device_types=[ROUTER]), tags=["wan", "circuit", "branch-outage", "bgp"],
            symptoms=["All users at one branch lose access to every corporate service", "Branch router unreachable from monitoring",
                      "Internet and ERP both unavailable at the same site"],
            indicator_codes=["NO_ROUTE_TO_DESTINATION", "LINK_DOWN_AT_FAILURE_POINT", "INTERFACE_DOWN", "ADJACENCY_FAILED",
                             "ADJACENCY_LOSS_FOLLOWS_INTERFACE_DOWN", "CARRIER_LOSS", "LINK_DOWN", "BGP_NEIGHBOR_DOWN"],
            possible_causes=["Carrier circuit outage or loss of signal", "WAN edge interface or optic failure",
                             "Upstream core router failure affecting the circuit termination"],
            required_evidence=[
                evidence("EV-WAN-PATH", "Branch router has no route towards the data centre", ["NO_ROUTE_TO_DESTINATION"],
                         "check_network_reachability", "Confirm where forwarding stops"),
                evidence("EV-WAN-LINK", "WAN interface reports operational status down", ["LINK_DOWN_AT_FAILURE_POINT", "INTERFACE_DOWN"],
                         "get_interface_stats", "Confirm the physical state of the WAN link"),
                evidence("EV-WAN-PEER", "Core-side termination is alive", ["DEVICE_AVAILABLE", "DEVICE_AVAILABLE_WITH_FAULTS"],
                         "check_device_availability", "Exclude an upstream device failure"),
            ],
            steps=[
                step(1, "Evaluate reachability from the branch switch to a data centre server", "Path stops at the branch WAN edge", reach),
                step(2, "Inspect the WAN interface state on the branch router", "Line protocol down with carrier loss",
                     tool("get_interface_stats", "Interface state"), [INTERFACE, PING_PEER]),
                step(3, "Check routing adjacency over the WAN link", "BGP or OSPF neighbor down after the interface failure",
                     tool("analyze_routing_adjacency", "Adjacency state"), [BGP_SUMMARY]),
                step(4, "Confirm the core-side device is still reporting telemetry", "Core router available with one interface down",
                     tool("check_device_availability", "Upstream device state")),
            ],
            decisions=[
                decide("WAN interface down and the core peer is available", "Treat as a carrier or circuit fault and engage the provider"),
                decide("Several branches fail at once through the same core router", "Investigate the shared upstream device first",
                       "PB-SHARED-DEVICE-FAILURE"),
                decide("Interfaces up but routes missing", "Investigate routing adjacency instead", "PB-OSPF-ADJACENCY-FAILURE"),
            ],
            escalation=[escalate("Circuit down for more than 15 minutes with carrier loss logged", WAN_TEAM, P1)],
            related_ids=["PB-SHARED-DEVICE-FAILURE", "PB-PACKET-LOSS", "DP-INTERFACE-HEALTH"],
            source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
        Playbook(
            record_id="PB-PACKET-LOSS", title="Packet loss and degradation on a WAN circuit", category=KnowledgeCategory.PERFORMANCE,
            description="Users at a branch report slowness and choppy calls while the WAN circuit stays up but drops packets.",
            fault_domains=[FaultDomain.WAN_ISP, FaultDomain.INTERFACE_LINK], layers=[NetworkLayer.PHYSICAL, NetworkLayer.DATA_LINK],
            applicability=Applicability(device_types=[ROUTER]), tags=["packet-loss", "latency", "crc", "degradation"],
            symptoms=["Slow application response at one branch", "Choppy or dropped voice calls", "Slow or intermittent name resolution"],
            indicator_codes=["PACKET_LOSS_MEASURED", "PHYSICAL_LAYER_DEGRADATION_SUSPECTED", "HIGH_ERROR_COUNT", "HIGH_DROP_COUNT",
                             "ERROR_COUNT_INCREASE", "HIGH_LATENCY", "INTERFACE_ERRORS", "SLA_THRESHOLD_EXCEEDED"],
            possible_causes=["Physical degradation on the carrier circuit", "Faulty optic, cable or interface",
                             "Congestion on an undersized circuit"],
            required_evidence=[
                evidence("EV-LOSS-MEASURED", "Packet loss above threshold on the WAN interface", ["PACKET_LOSS_MEASURED"],
                         "analyze_packet_loss", "Measure the loss pattern"),
                evidence("EV-LOSS-ERRORS", "Interface errors rise alongside the loss", ["HIGH_ERROR_COUNT", "ERROR_COUNT_INCREASE"],
                         "analyze_interface_errors", "Distinguish physical faults from congestion"),
            ],
            steps=[
                step(1, "Analyze packet loss on the branch WAN interface", "Sustained loss above 1 percent",
                     tool("analyze_packet_loss", "Loss pattern"), [PING_PEER]),
                step(2, "Analyze interface errors and drops on the same interface", "CRC and input errors rising with the loss",
                     tool("analyze_interface_errors", "Error pattern"), [INTERFACE]),
                step(3, "Compare utilization against the loss samples", "Utilization below congestion levels",
                     tool("get_interface_stats", "Utilization context")),
            ],
            decisions=[
                decide("Loss coincides with rising errors and normal utilization", "Treat as physical or circuit degradation"),
                decide("Loss coincides with utilization above 90 percent", "Treat as congestion and review capacity"),
                decide("Loss measured only while the interface is down", "Treat as an outage", "PB-WAN-FAILURE"),
            ],
            escalation=[escalate("Sustained loss above 5 percent for more than 10 minutes", WAN_TEAM, P2)],
            related_ids=["PB-WAN-FAILURE", "DP-INTERFACE-HEALTH"], source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
        Playbook(
            record_id="PB-OSPF-ADJACENCY-FAILURE", title="OSPF adjacency failure with links up", category=KnowledgeCategory.ROUTING,
            description="A site loses routes because an OSPF adjacency is stuck or down even though the physical link reports up.",
            fault_domains=[FaultDomain.ROUTING], layers=[NetworkLayer.NETWORK],
            applicability=Applicability(device_types=[ROUTER, SWITCH]), tags=["ospf", "adjacency", "mtu", "routing"],
            symptoms=["Site cannot reach data centre applications while the WAN circuit shows up",
                      "Routes to a site disappear from the core", "Recent configuration change on a WAN edge router"],
            indicator_codes=["ADJACENCY_STALLED", "ADJACENCY_FAILED", "CONTROL_PLANE_FAILURE_SUSPECTED", "NEIGHBOR_NOT_ESTABLISHED",
                             "ROUTES_WITHDRAWN", "OSPF_ADJACENCY_DOWN", "OSPF_MTU_MISMATCH", "MTU_CHANGE", "CONFIG_CHANGE"],
            possible_causes=["Interface MTU mismatch between neighbors", "Area, network type or timer mismatch",
                             "Authentication mismatch after a configuration change"],
            required_evidence=[
                evidence("EV-OSPF-STATE", "Adjacency not FULL while both interfaces are up",
                         ["ADJACENCY_STALLED", "CONTROL_PLANE_FAILURE_SUSPECTED"], "analyze_routing_adjacency", "Adjacency state"),
                evidence("EV-OSPF-ROUTES", "Routes withdrawn at the time of the adjacency change", ["ROUTES_WITHDRAWN", "NO_ROUTE_TO_DESTINATION"],
                         "get_routing_state", "Routing impact"),
                evidence("EV-OSPF-CHANGE", "Configuration or MTU change shortly before the failure", ["CONFIG_CHANGE", "MTU_CHANGE"],
                         "get_device_logs", "Preceding change"),
            ],
            steps=[
                step(1, "Analyze routing adjacencies on the site WAN edge", "Adjacency stuck in EXSTART or similar with links up",
                     tool("analyze_routing_adjacency", "Adjacency state"), [OSPF_NEIGHBOR]),
                step(2, "Compare OSPF interface parameters on both ends", "MTU or timers differ between neighbors",
                     commands=[OSPF_INTERFACE]),
                step(3, "Review device logs for recent changes", "Configuration change shortly before the adjacency dropped",
                     tool("get_device_logs", "Change history"), [LOGGING]),
            ],
            decisions=[
                decide("Adjacency stalled with interfaces up and an MTU difference", "Treat as a parameter mismatch introduced by the change"),
                decide("Interfaces down on the adjacency link", "Treat as a link failure", "PB-WAN-FAILURE"),
            ],
            escalation=[escalate("Routes withdrawn for a whole site", ROUTING_TEAM, P1)],
            related_ids=["PB-WAN-FAILURE", "DP-ROUTING-VERIFICATION"], source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
        Playbook(
            record_id="PB-FIREWALL-BLOCKING", title="Application traffic blocked by firewall policy", category=KnowledgeCategory.SECURITY,
            description="One application fails for a site while the routed path stays healthy, because a firewall rule denies the traffic.",
            fault_domains=[FaultDomain.FIREWALL], layers=[NetworkLayer.TRANSPORT, NetworkLayer.APPLICATION],
            applicability=Applicability(device_types=[FIREWALL]), tags=["firewall", "policy", "deny", "erp"],
            symptoms=["One application portal times out for a single site", "Denied sessions for the affected application",
                      "Problem started after a security policy change"],
            indicator_codes=["TRAFFIC_DENIED", "RULE_MODIFIED_IN_RANGE", "POLICY_CHANGE", "PATH_REACHABLE"],
            possible_causes=["New or reordered deny rule matching the traffic", "Overly broad source or destination object",
                             "Rule shadowing after a policy commit"],
            required_evidence=[
                evidence("EV-FW-DENY", "Flows to the application denied by a specific rule", ["TRAFFIC_DENIED"],
                         "get_firewall_logs", "Identify the denying rule"),
                evidence("EV-FW-CHANGE", "Denying rule modified shortly before the incident", ["RULE_MODIFIED_IN_RANGE"],
                         "get_firewall_logs", "Correlate with policy changes"),
                evidence("EV-FW-L3", "Layer-3 path to the application is reachable", ["PATH_REACHABLE"],
                         "check_network_reachability", "Exclude routing faults"),
            ],
            steps=[
                step(1, "Confirm the layer-3 path from the site to the application", "Path reachable", reach),
                step(2, "Query firewall logs for the site and application addresses", "Denied flows from the affected site",
                     tool("get_firewall_logs", "Deny events"), [DENY_LOG]),
                step(3, "Review the rule order around the matching rule", "Deny rule placed ahead of the expected allow rule",
                     commands=[SECURITY_POLICY]),
            ],
            decisions=[
                decide("Denies by a recently modified rule and a reachable path", "Treat as a firewall policy fault"),
                decide("No denies and the path is unreachable", "Investigate connectivity", "PB-WAN-FAILURE"),
            ],
            escalation=[escalate("Business application denied for a whole site", SECURITY_TEAM, P2)],
            related_ids=["DP-FIREWALL-POLICY"], source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
        Playbook(
            record_id="PB-DHCP-ALLOCATION-FAILURE", title="DHCP allocation failure and pool exhaustion",
            category=KnowledgeCategory.NETWORK_SERVICES,
            description="New clients at a site receive no address because the DHCP pool is exhausted or allocations fail.",
            fault_domains=[FaultDomain.DHCP], layers=[NetworkLayer.APPLICATION],
            applicability=Applicability(device_types=[SERVER], services=[PathService.DHCP]), tags=["dhcp", "lease", "pool", "ip-address"],
            symptoms=["New laptops show a self-assigned 169.254 address", "Existing users unaffected", "Cannot obtain an IP address"],
            indicator_codes=["DHCP_POOL_EXHAUSTED", "DHCP_ALLOCATION_FAILURES", "DHCP_IP_CONFLICTS", "DHCP_POOL_HIGH_UTILIZATION"],
            possible_causes=["Pool too small for the number of clients", "Addresses held in conflict state after DHCPDECLINE",
                             "Lease time too long for the client turnover"],
            required_evidence=[
                evidence("EV-DHCP-POOL", "Pool utilization at 100 percent", ["DHCP_POOL_EXHAUSTED"], "get_dhcp_dns_status", "Pool state"),
                evidence("EV-DHCP-FAIL", "Allocation failures for new clients", ["DHCP_ALLOCATION_FAILURES"], "get_dhcp_dns_status",
                         "Allocation outcome"),
                evidence("EV-DHCP-L3", "Path from the site to the DHCP server is reachable", ["PATH_REACHABLE"],
                         "check_network_reachability", "Exclude relay path faults"),
            ],
            steps=[
                step(1, "Check DHCP and DNS status for the site", "Pool exhausted with allocation failures",
                     tool("get_dhcp_dns_status", "Pool and lease state")),
                step(2, "Confirm the DHCP service is running", "Service active", commands=[KEA_STATUS]),
                step(3, "Review server logs for allocation failures and declines", "No-free-lease and DHCPDECLINE messages",
                     commands=[KEA_LOG]),
            ],
            decisions=[
                decide("Pool exhausted while the path is reachable", "Treat as a DHCP capacity fault"),
                decide("No transactions from the site at all", "Investigate site connectivity or access control", "PB-VLAN-AUTHENTICATION-FAILURE"),
            ],
            escalation=[escalate("Pool exhausted for user VLAN", SERVICES_TEAM, P3)],
            related_ids=["DP-DNS-DHCP-SERVICES"], source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
        Playbook(
            record_id="PB-DNS-RESOLUTION-FAILURE", title="DNS resolution failure for internal names",
            category=KnowledgeCategory.NETWORK_SERVICES,
            description="Users cannot reach internal services by name because a DNS server fails to resolve the internal zone.",
            fault_domains=[FaultDomain.DNS], layers=[NetworkLayer.APPLICATION],
            applicability=Applicability(device_types=[SERVER], services=[PathService.DNS]), tags=["dns", "servfail", "zone", "name-resolution"],
            symptoms=["Internal host names do not resolve", "Internet sites work", "Access by IP address works"],
            indicator_codes=["DNS_SERVFAIL", "DNS_SERVER_RESOLUTION_FAULT_SUSPECTED", "ZONE_LOAD_FAILURE", "ZONE_NOT_LOADED",
                             "DNS_LOOKUP_FAILURE"],
            possible_causes=["Zone file failed to load after a change", "Server process unhealthy", "Forwarder or delegation problem"],
            required_evidence=[
                evidence("EV-DNS-SERVFAIL", "SERVFAIL responses from one server", ["DNS_SERVFAIL"], "get_dhcp_dns_status", "Query results"),
                evidence("EV-DNS-PEER", "Other servers answer successfully", ["DNS_SERVER_RESOLUTION_FAULT_SUSPECTED"],
                         "get_dhcp_dns_status", "Isolate the faulty server"),
            ],
            steps=[
                step(1, "Check DNS query results for affected sites", "SERVFAIL from one server for internal names",
                     tool("get_dhcp_dns_status", "Query results")),
                step(2, "Reproduce the failing query against each server", "SERVFAIL from the faulty server only", commands=[DNS_QUERY]),
                step(3, "Inspect zone status and server logs", "Zone not loaded due to errors", commands=[DNS_ZONE, DNS_LOG]),
            ],
            decisions=[
                decide("SERVFAIL from one server while others answer", "Treat as a server-side resolution fault"),
                decide("All queries from a site time out", "Investigate connectivity from the site", "PB-WAN-FAILURE"),
            ],
            escalation=[escalate("Internal zone unavailable on the primary server", SERVICES_TEAM, P2)],
            related_ids=["DP-DNS-DHCP-SERVICES"], source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
        Playbook(
            record_id="PB-VLAN-AUTHENTICATION-FAILURE", title="802.1X authentication failure on access ports",
            category=KnowledgeCategory.ACCESS_CONTROL,
            description="Wired clients at a site get no network access because 802.1X authentication fails between the switch and RADIUS.",
            fault_domains=[FaultDomain.VLAN_AUTHENTICATION], layers=[NetworkLayer.DATA_LINK],
            applicability=Applicability(device_types=[SWITCH, SERVER], services=[PathService.AUTHENTICATION]),
            tags=["dot1x", "radius", "authentication", "access-port"],
            symptoms=["Wired desktops show authentication failed", "No network on wired desktops", "IP phones unaffected"],
            indicator_codes=["DOT1X_AUTH_FAILURE", "PORT_UNAUTHORIZED", "RADIUS_SERVER_DEAD", "RADIUS_INVALID_AUTHENTICATOR",
                             "DHCP_TRANSACTIONS_STOPPED"],
            possible_causes=["RADIUS shared secret mismatch", "RADIUS server unreachable or rejecting requests",
                             "Port authentication configuration change"],
            required_evidence=[
                evidence("EV-AUTH-SWITCH", "802.1X failures on the access switch", ["DOT1X_AUTH_FAILURE", "PORT_UNAUTHORIZED"],
                         "get_device_logs", "Access switch events"),
                evidence("EV-AUTH-RADIUS", "RADIUS rejections or dead-server events", ["RADIUS_INVALID_AUTHENTICATOR", "RADIUS_SERVER_DEAD"],
                         "get_device_logs", "RADIUS side"),
                evidence("EV-AUTH-L3", "Path from the switch to the RADIUS server is reachable", ["PATH_REACHABLE"],
                         "check_network_reachability", "Exclude connectivity faults"),
            ],
            steps=[
                step(1, "Review warnings on the access switch", "DOT1X failures and unauthorized ports",
                     tool("get_device_logs", "Switch events"), [AUTH_SESSIONS, AAA_SERVERS]),
                step(2, "Review the RADIUS server logs", "Requests dropped for an invalid authenticator", commands=[RADIUS_LOG]),
                step(3, "Confirm reachability between the switch and the RADIUS server", "Path reachable", reach),
            ],
            decisions=[
                decide("Server rejects requests for an invalid authenticator", "Treat as a shared secret mismatch"),
                decide("Path to the RADIUS server unreachable", "Investigate connectivity", "PB-WAN-FAILURE"),
            ],
            escalation=[escalate("Wired access lost for a site", NAC_TEAM, P2)],
            related_ids=["PB-DHCP-ALLOCATION-FAILURE"], source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
        Playbook(
            record_id="PB-SHARED-DEVICE-FAILURE", title="Shared upstream device failure affecting several sites",
            category=KnowledgeCategory.INFRASTRUCTURE,
            description="Several sites fail at the same time because a shared core device on their common path has failed.",
            fault_domains=[FaultDomain.SHARED_INFRASTRUCTURE, FaultDomain.NETWORK_DEVICE_FAILURE],
            layers=[NetworkLayer.PHYSICAL, NetworkLayer.NETWORK], applicability=Applicability(device_types=[ROUTER, SWITCH]),
            tags=["shared-device", "core", "multi-site", "power"],
            symptoms=["Two or more branches lose connectivity simultaneously", "Several sites offline through one core router",
                      "Core router not responding to monitoring"],
            indicator_codes=["TELEMETRY_GAP", "PEER_LINKS_DOWN", "PEER_ADJACENCIES_LOST", "DEVICE_FAILURE_LIKELY", "DEVICE_UNREACHABLE",
                             "POWER_SUPPLY_FAILURE", "SYSTEM_SHUTDOWN", "NO_ROUTE_TO_DESTINATION"],
            possible_causes=["Power failure on a shared core router", "Hardware or software crash of a shared device",
                             "Failure of the shared aggregation link"],
            required_evidence=[
                evidence("EV-SHARED-GAP", "Telemetry gap from the shared device", ["TELEMETRY_GAP"], "check_device_availability",
                         "Device telemetry"),
                evidence("EV-SHARED-PEERS", "Peers report links to the device down", ["PEER_LINKS_DOWN", "PEER_ADJACENCIES_LOST"],
                         "check_device_availability", "Independent peer evidence"),
                evidence("EV-SHARED-PATHS", "Affected paths share the device", ["NO_ROUTE_TO_DESTINATION"], "check_network_reachability",
                         "Path correlation"),
            ],
            steps=[
                step(1, "Evaluate reachability for every affected site", "Paths fail at branches served by the same core router", reach),
                step(2, "Identify devices common to the affected paths", "One shared upstream device",
                     tool("analyze_network_dependencies", "Shared dependencies")),
                step(3, "Check availability of the shared device", "Telemetry gap corroborated by peers",
                     tool("check_device_availability", "Device state"), [ENV_POWER]),
                step(4, "Confirm peer interfaces facing the device", "Peer interfaces down", commands=[INTERFACE]),
            ],
            decisions=[
                decide("Shared device silent and all peers report links down", "Treat as a shared device failure, not separate branch faults"),
                decide("Shared device reporting telemetry", "Investigate each branch circuit separately", "PB-WAN-FAILURE"),
            ],
            escalation=[escalate("Shared core device unavailable", CORE_TEAM, P1)],
            related_ids=["PB-WAN-FAILURE", "DP-TOPOLOGY-DEPENDENCIES"], source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
        Playbook(
            record_id="PB-GENERAL-TRIAGE", title="General network incident triage", category=KnowledgeCategory.GENERAL,
            description="Structured first steps for any network incident before a fault domain is known.",
            layers=[NetworkLayer.PHYSICAL, NetworkLayer.NETWORK, NetworkLayer.APPLICATION], tags=["triage", "general", "first-response"],
            symptoms=["Users report a network problem with unclear scope", "Intermittent or unexplained slowness",
                      "Unknown cause of service disruption"],
            possible_causes=["Connectivity failure", "Service failure", "Performance degradation", "Policy or access control change"],
            required_evidence=[
                evidence("EV-TRIAGE-PATH", "Reachability outcome for the affected site", ["PATH_REACHABLE", "PATH_UNREACHABLE"],
                         "check_network_reachability", "Establish whether the path works"),
            ],
            steps=[
                step(1, "Establish the affected sites, services and start time", "Scope and onset recorded"),
                step(2, "Evaluate reachability from the site to the affected service", "Path reachable or a failure point identified", reach),
                step(3, "Check site DHCP and DNS status", "Service health for the site", tool("get_dhcp_dns_status", "Service health")),
            ],
            decisions=[
                decide("Path unreachable", "Follow connectivity playbooks", "PB-WAN-FAILURE"),
                decide("Path reachable but a service fails", "Follow service playbooks", "DP-DNS-DHCP-SERVICES"),
            ],
            escalation=[escalate("No fault domain identified after triage", TRIAGE_TEAM, P3)],
            related_ids=["DP-TOPOLOGY-DEPENDENCIES"], source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
        Playbook(
            record_id="PB-TOPOLOGY-INVESTIGATION", title="Topology and dependency investigation", category=KnowledgeCategory.GENERAL,
            description="Use topology data to find upstream, downstream and shared dependencies before attributing a fault.",
            layers=[NetworkLayer.NETWORK], tags=["topology", "dependencies", "shared-path"],
            symptoms=["Multiple sites or services affected", "Unclear which device sits on the failing path"],
            indicator_codes=["PATH_UNREACHABLE"],
            possible_causes=["Shared upstream failure", "Single-site failure mistaken for a wider outage"],
            required_evidence=[
                evidence("EV-TOPO-PATHS", "Affected paths and their common devices", ["PATH_UNREACHABLE", "NO_ROUTE_TO_DESTINATION"],
                         "check_network_reachability", "Path correlation"),
            ],
            steps=[
                step(1, "Retrieve topology for each affected site", "Devices, links and dependencies listed",
                     tool("get_topology", "Site topology")),
                step(2, "Compare dependencies across affected sites", "Shared devices identified",
                     tool("analyze_network_dependencies", "Shared dependencies")),
            ],
            decisions=[decide("A device is common to all affected paths", "Investigate that device first", "PB-SHARED-DEVICE-FAILURE")],
            escalation=[escalate("Shared dependency suspected but unverified", CORE_TEAM, P2)],
            related_ids=["DP-TOPOLOGY-DEPENDENCIES"], source_ids=[PLAYBOOK_SOURCE], **STAMPS,
        ),
    ]


def runbooks() -> list[Runbook]:
    branch = [
        Runbook(
            record_id=f"RB-{site}-BRANCH", title=f"{name} branch WAN edge and access runbook",
            applicability=Applicability(site_ids=[site], device_types=[ROUTER, SWITCH]),
            fault_domains=[FaultDomain.WAN_ISP, FaultDomain.ROUTING, FaultDomain.VLAN_AUTHENTICATION],
            tags=["branch", site.lower(), protocol],
            context=f"The {name} branch connects through {site}-RTR-01 over a single {protocol.upper()} WAN circuit; "
                    f"users attach to {site}-SW-01 with 802.1X on the user VLAN.",
            preconditions=["Out-of-band or console access to the branch devices", "Carrier contact details for the WAN circuit"],
            procedures=[
                step(1, "Verify the WAN interface and peer reachability on the branch router", "Interface up with no loss",
                     tool("get_interface_stats", "WAN interface"), [INTERFACE, PING_PEER]),
                step(2, f"Verify the {protocol.upper()} session to the core", "Session established",
                     tool("analyze_routing_adjacency", "Adjacency"), [BGP_SUMMARY if protocol == "bgp" else OSPF_NEIGHBOR]),
                step(3, "Verify 802.1X sessions on user ports", "Ports authorized", commands=[AUTH_SESSIONS]),
            ],
            verification=["Users can reach the ERP service", "Branch router routing table contains the data centre prefix"],
            escalation=[escalate("WAN circuit down", WAN_TEAM, P1), escalate("802.1X failing on several ports", NAC_TEAM, P2)],
            related_ids=["PB-WAN-FAILURE", "PB-VLAN-AUTHENTICATION-FAILURE"], source_ids=[RUNBOOK_SOURCE], **STAMPS,
        )
        for site, name, protocol in (("NYC", "New York", "bgp"), ("SIN", "Singapore", "bgp"), ("BLR", "Bengaluru", "ospf"))
    ]
    return branch + [
        Runbook(
            record_id="RB-CORE-NETWORK", title="Core network runbook",
            applicability=Applicability(site_ids=["CORE"], device_types=[ROUTER, SWITCH, FIREWALL]),
            fault_domains=[FaultDomain.SHARED_INFRASTRUCTURE, FaultDomain.NETWORK_DEVICE_FAILURE, FaultDomain.ROUTING],
            tags=["core", "shared-device", "ospf"],
            context="The core terminates all branch WAN circuits on CORE-RTR-01 and CORE-RTR-02, aggregated by CORE-SW-01.",
            preconditions=["Console access to core devices", "Data centre remote hands contact"],
            procedures=[
                step(1, "Check availability of the core routers", "Both routers reporting telemetry",
                     tool("check_device_availability", "Core device state"), [ENV_POWER]),
                step(2, "Verify OSPF adjacencies across the core", "All adjacencies FULL",
                     tool("analyze_routing_adjacency", "Core adjacencies"), [OSPF_NEIGHBOR]),
            ],
            verification=["All branch paths traverse a reporting core router"],
            escalation=[escalate("Core router unavailable", CORE_TEAM, P1)],
            related_ids=["PB-SHARED-DEVICE-FAILURE"], source_ids=[RUNBOOK_SOURCE], **STAMPS,
        ),
        Runbook(
            record_id="RB-DC1-SERVICES", title="Data centre network services runbook",
            applicability=Applicability(site_ids=["DC1"], device_types=[SERVER, FIREWALL],
                                        services=[PathService.DNS, PathService.DHCP, PathService.AUTHENTICATION, PathService.APPLICATION]),
            fault_domains=[FaultDomain.DNS, FaultDomain.DHCP, FaultDomain.FIREWALL, FaultDomain.VLAN_AUTHENTICATION],
            tags=["data-centre", "dns", "dhcp", "radius", "firewall"],
            context="DNS, DHCP, RADIUS and the ERP application run in DC1 behind DC1-FW-01.",
            preconditions=["Read access to server logs", "Read access to the firewall policy"],
            procedures=[
                step(1, "Check DNS zone status and server logs", "Zones loaded", commands=[DNS_ZONE, DNS_LOG]),
                step(2, "Check DHCP service status", "Service active with free leases", commands=[KEA_STATUS, KEA_LOG]),
                step(3, "Review firewall denies for branch subnets", "No unexpected denies", tool("get_firewall_logs", "Deny events"),
                     [DENY_LOG]),
            ],
            verification=["Internal names resolve from each branch", "New clients obtain addresses"],
            escalation=[escalate("Core network service unavailable", SERVICES_TEAM, P2),
                        escalate("Unexpected deny rule affecting an application", SECURITY_TEAM, P2)],
            related_ids=["PB-DNS-RESOLUTION-FAILURE", "PB-DHCP-ALLOCATION-FAILURE", "PB-FIREWALL-BLOCKING"],
            source_ids=[RUNBOOK_SOURCE], **STAMPS,
        ),
    ]


def procedures() -> list[DiagnosticProcedure]:
    return [
        DiagnosticProcedure(
            record_id="DP-INTERFACE-HEALTH", title="Interface health check", tags=["interface", "errors", "loss"],
            fault_domains=[FaultDomain.INTERFACE_LINK, FaultDomain.WAN_ISP],
            symptoms=["Link flaps or down", "Errors or drops on an interface", "Packet loss on a link"],
            tools=[tool("get_interface_stats", "Status and counters"), tool("analyze_interface_errors", "Error pattern"),
                   tool("analyze_packet_loss", "Loss pattern")],
            commands=[INTERFACE, PING_PEER],
            expected_outputs=["Interface up with error and drop counters below threshold", "Loss below 1 percent"],
            required_evidence=[evidence("EV-IF-STATE", "Interface status and counters", ["INTERFACE_DOWN", "HIGH_ERROR_COUNT"],
                                        "get_interface_stats", "Counters")],
            decisions=[decide("Errors rise with loss", "Physical degradation suspected", "PB-PACKET-LOSS")],
            next_ids=["PB-PACKET-LOSS"], escalation_conditions=["Interface down or sustained errors on a WAN link"],
            source_ids=[REFERENCE_SOURCE], **STAMPS,
        ),
        DiagnosticProcedure(
            record_id="DP-ROUTING-VERIFICATION", title="Routing verification", tags=["routing", "ospf", "bgp"],
            fault_domains=[FaultDomain.ROUTING],
            symptoms=["Routes missing for a site", "Adjacency not established"],
            tools=[tool("get_routing_state", "Routes and neighbors"), tool("analyze_routing_adjacency", "Adjacency health")],
            commands=[ROUTE, OSPF_NEIGHBOR, BGP_SUMMARY],
            expected_outputs=["Destination prefix present with the expected next hop", "Neighbors FULL or Established"],
            required_evidence=[evidence("EV-RT-STATE", "Neighbor states and route changes", ["NEIGHBOR_NOT_ESTABLISHED", "ROUTES_WITHDRAWN"],
                                        "get_routing_state", "Routing state")],
            decisions=[decide("Adjacency stalled with links up", "Parameter mismatch suspected", "PB-OSPF-ADJACENCY-FAILURE")],
            next_ids=["PB-OSPF-ADJACENCY-FAILURE"], escalation_conditions=["Site routes withdrawn"],
            source_ids=[REFERENCE_SOURCE], **STAMPS,
        ),
        DiagnosticProcedure(
            record_id="DP-DNS-DHCP-SERVICES", title="DNS and DHCP service checks", tags=["dns", "dhcp", "services"],
            fault_domains=[FaultDomain.DNS, FaultDomain.DHCP],
            symptoms=["Names do not resolve", "Clients cannot obtain an address"],
            tools=[tool("get_dhcp_dns_status", "Service status per site")],
            commands=[DNS_QUERY, DNS_ZONE, KEA_STATUS],
            expected_outputs=["DNS queries return answers from all servers", "DHCP pools below 90 percent utilization"],
            required_evidence=[evidence("EV-SVC-STATE", "DNS results and DHCP pool state",
                                        ["DNS_SERVFAIL", "DHCP_POOL_EXHAUSTED", "DNS_TIMEOUTS"], "get_dhcp_dns_status", "Service state")],
            decisions=[decide("SERVFAIL from one server", "Server fault suspected", "PB-DNS-RESOLUTION-FAILURE"),
                       decide("Pool exhausted", "Capacity fault suspected", "PB-DHCP-ALLOCATION-FAILURE")],
            next_ids=["PB-DNS-RESOLUTION-FAILURE", "PB-DHCP-ALLOCATION-FAILURE"],
            escalation_conditions=["Internal zone or user pool unavailable"], source_ids=[REFERENCE_SOURCE], **STAMPS,
        ),
        DiagnosticProcedure(
            record_id="DP-FIREWALL-POLICY", title="Firewall policy verification", tags=["firewall", "policy"],
            fault_domains=[FaultDomain.FIREWALL],
            symptoms=["Single application blocked", "Traffic denied after a change"],
            tools=[tool("get_firewall_logs", "Allow and deny events"), tool("check_network_reachability", "Layer-3 path")],
            commands=[DENY_LOG, SECURITY_POLICY],
            expected_outputs=["Flows allowed by the intended rule", "No recent rule changes affecting the flow"],
            required_evidence=[evidence("EV-FWP-DENY", "Denied flows with rule identifiers", ["TRAFFIC_DENIED"], "get_firewall_logs",
                                        "Deny events")],
            decisions=[decide("Recently modified deny rule matches", "Policy fault suspected", "PB-FIREWALL-BLOCKING")],
            next_ids=["PB-FIREWALL-BLOCKING"], escalation_conditions=["Business traffic denied"], source_ids=[REFERENCE_SOURCE], **STAMPS,
        ),
        DiagnosticProcedure(
            record_id="DP-TOPOLOGY-DEPENDENCIES", title="Topology dependency analysis", tags=["topology", "dependencies"],
            symptoms=["Several sites affected", "Unknown failure point"],
            tools=[tool("get_topology", "Site topology"), tool("analyze_network_dependencies", "Shared devices"),
                   tool("check_network_reachability", "Path evaluation")],
            expected_outputs=["Shared devices on affected paths identified"],
            required_evidence=[evidence("EV-DEP-PATHS", "Path outcomes for each affected site", ["PATH_UNREACHABLE", "PATH_REACHABLE"],
                                        "check_network_reachability", "Path outcomes")],
            decisions=[decide("All affected paths share one device", "Investigate the shared device", "PB-SHARED-DEVICE-FAILURE")],
            next_ids=["PB-SHARED-DEVICE-FAILURE"], escalation_conditions=["Shared device unavailable"],
            source_ids=[REFERENCE_SOURCE], **STAMPS,
        ),
    ]


def documents() -> list[KnowledgeDocument]:
    return [
        KnowledgeDocument(
            record_id="KD-EVIDENCE-PRINCIPLES", title="Evidence principles for network diagnosis", document_type=DocumentType.GUIDE,
            category=KnowledgeCategory.GENERAL, tags=["evidence", "diagnosis", "triage"],
            content="Diagnostic tool evidence is authoritative; playbooks are guidance only. Missing telemetry is not proof of failure. "
                    "Confirm a fault with at least two independent observations before escalating, record contradicting evidence, "
                    "and consider shared upstream devices when several sites fail together. All recommended commands are read-only.",
            metadata={"audience": "l1_engineer"}, source_ids=[REFERENCE_SOURCE], **STAMPS,
        ),
        KnowledgeDocument(
            record_id="KD-READ-ONLY-COMMANDS", title="Illustrative read-only command reference", document_type=DocumentType.REFERENCE,
            category=KnowledgeCategory.GENERAL, tags=["commands", "read-only", "reference"],
            content="Commands in this knowledge base are illustrative read-only examples for Cisco IOS XE style routers and switches "
                    "(show, ping, traceroute), PAN-OS style firewalls (show) and Linux servers (journalctl, dig, rndc status, "
                    "keactrl status). Placeholders in braces must be filled in by the engineer. Configuration commands are never "
                    "recommended.",
            metadata={"validation": "read_only_allowlist"}, source_ids=[REFERENCE_SOURCE], **STAMPS,
        ),
        KnowledgeDocument(
            record_id="KD-ESCALATION-MATRIX", title="Escalation matrix by fault domain", document_type=DocumentType.CHECKLIST,
            category=KnowledgeCategory.GENERAL, tags=["escalation", "teams"],
            content=f"WAN and carrier faults: {WAN_TEAM}. Routing faults: {ROUTING_TEAM}. Firewall policy: {SECURITY_TEAM}. "
                    f"802.1X and RADIUS: {NAC_TEAM}. DHCP and DNS: {SERVICES_TEAM}. Shared core or data centre devices: "
                    f"{CORE_TEAM}. Unknown domain: {TRIAGE_TEAM}. Escalations are recommendations until a person sends them.",
            source_ids=[REFERENCE_SOURCE], **STAMPS,
        ),
    ]


def build_knowledge_base() -> KnowledgeBase:
    sources = [
        SourceReference(source_id=PLAYBOOK_SOURCE, title="Synthetic troubleshooting playbooks", kind="synthetic_internal", revision="1.0.0"),
        SourceReference(source_id=RUNBOOK_SOURCE, title="Synthetic site runbooks", kind="synthetic_internal", revision="1.0.0"),
        SourceReference(source_id=REFERENCE_SOURCE, title="Synthetic diagnostic reference material", kind="synthetic_internal",
                        revision="1.0.0"),
    ]
    return KnowledgeBase(schema_version="1.0.0", sources=sources, playbooks=playbooks(), runbooks=runbooks(),
                         documents=documents(), procedures=procedures())


def to_json(knowledge: KnowledgeBase) -> str:
    return json.dumps(knowledge.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"


def write_knowledge(path: Path = DATA_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(build_knowledge_base()), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    write_knowledge()
