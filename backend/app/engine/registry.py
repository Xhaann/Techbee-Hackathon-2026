from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app import diagnostics
from app.diagnostics import ToolResult

DeviceId = Annotated[str, Field(min_length=1, max_length=64)]
Timestamp = Annotated[str | None, Field(max_length=40)]


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SiteArguments(ToolArguments):
    site_id: str = Field(min_length=1, max_length=32)


class DeviceArguments(ToolArguments):
    device_id: DeviceId


class DeviceLogArguments(ToolArguments):
    device_id: DeviceId
    start: Timestamp = None
    end: Timestamp = None
    min_severity: Literal["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"] | None = None
    event_types: list[str] | None = Field(default=None, max_length=20)
    limit: int = Field(default=50, ge=1, le=100)


class InterfaceStatsArguments(ToolArguments):
    device_id: DeviceId
    interface: str | None = Field(default=None, max_length=64)


class InterfaceArguments(ToolArguments):
    device_id: DeviceId
    interface: str = Field(min_length=1, max_length=64)


class RoutingArguments(ToolArguments):
    device_id: DeviceId
    prefix: str | None = Field(default=None, max_length=43)


class FirewallArguments(ToolArguments):
    source: str | None = Field(default=None, max_length=43)
    destination: str | None = Field(default=None, max_length=43)
    start: Timestamp = None
    end: Timestamp = None
    action: Literal["allow", "deny"] | None = None
    limit: int = Field(default=50, ge=1, le=100)


class ReachabilityArguments(ToolArguments):
    source: str = Field(min_length=1, max_length=64)
    destination: str = Field(min_length=1, max_length=64)


class DependencyArguments(ToolArguments):
    site_id: str | None = Field(default=None, max_length=32)
    device_id: str | None = Field(default=None, max_length=64)


class HistoryArguments(ToolArguments):
    device_id: str | None = Field(default=None, max_length=64)
    site_id: str | None = Field(default=None, max_length=32)
    start: Timestamp = None
    end: Timestamp = None
    limit: int = Field(default=50, ge=1, le=100)


class ScopeArguments(ToolArguments):
    site_id: str | None = Field(default=None, max_length=32)
    device_id: str | None = Field(default=None, max_length=64)


class TrafficArguments(ToolArguments):
    site_id: str | None = Field(default=None, max_length=32)
    service: Literal["application", "internet", "dns", "dhcp", "authentication"] | None = None


class PacketArguments(ToolArguments):
    source: str = Field(min_length=1, max_length=64)
    destination: str = Field(min_length=1, max_length=64)
    protocol: Literal["tcp", "udp", "icmp"] = "tcp"
    port: int | None = Field(default=None, ge=1, le=65535)


class ProtocolArguments(ToolArguments):
    protocol: Literal["bgp", "ospf", "stp", "arp", "vlan", "nat", "ipsec", "tcp", "mtu", "qos", "ipv6", "wireless", "multicast", "tls",
                      "threats", "traffic", "lateral", "all"]
    site_id: str | None = Field(default=None, max_length=32)
    device_id: str | None = Field(default=None, max_length=64)


class CapacityArguments(ToolArguments):
    site_id: str | None = Field(default=None, max_length=32)
    link_id: str | None = Field(default=None, max_length=64)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    arguments: type[ToolArguments]
    function: Callable[..., ToolResult]
    uses_scenario: bool

    def schema(self) -> dict[str, Any]:
        parameters = self.arguments.model_json_schema()
        parameters.pop("title", None)
        return {"type": "function", "function": {"name": self.name, "description": self.description, "parameters": parameters}}

    def invoke(self, scenario_id: str, arguments: ToolArguments) -> ToolResult:
        values = arguments.model_dump()
        return self.function(scenario_id, **values) if self.uses_scenario else self.function(**values)


TOOLS = (
    ToolSpec("get_topology", "Topology for a site: devices, interfaces, links, VLANs, dependencies, paths and shared infrastructure.",
             SiteArguments, diagnostics.get_topology, False),
    ToolSpec("get_device_logs", "Chronological log events for one device with optional UTC time range, minimum severity and event types.",
             DeviceLogArguments, diagnostics.get_device_logs, True),
    ToolSpec("get_interface_stats", "Interface statistics for a device or one interface, with threshold findings.",
             InterfaceStatsArguments, diagnostics.get_interface_stats, True),
    ToolSpec("get_routing_state", "Routing table, OSPF and BGP neighbors, next hops and route changes for a device.",
             RoutingArguments, diagnostics.get_routing_state, True),
    ToolSpec("get_firewall_logs", "Firewall events matching a source and/or destination IPv4 address or CIDR, with allow/deny summary.",
             FirewallArguments, diagnostics.get_firewall_logs, True),
    ToolSpec("get_dhcp_dns_status", "DHCP pool, lease and allocation status and DNS query results for clients at a site.",
             SiteArguments, diagnostics.get_dhcp_dns_status, True),
    ToolSpec("check_network_reachability", "Layer-3 forward path evaluation between a device or IPv4 address and a destination.",
             ReachabilityArguments, diagnostics.check_network_reachability, True),
    ToolSpec("analyze_packet_loss", "Packet loss pattern analysis for one interface with errors, latency and peer measurements.",
             InterfaceArguments, diagnostics.analyze_packet_loss, True),
    ToolSpec("analyze_interface_errors", "Error and drop pattern analysis for one interface with related log events.",
             InterfaceArguments, diagnostics.analyze_interface_errors, True),
    ToolSpec("analyze_routing_adjacency", "OSPF and BGP adjacency health for a device using local and peer views.",
             DeviceArguments, diagnostics.analyze_routing_adjacency, True),
    ToolSpec("check_device_availability", "Device availability from telemetry gaps, peer link states and adjacencies.",
             DeviceArguments, diagnostics.check_device_availability, True),
    ToolSpec("analyze_network_dependencies", "Upstream/downstream dependencies, shared devices and failure impact for a site and/or device.",
             DependencyArguments, diagnostics.analyze_network_dependencies, False),
    ToolSpec("analyze_path_health", "Loss, errors, utilisation and optical/error events on every link of the forward path between two "
             "endpoints; separates physical degradation from congestion.", ReachabilityArguments, diagnostics.analyze_path_health, True),
    ToolSpec("get_event_timeline", "State changes over the window for a device or site: link, BGP/OSPF, probe and service outages with "
             "their recovery times, and routes withdrawn then restored. Finds faults that have already recovered.",
             HistoryArguments, diagnostics.get_event_timeline, True),
    ToolSpec("get_change_history", "Configuration, MTU, policy and DNS zone changes plus firewall rule edits, with parsed commands "
             "(for example DHCP relay helper removal). Device, site or the whole network.", HistoryArguments,
             diagnostics.get_change_history, True),
    ToolSpec("get_network_health", "Health scores (0-100) for the network, sites, devices and service paths with the top reasons; "
             "optional site or device scope.", ScopeArguments, diagnostics.get_network_health, True),
    ToolSpec("get_config_drift", "Running configuration versus the golden configuration: changed lines with severity and the "
             "logged change, user and ticket behind each, or none.", ScopeArguments, diagnostics.get_config_drift, True),
    ToolSpec("analyze_traffic_flows", "NetFlow/IPFIX summary: traffic by application, top talkers, flows dropped by firewall "
             "policy and traffic that stopped after the incident began.", TrafficArguments, diagnostics.analyze_traffic_flows, True),
    ToolSpec("trace_packet", "Hop-by-hop packet journey between two endpoints for a protocol and port: routes, firewall rule "
             "verdicts, link state, latency and path MTU.", PacketArguments, diagnostics.trace_packet, True),
    ToolSpec("analyze_protocol", "One protocol or security engine over synthetic protocol telemetry: bgp, ospf (LSDB), stp, arp, vlan "
             "(trunks), nat, ipsec, tcp (retransmissions), mtu, qos, ipv6, wireless, multicast, tls, threats (correlation), traffic "
             "(suspicious), lateral (movement), or all of them. Findings are labelled confirmed, suspicious, possible or insufficient evidence.",
             ProtocolArguments, diagnostics.analyze_protocol, True),
    ToolSpec("forecast_capacity", "Congestion risk and utilisation forecast for links: busy-hour trend, days until 80%/90% and "
             "drivers; optional site or link.", CapacityArguments, diagnostics.forecast_capacity, True),
)
REGISTRY = {tool.name: tool for tool in TOOLS}


def tool_schemas() -> list[dict[str, Any]]:
    return [tool.schema() for tool in TOOLS]
