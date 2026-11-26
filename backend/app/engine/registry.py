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
)
REGISTRY = {tool.name: tool for tool in TOOLS}


def tool_schemas() -> list[dict[str, Any]]:
    return [tool.schema() for tool in TOOLS]
