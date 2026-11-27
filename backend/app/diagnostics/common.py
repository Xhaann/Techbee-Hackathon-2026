import functools
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, TypeAdapter, ValidationError

from app.network.models import (
    BgpNeighbor,
    Device,
    DeviceId,
    EventType,
    Identifier,
    Interface,
    InterfaceId,
    InterfaceStatistics,
    Link,
    NetworkEvent,
    NetworkTopology,
    OspfNeighbor,
    ScenarioDataset,
    Severity,
    Site,
)
from app.network.repository import DatasetIntegrityError, DatasetNotFoundError, all_scenario_ids, load_scenario, load_topology

MAX_RECORDS = 500
DEFAULT_RECORDS = 100
MAX_EVIDENCE = 50
MAX_SAMPLE_EVIDENCE = 10
MAX_TIME_RANGE = timedelta(hours=24)
MAX_FILTER_VALUES = 20
MAX_TEXT_LENGTH = 128

IDENTIFIER = TypeAdapter(Identifier)
DEVICE_ID = TypeAdapter(DeviceId)
EVENT_TYPE = TypeAdapter(EventType)
AWARE_DATETIME = TypeAdapter(AwareDatetime)
INTERFACE_ID = TypeAdapter(InterfaceId)


class ToolStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"


class FindingKind(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"


class ResultModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceRef(ResultModel):
    collection: str
    record_id: str
    timestamp: datetime | None = None


class Finding(ResultModel):
    code: EventType
    kind: FindingKind
    summary: str
    device_id: str | None = None
    evidence: list[EvidenceRef] = []


class ToolError(ResultModel):
    code: str
    message: str


class ToolResult(ResultModel):
    tool: str
    status: ToolStatus
    parameters: dict[str, Any]
    scenario_id: str | None = None
    data: dict[str, Any] | None = None
    findings: list[Finding] = []
    warnings: list[str] = []
    missing_data: list[str] = []
    error: ToolError | None = None


@dataclass
class ToolOutput:
    data: dict[str, Any]
    scenario_id: str | None = None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    missing_data: list[str] = field(default_factory=list)


class ToolInputError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def invalid(message: str) -> ToolInputError:
    return ToolInputError("INVALID_ARGUMENT", message)


def not_found(message: str) -> ToolInputError:
    return ToolInputError("NOT_FOUND", message)


def jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_TEXT_LENGTH]
    if isinstance(value, Enum):
        return jsonable(value.value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        value = sorted(value, key=str)
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in list(value)[:MAX_FILTER_VALUES + 1]]
    return f"<{type(value).__name__}>"


def diagnostic_tool(name: str) -> Callable[[Callable[..., ToolOutput]], Callable[..., ToolResult]]:
    def decorate(function: Callable[..., ToolOutput]) -> Callable[..., ToolResult]:
        signature = inspect.signature(function)

        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> ToolResult:
            try:
                bound = signature.bind(*args, **kwargs)
            except TypeError as exc:
                return failure(name, {}, "INVALID_ARGUMENT", str(exc))
            bound.apply_defaults()
            parameters = {key: jsonable(value) for key, value in bound.arguments.items()}
            try:
                output = function(*bound.args, **bound.kwargs)
            except ToolInputError as exc:
                return failure(name, parameters, exc.code, exc.message)
            except DatasetIntegrityError:
                return failure(name, parameters, "DATA_UNAVAILABLE", "The requested dataset failed integrity validation")
            return ToolResult(
                tool=name, status=ToolStatus.SUCCESS, parameters=parameters, scenario_id=output.scenario_id,
                data=output.data, findings=output.findings, warnings=output.warnings,
                missing_data=output.missing_data,
            )

        return wrapper

    return decorate


def failure(name: str, parameters: dict[str, Any], code: str, message: str) -> ToolResult:
    return ToolResult(tool=name, status=ToolStatus.ERROR, parameters=parameters, error=ToolError(code=code, message=message))


def validated(adapter: TypeAdapter, value: Any, label: str) -> Any:
    if not isinstance(value, str) or len(value) > MAX_TEXT_LENGTH:
        raise invalid(f"{label} must be a string of at most {MAX_TEXT_LENGTH} characters")
    try:
        return adapter.validate_python(value)
    except ValidationError:
        raise invalid(f"{label} has an invalid format") from None


def load_dataset(scenario_id: Any) -> tuple[NetworkTopology, ScenarioDataset]:
    scenario_id = validated(IDENTIFIER, scenario_id, "scenario_id")
    try:
        dataset = load_scenario(scenario_id)
    except DatasetNotFoundError:
        raise not_found(f"Unknown scenario '{scenario_id}'. Available: {', '.join(all_scenario_ids())}") from None
    return load_topology(), dataset


def require_device(topology: NetworkTopology, device_id: Any) -> Device:
    device_id = validated(DEVICE_ID, device_id, "device_id")
    device = next((device for device in topology.devices if device.device_id == device_id), None)
    if device is None:
        raise not_found(f"Unknown device '{device_id}'")
    return device


def require_site(topology: NetworkTopology, site_id: Any) -> Site:
    site_id = validated(IDENTIFIER, site_id, "site_id")
    site = next((site for site in topology.sites if site.site_id == site_id), None)
    if site is None:
        known = ", ".join(site.site_id for site in topology.sites)
        raise not_found(f"Unknown site '{site_id}'. Available: {known}")
    return site


def require_interface(topology: NetworkTopology, device: Device, interface: Any) -> Interface:
    if not isinstance(interface, str):
        raise invalid("interface must be a string")
    interface_id = interface if ":" in interface else f"{device.device_id}:{interface}"
    interface_id = validated(INTERFACE_ID, interface_id, "interface")
    if not interface_id.startswith(f"{device.device_id}:"):
        raise invalid(f"Interface '{interface_id}' does not belong to device '{device.device_id}'")
    match = next((item for item in topology.interfaces if item.interface_id == interface_id), None)
    if match is None:
        raise not_found(f"Unknown interface '{interface_id}'")
    return match


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, (str, datetime)) or (isinstance(value, str) and len(value) > MAX_TEXT_LENGTH):
        raise invalid(f"{label} must be an ISO 8601 timestamp with a timezone")
    try:
        return AWARE_DATETIME.validate_python(value).astimezone(timezone.utc)
    except ValidationError:
        raise invalid(f"{label} must be an ISO 8601 timestamp with a timezone") from None


def parse_time_range(dataset: ScenarioDataset, start: Any, end: Any) -> tuple[datetime, datetime]:
    range_start = dataset.scenario.window_start if start is None else parse_timestamp(start, "start")
    range_end = dataset.scenario.window_end if end is None else parse_timestamp(end, "end")
    if range_start >= range_end:
        raise invalid("start must be earlier than end")
    if range_end - range_start > MAX_TIME_RANGE:
        raise invalid("time range must not exceed 24 hours")
    return range_start, range_end


def parse_limit(limit: Any) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RECORDS:
        raise invalid(f"limit must be an integer between 1 and {MAX_RECORDS}")
    return limit


def parse_severity(value: Any) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value)
    except ValueError:
        raise invalid(f"min_severity must be one of: {', '.join(item.value for item in Severity)}") from None


def parse_event_types(value: Any) -> list[str]:
    if value is None:
        return []
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, (list, tuple)) or len(values) > MAX_FILTER_VALUES:
        raise invalid(f"event_types must be a string or a list of at most {MAX_FILTER_VALUES} strings")
    return sorted({validated(EVENT_TYPE, item, "event_types") for item in values})


def parse_network(value: Any, label: str) -> IPv4Network | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 43:
        raise invalid(f"{label} must be an IPv4 address or CIDR network")
    try:
        return IPv4Network(value)
    except ValueError:
        raise invalid(f"{label} must be an IPv4 address or CIDR network without host bits") from None


def parse_address(value: str) -> IPv4Address | None:
    try:
        return IPv4Address(value)
    except ValueError:
        return None


def dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def evidence(collection: str, record_id: str, timestamp: datetime | None = None) -> EvidenceRef:
    return EvidenceRef(collection=collection, record_id=record_id, timestamp=timestamp)


def sample_ref(sample: InterfaceStatistics) -> EvidenceRef:
    return evidence("interface_statistics", f"{sample.interface_id}@{sample.timestamp.isoformat()}", sample.timestamp)


def event_refs(events: list[NetworkEvent]) -> list[EvidenceRef]:
    return capped([evidence("events", event.event_id, event.timestamp) for event in events])


def neighbor_ref(neighbor: OspfNeighbor | BgpNeighbor) -> EvidenceRef:
    collection = "ospf_neighbors" if isinstance(neighbor, OspfNeighbor) else "bgp_neighbors"
    return evidence(collection, f"{neighbor.device_id}->{neighbor.neighbor_device_id}", neighbor.last_state_change)


def capped(references: list[EvidenceRef]) -> list[EvidenceRef]:
    return references[:MAX_EVIDENCE]


def samples_for(dataset: ScenarioDataset, interface_id: str) -> list[InterfaceStatistics]:
    return sorted((sample for sample in dataset.interface_statistics if sample.interface_id == interface_id),
                  key=lambda sample: sample.timestamp)


def collection_times(dataset: ScenarioDataset) -> list[datetime]:
    return sorted({sample.timestamp for sample in dataset.interface_statistics})


def link_by_interface(topology: NetworkTopology) -> dict[str, Link]:
    return {endpoint: link for link in topology.links for endpoint in (link.a_interface_id, link.b_interface_id)}


def peer_interface(link: Link, interface_id: str) -> str:
    return link.b_interface_id if link.a_interface_id == interface_id else link.a_interface_id


def severity_rank(severity: Severity) -> int:
    return list(Severity).index(severity)
