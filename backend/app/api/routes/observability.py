"""Network intelligence and observability: ingestion, live telemetry, analytics, discovery and reliability reports.

Reads need view_diagnostics. Ingestion needs ingest_telemetry, which only service accounts hold. Everything is computed
in code from simulated or ingested data; no route calls a model or contacts a device.
"""
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.api.dependencies import MAX_OFFSET, MAX_PAGE_SIZE, ScenarioDependency, ServicesDependency, bearer_token, not_found, require
from app.core.exceptions import AppError
from app.diagnostics.common import ToolInputError
from app.network.repository import load_scenario, load_topology
from app.observability.adapters import FlowRecord, StreamingUpdate, TelemetrySample, TrapPayload
from app.observability.analytics import congestion, interface_baseline, interface_forecast, scenario_baselines, wan_interfaces
from app.observability.health import network_health
from app.observability.inventory import blast_radius, config_diff, config_drift, dependency_graph, discovery
from app.observability.journey import trace
from app.observability.reliability import export_csv, export_markdown, reliability_report
from app.observability.signals import snmp_overview, snmp_poll, syslog_view, trap_view
from app.observability.simulation import monitored_interfaces
from app.observability.traffic import flow_page, traffic_summary
from app.security.permissions import AuthenticationError, Permission, Principal

VIEW = Depends(require(Permission.VIEW_DIAGNOSTICS))
INGEST = Depends(require(Permission.INGEST_TELEMETRY))
router = APIRouter(prefix="/observability", tags=["observability"])
SSE_HEADERS = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}
DeviceQuery = Annotated[str | None, Query(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$", max_length=64)]
SiteQuery = Annotated[str | None, Query(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$", max_length=32)]
InterfaceIdQuery = Annotated[str | None, Query(pattern=r"^[A-Z0-9-]+:[A-Za-z0-9/._-]+$", max_length=96)]
Endpoint = Annotated[str, Query(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9.:_-]+$")]
SyslogLine = Annotated[str, StringConstraints(min_length=1, max_length=1024)]
Payload = dict[str, Any]


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TelemetryBatch(Body):
    samples: list[TelemetrySample] = Field(min_length=1, max_length=1000)


class StreamingBatch(Body):
    updates: list[StreamingUpdate] = Field(min_length=1, max_length=200)


class SyslogBatch(Body):
    lines: list[SyslogLine] = Field(min_length=1, max_length=500)


class TrapBatch(Body):
    traps: list[TrapPayload] = Field(min_length=1, max_length=500)


class FlowDatagram(Body):
    format: Literal["netflow_v5", "ipfix"]
    exporter: str = Field(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$", max_length=64)
    payload_base64: str = Field(min_length=4, max_length=90_000)


class FlowBatch(Body):
    records: list[FlowRecord] = Field(default_factory=list, max_length=2000)
    datagrams: list[FlowDatagram] = Field(default_factory=list, max_length=50)


def tool_errors(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except ToolInputError as error:
        raise AppError(error.message, code="NOT_FOUND" if error.code == "NOT_FOUND" else "VALIDATION_ERROR",
                       status_code=404 if error.code == "NOT_FOUND" else 422) from None


def require_device(device_id: str | None) -> None:
    if device_id is not None and device_id not in {d.device_id for d in load_topology().devices}:
        raise not_found(f"Unknown device '{device_id}'")


def require_site(site_id: str | None) -> None:
    if site_id is not None and site_id not in {s.site_id for s in load_topology().sites}:
        raise not_found(f"Unknown site '{site_id}'")


# ------------------------------------------------------------------ sources and ingestion

@router.get("/sources", response_model=Payload, dependencies=[VIEW])
def sources(registry: ServicesDependency) -> Payload:
    """Every telemetry source, whether it is simulated, ingested or not bundled, and the hub's buffer statistics."""
    return registry.observability.sources()


@router.post("/ingest/telemetry", response_model=Payload, dependencies=[INGEST], status_code=202)
def ingest_telemetry(body: TelemetryBatch, registry: ServicesDependency) -> Payload:
    return registry.observability.ingest_samples(body.samples)


@router.post("/ingest/streaming", response_model=Payload, dependencies=[INGEST], status_code=202)
def ingest_streaming(body: StreamingBatch, registry: ServicesDependency) -> Payload:
    return registry.observability.ingest_streaming(body.updates)


@router.post("/ingest/syslog", response_model=Payload, dependencies=[INGEST], status_code=202)
def ingest_syslog(body: SyslogBatch, registry: ServicesDependency) -> Payload:
    accepted, rejected = registry.observability.ingest_syslog(body.lines)
    return {"received": len(body.lines), "accepted": accepted, "rejected": len(body.lines) - accepted, "rejections": rejected}


@router.post("/ingest/traps", response_model=Payload, dependencies=[INGEST], status_code=202)
def ingest_traps(body: TrapBatch, registry: ServicesDependency) -> Payload:
    return registry.observability.ingest_traps(body.traps)


@router.post("/ingest/flows", response_model=Payload, dependencies=[INGEST], status_code=202)
def ingest_flows(body: FlowBatch, registry: ServicesDependency) -> Payload:
    if not body.records and not body.datagrams:
        raise AppError("Send flow records or datagrams", code="VALIDATION_ERROR", status_code=422)
    return registry.observability.ingest_flows(body.records, [d.model_dump() for d in body.datagrams])


# ------------------------------------------------------------------ live telemetry

@router.get("/live", response_model=Payload, dependencies=[VIEW])
def live(registry: ServicesDependency, scenario_id: ScenarioDependency, since: Annotated[int, Query(ge=0)] = 0,
         device_id: DeviceQuery = None, interface: Annotated[str | None, Query(max_length=64)] = None,
         metric: Annotated[str | None, Query(pattern=r"^[a-z_]+$", max_length=32)] = None) -> Payload:
    """Points newer than the `since` cursor (incremental polling); pass the returned cursor next time."""
    return registry.observability.live(scenario_id, since, device_id, interface, metric)


@router.get("/stream", responses={200: {"content": {"text/event-stream": {}}}})
async def stream(request: Request, registry: ServicesDependency, scenario_id: ScenarioDependency,
                 principal: Annotated[Principal, Depends(require(Permission.VIEW_DIAGNOSTICS))],
                 max_seconds: Annotated[float | None, Query(gt=0, le=3600)] = None) -> StreamingResponse:
    """Server-sent events: hello, metrics, event, flows, heartbeat and end. Bounded per client (drop-oldest), capped per
    session and in total, and ended as soon as the session is logged out or revoked."""
    refusal = registry.observability.stream_refusal(principal.subject)
    if refusal is not None:
        status, code, message = refusal
        raise AppError(message, code=code, status_code=status, headers={"retry-after": "10"})
    token = bearer_token(request)

    def still_authorized() -> bool:
        try:
            return Permission.VIEW_DIAGNOSTICS in registry.authenticator().authenticate(token).permissions
        except (AuthenticationError, AppError):
            return False

    limit = min(max_seconds or registry.settings.telemetry_stream_max_seconds, registry.settings.telemetry_stream_max_seconds)
    return StreamingResponse(registry.observability.stream(scenario_id, limit, request.is_disconnected, principal.subject, still_authorized),
                             media_type="text/event-stream", headers=SSE_HEADERS)


@router.get("/topology/live", response_model=Payload, dependencies=[VIEW])
def live_topology(registry: ServicesDependency, scenario_id: ScenarioDependency) -> Payload:
    return registry.observability.live_topology(scenario_id)


# ------------------------------------------------------------------ SNMP, traps, syslog, flows

@router.get("/snmp", response_model=Payload, dependencies=[VIEW])
def snmp(scenario_id: ScenarioDependency, device_id: DeviceQuery = None) -> Payload:
    require_device(device_id)
    return snmp_poll(scenario_id, device_id) if device_id else snmp_overview(scenario_id)


@router.get("/traps", response_model=Payload, dependencies=[VIEW])
def traps(registry: ServicesDependency, scenario_id: ScenarioDependency) -> Payload:
    return trap_view(scenario_id, registry.observability.ingested_events("trap"))


@router.get("/syslog", response_model=Payload, dependencies=[VIEW])
def syslog(registry: ServicesDependency, scenario_id: ScenarioDependency,
           limit: Annotated[int, Query(ge=1, le=100)] = 25) -> Payload:
    return syslog_view(scenario_id, registry.observability.ingested_events("syslog"), limit)


@router.get("/flows", response_model=Payload, dependencies=[VIEW])
def flows(scenario_id: ScenarioDependency, site_id: SiteQuery = None, service: str | None = Query(None, max_length=32),
          action: Literal["forwarded", "dropped", "unanswered"] | None = None,
          limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50, offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0) -> Payload:
    require_site(site_id)
    return flow_page(scenario_id, site_id, service, action, limit, offset)


@router.get("/traffic", response_model=Payload, dependencies=[VIEW])
def traffic(scenario_id: ScenarioDependency, site_id: SiteQuery = None,
            service: Literal["application", "internet", "dns", "dhcp", "authentication", "other"] | None = None) -> Payload:
    require_site(site_id)
    return traffic_summary(scenario_id, site_id, service)


# ------------------------------------------------------------------ analytics

@router.get("/baselines", response_model=Payload, dependencies=[VIEW])
def baselines(scenario_id: ScenarioDependency, interface_id: InterfaceIdQuery = None, device_id: DeviceQuery = None) -> Payload:
    if interface_id:
        if interface_id not in monitored_interfaces(load_scenario(scenario_id)):
            raise not_found(f"No telemetry history for '{interface_id}'")
        return {"items": [interface_baseline(scenario_id, interface_id)]}
    require_device(device_id)
    items = [b for b in scenario_baselines(scenario_id) if device_id is None or b["device_id"] == device_id]
    return {"items": [{k: v for k, v in b.items() if k != "weekday_profile"} for b in items],
            "anomalous": sum(1 for b in items if b["anomalies"])}


@router.get("/health", response_model=Payload, dependencies=[VIEW])
def health(scenario_id: ScenarioDependency) -> Payload:
    return network_health(scenario_id)


@router.get("/forecast", response_model=Payload, dependencies=[VIEW])
def forecast(scenario_id: ScenarioDependency, interface_id: InterfaceIdQuery = None,
             horizon_days: Annotated[int, Query(ge=7, le=90)] = 30) -> Payload:
    if interface_id:
        if interface_id not in monitored_interfaces(load_scenario(scenario_id)):
            raise not_found(f"No telemetry history for '{interface_id}'")
        return interface_forecast(scenario_id, interface_id, horizon_days)
    return {"items": [{k: v for k, v in interface_forecast(scenario_id, i, horizon_days).items() if k not in ("forecast", "observed", "next_24h")}
                      for i in wan_interfaces(scenario_id)]}


@router.get("/congestion", response_model=Payload, dependencies=[VIEW])
def congestion_risk(scenario_id: ScenarioDependency) -> Payload:
    items = congestion(scenario_id)
    return {"items": items, "summary": {level: sum(i["level"] == level for i in items)
                                        for level in ("high", "medium", "low", "unavailable", "unknown")}}


@router.get("/discovery", response_model=Payload, dependencies=[VIEW])
def topology_discovery(scenario_id: ScenarioDependency) -> Payload:
    return discovery(scenario_id)


@router.get("/dependencies", response_model=Payload, dependencies=[VIEW])
def dependencies(scenario_id: ScenarioDependency, node_id: Annotated[str | None, Query(max_length=64, pattern=r"^[A-Z0-9-]+$")] = None) -> Payload:
    graph = dependency_graph(scenario_id)
    if node_id is None:
        return graph
    known = {n["id"] for n in graph["nodes"]} | set(graph["link_usage"])
    if node_id not in known:
        raise not_found(f"Unknown node '{node_id}'")
    return blast_radius(scenario_id, node_id)


@router.get("/drift", response_model=Payload, dependencies=[VIEW])
def drift(scenario_id: ScenarioDependency, device_id: DeviceQuery = None) -> Payload:
    require_device(device_id)
    report = config_drift(scenario_id)
    if device_id is None:
        return report
    return {**report, "devices": [d for d in report["devices"] if d["device_id"] == device_id],
            "items": [i for i in report["items"] if i["device_id"] == device_id]}


@router.get("/drift/{device_id}/diff", response_model=Payload, dependencies=[VIEW])
def drift_diff(scenario_id: ScenarioDependency,
               device_id: Annotated[str, Path(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$", max_length=64)]) -> Payload:
    device = next((d for d in load_topology().devices if d.device_id == device_id), None)
    if device is None or device.device_type.value == "server":
        raise not_found(f"No managed configuration for '{device_id}'")
    return config_diff(scenario_id, device_id)


@router.get("/journey", response_model=Payload, dependencies=[VIEW])
def journey(scenario_id: ScenarioDependency, source: Endpoint, destination: Endpoint,
            protocol: Literal["tcp", "udp", "icmp"] = "tcp", port: Annotated[int | None, Query(ge=1, le=65535)] = None,
            size_bytes: Annotated[int, Query(ge=64, le=9216)] = 1500) -> Payload:
    return tool_errors(trace, scenario_id, source, destination, protocol, port, size_bytes)


@router.get("/reliability", response_model=Payload, dependencies=[VIEW],
            responses={200: {"content": {"text/markdown": {}, "text/csv": {}}}})
def reliability(scenario_id: ScenarioDependency, period: Literal["7d", "14d"] = "14d",
                format: Literal["json", "markdown", "csv"] = "json"):
    report = reliability_report(scenario_id, period)
    if format == "markdown":
        return PlainTextResponse(export_markdown(report), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="reliability-{scenario_id}-{period}.md"'})
    if format == "csv":
        return PlainTextResponse(export_csv(report), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="reliability-{scenario_id}-{period}.csv"'})
    return report

