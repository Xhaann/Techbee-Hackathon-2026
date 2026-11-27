"""One entry point for the observability features: ingestion, the hub, live topology and the source catalogue."""
import asyncio
import base64
import binascii
import json
import math
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

from app.core.config import Settings
from app.network.models import LinkType
from app.network.repository import load_scenario, load_topology
from app.observability.adapters import (
    FlowDecodeError,
    FlowRecord,
    IpfixTemplateCache,
    NetworkEventRecord,
    StreamingUpdate,
    TelemetrySample,
    TrapPayload,
    decode_ipfix,
    decode_netflow_v5,
    normalize_streaming,
    normalize_trap,
)
from app.observability.health import network_health
from app.observability.hub import INGEST, TelemetryHub, sim_namespace
from app.observability.live import LiveSimulator
from app.observability.signals import parse_ingested
from app.observability.simulation import SITE_GEO, interface_history, monitored_interfaces
from app.observability.traffic import link_load

MAX_REJECTIONS = 20
HEARTBEAT_SECONDS = 15.0
REAUTH_SECONDS = 1.0


class ObservabilityService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # Open streams hold a request slot for their whole life, so together they may use at most half the slots.
        self.max_streams = max(1, min(settings.telemetry_max_streams, settings.max_concurrent_requests // 2))
        self.hub = TelemetryHub(settings.telemetry_max_series, settings.telemetry_points_per_series, settings.telemetry_max_events,
                                settings.telemetry_max_flows, max_subscribers=self.max_streams)
        self.simulator = LiveSimulator(self.hub, settings.telemetry_interval_seconds)
        self.ipfix = IpfixTemplateCache()
        self.transports: list[asyncio.BaseTransport] = []
        self.collector_status: dict[str, str] = {}
        self.collector_errors: dict[str, str] = {}
        topology = load_topology()
        self.devices = {d.device_id: d for d in topology.devices}
        self.interfaces = {(i.device_id, i.name) for i in topology.interfaces}
        self.hosts = {d.hostname.lower(): d.device_id for d in topology.devices} | \
                     {d.device_id.lower(): d.device_id for d in topology.devices} | \
                     {str(d.management_ip): d.device_id for d in topology.devices}

    async def start(self) -> None:
        if self.settings.telemetry_simulation:
            self.simulator.start()
        if self.settings.telemetry_syslog_udp_port or self.settings.telemetry_flow_udp_port:
            from app.observability.collectors import start_collectors
            self.transports = await start_collectors(self)

    async def stop(self) -> None:
        await self.simulator.stop()
        for transport in self.transports:
            transport.close()
        self.transports = []

    # ------------------------------------------------------------ ingestion

    def reject(self, rejected: list[dict[str, Any]], index: int, reason: str) -> None:
        if len(rejected) < MAX_REJECTIONS:
            rejected.append({"index": index, "reason": reason})

    def known(self, device_id: str, interface: str | None) -> str | None:
        if device_id not in self.devices:
            return f"unknown device '{device_id[:40]}'"
        if interface is not None and (device_id, interface) not in self.interfaces:
            return f"unknown interface '{interface[:40]}' on {device_id}"
        return None

    def ingest_samples(self, samples: list[TelemetrySample]) -> dict[str, Any]:
        valid, rejected = [], []
        for index, sample in enumerate(samples):
            problem = self.known(sample.device_id, sample.interface)
            if problem:
                self.reject(rejected, index, problem)
            else:
                valid.append(sample)
        result = self.hub.ingest_samples(valid)
        self.hub.count("samples_rejected", len(samples) - len(valid))
        return {"received": len(samples), **result, "rejected": len(samples) - len(valid), "rejections": rejected}

    def ingest_streaming(self, updates: list[StreamingUpdate]) -> dict[str, Any]:
        samples, skipped = [], 0
        for update in updates:
            normalised, unknown_paths = normalize_streaming(update)
            samples += normalised
            skipped += len(unknown_paths)
        result = self.ingest_samples(samples)
        return {**result, "updates": len(updates), "unsupported_paths": skipped}

    def ingest_syslog(self, lines: list[str], source: str = "api", peer: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        hosts = dict(self.hosts)
        if peer and peer in self.hosts:
            # A relay forwarding for one device: messages without a known host are attributed to the sender.
            hosts |= {"unknown": self.hosts[peer]}
        events, rejected = parse_ingested(lines, hosts, source=source)
        self.hub.ingest_events(events)
        self.hub.count("syslog_rejected", len(rejected))
        return len(events), rejected[:MAX_REJECTIONS]

    def ingest_traps(self, traps: list[TrapPayload]) -> dict[str, Any]:
        events, rejected = [], []
        for index, trap in enumerate(traps):
            problem = self.known(trap.device_id, None)
            if problem:
                self.reject(rejected, index, problem)
                continue
            events.append(normalize_trap(trap))
        self.hub.ingest_events(events)
        return {"received": len(traps), "accepted": len(events), "rejected": len(traps) - len(events), "rejections": rejected,
                "flagged": sum(bool(e.security_flags) for e in events)}

    def exporter_for(self, address: str | None) -> str | None:
        return self.hosts.get(address or "")

    def ingest_flows(self, records: list[FlowRecord], datagrams: list[dict[str, str]]) -> dict[str, Any]:
        valid, rejected = [], []
        for index, record in enumerate(records):
            if record.exporter not in self.devices:
                self.reject(rejected, index, f"unknown exporter '{record.exporter[:40]}'")
            elif record.end < record.start:
                self.reject(rejected, index, "flow ends before it starts")
            else:
                valid.append(record)
        decoded = 0
        for index, datagram in enumerate(datagrams, start=len(records)):
            exporter = datagram["exporter"]
            if exporter not in self.devices:
                self.reject(rejected, index, f"unknown exporter '{exporter[:40]}'")
                continue
            try:
                raw = base64.b64decode(datagram["payload_base64"], validate=True)
                flows = decode_netflow_v5(raw, exporter, "netflow_v5_api") if datagram["format"] == "netflow_v5" \
                    else decode_ipfix(raw, exporter, self.ipfix, "ipfix_api")
            except (binascii.Error, FlowDecodeError, ValueError) as error:
                self.reject(rejected, index, f"undecodable datagram: {str(error)[:80]}")
                continue
            decoded += 1
            valid += flows
        self.hub.ingest_flows(valid)
        return {"received_records": len(records), "received_datagrams": len(datagrams), "decoded_datagrams": decoded,
                "accepted_flows": len(valid), "rejected": len(rejected), "rejections": rejected}

    # ------------------------------------------------------------ reads

    def namespaces(self, scenario_id: str) -> set[str]:
        return {sim_namespace(scenario_id), INGEST}

    def live(self, scenario_id: str, since: int, device_id: str | None, interface: str | None, metric: str | None) -> dict[str, Any]:
        self.simulator.touch(scenario_id)
        if self.settings.telemetry_simulation and self.simulator.task is None and since == 0:
            self.simulator.tick(scenario_id)  # no background task (for example under a test client): produce one sample now
        result = self.hub.read_series(self.namespaces(scenario_id), since, device_id, interface, metric)
        result["simulator"] = {"enabled": self.settings.telemetry_simulation, "running": self.simulator.task is not None,
                               "interval_seconds": self.settings.telemetry_interval_seconds}
        return result

    def ingested_events(self, kind: str, limit: int = 500) -> list[NetworkEventRecord]:
        return [event for _, event in self.hub.read_events({INGEST}, 0, limit) if event.kind == kind]

    def sources(self) -> dict[str, Any]:
        settings = self.settings
        return {
            "modes": {"simulated": "generated locally from the synthetic topology and scenario files",
                      "ingest_api": "pushed to the authenticated ingest endpoints by a collector you run",
                      "udp_receiver": "datagrams received on a local UDP port (off unless configured)",
                      "not_bundled": "an interface exists but no live transport ships with the application"},
            "sources": [
                {"id": "snmp_polling", "name": "SNMP polling (IF-MIB)", "mode": "simulated",
                 "detail": "Counter-rate engine with 32/64-bit wrap and restart handling over a simulated transport; a live "
                           "SNMPv2c/v3 transport is not bundled (SnmpTransport interface)", "live_transport": "not_bundled"},
                {"id": "snmp_traps", "name": "SNMP traps", "mode": "simulated+ingest_api",
                 "detail": "Standard IF-MIB/BGP/OSPF trap OIDs normalised; forward decoded traps to /observability/ingest/traps"},
                {"id": "syslog", "name": "Syslog", "mode": "simulated+ingest_api" + ("+udp_receiver" if settings.telemetry_syslog_udp_port else ""),
                 "detail": "RFC 3164, RFC 5424 and Cisco %FAC-SEV-MNEMONIC parsing with template mining",
                 "udp": self.collector_status.get("syslog") or self.collector_errors.get("syslog") or "disabled"},
                {"id": "flows", "name": "NetFlow v5 / IPFIX", "mode": "simulated+ingest_api" + ("+udp_receiver" if settings.telemetry_flow_udp_port else ""),
                 "detail": "Binary NetFlow v5 and IPFIX (template-based) decoding",
                 "udp": self.collector_status.get("flow") or self.collector_errors.get("flow") or "disabled"},
                {"id": "streaming", "name": "Streaming telemetry (OpenConfig paths)", "mode": "ingest_api",
                 "detail": "gNMI-collector JSON (interfaces/interface/state/counters, system cpu/memory) normalised; a gNMI "
                           "dial-in/out transport is not bundled", "live_transport": "not_bundled"},
                {"id": "live_simulator", "name": "Live telemetry simulator", "mode": "simulated",
                 "detail": f"Every {settings.telemetry_interval_seconds:g} s for watched scenarios",
                 "enabled": settings.telemetry_simulation, "running": self.simulator.task is not None},
                {"id": "lldp", "name": "LLDP neighbour discovery", "mode": "simulated",
                 "detail": "Neighbour tables derived from link state; no device is contacted", "live_transport": "not_bundled"},
                {"id": "configs", "name": "Configuration collection", "mode": "simulated",
                 "detail": "Golden configs from the design; running configs replay logged changes", "live_transport": "not_bundled"},
            ],
            "hub": self.hub.snapshot(),
        }

    def live_topology(self, scenario_id: str) -> dict[str, Any]:
        """Nodes and edges with health and the freshest values: live simulator or ingested data first, then the scenario's
        latest sample. Positions come from a fixed layered layout so the drawing is stable between refreshes."""
        self.simulator.touch(scenario_id)
        topology, dataset = load_topology(), load_scenario(scenario_id)
        health = network_health(scenario_id)
        devices = {d["device_id"]: d for d in health["devices"]}
        links = {l["link_id"]: l for l in health["links"]}
        latest = self.hub.latest_values(self.namespaces(scenario_id))
        monitored = set(monitored_interfaces(dataset))
        loads = link_load(scenario_id)
        positions = layout(topology)
        nodes = [{"id": d.device_id, "label": d.hostname, "site_id": d.site_id, "device_type": d.device_type.value, "role": d.role.value,
                  "x": positions[d.device_id][0], "y": positions[d.device_id][1], "score": devices[d.device_id]["score"],
                  "status": devices[d.device_id]["status"], "reasons": [f["detail"] for f in devices[d.device_id]["factors"][:3]]}
                 for d in topology.devices]
        edges = []
        names = {i.interface_id: i.name for i in topology.interfaces}
        for link in topology.links:
            values: dict[str, Any] = {}
            freshest = None
            for interface_id in (link.a_interface_id, link.b_interface_id):
                device_id = interface_id.split(":", 1)[0]
                for metric in ("utilization_percent", "packet_loss_percent", "latency_ms", "oper_status"):
                    hit = latest.get((device_id, names[interface_id], metric))
                    if hit is not None:
                        values[metric] = max(values.get(metric, 0.0), hit[1]) if metric != "oper_status" else min(values.get(metric, 1.0), hit[1])
                        freshest = max(freshest or 0.0, hit[0])
            source = "live" if values else "scenario"
            if not values:
                for interface_id in (link.a_interface_id, link.b_interface_id):
                    if interface_id in monitored:
                        history = interface_history(scenario_id, interface_id)
                        last = len(history) - 1
                        for metric, series in (("utilization_percent", history.utilization), ("packet_loss_percent", history.loss),
                                               ("latency_ms", history.latency)):
                            value = series[last]
                            if not math.isnan(value):
                                values[metric] = max(values.get(metric, 0.0), value)
                        values["oper_status"] = min(values.get("oper_status", 1.0), 0.0 if history.status[last] == 0 else 1.0)
            edges.append({"id": link.link_id, "source": link.a_device_id, "target": link.b_device_id, "link_type": link.link_type.value,
                          "interfaces": {link.a_device_id: names[link.a_interface_id], link.b_device_id: names[link.b_interface_id]},
                          "bandwidth_mbps": link.bandwidth_mbps, "provider": link.provider,
                          "status": "down" if values.get("oper_status") == 0.0 else ("up" if values else "unknown"),
                          "utilization_percent": round(values["utilization_percent"], 1) if "utilization_percent" in values else None,
                          "loss_percent": round(values["packet_loss_percent"], 2) if "packet_loss_percent" in values else None,
                          "latency_ms": round(values["latency_ms"], 1) if "latency_ms" in values else None,
                          "score": links[link.link_id]["score"], "health": links[link.link_id]["status"], "data_source": source,
                          "updated_at": datetime.fromtimestamp(freshest, timezone.utc).isoformat() if freshest else None,
                          "flow_bytes": loads.get(link.link_id, {}).get("bytes", 0)})
        sites = [{"site_id": s["site_id"], "name": s["name"], "city": s["city"], "score": s["score"], "status": s["status"],
                  "latitude": s["latitude"], "longitude": s["longitude"]} for s in health["sites"]]
        return {"scenario_id": scenario_id, "nodes": nodes, "edges": edges, "sites": sites, "network": health["network"],
                "cursor": self.hub.sequence, "generated_at": datetime.now(timezone.utc).isoformat()}

    def stream_refusal(self, owner: str) -> tuple[int, str, str] | None:
        """Why a new stream for this principal would be refused (status, code, message), checked before it starts."""
        if self.hub.streams_of(owner) >= self.settings.telemetry_max_streams_per_principal:
            return 429, "TOO_MANY_STREAMS", "This session already has the maximum number of live streams open"
        if len(self.hub.subscribers) >= self.max_streams:
            return 503, "STREAMS_BUSY", "Too many live streams are open; retry shortly"
        return None

    async def stream(self, scenario_id: str, max_seconds: float, is_disconnected, owner: str = "",
                     still_authorized=lambda: True) -> AsyncIterator[str]:
        """Server-sent events: a hello with the cursor, then metric batches, events and heartbeats. The session is
        re-checked every second, so a logout or revoked token ends the stream; otherwise it closes after `max_seconds`
        and clients reconnect with the cursor they last saw."""
        self.simulator.touch(scenario_id)
        subscriber = self.hub.subscribe(self.namespaces(scenario_id), owner, self.settings.telemetry_max_streams_per_principal)
        if subscriber is None:
            yield sse("error", {"code": "TOO_MANY_STREAMS", "message": "Too many live streams are open; retry shortly"})
            return
        deadline = time.monotonic() + max_seconds
        last_frame = checked = time.monotonic()
        reason = "max_seconds"
        try:
            yield sse("hello", {"scenario_id": scenario_id, "cursor": self.hub.sequence, "simulator": self.simulator.task is not None,
                                "interval_seconds": self.settings.telemetry_interval_seconds})
            while time.monotonic() < deadline:
                if await is_disconnected():
                    reason = "disconnected"
                    break
                if time.monotonic() - checked >= REAUTH_SECONDS:
                    checked = time.monotonic()
                    if not still_authorized():
                        reason = "session_ended"
                        break
                try:
                    message = await asyncio.wait_for(subscriber.queue.get(), timeout=min(REAUTH_SECONDS, max(0.05, deadline - time.monotonic())))
                except TimeoutError:
                    if time.monotonic() - last_frame >= HEARTBEAT_SECONDS:
                        last_frame = time.monotonic()
                        yield sse("heartbeat", {"cursor": self.hub.sequence, "dropped": subscriber.dropped})
                    continue
                last_frame = time.monotonic()
                yield sse(message["type"], message)
            if reason != "disconnected":
                yield sse("end", {"cursor": self.hub.sequence, "dropped": subscriber.dropped, "reason": reason})
        finally:
            self.hub.unsubscribe(subscriber)


def sse(event: str, data: dict[str, Any]) -> str:
    """One SSE frame; the payload repeats the event name as `type` for clients that only read `data`."""
    return f"event: {event}\ndata: {json.dumps({'type': event, **data}, separators=(',', ':'))}\n\n"


BRANCH_ROWS = {"NYC": 110, "SIN": 300, "BLR": 490}
ROLE_POSITION = {"core_router": 400, "core_switch": 545, "perimeter_firewall": 545, "data_centre_firewall": 690,
                 "distribution_switch": 815}


def layout(topology) -> dict[str, tuple[float, float]]:
    """A fixed left-to-right layout in a 1000 x 600 box: branches, core, data centre, servers. Stable between refreshes so
    the drawing never jumps; any device the rules do not place goes on a fallback grid."""
    positions: dict[str, tuple[float, float]] = {}
    core_routers = sorted(d.device_id for d in topology.devices if d.role.value == "core_router")
    servers = sorted(d.device_id for d in topology.devices if d.device_type.value == "server")
    for device in topology.devices:
        role = device.role.value
        if device.site_id in BRANCH_ROWS:
            positions[device.device_id] = (60.0 if role == "access_switch" else 205.0, float(BRANCH_ROWS[device.site_id]))
        elif role == "core_router":
            positions[device.device_id] = (400.0, 200.0 + 220.0 * core_routers.index(device.device_id))
        elif role == "perimeter_firewall":
            positions[device.device_id] = (545.0, 110.0)
        elif role in ROLE_POSITION:
            positions[device.device_id] = (float(ROLE_POSITION[role]), 310.0)
        elif device.device_id in servers:
            positions[device.device_id] = (945.0, 70.0 + 480.0 * servers.index(device.device_id) / max(1, len(servers) - 1))
    for index, device in enumerate(d for d in topology.devices if d.device_id not in positions):
        positions[device.device_id] = (100.0 + 120.0 * (index % 8), 570.0)
    return positions


def wan_links(topology) -> list[str]:
    return [l.link_id for l in topology.links if l.link_type == LinkType.WAN]


def site_geo() -> dict[str, dict[str, Any]]:
    return {site: {"city": g.city, "latitude": g.latitude, "longitude": g.longitude, "utc_offset_hours": g.utc_offset_hours}
            for site, g in SITE_GEO.items()}
