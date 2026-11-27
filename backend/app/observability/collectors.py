"""Optional UDP receivers for syslog (RFC 3164/5424) and NetFlow v5 / IPFIX.

They are off unless a port is configured, bind to loopback by default (a remote bind needs an explicit setting), drop
oversized datagrams, and are rate limited, so a flood cannot grow memory or starve the API. Each datagram goes through
the same decoders and inventory checks as the authenticated ingest API.
"""
import asyncio
import logging
import time
from typing import TYPE_CHECKING

from app.observability.adapters import FlowDecodeError, decode_ipfix, decode_netflow_v5

if TYPE_CHECKING:
    from app.observability.service import ObservabilityService

log = logging.getLogger(__name__)
MAX_SYSLOG_DATAGRAM = 8192
MAX_LINES_PER_DATAGRAM = 20


class TokenBucket:
    def __init__(self, rate: float, burst: float | None = None) -> None:
        self.rate, self.capacity = rate, burst or rate
        self.tokens, self.updated = self.capacity, time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class SyslogReceiver(asyncio.DatagramProtocol):
    def __init__(self, service: "ObservabilityService", rate: float) -> None:
        self.service, self.bucket = service, TokenBucket(rate)

    def datagram_received(self, data: bytes, addr) -> None:
        hub = self.service.hub
        if not self.bucket.allow():
            hub.count("udp_syslog_rate_limited")
            return
        if len(data) > MAX_SYSLOG_DATAGRAM:
            hub.count("udp_syslog_oversize")
            return
        lines = data.decode("utf-8", errors="replace").splitlines()[:MAX_LINES_PER_DATAGRAM]
        accepted, rejected = self.service.ingest_syslog(lines, source="syslog_udp", peer=addr[0] if addr else None)
        hub.count("udp_syslog_datagrams")
        hub.count("udp_syslog_rejected", len(rejected))


class FlowReceiver(asyncio.DatagramProtocol):
    def __init__(self, service: "ObservabilityService", rate: float) -> None:
        self.service, self.bucket = service, TokenBucket(rate)

    def datagram_received(self, data: bytes, addr) -> None:
        hub = self.service.hub
        if not self.bucket.allow():
            hub.count("udp_flow_rate_limited")
            return
        exporter = self.service.exporter_for(addr[0] if addr else None)
        if exporter is None:
            hub.count("udp_flow_unknown_exporter")
            return
        try:
            version = int.from_bytes(data[:2], "big") if len(data) >= 2 else 0
            if version == 5:
                records = decode_netflow_v5(data, exporter, source="netflow_udp")
            elif version == 10:
                records = decode_ipfix(data, exporter, self.service.ipfix, source="ipfix_udp")
            else:
                raise FlowDecodeError("unsupported flow export version")
        except (FlowDecodeError, ValueError):
            hub.count("udp_flow_malformed")
            return
        hub.ingest_flows(records)
        hub.count("udp_flow_datagrams")


async def start_collectors(service: "ObservabilityService") -> list[asyncio.BaseTransport]:
    settings = service.settings
    loop = asyncio.get_running_loop()
    transports = []
    for port, factory, name in ((settings.telemetry_syslog_udp_port, SyslogReceiver, "syslog"),
                                (settings.telemetry_flow_udp_port, FlowReceiver, "flow")):
        if not port:
            continue
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda f=factory: f(service, settings.telemetry_udp_max_datagrams_per_second),
                local_addr=(settings.telemetry_udp_host, port))
        except OSError as error:
            log.warning("%s UDP receiver could not bind %s:%s (%s)", name, settings.telemetry_udp_host, port, error.strerror)
            service.collector_errors[name] = error.strerror or "bind failed"
            continue
        transports.append(transport)
        service.collector_status[name] = f"{settings.telemetry_udp_host}:{transport.get_extra_info('sockname')[1]}"
    return transports
