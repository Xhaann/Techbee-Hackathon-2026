"""Ingestion adapters: SNMP, traps, syslog, NetFlow v5 / IPFIX and streaming (OpenConfig-style) telemetry.

These are real decoders and normalisers. What is not bundled is any outbound network transport: the SNMP poller takes a
`SnmpTransport` (the simulated one ships; a live one is a deployment choice), and push sources (trap forwarders,
syslog relays, flow exporters, gNMI collectors) reach the hub through the authenticated ingest API or the optional
loopback-only UDP receivers in `collectors.py`, which are off unless configured.
"""
import hashlib
import ipaddress
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.engine.safety import injection_flags

MAX_TEXT = 1024


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TelemetrySample(Record):
    """One normalised metric value."""
    device_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    interface: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9/._:-]+$")
    metric: Literal["utilization_percent", "in_bps", "out_bps", "in_errors", "out_errors", "in_discards", "out_discards",
                    "packet_loss_percent", "latency_ms", "oper_status", "cpu_percent", "memory_percent"]
    value: float = Field(ge=0, le=1e13)
    timestamp: datetime
    source: str = Field(default="api", max_length=40, pattern=r"^[a-z0-9_:.-]+$")

    @field_validator("timestamp")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)

    @property
    def key(self) -> str:
        return f"{self.device_id}|{self.interface or '-'}|{self.metric}"


class NetworkEventRecord(Record):
    """A normalised event from syslog or an SNMP trap."""
    timestamp: datetime
    device_id: str = Field(max_length=64)
    interface: str | None = Field(default=None, max_length=64)
    kind: Literal["syslog", "trap"]
    event_type: str = Field(max_length=64)
    severity: int = Field(ge=0, le=7)
    message: str = Field(max_length=MAX_TEXT)
    template_id: str | None = None
    source: str = Field(default="api", max_length=40)
    security_flags: list[str] = Field(default_factory=list)


class FlowRecord(Record):
    start: datetime
    end: datetime
    exporter: str = Field(max_length=64)
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: int = Field(ge=0, le=255)
    bytes: int = Field(ge=0)
    packets: int = Field(ge=0)
    input_if: int | None = Field(default=None, ge=0)
    output_if: int | None = Field(default=None, ge=0)
    source: str = Field(default="api", max_length=40)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def ipv4(cls, value: str) -> str:
        return str(ipaddress.IPv4Address(value))


# ---------------------------------------------------------------- SNMP polling

IF_COUNTERS = ("ifHCInOctets", "ifHCOutOctets", "ifInErrors", "ifOutErrors", "ifInDiscards", "ifOutDiscards")
COUNTER_WIDTH = {"ifHCInOctets": 64, "ifHCOutOctets": 64, "ifInErrors": 32, "ifOutErrors": 32, "ifInDiscards": 32, "ifOutDiscards": 32}


@dataclass(frozen=True)
class CounterSample:
    device_id: str
    interface: str
    if_index: int
    timestamp: datetime
    sys_uptime_ticks: int
    oper_status: int
    counters: dict[str, int]
    speed_bps: int


class SnmpTransport(Protocol):
    """Returns IF-MIB counters for one device. The bundled implementation is simulated; a live transport (SNMPv2c/v3
    over UDP) is a deployment choice and must be configured explicitly."""

    def interface_counters(self, device_id: str, moment: datetime) -> list[CounterSample]: ...


class SnmpTargetConfig(Record):
    device_id: str = Field(pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$")
    host: str = Field(min_length=1, max_length=255)
    version: Literal["v2c", "v3"] = "v3"
    credential_ref: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$", description="Name of a secret held outside the app")
    interval_seconds: int = Field(default=300, ge=30, le=3600)


@dataclass
class RateResult:
    rates: dict[str, float] | None
    reason: str | None = None


class CounterRateCalculator:
    """Turns successive counter polls into per-second rates, handling 32/64-bit wraps and agent restarts."""

    def __init__(self) -> None:
        self.previous: dict[tuple[str, int], CounterSample] = {}

    def update(self, sample: CounterSample) -> RateResult:
        key = (sample.device_id, sample.if_index)
        previous = self.previous.get(key)
        self.previous[key] = sample
        if previous is None:
            return RateResult(None, "first poll establishes the counter baseline")
        if sample.sys_uptime_ticks < previous.sys_uptime_ticks:
            return RateResult(None, "counter discontinuity: the agent restarted (sysUpTime went backwards)")
        seconds = (sample.timestamp - previous.timestamp).total_seconds()
        if seconds <= 0:
            return RateResult(None, "poll timestamps are not increasing")
        rates = {}
        for name in IF_COUNTERS:
            delta = sample.counters[name] - previous.counters[name]
            if delta < 0:
                delta += 2 ** COUNTER_WIDTH[name]
            rates[name] = delta / seconds
        rates["utilization_percent"] = min(100.0, max(rates["ifHCInOctets"], rates["ifHCOutOctets"]) * 8 / sample.speed_bps * 100)
        return RateResult(rates)


class SnmpPoller:
    def __init__(self, transport: SnmpTransport) -> None:
        self.transport = transport
        self.calculator = CounterRateCalculator()

    def poll(self, device_id: str, moment: datetime) -> list[tuple[CounterSample, RateResult]]:
        return [(sample, self.calculator.update(sample)) for sample in self.transport.interface_counters(device_id, moment)]


# ---------------------------------------------------------------- SNMP traps

TRAP_TYPES = {
    "1.3.6.1.6.3.1.1.5.1": ("COLD_START", 4), "1.3.6.1.6.3.1.1.5.2": ("WARM_START", 5),
    "1.3.6.1.6.3.1.1.5.3": ("LINK_DOWN", 3), "1.3.6.1.6.3.1.1.5.4": ("LINK_UP", 5),
    "1.3.6.1.6.3.1.1.5.5": ("AUTHENTICATION_FAILURE", 4), "1.3.6.1.2.1.15.0.2": ("BGP_BACKWARD_TRANSITION", 3),
    "1.3.6.1.2.1.15.0.1": ("BGP_ESTABLISHED", 5), "1.3.6.1.2.1.14.16.2.2": ("OSPF_NEIGHBOR_STATE_CHANGE", 4),
    "1.3.6.1.4.1.9.9.43.2.0.1": ("CONFIG_CHANGE", 5), "1.3.6.1.4.1.9.9.13.3.0.5": ("POWER_SUPPLY_FAILURE", 2),
}
EVENT_TO_TRAP = {"LINK_DOWN": "1.3.6.1.6.3.1.1.5.3", "CARRIER_LOSS": "1.3.6.1.6.3.1.1.5.3", "LINK_UP": "1.3.6.1.6.3.1.1.5.4",
                 "BGP_NEIGHBOR_DOWN": "1.3.6.1.2.1.15.0.2", "BGP_NEIGHBOR_UP": "1.3.6.1.2.1.15.0.1",
                 "OSPF_ADJACENCY_DOWN": "1.3.6.1.2.1.14.16.2.2", "CONFIG_CHANGE": "1.3.6.1.4.1.9.9.43.2.0.1",
                 "POWER_SUPPLY_FAILURE": "1.3.6.1.4.1.9.9.13.3.0.5", "SYSTEM_SHUTDOWN": "1.3.6.1.6.3.1.1.5.2"}
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"


class TrapPayload(Record):
    """A decoded trap as forwarded by a trap receiver (snmptrapd, Telegraf and similar)."""
    trap_oid: str = Field(pattern=r"^\d+(?:\.\d+){3,40}$")
    device_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    timestamp: datetime
    varbinds: dict[str, str] = Field(default_factory=dict, max_length=32)


def normalize_trap(payload: TrapPayload, source: str = "api") -> NetworkEventRecord:
    event_type, severity = TRAP_TYPES.get(payload.trap_oid.removeprefix("."), ("TRAP_" + payload.trap_oid.split(".")[-1], 6))
    interface = next((value for oid, value in payload.varbinds.items() if oid.startswith(IF_DESCR)), None)
    text = f"SNMP trap {event_type} ({payload.trap_oid})" + (f" on {interface}" if interface else "")
    flags = [flag for value in payload.varbinds.values() for flag in injection_flags("trap varbind", value[:MAX_TEXT])]
    return NetworkEventRecord(timestamp=payload.timestamp.astimezone(timezone.utc), device_id=payload.device_id,
                              interface=interface[:64] if interface else None, kind="trap", event_type=event_type,
                              severity=severity, message=text[:MAX_TEXT], source=source, security_flags=sorted(set(flags)))


def trap_analysis(events: list[NetworkEventRecord], storm_threshold: int = 10) -> dict[str, Any]:
    traps = sorted((e for e in events if e.kind == "trap"), key=lambda e: e.timestamp)
    flaps, open_downs = [], {}
    for event in traps:
        key = (event.device_id, event.interface)
        if event.event_type == "LINK_DOWN":
            open_downs.setdefault(key, event)
        elif event.event_type == "LINK_UP" and key in open_downs:
            down = open_downs.pop(key)
            flaps.append({"device_id": event.device_id, "interface": event.interface, "down_at": down.timestamp.isoformat(),
                          "up_at": event.timestamp.isoformat(), "seconds": int((event.timestamp - down.timestamp).total_seconds())})
    buckets = Counter((e.device_id, e.timestamp.replace(second=0, microsecond=0)) for e in traps)
    storms = [{"device_id": device, "minute": minute.isoformat(), "traps": count} for (device, minute), count in buckets.items()
              if count >= storm_threshold]
    return {
        "total": len(traps), "by_type": dict(Counter(e.event_type for e in traps).most_common()),
        "flaps": flaps, "still_down": [{"device_id": d, "interface": i, "since": e.timestamp.isoformat()} for (d, i), e in open_downs.items()],
        "storms": storms, "authentication_failures": sum(e.event_type == "AUTHENTICATION_FAILURE" for e in traps),
    }


# ---------------------------------------------------------------- syslog

CISCO = re.compile(r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>[0-7])-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<text>.*)$")
RFC5424 = re.compile(r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
                     r"(?P<sd>-|(?:\[[^\]]*\])+) ?(?P<msg>.*)$")
RFC3164 = re.compile(r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) (?P<msg>.*)$")
MASKS = [(re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b"), "<ip>"),
         (re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.IGNORECASE), "<mac>"),
         (re.compile(r"\b(?:Gi|Te|Fa|Eth|ethernet|GigabitEthernet|TenGigabitEthernet)\d+(?:/\d+)*(?:\.\d+)?\b"), "<if>"),
         (re.compile(r"'[^']*'|\"[^\"]*\""), "<str>"), (re.compile(r"\b[A-Za-z_]+\d[\w.]*\b"), "<id>"),
         (re.compile(r"-?\b\d+(?:\.\d+)?\b"), "<n>")]
MNEMONIC_EVENT = {"UPDOWN": "LINK_STATE", "ADJCHANGE": "ADJACENCY_CHANGE", "CONFIG_I": "CONFIG_CHANGE", "ERRRCV": "PROTOCOL_ERROR",
                  "THRESHOLD_VIOLATION": "OPTICAL_THRESHOLD", "FAIL": "AUTHENTICATION_FAILURE", "LOGGEDCMD": "CONFIG_COMMAND"}


@dataclass(frozen=True)
class SyslogMessage:
    timestamp: datetime
    host: str
    severity: int
    facility: str | None
    mnemonic: str | None
    text: str
    format: str


def parse_syslog(line: str, received_at: datetime, default_host: str = "unknown") -> SyslogMessage:
    line = line.strip()[:MAX_TEXT]
    timestamp, host, severity, body, fmt = received_at, default_host, 6, line, "raw"
    if match := RFC5424.match(line):
        pri = int(match["pri"])
        severity, host, body, fmt = pri % 8, match["host"], match["msg"], "rfc5424"
        try:
            timestamp = datetime.fromisoformat(match["ts"].replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            pass
    elif match := RFC3164.match(line):
        pri = int(match["pri"])
        severity, host, body, fmt = pri % 8, match["host"], match["msg"], "rfc3164"
        try:
            parsed = datetime.strptime(f"{received_at.year} {match['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            timestamp = parsed if parsed <= received_at + timedelta(days=1) else parsed.replace(year=received_at.year - 1)
        except ValueError:
            pass
    facility = mnemonic = None
    if cisco := CISCO.search(body):
        facility, mnemonic, severity = cisco["facility"], cisco["mnemonic"], int(cisco["severity"])
        fmt = f"{fmt}+cisco" if fmt != "raw" else "cisco"
    return SyslogMessage(timestamp, host[:64], severity, facility, mnemonic, body, fmt)


def template_of(text: str) -> tuple[str, str]:
    """Masks the variable parts of a message (addresses, interfaces, numbers, quoted values) to find its template. The
    Cisco tag (%FACILITY-SEVERITY-MNEMONIC) is kept verbatim: it names the message type."""
    prefix, body = "", text
    if (cisco := CISCO.search(text)) is not None:
        prefix, body = text[:cisco.start("text")], cisco["text"]
    template = body
    for pattern, token in MASKS:
        template = pattern.sub(token, template)
    template = (prefix + template)[:300]
    return template, hashlib.sha1(template.encode()).hexdigest()[:10]


def syslog_event(message: SyslogMessage, device_id: str, source: str) -> NetworkEventRecord:
    _, template_id = template_of(message.text)
    event_type = MNEMONIC_EVENT.get(message.mnemonic or "", message.mnemonic or "SYSLOG")
    interface = next((m.group(0) for m in MASKS[2][0].finditer(message.text)), None)
    return NetworkEventRecord(timestamp=message.timestamp, device_id=device_id, interface=interface, kind="syslog",
                              event_type=event_type[:64], severity=message.severity, message=message.text, template_id=template_id,
                              source=source, security_flags=injection_flags("syslog message", message.text))


def syslog_intelligence(messages: list[tuple[str, SyslogMessage]], storm_threshold: int = 20, limit: int = 25) -> dict[str, Any]:
    """Template clustering, severity mix, storms, cross-device bursts and notable rare messages."""
    groups: dict[str, dict[str, Any]] = {}
    per_minute: Counter = Counter()
    for device, message in sorted(messages, key=lambda item: item[1].timestamp):
        template, template_id = template_of(message.text)
        group = groups.setdefault(template_id, {"template_id": template_id, "template": template, "count": 0, "devices": set(),
                                               "severity": message.severity, "mnemonic": message.mnemonic,
                                               "first_seen": message.timestamp, "last_seen": message.timestamp, "example": message.text})
        group["count"] += 1
        group["devices"].add(device)
        group["severity"] = min(group["severity"], message.severity)
        group["last_seen"] = message.timestamp
        per_minute[(device, message.timestamp.replace(second=0, microsecond=0))] += 1
    templates = sorted(groups.values(), key=lambda g: (g["severity"], -g["count"], g["template_id"]))
    rendered = [{**g, "devices": sorted(g["devices"]), "first_seen": g["first_seen"].isoformat(), "last_seen": g["last_seen"].isoformat(),
                 "rare": g["count"] == 1} for g in templates]
    storms = [{"device_id": d, "minute": m.isoformat(), "messages": c} for (d, m), c in per_minute.items() if c >= storm_threshold]
    bursts = [g for g in rendered if len(g["devices"]) >= 2 and g["severity"] <= 5]
    notable = [g for g in rendered if g["severity"] <= 3 or (g["rare"] and g["severity"] <= 4)]
    return {
        "total": len(messages), "templates_total": len(rendered),
        "by_severity": {str(level): count for level, count in sorted(Counter(m.severity for _, m in messages).items())},
        "templates": rendered[:limit], "notable": notable[:limit], "cross_device": bursts[:limit], "storms": storms,
        "security_flags": sorted({flag for _, m in messages for flag in injection_flags("syslog message", m.text)}),
    }


# ---------------------------------------------------------------- NetFlow v5 and IPFIX

V5_HEADER = struct.Struct("!HHIIIIBBH")
V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")
IPFIX_HEADER = struct.Struct("!HHIII")
SET_HEADER = struct.Struct("!HH")
IPFIX_FIELDS = {1: "bytes", 2: "packets", 4: "protocol", 7: "src_port", 8: "src_ip", 10: "input_if", 11: "dst_port",
                12: "dst_ip", 14: "output_if", 150: "start_s", 151: "end_s", 152: "start_ms", 153: "end_ms"}
MAX_DATAGRAM = 65535


class FlowDecodeError(ValueError):
    pass


def decode_netflow_v5(datagram: bytes, exporter: str, source: str = "netflow_v5") -> list[FlowRecord]:
    if len(datagram) < V5_HEADER.size or len(datagram) > MAX_DATAGRAM:
        raise FlowDecodeError("datagram size is outside NetFlow v5 bounds")
    version, count, uptime_ms, secs, nsecs, _, _, _, _ = V5_HEADER.unpack_from(datagram)
    if version != 5 or not 1 <= count <= 30 or len(datagram) != V5_HEADER.size + count * V5_RECORD.size:
        raise FlowDecodeError("not a well-formed NetFlow v5 datagram")
    boot = datetime.fromtimestamp(secs + nsecs / 1e9, timezone.utc) - timedelta(milliseconds=uptime_ms)
    records = []
    for index in range(count):
        fields = V5_RECORD.unpack_from(datagram, V5_HEADER.size + index * V5_RECORD.size)
        src, dst, _, input_if, output_if, packets, octets, first, last, sport, dport, _, _, protocol = fields[:14]
        records.append(FlowRecord(start=boot + timedelta(milliseconds=first), end=boot + timedelta(milliseconds=last),
                                  exporter=exporter, src_ip=str(ipaddress.IPv4Address(src)), dst_ip=str(ipaddress.IPv4Address(dst)),
                                  src_port=sport, dst_port=dport, protocol=protocol, bytes=octets, packets=packets,
                                  input_if=input_if, output_if=output_if, source=source))
    return records


def encode_netflow_v5(records: list[FlowRecord], export_time: datetime, sequence: int = 0) -> bytes:
    """Builds a NetFlow v5 datagram (used by the simulator and tests; the format is the exporter's wire format)."""
    if not 1 <= len(records) <= 30:
        raise FlowDecodeError("a NetFlow v5 datagram carries 1 to 30 records")
    uptime_ms = 3_600_000
    boot = export_time - timedelta(milliseconds=uptime_ms)
    body = b"".join(V5_RECORD.pack(
        ipaddress.IPv4Address(r.src_ip).packed, ipaddress.IPv4Address(r.dst_ip).packed, b"\0\0\0\0", r.input_if or 0, r.output_if or 0,
        r.packets, r.bytes, int((r.start - boot).total_seconds() * 1000), int((r.end - boot).total_seconds() * 1000),
        r.src_port, r.dst_port, 0, 0, r.protocol, 0, 0, 0, 0, 0, 0) for r in records)
    seconds = export_time.timestamp()
    return V5_HEADER.pack(5, len(records), uptime_ms, int(seconds), int((seconds % 1) * 1e9), sequence, 0, 0, 0) + body


@dataclass
class IpfixTemplateCache:
    """Templates per (exporter, observation domain, template id), as RFC 7011 requires."""
    templates: dict[tuple[str, int, int], list[tuple[int, int]]] = field(default_factory=dict)


def decode_ipfix(message: bytes, exporter: str, cache: IpfixTemplateCache, source: str = "ipfix") -> list[FlowRecord]:
    if len(message) < IPFIX_HEADER.size or len(message) > MAX_DATAGRAM:
        raise FlowDecodeError("message size is outside IPFIX bounds")
    version, length, export_time, _, domain = IPFIX_HEADER.unpack_from(message)
    if version != 10 or length != len(message):
        raise FlowDecodeError("not a well-formed IPFIX message")
    exported = datetime.fromtimestamp(export_time, timezone.utc)
    offset, records = IPFIX_HEADER.size, []
    while offset + SET_HEADER.size <= length:
        set_id, set_length = SET_HEADER.unpack_from(message, offset)
        if set_length < SET_HEADER.size or offset + set_length > length:
            raise FlowDecodeError("set length runs past the message")
        body, end = offset + SET_HEADER.size, offset + set_length
        if set_id == 2:
            while body + 4 <= end:
                template_id, count = struct.unpack_from("!HH", message, body)
                body += 4
                fields = []
                for _ in range(count):
                    element, size = struct.unpack_from("!HH", message, body)
                    body += 4
                    if element & 0x8000:
                        body += 4
                        element &= 0x7FFF
                    fields.append((element, size))
                cache.templates[(exporter, domain, template_id)] = fields
        elif set_id >= 256:
            template = cache.templates.get((exporter, domain, set_id))
            if template is None:
                offset = end
                continue
            while body < end:
                values: dict[str, Any] = {}
                for element, size in template:
                    if size == 65535:
                        size = message[body]
                        body += 1
                        if size == 255:
                            size = struct.unpack_from("!H", message, body)[0]
                            body += 2
                    if body + size > end:
                        raise FlowDecodeError("data record runs past its set")
                    raw = message[body:body + size]
                    body += size
                    name = IPFIX_FIELDS.get(element)
                    if name in ("src_ip", "dst_ip") and size == 4:
                        values[name] = str(ipaddress.IPv4Address(raw))
                    elif name:
                        values[name] = int.from_bytes(raw, "big")
                if "src_ip" not in values or "dst_ip" not in values:
                    continue
                start = (datetime.fromtimestamp(values["start_ms"] / 1000, timezone.utc) if "start_ms" in values
                         else datetime.fromtimestamp(values["start_s"], timezone.utc) if "start_s" in values else exported)
                finish = (datetime.fromtimestamp(values["end_ms"] / 1000, timezone.utc) if "end_ms" in values
                          else datetime.fromtimestamp(values["end_s"], timezone.utc) if "end_s" in values else exported)
                records.append(FlowRecord(start=start, end=finish, exporter=exporter, src_ip=values["src_ip"], dst_ip=values["dst_ip"],
                                          src_port=values.get("src_port", 0), dst_port=values.get("dst_port", 0),
                                          protocol=values.get("protocol", 0), bytes=values.get("bytes", 0),
                                          packets=values.get("packets", 0), input_if=values.get("input_if"),
                                          output_if=values.get("output_if"), source=source))
        offset = end
    return records


def encode_ipfix(records: list[FlowRecord], export_time: datetime, domain: int = 1, template_id: int = 256) -> bytes:
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (2, 8), (152, 8), (153, 8)]
    template = struct.pack("!HH", template_id, len(fields)) + b"".join(struct.pack("!HH", e, s) for e, s in fields)
    template_set = SET_HEADER.pack(2, SET_HEADER.size + len(template)) + template
    data = b"".join(ipaddress.IPv4Address(r.src_ip).packed + ipaddress.IPv4Address(r.dst_ip).packed
                    + struct.pack("!HHBQQQQ", r.src_port, r.dst_port, r.protocol, r.bytes, r.packets,
                                  int(r.start.timestamp() * 1000), int(r.end.timestamp() * 1000)) for r in records)
    data_set = SET_HEADER.pack(template_id, SET_HEADER.size + len(data)) + data
    body = template_set + data_set
    return IPFIX_HEADER.pack(10, IPFIX_HEADER.size + len(body), int(export_time.timestamp()), 0, domain) + body


# ---------------------------------------------------------------- streaming telemetry (OpenConfig paths)

OPENCONFIG = {
    "state/oper-status": "oper_status", "state/counters/in-octets": "in_bps", "state/counters/out-octets": "out_bps",
    "state/counters/in-errors": "in_errors", "state/counters/out-errors": "out_errors",
    "state/counters/in-discards": "in_discards", "state/counters/out-discards": "out_discards",
}
INTERFACE_PATH = re.compile(r"^/?interfaces/interface\[name=(?P<name>[^\]]+)\]/(?P<leaf>.+)$")
SYSTEM_PATHS = {"system/cpus/cpu/state/total/instant": "cpu_percent", "system/memory/state/utilized-percent": "memory_percent"}


class StreamingUpdate(Record):
    """One update as a gNMI collector exports it in JSON (for example gnmic's event format)."""
    source: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    timestamp: datetime
    values: dict[str, float | int | str] = Field(min_length=1, max_length=64)


def normalize_streaming(update: StreamingUpdate, origin: str = "gnmi") -> tuple[list[TelemetrySample], list[str]]:
    samples, skipped = [], []
    for path, raw in update.values.items():
        clean = path.strip("/")
        interface, leaf = None, clean
        if match := INTERFACE_PATH.match(clean):
            interface, leaf = match["name"], match["leaf"]
        metric = OPENCONFIG.get(leaf) if interface else SYSTEM_PATHS.get(leaf)
        if metric is None:
            skipped.append(path[:120])
            continue
        if metric == "oper_status":
            value = 1.0 if str(raw).upper() == "UP" else 0.0
        else:
            try:
                value = float(raw)
            except (TypeError, ValueError):
                skipped.append(path[:120])
                continue
            if metric in ("in_bps", "out_bps"):
                value *= 8
        samples.append(TelemetrySample(device_id=update.source, interface=interface, metric=metric, value=value,
                                       timestamp=update.timestamp, source=origin))
    return samples, skipped


def group_by(items: list[Any], key) -> dict[Any, list[Any]]:
    grouped: dict[Any, list[Any]] = defaultdict(list)
    for item in items:
        grouped[key(item)].append(item)
    return grouped
