"""SNMP polling, trap analysis and syslog intelligence over the scenario data, through the real decoders.

The scenario's events are rendered to the wire formats devices send (syslog lines, SNMP traps) and parsed back with the
same adapters that handle ingested data, so the simulated and ingested paths share one implementation.
"""
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from app.network.models import DeviceType, LinkStatus, Severity
from app.network.repository import load_scenario, load_topology
from app.observability.adapters import (
    EVENT_TO_TRAP,
    IF_COUNTERS,
    IF_DESCR,
    CounterSample,
    NetworkEventRecord,
    SnmpPoller,
    TrapPayload,
    normalize_trap,
    parse_syslog,
    syslog_event,
    syslog_intelligence,
    trap_analysis,
)
from app.observability.simulation import seeded

SEVERITY_NUMBER = {Severity.EMERGENCY: 0, Severity.ALERT: 1, Severity.CRITICAL: 2, Severity.ERROR: 3, Severity.WARNING: 4,
                   Severity.NOTICE: 5, Severity.INFORMATIONAL: 6, Severity.DEBUG: 7}
LOCAL7 = 23
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


class SimulatedSnmpTransport:
    """IF-MIB counters reconstructed from the scenario's interface statistics: octet counters integrate the measured bit
    rates, sysUpTime comes from the sampled uptime, and some 32-bit error counters start close to their wrap point so the
    rate calculation has to handle a wrap. No packet leaves the process."""

    def __init__(self, scenario_id: str) -> None:
        self.scenario_id = scenario_id
        self.dataset = load_scenario(scenario_id)
        topology = load_topology()
        self.interfaces = {i.interface_id: i for i in topology.interfaces}
        self.index = {i.interface_id: n for n, i in enumerate(sorted(topology.interfaces, key=lambda x: x.interface_id), start=1)}

    def interface_counters(self, device_id: str, moment: datetime) -> list[CounterSample]:
        samples = sorted((s for s in self.dataset.interface_statistics if s.device_id == device_id and s.timestamp <= moment),
                         key=lambda s: s.timestamp)
        by_interface: dict[str, list] = {}
        for sample in samples:
            by_interface.setdefault(sample.interface_id, []).append(sample)
        result = []
        for interface_id, series in sorted(by_interface.items()):
            rng = seeded("snmp", self.scenario_id, interface_id)
            base = {name: rng.randrange(2 ** 40) if name.startswith("ifHC") else rng.randrange(2 ** 20) for name in IF_COUNTERS}
            if rng.random() < 0.25:
                base["ifInErrors"] = 2 ** 32 - rng.randrange(1, 50)  # about to wrap
            totals = dict(base)
            for sample in series:
                seconds = sample.interval_seconds
                totals["ifHCInOctets"] += int(sample.in_bps * seconds / 8)
                totals["ifHCOutOctets"] += int(sample.out_bps * seconds / 8)
                totals["ifInErrors"] += sample.in_errors + (rng.randrange(3, 9) if base["ifInErrors"] > 2 ** 31 else 0)
                totals["ifOutErrors"] += sample.out_errors
                totals["ifInDiscards"] += sample.in_drops
                totals["ifOutDiscards"] += sample.out_drops
            wrapped = {name: value % (2 ** 64 if name.startswith("ifHC") else 2 ** 32) for name, value in totals.items()}
            latest = series[-1]
            interface = self.interfaces[interface_id]
            result.append(CounterSample(device_id, interface.name, self.index[interface_id], latest.timestamp,
                                        latest.uptime_seconds * 100, 1 if latest.oper_status == LinkStatus.UP else 2, wrapped,
                                        interface.speed_mbps * 1_000_000))
        return result


@lru_cache(maxsize=256)
def snmp_poll(scenario_id: str, device_id: str) -> dict[str, Any]:
    dataset = load_scenario(scenario_id)
    times = sorted({s.timestamp for s in dataset.interface_statistics if s.device_id == device_id})
    if len(times) < 2:
        return {"device_id": device_id, "polls": len(times), "interfaces": [],
                "notes": ["Fewer than two polls answered in the window; rates need two"]}
    poller = SnmpPoller(SimulatedSnmpTransport(scenario_id))
    poller.poll(device_id, times[-2])
    rows = []
    for counters, rate in poller.poll(device_id, times[-1]):
        previous = poller.calculator.previous.get((device_id, counters.if_index))
        rows.append({
            "interface": counters.interface, "if_index": counters.if_index, "oper_status": "up" if counters.oper_status == 1 else "down",
            "speed_bps": counters.speed_bps, "polled_at": counters.timestamp.isoformat(), "sys_uptime_ticks": counters.sys_uptime_ticks,
            "counters": counters.counters,
            "rates": {k: round(v, 3) for k, v in rate.rates.items()} if rate.rates else None, "note": rate.reason,
            "wrapped": [name for name in IF_COUNTERS if previous and rate.rates and counters.counters[name] < 2 ** 16
                        and rate.rates[name] > 0 and name in ("ifInErrors", "ifOutErrors")],
        })
    last_gap = max(dataset.interface_statistics, key=lambda s: s.timestamp).timestamp
    notes = [] if times[-1] == last_gap else [f"The device stopped answering polls after {times[-1]:%H:%M}"]
    return {"device_id": device_id, "transport": "simulated (IF-MIB counters reconstructed from scenario samples)",
            "polls": len(times), "interval_seconds": int((times[-1] - times[-2]).total_seconds()), "interfaces": rows, "notes": notes}


def snmp_overview(scenario_id: str) -> dict[str, Any]:
    topology = load_topology()
    polled = [d for d in topology.devices if d.device_type != DeviceType.SERVER]
    results = [snmp_poll(scenario_id, d.device_id) for d in polled]
    return {"devices": [{"device_id": r["device_id"], "polls": r["polls"], "interfaces": len(r["interfaces"]),
                         "down": sum(i["oper_status"] == "down" for i in r["interfaces"]),
                         "wraps_handled": sum(len(i["wrapped"]) for i in r["interfaces"]),
                         "discontinuities": sum(1 for i in r["interfaces"] if i["note"] and "discontinuity" in i["note"]),
                         "notes": r["notes"]} for r in results]}


@lru_cache(maxsize=32)
def scenario_traps(scenario_id: str) -> tuple[NetworkEventRecord, ...]:
    dataset = load_scenario(scenario_id)
    topology = load_topology()
    names = {i.interface_id: i.name for i in topology.interfaces}
    index = {i.interface_id: n for n, i in enumerate(sorted(topology.interfaces, key=lambda x: x.interface_id), start=1)}
    traps = []
    for event in sorted(dataset.events, key=lambda e: (e.timestamp, e.event_id)):
        oid = EVENT_TO_TRAP.get(event.event_type)
        if oid is None:
            continue
        varbinds = {f"{IF_DESCR}.{index[event.interface_id]}": names[event.interface_id]} if event.interface_id in names else {}
        traps.append(normalize_trap(TrapPayload(trap_oid=oid, device_id=event.device_id, timestamp=event.timestamp, varbinds=varbinds),
                                    source="simulated_trap"))
    return tuple(traps)


def trap_view(scenario_id: str, extra: list[NetworkEventRecord] | None = None) -> dict[str, Any]:
    traps = list(scenario_traps(scenario_id)) + list(extra or [])
    analysis = trap_analysis(traps)
    analysis["recent"] = [t.model_dump(mode="json") for t in sorted(traps, key=lambda t: t.timestamp, reverse=True)[:50]]
    return analysis


def render_syslog(event, hostname: str) -> str:
    severity = SEVERITY_NUMBER[event.severity]
    stamp = f"{MONTHS[event.timestamp.month - 1]} {event.timestamp.day:2d} {event.timestamp:%H:%M:%S}"
    text = event.message if event.message.startswith("%") else f"%{event.event_type.split('_')[0]}-{severity}-{event.event_type}: {event.message}"
    return f"<{LOCAL7 * 8 + severity}>{stamp} {hostname} {text}"


@lru_cache(maxsize=32)
def scenario_syslog(scenario_id: str) -> tuple[tuple[str, str], ...]:
    """(device_id, raw line) for every scenario event, as the device would have sent it."""
    dataset = load_scenario(scenario_id)
    hostnames = {d.device_id: d.hostname for d in load_topology().devices}
    return tuple((e.device_id, render_syslog(e, hostnames[e.device_id])) for e in sorted(dataset.events, key=lambda e: (e.timestamp, e.event_id)))


def syslog_view(scenario_id: str, extra: list[NetworkEventRecord] | None = None, limit: int = 25) -> dict[str, Any]:
    dataset = load_scenario(scenario_id)
    received = dataset.scenario.window_end + timedelta(minutes=1)
    parsed = [(device, parse_syslog(line, received)) for device, line in scenario_syslog(scenario_id)]
    report = syslog_intelligence(parsed, limit=limit)
    report["formats"] = sorted({m.format for _, m in parsed})
    report["ingested"] = len(extra or [])
    report["recent"] = [{"device_id": d, "timestamp": m.timestamp.isoformat(), "severity": m.severity, "mnemonic": m.mnemonic,
                         "text": m.text} for d, m in parsed[-40:]][::-1]
    if extra:
        report["recent_ingested"] = [e.model_dump(mode="json") for e in extra[-40:]][::-1]
    return report


def parse_ingested(lines: list[str], hosts: dict[str, str], received_at: datetime | None = None,
                   source: str = "api") -> tuple[list[NetworkEventRecord], list[dict[str, Any]]]:
    """Parses pushed syslog lines; a line is accepted only when its host maps to a device in the inventory."""
    moment = received_at or datetime.now(timezone.utc)
    events, rejected = [], []
    for position, line in enumerate(lines):
        message = parse_syslog(line, moment)
        device = hosts.get(message.host.lower())
        if device is None:
            rejected.append({"index": position, "reason": f"unknown host '{message.host[:40]}'"})
            continue
        events.append(syslog_event(message, device, source))
    return events, rejected
