"""Shared types for the protocol engines.

An engine reads one section of the synthetic protocol telemetry (and, where it helps, the core dataset) and returns
drafts: what it found, how strong the basis is and which records it rests on. It never assigns ids or confidence; the
registry does that centrally so every engine is calibrated the same way.
"""
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property
from ipaddress import IPv4Address, IPv4Network, ip_address
from typing import Any, Literal

from app.diagnostics import EvidenceRef
from app.engine.safety import INJECTION_PATTERNS
from app.network.models import NetworkTopology, ScenarioDataset
from app.protocols.models import ProtocolTelemetry

Status = Literal["confirmed_fault", "suspicious_indicator", "possible_explanation", "insufficient_evidence"]
Kind = Literal["misconfiguration", "anomaly", "conflicting_state", "dependency", "threat_indicator", "performance", "coverage"]
Severity = Literal["critical", "major", "minor", "info"]
# How directly the data shows the problem: both ends agree (two_sided), the device states it (direct), a measurement
# crosses a threshold (measured), a behaviour pattern (behavioural) or a deduction from other findings (inferred).
Strength = Literal["two_sided", "direct", "measured", "behavioural", "inferred", "none"]

MAX_REFS = 8


def ref(collection: str, record_id: str, timestamp: datetime | None = None) -> EvidenceRef:
    return EvidenceRef(collection=collection, record_id=record_id, timestamp=timestamp)


def has_injection(text: str | None) -> bool:
    return bool(text) and any(pattern.search(text) for pattern in INJECTION_PATTERNS)


INTERNAL = tuple(IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def internal(address: Any) -> bool:
    """Inside our network (RFC 1918). Python's is_private also covers the documentation ranges the simulation uses for
    outside hosts, so it cannot be used here."""
    try:
        value = ip_address(str(address))
    except ValueError:
        return False
    return any(value in network for network in INTERNAL) if value.version == 4 else False


@dataclass
class Draft:
    code: str
    status: Status
    kind: Kind
    severity: Severity
    title: str
    summary: str
    strength: Strength
    evidence: list[EvidenceRef]
    basis: str
    device_id: str | None = None
    site_id: str | None = None
    timestamp: datetime | None = None
    affected_sites: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    corroboration: int = 0  # independent sources that agree beyond the first
    contradictions: int = 0
    benign: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)  # host IPs involved, for the security correlation
    injection: bool = False


@dataclass
class EngineOutput:
    drafts: list[Draft] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    applicable: bool = True


@dataclass
class Context:
    topology: NetworkTopology
    dataset: ScenarioDataset
    telemetry: ProtocolTelemetry
    site_id: str | None = None
    device_id: str | None = None
    prior: dict[str, list[Draft]] = field(default_factory=dict)  # earlier engines' drafts in the same run

    @property
    def scenario_id(self) -> str:
        return self.dataset.scenario.scenario_id

    @property
    def onset(self) -> datetime:
        return self.dataset.scenario.onset_at

    @property
    def window_start(self) -> datetime:
        return self.dataset.scenario.window_start

    @property
    def window_end(self) -> datetime:
        return self.dataset.scenario.window_end

    @cached_property
    def devices(self) -> dict[str, Any]:
        return {d.device_id: d for d in self.topology.devices}

    @cached_property
    def site_of(self) -> dict[str, str]:
        values = {d.device_id: d.site_id for d in self.topology.devices}
        if self.telemetry.wireless is not None:
            values |= {ap.ap_id: ap.site_id for ap in self.telemetry.wireless.access_points}
        return values

    @cached_property
    def interfaces(self) -> dict[str, Any]:
        return {i.interface_id: i for i in self.topology.interfaces}

    @cached_property
    def site_networks(self) -> list[tuple[IPv4Network, str, int]]:
        return [(v.subnet, v.site_id, v.vlan_id) for v in self.topology.vlans]

    def site_of_ip(self, address: Any) -> str | None:
        try:
            value = IPv4Address(str(address))
        except ValueError:
            return None
        return next((site for network, site, _ in self.site_networks if value in network), None)

    @cached_property
    def asns(self) -> set[int]:
        return {d.bgp_asn for d in self.topology.devices if d.bgp_asn}

    @cached_property
    def site_paths(self) -> dict[str, list[Any]]:
        paths: dict[str, list[Any]] = {}
        for path in self.topology.paths:
            paths.setdefault(path.source_site_id, []).append(path)
        return paths

    def sites_through(self, device_id: str) -> list[str]:
        """Sites whose service paths cross the device (the device's own site first)."""
        sites = sorted({p.source_site_id for p in self.topology.paths if device_id in p.device_ids})
        own = self.site_of.get(device_id)
        if own in sites:
            sites.remove(own)
            sites.insert(0, own)
        return sites or ([own] if own else [])

    def sites_served_by(self, device_ids: list[str]) -> list[str]:
        return sorted({p.source_site_id for p in self.topology.paths if p.device_ids[-1] in device_ids})

    def stale(self, collected_at: datetime) -> bool:
        return collected_at < self.window_start

    def text(self, value: str | None) -> str:
        """Device-supplied text is untrusted: instruction-like content is withheld, never repeated or followed."""
        if value is None:
            return ""
        return "[device text withheld: it contained instruction-like content]" if has_injection(value) else value

    def maintenance(self, device_id: str | None, at: datetime | None, host: str | None = None) -> str | None:
        security = self.telemetry.security
        if security is None or at is None:
            return None
        for window in security.allowlist.maintenance:
            covered = (device_id in window.devices) or (host is not None and host in {str(h) for h in window.hosts})
            if covered and window.start <= at <= window.end:
                return self.text(window.reason)
        return None


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def pct(value: float) -> str:
    return f"{value:.1f}%" if value < 10 else f"{value:.0f}%"
