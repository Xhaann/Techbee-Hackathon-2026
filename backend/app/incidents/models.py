from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.engine.safety import is_read_only_command
from app.engine.schema import Confidence, Diagnosis, DiagnosisMethod, DiagnosisStatus, FaultDomain
from app.network.models import (
    DeviceId,
    Identifier,
    IncidentPriority,
    PathService,
    UtcDatetime,
    ensure_unique,
)

IncidentId = Annotated[str, Field(pattern=r"^INC-\d{8}-\d{4}$")]
RecordId = Annotated[str, Field(pattern=r"^[A-Z]{3}-\d{8}-\d{4}-\d{2,4}$")]
Title = Annotated[str, Field(min_length=3, max_length=200)]
Text = Annotated[str, Field(min_length=1, max_length=4000)]
Note = Annotated[str, Field(min_length=1, max_length=1000)]
Team = Annotated[str, Field(min_length=1, max_length=120)]


class IncidentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class LifecycleStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    DIAGNOSED = "diagnosed"
    ESCALATED = "escalated"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    CLOSED = "closed"


TRANSITIONS: dict[LifecycleStatus, frozenset[LifecycleStatus]] = {
    LifecycleStatus.NEW: frozenset({LifecycleStatus.ACKNOWLEDGED}),
    LifecycleStatus.ACKNOWLEDGED: frozenset({LifecycleStatus.INVESTIGATING}),
    LifecycleStatus.INVESTIGATING: frozenset({LifecycleStatus.DIAGNOSED, LifecycleStatus.ESCALATED, LifecycleStatus.MONITORING}),
    LifecycleStatus.DIAGNOSED: frozenset({LifecycleStatus.INVESTIGATING, LifecycleStatus.ESCALATED, LifecycleStatus.MONITORING}),
    LifecycleStatus.ESCALATED: frozenset({LifecycleStatus.INVESTIGATING, LifecycleStatus.DIAGNOSED, LifecycleStatus.MONITORING}),
    LifecycleStatus.MONITORING: frozenset({LifecycleStatus.INVESTIGATING, LifecycleStatus.ESCALATED, LifecycleStatus.RESOLVED}),
    LifecycleStatus.RESOLVED: frozenset({LifecycleStatus.CLOSED, LifecycleStatus.INVESTIGATING}),
    LifecycleStatus.CLOSED: frozenset({LifecycleStatus.INVESTIGATING}),
}
ACTIVE_STATUSES = frozenset(set(LifecycleStatus) - {LifecycleStatus.RESOLVED, LifecycleStatus.CLOSED})
SEVERITY_RANK = {IncidentSeverity.LOW: 0, IncidentSeverity.MEDIUM: 1, IncidentSeverity.HIGH: 2, IncidentSeverity.CRITICAL: 3}
PRIORITY_FOR_SEVERITY = {IncidentSeverity.CRITICAL: IncidentPriority.P1, IncidentSeverity.HIGH: IncidentPriority.P2,
                         IncidentSeverity.MEDIUM: IncidentPriority.P3, IncidentSeverity.LOW: IncidentPriority.P4}
SEVERITY_FOR_PRIORITY = {priority: severity for severity, priority in PRIORITY_FOR_SEVERITY.items()}


class ActorKind(str, Enum):
    HUMAN = "human"
    SYSTEM = "system"
    AI = "ai"


class Actor(IncidentModel):
    kind: ActorKind
    actor_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._@-]{0,63}$")]


class IncidentSource(str, Enum):
    USER_REPORT = "user_report"
    MONITORING = "monitoring"
    SERVICE_DESK = "service_desk"
    DIAGNOSIS_ENGINE = "diagnosis_engine"


class ValueSource(str, Enum):
    MANUAL = "manual"
    DERIVED = "derived"
    DEFAULT = "default"


class EventType(str, Enum):
    CREATED = "created"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATION_STARTED = "investigation_started"
    STATUS_CHANGED = "status_changed"
    DETAILS_UPDATED = "details_updated"
    RELATED_REPORT_LINKED = "related_report_linked"
    DIAGNOSTIC_TOOLS_EXECUTED = "diagnostic_tools_executed"
    DIAGNOSIS_COMPLETED = "diagnosis_completed"
    DIAGNOSIS_SUPERSEDED = "diagnosis_superseded"
    CLASSIFICATION_CHANGED = "classification_changed"
    SEVERITY_CHANGED = "severity_changed"
    PRIORITY_CHANGED = "priority_changed"
    ASSETS_UPDATED = "assets_updated"
    ESCALATION_CREATED = "escalation_created"
    ESCALATION_UPDATED = "escalation_updated"
    MONITORING_STARTED = "monitoring_started"
    RESOLUTION_PROPOSED = "resolution_proposed"
    RESOLUTION_VERIFIED = "resolution_verified"
    RESOLUTION_REJECTED = "resolution_rejected"
    RESOLVED = "resolved"
    CLOSED = "closed"
    REOPENED = "reopened"
    KNOWLEDGE_LINKED = "knowledge_linked"


class TimelineEvent(IncidentModel):
    event_id: Annotated[str, Field(pattern=r"^INC-\d{8}-\d{4}-EV\d{4}$")]
    incident_id: IncidentId
    sequence: int = Field(ge=1)
    event_type: EventType
    timestamp: UtcDatetime
    actor: Actor
    description: Annotated[str, Field(min_length=1, max_length=2000)]
    device_id: DeviceId | None = None
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    diagnosis_id: RecordId | None = None
    from_status: LifecycleStatus | None = None
    to_status: LifecycleStatus | None = None
    details: dict[str, str] = Field(default_factory=dict)


class AssetType(str, Enum):
    SITE = "site"
    DEVICE = "device"
    INTERFACE = "interface"
    LINK = "link"
    SERVICE = "service"
    PATH = "path"
    SHARED_DEPENDENCY = "shared_dependency"


class ImpactBasis(str, Enum):
    REPORTED = "reported"
    INFERRED = "inferred"
    CONFIRMED = "confirmed"


IMPACT_RANK = {ImpactBasis.REPORTED: 0, ImpactBasis.INFERRED: 1, ImpactBasis.CONFIRMED: 2}


class AffectedAsset(IncidentModel):
    asset_type: AssetType
    asset_id: Annotated[str, Field(min_length=1, max_length=96)]
    basis: ImpactBasis
    sources: list[str] = Field(min_length=1, max_length=20)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    first_recorded_at: UtcDatetime

    @property
    def key(self) -> tuple[str, str]:
        return self.asset_type.value, self.asset_id


class Classification(IncidentModel):
    probable_fault_domain: FaultDomain | None = None
    probable_source_diagnosis_id: RecordId | None = None
    confirmed_fault_domain: FaultDomain | None = None
    confirmed_by: Actor | None = None
    confirmed_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def check_confirmation(self) -> "Classification":
        if (self.confirmed_fault_domain is None) != (self.confirmed_by is None) or (self.confirmed_by is None) != (self.confirmed_at is None):
            raise ValueError("confirmed classification requires the confirming actor and time")
        return self


class DiagnosisRecord(IncidentModel):
    diagnosis_id: RecordId
    incident_id: IncidentId
    created_at: UtcDatetime
    method: DiagnosisMethod
    status: DiagnosisStatus
    probable_fault_domain: FaultDomain
    confidence: Confidence
    root_cause: str
    alternative_fault_domains: list[FaultDomain]
    human_verified: Literal[False] = False
    superseded_by: RecordId | None = None
    diagnosis: Diagnosis


class KnowledgeReference(IncidentModel):
    record_id: Annotated[str, Field(pattern=r"^(PB|RB|KD|DP)-[A-Z0-9]+(?:-[A-Z0-9]+)*$")]
    record_type: Literal["playbook", "runbook", "document", "procedure"]
    title: Annotated[str, Field(min_length=1, max_length=200)]
    version: Annotated[str, Field(pattern=r"^\d+\.\d+\.\d+$")]
    match_type: Literal["exact", "partial", "site"]
    reasons: list[Annotated[str, Field(max_length=400)]] = Field(default_factory=list, max_length=10)
    source_ids: list[Annotated[str, Field(pattern=r"^SRC-[A-Z0-9-]+$")]] = Field(min_length=1, max_length=5)
    diagnosis_id: RecordId | None = None
    linked_at: UtcDatetime
    linked_by: Actor


class EvidenceLink(IncidentModel):
    diagnosis_id: RecordId
    evidence_id: str = Field(pattern=r"^E\d+$")
    tool: str
    code: str
    device_id: str | None = None
    timestamp: UtcDatetime | None = None


class EscalationStatus(str, Enum):
    RECOMMENDED = "recommended"
    ASSIGNED = "assigned"
    CLOSED = "closed"
    CANCELLED = "cancelled"


OPEN_ESCALATION_STATUSES = frozenset({EscalationStatus.RECOMMENDED, EscalationStatus.ASSIGNED})


class OutstandingCheck(IncidentModel):
    device_id: DeviceId
    command: str = Field(min_length=1, max_length=200)
    purpose: str = Field(min_length=1, max_length=600)

    @model_validator(mode="after")
    def check_read_only(self) -> "OutstandingCheck":
        if not is_read_only_command(self.command):
            raise ValueError("outstanding checks must be approved read-only commands")
        return self


class EscalationRecord(IncidentModel):
    escalation_id: RecordId
    incident_id: IncidentId
    created_at: UtcDatetime
    created_by: Actor
    recommended_team: Team
    assigned_team: Team | None = None
    priority: IncidentPriority
    reason: Note
    fault_domain: FaultDomain
    diagnosis_id: RecordId | None = None
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    outstanding_checks: list[OutstandingCheck] = Field(default_factory=list, max_length=10)
    handover_summary: Annotated[str, Field(min_length=1, max_length=4000)]
    status: EscalationStatus
    delivery: Literal["not_sent"] = "not_sent"
    status_notes: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def check_assignment(self) -> "EscalationRecord":
        if self.status == EscalationStatus.ASSIGNED and not self.assigned_team:
            raise ValueError("an assigned escalation requires an assigned team")
        return self


class VerificationStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    REVERTED = "reverted"


class Resolution(IncidentModel):
    resolution_id: RecordId
    summary: Note
    fault_domain: FaultDomain
    notes: list[str] = Field(default_factory=list, max_length=20)
    proposed_by: Actor
    proposed_at: UtcDatetime
    responsible_team: Team | None = None
    verification: VerificationStatus
    verified_by: Actor | None = None
    verified_at: UtcDatetime | None = None
    resolved_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def check_verification(self) -> "Resolution":
        decided = self.verification in (VerificationStatus.VERIFIED, VerificationStatus.REJECTED)
        if decided and (self.verified_by is None or self.verified_at is None):
            raise ValueError("a verification decision requires the verifying actor and time")
        if decided and self.verified_by.kind != ActorKind.HUMAN:
            raise ValueError("resolution verification requires a human actor")
        if (self.verification == VerificationStatus.VERIFIED) != (self.resolved_at is not None) and self.verification != VerificationStatus.REVERTED:
            raise ValueError("resolved_at is set exactly when the resolution is verified")
        return self


class Closure(IncidentModel):
    closed_at: UtcDatetime
    closed_by: Actor
    notes: Note


class Incident(IncidentModel):
    incident_id: IncidentId
    version: int = Field(ge=1)
    title: Title
    description: Text
    source: IncidentSource
    dataset_scenario_id: Identifier | None = None
    site_ids: list[Identifier] = Field(min_length=1, max_length=10)
    symptoms: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(default_factory=list, max_length=20)
    severity: IncidentSeverity
    severity_source: ValueSource
    priority: IncidentPriority
    priority_source: ValueSource
    status: LifecycleStatus
    classification: Classification = Classification()
    assigned_team: Team | None = None
    assigned_owner: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._@-]{0,63}$")] | None = None
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    affected_path: list[DeviceId] = Field(default_factory=list)
    active_diagnosis_id: RecordId | None = None
    diagnoses: list[DiagnosisRecord] = Field(default_factory=list)
    evidence: list[EvidenceLink] = Field(default_factory=list)
    escalations: list[EscalationRecord] = Field(default_factory=list)
    resolutions: list[Resolution] = Field(default_factory=list)
    closure: Closure | None = None
    security_flags: list[str] = Field(default_factory=list)
    knowledge_references: list[KnowledgeReference] = Field(default_factory=list, max_length=50)
    created_at: UtcDatetime
    updated_at: UtcDatetime
    timeline: list[TimelineEvent] = Field(min_length=1)

    @property
    def active_diagnosis(self) -> DiagnosisRecord | None:
        return next((record for record in self.diagnoses if record.diagnosis_id == self.active_diagnosis_id), None)

    @property
    def current_resolution(self) -> Resolution | None:
        return self.resolutions[-1] if self.resolutions else None

    @property
    def fault_domain(self) -> FaultDomain | None:
        return self.classification.confirmed_fault_domain or self.classification.probable_fault_domain

    @model_validator(mode="after")
    def check_integrity(self) -> "Incident":
        ensure_unique([event.event_id for event in self.timeline], "timeline event ids")
        ensure_unique([record.diagnosis_id for record in self.diagnoses], "diagnosis ids")
        ensure_unique([record.escalation_id for record in self.escalations], "escalation ids")
        ensure_unique([record.resolution_id for record in self.resolutions], "resolution ids")
        ensure_unique([f"{a.asset_type.value}:{a.asset_id}" for a in self.affected_assets], "affected assets")
        ensure_unique([f"{e.diagnosis_id}:{e.evidence_id}" for e in self.evidence], "evidence links")
        ensure_unique([f"{k.record_id}:{k.version}" for k in self.knowledge_references], "knowledge references")
        ensure_unique(self.site_ids, "site ids")
        if any(event.incident_id != self.incident_id or not event.event_id.startswith(f"{self.incident_id}-")
               for event in self.timeline):
            raise ValueError("timeline events must belong to the incident")
        if [event.sequence for event in self.timeline] != list(range(1, len(self.timeline) + 1)):
            raise ValueError("timeline sequence must be contiguous from 1")
        if any(b.timestamp < a.timestamp for a, b in zip(self.timeline, self.timeline[1:])):
            raise ValueError("timeline timestamps must be non-decreasing")
        if self.timeline[0].event_type != EventType.CREATED:
            raise ValueError("the first timeline event must be the creation event")
        if not self.created_at <= self.updated_at or self.timeline[-1].timestamp > self.updated_at:
            raise ValueError("updated_at must not precede creation or timeline events")
        diagnoses = {record.diagnosis_id: record for record in self.diagnoses}
        if self.active_diagnosis_id is not None and self.active_diagnosis_id not in diagnoses:
            raise ValueError("active diagnosis must be one of the incident diagnoses")
        if any(record.incident_id != self.incident_id for record in self.diagnoses):
            raise ValueError("diagnoses must belong to the incident")
        for link in self.evidence:
            record = diagnoses.get(link.diagnosis_id)
            if record is None or link.evidence_id not in {item.evidence_id for item in record.diagnosis.evidence}:
                raise ValueError(f"evidence link {link.diagnosis_id}:{link.evidence_id} does not resolve to a diagnosis")
        resolution = self.current_resolution
        if self.status in (LifecycleStatus.RESOLVED, LifecycleStatus.CLOSED):
            if resolution is None or resolution.verification != VerificationStatus.VERIFIED:
                raise ValueError("resolved or closed incidents require a human-verified resolution")
        if (self.status == LifecycleStatus.CLOSED) != (self.closure is not None):
            raise ValueError("closure details are present exactly when the incident is closed")
        return self


class IncidentCreateRequest(IncidentModel):
    title: Title
    description: Text
    site_ids: list[Identifier] = Field(min_length=1, max_length=10)
    device_ids: list[DeviceId] = Field(default_factory=list, max_length=20)
    services: list[PathService] = Field(default_factory=list, max_length=5)
    symptoms: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(default_factory=list, max_length=20)
    severity: IncidentSeverity | None = None
    priority: IncidentPriority | None = None
    source: IncidentSource = IncidentSource.USER_REPORT
    dataset_scenario_id: Identifier | None = None
    reported_at: UtcDatetime | None = None
    force_new: bool = False


class IncidentFilter(IncidentModel):
    site_id: Identifier | None = None
    device_id: DeviceId | None = None
    severity: IncidentSeverity | None = None
    status: LifecycleStatus | None = None
    fault_domain: FaultDomain | None = None
    start: UtcDatetime | None = None
    end: UtcDatetime | None = None
    limit: int = Field(default=100, ge=1, le=500)

    @model_validator(mode="after")
    def check_range(self) -> "IncidentFilter":
        if self.start is not None and self.end is not None and self.start >= self.end:
            raise ValueError("start must be earlier than end")
        return self


class IncidentSummary(IncidentModel):
    incident_id: IncidentId
    title: str
    site_ids: list[str]
    device_ids: list[str]
    severity: IncidentSeverity
    priority: IncidentPriority
    status: LifecycleStatus
    fault_domain: FaultDomain | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def of(cls, incident: Incident) -> "IncidentSummary":
        devices = sorted({a.asset_id for a in incident.affected_assets
                          if a.asset_type in (AssetType.DEVICE, AssetType.SHARED_DEPENDENCY)})
        return cls(incident_id=incident.incident_id, title=incident.title, site_ids=incident.site_ids, device_ids=devices,
                   severity=incident.severity, priority=incident.priority, status=incident.status,
                   fault_domain=incident.fault_domain, created_at=incident.created_at, updated_at=incident.updated_at)
