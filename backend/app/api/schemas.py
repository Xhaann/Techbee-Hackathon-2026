from datetime import datetime
from typing import Annotated, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent.review import AgentReport
from app.engine.schema import EvidenceItem, FaultDomain
from app.incidents.models import DeviceId, EscalationRecord, EscalationStatus, IncidentId, IncidentSeverity, LifecycleStatus
from app.network.models import Identifier, IncidentPriority, PathService

T = TypeVar("T")
Note = Annotated[str, Field(min_length=1, max_length=1000)]
Version = Annotated[int, Field(ge=1)]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Page(ApiModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class PrincipalView(ApiModel):
    subject: str
    kind: str
    roles: list[str]
    permissions: list[str]
    authenticated: bool


class IncidentPatch(ApiModel):
    expected_version: Version
    title: Annotated[str, Field(min_length=3, max_length=200)] | None = None
    description: Annotated[str, Field(min_length=1, max_length=4000)] | None = None
    assigned_team: Annotated[str, Field(min_length=1, max_length=120)] | None = None
    assigned_owner: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._@-]{0,63}$")] | None = None
    severity: IncidentSeverity | None = None
    priority: IncidentPriority | None = None
    status: LifecycleStatus | None = None
    reason: Note | None = None


class VersionedRequest(ApiModel):
    expected_version: Version


class ClassificationRequest(VersionedRequest):
    fault_domain: FaultDomain
    reason: Note


class ResolutionRequest(VersionedRequest):
    action: Literal["propose", "verify"]
    summary: Note | None = None
    fault_domain: FaultDomain | None = None
    notes: list[Note] = Field(default_factory=list, max_length=20)
    responsible_team: Annotated[str, Field(min_length=1, max_length=120)] | None = None
    approved: bool | None = None
    note: Note | None = None


class CloseRequest(VersionedRequest):
    note: Note


class ReopenRequest(VersionedRequest):
    reason: Note


class EscalationRequest(VersionedRequest):
    team: Annotated[str, Field(min_length=1, max_length=120)] | None = None
    priority: IncidentPriority | None = None
    reason: Note | None = None


class EscalationUpdateRequest(VersionedRequest):
    status: EscalationStatus
    note: Note
    assigned_team: Annotated[str, Field(min_length=1, max_length=120)] | None = None


class CountSummary(ApiModel):
    total: int
    counts: dict[str, dict[str, int]]


class EvidenceView(ApiModel):
    diagnosis_id: str | None
    evidence: EvidenceItem


class EvidencePage(Page[EvidenceView]):
    provenance_verified: bool
    unverified_diagnosis_ids: list[str]


class EscalationView(EscalationRecord):
    delivery_status: Literal["not_sent"] = "not_sent"


class DeviceHealth(ApiModel):
    device_id: str
    site_id: str
    status: str
    finding_codes: list[str]


class NetworkHealth(ApiModel):
    scenario_id: str
    synthetic: Literal[True] = True
    device_count: int
    status_counts: dict[str, int]
    sites: dict[str, dict[str, int]]
    devices: list[DeviceHealth]


class IncidentReportRow(ApiModel):
    incident_id: str
    title: str
    status: str
    severity: str
    priority: str
    fault_domain: str | None
    confirmed_fault_domain: str | None
    diagnoses: int
    escalations: int
    resolution_verification: str | None
    created_at: datetime
    closed_at: datetime | None


class AgentDiagnoseRequest(ApiModel):
    description: Annotated[str, Field(min_length=1, max_length=4000)]
    scenario_id: Annotated[Identifier, Field(max_length=64)] | None = None
    site_ids: list[Annotated[Identifier, Field(max_length=32)]] = Field(default_factory=list, max_length=5)
    device_ids: list[DeviceId] = Field(default_factory=list, max_length=20)
    services: list[PathService] = Field(default_factory=list, max_length=5)
    incident_id: IncidentId | None = None
    mode: Literal["agent", "rule_based"] = "agent"
    attach_to_incident: bool = False
    expected_version: Version | None = None

    @model_validator(mode="after")
    def attachment_requires_incident_version(self) -> "AgentDiagnoseRequest":
        if self.attach_to_incident and (self.incident_id is None or self.expected_version is None):
            raise ValueError("attach_to_incident requires incident_id and expected_version")
        if self.expected_version is not None and not self.attach_to_incident:
            raise ValueError("expected_version is only accepted with attach_to_incident")
        return self


class AgentExecution(ApiModel):
    request_id: str | None
    mode: Literal["agent", "rule_based"]
    method: str
    provider_status: Literal["completed", "fallback", "not_used"]
    model: str | None
    duration_ms: int
    tool_calls: int
    budget_used: int
    budget_limit: int
    fallback_used: bool
    human_review_required: Literal[True] = True


class AttachedIncident(ApiModel):
    incident_id: str
    version: int
    status: str
    active_diagnosis_id: str | None


class AgentDiagnoseResponse(ApiModel):
    report: AgentReport
    execution: AgentExecution
    incident: AttachedIncident | None
