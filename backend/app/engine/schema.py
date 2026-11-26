from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.diagnostics import EvidenceRef
from app.engine.safety import is_read_only_command
from app.network.models import Identifier, IncidentPriority, UtcDatetime

ShortText = Annotated[str, Field(min_length=1, max_length=600)]
LongText = Annotated[str, Field(min_length=1, max_length=2000)]
EvidenceIds = Annotated[list[str], Field(max_length=30)]


class EngineModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FaultDomain(str, Enum):
    WAN_ISP = "wan_isp"
    ROUTING = "routing"
    SWITCHING = "switching"
    FIREWALL = "firewall"
    VLAN_AUTHENTICATION = "vlan_authentication"
    DHCP = "dhcp"
    DNS = "dns"
    NETWORK_DEVICE_FAILURE = "network_device_failure"
    INTERFACE_LINK = "interface_link"
    SHARED_INFRASTRUCTURE = "shared_infrastructure"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class DiagnosisStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    NO_FAULT_IDENTIFIED = "no_fault_identified"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    FAILED = "failed"


class DiagnosisMethod(str, Enum):
    MODEL = "model"
    RULE_BASED = "rule_based"
    RULE_BASED_FALLBACK = "rule_based_fallback"


class EvidenceType(str, Enum):
    OBSERVED_FINDING = "observed_finding"
    INFERRED_FINDING = "inferred_finding"
    OBSERVED_RESULT = "observed_result"
    RECORD = "record"


class TimelineRelevance(str, Enum):
    FAULT_ONSET = "fault_onset"
    PRECEDES_FAULT = "precedes_fault"
    CORRELATED = "correlated"
    CONCURRENT = "concurrent"
    BACKGROUND = "background"


class DiagnosisRequest(EngineModel):
    scenario_id: Identifier
    description: str = Field(min_length=1, max_length=4000)
    incident_id: Identifier | None = None
    site_ids: list[Identifier] = Field(default_factory=list, max_length=5)
    severity: IncidentPriority | None = None
    reported_at: UtcDatetime | None = None


class EvidenceItem(EngineModel):
    evidence_id: str
    call_id: str
    tool: str
    evidence_type: EvidenceType
    code: str
    device_id: str | None = None
    summary: str
    timestamp: UtcDatetime | None = None
    references: list[EvidenceRef] = []


class NextCheck(EngineModel):
    device_id: str = Field(min_length=1, max_length=64)
    command: str = Field(min_length=1, max_length=200)
    purpose: ShortText
    expected_observation: ShortText
    reason: ShortText
    illustrative: Literal[True] = True

    @field_validator("command")
    @classmethod
    def check_read_only(cls, value: str) -> str:
        if not is_read_only_command(value):
            raise ValueError("recommended commands must be approved read-only commands")
        return value


class DraftCheck(EngineModel):
    device_id: str = Field(min_length=1, max_length=64)
    command: str = Field(min_length=1, max_length=200)
    purpose: ShortText
    expected_observation: ShortText
    reason: ShortText


class AlternativeDraft(EngineModel):
    fault_domain: FaultDomain
    hypothesis: ShortText
    supporting_evidence_ids: EvidenceIds = []
    contradictory_evidence_ids: EvidenceIds = []
    verification: ShortText


class EscalationDraft(EngineModel):
    team: str = Field(min_length=1, max_length=120)
    priority: IncidentPriority
    reason: ShortText
    unknowns: list[str] = Field(default_factory=list, max_length=10)


class Explanation(EngineModel):
    summary: LongText
    observed_facts: list[str] = Field(default_factory=list, max_length=12)
    hypotheses: list[str] = Field(default_factory=list, max_length=8)
    recommended_actions: list[str] = Field(default_factory=list, max_length=12)


class DiagnosisDraft(EngineModel):
    fault_domain: FaultDomain
    root_cause: ShortText
    root_cause_device_ids: list[str] = Field(default_factory=list, max_length=10)
    root_cause_link_ids: list[str] = Field(default_factory=list, max_length=10)
    reasoning: LongText
    supporting_evidence_ids: EvidenceIds = []
    contradictory_evidence_ids: EvidenceIds = []
    confidence: Confidence
    confidence_explanation: ShortText
    alternatives: list[AlternativeDraft] = Field(default_factory=list, max_length=5)
    next_checks: list[DraftCheck] = Field(default_factory=list, max_length=8)
    escalation: EscalationDraft
    explanation: Explanation


class IncidentSummary(EngineModel):
    incident_id: str | None
    scenario_id: str
    description: str
    site_ids: list[str]
    severity: IncidentPriority | None
    reported_at: UtcDatetime | None
    status: DiagnosisStatus


class AffectedPath(EngineModel):
    source: str
    destination: str
    reachability: str
    path: list[str]
    affected_devices: list[str]
    affected_links: list[str]
    shared_dependencies: list[str]


class TimelineEntry(EngineModel):
    timestamp: UtcDatetime
    device_id: str | None
    event: str
    event_type: str
    evidence_id: str
    relevance: TimelineRelevance


class FaultAssessment(EngineModel):
    fault_domain: FaultDomain
    root_cause: str
    device_ids: list[str]
    link_ids: list[str]
    reasoning: str
    supporting_evidence_ids: list[str]
    contradictory_evidence_ids: list[str]
    verified_against_rules: bool


class ConfidenceAssessment(EngineModel):
    level: Confidence
    explanation: str


class Alternative(EngineModel):
    fault_domain: FaultDomain
    hypothesis: str
    supporting_evidence_ids: list[str]
    contradictory_evidence_ids: list[str]
    verification: str


class Escalation(EngineModel):
    team: str
    priority: IncidentPriority
    reason: str
    evidence_ids: list[str]
    unknowns: list[str]


class ToolCallSummary(EngineModel):
    call_id: str
    tool: str
    arguments: dict
    status: str
    error_code: str | None


class ProviderInfo(EngineModel):
    name: str
    model: str


class Diagnosis(EngineModel):
    incident: IncidentSummary
    method: DiagnosisMethod
    provider: ProviderInfo | None
    affected_path: AffectedPath | None
    timeline: list[TimelineEntry]
    fault: FaultAssessment
    confidence: ConfidenceAssessment
    alternatives: list[Alternative]
    evidence: list[EvidenceItem]
    next_checks: list[NextCheck]
    escalation: Escalation
    explanation: Explanation
    tool_calls: list[ToolCallSummary]
    retrieved_document_ids: list[str]
    limitations: list[str]
    validation_issues: list[str]
    security_flags: list[str]
    human_verification_required: Literal[True] = True
