import re
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.engine.registry import REGISTRY
from app.engine.safety import is_read_only_command
from app.security.secrets import contains_secret
from app.engine.schema import FaultDomain
from app.network.models import DeviceType, EventType, Identifier, IncidentPriority, PathService, UtcDatetime, ensure_unique

RecordId = Annotated[str, Field(pattern=r"^(PB|RB|KD|DP)-[A-Z0-9]+(?:-[A-Z0-9]+)*$")]
SourceId = Annotated[str, Field(pattern=r"^SRC-[A-Z0-9]+(?:-[A-Z0-9]+)*$")]
Version = Annotated[str, Field(pattern=r"^\d+\.\d+\.\d+$")]
Line = Annotated[str, Field(min_length=3, max_length=400)]
PLACEHOLDER = re.compile(r"\{[a-z_]+\}")
PLATFORM_PREFIXES = {
    "cisco_ios_xe": ("show ", "ping ", "traceroute "),
    "pan_os": ("show ",),
    "linux": ("journalctl ", "dig ", "rndc status", "rndc zonestatus ", "keactrl status", "ping ", "traceroute "),
}


class KnowledgeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class KnowledgeCategory(str, Enum):
    CONNECTIVITY = "connectivity"
    PERFORMANCE = "performance"
    ROUTING = "routing"
    SECURITY = "security"
    NETWORK_SERVICES = "network_services"
    ACCESS_CONTROL = "access_control"
    INFRASTRUCTURE = "infrastructure"
    GENERAL = "general"


class NetworkLayer(str, Enum):
    PHYSICAL = "physical"
    DATA_LINK = "data_link"
    NETWORK = "network"
    TRANSPORT = "transport"
    APPLICATION = "application"


class RecordType(str, Enum):
    PLAYBOOK = "playbook"
    RUNBOOK = "runbook"
    DOCUMENT = "document"
    PROCEDURE = "procedure"


class DocumentType(str, Enum):
    GUIDE = "guide"
    REFERENCE = "reference"
    CHECKLIST = "checklist"


class Platform(str, Enum):
    CISCO_IOS_XE = "cisco_ios_xe"
    PAN_OS = "pan_os"
    LINUX = "linux"


def reject_secrets(value: str) -> str:
    if contains_secret(value):
        raise ValueError("knowledge content must not contain credentials or secrets")
    return value


class SourceReference(KnowledgeModel):
    source_id: SourceId
    title: Line
    kind: Literal["synthetic_internal"]
    revision: Version


class Applicability(KnowledgeModel):
    site_ids: list[Identifier] = Field(default_factory=list, max_length=10)
    device_types: list[DeviceType] = Field(default_factory=list, max_length=4)
    services: list[PathService] = Field(default_factory=list, max_length=5)


class CommandSpec(KnowledgeModel):
    text: Annotated[str, Field(min_length=3, max_length=200)]
    platform: Platform
    device_types: list[DeviceType] = Field(min_length=1, max_length=4)
    purpose: Line
    illustrative: Literal[True] = True

    @model_validator(mode="after")
    def check_read_only(self) -> "CommandSpec":
        concrete = PLACEHOLDER.sub("x", self.text)
        if not is_read_only_command(self.text):
            raise ValueError(f"command '{self.text}' is not an approved read-only command")
        if not concrete.startswith(PLATFORM_PREFIXES[self.platform.value]):
            raise ValueError(f"command '{self.text}' does not match the {self.platform.value} read-only format")
        return self

    @property
    def parameters(self) -> list[str]:
        return [match.strip("{}") for match in PLACEHOLDER.findall(self.text)]


class ToolReference(KnowledgeModel):
    tool: str
    purpose: Line

    @field_validator("tool")
    @classmethod
    def check_registered(cls, value: str) -> str:
        if value not in REGISTRY:
            raise ValueError(f"tool '{value}' is not a registered diagnostic tool")
        return value


class EvidenceRequirement(KnowledgeModel):
    requirement_id: Annotated[str, Field(pattern=r"^EV-[A-Z0-9-]+$")]
    description: Line
    codes: list[EventType] = Field(min_length=1, max_length=10)
    tool: ToolReference


class DiagnosticStep(KnowledgeModel):
    order: int = Field(ge=1, le=50)
    action: Line
    tool: ToolReference | None = None
    commands: list[CommandSpec] = Field(default_factory=list, max_length=5)
    expected_observation: Line


class DecisionCondition(KnowledgeModel):
    condition: Line
    conclusion: Line
    next_record_id: RecordId | None = None


class EscalationCriterion(KnowledgeModel):
    condition: Line
    team: Annotated[str, Field(min_length=1, max_length=120)]
    priority: IncidentPriority


class KnowledgeRecord(KnowledgeModel):
    record_id: RecordId
    title: Annotated[str, Field(min_length=5, max_length=200)]
    version: Version
    fault_domains: list[FaultDomain] = Field(default_factory=list, max_length=5)
    applicability: Applicability = Applicability()
    tags: list[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")]] = Field(default_factory=list, max_length=15)
    source_ids: list[SourceId] = Field(min_length=1, max_length=5)
    created_at: UtcDatetime
    updated_at: UtcDatetime
    active: bool = True

    @model_validator(mode="after")
    def check_record(self) -> "KnowledgeRecord":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        reject_secrets(self.model_dump_json())
        return self

    def texts(self) -> list[str]:
        return [self.title, *self.tags]


class Playbook(KnowledgeRecord):
    record_type: Literal[RecordType.PLAYBOOK] = RecordType.PLAYBOOK
    description: Annotated[str, Field(min_length=10, max_length=1500)]
    category: KnowledgeCategory
    layers: list[NetworkLayer] = Field(min_length=1, max_length=5)
    symptoms: list[Line] = Field(min_length=1, max_length=12)
    indicator_codes: list[EventType] = Field(default_factory=list, max_length=15)
    possible_causes: list[Line] = Field(min_length=1, max_length=10)
    required_evidence: list[EvidenceRequirement] = Field(min_length=1, max_length=10)
    steps: list[DiagnosticStep] = Field(min_length=1, max_length=15)
    decisions: list[DecisionCondition] = Field(min_length=1, max_length=10)
    escalation: list[EscalationCriterion] = Field(min_length=1, max_length=5)
    related_ids: list[RecordId] = Field(default_factory=list, max_length=10)

    def texts(self) -> list[str]:
        return [self.title, self.description, *self.symptoms, *self.tags]


class Runbook(KnowledgeRecord):
    record_type: Literal[RecordType.RUNBOOK] = RecordType.RUNBOOK
    context: Annotated[str, Field(min_length=10, max_length=1500)]
    preconditions: list[Line] = Field(min_length=1, max_length=10)
    procedures: list[DiagnosticStep] = Field(min_length=1, max_length=15)
    verification: list[Line] = Field(min_length=1, max_length=10)
    escalation: list[EscalationCriterion] = Field(min_length=1, max_length=5)
    related_ids: list[RecordId] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def check_scope(self) -> "Runbook":
        if not self.applicability.site_ids:
            raise ValueError("a runbook must apply to at least one site")
        return self

    def texts(self) -> list[str]:
        return [self.title, self.context, *self.tags]


class KnowledgeDocument(KnowledgeRecord):
    record_type: Literal[RecordType.DOCUMENT] = RecordType.DOCUMENT
    document_type: DocumentType
    category: KnowledgeCategory
    content: Annotated[str, Field(min_length=20, max_length=4000)]
    metadata: dict[Annotated[str, Field(pattern=r"^[a-z_]{1,30}$")], Annotated[str, Field(max_length=200)]] = Field(
        default_factory=dict, max_length=10)

    def texts(self) -> list[str]:
        return [self.title, self.content, *self.tags]


class DiagnosticProcedure(KnowledgeRecord):
    record_type: Literal[RecordType.PROCEDURE] = RecordType.PROCEDURE
    symptoms: list[Line] = Field(min_length=1, max_length=12)
    tools: list[ToolReference] = Field(min_length=1, max_length=6)
    commands: list[CommandSpec] = Field(default_factory=list, max_length=8)
    expected_outputs: list[Line] = Field(min_length=1, max_length=10)
    required_evidence: list[EvidenceRequirement] = Field(min_length=1, max_length=8)
    decisions: list[DecisionCondition] = Field(min_length=1, max_length=8)
    next_ids: list[RecordId] = Field(default_factory=list, max_length=5)
    escalation_conditions: list[Line] = Field(min_length=1, max_length=5)

    def texts(self) -> list[str]:
        return [self.title, *self.symptoms, *self.tags]


AnyRecord = Playbook | Runbook | KnowledgeDocument | DiagnosticProcedure
ID_PREFIX = {RecordType.PLAYBOOK: "PB-", RecordType.RUNBOOK: "RB-", RecordType.DOCUMENT: "KD-", RecordType.PROCEDURE: "DP-"}


class KnowledgeBase(KnowledgeModel):
    schema_version: Version
    sources: list[SourceReference] = Field(min_length=1)
    playbooks: list[Playbook]
    runbooks: list[Runbook]
    documents: list[KnowledgeDocument]
    procedures: list[DiagnosticProcedure]

    @property
    def records(self) -> list[AnyRecord]:
        return [*self.playbooks, *self.runbooks, *self.documents, *self.procedures]

    @model_validator(mode="after")
    def check_references(self) -> "KnowledgeBase":
        ensure_unique([source.source_id for source in self.sources], "source ids")
        ensure_unique([record.record_id for record in self.records], "knowledge record ids")
        sources = {source.source_id for source in self.sources}
        records = {record.record_id for record in self.records}
        for record in self.records:
            if not record.record_id.startswith(ID_PREFIX[record.record_type]):
                raise ValueError(f"{record.record_id} does not use the {record.record_type.value} identifier prefix")
            missing = sorted(set(record.source_ids) - sources)
            if missing:
                raise ValueError(f"{record.record_id} cites unknown sources: {', '.join(missing)}")
            links = list(getattr(record, "related_ids", [])) + list(getattr(record, "next_ids", []))
            links += [d.next_record_id for d in getattr(record, "decisions", []) if d.next_record_id]
            unknown = sorted(set(links) - records)
            if unknown:
                raise ValueError(f"{record.record_id} references unknown records: {', '.join(unknown)}")
            if record.record_id in links:
                raise ValueError(f"{record.record_id} cannot reference itself")
            steps = list(getattr(record, "steps", [])) + list(getattr(record, "procedures", []))
            if [step.order for step in steps] != list(range(1, len(steps) + 1)):
                raise ValueError(f"{record.record_id} steps must be ordered from 1")
        return self
