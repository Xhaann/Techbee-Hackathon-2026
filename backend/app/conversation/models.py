from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent.review import AgentReport
from app.engine.schema import EvidenceItem
from app.reasoning.report import ReasoningReport

ConversationId = Annotated[str, Field(pattern=r"^CNV-[0-9a-f]{16}$")]
InvestigationId = Annotated[str, Field(pattern=r"^INV-[0-9a-f]{12}$")]
Scope = Literal["everyone", "some", "single"]


class ConversationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Intent(str, Enum):
    GREETING = "greeting"
    GENERAL = "general"
    CAPABILITIES = "capabilities"
    KNOWLEDGE = "knowledge"
    INCIDENT_QUERY = "incident_query"
    SYMPTOM_REPORT = "symptom_report"
    CLARIFICATION = "clarification"
    TARGETED_DIAGNOSTIC = "targeted_diagnostic"
    FULL_DIAGNOSIS = "full_diagnosis"
    EVIDENCE_EXPLANATION = "evidence_explanation"
    STATUS = "status"
    HUMAN_ACTION = "human_action"
    CANCELLATION = "cancellation"
    CONFIRMATION = "confirmation"
    DECLINE = "decline"
    HYPOTHESIS_CHECK = "hypothesis_check"
    CUSTOMER_EMAIL = "customer_email"
    CUSTOMER_UPDATE = "customer_update"
    TROUBLESHOOTING = "troubleshooting"
    COMMANDS = "commands"
    OUTPUT_INTERPRETATION = "output_interpretation"
    STEP_FAILED = "step_failed"
    DETAIL = "detail"
    CONTINUE = "continue"
    SPECIALIST_REVIEW = "specialist_review"
    MULTI_AGENT = "multi_agent"
    PROTOCOL_CHECK = "protocol_check"


TOOL_INTENTS = frozenset({Intent.TARGETED_DIAGNOSTIC, Intent.FULL_DIAGNOSIS, Intent.MULTI_AGENT, Intent.PROTOCOL_CHECK})


class Entities(ConversationModel):
    site_ids: list[str] = Field(default_factory=list)
    device_ids: list[str] = Field(default_factory=list)
    interfaces: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    symptoms: list[str] = Field(default_factory=list)
    scope: Scope | None = None
    timeframe: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)
    unaffected_site_ids: list[str] = Field(default_factory=list)


class PlannedCall(ConversationModel):
    tool: str
    arguments: dict[str, Any]
    reason: str


class IntentResult(ConversationModel):
    intent: Intent
    confidence: Literal["high", "medium", "low"]
    source: Literal["rules", "quick_action", "pending_action", "pending_clarification"]
    entities: Entities = Field(default_factory=Entities)
    topics: list[str] = Field(default_factory=list)
    planned_calls: list[PlannedCall] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    human_action: str | None = None
    rerun: bool = False
    hypothesis: str | None = None
    audience: Literal["customer", "internal"] | None = None
    tone: Literal["friendly", "formal"] | None = None
    specialist: str | None = None
    step: int | None = None
    protocols: list[str] = Field(default_factory=list)
    scan_refused: bool = False
    broad: bool = False  # "check every log": proposed as a bounded plan, never run as asked


class PendingAction(ConversationModel):
    kind: Literal["full_diagnosis", "targeted_check", "plan", "multi_agent", "protocol"]
    calls: list[PlannedCall] = Field(default_factory=list)
    proposed_at: datetime


class PendingClarification(ConversationModel):
    for_intent: Intent
    question: str
    missing: list[str]
    topics: list[str] = Field(default_factory=list)
    device_id: str | None = None


class ConversationContext(ConversationModel):
    incident_id: str | None = None
    scenario_id: str | None = None
    site_ids: list[str] = Field(default_factory=list)
    device_ids: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    symptoms: list[str] = Field(default_factory=list)
    scope: Scope | None = None
    timeframe: str | None = None
    notes: list[str] = Field(default_factory=list)
    focus_device_id: str | None = None
    unaffected_site_ids: list[str] = Field(default_factory=list)
    asked: list[str] = Field(default_factory=list)
    last_topics: list[str] = Field(default_factory=list)
    pending_action: PendingAction | None = None
    pending_clarification: PendingClarification | None = None
    last_investigation_id: str | None = None
    guide: dict[str, Any] | None = None
    plan: list[PlannedCall] = Field(default_factory=list)
    last_intent: str | None = None
    draft_audience: Literal["customer", "internal"] = "customer"
    draft_tone: Literal["friendly", "formal"] = "friendly"


class ToolStep(ConversationModel):
    call_id: str | None
    tool: str
    arguments: dict[str, Any]
    status: Literal["running", "executed", "failed", "rejected", "duplicate", "cancelled"]
    error_code: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    summary: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class EvidenceReference(ConversationModel):
    evidence_id: str
    source: Literal["investigation", "incident_diagnosis"]
    investigation_id: str | None = None
    diagnosis_id: str | None = None
    tool: str
    call_id: str
    evidence_type: str
    code: str
    device_id: str | None
    summary: str
    timestamp: datetime | None = None
    plain: str | None = None  # the summary in plain words, for tooltips; the audit summary stays unchanged


class InvestigationSummary(ConversationModel):
    investigation_id: str
    kind: Literal["full_diagnosis", "targeted_check", "multi_agent", "protocol_check"]
    status: Literal["running", "completed", "partial", "failed", "cancelled"]
    started_at: datetime
    finished_at: datetime | None
    tool_calls: int
    budget_used: int
    budget_limit: int
    evidence_count: int
    fault_domain: str | None = None
    confidence: str | None = None
    root_cause: str | None = None
    attached_diagnosis_id: str | None = None


class Investigation(ConversationModel):
    investigation_id: str
    conversation_id: str
    turn_id: str
    kind: Literal["full_diagnosis", "targeted_check", "multi_agent", "protocol_check"]
    status: Literal["running", "completed", "partial", "failed", "cancelled"]
    scenario_id: str
    site_ids: list[str]
    device_ids: list[str]
    mode: Literal["agent", "rule_based", "direct"]
    model: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int | None = None
    steps: list[ToolStep] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    budget_used: int = 0
    budget_limit: int
    knowledge_documents: list[str] = Field(default_factory=list)
    report: AgentReport | None = None
    fallback_used: bool = False
    error: str | None = None
    attached_diagnosis_id: str | None = None
    attached_incident_version: int | None = None
    reasoning: ReasoningReport | None = None
    protocol: dict[str, Any] | None = None  # the Phase 3 protocol report for a protocol check

    def summary(self) -> InvestigationSummary:
        report = self.report
        return InvestigationSummary(
            investigation_id=self.investigation_id, kind=self.kind, status=self.status, started_at=self.started_at,
            finished_at=self.finished_at, tool_calls=len([s for s in self.steps if s.status in ("executed", "failed")]),
            budget_used=self.budget_used, budget_limit=self.budget_limit, evidence_count=len(self.evidence),
            fault_domain=report.fault_domain.value if report else (
                self.reasoning.leading.value if self.reasoning and self.reasoning.leading else None),
            confidence=report.confidence.level.value if report else (
                self.reasoning.self_evaluation.calibrated_confidence if self.reasoning else None),
            root_cause=report.root_cause_hypothesis.statement if report else (
                self.reasoning.explanation.summary if self.reasoning else None),
            attached_diagnosis_id=self.attached_diagnosis_id,
        )


ActionKind = Literal["full_diagnosis", "targeted_check", "explain_evidence", "status", "reply", "attach_investigation",
                     "open_human_action", "show_tab", "run_plan", "multi_agent", "copy", "protocol"]


class SuggestedAction(ConversationModel):
    action_id: str
    kind: ActionKind
    label: str
    params: dict[str, Any] = Field(default_factory=dict)
    executes_tools: bool = False
    requires_human: bool = False
    allowed: bool = True
    reason: str | None = None


class Clarification(ConversationModel):
    question: str
    missing: list[str]
    options: list[str] = Field(default_factory=list)


class HumanConfirmation(ConversationModel):
    action: str
    label: str
    reason: str
    permission: str
    allowed: bool
    performed_by_agent: Literal[False] = False


class PlanCall(ConversationModel):
    tool: Annotated[str, Field(max_length=64)]
    arguments: dict[str, Any]


class QuickAction(ConversationModel):
    kind: Literal["full_diagnosis", "targeted_check", "explain_evidence", "status", "run_plan", "multi_agent", "protocol"]
    tool: Annotated[str, Field(max_length=64)] | None = None
    arguments: dict[str, Any] | None = None
    calls: list[PlanCall] = Field(default_factory=list, max_length=4)
    evidence_ids: list[Annotated[str, Field(pattern=r"^E\d{1,4}$")]] = Field(default_factory=list, max_length=10)
    label: Annotated[str, Field(min_length=1, max_length=200)] | None = None

    @model_validator(mode="after")
    def check_targeted(self) -> "QuickAction":
        if self.kind == "targeted_check" and (not self.tool or self.arguments is None):
            raise ValueError("targeted_check actions require tool and arguments")
        if self.kind == "run_plan" and not self.calls:
            raise ValueError("run_plan actions require calls")
        if self.kind == "protocol" and (not self.calls or any(c.tool != "analyze_protocol" for c in self.calls)):
            raise ValueError("protocol actions require analyze_protocol calls")
        return self


class Attachment(ConversationModel):
    """A structured part of a reply that the workspace renders on its own: a draft, a guide, a command list, an output
    interpretation, the reasoning behind a diagnosis or a plan awaiting approval."""
    kind: Literal["email_draft", "customer_update", "troubleshooting_guide", "commands", "output_interpretation", "reasoning",
                  "plan", "specialists", "protocol"]
    title: str
    data: dict[str, Any]


class GeneratedBy(ConversationModel):
    """Who wrote the reply and who produced the result behind it, so a rule-based result is never passed off as the model's."""
    reply: Literal["model", "template"]
    result: Literal["ai_agent", "rule_based", "rule_based_fallback", "none"]
    model_configured: bool
    note: str | None = None


class Message(ConversationModel):
    message_id: str
    turn_id: str
    role: Literal["user", "assistant"]
    content: str
    created_at: datetime
    intent: Intent | None = None
    status: Literal["completed", "cancelled", "failed"] = "completed"
    composer: Literal["model", "template"] | None = None
    investigation_id: str | None = None
    evidence_refs: list[EvidenceReference] = Field(default_factory=list)
    suggested_actions: list[SuggestedAction] = Field(default_factory=list)
    clarification: Clarification | None = None
    human_confirmations: list[HumanConfirmation] = Field(default_factory=list)
    action: QuickAction | None = None
    details: str | None = None
    attachments: list[Attachment] = Field(default_factory=list)
    generated_by: GeneratedBy | None = None


class ExecutionSummary(ConversationModel):
    status: Literal["completed", "cancelled", "failed"]
    duration_ms: int
    tool_calls: int
    diagnostic_tool_calls: int
    knowledge_searches: int
    budget_used: int
    budget_limit: int
    tools: list[ToolStep] = Field(default_factory=list)
    mode: Literal["agent", "rule_based", "direct", "none"]
    model: str | None = None
    composer: Literal["model", "template"]
    fallback_used: bool = False
    human_review_required: Literal[True] = True
    composer_issues: list[str] = Field(default_factory=list)


class IntentView(ConversationModel):
    name: Intent
    confidence: Literal["high", "medium", "low"]
    source: str
    entities: Entities
    topics: list[str]


class TurnResult(ConversationModel):
    conversation_id: str
    turn_id: str
    intent: IntentView
    response: str
    user_message: Message
    assistant_message: Message
    clarification: Clarification | None
    investigation_id: str | None
    execution: ExecutionSummary
    evidence_references: list[EvidenceReference]
    suggested_actions: list[SuggestedAction]
    human_confirmations: list[HumanConfirmation]
    context: ConversationContext
    details: str | None = None
    attachments: list[Attachment] = Field(default_factory=list)
    generated_by: GeneratedBy | None = None


class ConversationEvent(ConversationModel):
    seq: int
    event: str
    conversation_id: str
    turn_id: str | None = None
    at: datetime
    data: dict[str, Any] = Field(default_factory=dict)


class ActiveTurn(ConversationModel):
    turn_id: str
    started_at: datetime
    investigation_id: str | None = None


class ConversationSummary(ConversationModel):
    conversation_id: str
    title: str
    incident_id: str | None
    scenario_id: str | None
    created_at: datetime
    updated_at: datetime
    message_count: int
    active_turn: ActiveTurn | None


class ConversationView(ConversationSummary):
    mode: Literal["auto", "rule_based"]
    messages: list[Message]
    context: ConversationContext
    investigations: list[InvestigationSummary]
    last_event_seq: int
    model_available: bool
