import json
import re
import time
from typing import Any

from pydantic import ValidationError

from app.engine.correlation import Candidate, Correlation, correlate
from app.engine.evidence import build_catalog, model_view
from app.engine.executor import MAX_TOOL_CALLS, ToolCallRecord, ToolExecutor
from app.engine.guidance import Guidance
from app.engine.instructions import SYSTEM_INSTRUCTIONS
from app.engine.planner import DiagnosisRequestError, IncidentContext, RuleBasedPlanner, resolve_context
from app.engine.providers import ModelProvider, ProviderError
from app.engine.registry import tool_schemas
from app.engine.retrieval import NoRetrieval, RetrievedDocument, Retriever
from app.engine.safety import injection_flags
from app.engine.schema import (
    Alternative,
    Confidence,
    ConfidenceAssessment,
    Diagnosis,
    DiagnosisDraft,
    DiagnosisMethod,
    DiagnosisRequest,
    DiagnosisStatus,
    EvidenceItem,
    EvidenceType,
    FaultAssessment,
    FaultDomain,
    IncidentSummary,
    ProviderInfo,
    ToolCallSummary,
)
from app.engine.validation import ValidatedDraft, check_diagnosis, validate_draft
from app.network.models import NetworkTopology
from app.network.repository import load_topology, scenario_exists

MAX_MODEL_TURNS = 12
MAX_DOCUMENTS = 3
DEFAULT_MODEL_RUN_SECONDS = 120.0
CODE_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$")


def parse_draft(content: str | None) -> DiagnosisDraft | None:
    if not content:
        return None
    try:
        return DiagnosisDraft.model_validate(json.loads(CODE_FENCE.sub("", content.strip())))
    except (ValueError, ValidationError):
        return None


class ModelSession:
    def __init__(self, provider: ModelProvider, executor: ToolExecutor, request: DiagnosisRequest,
                 context: IncidentContext, documents: list[RetrievedDocument],
                 deadline_seconds: float = DEFAULT_MODEL_RUN_SECONDS) -> None:
        self.provider = provider
        self.deadline_seconds = deadline_seconds
        self.executor = executor
        self.request = request
        self.context = context
        self.documents = documents
        self.limitations: list[str] = []
        self.issues: list[str] = []

    def opening(self) -> str:
        return json.dumps({
            "task": "Diagnose the incident using the diagnostic tools, then reply with the final JSON diagnosis.",
            "untrusted_incident": {
                "incident_id": self.request.incident_id,
                "description": self.request.description,
                "severity": self.request.severity.value if self.request.severity else None,
                "reported_at": self.request.reported_at.isoformat() if self.request.reported_at else None,
            },
            "triage_hints": {"sites": self.context.sites, "suggested_destination": self.context.target_device_id},
            "untrusted_reference_documents": [
                {"reference_id": f"K{index}", "title": doc.title, "source": doc.source, "content": doc.content}
                for index, doc in enumerate(self.documents, start=1)
            ],
            "tool_budget": self.executor.max_calls,
            "evidence_rule": "Cite only evidence_id values returned in tool results.",
            "output_schema": DiagnosisDraft.model_json_schema(),
        })

    def run(self) -> DiagnosisDraft | None:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_INSTRUCTIONS},
            {"role": "user", "content": self.opening()},
        ]
        tools = tool_schemas()
        started = time.monotonic()
        for _ in range(MAX_MODEL_TURNS):
            if time.monotonic() - started >= self.deadline_seconds:
                self.limitations.append(f"Model provider error (timeout: the model run exceeded {self.deadline_seconds:.0f} seconds)")
                return None
            exhausted = self.executor.remaining <= 0
            try:
                reply = self.provider.complete(messages, None if exhausted else tools)
            except ProviderError as exc:
                self.limitations.append(f"Model provider error ({exc.kind.value}): {exc.message}")
                return None
            if reply.tool_calls:
                messages.append({"role": "assistant", "content": reply.content, "tool_calls": [
                    {"id": call.id, "type": "function", "function": {"name": call.name, "arguments": call.arguments}}
                    for call in reply.tool_calls
                ]})
                for call in reply.tool_calls:
                    record = self.executor.execute(call.name, call.arguments)
                    if record.error_code in ("UNKNOWN_TOOL", "INVALID_ARGUMENTS", "REQUEST_LIMIT"):
                        self.issues.append(f"Model tool request rejected ({record.error_code}): {record.error}")
                    messages.append({"role": "tool", "tool_call_id": call.id,
                                     "content": model_view(record, build_catalog(self.executor.records))})
                if self.executor.remaining <= 0:
                    messages.append({"role": "user", "content": "The tool budget is exhausted. Reply now with the final JSON diagnosis."})
                continue
            draft = parse_draft(reply.content)
            if draft is None:
                self.issues.append("Model output was not a valid diagnosis JSON object and was rejected")
            return draft
        self.limitations.append(f"Model did not return a final diagnosis within {MAX_MODEL_TURNS} turns")
        return None


class DiagnosisEngine:
    def __init__(self, provider: ModelProvider | None = None, retriever: Retriever | None = None,
                 max_tool_calls: int = MAX_TOOL_CALLS, run_seconds: float = DEFAULT_MODEL_RUN_SECONDS) -> None:
        self.provider = provider
        self.retriever = retriever or NoRetrieval()
        self.max_tool_calls = max_tool_calls
        self.run_seconds = run_seconds

    def diagnose(self, request: DiagnosisRequest) -> Diagnosis:
        return self.diagnose_with_records(request)[0]

    def diagnose_with_records(self, request: DiagnosisRequest) -> tuple[Diagnosis, list[ToolCallRecord]]:
        if not scenario_exists(request.scenario_id):
            raise DiagnosisRequestError(f"Unknown scenario '{request.scenario_id}'")
        topology = load_topology()
        context = resolve_context(request, topology)
        executor = ToolExecutor(request.scenario_id, max_calls=self.max_tool_calls)
        flags = injection_flags("incident description", request.description)
        documents = self.retriever.search(request.description, MAX_DOCUMENTS)[:MAX_DOCUMENTS]
        for document in documents:
            flags += injection_flags(f"reference document {document.document_id}", f"{document.title}\n{document.content}")
        limitations: list[str] = []
        issues: list[str] = []
        validated: ValidatedDraft | None = None
        draft_rejected = False

        if not context.sites:
            limitations.append("No affected site could be identified from the request; supply site_ids")
        def sufficient() -> bool:
            catalog = build_catalog(executor.records)
            return correlate(executor.records, catalog, topology, context.sites, context.onset).confidence == Confidence.HIGH

        if self.provider is None:
            if context.sites:
                RuleBasedPlanner(topology, context).run(executor, sufficient)
        else:
            session = ModelSession(self.provider, executor, request, context, documents, self.run_seconds)
            draft = session.run()
            limitations += session.limitations
            issues += session.issues
            validated, draft_rejected = self.validate(draft, executor, topology, context, issues)
            if validated is None and context.sites and executor.remaining > 0:
                # The model failed, timed out or was rejected: finish the investigation with the rule-based planner,
                # within what is left of the same budget, instead of concluding from a partial tool sequence.
                RuleBasedPlanner(topology, context).run(executor, sufficient)
        diagnosis = self.conclude(request, context, topology, executor, documents, flags, validated, draft_rejected,
                                  limitations, issues)
        return diagnosis, list(executor.records)

    def validate(self, draft: DiagnosisDraft | None, executor: ToolExecutor, topology: NetworkTopology,
                 context: IncidentContext, issues: list[str]) -> tuple[ValidatedDraft | None, bool]:
        validated = None
        if draft is not None:
            catalog = build_catalog(executor.records)
            correlation = correlate(executor.records, catalog, topology, context.sites, context.onset)
            validated, draft_issues = validate_draft(draft, catalog, topology, correlation, self.known_secrets())
            issues += draft_issues
        return validated, validated is None

    def conclude(self, request: DiagnosisRequest, context: IncidentContext, topology: NetworkTopology,
                 executor: ToolExecutor, documents: list[RetrievedDocument], flags: list[str],
                 validated: ValidatedDraft | None, draft_rejected: bool, limitations: list[str],
                 issues: list[str]) -> Diagnosis:
        catalog = build_catalog(executor.records)
        for item in catalog:
            if item.evidence_type == EvidenceType.RECORD:
                flags += injection_flags(f"log record {item.references[0].record_id}", item.summary)
        correlation = correlate(executor.records, catalog, topology, context.sites, context.onset)
        limitations += correlation.limitations
        limitations += [f"Tool {r.tool} ({r.call_id}) failed: {r.error_code}" for r in executor.records if r.status == "failed"]
        if any(record.error_code == "BUDGET_EXHAUSTED" for record in executor.records):
            limitations.append(f"Tool call budget of {executor.max_calls} was exhausted before every planned check ran")
        diagnosis = self.assemble(request, context, topology, executor, catalog, correlation, validated,
                                  draft_rejected, limitations, issues, sorted(set(flags)), documents)
        final_issues = check_diagnosis(diagnosis, catalog, topology, self.known_secrets())
        if final_issues:
            diagnosis = diagnosis.model_copy(update={"validation_issues": diagnosis.validation_issues + final_issues,
                                                     "incident": diagnosis.incident.model_copy(update={"status": DiagnosisStatus.PARTIAL})})
        return diagnosis

    def known_secrets(self) -> tuple[str, ...]:
        key = getattr(getattr(self.provider, "config", None), "api_key", None)
        return (key.get_secret_value(),) if key is not None else ()

    def status(self, correlation: Correlation, executor: ToolExecutor, limitations: list[str], fallback: bool,
               domain: FaultDomain) -> DiagnosisStatus:
        succeeded = [record for record in executor.records if record.succeeded]
        if not succeeded:
            return DiagnosisStatus.FAILED if self.provider is not None and limitations else DiagnosisStatus.INSUFFICIENT_EVIDENCE
        if domain == FaultDomain.UNKNOWN:
            return DiagnosisStatus.PARTIAL if fallback or limitations else DiagnosisStatus.NO_FAULT_IDENTIFIED
        if fallback or limitations or correlation.confidence in (Confidence.LOW, Confidence.INSUFFICIENT_EVIDENCE):
            return DiagnosisStatus.PARTIAL
        return DiagnosisStatus.COMPLETED

    def assemble(self, request: DiagnosisRequest, context: IncidentContext, topology: NetworkTopology,
                 executor: ToolExecutor, catalog: list[EvidenceItem], correlation: Correlation,
                 validated: ValidatedDraft | None, draft_rejected: bool, limitations: list[str], issues: list[str],
                 flags: list[str], documents: list[RetrievedDocument]) -> Diagnosis:
        guidance = Guidance(topology)
        top = correlation.top
        missing = sorted({item for r in executor.records if r.succeeded for item in r.result.missing_data})
        unknowns = list(dict.fromkeys(limitations + missing))[:6]
        if validated is not None:
            draft = validated.draft
            method = DiagnosisMethod.MODEL
            fault = FaultAssessment(
                fault_domain=draft.fault_domain, root_cause=draft.root_cause, device_ids=draft.root_cause_device_ids,
                link_ids=draft.root_cause_link_ids, reasoning=draft.reasoning,
                supporting_evidence_ids=draft.supporting_evidence_ids, contradictory_evidence_ids=draft.contradictory_evidence_ids,
                verified_against_rules=validated.verified,
            )
            confidence = ConfidenceAssessment(level=draft.confidence, explanation=draft.confidence_explanation)
            alternatives = [Alternative(**alternative.model_dump()) for alternative in draft.alternatives]
            checks = validated.next_checks
            escalation = guidance.escalation(correlation, request.severity, unknowns).model_copy(update={
                "team": draft.escalation.team, "priority": request.severity or draft.escalation.priority,
                "reason": draft.escalation.reason, "evidence_ids": draft.supporting_evidence_ids[:10],
                "unknowns": (draft.escalation.unknowns + unknowns)[:10],
            })
            explanation = draft.explanation
        else:
            method = DiagnosisMethod.RULE_BASED_FALLBACK if self.provider is not None else DiagnosisMethod.RULE_BASED
            if draft_rejected and self.provider is not None:
                limitations.append("Model diagnosis was unavailable or rejected; rule-based correlation was used")
            fault = self.rule_fault(top)
            confidence = ConfidenceAssessment(level=correlation.confidence, explanation=correlation.confidence_explanation)
            alternatives = [self.rule_alternative(candidate) for candidate in correlation.alternatives[:5]]
            checks = guidance.next_checks(correlation, context.sites)
            escalation = guidance.escalation(correlation, request.severity, unknowns)
            explanation = guidance.explanation(correlation, checks, escalation)
        cited = set(fault.supporting_evidence_ids) | set(fault.contradictory_evidence_ids) | set(escalation.evidence_ids)
        cited |= {entry.evidence_id for entry in correlation.timeline}
        for alternative in alternatives:
            cited |= set(alternative.supporting_evidence_ids) | set(alternative.contradictory_evidence_ids)
        status = self.status(correlation, executor, limitations, method == DiagnosisMethod.RULE_BASED_FALLBACK, fault.fault_domain)
        return Diagnosis(
            incident=IncidentSummary(
                incident_id=request.incident_id, scenario_id=request.scenario_id, description=request.description,
                site_ids=context.sites, severity=request.severity, reported_at=request.reported_at, status=status,
            ),
            method=method,
            provider=ProviderInfo(name=self.provider.name, model=self.provider.model) if self.provider else None,
            affected_path=correlation.affected_path,
            timeline=correlation.timeline,
            fault=fault,
            confidence=confidence,
            alternatives=alternatives,
            evidence=[item for item in catalog if item.evidence_id in cited],
            next_checks=checks,
            escalation=escalation,
            explanation=explanation,
            tool_calls=[ToolCallSummary(call_id=r.call_id, tool=r.tool, arguments=r.arguments, status=r.status,
                                        error_code=r.error_code) for r in executor.records],
            retrieved_document_ids=[document.document_id for document in documents],
            limitations=list(dict.fromkeys(limitations)),
            validation_issues=list(dict.fromkeys(issues)),
            security_flags=flags,
        )

    @staticmethod
    def rule_fault(top: Candidate | None) -> FaultAssessment:
        if top is None:
            return FaultAssessment(
                fault_domain=FaultDomain.UNKNOWN, root_cause="No root cause is supported by the collected evidence",
                device_ids=[], link_ids=[], reasoning="The diagnostic tools returned no uncontradicted fault evidence",
                supporting_evidence_ids=[], contradictory_evidence_ids=[], verified_against_rules=True,
            )
        return FaultAssessment(
            fault_domain=top.domain, root_cause=top.root_cause, device_ids=top.device_ids, link_ids=top.link_ids,
            reasoning=top.reasoning, supporting_evidence_ids=[item.evidence_id for item in top.support],
            contradictory_evidence_ids=[item.evidence_id for item in top.contradicting], verified_against_rules=True,
        )

    @staticmethod
    def rule_alternative(candidate: Candidate) -> Alternative:
        if candidate.contradicting:
            verification = "Contradicted by collected evidence; re-check only if the primary hypothesis is disproved"
        else:
            scope = ", ".join(candidate.device_ids) or "the affected site"
            verification = f"Collect additional evidence on {scope} to confirm or exclude this hypothesis"
        return Alternative(
            fault_domain=candidate.domain, hypothesis=candidate.root_cause,
            supporting_evidence_ids=[item.evidence_id for item in candidate.support],
            contradictory_evidence_ids=[item.evidence_id for item in candidate.contradicting], verification=verification,
        )


def diagnose(request: DiagnosisRequest, provider: ModelProvider | None = None,
             retriever: Retriever | None = None) -> Diagnosis:
    return DiagnosisEngine(provider, retriever).diagnose(request)
