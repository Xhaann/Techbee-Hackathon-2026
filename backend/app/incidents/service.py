from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.engine import DiagnosisEngine, DiagnosisRequest
from app.engine.safety import injection_flags
from app.engine.schema import Diagnosis, FaultDomain
from app.incidents.assets import TopologyIndex, asset, diagnosis_assets, merge_assets
from app.incidents.errors import (
    IncidentValidationError,
    InvalidTransitionError,
    UnauthorizedActionError,
)
from app.incidents.models import (
    ACTIVE_STATUSES,
    OPEN_ESCALATION_STATUSES,
    PRIORITY_FOR_SEVERITY,
    SEVERITY_FOR_PRIORITY,
    SEVERITY_RANK,
    TRANSITIONS,
    Actor,
    ActorKind,
    AssetType,
    Closure,
    DiagnosisRecord,
    EscalationRecord,
    EscalationStatus,
    EventType,
    EvidenceLink,
    ImpactBasis,
    Incident,
    IncidentCreateRequest,
    IncidentFilter,
    IncidentSeverity,
    IncidentSummary,
    KnowledgeReference,
    LifecycleStatus,
    OutstandingCheck,
    Resolution,
    TimelineEvent,
    ValueSource,
    VerificationStatus,
)
from app.incidents.repository import IncidentRepository
from app.incidents.similarity import DEFAULT_WINDOW, SimilarIncident, compare, duplicate_reason
from app.network.models import IncidentPriority
from app.network.repository import load_topology, scenario_exists
from app.security.provenance import provenance_issues
from app.security.secrets import contains_secret, redact

HUMAN = (ActorKind.HUMAN,)
OPERATORS = (ActorKind.HUMAN, ActorKind.SYSTEM)
ANYONE = (ActorKind.HUMAN, ActorKind.SYSTEM, ActorKind.AI)
STATUS_EVENTS = {
    LifecycleStatus.ACKNOWLEDGED: EventType.ACKNOWLEDGED,
    LifecycleStatus.INVESTIGATING: EventType.INVESTIGATION_STARTED,
    LifecycleStatus.MONITORING: EventType.MONITORING_STARTED,
}
DEDICATED_TARGETS = {
    LifecycleStatus.ESCALATED: "create_escalation",
    LifecycleStatus.RESOLVED: "verify_resolution",
    LifecycleStatus.CLOSED: "close_incident",
}
ESCALATION_TRANSITIONS = {
    EscalationStatus.RECOMMENDED: {EscalationStatus.ASSIGNED, EscalationStatus.CLOSED, EscalationStatus.CANCELLED},
    EscalationStatus.ASSIGNED: {EscalationStatus.CLOSED, EscalationStatus.CANCELLED},
    EscalationStatus.CLOSED: set(),
    EscalationStatus.CANCELLED: set(),
}
MAX_LINKED_EVIDENCE = 50
SIMILARITY_SCAN_LIMIT = 500
Visibility = Callable[[IncidentSummary], bool] | None


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class ResultModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class CreationOutcome(ResultModel):
    incident: Incident
    created: bool
    duplicate_of: SimilarIncident | None = None
    duplicate_reason: str | None = None
    possible_duplicates: list[SimilarIncident] = []


class AssetUpdate(ResultModel):
    asset_type: AssetType
    asset_id: str = Field(min_length=1, max_length=96)
    basis: ImpactBasis


class DiagnosisComparison(ResultModel):
    diagnosis_id: str
    created_at: datetime
    method: str
    probable_fault_domain: FaultDomain
    confidence: str
    superseded_by: str | None
    changes_from_previous: list[str]


class RecurringGroup(ResultModel):
    site_id: str
    fault_domain: FaultDomain
    incident_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    common_devices: list[str]


class ResolutionHistoryEntry(ResultModel):
    incident_id: str
    resolution: Resolution


def require_actor(actor: Actor, allowed: tuple[ActorKind, ...], action: str) -> None:
    if not isinstance(actor, Actor):
        raise UnauthorizedActionError("A validated actor is required")
    if actor.kind not in allowed:
        raise UnauthorizedActionError(f"{actor.kind.value} actors may not {action}")


def coerce(kind: type[Enum], value: Any, label: str) -> Any:
    try:
        return kind(value)
    except ValueError:
        raise IncidentValidationError(f"Invalid {label}: must be one of {', '.join(item.value for item in kind)}") from None


def require_status(incident: Incident, allowed: set[LifecycleStatus] | frozenset[LifecycleStatus], action: str) -> None:
    if incident.status not in allowed:
        raise InvalidTransitionError(f"Cannot {action} while the incident is {incident.status.value}")


class IncidentService:
    def __init__(self, repository: IncidentRepository, clock: Callable[[], datetime] = utc_now) -> None:
        self.repository = repository
        self.clock = clock
        self.index = TopologyIndex(load_topology())

    def now(self) -> datetime:
        moment = self.clock()
        if moment.tzinfo is None or moment.utcoffset() != timedelta(0):
            raise IncidentValidationError("The service clock must return UTC timestamps")
        return moment

    def event(self, incident: Incident, pending: list[TimelineEvent], event_type: EventType, actor: Actor,
              description: str, **fields: Any) -> TimelineEvent:
        history = incident.timeline + pending
        sequence = len(history) + 1
        moment = max(self.now(), history[-1].timestamp) if history else self.now()
        event = TimelineEvent(event_id=f"{incident.incident_id}-EV{sequence:04d}", incident_id=incident.incident_id,
                              sequence=sequence, event_type=event_type, timestamp=moment, actor=actor,
                              description=description[:2000], **fields)
        pending.append(event)
        return event

    def commit(self, incident: Incident, updates: dict[str, Any], events: list[TimelineEvent]) -> Incident:
        timeline = incident.timeline + events
        values = incident.model_dump() | updates | {
            "timeline": timeline, "version": incident.version + 1,
            "updated_at": max(timeline[-1].timestamp, incident.updated_at),
        }
        try:
            updated = Incident.model_validate(values)
        except ValidationError as exc:
            raise IncidentValidationError(f"Incident update rejected: {exc.errors()[0]['msg']}") from None
        self.repository.save(updated)
        return updated

    def get_incident(self, incident_id: str) -> Incident:
        return self.repository.get(incident_id)

    def list_incidents(self, criteria: IncidentFilter | None = None, visible: Visibility = None) -> list[IncidentSummary]:
        return self.repository.query(criteria or IncidentFilter(), visible)

    def timeline(self, incident_id: str) -> list[TimelineEvent]:
        return self.get_incident(incident_id).timeline

    def new_incident(self, request: IncidentCreateRequest, actor: Actor, incident_id: str, moment: datetime,
                     description: str, demo: bool = False) -> Incident:
        """Validates a report and builds its version-1 record; the caller stores it."""
        self.index.require_sites(request.site_ids)
        self.index.require_devices(request.device_ids)
        if request.dataset_scenario_id and not scenario_exists(request.dataset_scenario_id):
            raise IncidentValidationError(f"Unknown dataset scenario '{request.dataset_scenario_id}'")
        if request.reported_at and request.reported_at > moment:
            raise IncidentValidationError("reported_at cannot be in the future")
        if request.severity:
            severity, severity_source = request.severity, ValueSource.MANUAL
        elif request.priority:
            severity, severity_source = SEVERITY_FOR_PRIORITY[request.priority], ValueSource.DERIVED
        elif len(set(request.site_ids)) >= 2:
            severity, severity_source = IncidentSeverity.HIGH, ValueSource.DERIVED
        else:
            severity, severity_source = IncidentSeverity.MEDIUM, ValueSource.DEFAULT
        priority, priority_source = ((request.priority, ValueSource.MANUAL) if request.priority
                                     else (PRIORITY_FOR_SEVERITY[severity], ValueSource.DERIVED))
        source = f"{actor.kind.value}:{actor.actor_id}"
        reported = [asset(AssetType.SITE, site, ImpactBasis.REPORTED, source, moment) for site in request.site_ids]
        reported += [asset(AssetType.DEVICE, device, ImpactBasis.REPORTED, source, moment) for device in request.device_ids]
        reported += [asset(AssetType.SERVICE, service.value, ImpactBasis.REPORTED, source, moment) for service in request.services]
        assets, _ = merge_assets([], reported)
        created = moment if request.reported_at is None else min(moment, request.reported_at)
        if any(contains_secret(text) for text in (request.title, request.description, *request.symptoms)):
            request = request.model_copy(update={"title": redact(request.title), "description": redact(request.description),
                                                 "symptoms": [redact(item) for item in request.symptoms]})
        return Incident(
            incident_id=incident_id, version=1, title=request.title, description=request.description,
            source=request.source, dataset_scenario_id=request.dataset_scenario_id, demo=demo,
            site_ids=list(dict.fromkeys(request.site_ids)),
            symptoms=request.symptoms, severity=severity, severity_source=severity_source, priority=priority,
            priority_source=priority_source, status=LifecycleStatus.NEW, affected_assets=assets,
            security_flags=injection_flags("incident report", f"{request.title}\n{request.description}"),
            created_at=created, updated_at=moment,
            timeline=[TimelineEvent(event_id=f"{incident_id}-EV0001", incident_id=incident_id, sequence=1,
                                    event_type=EventType.CREATED, timestamp=created, actor=actor, description=description,
                                    to_status=LifecycleStatus.NEW)],
        )

    def create_incident(self, request: IncidentCreateRequest, actor: Actor, visible: Visibility = None) -> CreationOutcome:
        require_actor(actor, ANYONE, "create incidents")
        moment = self.now()
        description = f"Incident reported via {request.source.value}"
        incident = self.new_incident(request, actor, self.repository.next_id(moment), moment, description)
        matches = self.similar_to(incident, active_only=True, visible=visible)
        reasons = {match.incident_id: duplicate_reason(incident, self.get_incident(match.incident_id), match) for match in matches}
        duplicates = [match for match in matches if reasons[match.incident_id]]
        possible = [match for match in matches if match.strength.value != "weak" and match not in duplicates]
        if duplicates and not request.force_new:
            best = duplicates[0]
            existing = self.get_incident(best.incident_id)
            events: list[TimelineEvent] = []
            self.event(existing, events, EventType.RELATED_REPORT_LINKED, actor,
                       f"A new report matched this incident and was not created separately: {request.title}",
                       details={"reason": reasons[best.incident_id]})
            return CreationOutcome(incident=self.commit(existing, {}, events), created=False, duplicate_of=best,
                                   duplicate_reason=reasons[best.incident_id], possible_duplicates=possible)
        if duplicates or possible:
            related = ", ".join(match.incident_id for match in duplicates + possible)
            first = incident.timeline[0].model_copy(update={"description": f"{description}; possibly related to {related}",
                                                           "details": {"possibly_related": related}})
            incident = incident.model_copy(update={"timeline": [first]})
        self.repository.add(incident)
        return CreationOutcome(incident=incident, created=True, possible_duplicates=duplicates + possible)

    def add_demo_incident(self, request: IncidentCreateRequest, actor: Actor, incident_id: str, note: str) -> Incident:
        """Stores a demo record under a fixed identifier. Only a system actor seeds demo data, an existing record is never
        replaced (the repository refuses the identifier), and no duplicate linking runs: demo and reported incidents stay apart."""
        require_actor(actor, (ActorKind.SYSTEM,), "seed demo incidents")
        if not request.dataset_scenario_id:
            raise IncidentValidationError("A demo incident must name its synthetic dataset scenario")
        incident = self.new_incident(request, actor, incident_id, self.now(), note, demo=True)
        self.repository.add(incident)
        return incident

    def update_details(self, incident_id: str, actor: Actor, title: str | None = None, description: str | None = None,
                       assigned_team: str | None = None, assigned_owner: str | None = None) -> Incident:
        require_actor(actor, OPERATORS, "update incident details")
        incident = self.get_incident(incident_id)
        proposed = {"title": title, "description": description, "assigned_team": assigned_team, "assigned_owner": assigned_owner}
        proposed = {key: redact(value) if isinstance(value, str) else value for key, value in proposed.items()}
        updates = {key: value for key, value in proposed.items() if value is not None and getattr(incident, key) != value}
        if not updates:
            raise IncidentValidationError("No changes were supplied")
        events: list[TimelineEvent] = []
        self.event(incident, events, EventType.DETAILS_UPDATED, actor, f"Updated {', '.join(sorted(updates))}",
                   details={key: str(value)[:200] for key, value in updates.items()})
        return self.commit(incident, updates, events)

    def transition(self, incident: Incident, target: LifecycleStatus, events: list[TimelineEvent], actor: Actor,
                   description: str, event_type: EventType | None = None) -> dict[str, Any]:
        if target not in TRANSITIONS[incident.status]:
            raise InvalidTransitionError(f"Transition {incident.status.value} -> {target.value} is not permitted")
        self.event(incident, events, event_type or STATUS_EVENTS.get(target, EventType.STATUS_CHANGED), actor, description,
                   from_status=incident.status, to_status=target)
        return {"status": target}

    def change_status(self, incident_id: str, actor: Actor, target: LifecycleStatus, reason: str | None = None) -> Incident:
        require_actor(actor, OPERATORS, "change incident status")
        target = coerce(LifecycleStatus, target, "status")
        incident = self.get_incident(incident_id)
        if target in DEDICATED_TARGETS:
            raise InvalidTransitionError(f"Use {DEDICATED_TARGETS[target]} to move an incident to {target.value}")
        if incident.status in (LifecycleStatus.RESOLVED, LifecycleStatus.CLOSED):
            raise InvalidTransitionError("Use reopen_incident to resume work on a resolved or closed incident")
        if target == LifecycleStatus.DIAGNOSED and incident.active_diagnosis_id is None:
            raise InvalidTransitionError("An incident cannot be marked diagnosed without an associated diagnosis")
        events: list[TimelineEvent] = []
        text = f"Status changed to {target.value}" + (f": {reason[:500]}" if reason else "")
        return self.commit(incident, self.transition(incident, target, events, actor, text), events)

    def change_severity(self, incident_id: str, actor: Actor, severity: IncidentSeverity, reason: str) -> Incident:
        require_actor(actor, HUMAN, "change severity")
        severity = coerce(IncidentSeverity, severity, "severity")
        if not reason or not reason.strip():
            raise IncidentValidationError("A reason is required to change severity")
        incident = self.get_incident(incident_id)
        if severity == incident.severity:
            raise IncidentValidationError(f"Severity is already {severity.value}")
        events: list[TimelineEvent] = []
        updates = self.severity_updates(incident, severity, ValueSource.MANUAL, events, actor, reason)
        return self.commit(incident, updates, events)

    def severity_updates(self, incident: Incident, severity: IncidentSeverity, source: ValueSource,
                         events: list[TimelineEvent], actor: Actor, reason: str) -> dict[str, Any]:
        direction = "raised" if SEVERITY_RANK[severity] > SEVERITY_RANK[incident.severity] else "lowered"
        self.event(incident, events, EventType.SEVERITY_CHANGED, actor,
                   f"Severity {direction} from {incident.severity.value} to {severity.value}: {reason[:500]}",
                   details={"from": incident.severity.value, "to": severity.value, "source": source.value})
        updates: dict[str, Any] = {"severity": severity, "severity_source": source}
        priority = PRIORITY_FOR_SEVERITY[severity]
        if incident.priority_source != ValueSource.MANUAL and priority != incident.priority:
            self.event(incident, events, EventType.PRIORITY_CHANGED, actor,
                       f"Priority derived from severity changed from {incident.priority.value} to {priority.value}",
                       details={"from": incident.priority.value, "to": priority.value, "source": ValueSource.DERIVED.value})
            updates |= {"priority": priority, "priority_source": ValueSource.DERIVED}
        return updates

    def change_priority(self, incident_id: str, actor: Actor, priority: IncidentPriority, reason: str) -> Incident:
        require_actor(actor, HUMAN, "change priority")
        priority = coerce(IncidentPriority, priority, "priority")
        if not reason or not reason.strip():
            raise IncidentValidationError("A reason is required to change priority")
        incident = self.get_incident(incident_id)
        if priority == incident.priority:
            raise IncidentValidationError(f"Priority is already {priority.value}")
        events: list[TimelineEvent] = []
        self.event(incident, events, EventType.PRIORITY_CHANGED, actor,
                   f"Priority changed from {incident.priority.value} to {priority.value}: {reason[:500]}",
                   details={"from": incident.priority.value, "to": priority.value, "source": ValueSource.MANUAL.value})
        return self.commit(incident, {"priority": priority, "priority_source": ValueSource.MANUAL}, events)

    def classify(self, incident_id: str, actor: Actor, fault_domain: FaultDomain, reason: str) -> Incident:
        require_actor(actor, HUMAN, "confirm a classification")
        fault_domain = coerce(FaultDomain, fault_domain, "fault domain")
        if not reason or not reason.strip():
            raise IncidentValidationError("A reason is required to confirm a classification")
        incident = self.get_incident(incident_id)
        events: list[TimelineEvent] = []
        updates = self.classification_updates(incident, fault_domain, events, actor, reason)
        return self.commit(incident, updates, events)

    def classification_updates(self, incident: Incident, fault_domain: FaultDomain, events: list[TimelineEvent],
                               actor: Actor, reason: str) -> dict[str, Any]:
        previous = incident.classification.confirmed_fault_domain
        if previous == fault_domain:
            raise IncidentValidationError(f"Classification is already confirmed as {fault_domain.value}")
        moment = max(self.now(), incident.timeline[-1].timestamp)
        self.event(incident, events, EventType.CLASSIFICATION_CHANGED, actor,
                   f"Confirmed classification set to {fault_domain.value}: {reason[:500]}",
                   details={"from": previous.value if previous else "unconfirmed", "to": fault_domain.value,
                            "probable": (incident.classification.probable_fault_domain or FaultDomain.UNKNOWN).value})
        return {"classification": incident.classification.model_copy(update={
            "confirmed_fault_domain": fault_domain, "confirmed_by": actor, "confirmed_at": moment})}

    def associate_diagnosis(self, incident_id: str, actor: Actor, diagnosis: Diagnosis) -> Incident:
        require_actor(actor, OPERATORS, "associate diagnoses")
        if not isinstance(diagnosis, Diagnosis):
            raise IncidentValidationError("A validated diagnosis is required")
        problems = provenance_issues(diagnosis)
        if problems:
            raise IncidentValidationError(f"Diagnosis provenance check failed: {problems[0]}")
        incident = self.get_incident(incident_id)
        require_status(incident, {LifecycleStatus.ACKNOWLEDGED} | ACTIVE_STATUSES - {LifecycleStatus.NEW}, "associate a diagnosis")
        if incident.dataset_scenario_id and diagnosis.incident.scenario_id != incident.dataset_scenario_id:
            raise IncidentValidationError("The diagnosis was produced for a different dataset scenario")
        self.index.require_sites(diagnosis.incident.site_ids)
        if diagnosis.affected_path:
            self.index.require_path(diagnosis.affected_path.path)
        events: list[TimelineEvent] = []
        updates: dict[str, Any] = {}
        status = incident.status
        if status == LifecycleStatus.ACKNOWLEDGED:
            updates |= self.transition(incident, LifecycleStatus.INVESTIGATING, events, actor,
                                       "Investigation started for automated diagnosis")
            status = LifecycleStatus.INVESTIGATING
        number = len(incident.diagnoses) + 1
        diagnosis_id = f"DGN-{incident.incident_id[4:]}-{number:02d}"
        moment = max(self.now(), incident.timeline[-1].timestamp)
        record = DiagnosisRecord(
            diagnosis_id=diagnosis_id, incident_id=incident.incident_id, created_at=moment, method=diagnosis.method,
            status=diagnosis.incident.status, probable_fault_domain=diagnosis.fault.fault_domain,
            confidence=diagnosis.confidence.level, root_cause=diagnosis.fault.root_cause,
            alternative_fault_domains=[alternative.fault_domain for alternative in diagnosis.alternatives],
            diagnosis=diagnosis,
        )
        diagnoses = list(incident.diagnoses)
        previous = incident.active_diagnosis
        if previous is not None:
            diagnoses = [d.model_copy(update={"superseded_by": diagnosis_id}) if d.diagnosis_id == previous.diagnosis_id else d
                         for d in diagnoses]
            self.event(incident, events, EventType.DIAGNOSIS_SUPERSEDED, actor,
                       f"Diagnosis {previous.diagnosis_id} superseded by {diagnosis_id}; history retained",
                       diagnosis_id=previous.diagnosis_id)
        executed = [call for call in diagnosis.tool_calls if call.status == "executed"]
        if diagnosis.tool_calls:
            self.event(incident, events, EventType.DIAGNOSTIC_TOOLS_EXECUTED, actor,
                       f"{len(executed)} diagnostic tool calls executed ({len(diagnosis.tool_calls)} requested): "
                       f"{', '.join(dict.fromkeys(call.tool for call in executed))}",
                       diagnosis_id=diagnosis_id)
        supporting = diagnosis.fault.supporting_evidence_ids
        self.event(incident, events, EventType.DIAGNOSIS_COMPLETED, actor,
                   f"{diagnosis.method.value} diagnosis {diagnosis.incident.status.value}: probable "
                   f"{diagnosis.fault.fault_domain.value} ({diagnosis.confidence.level.value} confidence). "
                   "Requires human verification; not a confirmed resolution.",
                   diagnosis_id=diagnosis_id, evidence_ids=supporting[:50],
                   device_id=diagnosis.fault.device_ids[0] if diagnosis.fault.device_ids else None,
                   details={"method": diagnosis.method.value, "probable_fault_domain": diagnosis.fault.fault_domain.value,
                            "confidence": diagnosis.confidence.level.value})
        by_id = {item.evidence_id: item for item in diagnosis.evidence}
        links = [EvidenceLink(diagnosis_id=diagnosis_id, evidence_id=evidence_id, tool=by_id[evidence_id].tool,
                              code=by_id[evidence_id].code, device_id=by_id[evidence_id].device_id,
                              timestamp=by_id[evidence_id].timestamp)
                 for evidence_id in supporting if evidence_id in by_id][:MAX_LINKED_EVIDENCE]
        assets, changes = merge_assets(incident.affected_assets,
                                       diagnosis_assets(self.index, diagnosis, incident.site_ids, f"diagnosis:{diagnosis_id}", moment))
        if changes:
            self.event(incident, events, EventType.ASSETS_UPDATED, actor,
                       f"Affected scope updated from diagnosis {diagnosis_id}: {'; '.join(changes)[:1500]}", diagnosis_id=diagnosis_id)
        known = diagnosis.fault.fault_domain != FaultDomain.UNKNOWN
        updates |= {
            "diagnoses": diagnoses + [record], "active_diagnosis_id": diagnosis_id, "evidence": incident.evidence + links,
            "affected_assets": assets,
            "affected_path": diagnosis.affected_path.path if diagnosis.affected_path else incident.affected_path,
            "classification": incident.classification.model_copy(update={
                "probable_fault_domain": diagnosis.fault.fault_domain, "probable_source_diagnosis_id": diagnosis_id}),
            "security_flags": sorted(set(incident.security_flags) | set(diagnosis.security_flags)),
        }
        suggested = SEVERITY_FOR_PRIORITY[diagnosis.escalation.priority]
        if known and incident.severity_source != ValueSource.MANUAL and SEVERITY_RANK[suggested] > SEVERITY_RANK[incident.severity]:
            updates |= self.severity_updates(incident, suggested, ValueSource.DERIVED, events, actor,
                                             f"diagnosis {diagnosis_id} indicates higher impact")
        if known and status == LifecycleStatus.INVESTIGATING:
            staged = incident.model_copy(update={"status": status})
            updates |= self.transition(staged, LifecycleStatus.DIAGNOSED, events, actor,
                                       f"Diagnosis {diagnosis_id} available; awaiting human verification")
        return self.commit(incident, updates, events)

    @staticmethod
    def diagnosis_request(incident: Incident) -> DiagnosisRequest:
        if not incident.dataset_scenario_id:
            raise IncidentValidationError("The incident is not linked to a dataset scenario for diagnosis")
        return DiagnosisRequest(scenario_id=incident.dataset_scenario_id, description=incident.description,
                                incident_id=incident.incident_id, site_ids=incident.site_ids[:5],
                                severity=incident.priority if incident.priority_source == ValueSource.MANUAL else None,
                                reported_at=incident.created_at)

    def run_diagnosis(self, incident_id: str, actor: Actor, engine: DiagnosisEngine | None = None) -> Incident:
        require_actor(actor, OPERATORS, "run diagnoses")
        request = self.diagnosis_request(self.get_incident(incident_id))
        diagnosis = (engine or DiagnosisEngine()).diagnose(request)
        return self.associate_diagnosis(incident_id, actor, diagnosis)

    def update_affected_assets(self, incident_id: str, actor: Actor, updates: list[AssetUpdate]) -> Incident:
        require_actor(actor, ANYONE, "update affected assets")
        if not updates:
            raise IncidentValidationError("No asset updates were supplied")
        if actor.kind != ActorKind.HUMAN and any(update.basis == ImpactBasis.CONFIRMED for update in updates):
            raise UnauthorizedActionError("Only human actors may confirm impact")
        incident = self.get_incident(incident_id)
        moment = max(self.now(), incident.timeline[-1].timestamp)
        source = f"{actor.kind.value}:{actor.actor_id}"
        for update in updates:
            self.index.require_asset(update.asset_type, update.asset_id)
        assets, changes = merge_assets(incident.affected_assets,
                                       [asset(u.asset_type, u.asset_id, u.basis, source, moment) for u in updates])
        if not changes:
            raise IncidentValidationError("The supplied assets do not change the affected scope")
        events: list[TimelineEvent] = []
        self.event(incident, events, EventType.ASSETS_UPDATED, actor, f"Affected scope updated: {'; '.join(changes)[:1500]}")
        return self.commit(incident, {"affected_assets": assets}, events)

    def create_escalation(self, incident_id: str, actor: Actor, team: str | None = None,
                          priority: IncidentPriority | None = None, reason: str | None = None) -> Incident:
        require_actor(actor, OPERATORS, "create escalations")
        priority = coerce(IncidentPriority, priority, "priority") if priority is not None else None
        incident = self.get_incident(incident_id)
        record = incident.active_diagnosis
        if record is None and not (team and reason):
            raise IncidentValidationError("Escalation without a diagnosis requires an explicit team and reason")
        recommendation = record.diagnosis.escalation if record else None
        if incident.status != LifecycleStatus.ESCALATED and LifecycleStatus.ESCALATED not in TRANSITIONS[incident.status]:
            raise InvalidTransitionError(f"Cannot escalate while the incident is {incident.status.value}")
        checks = [OutstandingCheck(device_id=c.device_id, command=c.command, purpose=c.purpose)
                  for c in (record.diagnosis.next_checks if record else [])][:10]
        domain = incident.fault_domain or FaultDomain.UNKNOWN
        number = len(incident.escalations) + 1
        escalation_id = f"ESC-{incident.incident_id[4:]}-{number:02d}"
        summary_lines = [
            f"Incident {incident.incident_id}: {incident.title}",
            f"Sites: {', '.join(incident.site_ids)}; severity {incident.severity.value}; status {incident.status.value}",
            f"Fault domain: {domain.value} ({'confirmed' if incident.classification.confirmed_fault_domain else 'probable, unverified'})",
        ]
        if record:
            summary_lines.append(f"Diagnosis {record.diagnosis_id} ({record.method.value}, {record.confidence.value} confidence): "
                                 f"{record.root_cause}")
        summary_lines += [f"Outstanding check on {c.device_id}: {c.command}" for c in checks]
        summary_lines += [f"Reference knowledge (guidance only): {k.record_id} v{k.version} {k.title}"
                          for k in incident.knowledge_references]
        moment = max(self.now(), incident.timeline[-1].timestamp)
        escalation = EscalationRecord(
            escalation_id=escalation_id, incident_id=incident.incident_id, created_at=moment, created_by=actor,
            recommended_team=team or recommendation.team, priority=priority or incident.priority,
            reason=(reason or recommendation.reason)[:1000], fault_domain=domain,
            diagnosis_id=record.diagnosis_id if record else None,
            evidence_ids=(recommendation.evidence_ids if recommendation else [])[:50], outstanding_checks=checks,
            handover_summary="\n".join(summary_lines)[:4000], status=EscalationStatus.RECOMMENDED,
        )
        events: list[TimelineEvent] = []
        updates: dict[str, Any] = {"escalations": incident.escalations + [escalation]}
        text = f"Escalation {escalation_id} recommended to {escalation.recommended_team} ({escalation.priority.value}); not sent"
        if incident.status == LifecycleStatus.ESCALATED:
            self.event(incident, events, EventType.ESCALATION_CREATED, actor, text, diagnosis_id=escalation.diagnosis_id,
                       evidence_ids=escalation.evidence_ids)
        else:
            updates |= self.transition(incident, LifecycleStatus.ESCALATED, events, actor, text, EventType.ESCALATION_CREATED)
        return self.commit(incident, updates, events)

    def update_escalation(self, incident_id: str, escalation_id: str, actor: Actor, status: EscalationStatus,
                          note: str, assigned_team: str | None = None) -> Incident:
        require_actor(actor, HUMAN, "update escalations")
        status = coerce(EscalationStatus, status, "escalation status")
        incident = self.get_incident(incident_id)
        current = next((e for e in incident.escalations if e.escalation_id == escalation_id), None)
        if current is None:
            raise IncidentValidationError(f"Unknown escalation '{escalation_id[:40]}'")
        if status not in ESCALATION_TRANSITIONS[current.status]:
            raise InvalidTransitionError(f"Escalation transition {current.status.value} -> {status.value} is not permitted")
        changed = current.model_copy(update={"status": status, "assigned_team": assigned_team or current.assigned_team,
                                              "status_notes": current.status_notes + [note[:500]]})
        try:
            changed = EscalationRecord.model_validate(changed.model_dump())
        except ValidationError as exc:
            raise IncidentValidationError(f"Escalation update rejected: {exc.errors()[0]['msg']}") from None
        events: list[TimelineEvent] = []
        self.event(incident, events, EventType.ESCALATION_UPDATED, actor,
                   f"Escalation {escalation_id} {current.status.value} -> {status.value}: {note[:500]}")
        escalations = [changed if e.escalation_id == escalation_id else e for e in incident.escalations]
        return self.commit(incident, {"escalations": escalations}, events)

    def link_knowledge(self, incident_id: str, actor: Actor, references: list[KnowledgeReference]) -> Incident:
        require_actor(actor, ANYONE, "link knowledge")
        incident = self.get_incident(incident_id)
        require_status(incident, set(LifecycleStatus) - {LifecycleStatus.CLOSED}, "link knowledge")
        if any(not isinstance(reference, KnowledgeReference) for reference in references):
            raise IncidentValidationError("Knowledge references must be validated records")
        known = {(k.record_id, k.version) for k in incident.knowledge_references}
        new = [k for k in references if (k.record_id, k.version) not in known]
        new = list({(k.record_id, k.version): k for k in new}.values())
        if not new:
            raise IncidentValidationError("No new knowledge references were supplied")
        if any(k.diagnosis_id and k.diagnosis_id not in {d.diagnosis_id for d in incident.diagnoses} for k in new):
            raise IncidentValidationError("Knowledge references must cite a diagnosis of this incident")
        events: list[TimelineEvent] = []
        self.event(incident, events, EventType.KNOWLEDGE_LINKED, actor,
                   f"Linked troubleshooting guidance (not evidence): {', '.join(f'{k.record_id} v{k.version}' for k in new)}",
                   diagnosis_id=new[0].diagnosis_id)
        return self.commit(incident, {"knowledge_references": incident.knowledge_references + new}, events)

    def propose_resolution(self, incident_id: str, actor: Actor, summary: str, fault_domain: FaultDomain,
                           notes: list[str] | None = None, responsible_team: str | None = None) -> Incident:
        require_actor(actor, ANYONE, "propose resolutions")
        fault_domain = coerce(FaultDomain, fault_domain, "fault domain")
        incident = self.get_incident(incident_id)
        require_status(incident, ACTIVE_STATUSES - {LifecycleStatus.NEW, LifecycleStatus.ACKNOWLEDGED}, "propose a resolution")
        current = incident.current_resolution
        if current is not None and current.verification == VerificationStatus.PENDING:
            raise IncidentValidationError(f"Resolution {current.resolution_id} is still awaiting verification")
        resolution_id = f"RES-{incident.incident_id[4:]}-{len(incident.resolutions) + 1:02d}"
        moment = max(self.now(), incident.timeline[-1].timestamp)
        resolution = Resolution(resolution_id=resolution_id, summary=summary, fault_domain=fault_domain, notes=notes or [],
                                proposed_by=actor, proposed_at=moment, responsible_team=responsible_team,
                                verification=VerificationStatus.PENDING)
        events: list[TimelineEvent] = []
        self.event(incident, events, EventType.RESOLUTION_PROPOSED, actor,
                   f"Resolution {resolution_id} proposed by {actor.kind.value} ({fault_domain.value}); awaiting human verification")
        return self.commit(incident, {"resolutions": incident.resolutions + [resolution]}, events)

    def verify_resolution(self, incident_id: str, actor: Actor, approved: bool, note: str,
                          responsible_team: str | None = None) -> Incident:
        require_actor(actor, HUMAN, "verify resolutions")
        if not note or not note.strip():
            raise IncidentValidationError("A verification note is required")
        incident = self.get_incident(incident_id)
        current = incident.current_resolution
        if current is None or current.verification != VerificationStatus.PENDING:
            raise IncidentValidationError("There is no resolution awaiting verification")
        moment = max(self.now(), incident.timeline[-1].timestamp)
        events: list[TimelineEvent] = []
        updates: dict[str, Any] = {}
        team = responsible_team or current.responsible_team
        if approved:
            if LifecycleStatus.RESOLVED not in TRANSITIONS[incident.status]:
                raise InvalidTransitionError("Resolution can only be verified while the incident is in monitoring")
            resolution = current.model_copy(update={"verification": VerificationStatus.VERIFIED, "verified_by": actor,
                                                    "verified_at": moment, "resolved_at": moment, "responsible_team": team,
                                                    "notes": current.notes + [note[:1000]]})
            self.event(incident, events, EventType.RESOLUTION_VERIFIED, actor, f"Resolution {current.resolution_id} verified: {note[:500]}")
            if incident.classification.confirmed_fault_domain != current.fault_domain:
                updates |= self.classification_updates(incident, current.fault_domain, events, actor,
                                                       f"confirmed by verified resolution {current.resolution_id}")
            updates |= self.transition(incident, LifecycleStatus.RESOLVED, events, actor,
                                       f"Incident resolved; verified by {actor.actor_id}", EventType.RESOLVED)
        else:
            resolution = current.model_copy(update={"verification": VerificationStatus.REJECTED, "verified_by": actor,
                                                    "verified_at": moment, "notes": current.notes + [note[:1000]]})
            self.event(incident, events, EventType.RESOLUTION_REJECTED, actor, f"Resolution {current.resolution_id} rejected: {note[:500]}")
        resolution = Resolution.model_validate(resolution.model_dump())
        updates["resolutions"] = incident.resolutions[:-1] + [resolution]
        return self.commit(incident, updates, events)

    def close_incident(self, incident_id: str, actor: Actor, note: str) -> Incident:
        require_actor(actor, HUMAN, "close incidents")
        if not note or not note.strip():
            raise IncidentValidationError("A closure note is required")
        incident = self.get_incident(incident_id)
        unmet = []
        if incident.status != LifecycleStatus.RESOLVED:
            unmet.append(f"incident must be resolved (currently {incident.status.value})")
        resolution = incident.current_resolution
        if resolution is None or resolution.verification != VerificationStatus.VERIFIED:
            unmet.append("a human-verified resolution is required")
        if incident.classification.confirmed_fault_domain is None:
            unmet.append("a confirmed classification is required")
        open_escalations = [e.escalation_id for e in incident.escalations if e.status in OPEN_ESCALATION_STATUSES]
        if open_escalations:
            unmet.append(f"open escalations must be closed or cancelled: {', '.join(open_escalations)}")
        if unmet:
            raise InvalidTransitionError(f"Incident cannot be closed: {'; '.join(unmet)}")
        moment = max(self.now(), incident.timeline[-1].timestamp)
        events: list[TimelineEvent] = []
        updates = self.transition(incident, LifecycleStatus.CLOSED, events, actor, f"Incident closed: {note[:500]}", EventType.CLOSED)
        updates["closure"] = Closure(closed_at=moment, closed_by=actor, notes=note[:1000])
        return self.commit(incident, updates, events)

    def reopen_incident(self, incident_id: str, actor: Actor, reason: str) -> Incident:
        require_actor(actor, HUMAN, "reopen incidents")
        if not reason or not reason.strip():
            raise IncidentValidationError("A reason is required to reopen an incident")
        incident = self.get_incident(incident_id)
        require_status(incident, {LifecycleStatus.RESOLVED, LifecycleStatus.CLOSED}, "reopen")
        events: list[TimelineEvent] = []
        updates = self.transition(incident, LifecycleStatus.INVESTIGATING, events, actor,
                                  f"Incident reopened: {reason[:500]}", EventType.REOPENED)
        current = incident.current_resolution
        reverted = current.model_copy(update={"verification": VerificationStatus.REVERTED,
                                              "notes": current.notes + [f"Reverted on reopen: {reason[:500]}"]})
        updates |= {"closure": None, "resolutions": incident.resolutions[:-1] + [reverted]}
        return self.commit(incident, updates, events)

    def similar_to(self, incident: Incident, active_only: bool = False, window: timedelta = DEFAULT_WINDOW,
                   limit: int = 10, visible: Visibility = None) -> list[SimilarIncident]:
        summaries = self.repository.query(IncidentFilter(limit=SIMILARITY_SCAN_LIMIT), visible)
        # Demo records are compared only with demo records, so a real report is never linked to or merged into synthetic data.
        candidates = [s for s in summaries if s.incident_id != incident.incident_id and s.demo == incident.demo
                      and (not active_only or s.status in ACTIVE_STATUSES)
                      and (not active_only or set(s.site_ids) & set(incident.site_ids))]
        matches = [compare(incident, self.get_incident(s.incident_id), window) for s in candidates]
        matches = [match for match in matches if match.points > 0]
        matches.sort(key=lambda match: (-match.points, match.incident_id))
        return matches[:limit]

    def find_similar(self, incident_id: str, limit: int = 5, window: timedelta = DEFAULT_WINDOW,
                     visible: Visibility = None) -> list[SimilarIncident]:
        return self.similar_to(self.get_incident(incident_id), window=window, limit=limit, visible=visible)

    def diagnosis_history(self, incident_id: str) -> list[DiagnosisComparison]:
        history, previous = [], None
        for record in self.get_incident(incident_id).diagnoses:
            changes = []
            if previous is not None:
                if previous.probable_fault_domain != record.probable_fault_domain:
                    changes.append(f"fault domain {previous.probable_fault_domain.value} -> {record.probable_fault_domain.value}")
                if previous.confidence != record.confidence:
                    changes.append(f"confidence {previous.confidence.value} -> {record.confidence.value}")
                if previous.method != record.method:
                    changes.append(f"method {previous.method.value} -> {record.method.value}")
            history.append(DiagnosisComparison(
                diagnosis_id=record.diagnosis_id, created_at=record.created_at, method=record.method.value,
                probable_fault_domain=record.probable_fault_domain, confidence=record.confidence.value,
                superseded_by=record.superseded_by, changes_from_previous=changes,
            ))
            previous = record
        return history

    def resolution_history(self, criteria: IncidentFilter | None = None) -> list[ResolutionHistoryEntry]:
        entries = []
        for summary in self.list_incidents(criteria):
            for resolution in self.get_incident(summary.incident_id).resolutions:
                if resolution.verification != VerificationStatus.PENDING:
                    entries.append(ResolutionHistoryEntry(incident_id=summary.incident_id, resolution=resolution))
        return sorted(entries, key=lambda e: (e.resolution.proposed_at, e.resolution.resolution_id))

    def recurring_incidents(self, window: timedelta = timedelta(days=30), minimum: int = 2,
                            reference: datetime | None = None, visible: Visibility = None) -> list[RecurringGroup]:
        end = reference or self.now()
        summaries = self.repository.query(IncidentFilter(start=end - window, end=end + timedelta(seconds=1),
                                                         limit=SIMILARITY_SCAN_LIMIT), visible)
        groups: dict[tuple[str, FaultDomain, bool], list[IncidentSummary]] = {}
        for summary in summaries:
            if summary.fault_domain in (None, FaultDomain.UNKNOWN):
                continue
            for site in summary.site_ids:  # demo records never form a recurrence with reported incidents
                groups.setdefault((site, summary.fault_domain, summary.demo), []).append(summary)
        recurring = []
        for (site, domain, _), members in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1].value, item[0][2])):
            if len(members) < minimum:
                continue
            members.sort(key=lambda s: (s.created_at, s.incident_id))
            common = set.intersection(*(set(member.device_ids) for member in members))
            recurring.append(RecurringGroup(site_id=site, fault_domain=domain, incident_ids=[m.incident_id for m in members],
                                            first_seen=members[0].created_at, last_seen=members[-1].created_at,
                                            common_devices=sorted(common)))
        return recurring
