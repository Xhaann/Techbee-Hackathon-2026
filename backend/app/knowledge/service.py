from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.engine.safety import is_read_only_command
from app.engine.schema import Confidence, Diagnosis, FaultDomain
from app.incidents.models import ACTIVE_STATUSES, Actor, Incident, KnowledgeReference
from app.incidents.service import ANYONE, IncidentService, require_actor
from app.knowledge.models import AnyRecord, Playbook, RecordType, Runbook
from app.knowledge.repository import KnowledgeNotFoundError, KnowledgeRepository, default_repository
from app.knowledge.retrieval import GUIDANCE_NOTICE, KnowledgeMatch, KnowledgeQuery, KnowledgeRetriever, MatchType, PlaybookRetriever, RetrievalResult
from app.network.repository import load_topology

MAX_CHECKS = 10
GUIDANCE_TYPES = [RecordType.PLAYBOOK, RecordType.PROCEDURE, RecordType.DOCUMENT]


class AssessmentModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class EvidenceExpectation(AssessmentModel):
    requirement_id: str
    description: str
    tool: str
    expected_codes: list[str]
    observed: bool
    evidence_ids: list[str]


class GuidanceCheck(AssessmentModel):
    source_record_id: str
    step_order: int
    device_id: str | None
    command: str
    platform: str
    purpose: str
    parameters: list[str]
    illustrative: Literal[True] = True


class KnowledgeAssessment(AssessmentModel):
    query: KnowledgeQuery
    matches: list[KnowledgeMatch]
    selected_playbook_id: str | None
    selection_reasons: list[str]
    runbook_ids: list[str]
    evidence_comparison: list[EvidenceExpectation]
    missing_evidence: list[str]
    supplementary_checks: list[GuidanceCheck]
    diagnosis_confidence: Confidence | None
    confidence_changed: Literal[False] = False
    establishes_root_cause: Literal[False] = False
    notice: str = GUIDANCE_NOTICE
    security_flags: list[str]


class KnowledgeService:
    def __init__(self, repository: KnowledgeRepository | None = None) -> None:
        self.repository = repository or default_repository()
        self.retriever = KnowledgeRetriever(self.repository)
        topology = load_topology()
        self.devices = {device.device_id: device for device in topology.devices}

    def search(self, query: KnowledgeQuery) -> RetrievalResult:
        return self.retriever.search(query)

    def diagnosis_retriever(self) -> PlaybookRetriever:
        return PlaybookRetriever(self.retriever)

    def query_for_diagnosis(self, diagnosis: Diagnosis) -> KnowledgeQuery:
        domain = diagnosis.fault.fault_domain
        return KnowledgeQuery(
            text=diagnosis.incident.description, record_types=GUIDANCE_TYPES,
            fault_domain=None if domain == FaultDomain.UNKNOWN else domain,
            finding_codes=sorted({item.code for item in diagnosis.evidence})[:60],
            site_id=diagnosis.incident.site_ids[0] if diagnosis.incident.site_ids else None,
        )

    def runbooks_for(self, sites: list[str], domain: FaultDomain | None) -> list[Runbook]:
        selected = {}
        for site in sites:
            for record in self.repository.list(record_type=RecordType.RUNBOOK, site_id=site):
                if site in record.applicability.site_ids and (domain is None or domain in record.fault_domains):
                    selected[record.record_id] = record
        return [selected[key] for key in sorted(selected)]

    def select_playbook(self, matches: list[KnowledgeMatch]) -> KnowledgeMatch | None:
        playbooks = [m for m in matches if m.record_type == RecordType.PLAYBOOK]
        return next((m for m in playbooks if m.match_type == MatchType.EXACT), playbooks[0] if playbooks else None)

    def checks(self, records: list[AnyRecord], devices: list[str], existing: set[tuple[str | None, str]]) -> list[GuidanceCheck]:
        checks: list[GuidanceCheck] = []
        for record in records:
            for step in getattr(record, "steps", []) + getattr(record, "procedures", []):
                for command in step.commands:
                    if not is_read_only_command(command.text):
                        continue
                    device = next((d for d in devices if self.devices[d].device_type in command.device_types), None)
                    key = (device, command.text)
                    if key in existing:
                        continue
                    existing.add(key)
                    checks.append(GuidanceCheck(source_record_id=record.record_id, step_order=step.order, device_id=device,
                                                command=command.text, platform=command.platform.value, purpose=command.purpose,
                                                parameters=command.parameters))
        return checks[:MAX_CHECKS]

    def assess(self, query: KnowledgeQuery, sites: list[str], devices: list[str], evidence: dict[str, list[str]],
               existing: set[tuple[str | None, str]], confidence: Confidence | None) -> KnowledgeAssessment:
        result = self.retriever.search(query)
        selected = self.select_playbook(result.matches)
        playbook = self.repository.get(selected.record_id) if selected else None
        runbooks = self.runbooks_for(sites, query.fault_domain)
        comparison = []
        for requirement in playbook.required_evidence if isinstance(playbook, Playbook) else []:
            ids = sorted({evidence_id for code in requirement.codes for evidence_id in evidence.get(code, [])},
                         key=lambda value: int(value[1:]) if value[1:].isdigit() else 0)
            comparison.append(EvidenceExpectation(requirement_id=requirement.requirement_id, description=requirement.description,
                                                  tool=requirement.tool.tool, expected_codes=list(requirement.codes),
                                                  observed=bool(ids), evidence_ids=ids))
        missing = [f"{item.description} (collect with {item.tool})" for item in comparison if not item.observed]
        records = ([playbook] if playbook else []) + runbooks
        return KnowledgeAssessment(
            query=query, matches=result.matches, selected_playbook_id=selected.record_id if selected else None,
            selection_reasons=selected.reasons if selected else [], runbook_ids=[r.record_id for r in runbooks],
            evidence_comparison=comparison, missing_evidence=missing, supplementary_checks=self.checks(records, devices, existing),
            diagnosis_confidence=confidence, security_flags=result.security_flags,
        )

    def assess_diagnosis(self, diagnosis: Diagnosis) -> KnowledgeAssessment:
        query = self.query_for_diagnosis(diagnosis)
        devices = list(dict.fromkeys(diagnosis.fault.device_ids + (diagnosis.affected_path.path if diagnosis.affected_path else [])))
        sites = list(dict.fromkeys(diagnosis.incident.site_ids + [self.devices[d].site_id for d in diagnosis.fault.device_ids]))
        evidence: dict[str, list[str]] = {}
        for item in diagnosis.evidence:
            evidence.setdefault(item.code, []).append(item.evidence_id)
        existing = {(check.device_id, check.command) for check in diagnosis.next_checks}
        return self.assess(query, sites, devices, evidence, existing, diagnosis.confidence.level)

    def guidance_for_incident(self, incident: Incident) -> KnowledgeAssessment:
        if incident.status not in ACTIVE_STATUSES:
            raise KnowledgeNotFoundError("Troubleshooting guidance is provided for unresolved incidents only")
        record = incident.active_diagnosis
        if record is not None:
            return self.assess_diagnosis(record.diagnosis)
        query = KnowledgeQuery(text=f"{incident.title}. {incident.description}"[:4000], symptoms=incident.symptoms,
                               site_id=incident.site_ids[0], record_types=GUIDANCE_TYPES)
        devices = sorted({a.asset_id for a in incident.affected_assets if a.asset_id in self.devices})
        return self.assess(query, incident.site_ids, devices, {}, set(), None)

    def link_to_incident(self, incidents: IncidentService, incident_id: str, actor: Actor) -> Incident:
        require_actor(actor, ANYONE, "link knowledge")
        incident = incidents.get_incident(incident_id)
        assessment = self.guidance_for_incident(incident)
        matches = {m.record_id: m for m in assessment.matches}
        chosen = ([assessment.selected_playbook_id] if assessment.selected_playbook_id else []) + assessment.runbook_ids
        if not chosen:
            raise KnowledgeNotFoundError("No relevant knowledge records were found for the incident")
        moment = incidents.now()
        references = []
        for record_id in chosen:
            record = self.repository.get(record_id)
            match = matches.get(record_id)
            references.append(KnowledgeReference(
                record_id=record.record_id, record_type=record.record_type.value, title=record.title, version=record.version,
                match_type=match.match_type.value if match else "site",
                reasons=(match.reasons if match else [f"runbook applies to an affected site"])[:10],
                source_ids=record.source_ids, diagnosis_id=incident.active_diagnosis_id, linked_at=moment, linked_by=actor,
            ))
        return incidents.link_knowledge(incident_id, actor, references)
