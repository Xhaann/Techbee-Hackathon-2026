from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from typing import Annotated

from fastapi import Path

from app.api.dependencies import Pagination, not_found
from app.api.schemas import EvidencePage, EvidenceView
from app.incidents import IncidentConflictError, IncidentNotFoundError
from app.incidents.models import DiagnosisRecord, Incident, IncidentFilter
from app.security.permissions import Principal, SecuredIncidentService
from app.security.provenance import provenance_issues

IncidentPath = Annotated[str, Path(pattern=r"^INC-\d{8}-\d{4}$")]
DiagnosisPath = Annotated[str, Path(pattern=r"^DGN-\d{8}-\d{4}-\d{2,4}$")]
REPORT_LIMIT = 500


def current(secured: SecuredIncidentService, principal: Principal, incident_id: str, expected_version: int) -> Incident:
    incident = secured.get_incident(principal, incident_id)
    if incident.version != expected_version:
        raise IncidentConflictError(f"Incident {incident_id} is at version {incident.version}, not {expected_version}")
    return incident


@contextmanager
def expected(secured: SecuredIncidentService, principal: Principal, incident_id: str, expected_version: int) -> Iterator[Incident]:
    with getattr(secured.service.repository, "lock", nullcontext()):
        yield current(secured, principal, incident_id, expected_version)


def all_incidents(secured: SecuredIncidentService, principal: Principal) -> list[Incident]:
    summaries = secured.list_incidents(principal, IncidentFilter(limit=REPORT_LIMIT))
    return [secured.get_incident(principal, summary.incident_id) for summary in summaries]


def diagnosis_record(secured: SecuredIncidentService, principal: Principal, diagnosis_id: str) -> DiagnosisRecord:
    try:
        incident = secured.get_incident(principal, f"INC-{diagnosis_id[4:17]}")
    except IncidentNotFoundError:
        raise not_found(f"Unknown diagnosis '{diagnosis_id}'") from None
    record = next((r for r in incident.diagnoses if r.diagnosis_id == diagnosis_id), None)
    if record is None:
        raise not_found(f"Unknown diagnosis '{diagnosis_id}'")
    return record


def evidence_page(records: list[DiagnosisRecord], page: Pagination) -> EvidencePage:
    verified, unverified = [], []
    for record in records:
        if provenance_issues(record.diagnosis):
            unverified.append(record.diagnosis_id)
            continue
        verified += [EvidenceView(diagnosis_id=record.diagnosis_id, evidence=item) for item in record.diagnosis.evidence]
    return EvidencePage(**page.slice(verified), provenance_verified=not unverified, unverified_diagnosis_ids=unverified)
