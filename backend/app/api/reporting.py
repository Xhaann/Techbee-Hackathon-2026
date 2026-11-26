from collections import Counter
from typing import Iterable

from app.api.schemas import CountSummary, IncidentReportRow
from app.incidents.models import Incident, IncidentSummary


def tally(values: Iterable[object]) -> dict[str, int]:
    counts = Counter("unclassified" if value is None else getattr(value, "value", str(value)) for value in values)
    return dict(sorted(counts.items()))


def incident_counts(summaries: list[IncidentSummary]) -> CountSummary:
    return CountSummary(total=len(summaries), counts={
        "status": tally(s.status for s in summaries), "severity": tally(s.severity for s in summaries),
        "priority": tally(s.priority for s in summaries), "fault_domain": tally(s.fault_domain for s in summaries),
    })


def report_row(incident: Incident) -> IncidentReportRow:
    resolution = incident.current_resolution
    domain = incident.fault_domain
    confirmed = incident.classification.confirmed_fault_domain
    return IncidentReportRow(
        incident_id=incident.incident_id, title=incident.title, status=incident.status.value, severity=incident.severity.value,
        priority=incident.priority.value, fault_domain=domain.value if domain else None,
        confirmed_fault_domain=confirmed.value if confirmed else None, diagnoses=len(incident.diagnoses),
        escalations=len(incident.escalations), resolution_verification=resolution.verification.value if resolution else None,
        created_at=incident.created_at, closed_at=incident.closure.closed_at if incident.closure else None,
    )


def fault_domain_report(incidents: list[Incident]) -> CountSummary:
    rows = [report_row(incident) for incident in incidents]
    return CountSummary(total=len(rows), counts={
        "current": tally(r.fault_domain for r in rows), "human_confirmed": tally(r.confirmed_fault_domain for r in rows if r.confirmed_fault_domain),
        "probable_from_diagnosis": tally(i.classification.probable_fault_domain for i in incidents if i.classification.probable_fault_domain),
    })


def diagnosis_report(incidents: list[Incident]) -> CountSummary:
    records = [record for incident in incidents for record in incident.diagnoses]
    active = [record for record in records if record.superseded_by is None]
    confirmed = [(i.classification.confirmed_fault_domain, i.active_diagnosis) for i in incidents
                 if i.classification.confirmed_fault_domain and i.active_diagnosis]
    return CountSummary(total=len(records), counts={
        "method": tally(r.method for r in records), "status": tally(r.status for r in records),
        "confidence": tally(r.confidence for r in records), "probable_fault_domain": tally(r.probable_fault_domain for r in active),
        "superseded": {"superseded": len(records) - len(active), "current": len(active)},
        "human_confirmation": tally("matches_diagnosis" if domain == record.probable_fault_domain else "differs_from_diagnosis"
                                    for domain, record in confirmed),
    })
