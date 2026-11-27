"""Demo incidents: the ten SCN synthetic scenarios stored as real incident records.

Each record is built from the scenario's reported incident (title, description, symptoms, priority, sites, report time) and
stored through IncidentService, so it is listed, counted, filtered and opened exactly like any other incident. It is marked
``demo`` and created by the ``demo-seed`` system actor, which also acknowledges it and runs the rule-based diagnosis on it,
the same steps an operator takes. The fault domain shown is therefore that unverified diagnosis, never the scenario's answer:
only the reported incident is read here, not the dataset's truth block or the evaluation answer keys.

Seeding is idempotent. A record that already exists is left alone, whoever changed it since, so restarts add nothing and
reported incidents are never touched. Only a run that stopped part-way resumes, and only while the seeder is still the
sole actor on the record.
"""
import logging
from dataclasses import dataclass, field

from app.engine import DiagnosisEngine
from app.incidents.errors import IncidentConflictError, IncidentError, IncidentIntegrityError, IncidentNotFoundError
from app.incidents.models import Actor, ActorKind, Incident, IncidentCreateRequest, IncidentSource, LifecycleStatus
from app.incidents.service import IncidentService
from app.network.repository import list_protocol_scenario_ids, load_scenario

logger = logging.getLogger(__name__)
DEMO_ACTOR = Actor(kind=ActorKind.SYSTEM, actor_id="demo-seed")
DEMO_PREFIX = "SCN-"


def demo_scenario_ids() -> list[str]:
    return [scenario for scenario in list_protocol_scenario_ids() if scenario.startswith(DEMO_PREFIX)]


def demo_incident_id(dataset_incident_id: str) -> str:
    """Dataset references use a three-digit sequence (INC-20260421-401); incident records use four (INC-20260421-0401)."""
    prefix, _, number = dataset_incident_id.rpartition("-")
    if not prefix.startswith("INC-") or not number.isdigit():
        raise ValueError(f"Unexpected dataset incident reference '{dataset_incident_id}'")
    return f"{prefix}-{int(number):04d}"


@dataclass
class SeedReport:
    created: list[str] = field(default_factory=list)
    resumed: list[str] = field(default_factory=list)
    existing: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)

    def describe(self) -> str:
        text = (f"{len(self.created)} created, {len(self.resumed)} resumed, {len(self.existing)} already present, "
                f"{len(self.skipped)} skipped")
        return text + (f" ({'; '.join(f'{key}: {value}' for key, value in self.skipped.items())})" if self.skipped else "")


def seed_request(scenario_id: str) -> tuple[str, IncidentCreateRequest, str]:
    reported = load_scenario(scenario_id).incident
    if reported is None:
        raise ValueError(f"Scenario {scenario_id} has no reported incident")
    request = IncidentCreateRequest(
        title=reported.title, description=reported.description, site_ids=reported.affected_site_ids,
        symptoms=reported.symptoms, priority=reported.priority, source=IncidentSource.SERVICE_DESK,
        dataset_scenario_id=scenario_id, reported_at=reported.reported_at,
    )
    note = (f"Demo incident seeded from synthetic scenario {scenario_id} (dataset reference {reported.incident_id}, "
            f"reported by {reported.reported_by}); telemetry is synthetic")
    return demo_incident_id(reported.incident_id), request, note


def seeded_only(incident: Incident) -> bool:
    return all(event.actor == DEMO_ACTOR for event in incident.timeline)


def finish(service: IncidentService, incident: Incident, engine: DiagnosisEngine) -> Incident:
    """Acknowledge and diagnose, unless someone else has worked the record or it is already diagnosed."""
    if not seeded_only(incident):
        return incident
    if incident.status == LifecycleStatus.NEW:
        incident = service.change_status(incident.incident_id, DEMO_ACTOR, LifecycleStatus.ACKNOWLEDGED,
                                         "Demo incident acknowledged by the seeder")
    if not incident.diagnoses and incident.status == LifecycleStatus.ACKNOWLEDGED:
        incident = service.run_diagnosis(incident.incident_id, DEMO_ACTOR, engine)
    return incident


def complete(incident: Incident) -> bool:
    return bool(incident.diagnoses) or not seeded_only(incident)


def seed_demo_incidents(service: IncidentService, scenario_ids: list[str] | None = None,
                        engine: DiagnosisEngine | None = None) -> SeedReport:
    engine = engine or DiagnosisEngine()  # rule-based: seeding never calls a model
    report = SeedReport()
    for scenario_id in scenario_ids if scenario_ids is not None else demo_scenario_ids():
        try:
            incident_id, request, note = seed_request(scenario_id)
        except (ValueError, IncidentError) as exc:
            report.skipped[scenario_id] = f"dataset unusable: {exc}"
            continue
        try:
            existing = service.get_incident(incident_id)
        except IncidentNotFoundError:
            existing = None
        except IncidentIntegrityError:
            report.skipped[incident_id] = "stored record is unreadable; left untouched"
            continue
        if existing is not None and (not existing.demo or existing.dataset_scenario_id != scenario_id):
            report.skipped[incident_id] = "identifier already holds another incident; left untouched"
            continue
        if existing is not None and complete(existing):
            report.existing.append(incident_id)
            continue
        try:
            created = existing is None
            incident = service.add_demo_incident(request, DEMO_ACTOR, incident_id, note) if created else existing
            finish(service, incident, engine)
            (report.created if created else report.resumed).append(incident_id)
        except IncidentConflictError:
            report.existing.append(incident_id)  # another process seeded or changed it first
        except IncidentError as exc:
            report.skipped[incident_id] = f"{type(exc).__name__}: {exc}"
    return report


def seed_on_startup(service: IncidentService) -> SeedReport | None:
    try:
        report = seed_demo_incidents(service)
    except Exception:  # a demo-data problem must never stop the API from starting
        logger.exception("Demo incident seeding failed")
        return None
    (logger.warning if report.skipped else logger.info)("Demo incidents: %s", report.describe())
    return report
