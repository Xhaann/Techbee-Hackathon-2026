from datetime import datetime, timedelta, timezone
from typing import Any

from app.engine.schema import FaultDomain
from app.incidents import Actor, Incident, IncidentCreateRequest, IncidentService, LifecycleStatus
from app.network.repository import load_scenario

HUMAN = Actor(kind="human", actor_id="noc.engineer")
SECOND_HUMAN = Actor(kind="human", actor_id="network.lead")
SYSTEM = Actor(kind="system", actor_id="diagnosis-engine")
AI = Actor(kind="ai", actor_id="assistant")


class SteppingClock:
    def __init__(self, start: datetime = datetime(2026, 3, 3, 9, 10, tzinfo=timezone.utc), step: timedelta = timedelta(minutes=1)) -> None:
        self.current = start
        self.step = step

    def __call__(self) -> datetime:
        self.current += self.step
        return self.current


def scenario_request(scenario_id: str, **overrides: Any) -> IncidentCreateRequest:
    incident = load_scenario(scenario_id).incident
    values = {"title": incident.title, "description": incident.description, "site_ids": incident.affected_site_ids,
              "symptoms": incident.symptoms, "source": "service_desk", "dataset_scenario_id": scenario_id}
    return IncidentCreateRequest(**(values | overrides))


def create(service: IncidentService, scenario_id: str = "WAN-FAILURE", **overrides: Any) -> Incident:
    return service.create_incident(scenario_request(scenario_id, **overrides), HUMAN).incident


def diagnosed(service: IncidentService, scenario_id: str = "WAN-FAILURE", **overrides: Any) -> Incident:
    incident = create(service, scenario_id, **overrides)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    return service.run_diagnosis(incident.incident_id, SYSTEM)


def resolved(service: IncidentService, scenario_id: str = "WAN-FAILURE") -> Incident:
    incident = diagnosed(service, scenario_id)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.MONITORING, "Fix applied by carrier")
    service.propose_resolution(incident.incident_id, HUMAN, "Carrier restored the circuit", FaultDomain.WAN_ISP)
    return service.verify_resolution(incident.incident_id, SECOND_HUMAN, True, "Users confirmed service restored")
