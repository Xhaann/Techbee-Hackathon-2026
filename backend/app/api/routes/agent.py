import time
from contextlib import nullcontext

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from app.agent import DiagnosisAgent, build_report
from app.api.dependencies import CurrentPrincipal, ServicesDependency, invalid, not_found
from app.api.records import current, expected
from app.api.schemas import AgentDiagnoseRequest, AgentDiagnoseResponse, AgentExecution, AttachedIncident
from app.core.exceptions import AppError
from app.engine.planner import DiagnosisRequestError
from app.network.repository import scenario_exists
from app.security.permissions import Permission, authorize
from app.security.secrets import redact

router = APIRouter(prefix="/agent", tags=["agent"])


def scenario_for(body: AgentDiagnoseRequest, linked: str | None) -> str:
    if body.scenario_id and linked and body.scenario_id != linked:
        raise invalid(f"scenario_id does not match the incident's dataset scenario '{linked}'")
    scenario_id = body.scenario_id or linked
    if scenario_id is None:
        raise invalid("scenario_id is required unless incident_id names an incident linked to a dataset scenario")
    if not scenario_exists(scenario_id):
        raise not_found(f"Unknown scenario '{scenario_id}'")
    return scenario_id


@router.post("/diagnose", response_model=AgentDiagnoseResponse)
async def diagnose(body: AgentDiagnoseRequest, request: Request, principal: CurrentPrincipal,
                   registry: ServicesDependency) -> AgentDiagnoseResponse:
    authorize(principal, Permission.RUN_DIAGNOSTICS)
    secured = registry.secured_incidents
    incident = None
    if body.incident_id:
        incident = await run_in_threadpool(secured.get_incident, principal, body.incident_id)
        if body.attach_to_incident:
            await run_in_threadpool(current, secured, principal, body.incident_id, body.expected_version)
    scenario_id = scenario_for(body, incident.dataset_scenario_id if incident else None)
    resources = registry.agent
    if body.mode == "agent" and resources.model is None:
        detail = f": {redact(resources.error)}" if resources.error else ""
        raise AppError(f"The AI agent is not configured{detail}", code="AGENT_NOT_CONFIGURED", status_code=503)
    claim = (registry.in_flight.claim(f"diagnosis:{body.incident_id}", f"A diagnosis of {body.incident_id} is already running")
             if body.attach_to_incident else nullcontext())
    with claim:
        if not registry.agent_runs.acquire():
            raise AppError("Too many concurrent agent runs", code="AGENT_BUSY", status_code=503, headers={"retry-after": "5"})
        started = time.monotonic()
        try:
            async with resources.http_client() as client:
                agent = DiagnosisAgent(settings=registry.settings, retriever=registry.knowledge.diagnosis_retriever(),
                                       http_client=client, rule_based=body.mode == "rule_based")
                run = await agent.arun(scenario_id, body.description, body.site_ids, body.device_ids, body.services,
                                       body.incident_id)
        except DiagnosisRequestError as exc:
            raise invalid(redact(str(exc))) from None
        finally:
            registry.agent_runs.release()
        report = await run_in_threadpool(build_report, run)
        attached = None
        if body.attach_to_incident:
            def attach():
                with expected(secured, principal, body.incident_id, body.expected_version):
                    return secured.associate_diagnosis(principal, body.incident_id, run.diagnosis)
            updated = await run_in_threadpool(attach)
            attached = AttachedIncident(incident_id=updated.incident_id, version=updated.version, status=updated.status.value,
                                        active_diagnosis_id=updated.active_diagnosis_id)
    execution = AgentExecution(
        request_id=getattr(request.state, "request_id", None), mode=body.mode, method=report.method.value,
        provider_status="not_used" if body.mode == "rule_based" else "completed" if run.agent_completed else "fallback",
        model=run.model, duration_ms=int((time.monotonic() - started) * 1000),
        tool_calls=len([r for r in run.records if r.status in ("executed", "failed")]), budget_used=run.budget.attempts,
        budget_limit=run.budget.limit, fallback_used=body.mode == "agent" and not run.agent_completed,
    )
    return AgentDiagnoseResponse(report=report, execution=execution, incident=attached)
