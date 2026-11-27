from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.network.repository import load_scenario
from app.security.permissions import Principal
from app.security.tokens import issue_token

API = "/api/v1"
PRINCIPALS = {
    "viewer": Principal(subject="viewer.one", kind="human", roles=["viewer"]),
    "operator": Principal(subject="noc.operator", kind="human", roles=["operator"]),
    "other_operator": Principal(subject="noc.operator2", kind="human", roles=["operator"]),
    "manager": Principal(subject="noc.manager", kind="human", roles=["incident_manager"]),
    "second_manager": Principal(subject="network.lead", kind="human", roles=["incident_manager"]),
    "system": Principal(subject="diagnosis-service", kind="system", roles=["system_service"]),
    "ai": Principal(subject="assistant", kind="ai", roles=["ai_assistant"]),
    "librarian": Principal(subject="kb.owner", kind="human", roles=["knowledge_manager"]),
}
EXPECTED_ROUTES = {
    "/health": {"get"}, f"{API}/auth/verify": {"post"}, f"{API}/auth/login": {"post"}, f"{API}/auth/logout": {"post"},
    f"{API}/dashboard/summary": {"get"}, f"{API}/dashboard/incidents": {"get"}, f"{API}/dashboard/network-health": {"get"},
    f"{API}/topology": {"get"}, f"{API}/topology/sites": {"get"}, f"{API}/topology/sites/{{site_id}}": {"get"},
    f"{API}/topology/devices": {"get"}, f"{API}/topology/devices/{{device_id}}": {"get"},
    f"{API}/topology/devices/{{device_id}}/interfaces": {"get"}, f"{API}/topology/links": {"get"},
    f"{API}/topology/services": {"get"},
    f"{API}/diagnosis": {"post"}, f"{API}/diagnosis/advanced": {"post"}, f"{API}/diagnosis/{{diagnosis_id}}": {"get"},
    f"{API}/diagnosis/{{diagnosis_id}}/evidence": {"get"}, f"{API}/agent/diagnose": {"post"},
    f"{API}/incidents": {"get", "post"}, f"{API}/incidents/{{incident_id}}": {"get", "patch"},
    f"{API}/incidents/{{incident_id}}/timeline": {"get"}, f"{API}/incidents/{{incident_id}}/diagnosis": {"post"},
    f"{API}/incidents/{{incident_id}}/classification": {"post"}, f"{API}/incidents/{{incident_id}}/resolution": {"post"},
    f"{API}/incidents/{{incident_id}}/close": {"post"}, f"{API}/incidents/{{incident_id}}/reopen": {"post"},
    f"{API}/incidents/{{incident_id}}/evidence": {"get"}, f"{API}/incidents/{{incident_id}}/escalations": {"get", "post"},
    f"{API}/incidents/{{incident_id}}/escalations/{{escalation_id}}": {"patch"},
    f"{API}/knowledge/playbooks": {"get"}, f"{API}/knowledge/playbooks/{{playbook_id}}": {"get"},
    f"{API}/knowledge/runbooks": {"get"}, f"{API}/knowledge/procedures": {"get"}, f"{API}/knowledge/search": {"get"},
    f"{API}/reports/summary": {"get"}, f"{API}/reports/incidents": {"get"}, f"{API}/reports/fault-domains": {"get"},
    f"{API}/reports/diagnosis": {"get"},
    f"{API}/conversations": {"get", "post"}, f"{API}/conversations/{{conversation_id}}": {"get", "delete"},
    f"{API}/conversations/{{conversation_id}}/messages": {"post"}, f"{API}/conversations/{{conversation_id}}/events": {"get"},
    f"{API}/conversations/{{conversation_id}}/cancel": {"post"},
    f"{API}/conversations/{{conversation_id}}/context": {"get", "delete"},
    f"{API}/conversations/{{conversation_id}}/investigations/{{investigation_id}}": {"get"},
    f"{API}/conversations/{{conversation_id}}/investigations/{{investigation_id}}/attach": {"post"},
    f"{API}/conversations/{{conversation_id}}/investigations/{{investigation_id}}/reasoning": {"get"},
    f"{API}/diagnosis/multi-agent": {"post"},
    f"{API}/protocols/engines": {"get"},
    f"{API}/protocols/analyze": {"post"},
    f"{API}/observability/sources": {"get"}, f"{API}/observability/ingest/telemetry": {"post"},
    f"{API}/observability/ingest/streaming": {"post"}, f"{API}/observability/ingest/syslog": {"post"},
    f"{API}/observability/ingest/traps": {"post"}, f"{API}/observability/ingest/flows": {"post"},
    f"{API}/observability/live": {"get"}, f"{API}/observability/stream": {"get"}, f"{API}/observability/topology/live": {"get"},
    f"{API}/observability/snmp": {"get"}, f"{API}/observability/traps": {"get"}, f"{API}/observability/syslog": {"get"},
    f"{API}/observability/flows": {"get"}, f"{API}/observability/traffic": {"get"}, f"{API}/observability/baselines": {"get"},
    f"{API}/observability/health": {"get"}, f"{API}/observability/forecast": {"get"}, f"{API}/observability/congestion": {"get"},
    f"{API}/observability/discovery": {"get"}, f"{API}/observability/dependencies": {"get"}, f"{API}/observability/drift": {"get"},
    f"{API}/observability/drift/{{device_id}}/diff": {"get"}, f"{API}/observability/journey": {"get"},
    f"{API}/observability/reliability": {"get"},
}


def route_surface(client: TestClient) -> dict[str, set[str]]:
    return {path: set(methods) for path, methods in client.get("/openapi.json").json()["paths"].items()}


def incident_payload(scenario_id: str = "WAN-FAILURE", **overrides: Any) -> dict:
    incident = load_scenario(scenario_id).incident
    values = {"title": incident.title, "description": incident.description, "site_ids": incident.affected_site_ids,
              "symptoms": incident.symptoms, "source": "service_desk", "dataset_scenario_id": scenario_id}
    return values | overrides


class ApiHarness:
    def __init__(self, root: Path, **settings: Any) -> None:
        self.root = root
        self.tokens_file = root / "auth" / "tokens.json"
        self.tokens = {name: issue_token(self.tokens_file, principal, 24) for name, principal in PRINCIPALS.items()}
        self.tokens["expired"] = issue_token(self.tokens_file, PRINCIPALS["manager"], 1,
                                             now=datetime.now(timezone.utc) - timedelta(hours=3))
        values = {"incident_store_dir": str(root / "incidents"), "auth_tokens_file": str(self.tokens_file),
                  "conversation_store_dir": str(root / "conversations"), "rate_limit_requests": 10_000,
                  "demo_incidents": False} | settings
        self.settings = Settings(_env_file=None, **values)
        self.client = TestClient(create_app(self.settings), raise_server_exceptions=False)

    def headers(self, name: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens[name]}"}

    def get(self, path: str, as_: str = "manager", **kwargs: Any):
        return self.client.get(f"{API}{path}", headers=self.headers(as_), **kwargs)

    def post(self, path: str, body: dict | None = None, as_: str = "manager", **kwargs: Any):
        return self.client.post(f"{API}{path}", json=body or {}, headers=self.headers(as_), **kwargs)

    def patch(self, path: str, body: dict, as_: str = "manager"):
        return self.client.patch(f"{API}{path}", json=body, headers=self.headers(as_))

    def create_incident(self, scenario_id: str = "WAN-FAILURE", as_: str = "operator", **overrides: Any) -> dict:
        response = self.post("/incidents", incident_payload(scenario_id, **overrides), as_=as_)
        assert response.status_code == 201, response.text
        return response.json()["incident"]

    def incident(self, incident_id: str) -> dict:
        return self.get(f"/incidents/{incident_id}").json()

    def acknowledge(self, incident: dict) -> dict:
        response = self.patch(f"/incidents/{incident['incident_id']}", {"expected_version": incident["version"], "status": "acknowledged"},
                              as_="operator")
        assert response.status_code == 200, response.text
        return response.json()

    def diagnosed(self, scenario_id: str = "WAN-FAILURE") -> dict:
        incident = self.acknowledge(self.create_incident(scenario_id))
        response = self.post(f"/incidents/{incident['incident_id']}/diagnosis", {"expected_version": incident["version"]}, as_="system")
        assert response.status_code == 200, response.text
        return response.json()
