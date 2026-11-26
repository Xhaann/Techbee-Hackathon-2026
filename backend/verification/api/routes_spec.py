import pytest

from app.engine.safety import is_read_only_command
from app.network.repository import load_scenario, load_topology
from verification.api.helpers import API, EXPECTED_ROUTES, route_surface


def test_route_surface_is_exactly_the_approved_set(api) -> None:
    assert route_surface(api.client) == EXPECTED_ROUTES
    tags = {tag for path in api.client.get("/openapi.json").json()["paths"].values() for op in path.values() for tag in op["tags"]}
    assert tags == {"health", "auth", "dashboard", "topology", "diagnosis", "agent", "conversations", "incidents", "knowledge",
                    "reports"}


def test_health_is_public_and_unchanged(api) -> None:
    response = api.client.get("/health")
    assert response.status_code == 200 and response.json() == {"status": "healthy"}


def test_topology_routes_return_validated_dataset(api) -> None:
    topology = load_topology()
    assert api.get("/topology").json() == topology.model_dump(mode="json")
    sites = api.get("/topology/sites?limit=2").json()
    assert sites["total"] == len(topology.sites) and len(sites["items"]) == 2 and sites["limit"] == 2
    assert api.get("/topology/sites/SIN").json()["data"]["site"]["site_id"] == "SIN"
    devices = api.get("/topology/devices", params={"site_id": "SIN"}).json()["items"]
    assert devices and {d["site_id"] for d in devices} == {"SIN"}
    assert api.get("/topology/devices/SIN-RTR-01").json()["device_id"] == "SIN-RTR-01"
    interfaces = api.get("/topology/devices/SIN-RTR-01/interfaces").json()["items"]
    assert interfaces and {i["device_id"] for i in interfaces} == {"SIN-RTR-01"}
    assert api.get("/topology/links").json()["total"] == len(topology.links)
    assert api.get("/topology/services").json()["total"] == len(topology.paths)


def test_topology_is_scenario_independent(api) -> None:
    assert api.get("/topology?scenario_id=WAN-FAILURE").json() == api.get("/topology").json()


@pytest.mark.parametrize("path", ["/topology/devices/NOPE-RTR-99", "/topology/devices/NOPE-RTR-99/interfaces", "/topology/sites/ZZZ"])
def test_unknown_topology_items_return_not_found(api, path: str) -> None:
    response = api.get(path)
    assert response.status_code == 404 and response.json()["error"]["code"] == "NOT_FOUND"


def test_knowledge_routes(api) -> None:
    playbooks = api.get("/knowledge/playbooks").json()
    assert playbooks["total"] > 0 and all(p["record_type"] == "playbook" for p in playbooks["items"])
    first = playbooks["items"][0]["record_id"]
    assert api.get(f"/knowledge/playbooks/{first}").json()["record_id"] == first
    assert api.get("/knowledge/playbooks/PB-DOES-NOT-EXIST").status_code == 404
    assert all(r["record_type"] == "runbook" for r in api.get("/knowledge/runbooks").json()["items"])
    assert all(r["record_type"] == "procedure" for r in api.get("/knowledge/procedures").json()["items"])
    search = api.get("/knowledge/search", params={"q": "dns resolution failure", "limit": 3}).json()
    assert search["matches"] and len(search["matches"]) <= 3
    assert api.get("/knowledge/search").status_code == 422


def test_dashboard_routes(api) -> None:
    open_incident = api.create_incident()
    summary = api.get("/dashboard/summary").json()
    assert summary["total"] == 1 and summary["counts"]["status"] == {"new": 1}
    assert [i["incident_id"] for i in api.get("/dashboard/incidents").json()["items"]] == [open_incident["incident_id"]]
    health = api.get("/dashboard/network-health", params={"scenario_id": "WAN-FAILURE"}).json()
    assert health["synthetic"] is True and health["scenario_id"] == "WAN-FAILURE"
    assert health["device_count"] == len(load_topology().devices) == sum(health["status_counts"].values())
    baseline = api.get("/dashboard/network-health").json()
    assert baseline["scenario_id"] == "BASELINE" and baseline != health


def test_unknown_scenario_is_rejected(api) -> None:
    assert api.get("/dashboard/network-health", params={"scenario_id": "NOT-A-SCENARIO"}).status_code == 404
    assert api.get("/dashboard/network-health", params={"scenario_id": "../etc/passwd"}).status_code == 422
    assert api.post("/diagnosis", {"scenario_id": "NOT-A-SCENARIO", "description": "x"}).status_code == 404


def test_standalone_diagnosis_runs_existing_engine(api) -> None:
    scenario = load_scenario("DNS-RESOLUTION-FAILURE").incident
    response = api.post("/diagnosis", {"scenario_id": "DNS-RESOLUTION-FAILURE", "description": scenario.description,
                                       "site_ids": scenario.affected_site_ids}, as_="operator")
    body = response.json()
    assert response.status_code == 200 and body["fault"]["fault_domain"] == "dns"
    assert len(body["tool_calls"]) <= 10 and body["next_checks"]
    assert all(c["illustrative"] is True and is_read_only_command(c["command"]) for c in body["next_checks"])
    assert body["method"] == "rule_based"


def test_advanced_diagnosis(api) -> None:
    incident = api.diagnosed()
    response = api.post("/diagnosis/advanced", {"diagnosis": {"scenario_id": "WAN-FAILURE", "description": incident["description"]},
                                                "incident_id": incident["incident_id"]}, as_="operator")
    body = response.json()
    assert response.status_code == 200 and body["incident_id"] == incident["incident_id"]
    assert body["primary_fault"]["fault_domain"] == "wan_isp" and body["validation_issues"] == []
    assert api.incident(incident["incident_id"])["version"] == incident["version"]


def test_incident_diagnosis_lookup_and_evidence(api) -> None:
    incident = api.diagnosed()
    diagnosis_id = incident["active_diagnosis_id"]
    record = api.get(f"/diagnosis/{diagnosis_id}").json()
    assert record["diagnosis_id"] == diagnosis_id and record["human_verified"] is False
    for path in (f"/diagnosis/{diagnosis_id}/evidence", f"/incidents/{incident['incident_id']}/evidence"):
        page = api.get(path).json()
        assert page["provenance_verified"] is True and page["total"] == len(record["diagnosis"]["evidence"]) > 0
        assert {e["evidence"]["call_id"] for e in page["items"]} <= {c["call_id"] for c in record["diagnosis"]["tool_calls"]}
    assert api.get("/diagnosis/DGN-20260101-0001-01").status_code == 404
    assert api.get(f"/diagnosis/{diagnosis_id[:-2]}99").status_code == 404
    assert api.get("/diagnosis/not-an-id").status_code == 422


def test_incident_without_diagnosis_has_empty_evidence(api) -> None:
    incident = api.create_incident()
    page = api.get(f"/incidents/{incident['incident_id']}/evidence").json()
    assert page["items"] == [] and page["provenance_verified"] is True


def test_reports_reflect_only_stored_records(api) -> None:
    for name in ("summary", "incidents", "fault-domains", "diagnosis"):
        empty = api.get(f"/reports/{name}").json()
        assert empty["total"] == 0
    incident = api.diagnosed()
    api.create_incident("DNS-RESOLUTION-FAILURE")
    summary = api.get("/reports/summary").json()
    assert summary["total"] == 2 and summary["counts"]["records"] == {"diagnoses": 1, "escalations": 0, "resolutions": 0}
    rows = {r["incident_id"]: r for r in api.get("/reports/incidents").json()["items"]}
    assert rows[incident["incident_id"]]["diagnoses"] == 1 and rows[incident["incident_id"]]["fault_domain"] == "wan_isp"
    assert api.get("/reports/fault-domains").json()["counts"]["human_confirmed"] == {}
    diagnosis = api.get("/reports/diagnosis").json()
    assert diagnosis["total"] == 1 and diagnosis["counts"]["probable_fault_domain"] == {"wan_isp": 1}


def test_auth_verify_returns_principal_without_secrets(api) -> None:
    body = api.post("/auth/verify", as_="manager").json()
    assert body["subject"] == "noc.manager" and body["roles"] == ["incident_manager"] and "verify_resolutions" in body["permissions"]
    text = api.post("/auth/verify", as_="manager").text
    assert api.tokens["manager"] not in text and "hash" not in text


def test_api_prefix_is_versioned(api) -> None:
    assert api.client.get("/topology", headers=api.headers("manager")).status_code == 404
    assert all(path == "/health" or path.startswith(API) for path in EXPECTED_ROUTES)
