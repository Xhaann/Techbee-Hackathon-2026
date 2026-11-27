"""The /protocols API and the integration points: permissions, incident visibility, validation, the tool in the agent
registry, protocol scenarios accepted by incidents, diagnosis and the multi-agent route, and specialist planning."""
import pytest

from app.engine.executor import ToolExecutor
from app.engine.registry import REGISTRY
from app.network.repository import list_scenario_ids, load_scenario
from app.reasoning.specialists import AGENTS, Scope, coordinate, protocol_engines
from verification.api.helpers import ApiHarness, incident_payload


@pytest.fixture
def api(tmp_path) -> ApiHarness:
    return ApiHarness(tmp_path)


def test_catalog_lists_17_engines_and_20_synthetic_scenarios(api) -> None:
    body = api.get("/protocols/engines", as_="viewer").json()
    assert body["synthetic"] is True and len(body["engines"]) == 17 and len(body["scenarios"]) == 30
    assert {s["kind"] for s in body["scenarios"]} == {"normal", "failure", "edge", "adversarial"}
    assert api.client.get("/api/v1/protocols/engines").status_code == 401


def test_running_checks_needs_run_diagnostics(api) -> None:
    body = {"scenario_id": "P3-STP-LOOP-NYC", "engines": ["stp"]}
    assert api.post("/protocols/analyze", body, as_="viewer").status_code == 403
    assert api.client.post("/api/v1/protocols/analyze", json=body).status_code == 401
    report = api.post("/protocols/analyze", body, as_="operator").json()
    assert report["synthetic"] is True and report["findings"][0]["code"] == "STP_LOOP" and report["validation"]["grounded"]


def test_validation(api) -> None:
    assert api.post("/protocols/analyze", {"engines": ["stp"]}, as_="operator").status_code == 422
    assert api.post("/protocols/analyze", {"scenario_id": "BASELINE", "incident_id": "INC-20260101-0001"}, as_="operator").status_code == 422
    assert api.post("/protocols/analyze", {"scenario_id": "BASELINE", "engines": ["nope"]}, as_="operator").status_code == 422
    assert api.post("/protocols/analyze", {"scenario_id": "BASELINE", "extra": 1}, as_="operator").status_code == 422
    assert api.post("/protocols/analyze", {"scenario_id": "NOPE"}, as_="operator").status_code == 404
    assert api.post("/protocols/analyze", {"scenario_id": "BASELINE", "site_id": "XYZ"}, as_="operator").status_code == 404
    assert api.post("/protocols/analyze", {"scenario_id": "BASELINE", "device_id": "NOT-A-DEVICE-01"}, as_="operator").status_code == 404
    assert api.post("/protocols/analyze", {"scenario_id": "BASELINE", "symptoms": "x" * 1001}, as_="operator").status_code == 422


def test_incident_scope_respects_visibility(api) -> None:
    created = api.post("/incidents", incident_payload("P3-NAT-EXHAUSTION"), as_="operator").json()["incident"]
    body = {"incident_id": created["incident_id"], "engines": ["nat", "tcp"]}
    report = api.post("/protocols/analyze", body, as_="operator").json()
    assert report["scenario_id"] == "P3-NAT-EXHAUSTION" and "NAT pool" in report["headline"]
    assert api.post("/protocols/analyze", body, as_="other_operator").status_code == 404


def test_all_engines_by_default(api) -> None:
    report = api.post("/protocols/analyze", {"scenario_id": "BASELINE"}, as_="operator").json()
    assert len(report["engines"]) == 17 and report["findings"] == [] and "No protocol or security problem" in report["headline"]


def test_protocol_scenarios_work_with_incidents_diagnosis_and_the_team(api) -> None:
    assert api.post("/incidents", incident_payload("P3-STP-LOOP-NYC"), as_="operator").status_code == 201
    body = {"scenario_id": "P3-QOS-REMARK-NYC", "site_ids": ["NYC"], "description": "NYC calls are choppy and robotic"}
    team = api.post("/diagnosis/multi-agent", body, as_="operator").json()
    assert any(c["tool"] == "analyze_protocol" and c["executed"] for c in team["plan"])
    assert team["reasoning"]["leading"] == "interface_link" and team["tool_calls"] <= 10


def test_tool_is_registered_read_only_and_validated() -> None:
    assert "analyze_protocol" in REGISTRY
    executor = ToolExecutor("P3-STP-LOOP-NYC")
    good = executor.execute("analyze_protocol", {"protocol": "stp", "site_id": "NYC"})
    bad = executor.execute("analyze_protocol", {"protocol": "rm -rf"})
    unknown = executor.execute("analyze_protocol", {"protocol": "stp", "site_id": "MARS"})
    assert good.status == "executed" and good.succeeded and bad.status == "rejected"
    assert not unknown.succeeded and unknown.result.error.code == "NOT_FOUND"
    everything = ToolExecutor("P3-SEC-LATERAL-MOVEMENT-NYC").execute("analyze_protocol", {"protocol": "all"})
    assert everything.result.data["status"] == "suspicious" and len(everything.result.data["findings"]) <= 6


def test_core_specialist_plans_are_unchanged() -> None:
    for scenario in list_scenario_ids():
        dataset = load_scenario(scenario)
        if dataset.incident is None:
            continue
        text = " ".join([dataset.incident.title, dataset.incident.description, *dataset.incident.symptoms])
        plan = coordinate(Scope(scenario, tuple(dataset.incident.affected_site_ids), (), (), (), text))
        assert not any(c.tool == "analyze_protocol" for c in plan), scenario


def test_protocol_checks_only_for_clear_protocol_symptoms() -> None:
    assert protocol_engines(Scope("x", ("NYC",), text="calls are choppy and robotic")) == ["qos"]
    assert protocol_engines(Scope("x", ("NYC",), text="users cannot reach ERP")) == []
    plan = coordinate(Scope("P3-VLAN-TRUNK-PRUNE-BLR", ("BLR",), text="IP phones have no network after this morning's trunk change"))
    protocol = [c for c in plan if c.tool == "analyze_protocol"]
    assert protocol and all(c.agent == "switching" for c in protocol) and len(protocol) <= 3 and len(plan) <= 10
    assert set(AGENTS) == {"transport", "routing", "security", "dns_dhcp", "switching"}


@pytest.mark.parametrize("scenario", ["P3-STP-LOOP-NYC", "P3-BGP-ROUTE-LEAK", "P3-EDGE-PARTIAL-TELEMETRY"])
def test_phase_1_observability_works_on_protocol_scenarios(api, scenario: str) -> None:
    for endpoint in ("live", "topology/live", "syslog", "flows", "traffic", "health", "congestion", "dependencies", "drift", "reliability"):
        assert api.get(f"/observability/{endpoint}?scenario_id={scenario}", as_="operator").status_code == 200, endpoint
    journey = api.get(f"/observability/journey?scenario_id={scenario}&source=SIN-SW-01&destination=10.100.100.40", as_="operator")
    assert journey.status_code == 200
