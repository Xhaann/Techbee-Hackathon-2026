"""Phase 2 API surface: the multi-agent diagnosis endpoint and investigation reasoning, with permissions and isolation."""
from verification.phase2.conversation_spec import start, say

BODY = {"scenario_id": "ADV-SIN-RADIUS-UDP-BLOCK", "site_ids": ["SIN"], "services": ["authentication"],
        "description": "Singapore desktops fail 802.1X authentication"}


def test_multi_agent_endpoint_requires_run_diagnostics(api) -> None:
    assert api.post("/diagnosis/multi-agent", BODY, as_="viewer").status_code == 403
    assert api.client.post("/api/v1/diagnosis/multi-agent", json=BODY).status_code == 401
    response = api.post("/diagnosis/multi-agent", BODY, as_="operator")
    assert response.status_code == 200
    body = response.json()
    assert body["tool_calls"] <= 10 and body["reasoning"]["leading"] == "firewall" and body["human_verification_required"] is True
    assert body["plan"][0]["agent"] == "security" and all(p["executed"] for p in body["plan"][: body["tool_calls"]])


def test_multi_agent_endpoint_validates_input(api) -> None:
    assert api.post("/diagnosis/multi-agent", BODY | {"scenario_id": "NOPE"}, as_="operator").status_code == 404
    assert api.post("/diagnosis/multi-agent", BODY | {"site_ids": []}, as_="operator").status_code == 422
    assert api.post("/diagnosis/multi-agent", BODY | {"services": ["ssh"]}, as_="operator").status_code == 422
    assert api.post("/diagnosis/multi-agent", BODY | {"extra": 1}, as_="operator").status_code == 422


def test_reasoning_endpoint_is_owner_scoped(api) -> None:
    cid = start(api)
    diagnosis = say(api, cid, "diagnose it")
    path = f"/conversations/{cid}/investigations/{diagnosis['investigation_id']}/reasoning"
    report = api.get(path, as_="operator")
    assert report.status_code == 200 and report.json()["leading"] == "wan_isp" and report.json()["method"] == "deterministic_reasoning"
    assert api.get(path, as_="other_operator").status_code == 404 and api.get(path, as_="manager").status_code == 404
    check = say(api, cid, "check SIN-RTR-01 routing")
    assert api.get(f"/conversations/{cid}/investigations/{check['investigation_id']}/reasoning", as_="operator").status_code == 404
