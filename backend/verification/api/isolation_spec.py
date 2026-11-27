"""Users cannot reach each other's incidents or conversations; team scope is an explicit role permission."""
from verification.api.helpers import API, ApiHarness, incident_payload


def own_incident(api: ApiHarness) -> dict:
    return api.create_incident("WAN-FAILURE", as_="operator")


def test_an_operator_cannot_read_or_change_another_operators_incident(api: ApiHarness) -> None:
    incident = own_incident(api)
    incident_id, version = incident["incident_id"], incident["version"]
    assert api.get(f"/incidents/{incident_id}", as_="operator").status_code == 200
    reads = [f"/incidents/{incident_id}", f"/incidents/{incident_id}/timeline", f"/incidents/{incident_id}/evidence",
             f"/incidents/{incident_id}/escalations"]
    for path in reads:
        response = api.get(path, as_="other_operator")
        assert response.status_code == 404 and response.json()["error"]["code"] == "INCIDENT_NOT_FOUND", path
    writes = [
        ("patch", f"/incidents/{incident_id}", {"expected_version": version, "title": "Taken over"}),
        ("post", f"/incidents/{incident_id}/diagnosis", {"expected_version": version}),
        ("post", f"/incidents/{incident_id}/escalations", {"expected_version": version, "reason": "x"}),
        ("post", f"/incidents/{incident_id}/resolution",
         {"expected_version": version, "action": "propose", "summary": "x", "fault_domain": "wan_isp"}),
    ]
    for method, path, body in writes:
        response = getattr(api, method)(path, body, as_="other_operator")
        assert response.status_code == 404, (path, response.text)
    assert api.incident(incident_id)["version"] == version


def test_lists_dashboards_and_reports_exclude_other_users_incidents(api: ApiHarness) -> None:
    mine = own_incident(api)["incident_id"]
    theirs = api.create_incident("DNS-RESOLUTION-FAILURE", as_="other_operator")["incident_id"]
    for name, own, other in (("operator", mine, theirs), ("other_operator", theirs, mine)):
        listed = {item["incident_id"] for item in api.get("/incidents", as_=name).json()["items"]}
        assert own in listed and other not in listed
        assert api.get("/dashboard/summary", as_=name).json()["total"] == 1
        assert {row["incident_id"] for row in api.get("/reports/incidents", as_=name).json()["items"]} == {own}
    for team in ("manager", "viewer", "librarian"):
        listed = {item["incident_id"] for item in api.get("/incidents", as_=team).json()["items"]}
        assert {mine, theirs} <= listed, team


def test_summaries_name_the_reporter(api: ApiHarness) -> None:
    incident_id = own_incident(api)["incident_id"]
    summary = next(i for i in api.get("/incidents").json()["items"] if i["incident_id"] == incident_id)
    assert summary["created_by"] == "noc.operator" and summary["assigned_owner"] is None


def test_diagnosis_records_follow_incident_visibility(api: ApiHarness) -> None:
    incident = api.acknowledge(own_incident(api))
    diagnosed = api.post(f"/incidents/{incident['incident_id']}/diagnosis", {"expected_version": incident["version"]}, as_="operator")
    assert diagnosed.status_code == 200, diagnosed.text
    diagnosis_id = diagnosed.json()["active_diagnosis_id"]
    assert api.get(f"/diagnosis/{diagnosis_id}", as_="operator").status_code == 200
    assert api.get(f"/diagnosis/{diagnosis_id}", as_="other_operator").status_code == 404
    assert api.get(f"/diagnosis/{diagnosis_id}/evidence", as_="other_operator").status_code == 404


def test_duplicate_detection_never_returns_another_users_incident(api: ApiHarness) -> None:
    first = own_incident(api)
    repeat = api.post("/incidents", incident_payload("WAN-FAILURE"), as_="other_operator")
    assert repeat.status_code == 201, repeat.text
    body = repeat.json()
    assert body["created"] is True and body["incident"]["incident_id"] != first["incident_id"]
    assert all(match["incident_id"] != first["incident_id"] for match in body["possible_duplicates"])
    same_user = api.post("/incidents", incident_payload("WAN-FAILURE"), as_="operator")
    assert same_user.status_code == 200 and same_user.json()["incident"]["incident_id"] == first["incident_id"]


def test_assignment_grants_access_to_the_new_owner(api: ApiHarness) -> None:
    incident = own_incident(api)
    assigned = api.patch(f"/incidents/{incident['incident_id']}", {"expected_version": incident["version"],
                                                                   "assigned_owner": "noc.operator2"})
    assert assigned.status_code == 200, assigned.text
    assert api.get(f"/incidents/{incident['incident_id']}", as_="other_operator").status_code == 200


def test_viewers_read_team_incidents_but_cannot_change_them(api: ApiHarness) -> None:
    incident = own_incident(api)
    assert api.get(f"/incidents/{incident['incident_id']}", as_="viewer").status_code == 200
    response = api.patch(f"/incidents/{incident['incident_id']}", {"expected_version": incident["version"], "title": "x" * 5},
                         as_="viewer")
    assert response.status_code == 403


def test_incident_linked_work_respects_visibility(api: ApiHarness) -> None:
    incident = own_incident(api)
    incident_id = incident["incident_id"]
    conversation = api.post("/conversations", {"incident_id": incident_id}, as_="other_operator")
    assert conversation.status_code == 404
    agent = api.post("/agent/diagnose", {"description": "Singapore users cannot reach ERP.", "incident_id": incident_id,
                                         "mode": "rule_based"}, as_="other_operator")
    assert agent.status_code == 404
    advanced = api.post("/diagnosis/advanced", {"diagnosis": {"scenario_id": "WAN-FAILURE", "description": "x" * 10,
                                                              "site_ids": ["SIN"]}, "incident_id": incident_id},
                        as_="other_operator")
    assert advanced.status_code == 404


def test_conversations_are_private_to_their_owner(api: ApiHarness) -> None:
    created = api.post("/conversations", {"scenario_id": "WAN-FAILURE", "mode": "rule_based"}, as_="operator")
    assert created.status_code == 201
    cid = created.json()["conversation_id"]
    assert api.post(f"/conversations/{cid}/messages", {"content": "hi"}, as_="operator").status_code == 200
    probes = [("get", f"/conversations/{cid}", None), ("get", f"/conversations/{cid}/context", None),
              ("get", f"/conversations/{cid}/events", None), ("post", f"/conversations/{cid}/messages", {"content": "hi"}),
              ("post", f"/conversations/{cid}/cancel", None), ("get", f"/conversations/{cid}/investigations/INV-000000000000", None)]
    for method, path, body in probes:
        response = api.get(path, as_="other_operator") if method == "get" else api.post(path, body, as_="other_operator")
        assert response.status_code == 404, path
    assert api.client.delete(f"{API}/conversations/{cid}", headers=api.headers("other_operator")).status_code == 404
    assert api.get("/conversations", as_="other_operator").json()["total"] == 0
    assert api.get(f"/conversations/{cid}", as_="manager").status_code == 404
    assert api.get(f"/conversations/{cid}", as_="operator").status_code == 200
