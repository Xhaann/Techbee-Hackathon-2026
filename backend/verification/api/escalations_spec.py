import threading
import time
from pathlib import Path

import pytest

from app.incidents import JsonIncidentRepository
from verification.api.helpers import API


def escalated(api) -> tuple[dict, str]:
    incident = api.diagnosed()
    created = api.post(f"/incidents/{incident['incident_id']}/escalations", {"expected_version": incident["version"]}, as_="operator")
    assert created.status_code == 201, created.text
    return api.incident(incident["incident_id"]), created.json()["escalation_id"]


def update(api, incident: dict, escalation_id: str, as_: str = "manager", **body):
    values = {"expected_version": incident["version"], "status": "assigned", "note": "Carrier ticket opened",
              "assigned_team": "Carrier B NOC"} | body
    return api.patch_as(f"/incidents/{incident['incident_id']}/escalations/{escalation_id}", values, as_)


@pytest.fixture
def api(api):
    def patch_as(path: str, body: dict, as_: str):
        return api.client.patch(f"{API}{path}", json=body, headers=api.headers(as_))
    api.patch_as = patch_as
    return api


def test_escalated_incident_completes_its_closure_workflow(api) -> None:
    incident, escalation_id = escalated(api)
    iid = incident["incident_id"]
    listed = api.get(f"/incidents/{iid}/escalations").json()["items"]
    assert [(e["escalation_id"], e["status"]) for e in listed] == [(escalation_id, "recommended")]

    assigned = update(api, incident, escalation_id)
    assert assigned.status_code == 200, assigned.text
    body = assigned.json()
    assert body["status"] == "assigned" and body["assigned_team"] == "Carrier B NOC" and body["delivery_status"] == "not_sent"
    assert body["status_notes"] == ["Carrier ticket opened"] and assigned.headers["x-request-id"]
    incident = api.incident(iid)
    assert incident["status"] == "escalated" and incident["escalations"][0]["status"] == "assigned"

    for target, reason in (("investigating", "Carrier engaged"), ("monitoring", "Circuit restored by carrier")):
        incident = api.patch(f"/incidents/{iid}", {"expected_version": incident["version"], "status": target, "reason": reason}).json()
    incident = api.post(f"/incidents/{iid}/resolution", {"expected_version": incident["version"], "action": "propose",
                                                         "summary": "Carrier restored circuit", "fault_domain": "wan_isp"}).json()
    incident = api.post(f"/incidents/{iid}/resolution", {"expected_version": incident["version"], "action": "verify",
                                                         "approved": True, "note": "Verified"}, as_="second_manager").json()
    assert incident["status"] == "resolved"

    blocked = api.post(f"/incidents/{iid}/close", {"expected_version": incident["version"], "note": "Done"})
    assert blocked.status_code == 409 and escalation_id in blocked.json()["error"]["message"]
    assert api.incident(iid)["version"] == incident["version"]

    closed_escalation = update(api, incident, escalation_id, status="closed", note="Carrier confirmed fix", assigned_team=None)
    assert closed_escalation.status_code == 200 and closed_escalation.json()["assigned_team"] == "Carrier B NOC"
    incident = api.incident(iid)
    closed = api.post(f"/incidents/{iid}/close", {"expected_version": incident["version"], "note": "Done"})
    assert closed.status_code == 200, closed.text
    final = closed.json()
    assert final["status"] == "closed" and final["escalations"][0]["status"] == "closed"
    assert final["escalations"][0]["status_notes"] == ["Carrier ticket opened", "Carrier confirmed fix"]

    events = final["timeline"]
    assert [e["sequence"] for e in events] == list(range(1, len(events) + 1))
    updates = [e for e in events if e["event_type"] == "escalation_updated"]
    assert [e["actor"]["actor_id"] for e in updates] == ["noc.manager", "noc.manager"]
    assert "recommended -> assigned" in updates[0]["description"] and "assigned -> closed" in updates[1]["description"]
    stored = JsonIncidentRepository(Path(api.settings.incident_store_dir)).get(iid)
    assert stored.model_dump(mode="json") == final


def test_cancelling_an_escalation_also_unblocks_closure_rules(api) -> None:
    incident, escalation_id = escalated(api)
    response = update(api, incident, escalation_id, status="cancelled", note="Raised in error", assigned_team=None)
    assert response.status_code == 200 and response.json()["status"] == "cancelled"
    again = update(api, api.incident(incident["incident_id"]), escalation_id, status="assigned")
    assert again.status_code == 409 and again.json()["error"]["code"] == "INVALID_STATUS_TRANSITION"


@pytest.mark.parametrize("body, code", [
    ({"status": "recommended"}, "INVALID_STATUS_TRANSITION"),
    ({"status": "assigned", "assigned_team": None}, "INCIDENT_VALIDATION_ERROR"),
])
def test_invalid_transitions_are_rejected_without_changes(api, body: dict, code: str) -> None:
    incident, escalation_id = escalated(api)
    response = update(api, incident, escalation_id, **body)
    assert response.json()["error"]["code"] == code and response.status_code in (409, 422)
    assert api.incident(incident["incident_id"]) == incident


@pytest.mark.parametrize("body", [{"status": "resolved"}, {"note": ""}, {"assigned_team": "x" * 121}, {"delivery": "sent"},
                                  {"expected_version": 0}])
def test_malformed_requests_are_rejected(api, body: dict) -> None:
    incident, escalation_id = escalated(api)
    response = update(api, incident, escalation_id, **body)
    assert response.status_code == 422 and response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert api.incident(incident["incident_id"]) == incident


def test_identifiers_are_validated(api) -> None:
    incident, escalation_id = escalated(api)
    iid = incident["incident_id"]
    unknown_escalation = update(api, incident, f"{escalation_id[:-2]}09")
    assert unknown_escalation.status_code == 404 and unknown_escalation.json()["error"]["code"] == "NOT_FOUND"
    assert update(api, incident, "ESC-../../etc").status_code in (404, 422)
    assert update(api, incident, "DGN-20260101-0001-01").status_code == 422
    missing = update(api, incident | {"incident_id": "INC-20000101-0001"}, escalation_id)
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "INCIDENT_NOT_FOUND"
    assert update(api, incident | {"incident_id": "INC-1"}, escalation_id).status_code == 422
    assert api.incident(iid) == incident


@pytest.mark.parametrize("role", ["viewer", "operator", "system", "ai", "librarian"])
def test_only_human_escalation_managers_may_update(api, role: str) -> None:
    incident, escalation_id = escalated(api)
    response = update(api, incident, escalation_id, as_=role)
    assert response.status_code == 403 and response.json()["error"]["code"] == "PERMISSION_DENIED"
    assert api.incident(incident["incident_id"]) == incident


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer " + "x" * 40}, {"Authorization": "Basic abc"}, "expired"])
def test_authentication_is_required(api, headers) -> None:
    incident, escalation_id = escalated(api)
    headers = api.headers("expired") if headers == "expired" else headers
    response = api.client.patch(f"{API}/incidents/{incident['incident_id']}/escalations/{escalation_id}",
                                json={"expected_version": incident["version"], "status": "cancelled", "note": "x"}, headers=headers)
    assert response.status_code == 401 and response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert api.incident(incident["incident_id"]) == incident


def test_stale_expected_version_is_a_conflict(api) -> None:
    incident, escalation_id = escalated(api)
    stale = update(api, incident | {"version": incident["version"] - 1}, escalation_id)
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "INCIDENT_CONFLICT"
    assert api.incident(incident["incident_id"]) == incident


def test_concurrent_updates_with_the_same_version_cannot_both_succeed(api, monkeypatch: pytest.MonkeyPatch) -> None:
    incident, escalation_id = escalated(api)
    service = api.client.app.state.services.incidents
    original = service.update_escalation

    def slow_update(*args, **kwargs):
        time.sleep(0.2)
        return original(*args, **kwargs)
    monkeypatch.setattr(service, "update_escalation", slow_update)
    results: list[int] = []

    def write(status: str) -> None:
        results.append(update(api, incident, escalation_id, status=status, note=f"Set {status}").status_code)
    threads = [threading.Thread(target=write, args=(status,)) for status in ("assigned", "cancelled")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [200, 409]
    stored = api.incident(incident["incident_id"])
    assert stored["version"] == incident["version"] + 1
    assert [e["event_type"] for e in stored["timeline"]].count("escalation_updated") == 1
