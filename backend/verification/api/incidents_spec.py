import json
import threading
import time

import pytest

from app.engine.safety import is_read_only_command
from verification.api.helpers import incident_payload


def test_create_list_get_and_timeline(api) -> None:
    incident = api.create_incident()
    assert incident["status"] == "new" and incident["version"] == 1
    assert incident["timeline"][0]["actor"] == {"kind": "human", "actor_id": "noc.operator"}
    listing = api.get("/incidents").json()
    assert listing["total"] == 1 and listing["items"][0]["incident_id"] == incident["incident_id"]
    assert api.get("/incidents", params={"status": "closed"}).json()["total"] == 0
    assert api.get(f"/incidents/{incident['incident_id']}").json()["incident_id"] == incident["incident_id"]
    timeline = api.get(f"/incidents/{incident['incident_id']}/timeline").json()
    assert timeline["total"] == 1 and timeline["items"][0]["event_type"] == "created"


def test_duplicate_detection_is_preserved(api) -> None:
    first = api.create_incident()
    response = api.post("/incidents", incident_payload(), as_="operator")
    again = response.json()
    assert response.status_code == 200 and again["created"] is False and again["incident"]["incident_id"] == first["incident_id"]


def test_actor_is_taken_from_token_not_body(api) -> None:
    payload = incident_payload() | {"actor": {"kind": "human", "actor_id": "ceo"}}
    assert api.post("/incidents", payload, as_="operator").status_code == 422
    incident = api.create_incident(as_="system")
    assert incident["timeline"][0]["actor"] == {"kind": "system", "actor_id": "diagnosis-service"}


def test_patch_details_and_status(api) -> None:
    incident = api.create_incident()
    path = f"/incidents/{incident['incident_id']}"
    updated = api.patch(path, {"expected_version": 1, "title": "Singapore WAN outage", "assigned_team": "WAN Operations"}, as_="operator")
    assert updated.status_code == 200 and updated.json()["title"] == "Singapore WAN outage" and updated.json()["version"] == 2
    acknowledged = api.patch(path, {"expected_version": 2, "status": "acknowledged", "reason": "Triage started"}, as_="operator")
    assert acknowledged.json()["status"] == "acknowledged"


def test_patch_requires_exactly_one_change(api) -> None:
    incident = api.create_incident()
    path = f"/incidents/{incident['incident_id']}"
    for body in ({"expected_version": 1}, {"expected_version": 1, "title": "New title", "severity": "low", "reason": "x"},
                 {"expected_version": 1, "status": "acknowledged", "priority": "p1", "reason": "x"},
                 {"expected_version": 1, "status": None}):
        response = api.patch(path, body)
        assert response.status_code == 422 and response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert api.patch(path, {"expected_version": 1, "unknown": "x"}).status_code == 422
    assert api.patch(path, {"title": "No version"}).status_code == 422


def test_optimistic_version_conflict(api) -> None:
    incident = api.create_incident()
    path = f"/incidents/{incident['incident_id']}"
    assert api.patch(path, {"expected_version": 1, "title": "First writer wins"}, as_="operator").status_code == 200
    stale = api.patch(path, {"expected_version": 1, "title": "Second writer is stale"}, as_="operator")
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "INCIDENT_CONFLICT"
    for action, body in (("close", {"note": "x"}), ("reopen", {"reason": "x"}), ("diagnosis", {}), ("escalations", {}),
                         ("classification", {"fault_domain": "dns", "reason": "x"})):
        assert api.post(f"{path}/{action}", body | {"expected_version": 1}).status_code == 409
    assert api.incident(incident["incident_id"])["title"] == "First writer wins"


def test_full_lifecycle_through_api(api) -> None:
    incident = api.diagnosed()
    iid = incident["incident_id"]
    assert incident["status"] == "diagnosed" and incident["closure"] is None and incident["resolutions"] == []
    classified = api.post(f"/incidents/{iid}/classification", {"expected_version": incident["version"], "fault_domain": "wan_isp",
                                                                "reason": "Carrier confirmed circuit fault"}).json()
    assert classified["classification"]["confirmed_fault_domain"] == "wan_isp"
    monitoring = api.patch(f"/incidents/{iid}", {"expected_version": classified["version"], "status": "monitoring", "reason": "Fix applied"},
                           as_="operator").json()
    proposed = api.post(f"/incidents/{iid}/resolution", {"expected_version": monitoring["version"], "action": "propose",
                                                          "summary": "Carrier restored circuit", "fault_domain": "wan_isp"},
                        as_="ai").json()
    assert proposed["resolutions"][-1]["verification"] == "pending" and proposed["status"] == "monitoring"
    verified = api.post(f"/incidents/{iid}/resolution", {"expected_version": proposed["version"], "action": "verify", "approved": True,
                                                          "note": "Users confirmed"}, as_="second_manager").json()
    assert verified["status"] == "resolved"
    closed = api.post(f"/incidents/{iid}/close", {"expected_version": verified["version"], "note": "Closed after review"}).json()
    assert closed["status"] == "closed"
    reopened = api.post(f"/incidents/{iid}/reopen", {"expected_version": closed["version"], "reason": "Fault recurred"}).json()
    assert reopened["status"] == "investigating"
    events = [e["event_type"] for e in api.get(f"/incidents/{iid}/timeline", params={"limit": 100}).json()["items"]]
    assert events[0] == "created" and len(events) == len(set(e["sequence"] for e in reopened["timeline"]))


def test_diagnosis_never_resolves_or_closes(api) -> None:
    incident = api.diagnosed()
    rerun = api.post(f"/incidents/{incident['incident_id']}/diagnosis", {"expected_version": incident["version"]}, as_="operator").json()
    assert rerun["status"] == "diagnosed" and rerun["closure"] is None and rerun["resolutions"] == []
    assert rerun["diagnoses"][0]["superseded_by"] == rerun["active_diagnosis_id"]


@pytest.mark.parametrize("target", ["resolved", "closed"])
def test_status_patch_cannot_shortcut_lifecycle(api, target: str) -> None:
    incident = api.diagnosed()
    response = api.patch(f"/incidents/{incident['incident_id']}", {"expected_version": incident["version"], "status": target})
    assert response.status_code == 409 and response.json()["error"]["code"] == "INVALID_STATUS_TRANSITION"


def test_lifecycle_rules_still_apply(api) -> None:
    incident = api.create_incident()
    iid = incident["incident_id"]
    assert api.patch(f"/incidents/{iid}", {"expected_version": 1, "status": "diagnosed"}).status_code == 409
    assert api.post(f"/incidents/{iid}/close", {"expected_version": 1, "note": "x"}).status_code == 409
    unverifiable = api.post(f"/incidents/{iid}/resolution", {"expected_version": 1, "action": "verify", "approved": True, "note": "x"})
    assert unverifiable.status_code == 422 and unverifiable.json()["error"]["message"] == "There is no resolution awaiting verification"
    assert api.post(f"/incidents/{iid}/resolution", {"expected_version": 1, "action": "propose"}).status_code == 422
    assert api.post(f"/incidents/{iid}/resolution", {"expected_version": 1, "action": "verify", "summary": "x", "approved": True,
                                                       "note": "x"}).status_code == 422
    assert api.patch(f"/incidents/{iid}", {"expected_version": 1, "severity": "low"}).status_code == 422


def test_escalations_are_marked_not_sent(api) -> None:
    incident = api.diagnosed()
    created = api.post(f"/incidents/{incident['incident_id']}/escalations", {"expected_version": incident["version"]}, as_="operator")
    assert created.status_code == 201
    body = created.json()
    assert body["delivery_status"] == "not_sent" and body["status"] == "recommended"
    assert body["outstanding_checks"] and all(is_read_only_command(c["command"]) for c in body["outstanding_checks"])
    listing = api.get(f"/incidents/{incident['incident_id']}/escalations").json()
    assert listing["total"] == 1 and listing["items"][0]["delivery_status"] == "not_sent"


def test_unknown_incident_and_malformed_ids(api) -> None:
    assert api.get("/incidents/INC-20990101-0001").status_code == 404
    assert api.get("/incidents/INC-20990101-0001").json()["error"]["code"] == "INCIDENT_NOT_FOUND"
    assert api.get("/incidents/..%2F..%2Fetc").status_code in (404, 422)
    assert api.get("/incidents/not-an-incident").status_code == 422


def test_secrets_are_redacted_through_api(api) -> None:
    incident = api.create_incident(description="Router enable password: Sup3rS3cret! and key sk-proj-ABCDEFGHIJKLMNOP1234")
    text = json.dumps(api.incident(incident["incident_id"]))
    assert "Sup3rS3cret" not in text and "ABCDEFGHIJKLMNOP" not in text and "[redacted]" in text
    path = f"/incidents/{incident['incident_id']}"
    updated = api.patch(path, {"expected_version": 1, "description": "Rotated token=abcd1234efgh5678"}, as_="operator").json()
    assert "abcd1234efgh5678" not in updated["description"]
    stored = "".join(p.read_text(encoding="utf-8") for p in (api.root / "incidents").glob("*.json"))
    assert "Sup3rS3cret" not in stored and "abcd1234efgh5678" not in stored


def test_list_filters_are_validated(api) -> None:
    assert api.get("/incidents", params={"status": "bogus"}).status_code == 422
    assert api.get("/incidents", params={"severity": "urgent"}).status_code == 422
    assert api.get("/incidents", params={"start": "not-a-date"}).status_code == 422
    assert api.get("/incidents", params={"site_id": "x" * 100}).status_code == 422


def test_concurrent_writers_with_the_same_version_cannot_both_succeed(api, monkeypatch: pytest.MonkeyPatch) -> None:
    incident = api.create_incident()
    path = f"/incidents/{incident['incident_id']}"
    service = api.client.app.state.services.incidents
    original = service.update_details

    def slow_update(*args, **kwargs):
        time.sleep(0.2)
        return original(*args, **kwargs)
    monkeypatch.setattr(service, "update_details", slow_update)
    results: list[int] = []

    def write(title: str) -> None:
        results.append(api.patch(path, {"expected_version": 1, "title": title}, as_="operator").status_code)
    threads = [threading.Thread(target=write, args=(f"Concurrent title {n}",)) for n in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [200, 409]
    assert api.incident(incident["incident_id"])["version"] == 2


def test_diagnosis_is_not_attached_when_the_incident_changed_during_the_run(api, monkeypatch: pytest.MonkeyPatch) -> None:
    incident = api.acknowledge(api.create_incident())
    iid, version = incident["incident_id"], incident["version"]
    registry = api.client.app.state.services
    build_engine = registry.diagnosis_engine

    def engine_with_concurrent_edit():
        engine = build_engine()
        diagnose = engine.diagnose

        def run(request):
            diagnosis = diagnose(request)
            assert api.patch(f"/incidents/{iid}", {"expected_version": version, "title": "Edited during diagnosis"},
                             as_="operator").status_code == 200
            return diagnosis
        engine.diagnose = run
        return engine
    monkeypatch.setattr(registry, "diagnosis_engine", engine_with_concurrent_edit)
    response = api.post(f"/incidents/{iid}/diagnosis", {"expected_version": version}, as_="operator")
    assert response.status_code == 409 and response.json()["error"]["code"] == "INCIDENT_CONFLICT"
    stored = api.incident(iid)
    assert stored["version"] == version + 1 and stored["title"] == "Edited during diagnosis" and stored["diagnoses"] == []
