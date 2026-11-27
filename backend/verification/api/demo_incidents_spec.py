"""Demo incidents: the ten SCN scenarios are seeded at startup as real incident records, through the incident service, and
are listed, counted, filtered and opened through the existing API. Seeding is idempotent across restarts, never touches
reported incidents, keeps ownership and isolation rules, and exposes no scenario ground truth."""
from pathlib import Path

from app.incidents import IncidentService
from app.incidents.demo import DEMO_ACTOR, demo_incident_id, demo_scenario_ids, seed_demo_incidents, seed_request
from app.incidents.models import Actor, ActorKind
from app.incidents.repository import JsonIncidentRepository
from app.network.repository import load_scenario
from app.protocols.cards import CARD_BY_ID
from verification.api.helpers import ApiHarness, incident_payload

EXPECTED = {demo_incident_id(load_scenario(s).incident.incident_id): s for s in demo_scenario_ids()}


def started(root: Path, **settings) -> ApiHarness:
    api = ApiHarness(root, demo_incidents=True, **settings)
    api.client.__enter__()  # runs the lifespan, which seeds
    return api


def stop(api: ApiHarness) -> None:
    api.client.__exit__(None, None, None)


def listed(api: ApiHarness, as_: str = "manager", **query) -> list[dict]:
    response = api.get("/incidents", as_=as_, params={"limit": 100, **query})
    assert response.status_code == 200, response.text
    return response.json()["items"]


def files(root: Path) -> dict[str, str]:
    return {path.name: path.read_text() for path in sorted((root / "incidents").glob("INC-*.json"))}


def test_ten_scn_scenarios_are_seeded_as_incident_records(tmp_path: Path) -> None:
    assert len(EXPECTED) == 10 and all(s.startswith("SCN-") for s in EXPECTED.values())
    api = started(tmp_path)
    try:
        items = {item["incident_id"]: item for item in listed(api)}
        assert set(items) == set(EXPECTED)
        for incident_id, scenario_id in EXPECTED.items():
            item, reported = items[incident_id], load_scenario(scenario_id).incident
            assert item["demo"] is True and item["dataset_scenario_id"] == scenario_id and item["created_by"] == DEMO_ACTOR.actor_id
            assert item["title"] == reported.title and item["priority"] == reported.priority.value
            assert item["site_ids"] == reported.affected_site_ids and item["created_at"].startswith(reported.reported_at.strftime("%Y-%m-%dT%H:%M"))
            assert item["status"] in ("diagnosed", "investigating") and item["fault_domain"] is not None
            record = api.incident(incident_id)
            assert record["demo"] is True and record["source"] == "service_desk" and record["symptoms"] == reported.symptoms
            assert reported.incident_id in record["timeline"][0]["description"] and "synthetic" in record["timeline"][0]["description"]
            assert len(record["diagnoses"]) == 1 and record["diagnoses"][0]["method"] == "rule_based"
            assert record["classification"]["confirmed_fault_domain"] is None  # an unverified diagnosis, never confirmed truth
    finally:
        stop(api)


def test_counts_filters_and_details_come_from_the_records(tmp_path: Path) -> None:
    api = started(tmp_path)
    try:
        items = listed(api)
        summary = api.get("/dashboard/summary").json()
        assert summary["total"] == 10 and summary["counts"]["origin"] == {"demo": 10}
        assert sum(summary["counts"]["status"].values()) == 10
        for status, count in summary["counts"]["status"].items():
            assert len(listed(api, status=status)) == count
        for domain in {item["fault_domain"] for item in items}:
            assert {i["incident_id"] for i in listed(api, fault_domain=domain)} == {i["incident_id"] for i in items if i["fault_domain"] == domain}
        for site in ("NYC", "SIN", "BLR"):
            assert {i["incident_id"] for i in listed(api, site_id=site)} == {i["incident_id"] for i in items if site in i["site_ids"]}
        for severity in {item["severity"] for item in items}:
            assert len(listed(api, severity=severity)) == sum(i["severity"] == severity for i in items)
        active = api.get("/dashboard/incidents", params={"limit": 100}).json()
        assert active["total"] == sum(i["status"] not in ("resolved", "closed") for i in items)
        reports = api.get("/reports/summary").json()
        assert reports["total"] == 10
    finally:
        stop(api)


def test_restart_adds_nothing_and_keeps_changes(tmp_path: Path) -> None:
    api = started(tmp_path)
    incident_id = sorted(EXPECTED)[0]
    record = api.incident(incident_id)
    changed = api.patch(f"/incidents/{incident_id}", {"expected_version": record["version"], "title": "Renamed by the manager"})
    assert changed.status_code == 200, changed.text
    stop(api)
    before = files(tmp_path)
    assert len(before) == 10
    for _ in range(2):
        again = started(tmp_path)
        try:
            assert files(tmp_path) == before and len(listed(again)) == 10
            assert again.incident(incident_id)["title"] == "Renamed by the manager"
        finally:
            stop(again)


def test_reported_incidents_are_never_touched(tmp_path: Path) -> None:
    plain = ApiHarness(tmp_path)  # seeding off, as for every other suite
    mine = plain.create_incident("WAN-FAILURE", as_="operator")["incident_id"]
    assert listed(plain) and not any(item["demo"] for item in listed(plain))
    original = files(tmp_path)[f"{mine}.json"]
    api = started(tmp_path)
    try:
        assert files(tmp_path)[f"{mine}.json"] == original
        ids = {item["incident_id"] for item in listed(api)}
        assert ids == set(EXPECTED) | {mine} and api.get("/dashboard/summary").json()["counts"]["origin"] == {"demo": 10, "reported": 1}
        new = api.post("/incidents", incident_payload("SCN-01-NYC-WAN-FLAP-STORM", site_ids=["NYC"]), as_="operator")
        assert new.status_code == 201, new.text  # never linked to, or merged into, the demo record
        body = new.json()
        assert body["created"] and not body["possible_duplicates"] and body["incident"]["demo"] is False
        service = api.client.app.state.services.incidents
        assert not {m.incident_id for m in service.find_similar(sorted(EXPECTED)[0], limit=50)} & {mine, body["incident"]["incident_id"]}
        assert not {m.incident_id for m in service.find_similar(mine, limit=50)} & set(EXPECTED)
    finally:
        stop(api)


def test_an_identifier_held_by_another_incident_is_left_alone(tmp_path: Path) -> None:
    service = IncidentService(JsonIncidentRepository(tmp_path))
    incident_id, request, _ = seed_request(EXPECTED[sorted(EXPECTED)[0]])
    human = Actor(kind=ActorKind.HUMAN, actor_id="noc.operator")
    occupant = service.new_incident(request, human, incident_id, service.now(), "Reported by hand")
    service.repository.add(occupant)
    stored = (tmp_path / f"{incident_id}.json").read_text()
    report = seed_demo_incidents(service)
    assert incident_id in report.skipped and len(report.created) == 9
    assert (tmp_path / f"{incident_id}.json").read_text() == stored


def test_an_interrupted_seed_resumes_without_duplicating(tmp_path: Path) -> None:
    service = IncidentService(JsonIncidentRepository(tmp_path))
    incident_id, request, note = seed_request(EXPECTED[sorted(EXPECTED)[0]])
    service.add_demo_incident(request, DEMO_ACTOR, incident_id, note)  # stopped before acknowledging and diagnosing
    report = seed_demo_incidents(service)
    assert report.resumed == [incident_id] and len(report.created) == 9
    assert service.get_incident(incident_id).diagnoses and len(list(tmp_path.glob("INC-*.json"))) == 10
    assert seed_demo_incidents(service).existing == sorted(EXPECTED, key=lambda i: EXPECTED[i])


def test_only_a_system_actor_seeds_and_requests_cannot_claim_demo(tmp_path: Path) -> None:
    service = IncidentService(JsonIncidentRepository(tmp_path / "store"))
    incident_id, request, note = seed_request(EXPECTED[sorted(EXPECTED)[0]])
    for kind in (ActorKind.HUMAN, ActorKind.AI):
        try:
            service.add_demo_incident(request, Actor(kind=kind, actor_id="someone"), incident_id, note)
            raise AssertionError("a non-system actor seeded a demo incident")
        except Exception as exc:  # UnauthorizedActionError
            assert type(exc).__name__ == "UnauthorizedActionError"
    api = ApiHarness(tmp_path / "api")
    response = api.post("/incidents", incident_payload("WAN-FAILURE", demo=True), as_="operator")
    assert response.status_code == 422


def test_isolation_and_ownership_are_unchanged(tmp_path: Path) -> None:
    api = started(tmp_path)
    try:
        incident_id = sorted(EXPECTED)[0]
        version = api.incident(incident_id)["version"]
        # Operators see the incidents they reported or own; a system-created demo record is neither.
        assert listed(api, as_="operator") == [] and api.get("/dashboard/summary", as_="operator").json()["total"] == 0
        assert api.get(f"/incidents/{incident_id}", as_="operator").status_code == 404
        assert api.patch(f"/incidents/{incident_id}", {"expected_version": version, "title": "Taken over by someone"}, as_="operator").status_code == 404
        # Team scope reads them; a viewer still cannot change them.
        for team in ("manager", "viewer", "librarian"):
            assert len(listed(api, as_=team)) == 10
        assert api.patch(f"/incidents/{incident_id}", {"expected_version": version, "title": "Taken over by someone"}, as_="viewer").status_code == 403
        # Assigning a demo incident to an operator is the existing way to share it, and it then shows up for them.
        assigned = api.patch(f"/incidents/{incident_id}", {"expected_version": version, "assigned_owner": "noc.operator"})
        assert assigned.status_code == 200, assigned.text
        assert [item["incident_id"] for item in listed(api, as_="operator")] == [incident_id]
        assert listed(api, as_="other_operator") == []
    finally:
        stop(api)


def test_records_expose_no_scenario_ground_truth(tmp_path: Path) -> None:
    api = started(tmp_path)
    try:
        text = "".join(files(tmp_path).values())
        for scenario_id in EXPECTED.values():
            card = CARD_BY_ID[scenario_id]
            assert card.title not in text, scenario_id
            assert load_scenario(scenario_id).ground_truth.root_cause not in text, scenario_id
        assert '"ground_truth"' not in text and '"truth' not in text
    finally:
        stop(api)
    source = Path("app/incidents/demo.py").read_text()
    assert "cards" not in source and "ground_truth" not in source


def test_seeding_can_be_switched_off(tmp_path: Path) -> None:
    api = ApiHarness(tmp_path, demo_incidents=False)
    with api.client:
        assert listed(api) == [] and files(tmp_path) == {}


def test_the_app_seeds_by_default_but_tests_never_seed_the_real_store(monkeypatch) -> None:
    from app.core.config import Settings
    assert Settings(_env_file=None).demo_incidents is False  # the autouse guard in verification/conftest.py
    monkeypatch.delenv("DEMO_INCIDENTS")
    assert Settings(_env_file=None).demo_incidents is True
