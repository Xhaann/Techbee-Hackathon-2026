import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.engine.instructions import SYSTEM_INSTRUCTIONS
from app.main import create_app
from app.api.dependencies import require
from app.security.permissions import AuthenticationError, AuthorizationError, Permission, Principal
from app.security.tokens import MAX_EXPIRY_HOURS, TokenStoreError, issue_token, load_token_records, main
from verification.api.helpers import API, EXPECTED_ROUTES, ApiHarness, incident_payload

SAMPLE_IDS = {"{site_id}": "SIN", "{device_id}": "SIN-RTR-01", "{diagnosis_id}": "DGN-20260101-0001-01",
              "{incident_id}": "INC-20260101-0001", "{playbook_id}": "PB-WAN-ISP", "{conversation_id}": "CNV-0123456789abcdef",
              "{investigation_id}": "INV-0123456789ab"}
PUBLIC = {"/health", f"{API}/auth/login"}
PROTECTED = [(method, path) for path, methods in EXPECTED_ROUTES.items() if path not in PUBLIC for method in sorted(methods)]


def concrete(path: str) -> str:
    for placeholder, value in SAMPLE_IDS.items():
        path = path.replace(placeholder, value)
    return path


@pytest.mark.parametrize("method,path", PROTECTED)
def test_every_protected_route_requires_authentication(api, method: str, path: str) -> None:
    response = api.client.request(method.upper(), concrete(path), json={})
    assert response.status_code == 401 and response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("header", ["Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "bearer short", "Token abc", "Bearer " + "x" * 300])
def test_malformed_or_unknown_credentials_are_rejected(api, header: str) -> None:
    response = api.client.post(f"{API}/auth/verify", headers={"Authorization": header})
    assert response.status_code == 401 and response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_invalid_and_expired_tokens_are_rejected(api) -> None:
    forged = api.tokens["manager"][:-4] + ("AAAA" if not api.tokens["manager"].endswith("AAAA") else "BBBB")
    assert api.client.post(f"{API}/auth/verify", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    expired = api.post("/auth/verify", as_="expired")
    assert expired.status_code == 401 and api.tokens["expired"] not in expired.text


def test_no_token_store_means_no_access(tmp_path: Path) -> None:
    client = TestClient(create_app(Settings(_env_file=None, incident_store_dir=str(tmp_path / "s"))), raise_server_exceptions=False)
    assert client.get("/health").status_code == 200
    assert client.post(f"{API}/auth/verify", headers={"Authorization": "Bearer " + "a" * 43}).status_code == 401


def test_corrupt_token_store_fails_closed_without_detail(tmp_path: Path) -> None:
    tokens = tmp_path / "tokens.json"
    tokens.write_text('[{"token_hash": "not-a-hash", "secret": "leak-me"}]', encoding="utf-8")
    client = TestClient(create_app(Settings(_env_file=None, auth_tokens_file=str(tokens))), raise_server_exceptions=False)
    response = client.post(f"{API}/auth/verify", headers={"Authorization": "Bearer " + "a" * 43})
    assert response.status_code == 503 and response.json()["error"] == {"code": "AUTHENTICATION_UNAVAILABLE",
                                                                         "message": "Authentication store is unavailable"}
    assert "leak-me" not in response.text and str(tokens) not in response.text


def test_client_supplied_identity_claims_are_ignored(api) -> None:
    forged = {"X-Role": "incident_manager", "X-User": "noc.manager", "X-Actor-Kind": "human", "X-Forwarded-User": "admin"}
    response = api.client.post(f"{API}/auth/verify", headers=api.headers("viewer") | forged)
    assert response.json()["subject"] == "viewer.one" and response.json()["roles"] == ["viewer"]
    incident = api.create_incident()
    denied = api.client.post(f"{API}/incidents/{incident['incident_id']}/close", json={"expected_version": 1, "note": "x"},
                             headers=api.headers("ai") | forged)
    assert denied.status_code == 403


VIEW_ROUTES = ["/topology", "/knowledge/playbooks", "/dashboard/network-health", "/incidents", "/dashboard/summary", "/reports/summary"]


@pytest.mark.parametrize("role", ["viewer", "operator", "manager", "system", "ai", "librarian"])
def test_every_role_can_read(api, role: str) -> None:
    assert [api.get(path, as_=role).status_code for path in VIEW_ROUTES] == [200] * len(VIEW_ROUTES)


@pytest.mark.parametrize("role,allowed", [("viewer", False), ("librarian", False), ("ai", False), ("operator", True),
                                          ("manager", True), ("system", True)])
def test_create_and_diagnose_permissions(api, role: str, allowed: bool) -> None:
    created = api.post("/incidents", incident_payload(), as_=role)
    diagnosed = api.post("/diagnosis", {"scenario_id": "WAN-FAILURE", "description": "Branch down"}, as_=role)
    expected = (201, 200) if allowed else (403, 403)
    assert (created.status_code, diagnosed.status_code) == expected
    if not allowed:
        assert created.json()["error"]["code"] == "PERMISSION_DENIED"


HUMAN_ONLY_CALLS = [
    ("patch", "", {"severity": "low", "reason": "x"}), ("patch", "", {"priority": "p4", "reason": "x"}),
    ("post", "/classification", {"fault_domain": "dns", "reason": "x"}),
    ("post", "/resolution", {"action": "verify", "approved": True, "note": "x"}),
    ("post", "/close", {"note": "x"}), ("post", "/reopen", {"reason": "x"}),
]


@pytest.mark.parametrize("role", ["ai", "system", "operator", "viewer"])
@pytest.mark.parametrize("method,suffix,body", HUMAN_ONLY_CALLS)
def test_human_only_operations_are_denied(api, role: str, method: str, suffix: str, body: dict) -> None:
    incident = api.diagnosed()
    path = f"/incidents/{incident['incident_id']}{suffix}"
    payload = body | {"expected_version": incident["version"]}
    response = api.patch(path, payload, as_=role) if method == "patch" else api.post(path, payload, as_=role)
    assert response.status_code == 403 and response.json()["error"]["code"] == "PERMISSION_DENIED"
    assert api.incident(incident["incident_id"])["version"] == incident["version"]


def test_ai_may_only_propose(api) -> None:
    incident = api.diagnosed()
    iid, version = incident["incident_id"], incident["version"]
    for method, suffix, body in (("patch", "", {"title": "AI rename"}), ("patch", "", {"status": "investigating"}),
                                 ("post", "/diagnosis", {}), ("post", "/escalations", {})):
        payload = body | {"expected_version": version}
        response = api.patch(f"/incidents/{iid}{suffix}", payload, as_="ai") if method == "patch" else \
            api.post(f"/incidents/{iid}{suffix}", payload, as_="ai")
        assert response.status_code == 403, (suffix, body)
    proposal = api.post(f"/incidents/{iid}/resolution", {"expected_version": version, "action": "propose",
                                                         "summary": "Carrier fault suspected", "fault_domain": "wan_isp"}, as_="ai")
    assert proposal.status_code == 200
    resolution = proposal.json()["resolutions"][-1]
    assert resolution["proposed_by"]["kind"] == "ai" and resolution["verification"] == "pending"
    assert proposal.json()["status"] == incident["status"]


def test_human_manager_can_change_severity_and_priority(api) -> None:
    incident = api.create_incident()
    path = f"/incidents/{incident['incident_id']}"
    raised = api.patch(path, {"expected_version": 1, "severity": "critical", "reason": "Whole site down"}).json()
    assert raised["severity"] == "critical" and raised["severity_source"] == "manual" and raised["priority"] == "p1"
    reprioritised = api.patch(path, {"expected_version": raised["version"], "priority": "p2", "reason": "Business impact limited"}).json()
    assert reprioritised["priority"] == "p2" and reprioritised["timeline"][-1]["actor"]["actor_id"] == "noc.manager"


def test_advanced_diagnosis_with_incident_requires_incident_access(api) -> None:
    incident = api.diagnosed()
    body = {"diagnosis": {"scenario_id": "WAN-FAILURE", "description": "Branch down"}, "incident_id": incident["incident_id"]}
    assert api.post("/diagnosis/advanced", body, as_="viewer").status_code == 403
    assert api.post("/diagnosis/advanced", body, as_="operator").status_code == 200


def test_responses_never_expose_prompts_credentials_or_paths(tmp_path: Path) -> None:
    harness = ApiHarness(tmp_path, openai_api_key="sk-test-ABCDEFGHIJKLMNOPQRSTUV")
    incident = harness.diagnosed()
    bodies = [harness.get(f"/incidents/{incident['incident_id']}").text,
              harness.get(f"/diagnosis/{incident['active_diagnosis_id']}").text,
              harness.post("/diagnosis/advanced", {"diagnosis": {"scenario_id": "WAN-FAILURE", "description": "x"}}).text,
              harness.post("/diagnosis", {"scenario_id": "WAN-FAILURE", "description": "x"}).text,
              harness.get("/dashboard/network-health").text, harness.get("/reports/diagnosis").text]
    combined = "\n".join(bodies)
    assert "ABCDEFGHIJKLMNOP" not in combined and str(tmp_path) not in combined and "token_hash" not in combined
    assert SYSTEM_INSTRUCTIONS[:80] not in combined and "untrusted_incident" not in combined


def test_unexpected_errors_are_generic(api, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.routes.topology.load_topology", lambda: (_ for _ in ()).throw(RuntimeError("/srv/secret/path")))
    response = api.get("/topology")
    assert response.status_code == 500 and response.json() == {"error": {"code": "INTERNAL_SERVER_ERROR", "message": "An unexpected error occurred"}}
    assert "Traceback" not in response.text and "/srv/secret" not in response.text


def test_validation_errors_use_standard_format(api) -> None:
    response = api.post("/incidents", {"title": "x"}, as_="operator")
    assert response.status_code == 422 and response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert set(response.json()["error"]) <= {"code", "message", "details"}


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"offset": 10_001}, {"limit": "many"}])
def test_pagination_is_bounded(api, params: dict) -> None:
    assert api.get("/topology/devices", params=params).status_code == 422


def test_middleware_applies_to_api_routes(tmp_path: Path) -> None:
    harness = ApiHarness(tmp_path, max_request_bytes=2048, rate_limit_requests=5)
    oversized = harness.post("/incidents", incident_payload(description="x" * 4000), as_="operator")
    assert oversized.status_code == 413 and oversized.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    response = harness.get("/topology/sites")
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert response.headers["cache-control"] == "no-store"
    codes = [harness.get("/topology/sites").status_code for _ in range(5)]
    assert codes[-1] == 429


def test_request_ids_are_generated_or_safely_echoed(api) -> None:
    generated = api.get("/topology/sites").headers["x-request-id"]
    assert len(generated) == 32 and generated.isalnum()
    echoed = api.client.get(f"{API}/topology/sites", headers=api.headers("viewer") | {"X-Request-ID": "trace-1234-abcd"})
    assert echoed.headers["x-request-id"] == "trace-1234-abcd"
    for unsafe in ("<script>", "a" * 100, "short", "id with spaces"):
        replaced = api.client.get("/health", headers={"X-Request-ID": unsafe}).headers["x-request-id"]
        assert replaced != unsafe and len(replaced) == 32
    assert api.client.get(f"{API}/auth/verify").headers["x-request-id"]


def test_production_disables_docs_but_keeps_api(tmp_path: Path) -> None:
    harness = ApiHarness(tmp_path, environment="production")
    assert harness.client.get("/docs").status_code == 404 and harness.client.get("/openapi.json").status_code == 404
    assert harness.get("/topology/sites").status_code == 200


def test_token_issuance_is_private_atomic_and_expiring(tmp_path: Path) -> None:
    store = tmp_path / "auth" / "tokens.json"
    principal = Principal(subject="noc.lead", kind="human", roles=["incident_manager"])
    now = datetime(2026, 3, 1, tzinfo=timezone.utc)
    first = issue_token(store, principal, 8, now=now)
    second = issue_token(store, principal, 8, now=now)
    assert first != second and len(first) >= 43
    assert stat.S_IMODE(store.stat().st_mode) == 0o600 and stat.S_IMODE(store.parent.stat().st_mode) == 0o700
    content = store.read_text(encoding="utf-8")
    assert first not in content and second not in content
    records = load_token_records(store)
    assert [r.expires_at for r in records] == [now + timedelta(hours=8)] * 2
    assert sorted(os.listdir(store.parent)) == ["tokens.json"]
    issue_token(store, principal, 1, now=now + timedelta(hours=9))
    assert len(load_token_records(store)) == 1
    for hours in (0, MAX_EXPIRY_HOURS + 1):
        with pytest.raises(TokenStoreError):
            issue_token(store, principal, hours)


def test_failed_token_write_leaves_store_intact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = tmp_path / "tokens.json"
    issue_token(store, Principal(subject="a", kind="human", roles=["viewer"]), 1)
    before = store.read_text(encoding="utf-8")
    monkeypatch.setattr("app.security.tokens.os.replace", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        issue_token(store, Principal(subject="b", kind="human", roles=["viewer"]), 1)
    assert store.read_text(encoding="utf-8") == before and sorted(os.listdir(tmp_path)) == ["tokens.json"]


def test_new_and_removed_tokens_apply_without_restart(api) -> None:
    late = issue_token(api.tokens_file, Principal(subject="late.joiner", kind="human", roles=["viewer"]), 1)
    headers = {"Authorization": f"Bearer {late}"}
    assert api.client.post(f"{API}/auth/verify", headers=headers).json()["subject"] == "late.joiner"
    api.tokens_file.write_text("[]", encoding="utf-8")
    assert api.client.post(f"{API}/auth/verify", headers=headers).status_code == 401
    assert api.post("/auth/verify", as_="manager").status_code == 401


def test_token_store_rejects_symlinks_and_oversized_files(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text("[]", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(TokenStoreError):
        load_token_records(link)
    real.write_text(" " * 1_000_001, encoding="utf-8")
    with pytest.raises(TokenStoreError):
        load_token_records(real)


def test_issue_command_shows_token_once(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    store = tmp_path / "tokens.json"
    assert main(["issue", "--subject", "noc.lead", "--kind", "human", "--role", "operator", "--expires-hours", "4",
                 "--file", str(store)]) == 0
    token = capsys.readouterr().out.splitlines()[0]
    records = load_token_records(store)
    assert len(records) == 1 and token not in store.read_text(encoding="utf-8")
    harness_client = TestClient(create_app(Settings(_env_file=None, auth_tokens_file=str(store))))
    assert harness_client.post(f"{API}/auth/verify", headers={"Authorization": f"Bearer {token}"}).json()["subject"] == "noc.lead"
    for arguments in (["--kind", "ai", "--role", "incident_manager"], ["--kind", "human", "--role", "viewer", "--expires-hours", "0"]):
        with pytest.raises(SystemExit):
            main(["issue", "--subject", "x", "--file", str(store)] + arguments)
    assert len(load_token_records(store)) == 1
    assert json.loads(store.read_text(encoding="utf-8"))[0]["principal"]["subject"] == "noc.lead"


@pytest.mark.parametrize("scheme", ["Basic", "Token", "Digest", ""])
def test_valid_token_with_wrong_scheme_is_rejected(api, scheme: str) -> None:
    header = f"{scheme} {api.tokens['manager']}".strip()
    response = api.client.post(f"{API}/auth/verify", headers={"Authorization": header})
    assert response.status_code == 401 and api.tokens["manager"] not in response.text


def test_route_permission_dependency_enforces_permission() -> None:
    viewer = Principal(subject="viewer.one", kind="human", roles=["viewer"])
    assert require(Permission.VIEW_DIAGNOSTICS)(viewer) is viewer
    with pytest.raises(AuthorizationError):
        require(Permission.MANAGE_KNOWLEDGE)(viewer)
    with pytest.raises(AuthenticationError):
        require(Permission.VIEW_DIAGNOSTICS)(viewer.model_copy(update={"authenticated": False}))


def test_evidence_hides_unverified_diagnoses(api) -> None:
    incident = api.diagnosed()
    path = api.root / "incidents" / f"{incident['incident_id']}.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    evidence = next(e for e in stored["diagnoses"][0]["diagnosis"]["evidence"] if e["references"])
    evidence["references"][0]["record_id"] = "EVT-99999"
    path.write_text(json.dumps(stored), encoding="utf-8")
    fresh = ApiHarness.__new__(ApiHarness)
    fresh.__dict__.update(api.__dict__)
    fresh.client = TestClient(create_app(api.settings), raise_server_exceptions=False)
    for route in (f"/incidents/{incident['incident_id']}/evidence", f"/diagnosis/{incident['active_diagnosis_id']}/evidence"):
        page = fresh.get(route).json()
        assert page["provenance_verified"] is False and page["items"] == [] and page["total"] == 0
        assert page["unverified_diagnosis_ids"] == [incident["active_diagnosis_id"]]
