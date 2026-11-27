"""Human-first replies: short plain answers by default, detail on request, nothing hidden and nothing invented.

The reference conversation is the reported one: demo incident INC-20260430-0410 (certificate errors at every office plus
an IDS port-sweep alert), whose stored rule-based diagnosis found no cause. Its evidence is three reachable paths and one
blocked flow, which the old reply dumped as full layer-3 paths.
"""
import json
import re
from pathlib import Path

import pytest

from verification.api.helpers import ApiHarness
from verification.conversation.helpers import AI_SETTINGS, ConversationModel

INCIDENT = "INC-20260430-0410"
DEVICE_ID = re.compile(r"\b[A-Z][A-Z0-9]{1,5}-(?:[A-Z]{2,5}-){0,2}\d{2}\b")


def harness(root: Path, model: ConversationModel | None = None) -> ApiHarness:
    if model is None:
        return ApiHarness(root, demo_incidents=True)
    api = ApiHarness(root, demo_incidents=True, **AI_SETTINGS)
    api.client.app.state.services.agent.transport = __import__("httpx2").MockTransport(model.handler)
    return api


def talk(api: ApiHarness, cid: str, text: str) -> dict:
    response = api.post(f"/conversations/{cid}/messages", {"content": text}, as_="manager")
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def chat(tmp_path: Path):
    api = harness(tmp_path)
    with api.client:
        cid = api.post("/conversations", {"incident_id": INCIDENT}, as_="manager").json()["conversation_id"]
        yield api, cid


def test_the_reported_explanation_is_short_plain_and_keeps_the_security_warning(chat) -> None:
    api, cid = chat
    talk(api, cid, "Hi")
    turn = talk(api, cid, "Explain the current diagnosis")
    text = turn["response"]
    assert turn["execution"]["tool_calls"] == 0 and len(text.split()) <= 80
    assert " > " not in text and "->" not in text and not DEVICE_ID.search(text), text
    assert text.startswith("I haven't found the cause yet") and "port-sweep" in text and "neither confirmed nor ruled out" in text
    assert "No root cause is supported" not in text
    # The full record stays available: evidence references, plain tooltips and the technical details.
    refs = turn["evidence_references"]
    assert [r["evidence_id"] for r in refs] == ["E1", "E2", "E3", "E4"]
    assert all(r["plain"] and " > " not in r["plain"] for r in refs) and " > " in refs[0]["summary"]
    assert "DC1-FW-01" in turn["details"]


def test_detail_comes_on_request_and_technical_detail_when_asked(chat) -> None:
    api, cid = chat
    why = talk(api, cid, "Why do you think that?")
    assert "(E1 to E3)" in why["response"] and "(E4)" in why["response"] and " > " not in why["response"]
    assert "DC1-FW-01" in why["response"], "the detail level names the affected device"
    one = talk(api, cid, "Explain E1.")
    assert one["response"].startswith("**E1**") and "New York" in one["response"] and " > " not in one["response"]
    assert "It collected" not in one["details"] and "was collected during the diagnosis" in one["details"]
    raw = talk(api, cid, "Show technical details")
    assert raw["intent"]["name"] == "detail" and "NYC-SW-01 > NYC-RTR-01" in raw["response"]


def test_questions_about_the_incident_are_answered_without_running_anything(chat) -> None:
    api, cid = chat
    root = talk(api, cid, "What is the root issue?")
    assert root["intent"]["name"] == "incident_query" and root["response"].startswith("I haven't found the cause yet")
    confirmed = talk(api, cid, "Is this confirmed?")
    assert confirmed["intent"]["name"] == "incident_query" and confirmed["response"].startswith("No.")
    happened = talk(api, cid, "What happened?")
    assert happened["intent"]["name"] == "incident_query" and "Certificate errors" in happened["response"]
    attack = talk(api, cid, "Is this a confirmed attack?")
    assert attack["response"].startswith("No, nothing confirms an attack") and "Go ahead?" in attack["response"]
    for turn in (root, confirmed, happened, attack):
        assert turn["execution"]["tool_calls"] == 0 and turn["investigation_id"] is None


def test_next_check_is_offered_in_a_sentence_and_steps_come_when_asked(chat) -> None:
    api, cid = chat
    nxt = talk(api, cid, "What should I check next?")
    assert nxt["execution"]["tool_calls"] == 0 and len(nxt["response"].split()) <= 45
    assert "certificates" in nxt["response"] and nxt["context"]["pending_action"]["kind"] == "protocol"
    engines = {c["arguments"]["protocol"] for c in nxt["context"]["pending_action"]["calls"]}
    assert engines == {"tls", "threats"}
    steps = talk(api, cid, "Give me step-by-step commands.")
    # Nothing in the evidence or the report justifies a device command here, so none is invented (see troubleshooting_grounds_spec).
    assert steps["response"].startswith("I can't point to specific commands yet") and "Run: `" not in steps["response"]


def test_customer_drafts_never_claim_a_cause_the_diagnosis_did_not_find(chat) -> None:
    api, cid = chat
    email = talk(api, cid, "Prepare a customer email.")
    body = email["response"].split("**Subject:**", 1)[1]
    assert "likely cause" not in body and "investigating" in body and "ERP" not in body and "internet access" in body
    shorter = talk(api, cid, "Make it shorter.")
    assert shorter["intent"]["name"] == "customer_email" and len(shorter["response"]) < len(email["response"])
    assert "hasn't been sent" in shorter["response"] and "likely cause" not in shorter["response"]
    update = talk(api, cid, "Give me a status update")
    assert "likely cause" not in update["response"].lower() and "investigating the cause" in update["response"]


def test_go_ahead_with_nothing_pending_asks_and_never_runs(chat) -> None:
    api, cid = chat
    talk(api, cid, "Give me step-by-step commands.")
    talk(api, cid, "Prepare a customer email.")
    talk(api, cid, "Make it shorter.")
    ask = talk(api, cid, "Go ahead.")
    assert ask["execution"]["tool_calls"] == 0 and ask["response"].startswith("Do you mean the read-only checks of the certificates")
    assert ask["context"]["pending_action"]["kind"] == "protocol"
    declined = talk(api, cid, "no thanks")
    assert declined["intent"]["name"] == "decline"
    again = talk(api, cid, "Go ahead.")
    assert again["execution"]["tool_calls"] == 0 and "nothing waiting" in again["response"]


def test_check_every_log_becomes_a_bounded_plan_that_runs_only_after_approval(chat) -> None:
    api, cid = chat
    offer = talk(api, cid, "Check every single log.")
    assert offer["execution"]["tool_calls"] == 0 and "Go ahead?" in offer["response"]
    calls = offer["context"]["pending_action"]["calls"]
    assert len(calls) == 4 and {c["tool"] for c in calls} == {"get_device_logs"}
    assert calls[0]["arguments"]["device_id"] == "DC1-FW-01", "the device with odd evidence comes first"
    ran = talk(api, cid, "go ahead")
    assert ran["intent"]["name"] == "confirmation" and 1 <= ran["execution"]["diagnostic_tool_calls"] <= 4


def test_the_model_gets_a_compact_view_and_simple_turns_skip_it(tmp_path: Path) -> None:
    model = ConversationModel(default_reply="I haven't found the cause yet. The port-sweep alert isn't covered by any evidence yet.")
    api = harness(tmp_path, model)
    with api.client:
        cid = api.post("/conversations", {"incident_id": INCIDENT}, as_="manager").json()["conversation_id"]
        for text in ("Hi", "thanks!", "Is this confirmed?", "Prepare a customer email."):
            talk(api, cid, text)
        assert model.streamed == [], "greetings, acknowledgements, yes/no facts and drafts are deterministic"
        turn = talk(api, cid, "Explain the current diagnosis")
        assert turn["execution"]["composer"] == "model"
        request = model.streamed[-1]
        envelope = json.loads(request["messages"][-1]["content"])
        assert set(envelope) <= {"message", "draft", "intent", "detail", "ran_checks", "confirmed", "incident", "offer", "warnings",
                                 "question", "evidence", "guidance", "guidance_is_not_evidence", "concepts", "draft_issues",
                                 "user_can_run_checks"}
        assert envelope["warnings"] and " > " not in json.dumps(envelope) and "description" not in envelope["incident"]
        assert len(request["messages"][0]["content"]) < 1600, "the system instructions stay short"
        assert all(len(m["content"]) <= 400 for m in request["messages"][1:-1]), "history messages are trimmed"


@pytest.mark.parametrize("reply,issue", [
    ("This is a confirmed attack from the scanner.", "calls an alert an attack"),
    ("The cause is confirmed as a firewall fault.", "calls something confirmed"),
    ("I haven't found the cause yet. The paths all work.", "drops a security warning"),
])
def test_model_replies_that_overstate_or_hide_warnings_are_rejected(tmp_path: Path, reply: str, issue: str) -> None:
    model = ConversationModel(default_reply=reply)
    api = harness(tmp_path, model)
    with api.client:
        cid = api.post("/conversations", {"incident_id": INCIDENT}, as_="manager").json()["conversation_id"]
        turn = talk(api, cid, "Explain the current diagnosis")
        assert turn["execution"]["composer"] == "template" and any(issue in i for i in turn["execution"]["composer_issues"])
        assert "port-sweep" in turn["response"] and "was not used" in turn["generated_by"]["note"]


def test_em_dashes_from_the_model_are_removed(tmp_path: Path) -> None:
    model = ConversationModel(default_reply="I haven't found the cause yet — the port-sweep alert isn't covered by evidence.")
    api = harness(tmp_path, model)
    with api.client:
        cid = api.post("/conversations", {"incident_id": INCIDENT}, as_="manager").json()["conversation_id"]
        turn = talk(api, cid, "Explain the current diagnosis")
        assert turn["execution"]["composer"] == "model" and "—" not in turn["response"]
