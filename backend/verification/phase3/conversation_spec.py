"""Protocol and security checks in the conversation: offered first and run only after approval, short replies that keep
statuses apart, scan requests declined, definitions answered without tools, commands, guides and pasted output for the
protocol findings, permission and user isolation."""
import pytest

from app.engine.safety import is_read_only_command
from verification.api.helpers import ApiHarness, incident_payload


@pytest.fixture
def api(tmp_path) -> ApiHarness:
    return ApiHarness(tmp_path)


def start(api: ApiHarness, scenario: str, as_: str = "operator") -> str:
    created = api.post("/incidents", incident_payload(scenario), as_=as_).json()["incident"]
    return api.post("/conversations", {"mode": "rule_based", "incident_id": created["incident_id"]}, as_=as_).json()["conversation_id"]


def say(api: ApiHarness, cid: str, text: str | None = None, as_: str = "operator", action: dict | None = None) -> dict:
    response = api.post(f"/conversations/{cid}/messages", {"content": text} if action is None else {"action": action}, as_=as_)
    assert response.status_code == 200, response.text
    return response.json()


def ran(turn: dict) -> list[str]:
    return [s["arguments"].get("protocol") for s in turn["execution"]["tools"] if s["tool"] == "analyze_protocol" and s["status"] == "executed"]


def words(text: str) -> int:
    return len(text.split())


def test_offer_first_then_run_on_approval(api) -> None:
    cid = start(api, "P3-STP-LOOP-NYC")
    offer = say(api, cid, "Is there a spanning tree loop?")
    assert offer["intent"]["name"] == "protocol_check" and ran(offer) == [] and "Go ahead?" in offer["response"]
    assert any(a["kind"] == "protocol" for a in offer["suggested_actions"])
    result = say(api, cid, "go ahead")
    assert ran(result) == ["stp"] and "Layer-2 loop" in result["response"] and "confirmed" in result["response"]
    assert words(result["response"]) <= 40 and result["generated_by"]["result"] == "rule_based"
    card = next(a for a in result["attachments"] if a["kind"] == "protocol")["data"]
    assert card["synthetic"] is True and card["findings"][0]["code"] == "STP_LOOP" and card["findings"][0]["evidence"]
    assert result["evidence_references"] and result["details"] and "nothing was changed" in result["details"]


def test_decline_runs_nothing(api) -> None:
    cid = start(api, "P3-STP-LOOP-NYC")
    say(api, cid, "any spanning tree problems?")
    declined = say(api, cid, "no")
    assert declined["intent"]["name"] == "decline" and ran(declined) == []


def test_quick_action_is_the_approval(api) -> None:
    cid = start(api, "P3-NAT-EXHAUSTION")
    action = {"kind": "protocol", "calls": [{"tool": "analyze_protocol", "arguments": {"protocol": "nat"}}], "label": "Run the NAT check"}
    turn = say(api, cid, action=action)
    assert ran(turn) == ["nat"] and "NAT pool" in turn["response"]
    bad = api.post(f"/conversations/{cid}/messages", {"action": {"kind": "protocol", "calls": [{"tool": "get_topology", "arguments": {}}]}}, as_="operator")
    assert bad.status_code == 422


def test_repeat_request_reuses_the_result(api) -> None:
    cid = start(api, "P3-TLS-CERT-EXPIRED")
    say(api, cid, "check the certificates")
    say(api, cid, "go ahead")
    again = say(api, cid, "check the certificates")
    assert ran(again) == [] and "already ran" in again["response"]


def test_security_reply_never_confirms_or_attributes(api) -> None:
    cid = start(api, "P3-SEC-LATERAL-MOVEMENT-NYC")
    say(api, cid, "run a security review")
    result = say(api, cid, "go ahead")
    text = result["response"]
    assert set(ran(result)) == {"traffic", "lateral", "arp", "tls", "threats"}
    assert "not confirmed" in text and "analyst" in text and "who is behind it" in text and "10.10.10.102" in text
    assert "attacker is" not in text.lower() and "confirmed attack" not in text.lower()


def test_scan_requests_are_declined_with_a_read_only_alternative(api) -> None:
    cid = start(api, "P3-SEC-LATERAL-MOVEMENT-NYC")
    turn = say(api, cid, "scan the network for open ports")
    assert ran(turn) == [] and "don't scan networks" in turn["response"]
    follow = say(api, cid, "go ahead")
    assert set(ran(follow)) == {"traffic", "lateral", "threats"}


def test_definitions_and_existing_checks_are_unchanged(api) -> None:
    cid = start(api, "P3-STP-LOOP-NYC")
    definition = say(api, cid, "what is ARP spoofing?")
    assert definition["intent"]["name"] == "knowledge" and ran(definition) == []
    adjacency = say(api, cid, "check BGP on NYC-RTR-01")
    assert adjacency["intent"]["name"] == "targeted_diagnostic"


def test_commands_guide_and_output_follow_the_protocol_findings(api) -> None:
    cid = start(api, "P3-MTU-BLACKHOLE-SIN")
    say(api, cid, "check MTU")
    say(api, cid, "go ahead")
    commands = say(api, cid, "show me the commands")
    rows = next(a for a in commands["attachments"] if a["kind"] == "commands")["data"]["commands"]
    assert rows and all(is_read_only_command(r["command"]) for r in rows) and any("df-bit" in r["command"] for r in rows)
    guide = say(api, cid, "give me step by step troubleshooting")
    steps = next(a for a in guide["attachments"] if a["kind"] == "troubleshooting_guide")["data"]["steps"]
    assert steps[0]["number"] == 1 and steps[0]["expected_healthy"] and steps[0]["expected_fault"]
    pasted = say(api, cid, "Sending 5, 1500-byte ICMP Echos to 10.100.100.40, timeout is 2 seconds:\nPacket sent with the DF bit set\n.....\n"
                           "Success rate is 0 percent (0/5)")
    assert pasted["intent"]["name"] == "output_interpretation" and "black hole" in pasted["response"]


def test_explanation_reuses_evidence_without_rerunning(api) -> None:
    cid = start(api, "P3-VLAN-TRUNK-PRUNE-BLR")
    say(api, cid, "check the trunks")
    result = say(api, cid, "go ahead")
    explained = say(api, cid, "why?")
    assert ran(explained) == [] and explained["intent"]["name"] == "evidence_explanation"
    assert any(ref["evidence_id"] in explained["response"] for ref in result["evidence_references"])


def test_viewers_cannot_run_and_others_cannot_see(api) -> None:
    cid = start(api, "P3-STP-LOOP-NYC")
    created = api.post("/incidents", incident_payload("P3-STP-LOOP-NYC"), as_="manager").json()["incident"]
    viewer = api.post("/conversations", {"mode": "rule_based", "incident_id": created["incident_id"]}, as_="viewer").json()["conversation_id"]
    denied = say(api, viewer, "is there a spanning tree loop?", as_="viewer")
    assert ran(denied) == [] and "run_diagnostics" in denied["response"]
    assert api.get(f"/conversations/{cid}", as_="other_operator").status_code == 404


def test_missing_data_is_said_plainly(api) -> None:
    cid = api.post("/conversations", {"mode": "rule_based", "scenario_id": "P3-EDGE-PARTIAL-TELEMETRY"}, as_="operator").json()["conversation_id"]
    say(api, cid, "check the wi-fi")
    result = say(api, cid, "go ahead")
    assert ran(result) == ["wireless"] and "couldn't check" in result["response"]
