"""The 17-message conversation probe: three realistic conversations, each turn with explicit expectations.

Runs rule-based with no model, so replies are the deterministic templates; intent and tool decisions are the same with a
model because classification is deterministic.
"""
import re
from dataclasses import dataclass, field

import pytest

from verification.api.helpers import ApiHarness


@dataclass
class Step:
    message: str
    intent: str
    tools: int | tuple[int, int]
    contains: tuple[str, ...] = ()
    absent: tuple[str, ...] = ()
    clarifies: bool | None = None
    sites: tuple[str, ...] | None = None
    tool_names: tuple[str, ...] = ()
    extra: dict = field(default_factory=dict)


WAN = [
    Step("hi", "greeting", 0, clarifies=False),
    Step("Users in Singapore can't reach the ERP since this morning", "symptom_report", 0, contains=("Singapore",),
         absent=("are seeing",), clarifies=True, sites=("SIN",)),
    Step("everyone at the site", "clarification", 0, contains=("full diagnosis",), clarifies=False),
    Step("go ahead", "confirmation", (1, 10), contains=("LNK-WAN-SIN", "WAN / ISP")),
    Step("why do you think that?", "evidence_explanation", 0, contains=("LNK-WAN-SIN",)),
    Step("what about E2?", "evidence_explanation", 0, contains=("**E2**",)),
    Step("is it the firewall?", "hypothesis_check", 0, contains=("points elsewhere", "LNK-WAN-SIN")),
    Step("what's the difference between OSPF and BGP?", "knowledge", 0, contains=("link-state", "path-vector", "general networking")),
    Step("check SIN-RTR-01 routing", "targeted_diagnostic", 1, tool_names=("get_routing_state",)),
    Step("could it be DNS instead?", "hypothesis_check", 0, contains=("points elsewhere",)),
    Step("restart the router", "human_action", 0, contains=("can't make changes",)),
]
SHARED = [
    Step("Two branches lost all connectivity at the same time; Bengaluru is fine", "symptom_report", 0,
         contains=("Unaffected: Bengaluru",), clarifies=True, sites=()),
    Step("New York and Singapore", "clarification", 0, absent=("Which site",), sites=("NYC", "SIN")),
    Step("diagnose it", "full_diagnosis", (1, 10), contains=("CORE-RTR-01",)),
]
LOSS = [
    Step("NYC voice calls are choppy", "symptom_report", 0, clarifies=True, sites=("NYC",)),
    Step("is the WAN link dropping packets?", "targeted_diagnostic", 1, tool_names=("analyze_packet_loss",), clarifies=False,
         contains=("NYC-RTR-01",)),
    Step("Bangalore users also complain, check there too", "targeted_diagnostic", 1, tool_names=("analyze_packet_loss",),
         clarifies=False, contains=("BLR-RTR-01",)),
]
CONVERSATIONS = {"WAN-FAILURE": WAN, "SHARED-DEVICE-FAILURE": SHARED, "PACKET-LOSS": LOSS}


def run(api: ApiHarness, scenario: str, steps: list[Step]) -> list[tuple[Step, dict]]:
    created = api.post("/conversations", {"scenario_id": scenario, "mode": "rule_based"}, as_="operator")
    assert created.status_code == 201, created.text
    cid = created.json()["conversation_id"]
    results = []
    for step in steps:
        response = api.post(f"/conversations/{cid}/messages", {"content": step.message}, as_="operator")
        assert response.status_code == 200, (step.message, response.text)
        results.append((step, response.json()))
    return results


def failures(step: Step, turn: dict, previous: dict | None) -> list[str]:
    problems = []
    if turn["intent"]["name"] != step.intent:
        problems.append(f"intent {turn['intent']['name']} != {step.intent}")
    calls = turn["execution"]["diagnostic_tool_calls"]
    low, high = (step.tools, step.tools) if isinstance(step.tools, int) else step.tools
    if not low <= calls <= high:
        problems.append(f"{calls} tool calls, expected {step.tools}")
    tools = [s["tool"] for s in turn["execution"]["tools"] if s["status"] in ("executed", "failed")]
    for name in step.tool_names:
        if name not in tools:
            problems.append(f"{name} did not run ({tools})")
    text = turn["response"]
    # Default replies use plain names; identifiers and fault labels sit one click away in the technical details.
    shown = f"{text}\n{turn.get('details') or ''}"
    problems += [f"missing {needle!r}" for needle in step.contains if needle.lower() not in shown.lower()]
    problems += [f"contains {needle!r}" for needle in step.absent if needle in text]
    if re.search(r"\bNone\b", text):
        problems.append("reply prints None")
    if step.clarifies is not None and bool(turn["clarification"]) != step.clarifies:
        problems.append(f"clarification={bool(turn['clarification'])}, expected {step.clarifies}")
    if step.sites is not None and tuple(turn["context"]["site_ids"]) != step.sites:
        problems.append(f"context sites {turn['context']['site_ids']} != {list(step.sites)}")
    if previous and previous["clarification"] and turn["clarification"] \
            and turn["clarification"]["question"] == previous["clarification"]["question"]:
        problems.append("repeated the previous clarifying question")
    return problems


@pytest.fixture(scope="module")
def transcript(tmp_path_factory) -> list[tuple[str, Step, dict, dict | None]]:
    api = ApiHarness(tmp_path_factory.mktemp("probe"))
    rows = []
    for scenario, steps in CONVERSATIONS.items():
        previous = None
        for step, turn in run(api, scenario, steps):
            rows.append((scenario, step, turn, previous))
            previous = turn
    return rows


@pytest.mark.parametrize("index", range(17), ids=[f"{s}:{st.message[:40]}" for s, steps in CONVERSATIONS.items() for st in steps])
def test_probe_turn(transcript, index: int) -> None:
    scenario, step, turn, previous = transcript[index]
    assert not failures(step, turn, previous), (scenario, step.message, failures(step, turn, previous), turn["response"])


def test_probe_meets_the_acceptance_target(transcript) -> None:
    passed = sum(not failures(step, turn, previous) for _, step, turn, previous in transcript)
    assert len(transcript) == 17 and passed >= 16, passed


def test_evidence_ids_are_unique_across_investigations_in_a_conversation(transcript) -> None:
    wan = [turn for scenario, _, turn, _ in transcript if scenario == "WAN-FAILURE"]
    diagnosis_ids = {ref["evidence_id"] for ref in wan[3]["evidence_references"]}
    check_ids = {ref["evidence_id"] for ref in wan[8]["evidence_references"]}
    assert diagnosis_ids and check_ids and not diagnosis_ids & check_ids
    assert min(int(e[1:]) for e in check_ids) > max(int(e[1:]) for e in diagnosis_ids)


def test_each_clarifying_question_is_asked_at_most_once(tmp_path) -> None:
    api = ApiHarness(tmp_path)
    steps = [Step("NYC users have a problem", "symptom_report", 0), Step("not sure", "clarification", 0),
             Step("still not sure", "clarification", 0)]
    questions = [turn["clarification"]["question"] for _, turn in run(api, "PACKET-LOSS", steps) if turn["clarification"]]
    assert len(questions) == len(set(questions)) and len(questions) <= 2


def test_greetings_and_small_talk_never_run_tools(tmp_path) -> None:
    api = ApiHarness(tmp_path)
    chat = ["hello", "good morning team", "how are you?", "thanks!", "what can you do?", "ok", "bye"]
    for _, turn in run(api, "WAN-FAILURE", [Step(m, "", 0) for m in chat]):
        assert turn["execution"]["tool_calls"] == 0 and turn["investigation_id"] is None, turn["user_message"]["content"]


def test_inferred_findings_are_never_presented_as_measured_facts(tmp_path) -> None:
    api = ApiHarness(tmp_path)
    steps = [Step("New York desk phones are stuck on Configuring IP", "symptom_report", 0),
             Step("diagnose it", "full_diagnosis", (1, 10))]
    _, turn = run(api, "ADV-NYC-VOICE-DHCP-RELAY", steps)[-1]
    assert "New York router" in turn["response"] and "relay" in turn["response"].lower() and "NYC-RTR-01" in turn["details"]
    lines = [line for line in turn["details"].splitlines() if line.startswith("- **E")]
    assert lines, "the technical details list the key evidence"
    inferred = {ref["evidence_id"] for ref in turn["evidence_references"] if ref["evidence_type"] == "inferred_finding"}
    for line in lines:
        evidence_id = line[4:].split("*", 1)[0]
        assert (evidence_id in inferred) == ("(inferred, not measured)" in line), line
    assert inferred, "the relay diagnosis should cite its inferred relay-failure finding"
