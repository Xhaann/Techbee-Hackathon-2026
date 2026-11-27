"""Regression conversations for the seven reported screenshots.

The screenshot images were not attached to the request, so each case is reconstructed from the behaviour requirements
that accompanied them (short human replies, "Go ahead" handling, customer email, step-by-step troubleshooting, evidence
explanation without reruns, no repeated questions, honest fallback). Replace or extend these once the images are available.
"""
import re

from app.engine.safety import is_read_only_command
from verification.phase2.conversation_spec import start, say, tools


def test_screenshot_1_greeting_is_short_friendly_and_runs_nothing(api) -> None:
    cid = start(api)
    turn = say(api, cid, "hello")
    assert turn["intent"]["name"] == "greeting" and turn["execution"]["tool_calls"] == 0
    assert len(turn["response"].split()) <= 25 and turn["response"].startswith("Hi")


def test_screenshot_2_go_ahead_runs_the_offer_without_asking_again(api) -> None:
    cid = start(api)
    offer = say(api, cid, "Singapore users can't reach the ERP; everyone is affected")
    assert "full diagnosis" in offer["response"] and offer["execution"]["tool_calls"] == 0
    done = say(api, cid, "Go ahead")
    assert done["intent"]["name"] == "confirmation" and tools(done) and done["clarification"] is None
    assert "Which site" not in done["response"] and len(done["response"].split()) <= 60


def test_screenshot_3_customer_email_is_a_grounded_unsent_draft(api) -> None:
    cid = start(api)
    say(api, cid, "diagnose it")
    email = say(api, cid, "Can you write an email to the customer explaining the issue?")
    assert email["intent"]["name"] == "customer_email" and email["execution"]["tool_calls"] == 0
    assert "**Subject:**" in email["response"] and "hasn't been sent" in email["response"]
    body = email["response"].split("**Subject:**", 1)[1]
    assert "Singapore" in body and "[customer name]" in body
    assert not re.search(r"\b(?:will be (?:fixed|restored) (?:by|within)|ETA[: ]+\d|within \d+ (?:minutes|hours))", body, re.I)
    assert "LNK-WAN-SIN" not in body and "Carrier B" not in body


def test_screenshot_4_step_by_step_troubleshooting_has_everything_an_engineer_needs(api) -> None:
    cid = start(api)
    say(api, cid, "diagnose it")
    guide = say(api, cid, "Give me step by step troubleshooting instructions")
    text = guide["response"]
    numbers = [int(n) for n in re.findall(r"^(\d)\. \*\*", text, re.M)]
    assert numbers == list(range(1, len(numbers) + 1)) and len(numbers) >= 4
    for block in re.split(r"^\d\. ", text, flags=re.M)[1:]:
        assert re.search(r"\bon [A-Z0-9]+-[A-Z0-9-]+\b", block), block[:80]
        command = re.search(r"Run: `([^`]+)`", block).group(1)
        assert is_read_only_command(command), command
        assert "Expect:" in block and "If you see instead:" in block and "If it looks healthy:" in block


def test_screenshot_5_explaining_evidence_does_not_rerun_the_diagnosis(api) -> None:
    cid = start(api)
    say(api, cid, "diagnose it")
    turn = say(api, cid, "What does E2 mean?")
    assert turn["execution"]["tool_calls"] == 0 and turn["investigation_id"] is None and "**E2**" in turn["response"]


def test_screenshot_6_information_already_given_is_not_asked_for_again(api) -> None:
    cid = start(api, incident=False)
    first = say(api, cid, "Users at Singapore can't reach the internet and ERP")
    asked = first["clarification"]["missing"] if first["clarification"] else []
    assert "site" not in asked and "services" not in asked
    second = say(api, cid, "everyone at Singapore")
    assert second["clarification"] is None and "Singapore" not in (second["clarification"] or {}).get("question", "")


def test_screenshot_7_rule_based_results_are_never_presented_as_ai(api) -> None:
    cid = start(api)
    turn = say(api, cid, "diagnose it")
    assert turn["generated_by"]["result"] == "rule_based" and turn["generated_by"]["model_configured"] is False
    assert not re.search(r"\b(?:the AI|AI model|GPT|LLM) (?:found|diagnosed|determined|concluded)", turn["response"], re.I)
    assert "No AI model is configured" in turn["generated_by"]["note"]
