import json
from collections.abc import Callable
from typing import Any

from app.core.config import Settings
from app.engine import DiagnosisRequest
from app.engine.providers import ModelReply, ProviderError, ProviderErrorKind, ToolCallRequest
from app.network.repository import load_scenario

FAKE_KEY = "sk-test-phase4-not-real"

Step = Callable[[list[dict[str, Any]], list[dict[str, Any]] | None], ModelReply]


def incident_request(scenario_id: str, **overrides: Any) -> DiagnosisRequest:
    incident = load_scenario(scenario_id).incident
    values = {"scenario_id": scenario_id, "description": incident.description, "incident_id": incident.incident_id,
              "site_ids": incident.affected_site_ids, "severity": incident.priority}
    return DiagnosisRequest(**(values | overrides))


def ai_settings(**overrides: Any) -> Settings:
    values = {"_env_file": None, "ai_provider": "openai", "ai_model": "approved-test-model", "openai_api_key": FAKE_KEY}
    return Settings(**(values | overrides))


def tool_call(name: str, arguments: dict[str, Any] | str, call_id: str = "call-1") -> ModelReply:
    payload = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return ModelReply(content=None, tool_calls=[ToolCallRequest(id=call_id, name=name, arguments=payload)], finish_reason="tool_calls")


def final(payload: dict[str, Any] | str) -> ModelReply:
    content = payload if isinstance(payload, str) else json.dumps(payload)
    return ModelReply(content=content, tool_calls=[], finish_reason="stop")


def tool_evidence(messages: list[dict[str, Any]], code: str | None = None) -> list[str]:
    ids = []
    for message in messages:
        if message["role"] == "tool":
            for item in json.loads(message["content"]).get("evidence", []):
                if code is None or item["code"] == code:
                    ids.append(item["evidence_id"])
    return ids


def draft(**overrides: Any) -> dict[str, Any]:
    values = {
        "fault_domain": "wan_isp",
        "root_cause": "WAN circuit LNK-WAN-SIN is down",
        "root_cause_device_ids": ["SIN-RTR-01"],
        "root_cause_link_ids": ["LNK-WAN-SIN"],
        "reasoning": "The branch router has no route and its WAN interface is down",
        "supporting_evidence_ids": [],
        "contradictory_evidence_ids": [],
        "confidence": "high",
        "confidence_explanation": "Multiple observed findings agree",
        "alternatives": [],
        "next_checks": [{"device_id": "SIN-RTR-01", "command": "show interfaces Gi0/0/0", "purpose": "Check WAN state",
                         "expected_observation": "Line protocol down", "reason": "WAN link suspected"}],
        "escalation": {"team": "WAN Operations", "priority": "p1", "reason": "Branch isolated"},
        "explanation": {"summary": "The Singapore WAN circuit is down.", "observed_facts": ["WAN interface down"],
                        "hypotheses": ["Carrier fault"], "recommended_actions": ["Check the WAN interface"]},
    }
    return values | overrides


class ScriptedProvider:
    name = "scripted"
    model = "scripted-model"

    def __init__(self, steps: list[Step | ModelReply | ProviderError]) -> None:
        self.steps = list(steps)
        self.calls: list[dict[str, Any]] = []

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> ModelReply:
        self.calls.append({"messages": [dict(message) for message in messages], "tools": tools})
        if not self.steps:
            raise ProviderError(ProviderErrorKind.MALFORMED, "script exhausted")
        step = self.steps.pop(0)
        if isinstance(step, ProviderError):
            raise step
        return step(messages, tools) if callable(step) else step


class FakeTransport:
    def __init__(self, status: int = 200, body: Any = None, error: Exception | None = None) -> None:
        self.status = status
        self.body = body
        self.error = error
        self.requests: list[dict[str, Any]] = []

    def __call__(self, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
        self.requests.append({"url": url, "headers": headers, "payload": json.loads(body), "timeout": timeout})
        if self.error is not None:
            raise self.error
        raw = self.body if isinstance(self.body, bytes) else json.dumps(self.body).encode()
        return self.status, raw


def completion(content: str | None = None, tool_calls: list[dict[str, Any]] | None = None,
               finish_reason: str = "stop") -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {"id": "cmpl-test", "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}]}
