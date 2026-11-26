import asyncio
import json
import threading
from pathlib import Path
from typing import Any

import httpx2

from verification.agent.helpers import FAKE_KEY, completion
from verification.api.helpers import API, ApiHarness

AI_SETTINGS = {"ai_provider": "openai", "ai_model": "approved-test-model", "openai_api_key": FAKE_KEY}
DIAGNOSTIC_TOOLS = {"get_topology", "get_device_logs", "get_interface_stats", "get_routing_state", "get_firewall_logs",
                    "get_dhcp_dns_status", "check_network_reachability", "analyze_packet_loss", "analyze_interface_errors",
                    "analyze_routing_adjacency", "check_device_availability", "analyze_network_dependencies"}


def chunk(delta: dict, finish: str | None = None) -> str:
    return "data: " + json.dumps({"id": "chatcmpl-test", "object": "chat.completion.chunk", "created": 0, "model": "approved-test-model",
                                  "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}) + "\n\n"


def sse_reply(text: str, pieces: int = 4) -> bytes:
    size = max(1, len(text) // pieces)
    parts = [text[i:i + size] for i in range(0, len(text), size)]
    body = chunk({"role": "assistant", "content": ""})
    body += "".join(chunk({"content": part}) for part in parts)
    body += chunk({}, "stop") + "data: [DONE]\n\n"
    return body.encode()


class ConversationModel:
    """Scripted chat-completions endpoint that answers streamed (composer) and plain (diagnosis agent) requests.

    Steps are consumed in order. A step is {"reply": text} for a streamed composer reply, {"status": code} for a provider
    error, {"tool_calls": [(name, args)]} / {"answer": payload} for the diagnosis agent, or {"hang": seconds}.
    """

    def __init__(self, steps: list[dict] | None = None, default_reply: str | None = None) -> None:
        self.steps = list(steps or [])
        self.default_reply = default_reply
        self.requests: list[dict] = []
        self.lock = threading.Lock()

    async def handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        with self.lock:
            self.requests.append(body)
            step = self.steps.pop(0) if self.steps else None
        if step is None:
            step = {"reply": self.default_reply} if self.default_reply and body.get("stream") else {"status": 500}
        if "hang" in step:
            await asyncio.sleep(step["hang"])
            step = {"status": 504}
        if "status" in step:
            return httpx2.Response(step["status"], json={"error": {"message": "scripted failure"}})
        if "reply" in step:
            if body.get("stream"):
                return httpx2.Response(200, content=sse_reply(step["reply"]), headers={"content-type": "text/event-stream"})
            return httpx2.Response(200, json=completion({"role": "assistant", "content": step["reply"]}, "stop"))
        if "tool_calls" in step:
            calls = [{"id": f"call-{len(self.requests)}-{i}", "type": "function",
                      "function": {"name": name, "arguments": json.dumps(arguments)}} for i, (name, arguments) in enumerate(step["tool_calls"])]
            return httpx2.Response(200, json=completion({"role": "assistant", "content": None, "tool_calls": calls}, "tool_calls"))
        payload = step["answer"]
        content = payload if isinstance(payload, str) else json.dumps(payload)
        return httpx2.Response(200, json=completion({"role": "assistant", "content": content}, "stop"))

    @property
    def streamed(self) -> list[dict]:
        return [r for r in self.requests if r.get("stream")]

    @property
    def tool_enabled(self) -> list[dict]:
        return [r for r in self.requests if r.get("tools")]


def model_harness(root: Path, model: ConversationModel, **settings: Any) -> ApiHarness:
    api = ApiHarness(root, **(AI_SETTINGS | settings))
    api.client.app.state.services.agent.transport = httpx2.MockTransport(model.handler)
    return api


def conversation(api: ApiHarness, incident_id: str | None = None, as_: str = "operator", **extra: Any) -> str:
    body = ({"incident_id": incident_id} if incident_id else {}) | extra
    response = api.post("/conversations", body, as_=as_)
    assert response.status_code == 201, response.text
    return response.json()["conversation_id"]


def say(api: ApiHarness, conversation_id: str, content: str | None = None, as_: str = "operator", **extra: Any) -> dict:
    body = ({"content": content} if content is not None else {}) | extra
    response = api.post(f"/conversations/{conversation_id}/messages", body, as_=as_)
    assert response.status_code == 200, response.text
    return response.json()


def events(api: ApiHarness, conversation_id: str, after: int = 0, as_: str = "operator") -> list[dict]:
    response = api.client.get(f"{API}/conversations/{conversation_id}/events", params={"after": after}, headers=api.headers(as_))
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/event-stream"), response.text
    return parse_sse(response.text)


def parse_sse(text: str) -> list[dict]:
    parsed = []
    for frame in text.split("\n\n"):
        data = [line[6:] for line in frame.splitlines() if line.startswith("data: ")]
        if data and data[0] != "{}":
            parsed.append(json.loads(data[0]))
    return parsed


def tool_events(items: list[dict]) -> list[dict]:
    return [e for e in items if e["event"] in ("tool.started", "tool.completed", "tool.failed", "tool.skipped")]


def diagnostic_calls(result: dict) -> list[str]:
    return [step["tool"] for step in result["execution"]["tools"] if step["tool"] in DIAGNOSTIC_TOOLS
            and step["status"] in ("executed", "failed")]
